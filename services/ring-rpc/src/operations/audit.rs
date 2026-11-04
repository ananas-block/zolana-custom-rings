use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

use custom_ring_interface::RingMode;
use solana_address::Address;
use solana_signature::Signature;
use spr_client::GetShieldedTransactionsByTagsResponse;
use spr_indexer_api::{Base64String, Hash, Limit};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{hash::owner_hash, NullifierKey, PublicKey, X25519Keypair, X25519Pubkey};
use spr_transaction::{instructions::transact::canonical_shape, ShieldedTransaction};
use zolana_ring_client::{
    auditor_view_tag, confirmed_merge, historical_evidence,
    history::{HistoryCursor, HistoryPosition, HistoryQuery, HistoryStream, PageEnd},
    records::{MemberOpeningRead, StorageTip},
    rpc::{
        cursor_in_bounds, limit_in_bounds, utxo_hashes_in_bounds, Attestation, AuditedMergesPage,
        AuditedUtxosAttestation, AuditedUtxosPage, AuditorKeyStatement, AuthorityAuth,
        ConfirmedAudit, DecryptedTransaction, DecryptedTransactionsPage, GetAuditedMergesResponse,
        GetAuditedUtxosRequest, GetAuditedUtxosResponse, GetDecryptedTransactionsResponse,
        GetSpendCoverageRequest, GetSpendCoverageResponse, GetWalletActivityResponse,
        GetWalletStatusRequest, GetWalletStatusResponse, PagedRead, ReadAttestation, ReadAuth,
        ReadTarget, ReaderGrantAction, ReaderGrantAttestation, RingChainStatus,
        SetReaderGrantRequest, SkippedReason, SkippedTransaction, SpendCoverageAttestation,
        WalletStatusAttestation, AUDIT_PAGE_LIMIT,
    },
    AuditError, AuditedInput, AuditedMergeOutput, AuditedTransaction, ConfirmedEventKind,
    ConfirmedMerge, CreatedUtxo, CreatedUtxos, DepositNote, EscrowedKeys, HistoricalEvidence,
    InputOpening, InputRing, KnownUtxos, MergeInput, MergeLedger, ReaderKey, RingOrigin,
    RowDisposition, TransactionAudit, UtxoOwner,
};
use zolana_ring_indexer::rpc::{
    GetStorageMemberRecordsRequest, RingMemberOpening, MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_ring_policy::Member;
use zolana_ring_transaction::{
    historical::{assign_prefixed_inputs, InputPrefix, PrefixAssignment},
    RingAssets,
};

use crate::{
    authorize::{AuthorityCheck, AuthorityClaim, ReadCheck, ReadClaim, Unauthorized, WalletCheck},
    error::{redacted, GrantRefusal, RingRpcError},
    grant_rows::{GrantPair, GrantRow},
    grants::{GrantQuery, Grants, ReadScope},
    hub::Shared,
    limits::ReaderPermit,
    replay::ReplayCheck,
    spend_machine::{InputRead, Observation},
    spent_index::{LoadSpends, NoteSeal, PageCommit, SpentCommitment, SpentIndex, SpentSource},
    upstream::{
        MergeAuditRequest, RecordsTip, RingConfiguration, RingHistoryPage, TransactionPage,
        TransactionSource,
    },
    utxos::{
        AuditStore, CreatedIn, EscrowRoot, EscrowedOwner, PageDelta, PageWork, WalletStatusQuery,
        MAX_BACKFILL_PAGES,
    },
};

pub(crate) const WALLET_NOTE_PAGE_LIMIT: usize = 100;
/// Frames one pass retries, the oldest first.
const MAX_RETRIED_FRAMES: usize = 16;
/// A retried slot holds few frames, the next pass reads on.
const MAX_RETRY_PAGES: usize = 4;
pub(crate) const ASSET_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// A delivered output of a mint no registration names misses on every read, the floor bounds the registry reads it causes.
pub(crate) const ASSET_MISS_INTERVAL: Duration = Duration::from_secs(5);

/// The attested limit is what the reader signed, absent for the default page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    cursor: Option<Base64String>,
    history: Option<HistoryCursor>,
    limit: NonZeroU32,
    attested_limit: Option<Limit>,
}

pub struct AuditService<S> {
    ring: Address,
    auditor: X25519Keypair,
    view_tag: [u8; 32],
    shared: Arc<Shared<S>>,
}

#[must_use]
pub(crate) struct AuditServiceInit<S> {
    pub ring: Address,
    pub auditor: X25519Keypair,
    pub shared: Arc<Shared<S>>,
}

/// Its nonce is spent when the read executes.
struct Grant<'a, S> {
    service: &'a AuditService<S>,
    nonce: [u8; 32],
    timestamp: u64,
    /// The config read at authorization names the rail its frames parse under.
    mode: RingMode,
    scope: ReadScope,
    _reader: ReaderPermit<'a>,
}

pub(crate) struct AuthorizedRead<'a, S> {
    grant: Grant<'a, S>,
    page: &'a Page,
}

struct AuthorizedUtxos<'a, S> {
    grant: Grant<'a, S>,
    utxo_hashes: &'a [Hash],
}

#[must_use]
pub struct AuditRead<'a> {
    pub read: PagedRead,
    pub auth: &'a ReadAuth,
    pub page: &'a Page,
    /// Narrows the read to one wallet's rows.
    pub wallet: Option<Address>,
}

#[derive(Clone, Copy)]
struct BoundTransaction<'a> {
    transaction: &'a spr_client::ShieldedTransaction,
    origin: &'a RingOrigin,
    known: &'a dyn KnownUtxos,
    keys: &'a dyn EscrowedKeys,
    mode: RingMode,
}

struct AuditedRows {
    items: Vec<DecryptedTransaction>,
    skipped: Vec<SkippedTransaction>,
    /// The first failure a retry can change, the backfill stops on it and a page read goes on.
    unfinished: Option<AuditError>,
}

impl Page {
    pub fn new(cursor: Option<Base64String>, limit: Option<Limit>) -> Result<Self, RingRpcError> {
        if cursor
            .as_ref()
            .is_some_and(|cursor| !cursor_in_bounds(&cursor.0))
            || limit.as_ref().is_some_and(|limit| !limit_in_bounds(limit))
        {
            return Err(RingRpcError::InvalidPage);
        }
        let count = limit.as_ref().map_or(AUDIT_PAGE_LIMIT, Limit::value);
        let history = cursor
            .as_ref()
            .map(|cursor| HistoryCursor::try_from(cursor.0.as_slice()))
            .transpose()
            .map_err(|_| RingRpcError::InvalidPage)?;
        Ok(Self {
            cursor,
            history,
            limit: u32::try_from(count)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or(RingRpcError::InvalidPage)?,
            attested_limit: limit,
        })
    }

    pub fn history_cursor(&self) -> Option<HistoryCursor> {
        self.history
    }

    fn position(&self, query: HistoryQuery) -> Result<HistoryPosition, RingRpcError> {
        query
            .position(self.history)
            .map_err(|_| RingRpcError::InvalidPage)
    }

    pub fn limit(&self) -> NonZeroU32 {
        self.limit
    }
}

impl<S> AuditServiceInit<S> {
    pub(crate) fn build(self) -> AuditService<S> {
        AuditService {
            ring: self.ring,
            view_tag: auditor_view_tag(&self.auditor.pubkey()),
            auditor: self.auditor,
            shared: self.shared,
        }
    }
}

impl<S: TransactionSource> AuditService<S> {
    pub fn ring(&self) -> Address {
        self.ring
    }

    pub fn auditor_pubkey(&self) -> X25519Pubkey {
        self.auditor.pubkey()
    }

    pub fn auditor_view_tag(&self) -> [u8; 32] {
        self.view_tag
    }

    /// Opened from the verified escrow record, never kept past one merge.
    pub(crate) fn escrowed_nullifier_key(
        &self,
        owner_key: &[u8; 32],
    ) -> Result<Option<NullifierKey>, RingRpcError> {
        let Some(escrowed) = self.shared.store(self.ring).escrowed(owner_key) else {
            return Ok(None);
        };
        let key = escrowed
            .sealed
            .open(&self.auditor)
            .map_err(|_| RingRpcError::EscrowedKey)?;
        if key.pubkey()? != escrowed.nullifier_pk {
            return Err(RingRpcError::EscrowedKey);
        }
        Ok(Some(key))
    }

    /// `None` until the config exists, the config then fixes the key forever.
    pub async fn configured_auditor(&self) -> Result<Option<X25519Pubkey>, RingRpcError> {
        let config = self.shared.source.ring_config(self.ring).await?;
        Ok(config.map(|config| config.auditor_pubkey))
    }

    /// `None` unless the ring's config names the auditor key held here.
    pub(crate) async fn served_config(&self) -> Result<Option<RingConfiguration>, RingRpcError> {
        let config = self.shared.source.ring_config(self.ring).await?;
        Ok(config.filter(|config| config.auditor_pubkey == self.auditor.pubkey()))
    }

    pub async fn chain_status(&self) -> Result<RingChainStatus, RingRpcError> {
        Ok(self.shared.source.ring_chain_status(self.ring).await?)
    }

    pub async fn read(
        &self,
        request: AuditRead<'_>,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        self.authorize(request).await?.execute().await
    }

    pub async fn wallet_activity(
        &self,
        request: AuditRead<'_>,
    ) -> Result<GetWalletActivityResponse, RingRpcError> {
        self.authorize(request)
            .await?
            .execute_wallet_activity()
            .await
    }

    /// Reads only the store's finalized state, the response names no other transaction.
    pub async fn wallet_status(
        &self,
        request: &GetWalletStatusRequest,
    ) -> Result<GetWalletStatusResponse, RingRpcError> {
        let cursor = request
            .cursor
            .as_ref()
            .map(|cursor| <[u8; 32]>::try_from(cursor.0.as_slice()))
            .transpose()
            .map_err(|_| RingRpcError::InvalidCursor)?;
        let wallet = request.wallet.0;
        let attestation = WalletStatusAttestation {
            target: self.read_target(),
            wallet,
            cursor: request.cursor.clone(),
        };
        let grant = self
            .grant(&request.auth, &attestation, Some(wallet))
            .await?;
        grant.spend().await?;
        Ok(self
            .shared
            .store(self.ring)
            .wallet_status(WalletStatusQuery {
                wallet,
                after: cursor,
                limit: WALLET_NOTE_PAGE_LIMIT,
            }))
    }

    /// The one read that names an unresolved spend, a reader grant reaches it never.
    pub async fn spend_coverage(
        &self,
        request: &GetSpendCoverageRequest,
    ) -> Result<GetSpendCoverageResponse, RingRpcError> {
        let authority = request.authority.0;
        let now = self.shared.clock.now()?;
        let nonce = WalletCheck {
            wallet: authority,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            signature: &request.signature,
            attestation: &SpendCoverageAttestation {
                target: self.read_target(),
                authority,
            },
            now,
        }
        .decide()?;
        self.shared
            .require_ring_authority(self.ring, authority)
            .await?;
        self.shared
            .replay
            .accept(ReplayCheck {
                ring: self.ring,
                nonce,
                timestamp: request.timestamp,
                now,
            })
            .await?;
        Ok(self.shared.store(self.ring).spend_coverage())
    }

    /// A limited co-signer opens the frame it signs under the served ring's key.
    pub(crate) const fn auditor_keypair(&self) -> &X25519Keypair {
        &self.auditor
    }

    pub async fn audited_utxos(
        &self,
        request: &GetAuditedUtxosRequest,
    ) -> Result<GetAuditedUtxosResponse, RingRpcError> {
        self.authorize_utxos(request).await?.execute().await
    }

    /// The upgrade authority asks before `Initialize`, the policy authority after.
    pub async fn auditor_key_statement(
        &self,
        auth: &AuthorityAuth,
    ) -> Result<Vec<u8>, RingRpcError> {
        let now = self.shared.clock.now()?;
        let AuthorityClaim { authority, nonce } = AuthorityCheck {
            auth,
            ring: self.ring,
            genesis_hash: self.shared.genesis_hash,
            now,
        }
        .decide()?;
        self.shared
            .require_ring_authority(self.ring, authority)
            .await?;
        self.shared
            .replay
            .accept(ReplayCheck {
                ring: self.ring,
                nonce,
                timestamp: auth.timestamp,
                now: self.shared.clock.now()?,
            })
            .await?;
        Ok(AuditorKeyStatement {
            cluster: &self.shared.genesis_hash,
            ring: &self.ring,
            auditor_pubkey: &self.auditor.pubkey(),
            nonce: &nonce,
        }
        .message())
    }

    /// The service's own cluster, key and ring, a reader's signature carries to no other.
    pub(crate) fn read_target(&self) -> ReadTarget {
        ReadTarget {
            cluster: self.shared.genesis_hash,
            service: self.shared.service,
            ring: self.ring,
        }
    }

    pub(crate) async fn authorize<'a>(
        &'a self,
        request: AuditRead<'a>,
    ) -> Result<AuthorizedRead<'a, S>, RingRpcError> {
        let attestation = ReadAttestation {
            read: request.read,
            target: self.read_target(),
            cursor: request.page.cursor.clone(),
            limit: request.page.attested_limit.clone(),
            wallet: request.wallet,
        };
        Ok(AuthorizedRead {
            grant: self
                .grant(request.auth, &attestation, request.wallet)
                .await?,
            page: request.page,
        })
    }

    /// Refuses a count out of bounds before the signature is checked.
    async fn authorize_utxos<'a>(
        &'a self,
        request: &'a GetAuditedUtxosRequest,
    ) -> Result<AuthorizedUtxos<'a, S>, RingRpcError> {
        if !utxo_hashes_in_bounds(&request.utxo_hashes) {
            return Err(RingRpcError::InvalidUtxoRequest);
        }
        let wallet = request.wallet.map(|wallet| wallet.0);
        let attestation = AuditedUtxosAttestation {
            wallet,
            ..AuditedUtxosAttestation::new(self.read_target(), &request.utxo_hashes)
        };
        Ok(AuthorizedUtxos {
            grant: self.grant(&request.auth, &attestation, wallet).await?,
            utxo_hashes: &request.utxo_hashes,
        })
    }

    async fn grant<'a>(
        &'a self,
        auth: &ReadAuth,
        attestation: &impl Attestation,
        wallet: Option<Address>,
    ) -> Result<Grant<'a, S>, RingRpcError> {
        let ReadClaim { reader, nonce } = ReadCheck {
            auth,
            attestation,
            now: self.shared.clock.now()?,
            origins: &self.shared.origins,
        }
        .decide()?;
        let permit = ReaderPermit::acquire(&self.shared.active_readers, (self.ring, reader))?;
        let source = &self.shared.source;
        let config = source
            .ring_config(self.ring)
            .await?
            .ok_or(Unauthorized::NoConfig)?;
        if config.auditor_pubkey != self.auditor.pubkey() {
            return Err(Unauthorized::AuditorKeyMismatch.into());
        }
        let scope = self
            .shared
            .read_scope(GrantQuery {
                ring: self.ring,
                reader,
                wallet,
            })
            .await?;
        Ok(Grant {
            service: self,
            nonce,
            timestamp: auth.timestamp,
            mode: config.mode,
            scope,
            _reader: permit,
        })
    }

    /// Returns the action the store holds for the grant after the write.
    pub async fn set_reader_grant(
        &self,
        request: &SetReaderGrantRequest,
    ) -> Result<ReaderGrantAction, RingRpcError> {
        let Grants::Database(rows) = &self.shared.grants else {
            return Err(GrantRefusal::GrantsInTree.into());
        };
        let reader = <[u8; 34]>::try_from(request.reader.0.as_slice())
            .ok()
            .and_then(|tagged| ReaderKey::from_bytes(tagged).ok())
            .ok_or(Unauthorized::UnknownReaderKey)?;
        let wallet = request.wallet.map(|wallet| wallet.0);
        let signer = match wallet {
            Some(wallet) => wallet,
            None => {
                self.shared
                    .source
                    .ring_config(self.ring)
                    .await?
                    .ok_or(Unauthorized::NoConfig)?
                    .roles
                    .policy
            }
        };
        let attestation = ReaderGrantAttestation {
            target: self.read_target(),
            wallet,
            reader,
            action: request.action,
        };
        let nonce = WalletCheck {
            wallet: signer,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            signature: &request.signature,
            attestation: &attestation,
            now: self.shared.clock.now()?,
        }
        .decide()?;
        self.shared
            .replay
            .accept(ReplayCheck {
                ring: self.ring,
                nonce,
                timestamp: request.timestamp,
                now: self.shared.clock.now()?,
            })
            .await?;
        rows.write(GrantRow {
            pair: GrantPair {
                ring: self.ring,
                wallet,
                reader,
            },
            action: request.action,
            timestamp: request.timestamp,
        })
        .await
    }

    /// Opens the ring's transfers, audited deposits and merges from the durable position.
    pub async fn backfill_utxos(&self) -> Result<(), RingRpcError> {
        let store = self.shared.store(self.ring);
        let Some(config) = self.shared.source.ring_config(self.ring).await? else {
            return Ok(());
        };
        if config.auditor_pubkey != self.auditor.pubkey() {
            return Err(Unauthorized::AuditorKeyMismatch.into());
        }
        self.read_history(&store, config.mode).await
    }

    /// Reads the durable tables once per store, a restart resumes where the last commit stopped.
    async fn load_tables(
        &self,
        store: &AuditStore,
        position: &mut HistoryPosition,
    ) -> Result<(), RingRpcError> {
        let Some(database) = self.shared.database.as_ref() else {
            return Ok(());
        };
        if !store.loads_tables() {
            return Ok(());
        }
        let seal = self.note_seal()?;
        let loaded = LoadSpends {
            db: database.connection(),
            ring: self.ring,
            seal: &seal,
        }
        .load()
        .await?;
        *position = loaded.checkpoint.position;
        store.seed(loaded);
        store.seed_historical(
            SpentIndex {
                conn: database.connection(),
            }
            .rows()
            .await?,
        );
        Ok(())
    }

    fn note_seal(&self) -> Result<NoteSeal, RingRpcError> {
        Ok(NoteSeal::derive(&self.auditor, self.ring)?)
    }

    /// The transaction commits before the mirror moves, a crash replays the page idempotently.
    async fn commit_page(&self, store: &AuditStore, delta: PageDelta) -> Result<(), RingRpcError> {
        if let Some(database) = self.shared.database.as_ref() {
            let seal = self.note_seal()?;
            PageCommit {
                db: database.connection(),
                ring: self.ring,
                seal: &seal,
                delta: &delta,
            }
            .commit()
            .await?;
        }
        store.commit(delta);
        Ok(())
    }

    /// An unreadable secret reads as absent, the note stays `Unknown` until it opens.
    fn open_tracked_key(&self, owner_key: &[u8; 32]) -> Option<NullifierKey> {
        self.escrowed_nullifier_key(owner_key)
            .inspect_err(|error| {
                log::warn!("a tracked key failed to open because {}", redacted(error));
            })
            .ok()
            .flatten()
    }

    /// Moves the position only past a page whose every row applied, a retry reads it again.
    async fn read_history(&self, store: &AuditStore, mode: RingMode) -> Result<(), RingRpcError> {
        let source = &self.shared.source;
        let limit = Page::new(None, None)?.limit();
        let mut position = store.backfill.lock().await;
        self.load_tables(store, &mut position).await?;
        self.retry_unread(store, mode, limit).await?;
        let opener = |owner_key: &[u8; 32]| self.open_tracked_key(owner_key);
        for _ in 0..MAX_BACKFILL_PAGES {
            let response = source
                .ring_history(RingHistoryPage {
                    ring: self.ring,
                    position: *position,
                    limit,
                })
                .await?;
            let mut next = *position;
            let end = next
                .advance(&response, limit.get())
                .map_err(|_| RingRpcError::InvalidIndexerResponse)?;
            self.validate_indexer_response(&response)?;
            // Read after the page, the root every transfer on it proves under is already on chain.
            if let Err(error) = self.refresh_escrow(store).await {
                log::warn!(
                    "tracked key refresh of ring {} failed because {}",
                    self.ring,
                    redacted(&error)
                );
            }
            let mut work = PageWork::new(store, &opener);
            work.late_keys();
            let rows = self.audit_rows(response, mode, &mut work, None).await?;
            if let Some(error) = rows.unfinished {
                return Err(error.into());
            }
            let terminal = match end {
                PageEnd::Terminal(context) => Some(context),
                PageEnd::More => None,
            };
            work.checkpoint(next, terminal);
            self.commit_page(store, work.finish()).await?;
            *position = next;
            if terminal.is_some() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Reads each unreadable frame again at its own slot, the position stays where it is.
    async fn retry_unread(
        &self,
        store: &AuditStore,
        mode: RingMode,
        limit: NonZeroU32,
    ) -> Result<(), RingRpcError> {
        let opener = |owner_key: &[u8; 32]| self.open_tracked_key(owner_key);
        for frame in store.unread_frames().into_iter().take(MAX_RETRIED_FRAMES) {
            let mut position = frame
                .slot
                .checked_sub(1)
                .map_or_else(HistoryPosition::default, HistoryPosition::after_slot);
            for _ in 0..MAX_RETRY_PAGES {
                let response = self
                    .shared
                    .source
                    .ring_history(RingHistoryPage {
                        ring: self.ring,
                        position,
                        limit,
                    })
                    .await?;
                let end = position
                    .advance(&response, limit.get())
                    .map_err(|_| RingRpcError::InvalidIndexerResponse)?;
                self.validate_indexer_response(&response)?;
                let held = response
                    .data
                    .iter()
                    .flat_map(|item| &item.events)
                    .any(|tx| {
                        tx.tx_signature == frame.tx_signature
                            && tx.event_index == Some(frame.event_index)
                    });
                if held {
                    if let Err(error) = self.refresh_escrow(store).await {
                        log::warn!(
                            "tracked key refresh of ring {} failed because {}",
                            self.ring,
                            redacted(&error)
                        );
                    }
                    let mut work = PageWork::new(store, &opener);
                    work.late_keys();
                    let rows = self
                        .audit_rows(response, mode, &mut work, Some(frame))
                        .await?;
                    if let Some(error) = rows.unfinished {
                        return Err(error.into());
                    }
                    self.commit_page(store, work.finish()).await?;
                    break;
                }
                if matches!(end, PageEnd::Terminal(_)) {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Every escrowed key under the records registry's newest root, read again once that root moves.
    async fn refresh_escrow(&self, store: &AuditStore) -> Result<(), RingRpcError> {
        let RecordsTip::Newest(tip) = self.shared.source.records_root(self.ring).await? else {
            return Ok(());
        };
        let root = EscrowRoot {
            registry: tip.registry,
            root: tip.root,
            revision: tip.revision,
        };
        let settled = store
            .escrow_root()
            .is_some_and(|current| current.settles(&root));
        if !settled {
            store.replace_escrow(root, self.rescan_records(tip).await?);
        }
        Ok(())
    }

    /// Every record from leaf 1, each verified under the registry's newest root.
    async fn rescan_records(
        &self,
        tip: StorageTip,
    ) -> Result<HashMap<[u8; 32], EscrowedOwner>, RingRpcError> {
        let mut owners = HashMap::new();
        let mut start_index = Some(1);
        while let Some(start) = start_index {
            let page = self
                .shared
                .source
                .storage_member_records(GetStorageMemberRecordsRequest {
                    registry: tip.registry.into(),
                    expected_root: Hash(tip.root),
                    start_index: start,
                    limit: MAX_RING_MEMBER_PAGE_LIMIT,
                })
                .await?;
            start_index = tip
                .next_page(&page, start)
                .map_err(|_| RingRpcError::InvalidIndexerResponse)?;
            for row in &page.records {
                let opening = RingMemberOpening {
                    present: true,
                    record: row.record.clone(),
                    path: row.path.clone(),
                };
                let member = row.record.member.0;
                if let Some(owner) = escrowed_owner(&opening, &tip.root, &member)? {
                    owners.insert(member, owner);
                }
            }
        }
        Ok(owners)
    }

    fn audit(
        &self,
        bound: BoundTransaction<'_>,
        assets: &RingAssets,
    ) -> Result<AuditedTransaction, AuditError> {
        let trees = bound.origin.event.input_tree_ids(bound.transaction);
        TransactionAudit::new(bound.transaction, bound.origin.audit_stream(bound.mode)?)
            .with_input_trees(&trees)?
            .with_known_utxos(bound.known)
            .with_escrowed_keys(bound.keys)
            .run(&self.auditor, assets)
    }

    /// A page read writes nothing, only the backfill's checkpoint feeds the index.
    async fn decrypted_transactions(
        &self,
        page: &Page,
        mode: RingMode,
    ) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let query = HistoryQuery {
            ring: self.ring,
            stream: HistoryStream::Tags,
        };
        let mut position = page.position(query)?;
        let limit = page.limit();
        let response = self
            .shared
            .source
            .transactions_by_tag(TransactionPage {
                ring: self.ring,
                tag: self.view_tag,
                position,
                limit,
            })
            .await?;
        let _ = position
            .advance(&response, limit.get())
            .map_err(|_| RingRpcError::InvalidIndexerResponse)?;
        self.validate_indexer_response(&response)?;
        let context = response.context;
        let cursor = query.next_cursor(&position).map(Into::into);
        let store = self.shared.store(self.ring);
        let opener = |owner_key: &[u8; 32]| self.open_tracked_key(owner_key);
        let mut work = PageWork::new(&store, &opener);
        let rows = self.audit_rows(response, mode, &mut work, None).await?;
        Ok(GetDecryptedTransactionsResponse {
            context,
            value: DecryptedTransactionsPage {
                items: rows.items,
                skipped: rows.skipped,
                cursor,
            },
        })
    }

    /// Only a row of the served ring meets the shape check, a feature build can publish other shapes.
    fn validate_indexer_response(
        &self,
        response: &GetShieldedTransactionsByTagsResponse,
    ) -> Result<(), RingRpcError> {
        // Compact padding leaves trailing slots out, a transaction publishes at most its shape.
        let unsupported = response
            .data
            .iter()
            .flat_map(|item| &item.events)
            .any(|transaction| {
                transaction.ring_program_id == Some(self.ring)
                    && transaction
                        .messages
                        .iter()
                        .any(|message| message.view_tag == self.view_tag)
                    && (transaction.nullifiers.is_empty()
                        || canonical_shape(
                            transaction.nullifiers.len(),
                            transaction.output_slots.len(),
                        )
                        .is_err())
            });
        if unsupported {
            return Err(RingRpcError::InvalidIndexerResponse);
        }
        Ok(())
    }

    /// Exact inputs keep their hash rows, every nullifier joins the machine.
    fn read_historical(&self, row: HistoricalRow<'_, '_>) {
        let HistoricalRow {
            tx,
            origin,
            mode,
            created_in,
            work,
        } = row;
        let evidence = origin
            .transact
            .as_deref()
            .filter(|_| origin.event.kind() == ConfirmedEventKind::Transfer)
            .map(|transact| historical_evidence(tx, transact, mode, &self.auditor));
        let commitments = match evidence {
            Some(Ok(evidence)) => historical_inputs(work, evidence),
            Some(Err(_)) | None => Vec::new(),
        };
        work.record_historical(spent_rows(SpentEvent {
            created_in,
            first_nullifier: tx.nullifiers.first().copied().unwrap_or_default(),
            source: SpentSource::Historical,
            commitments,
        }));
        observe_all(work, tx, created_in, |_| InputRead::Real { evidence: None });
        work.mark_read(created_in);
    }

    /// The record names the output, its nullifiers mark the inputs through the machine.
    fn read_merge(&self, row: MergeRow<'_, '_>) {
        let MergeRow {
            tx,
            merge,
            created_in,
            work,
        } = row;
        let inputs = merge.inputs.clone();
        observe_all(work, tx, created_in, |position| {
            match inputs.get(usize::from(position)) {
                Some(commitment) => InputRead::Real {
                    evidence: Some(*commitment),
                },
                None => InputRead::Padding,
            }
        });
        match merge_output_note(self.ring, merge, work) {
            Some(note) => {
                work.open(created_in, [note]);
                work.mark_read(created_in);
            }
            None => work.mark_unread(created_in),
        }
    }

    /// `only` narrows a retry to its frame, a read failure leaves the frame to the next pass.
    async fn audit_rows(
        &self,
        response: GetShieldedTransactionsByTagsResponse,
        mode: RingMode,
        work: &mut PageWork<'_>,
        only: Option<CreatedIn>,
    ) -> Result<AuditedRows, RingRpcError> {
        let source = &self.shared.source;
        let store = self.shared.store(self.ring);
        let mut assets = self.shared.due_assets().await;
        store.name_assets(&assets);
        let mut items = Vec::new();
        let mut skipped = Vec::new();
        let mut unfinished = None;
        let mut origins: HashMap<(Signature, u16), RingOrigin> = HashMap::new();
        for mut tx in response.data.into_iter().flat_map(|item| item.events) {
            if tx.ring_program_id != Some(self.ring) {
                continue;
            }
            let event_index = tx.event_index.ok_or(RingRpcError::InvalidIndexerResponse)?;
            if only.is_some_and(|frame| {
                frame.tx_signature != tx.tx_signature || frame.event_index != event_index
            }) {
                continue;
            }
            let created_in = CreatedIn {
                slot: tx.slot,
                tx_signature: tx.tx_signature,
                event_index,
            };
            let origin = match origins.get(&(tx.tx_signature, event_index)) {
                Some(known) => known.clone(),
                None => {
                    match source
                        .transaction_origin(tx.tx_signature, event_index, self.ring)
                        .await
                    {
                        Ok(found) => {
                            origins.insert((tx.tx_signature, event_index), found.clone());
                            found
                        }
                        Err(error) if error.disposition() == RowDisposition::Retry => {
                            return Err(error.into())
                        }
                        Err(error) => {
                            log::warn!(
                                "ring {} event {}:{event_index} has no readable origin because {}",
                                self.ring,
                                tx.tx_signature,
                                redacted(&error)
                            );
                            work.mark_unread(created_in);
                            skipped.push(SkippedTransaction {
                                slot: tx.slot,
                                tx_signature: tx.tx_signature.into(),
                                event_index,
                                reason: SkippedReason::InvalidAuditData,
                            });
                            continue;
                        }
                    }
                }
            };
            if !origin.ring_invoked {
                continue;
            }
            let bound = origin.bind_transaction(&mut tx, self.ring);
            if bound.is_ok() {
                if origin.is_historical() {
                    self.read_historical(HistoricalRow {
                        tx: &tx,
                        origin: &origin,
                        mode,
                        created_in,
                        work,
                    });
                    continue;
                }
                if origin.event.kind() == ConfirmedEventKind::Merge {
                    match confirmed_merge(&tx, event_index, &origin, &self.auditor) {
                        Ok(Some(merge)) => self.read_merge(MergeRow {
                            tx: &tx,
                            merge,
                            created_in,
                            work,
                        }),
                        Ok(None) => {
                            observe_all(work, &tx, created_in, |_| InputRead::Real {
                                evidence: None,
                            });
                            work.mark_read(created_in);
                        }
                        Err(error) if error.disposition() == RowDisposition::Retry => {
                            unfinished.get_or_insert(error);
                        }
                        Err(error) => {
                            log::warn!(
                                "ring {} merge {}:{event_index} is unreadable because {}",
                                self.ring,
                                tx.tx_signature,
                                redacted(&error)
                            );
                            observe_all(work, &tx, created_in, |_| InputRead::Unreadable);
                            work.mark_unread(created_in);
                        }
                    }
                    continue;
                }
            }
            if !origin.requires_audit() {
                // A later commitment layout spends a deposited or merged UTXO by hash or prefix.
                let created = bound.and_then(|()| {
                    CreatedUtxos {
                        transaction: &tx,
                        origin: &origin,
                        ring: self.ring,
                    }
                    .open_for(&self.auditor, &*store)
                });
                match created {
                    Ok(created) => {
                        observe_all(work, &tx, created_in, |_| InputRead::Real {
                            evidence: None,
                        });
                        work.open(created_in, created.utxos);
                        match mode {
                            // Only an escrow ring's retry names an unowned deposit.
                            RingMode::ConfidentialEscrow if !created.unowned.is_empty() => {
                                work.mark_unread(created_in);
                            }
                            RingMode::ConfidentialEscrow => work.mark_read(created_in),
                            RingMode::Confidential | RingMode::Anonymous => {
                                work.open(
                                    created_in,
                                    created.unowned.iter().map(DepositNote::deposited),
                                );
                                work.mark_read(created_in);
                            }
                        }
                    }
                    Err(error) => {
                        log::warn!(
                            "ring {} event {}:{event_index} opened no UTXOs because {}",
                            self.ring,
                            tx.tx_signature,
                            redacted(&error)
                        );
                        if error.disposition() == RowDisposition::Retry {
                            unfinished.get_or_insert(error);
                        } else {
                            work.mark_unread(created_in);
                        }
                    }
                }
                continue;
            }
            let mut opened = bound.and_then(|()| {
                self.audit(
                    BoundTransaction {
                        transaction: &tx,
                        origin: &origin,
                        known: &*work,
                        keys: &*store,
                        mode,
                    },
                    &assets,
                )
            });
            // A mint registered inside the refresh interval misses the cache.
            if opened
                .as_ref()
                .is_ok_and(AuditedTransaction::has_unknown_assets)
            {
                let fresh = self.shared.assets_after_miss().await;
                if fresh != assets {
                    assets = fresh;
                    store.name_assets(&assets);
                    opened = opened.and_then(|mut opened| {
                        opened.resolve(&*store, &assets)?;
                        Ok(opened)
                    });
                }
            }
            if let Ok(opened) = &opened {
                work.open(created_in, opened.utxos());
                for (position, input) in opened.inputs.iter().enumerate() {
                    work.observe(Observation {
                        nullifier: input.nullifier,
                        frame: created_in,
                        position: u16::try_from(position).unwrap_or(u16::MAX),
                        read: audited_input_read(input),
                        hit: None,
                    });
                }
                match opened.unresolved.is_empty() {
                    true => work.mark_read(created_in),
                    // A slot awaits its key, the frame reads again with it.
                    false => work.mark_unread(created_in),
                }
            }
            let result = opened.and_then(|opened| Ok((opened, origin.spenders(mode)?)));
            match result {
                Ok((opened, spenders)) => items.push(
                    ConfirmedAudit {
                        audited: opened,
                        event_index,
                        nullifiers: tx.nullifiers,
                        spenders,
                        signers: origin.signers,
                        withdrawals: origin.withdrawals,
                    }
                    .into(),
                ),
                Err(error) => {
                    if error.disposition() != RowDisposition::Retry {
                        if origin_is_bound(&origin, &tx) {
                            observe_all(work, &tx, created_in, |_| InputRead::Unreadable);
                        }
                        work.mark_unread(created_in);
                    }
                    skipped.push(SkippedTransaction {
                        slot: tx.slot,
                        tx_signature: tx.tx_signature.into(),
                        event_index,
                        reason: match error {
                            AuditError::MissingAuditorMessage => {
                                SkippedReason::MissingAuditorMessage
                            }
                            _ => SkippedReason::InvalidAuditData,
                        },
                    });
                    if error.disposition() == RowDisposition::Retry {
                        unfinished.get_or_insert(error);
                    }
                }
            }
        }
        Ok(AuditedRows {
            items,
            skipped,
            unfinished,
        })
    }
}

impl<S> Grant<'_, S> {
    /// The clock is read again, a nonce evicted while the read awaited stays spent.
    async fn spend(&self) -> Result<(), RingRpcError> {
        let service = self.service;
        service
            .shared
            .replay
            .accept(ReplayCheck {
                ring: service.ring,
                nonce: self.nonce,
                timestamp: self.timestamp,
                now: service.shared.clock.now()?,
            })
            .await
    }
}

impl<S: TransactionSource> AuthorizedRead<'_, S> {
    pub(crate) async fn execute(self) -> Result<GetDecryptedTransactionsResponse, RingRpcError> {
        let ReadScope::Ring = self.grant.scope else {
            return Err(GrantRefusal::WalletScope.into());
        };
        let service = self.grant.service;
        self.grant.spend().await?;
        service
            .decrypted_transactions(self.page, self.grant.mode)
            .await
    }

    pub(crate) async fn execute_wallet_activity(
        self,
    ) -> Result<GetWalletActivityResponse, RingRpcError> {
        let ReadScope::Wallet(scope) = self.grant.scope else {
            return Err(GrantRefusal::WalletScope.into());
        };
        let service = self.grant.service;
        self.grant.spend().await?;
        let response = service
            .decrypted_transactions(self.page, self.grant.mode)
            .await?;
        Ok(scope.activity(response, &service.shared.store(service.ring)))
    }

    pub(crate) async fn execute_merges(self) -> Result<GetAuditedMergesResponse, RingRpcError> {
        let service = self.grant.service;
        self.grant.spend().await?;
        let page = service
            .shared
            .source
            .merge_audit_page(MergeAuditRequest {
                ring: service.ring,
                auditor: &service.auditor,
                page: self.page,
            })
            .await
            .map_err(|error| match error {
                AuditError::InvalidHistoryPage => RingRpcError::InvalidIndexerResponse,
                AuditError::HistoryCursor(_) => RingRpcError::InvalidPage,
                error => error.into(),
            })?;
        let store = service.shared.store(service.ring);
        let mut value = AuditedMergesPage {
            opened: Vec::new(),
            unresolved: Vec::new(),
            cursor: page.next_cursor.map(Into::into),
        };
        for merge in page.merges {
            // A merge the checkpoint has not opened stays out, no reader learns it is unresolved.
            if let Some(output) = store.merge_output(&merge) {
                value.opened.push((&output).into());
            }
        }
        self.grant.scope.merges(&mut value);
        Ok(GetAuditedMergesResponse {
            context: page.context,
            value,
        })
    }
}

impl<S: TransactionSource> AuthorizedUtxos<'_, S> {
    /// The store answers alone, a UTXO no page or backfill opened yet reads `null`.
    async fn execute(self) -> Result<GetAuditedUtxosResponse, RingRpcError> {
        let service = self.grant.service;
        self.grant.spend().await?;
        let store = service.shared.store(service.ring);
        Ok(GetAuditedUtxosResponse {
            context: store.context(),
            value: AuditedUtxosPage {
                utxos: self
                    .utxo_hashes
                    .iter()
                    .map(|hash| self.grant.scope.utxo(store.view(hash)))
                    .collect(),
            },
        })
    }
}

/// The escrowed key of a record verified under `root`, `None` while its member holds none.
fn escrowed_owner(
    opening: &RingMemberOpening,
    root: &[u8; 32],
    member: &[u8; 32],
) -> Result<Option<EscrowedOwner>, RingRpcError> {
    let invalid = |_| RingRpcError::InvalidIndexerResponse;
    let read = MemberOpeningRead::verify(opening, root, member).map_err(invalid)?;
    let Some(owner) = read.owner_pubkey else {
        return Ok(None);
    };
    let Some(nullifier_pk) = read.nullifier_pk else {
        return Ok(None);
    };
    let Some(sealed) = read.sealed else {
        return Ok(None);
    };
    // The record binds the owner key through its member identity.
    let bound = Member::owner_tag(owner.as_array()).is_ok_and(|tag| tag.as_bytes() == member);
    let escrowed = read.escrowed(&nullifier_pk).map_err(invalid)?;
    if escrowed.is_none() || !bound {
        return Err(RingRpcError::InvalidIndexerResponse);
    }
    Ok(Some(EscrowedOwner {
        owner_key: owner.to_bytes(),
        nullifier_pk,
        owner_hash: owner_hash(&PublicKey::from_ed25519(owner.as_array()), &nullifier_pk)?,
        sealed,
    }))
}

/// A confirmed row of a frame the v3 path never decodes.
struct HistoricalRow<'a, 'w> {
    tx: &'a ShieldedTransaction,
    origin: &'a RingOrigin,
    mode: RingMode,
    created_in: CreatedIn,
    work: &'a mut PageWork<'w>,
}

struct MergeRow<'a, 'w> {
    tx: &'a ShieldedTransaction,
    merge: ConfirmedMerge,
    created_in: CreatedIn,
    work: &'a mut PageWork<'w>,
}

fn observe_all(
    work: &mut PageWork<'_>,
    tx: &ShieldedTransaction,
    created_in: CreatedIn,
    read: impl Fn(u16) -> InputRead,
) {
    for (position, nullifier) in tx.nullifiers.iter().enumerate() {
        let position = u16::try_from(position).unwrap_or(u16::MAX);
        work.observe(Observation {
            nullifier: *nullifier,
            frame: created_in,
            position,
            read: read(position),
            hit: None,
        });
    }
}

/// A hash-bearing frame names its input, a default-ring opening is no note of this ring.
fn audited_input_read(input: &AuditedInput) -> InputRead {
    match &input.opening {
        InputOpening::Dummy => InputRead::Padding,
        InputOpening::Opened(opening)
            if matches!(opening.ring, Some(InputRing::Default { .. })) =>
        {
            InputRead::External
        }
        InputOpening::Opened(_) | InputOpening::Merged(_) | InputOpening::UnseenHash { .. } => {
            InputRead::Real {
                evidence: Some(input.hash),
            }
        }
    }
}

/// Only a row bound to its confirmed event publishes nullifiers.
fn origin_is_bound(origin: &RingOrigin, tx: &ShieldedTransaction) -> bool {
    let mut bound = tx.clone();
    origin
        .bind_transaction(&mut bound, tx.ring_program_id.unwrap_or_default())
        .is_ok()
}

/// The output of a merge with every input opened, its blinding derives from the owner's secret.
fn merge_output_note(
    ring: Address,
    merge: ConfirmedMerge,
    work: &mut PageWork<'_>,
) -> Option<CreatedUtxo> {
    let (commitment, leaf_index) = (merge.output_commitment, merge.leaf_index);
    let output: AuditedMergeOutput = MergeLedger::default()
        .apply(merge, |input| {
            work.note(input).map(|note| MergeInput::from(&note.utxo))
        })
        .resolved
        .pop()?;
    let key = match output.owner {
        UtxoOwner::Keyed { nullifier_pk } if nullifier_pk == ZERO_NULLIFIER_PUBKEY => {
            NullifierKey::from_secret([0; 31])
        }
        _ => work.open_key(&output.owner_key)?,
    };
    let utxo = output.opening(ring, &key).ok().flatten()?;
    Some(CreatedUtxo {
        commitment,
        slot_index: 0,
        leaf_index,
        utxo,
        ring_note: true,
    })
}

/// The row's exact inputs, an ambiguous or unnamed input stays out.
fn historical_inputs(work: &PageWork<'_>, evidence: HistoricalEvidence) -> Vec<[u8; 32]> {
    let assigned = |prefixes: &[Option<InputPrefix>], owner: Option<[u8; 32]>| {
        assign_prefixed_inputs(prefixes, |prefix| work.prefixed(prefix, owner))
    };
    let (mut exact, assignments) = match evidence {
        HistoricalEvidence::Unnamed => return Vec::new(),
        HistoricalEvidence::Prefixes(prefixes) => (Vec::new(), assigned(&prefixes, None)),
        HistoricalEvidence::Commitments { first, prefixes } => {
            let owner = work.note(&first).map(|note| note.utxo.owner_key);
            (vec![first], assigned(&prefixes, owner))
        }
    };
    for assignment in assignments {
        if let PrefixAssignment::Exact(commitment) = assignment {
            exact.push(commitment);
        }
    }
    exact
}

struct SpentEvent {
    created_in: CreatedIn,
    first_nullifier: [u8; 32],
    source: SpentSource,
    commitments: Vec<[u8; 32]>,
}

fn spent_rows(event: SpentEvent) -> Vec<SpentCommitment> {
    let SpentEvent {
        created_in,
        first_nullifier,
        source,
        commitments,
    } = event;
    commitments
        .into_iter()
        .map(|utxo_hash| SpentCommitment {
            utxo_hash,
            slot: created_in.slot,
            tx_signature: created_in.tx_signature,
            event_index: created_in.event_index,
            first_nullifier,
            source,
        })
        .collect()
}
