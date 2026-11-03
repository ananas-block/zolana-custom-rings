use std::{collections::HashMap, num::NonZeroU32, sync::Arc, time::Duration};

use custom_ring_interface::RingMode;
use solana_address::Address;
use solana_signature::Signature;
use spr_client::GetShieldedTransactionsByTagsResponse;
use spr_indexer_api::{Base64String, Hash, Limit};
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
        GetUnspentUtxosRequest, GetUnspentUtxosResponse, GetWalletActivityResponse, PagedRead,
        ReadAttestation, ReadAuth, ReadTarget, ReaderGrantAction, ReaderGrantAttestation,
        RingChainStatus, SetReaderGrantRequest, SkippedReason, SkippedTransaction,
        UnresolvedMergeRecord, UnresolvedReason, UnspentUtxosAttestation, AUDIT_PAGE_LIMIT,
    },
    AuditError, AuditedTransaction, ConfirmedEventKind, ConfirmedMerge, CreatedUtxos, DepositNote,
    HistoricalEvidence, ReaderKey, RingOrigin, RowDisposition, TransactionAudit,
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
    database::Store,
    error::{redacted, GrantRefusal, RingRpcError},
    grant_rows::{GrantPair, GrantRow},
    grants::{GrantQuery, Grants, ReadScope},
    hub::Shared,
    limits::ReaderPermit,
    replay::ReplayCheck,
    spent_index::{SpentCommitment, SpentIndex, SpentSource},
    upstream::{
        MergeAuditRequest, RecordsTip, RingConfiguration, RingHistoryPage, TransactionPage,
        TransactionSource,
    },
    utxos::{
        AuditStore, CreatedIn, EscrowRoot, EscrowedOwner, HeldNote, UnnamedSpend, UnspentQuery,
        MAX_BACKFILL_PAGES,
    },
};

const UNSPENT_PAGE_LIMIT: usize = 100;
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
    store: &'a AuditStore,
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

    pub async fn unspent_utxos(
        &self,
        request: &GetUnspentUtxosRequest,
    ) -> Result<GetUnspentUtxosResponse, RingRpcError> {
        let cursor = request
            .cursor
            .as_ref()
            .map(|cursor| <[u8; 32]>::try_from(cursor.0.as_slice()))
            .transpose()
            .map_err(|_| RingRpcError::InvalidCursor)?;
        let wallet = request.wallet.map(|wallet| wallet.0);
        let attestation = UnspentUtxosAttestation {
            target: self.read_target(),
            owner: request.owner.0,
            cursor: request.cursor.clone(),
            wallet,
        };
        let grant = self.grant(&request.auth, &attestation, wallet).await?;
        if !grant.scope.covers_member(&request.owner.0) {
            return Err(GrantRefusal::WalletScope.into());
        }
        grant.spend().await?;
        let store = self.shared.store(self.ring);
        let page = grant.scope.unspent(store.unspent(UnspentQuery {
            owner: &request.owner.0,
            after: cursor,
            limit: UNSPENT_PAGE_LIMIT,
        }));
        Ok(GetUnspentUtxosResponse {
            utxos: page.utxos,
            coverage: page.coverage,
            unresolved: page.unresolved,
            cursor: page.cursor.map(|cursor| cursor.to_vec().into()),
        })
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

    /// Opens the ring's transfers, audited deposits and merges from the store's resume point.
    pub async fn backfill_utxos(&self) -> Result<(), RingRpcError> {
        let store = self.shared.store(self.ring);
        let outcome = async {
            let Some(config) = self.shared.source.ring_config(self.ring).await? else {
                store.pass_unfinished();
                return Ok(());
            };
            if config.auditor_pubkey != self.auditor.pubkey() {
                return Err(Unauthorized::AuditorKeyMismatch.into());
            }
            self.read_history(&store, config.mode).await
        }
        .await;
        if outcome.is_err() {
            store.pass_unfinished();
        }
        outcome
    }

    /// Moves the position only past a page whose every row applied, a retry reads it again.
    async fn read_history(&self, store: &AuditStore, mode: RingMode) -> Result<(), RingRpcError> {
        let source = &self.shared.source;
        let limit = Page::new(None, None)?.limit();
        let mut position = store.backfill.lock().await;
        if let Some(database) = self
            .shared
            .database
            .as_ref()
            .filter(|_| store.seeds_spent())
        {
            let rows = SpentIndex {
                conn: database.connection(),
            }
            .rows()
            .await?;
            store.spend_commitments(rows);
        }
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
            if mode == RingMode::ConfidentialEscrow {
                if let Err(error) = self.refresh_escrow(store).await {
                    log::warn!(
                        "escrow refresh of ring {} failed because {}",
                        self.ring,
                        redacted(&error)
                    );
                }
            }
            let rows = self.audit_rows(response, mode, store).await?;
            if let Some(error) = rows.unfinished {
                return Err(error.into());
            }
            *position = next;
            if let PageEnd::Terminal(context) = end {
                store.absorbed(context);
                return Ok(());
            }
        }
        store.pass_unfinished();
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
            .with_known_utxos(bound.store)
            .with_escrowed_keys(bound.store)
            .run(&self.auditor, assets)
    }

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
        let rows = self
            .audit_rows(response, mode, &self.shared.store(self.ring))
            .await?;
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

    /// Exact inputs join the index, an ambiguous or unnamed one holds the row unresolved.
    async fn read_historical(&self, row: HistoricalRow<'_>) -> Result<(), RingRpcError> {
        let HistoricalRow {
            tx,
            origin,
            mode,
            created_in,
            store,
        } = row;
        let evidence = origin
            .transact
            .as_deref()
            .filter(|_| origin.event.kind() == ConfirmedEventKind::Transfer)
            .map(|transact| historical_evidence(tx, transact, mode, &self.auditor));
        let (commitments, complete) = match evidence {
            Some(Ok(evidence)) => historical_inputs(store, evidence),
            // A historical merge's list stays unread, its row holds the claim false.
            Some(Err(_)) | None => (Vec::new(), false),
        };
        record_spent(
            self.shared.database.as_ref(),
            store,
            spent_rows(SpentEvent {
                created_in,
                first_nullifier: tx.nullifiers.first().copied().unwrap_or_default(),
                source: SpentSource::Historical,
                commitments,
            }),
        )
        .await?;
        if !complete {
            store.hold_unnamed(
                created_in,
                UnnamedSpend::of(UnresolvedReason::HistoricalPrefix),
            );
        }
        Ok(())
    }

    /// Every opened UTXO enters `store` before the next row, a later input resolves through it.
    async fn audit_rows(
        &self,
        response: GetShieldedTransactionsByTagsResponse,
        mode: RingMode,
        store: &AuditStore,
    ) -> Result<AuditedRows, RingRpcError> {
        let source = &self.shared.source;
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
                            store.hold_unnamed(
                                CreatedIn {
                                    slot: tx.slot,
                                    tx_signature: tx.tx_signature,
                                    event_index,
                                },
                                UnnamedSpend::of(UnresolvedReason::UnreadableRow),
                            );
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
            let created_in = CreatedIn {
                slot: tx.slot,
                tx_signature: tx.tx_signature,
                event_index,
            };
            // A confirmed spend holds even when its outputs cannot open yet.
            if bound.is_ok() {
                store.spend(tx.nullifiers.iter().copied());
                store.saw_row(tx.slot, origin.is_historical());
                if origin.is_historical() {
                    self.read_historical(HistoricalRow {
                        tx: &tx,
                        origin: &origin,
                        mode,
                        created_in,
                        store,
                    })
                    .await?;
                    continue;
                }
                if origin.event.kind() == ConfirmedEventKind::Merge {
                    match confirmed_merge(&tx, event_index, &origin, &self.auditor) {
                        Ok(merge) => {
                            if let Some(merge) = merge {
                                apply_confirmed_merge(self.shared.database.as_ref(), store, merge)
                                    .await?;
                                store.remember_merge(&tx)?;
                            }
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
                            store.hold_unnamed(
                                created_in,
                                UnnamedSpend::of(UnresolvedReason::UnreadableRow),
                            );
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
                    .open_for(&self.auditor, store)
                });
                match created {
                    Ok(created) => {
                        store.record(created_in, created.utxos);
                        match mode {
                            // Only an escrow ring's backfill names a held owner.
                            RingMode::ConfidentialEscrow => store.hold(
                                created_in,
                                created.unowned.into_iter().map(HeldNote::Deposit),
                            ),
                            RingMode::Confidential | RingMode::Anonymous => store.record(
                                created_in,
                                created.unowned.iter().map(DepositNote::deposited),
                            ),
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
                            store.hold_unnamed(
                                created_in,
                                UnnamedSpend::of(UnresolvedReason::UnreadableRow),
                            );
                        }
                    }
                }
                continue;
            }
            let audit = BoundTransaction {
                transaction: &tx,
                origin: &origin,
                store,
                mode,
            };
            let mut opened = bound.and_then(|()| self.audit(audit, &assets));
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
                        opened.resolve(store, &assets)?;
                        Ok(opened)
                    });
                }
            }
            if let Ok(opened) = &opened {
                store.record(created_in, opened.utxos());
                store.hold(
                    created_in,
                    opened.unresolved.iter().cloned().map(HeldNote::Output),
                );
                let unseen: Vec<[u8; 32]> = opened
                    .inputs
                    .iter()
                    .filter(|input| input.opening.is_unseen())
                    .map(|input| input.hash)
                    .collect();
                if !unseen.is_empty() {
                    store.hold_unnamed(
                        created_in,
                        UnnamedSpend {
                            reason: UnresolvedReason::UnknownSpend,
                            inputs: unseen,
                        },
                    );
                }
                record_spent(
                    self.shared.database.as_ref(),
                    store,
                    spent_rows(SpentEvent {
                        created_in,
                        first_nullifier: tx.nullifiers.first().copied().unwrap_or_default(),
                        source: SpentSource::Transfer,
                        commitments: opened
                            .inputs
                            .iter()
                            .map(|input| input.hash)
                            .filter(|hash| *hash != [0; 32])
                            .collect(),
                    }),
                )
                .await?;
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
                        store.hold_unnamed(
                            created_in,
                            UnnamedSpend::of(UnresolvedReason::UnreadableRow),
                        );
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
        Ok(scope.activity(response))
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
            let output_commitment = merge.output_commitment;
            let record = UnresolvedMergeRecord::from(&merge);
            apply_confirmed_merge(service.shared.database.as_ref(), &store, merge).await?;
            match store.merged(&output_commitment) {
                Some(output) => value.opened.push((&output).into()),
                None => value.unresolved.push(record),
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
struct HistoricalRow<'a> {
    tx: &'a ShieldedTransaction,
    origin: &'a RingOrigin,
    mode: RingMode,
    created_in: CreatedIn,
    store: &'a AuditStore,
}

/// The row's exact inputs, and whether it named every input it spent.
fn historical_inputs(store: &AuditStore, evidence: HistoricalEvidence) -> (Vec<[u8; 32]>, bool) {
    let assigned = |prefixes: &[Option<InputPrefix>], owner: Option<[u8; 32]>| {
        assign_prefixed_inputs(prefixes, |prefix| store.prefixed(prefix, owner))
    };
    let (mut exact, assignments) = match evidence {
        HistoricalEvidence::Unnamed => return (Vec::new(), false),
        HistoricalEvidence::Prefixes(prefixes) => (Vec::new(), assigned(&prefixes, None)),
        HistoricalEvidence::Commitments { first, prefixes } => {
            let owner = store.note_owner(&first);
            (vec![first], assigned(&prefixes, owner))
        }
    };
    let mut complete = true;
    for assignment in assignments {
        match assignment {
            PrefixAssignment::Dummy => {}
            PrefixAssignment::Exact(commitment) => exact.push(commitment),
            PrefixAssignment::Ambiguous { .. } | PrefixAssignment::Unseen { .. } => {
                complete = false;
            }
        }
    }
    (exact, complete)
}

/// The row commits before the mirror, a failed write leaves the page to run again.
async fn record_spent(
    database: Option<&Store>,
    store: &AuditStore,
    rows: Vec<SpentCommitment>,
) -> Result<(), RingRpcError> {
    if let Some(database) = database {
        SpentIndex {
            conn: database.connection(),
        }
        .record(&rows)
        .await?;
    }
    store.spend_commitments(rows);
    Ok(())
}

/// The inputs commit before the ledger applies the merge, a replay of an applied merge does nothing.
async fn apply_confirmed_merge(
    database: Option<&Store>,
    store: &AuditStore,
    merge: ConfirmedMerge,
) -> Result<(), RingRpcError> {
    record_spent(
        database,
        store,
        spent_rows(SpentEvent {
            created_in: CreatedIn {
                slot: merge.slot,
                tx_signature: merge.tx_signature,
                event_index: merge.event_index,
            },
            first_nullifier: merge.first_nullifier,
            source: SpentSource::Merge,
            commitments: merge.inputs.clone(),
        }),
    )
    .await?;
    store.apply_merge(merge);
    Ok(())
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

#[cfg(test)]
#[path = "merge_successor_tests.rs"]
mod merge_successor_tests;

#[cfg(test)]
mod tests {
    use spr_keypair::ViewingKey;
    use zolana_ring_client::ConfirmedMerge;

    use super::*;
    use crate::{
        managed_merge::tests::{Fixture, RING},
        upstream::origin_fixture,
    };

    fn row(signature: u8, nullifier: u8) -> ShieldedTransaction {
        ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::from([signature; 64]),
            event_index: Some(0),
            tx_viewing_pk: Some(ViewingKey::from_bytes(&[signature; 32]).pubkey()),
            salt: Some([signature; 16]),
            output_slots: Vec::new(),
            messages: Vec::new(),
            nullifiers: vec![[nullifier; 32]],
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }

    fn origin_of(confirmed: &ShieldedTransaction, ring_invoked: bool) -> RingOrigin {
        RingOrigin {
            ring_invoked,
            event: origin_fixture::event(confirmed),
            signers: Vec::new(),
            withdrawals: Vec::new(),
            deposits: Vec::new(),
            merge_disclosure: None,
            transact: None,
            pool_accounts: Vec::new(),
        }
    }

    #[tokio::test]
    async fn only_a_confirmed_event_marks_a_note_spent() {
        let fixture = Fixture::serving(None, None).await;
        let shared = fixture.hub.shared();
        let forged = row(1, 9);
        let foreign = row(2, 8);
        let confirmed = row(3, 7);
        {
            let mut origins = shared.source.origins.lock().expect("origins");
            origins.insert(forged.tx_signature, origin_of(&row(1, 6), true));
            origins.insert(foreign.tx_signature, origin_of(&foreign, false));
            origins.insert(confirmed.tx_signature, origin_of(&confirmed, true));
        }
        let service = fixture.hub.service(None).expect("service");
        let store = shared.store(RING);
        let rows = service
            .audit_rows(
                GetShieldedTransactionsByTagsResponse {
                    context: spr_client::Context {
                        slot: 1,
                        block_time: 1,
                    },
                    data: [forged, foreign, confirmed]
                        .into_iter()
                        .map(|row| spr_client::rpc::TransactionEvents {
                            slot: row.slot,
                            signature: row.tx_signature,
                            events: vec![row],
                        })
                        .collect(),
                    pagination_token: None,
                    output_tree_id: None,
                },
                RingMode::ConfidentialEscrow,
                &store,
            )
            .await
            .expect("rows");
        assert!(!store.is_spent(&[9; 32]), "the rejected row");
        assert!(!store.is_spent(&[6; 32]), "the rejected row's event");
        assert!(!store.is_spent(&[8; 32]), "the ring never ran");
        // The row names no ring frame, its outputs cannot open.
        assert!(store.is_spent(&[7; 32]));
        let skipped: Vec<_> = rows.skipped.iter().map(|row| row.tx_signature.0).collect();
        assert_eq!(
            skipped,
            [Signature::from([1; 64]), Signature::from([3; 64])]
        );
        assert!(rows.unfinished.is_none());
    }

    fn two_input_merge() -> ConfirmedMerge {
        ConfirmedMerge {
            slot: 7,
            tx_signature: Signature::from([7; 64]),
            event_index: 0,
            output_commitment: [0x20; 32],
            tree_id: 1,
            leaf_index: 3,
            first_nullifier: [9; 32],
            inputs: vec![[1; 32], [2; 32]],
        }
    }

    async fn rename_spent_table(database: &Store, from: &str, to: &str) {
        use sea_orm::ConnectionTrait;
        database
            .connection()
            .execute_unprepared(&format!("ALTER TABLE {from} RENAME TO {to}"))
            .await
            .expect("rename");
    }

    #[tokio::test]
    async fn a_failed_spent_write_leaves_a_merge_to_a_retry_that_repairs_every_input() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = AuditStore::default();
        let merge = two_input_merge();
        rename_spent_table(&database, "spent_commitments", "parked").await;
        assert!(
            apply_confirmed_merge(Some(&database), &store, merge.clone())
                .await
                .is_err()
        );
        assert!(store.spent_commitment(&[1; 32]).is_none());
        rename_spent_table(&database, "parked", "spent_commitments").await;
        apply_confirmed_merge(Some(&database), &store, merge.clone())
            .await
            .expect("retry");
        for input in &merge.inputs {
            assert!(store.spent_commitment(input).is_some());
        }
        let rows = SpentIndex {
            conn: database.connection(),
        }
        .rows()
        .await
        .expect("rows");
        assert_eq!(rows.len(), merge.inputs.len());

        // A restart seeds the mirror and replays into a fresh ledger, the first event keeps its rows.
        let restarted = AuditStore::default();
        restarted.spend_commitments(rows.clone());
        for input in &merge.inputs {
            assert!(restarted.spent_commitment(input).is_some());
        }
        apply_confirmed_merge(Some(&database), &restarted, merge)
            .await
            .expect("replay");
        let replayed = SpentIndex {
            conn: database.connection(),
        }
        .rows()
        .await
        .expect("rows");
        assert_eq!(replayed.len(), rows.len());
    }

    #[tokio::test]
    async fn a_merge_lost_to_a_restart_before_its_write_replays_every_input() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let merge = two_input_merge();
        rename_spent_table(&database, "spent_commitments", "parked").await;
        assert!(
            apply_confirmed_merge(Some(&database), &AuditStore::default(), merge.clone())
                .await
                .is_err()
        );
        rename_spent_table(&database, "parked", "spent_commitments").await;
        let restarted = AuditStore::default();
        apply_confirmed_merge(Some(&database), &restarted, merge.clone())
            .await
            .expect("replay");
        for input in &merge.inputs {
            assert!(restarted.spent_commitment(input).is_some());
        }
    }

    #[test]
    fn a_historical_row_names_only_exact_inputs_and_holds_the_rest() {
        let store = AuditStore::default();
        let (known, other) = ([0x11; 32], [0x12; 32]);
        for commitment in [known, other] {
            store.record(
                CreatedIn {
                    slot: 1,
                    tx_signature: Signature::from([1; 64]),
                    event_index: 0,
                },
                [zolana_ring_client::CreatedUtxo {
                    commitment,
                    slot_index: 0,
                    leaf_index: 0,
                    utxo: zolana_ring_client::KnownUtxo {
                        owner_key: [2; 32],
                        owner: zolana_ring_client::UtxoOwner::Keyed {
                            nullifier_pk: [3; 32],
                        },
                        asset: [4; 32],
                        mint: None,
                        amount: 1,
                        blinding: [5; 32],
                        data_hash: [0; 32],
                        ring_data_hash: [0; 32],
                        tree_id: 1,
                    },
                    ring_note: true,
                }],
            );
        }
        let prefix = |commitment: &[u8; 32]| InputPrefix::of(commitment);
        assert_eq!(
            historical_inputs(
                &store,
                HistoricalEvidence::Prefixes(vec![prefix(&known), None])
            ),
            (vec![known], true)
        );
        // One note, two inputs of the prefix, no input is exact.
        assert_eq!(
            historical_inputs(
                &store,
                HistoricalEvidence::Prefixes(vec![prefix(&known), prefix(&known)])
            ),
            (Vec::new(), false)
        );
        assert_eq!(
            historical_inputs(
                &store,
                HistoricalEvidence::Commitments {
                    first: known,
                    prefixes: vec![prefix(&other)],
                }
            ),
            (vec![known, other], true)
        );
        assert_eq!(
            historical_inputs(&store, HistoricalEvidence::Unnamed),
            (Vec::new(), false)
        );
    }
}
