use std::{future::Future, num::NonZeroU32, time::Duration};

use async_trait::async_trait;
use custom_ring_interface::{
    storage::StorageRegistry,
    tracking::{OwnerGrant, TrackingAuthorization, TrackingRegistry, TRACKING_CAPACITY},
    CoSignScope, ReaderKeyBytes, RingAccount, RingMode, RingPolicy, RingRoles,
};
use custom_ring_sdk::{CustomRing, RingError};
use solana_account::Account;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_loader_v3_interface::get_program_data_address;
use solana_rpc_client::{
    nonblocking::rpc_client::RpcClient as NonblockingRpcClient,
    rpc_client::GetConfirmedSignaturesForAddress2Config,
};
use solana_signature::Signature;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedTransaction, UiMessage,
};
use spr_api::ZolanaApi;
use spr_client::{
    rpc::ProgramAccountsFilter, AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer, ClientError,
    GetShieldedTransactionsByTagsResponse, IndexedShieldedTransaction, IndexerRpcConfig,
    RingHistoryOptions,
};
use spr_interface::{
    pda,
    state::{discriminator::SPL_ASSET_REGISTRY, SplAssetRegistry},
    BPF_LOADER_UPGRADEABLE_ID, PROGRAM_ID_PUBKEY,
};
use spr_keypair::X25519Pubkey;
use spr_transaction::{AssetRegistry, Mint, SOL_MINT};
use zolana_ring_client::{
    history::HistoryPosition, program_data, ring_deposits_in, AsyncRingIndexer, AuditError,
    ConfirmedEventKind, MemberOpeningRead, MergeAudit, MergeAuditPage, RingIndexerError,
    RingOrigin, StorageTip, TransactionOrigin, ORIGIN_TRANSACTION_CONFIG,
};
use zolana_ring_indexer::rpc::{
    GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
    GetStorageMemberRecordsRequest, GetStorageMemberRecordsResponse,
};
use zolana_ring_indexer::tracking::{GetTrackingRecordsRequest, GetTrackingRecordsResponse};
use zolana_ring_transaction::RingAssets;

use zolana_ring_client::rpc::{
    DepositRecord, RingChainStatus, RingDepositsResponse, WalletEnrollment,
};

use crate::{
    audit::Page,
    cosign::CoSignError,
    error::RingRpcError,
    finalized_history::{
        FinalizedHistory, FinalizedPage, FinalizedUpstreams, HistorySelection, OriginRead,
    },
    utxos::TrackingRoot,
};

pub trait TransactionSource: Send + Sync {
    /// A buffer the co-signer reads against its signed digest, an absent one refuses.
    fn account(
        &self,
        _address: Address,
    ) -> impl Future<Output = Result<Option<Account>, ClientError>> + Send {
        async { Ok(None) }
    }

    /// The authorities of the registries a salted list reads.
    fn salted_list_writers(
        &self,
        _ring: Address,
    ) -> impl Future<Output = Result<Vec<Address>, ClientError>> + Send {
        async { Ok(Vec::new()) }
    }

    fn transactions_by_tag(
        &self,
        request: TransactionPage,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    /// Rows strictly after the requested position, in history order.
    fn ring_history(
        &self,
        request: RingHistoryPage,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    fn merge_audit_page<'a>(
        &'a self,
        request: MergeAuditRequest<'a>,
    ) -> impl Future<Output = Result<MergeAuditPage, AuditError>> + Send + 'a;

    fn transaction_origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> impl Future<Output = Result<RingOrigin, AuditError>> + Send;

    fn ring_deposits(
        &self,
        page: DepositPage,
    ) -> impl Future<Output = Result<DepositHistory, ClientError>> + Send;

    fn ring_config(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<Option<RingConfiguration>, ClientError>> + Send;

    fn ring_chain_status(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<RingChainStatus, ClientError>> + Send;

    fn slot(&self) -> impl Future<Output = Result<u64, ClientError>> + Send;

    fn records_root(
        &self,
        ring: Address,
    ) -> impl Future<Output = Result<RecordsTip, ClientError>> + Send;

    fn storage_member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> impl Future<Output = Result<GetStorageMemberOpeningsResponse, RingIndexerError>> + Send;

    fn storage_member_records(
        &self,
        request: GetStorageMemberRecordsRequest,
    ) -> impl Future<Output = Result<GetStorageMemberRecordsResponse, RingIndexerError>> + Send;

    /// `None` for a program that is immutable or not deployed.
    fn upgrade_authority(
        &self,
        program: Address,
    ) -> impl Future<Output = Result<Option<Address>, ClientError>> + Send;

    fn health(&self) -> impl Future<Output = Result<(), ClientError>> + Send;

    /// Binds every derived auditor key to one cluster.
    fn genesis_hash(&self) -> impl Future<Output = Result<[u8; 32], ClientError>> + Send;

    fn ring_assets(&self) -> impl Future<Output = Result<RingAssets, ClientError>> + Send;

    /// The id a tree's commitments hash under.
    fn tree_id(&self, tree: Address) -> impl Future<Output = Result<u16, RingError>> + Send;

    /// The newest root of the ring's pinned tracking registry, `None` reads no owner's secret.
    fn tracking_root(
        &self,
        _ring: Address,
    ) -> impl Future<Output = Result<Option<TrackingRoot>, ClientError>> + Send {
        async { Ok(None) }
    }

    /// The classes the ring's record of `signer` holds.
    fn co_signer_scope(
        &self,
        _ring: Address,
        _signer: Address,
    ) -> impl Future<Output = Result<Option<CoSignScope>, RingRpcError>> + Send {
        async { Ok(None) }
    }

    fn tracking_records(
        &self,
        _request: GetTrackingRecordsRequest,
    ) -> impl Future<Output = Result<GetTrackingRecordsResponse, RingIndexerError>> + Send {
        async { Err(ClientError::Rpc("no tracking records".to_owned()).into()) }
    }

    /// Every account key of a finalized transaction.
    fn transaction_accounts(
        &self,
        _signature: Signature,
    ) -> impl Future<Output = Result<Vec<Address>, ClientError>> + Send {
        async { Ok(Vec::new()) }
    }

    /// The owner's tracking account under the ring's pinned registry.
    fn tracking_enrollment(
        &self,
        _ring: Address,
        _owner: Address,
    ) -> impl Future<Output = Result<WalletEnrollment, ClientError>> + Send {
        async { Ok(WalletEnrollment::NotEnrolled) }
    }

    /// Whether the owner's own `OwnerGrant` account names `reader`, a PDA grants through CPI.
    fn owner_grant_held(
        &self,
        _ring: Address,
        _owner: Address,
        _reader: ReaderKeyBytes,
    ) -> impl Future<Output = Result<bool, ClientError>> + Send {
        async { Ok(false) }
    }
}

/// Unverified, callers read openings through `VerifiedOpenings`.
pub(crate) trait OpeningFetch: Sync {
    fn fetch_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> impl Future<Output = Result<GetStorageMemberOpeningsResponse, RingRpcError>> + Send;
}

impl<S: TransactionSource> OpeningFetch for S {
    async fn fetch_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingRpcError> {
        Ok(self.storage_member_openings(request).await?)
    }
}

/// No source overrides the opening check.
#[async_trait]
pub(crate) trait VerifiedOpenings: OpeningFetch {
    /// Refused unless every opening verifies under `tip`.
    async fn verified_openings(
        &self,
        tip: &StorageTip,
        members: &[[u8; 32]],
    ) -> Result<Vec<MemberOpeningRead>, RingRpcError>;
}

#[async_trait]
impl<S: OpeningFetch + ?Sized> VerifiedOpenings for S {
    async fn verified_openings(
        &self,
        tip: &StorageTip,
        members: &[[u8; 32]],
    ) -> Result<Vec<MemberOpeningRead>, RingRpcError> {
        let response = self.fetch_openings(tip.openings_request(members)).await?;
        tip.verify_openings(&response, members)
            .map_err(|_| RingRpcError::InvalidIndexerResponse)
    }
}

/// A first enrollment names a new leaf, a full tree can never apply it, a rotation still can.
fn enrollment_of(
    authorization: Option<&TrackingAuthorization>,
    tree_full: bool,
) -> WalletEnrollment {
    match authorization {
        None => WalletEnrollment::NotEnrolled,
        Some(held) if !held.is_pending() => WalletEnrollment::Applied,
        Some(held) if held.applied_revision() == 0 && tree_full => {
            WalletEnrollment::PendingPastCapacity
        }
        Some(_) => WalletEnrollment::Pending,
    }
}

#[derive(Clone, Copy)]
#[must_use]
pub struct TransactionPage {
    pub ring: Address,
    pub tag: [u8; 32],
    pub position: HistoryPosition,
    pub limit: NonZeroU32,
}

#[derive(Clone, Copy)]
#[must_use]
pub struct RingHistoryPage {
    pub ring: Address,
    pub position: HistoryPosition,
    pub limit: NonZeroU32,
}

#[must_use]
pub struct MergeAuditRequest<'a> {
    pub ring: Address,
    pub auditor: &'a spr_keypair::X25519Keypair,
    pub page: &'a Page,
}

#[derive(Clone, Copy)]
#[must_use]
pub struct DepositPage {
    pub ring: Address,
    /// Signatures examined, which is not the number of deposits found.
    pub limit: usize,
    /// Resume bound, the oldest signature the previous page examined.
    pub before: Option<Signature>,
}

pub struct DepositHistory {
    pub deposits: Vec<DepositRecord>,
    /// Absent once the ring has no older history.
    pub cursor: Option<Signature>,
    /// Slot of the oldest signature examined, absent when the page examined
    /// nothing.
    pub oldest_slot: Option<u64>,
}

impl From<DepositHistory> for RingDepositsResponse {
    fn from(history: DepositHistory) -> Self {
        Self {
            deposits: history.deposits,
            cursor: history
                .cursor
                .map(|signature| signature.as_ref().to_vec().into()),
            oldest_slot: history.oldest_slot,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordsTip {
    NoPolicy,
    /// The ring's records address holds no initialized storage registry.
    NoRegistry,
    Newest(StorageTip),
}

#[derive(Clone, Copy)]
pub struct RingConfiguration {
    pub auditor_pubkey: X25519Pubkey,
    pub roles: RingRoles,
    pub mode: RingMode,
    pub delegate: Option<Address>,
}

#[must_use]
#[derive(Clone, Copy)]
pub struct Upstreams<'a> {
    pub indexer_url: &'a str,
    pub rpc_url: &'a str,
    pub timeout: Duration,
}

pub struct ChainSource {
    history: FinalizedHistory,
    indexer: AsyncZolanaIndexer,
    rpc: AsyncSolanaRpc,
}

/// The merge audit reads ring history and its registry through one source.
struct HistorySource<'a> {
    source: &'a ChainSource,
}

#[async_trait]
impl AsyncRpc for HistorySource<'_> {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.source.rpc.get_account(address).await
    }

    async fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let position = match options.pagination_token {
            Some(token) => HistoryPosition::resume(token),
            None => options
                .filters
                .slot
                .floor()
                .map_or_else(HistoryPosition::default, HistoryPosition::after_slot),
        };
        if options.filters.slot.lt.is_some() || options.filters.slot.lte.is_some() {
            return Err(ClientError::Rpc(
                "finalized history rejects an upper slot bound".into(),
            ));
        }
        let limit = options
            .limit
            .and_then(NonZeroU32::new)
            .ok_or_else(|| ClientError::Rpc("finalized history requires a page limit".into()))?;
        self.source
            .ring_history(RingHistoryPage {
                ring: options.ring_program_id,
                position,
                limit,
            })
            .await
    }
}

impl TransactionOrigin for HistorySource<'_> {
    async fn origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        self.source
            .transaction_origin(signature, event_index, ring)
            .await
    }
}

#[async_trait]
impl AsyncRingIndexer for HistorySource<'_> {
    async fn get_storage_member_records(
        &self,
        request: GetStorageMemberRecordsRequest,
    ) -> Result<GetStorageMemberRecordsResponse, RingIndexerError> {
        self.source
            .indexer
            .get_storage_member_records(request)
            .await
    }
}

impl ChainSource {
    pub fn connect(upstreams: Upstreams<'_>) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(upstreams.timeout)
            .build()
            .map_err(|error| ClientError::Rpc(format!("http client: {error}")))?;
        Ok(Self {
            history: FinalizedHistory::default(),
            indexer: AsyncZolanaIndexer::with_api(ZolanaApi::with_client(
                upstreams.indexer_url,
                http,
            )),
            rpc: AsyncSolanaRpc::with_client(
                NonblockingRpcClient::new_with_timeout_and_commitment(
                    upstreams.rpc_url.to_owned(),
                    upstreams.timeout,
                    CommitmentConfig::confirmed(),
                ),
            ),
        })
    }

    pub fn rpc(&self) -> &AsyncSolanaRpc {
        &self.rpc
    }

    fn history(&self) -> HistorySource<'_> {
        HistorySource { source: self }
    }

    /// A foreign owner means the account does not exist for its program, not
    /// that it is broken.
    async fn owned_account(
        &self,
        address: Address,
        owner: Address,
    ) -> Result<Option<Account>, ClientError> {
        Ok(self
            .rpc
            .get_account(address)
            .await?
            .filter(|account| account.owner == owner))
    }
}

impl TransactionSource for ChainSource {
    async fn account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.rpc.get_account(address).await
    }

    async fn tree_id(&self, tree: Address) -> Result<u16, RingError> {
        custom_ring_sdk::tree_id(&self.rpc, tree).await
    }

    async fn merge_audit_page<'a>(
        &'a self,
        request: MergeAuditRequest<'a>,
    ) -> Result<MergeAuditPage, AuditError> {
        MergeAudit::new(request.ring, request.auditor)
            .with_cursor(request.page.history_cursor())
            .with_page_size(request.page.limit())
            .page(&self.history(), &self.history())
            .await
    }

    async fn transactions_by_tag(
        &self,
        request: TransactionPage,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.history
            .page(
                FinalizedPage {
                    ring: request.ring,
                    position: request.position,
                    limit: request.limit,
                    selection: HistorySelection::Tag(request.tag),
                },
                &FinalizedUpstreams {
                    rpc: &self.rpc,
                    indexer: &self.indexer,
                },
            )
            .await
    }

    async fn ring_history(
        &self,
        request: RingHistoryPage,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.history
            .page(
                FinalizedPage {
                    ring: request.ring,
                    position: request.position,
                    limit: request.limit,
                    selection: HistorySelection::Ring,
                },
                &FinalizedUpstreams {
                    rpc: &self.rpc,
                    indexer: &self.indexer,
                },
            )
            .await
    }

    /// The ring's own signatures name the candidates, and every deposit field
    /// this reports is public.
    async fn ring_deposits(&self, page: DepositPage) -> Result<DepositHistory, ClientError> {
        let ring = page.ring;
        let signatures = self
            .rpc
            .client()
            .get_signatures_for_address_with_config(
                &ring,
                GetConfirmedSignaturesForAddress2Config {
                    before: page.before,
                    until: None,
                    limit: Some(page.limit),
                    commitment: Some(CommitmentConfig::finalized()),
                },
            )
            .await
            .map_err(|error| ClientError::Rpc(format!("signatures for {ring}: {error}")))?;
        // A short page means the ring has no older history.
        let more = signatures.len() == page.limit;
        let mut deposits = Vec::new();
        let mut oldest = None;
        for entry in signatures {
            let signature = confirmed_signature(&entry.signature)?;
            oldest = Some((signature, entry.slot));
            if entry.err.is_some() {
                continue;
            }
            let response = self
                .indexer
                .get_shielded_transactions_by_signature(signature, None)
                .await?;
            for indexed in response.transactions {
                let records = ConfirmedDepositRecords {
                    origin: &self.history(),
                    signature,
                    ring,
                    indexed,
                };
                deposits.extend(records.read().await?);
            }
        }
        Ok(DepositHistory {
            deposits,
            cursor: oldest.map(|(signature, _)| signature).filter(|_| more),
            oldest_slot: oldest.map(|(_, slot)| slot),
        })
    }

    async fn transaction_origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        FinalizedUpstreams {
            rpc: &self.rpc,
            indexer: &self.indexer,
        }
        .origins(OriginRead { ring, signature })
        .await?
        .origins
        .remove(&event_index)
        .ok_or(AuditError::InvalidEventIndex(event_index))
    }

    async fn ring_config(&self, ring: Address) -> Result<Option<RingConfiguration>, ClientError> {
        let (address, bump) = Address::find_program_address(&[RingPolicy::SEED], &ring);
        let Some(account) = self.owned_account(address, ring).await? else {
            return Ok(None);
        };
        CanonicalAccount {
            account: &account,
            ring,
            bump,
        }
        .configuration()
        .map(Some)
    }

    async fn salted_list_writers(&self, ring: Address) -> Result<Vec<Address>, ClientError> {
        let (address, _) = Address::find_program_address(&[RingPolicy::SEED], &ring);
        let Some(account) = self.owned_account(address, ring).await? else {
            return Ok(Vec::new());
        };
        let policy = RingPolicy::decode(&account.owner, &ring, &account.data)
            .ok_or_else(|| ClientError::Rpc(INVALID_POLICY.to_owned()))?;
        let mut writers = Vec::new();
        for registry in policy.salted_registries() {
            let account = self.rpc.get_account(registry).await?;
            writers.extend(
                account
                    .as_ref()
                    .and_then(|account| StorageRegistry::decode(&account.owner, &account.data))
                    .map(|registry| registry.authority),
            );
        }
        Ok(writers)
    }

    async fn ring_chain_status(&self, ring: Address) -> Result<RingChainStatus, ClientError> {
        RingChainStatus::read(&self.rpc, ring).await
    }

    async fn upgrade_authority(&self, program: Address) -> Result<Option<Address>, ClientError> {
        let loader = Address::new_from_array(BPF_LOADER_UPGRADEABLE_ID);
        let address = get_program_data_address(&program);
        let Some(account) = self.owned_account(address, loader).await? else {
            return Ok(None);
        };
        let data = program_data(&account)
            .ok_or_else(|| ClientError::Rpc("program data account is invalid".to_owned()))?;
        Ok(data
            .upgrade_authority
            .filter(|key| *key != Address::default()))
    }

    async fn slot(&self) -> Result<u64, ClientError> {
        self.rpc.get_slot().await
    }

    async fn records_root(&self, ring: Address) -> Result<RecordsTip, ClientError> {
        let (address, bump) = Address::find_program_address(&[RingPolicy::SEED], &ring);
        let Some(account) = self.owned_account(address, ring).await? else {
            return Ok(RecordsTip::NoPolicy);
        };
        let records = CanonicalAccount {
            account: &account,
            ring,
            bump,
        }
        .decode::<RingPolicy>()
        .ok_or_else(|| ClientError::Rpc(INVALID_POLICY.to_owned()))?
        .records;
        Ok(self
            .rpc
            .get_account(records)
            .await?
            .and_then(|account| StorageRegistry::decode(&account.owner, &account.data))
            .map_or(RecordsTip::NoRegistry, |registry| {
                RecordsTip::Newest(StorageTip::newest(records, &registry))
            }))
    }

    async fn co_signer_scope(
        &self,
        ring: Address,
        signer: Address,
    ) -> Result<Option<CoSignScope>, RingRpcError> {
        let record = CustomRing::new(ring)
            .co_signer(&HistorySource { source: self }, &signer)
            .await
            .map_err(|_| CoSignError::LimitsUnavailable)?;
        Ok(record.map(|record| record.scope))
    }

    async fn tracking_root(&self, ring: Address) -> Result<Option<TrackingRoot>, ClientError> {
        let (address, bump) = Address::find_program_address(&[RingPolicy::SEED], &ring);
        let Some(account) = self.owned_account(address, ring).await? else {
            return Ok(None);
        };
        let tracking = CanonicalAccount {
            account: &account,
            ring,
            bump,
        }
        .decode::<RingPolicy>()
        .ok_or_else(|| ClientError::Rpc(INVALID_POLICY.to_owned()))?
        .tracking;
        let account = self.rpc.get_account(tracking).await?;
        // The pin names the registry, an account it does not decode to serves no root.
        Ok(account
            .and_then(|account| TrackingRegistry::decode(&account.owner, &account.data))
            .map(|registry| {
                let newest = registry.newest();
                TrackingRoot {
                    registry: tracking,
                    root: newest.hash,
                    revision: newest.revision.value(),
                }
            }))
    }

    async fn tracking_records(
        &self,
        request: GetTrackingRecordsRequest,
    ) -> Result<GetTrackingRecordsResponse, RingIndexerError> {
        self.indexer.get_tracking_records(request).await
    }

    /// A v1 message carries every key, a loaded address list is refused.
    async fn transaction_accounts(
        &self,
        signature: Signature,
    ) -> Result<Vec<Address>, ClientError> {
        let mut config = ORIGIN_TRANSACTION_CONFIG;
        config.commitment = Some(CommitmentConfig::finalized());
        let transaction = self
            .rpc
            .client()
            .get_transaction_with_config(&signature, config)
            .await
            .map_err(|error| ClientError::Rpc(error.to_string()))?
            .transaction;
        let EncodedTransaction::Json(encoded) = transaction.transaction else {
            return Err(ClientError::Rpc(
                "transaction is not JSON encoded".to_owned(),
            ));
        };
        let UiMessage::Raw(message) = encoded.message else {
            return Err(ClientError::Rpc(
                "transaction message is not raw".to_owned(),
            ));
        };
        let loaded = transaction.meta.map(|meta| meta.loaded_addresses);
        if matches!(loaded, Some(OptionSerializer::Some(loaded)) if !loaded.writable.is_empty() || !loaded.readonly.is_empty())
        {
            return Err(ClientError::Rpc(
                "a v1 transaction names loaded addresses".to_owned(),
            ));
        }
        message
            .account_keys
            .iter()
            .map(|key| {
                key.parse().map_err(|_| {
                    ClientError::Rpc("transaction account key is malformed".to_owned())
                })
            })
            .collect()
    }

    async fn tracking_enrollment(
        &self,
        ring: Address,
        owner: Address,
    ) -> Result<WalletEnrollment, ClientError> {
        let Some(root) = self.tracking_root(ring).await? else {
            return Ok(WalletEnrollment::NotEnrolled);
        };
        let (address, _) = TrackingAuthorization::find_address(&root.registry, &owner);
        let authorization = self
            .rpc
            .get_account(address)
            .await?
            .and_then(|account| TrackingAuthorization::decode(&account.owner, &account.data));
        let registry = self
            .rpc
            .get_account(root.registry)
            .await?
            .and_then(|account| TrackingRegistry::decode(&account.owner, &account.data));
        Ok(enrollment_of(
            authorization.as_ref(),
            registry
                .as_ref()
                .is_some_and(|registry| u64::from(registry.next_index()) >= TRACKING_CAPACITY),
        ))
    }

    async fn owner_grant_held(
        &self,
        ring: Address,
        owner: Address,
        reader: ReaderKeyBytes,
    ) -> Result<bool, ClientError> {
        let Some(root) = self.tracking_root(ring).await? else {
            return Ok(false);
        };
        let (address, _) = OwnerGrant::find_address(&root.registry, &owner, &reader);
        Ok(self
            .rpc
            .get_account(address)
            .await?
            .and_then(|account| OwnerGrant::decode(&account.owner, &account.data))
            .is_some_and(|grant| grant.is_active()))
    }

    async fn storage_member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
        self.indexer.get_storage_member_openings(request).await
    }

    async fn storage_member_records(
        &self,
        request: GetStorageMemberRecordsRequest,
    ) -> Result<GetStorageMemberRecordsResponse, RingIndexerError> {
        self.indexer.get_storage_member_records(request).await
    }

    async fn health(&self) -> Result<(), ClientError> {
        self.indexer
            .get_shielded_transactions_by_tags(
                vec![[0; 32]],
                None,
                Some(1),
                HistoryPosition::default().filters(),
                None,
            )
            .await?;
        self.rpc.health().await
    }

    async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
        self.rpc.genesis_hash().await
    }

    async fn ring_assets(&self) -> Result<RingAssets, ClientError> {
        let filter =
            ProgramAccountsFilter::new(SplAssetRegistry::SIZE).with_memcmp(0, [SPL_ASSET_REGISTRY]);
        let accounts = self
            .rpc
            .get_program_accounts_filtered(PROGRAM_ID_PUBKEY, &filter)
            .await?;
        let mut assets = AssetRegistry::default();
        let mut mints = Vec::with_capacity(accounts.len());
        for (address, account) in accounts {
            let invalid = || ClientError::InvalidSplAssetRegistration { address };
            if account.owner != PROGRAM_ID_PUBKEY || !filter.matches(&account.data) {
                return Err(invalid());
            }
            let registration =
                SplAssetRegistry::from_account_bytes(&account.data).map_err(|_| invalid())?;
            if address != pda::spl_asset_registry(&registration.mint)
                || registration.mint == SOL_MINT
            {
                return Err(invalid());
            }
            assets
                .insert(registration.asset_id, registration.mint)
                .map_err(|_| invalid())?;
            mints.push(Mint::new(registration.mint, registration.asset_id));
        }
        RingAssets::new(mints).map_err(|error| ClientError::Rpc(error.to_string()))
    }
}

/// A malformed signature must stop the page before its cursor can advance.
fn confirmed_signature(value: &str) -> Result<Signature, ClientError> {
    value
        .parse()
        .map_err(|_| ClientError::Rpc("confirmed ring signature is invalid".to_owned()))
}

/// Public deposit metadata needs the same settlement binding as private recovery.
#[must_use]
struct ConfirmedDepositRecords<'a, O> {
    origin: &'a O,
    signature: Signature,
    ring: Address,
    indexed: IndexedShieldedTransaction,
}

impl<O: TransactionOrigin> ConfirmedDepositRecords<'_, O> {
    async fn read(self) -> Result<Vec<DepositRecord>, ClientError> {
        let Self {
            origin,
            signature,
            ring,
            mut indexed,
        } = self;
        let transaction = &mut indexed.transaction;
        let failure = |error: AuditError| {
            ClientError::Rpc(format!("confirmed deposit event refused because {error}"))
        };
        if transaction.tx_signature != signature
            || transaction.event_index != Some(indexed.event_index)
        {
            return Err(failure(AuditError::ConfirmedEventMismatch));
        }
        let confirmed = origin
            .origin(signature, indexed.event_index, ring)
            .await
            .map_err(failure)?;
        if !confirmed.ring_invoked || confirmed.event.kind() != ConfirmedEventKind::Deposit {
            return Ok(Vec::new());
        }
        confirmed
            .bind_transaction(transaction, ring)
            .map_err(failure)?;
        let slots = transaction
            .output_slots
            .iter()
            .map(|slot| (slot.view_tag, slot.payload.clone()));
        Ok(ring_deposits_in(slots, ring)
            .into_iter()
            .map(|found| DepositRecord {
                signature: signature.into(),
                slot: transaction.slot,
                depositor: found.depositor.into(),
                asset: found.asset.to_bytes().into(),
                amount: found.amount,
            })
            .collect())
    }
}

const INVALID_POLICY: &str = "custom ring policy account is invalid";

/// `bump` is the canonical bump of the address `account` was read from.
#[derive(Clone, Copy)]
#[must_use]
struct CanonicalAccount<'a> {
    account: &'a Account,
    ring: Address,
    bump: u8,
}

impl CanonicalAccount<'_> {
    fn decode<T: RingAccount>(self) -> Option<T> {
        T::decode(&self.account.owner, &self.ring, &self.account.data)
            .filter(|value| value.bump() == self.bump)
    }

    fn configuration(self) -> Result<RingConfiguration, ClientError> {
        let invalid = || ClientError::Rpc(INVALID_POLICY.to_owned());
        let config: RingPolicy = self.decode().ok_or_else(invalid)?;
        Ok(RingConfiguration {
            auditor_pubkey: X25519Pubkey::from_bytes(config.auditor_pubkey)
                .map_err(|_| invalid())?,
            roles: config.roles,
            mode: config.mode().map_err(|_| invalid())?,
            delegate: config.delegate().copied(),
        })
    }
}

#[cfg(test)]
mod enrollment_tests {
    use bytemuck::Zeroable;

    use super::*;

    #[test]
    fn a_full_tree_names_a_first_enrollment_and_leaves_a_rotation_pending() {
        let mut held = TrackingAuthorization::zeroed();
        assert_eq!(enrollment_of(None, true), WalletEnrollment::NotEnrolled);
        held.revision = 1u64.to_le_bytes();
        assert_eq!(enrollment_of(Some(&held), false), WalletEnrollment::Pending);
        assert_eq!(
            enrollment_of(Some(&held), true),
            WalletEnrollment::PendingPastCapacity
        );
        held.applied_revision = 1u64.to_le_bytes();
        assert_eq!(enrollment_of(Some(&held), true), WalletEnrollment::Applied);
        held.revision = 2u64.to_le_bytes();
        assert_eq!(enrollment_of(Some(&held), true), WalletEnrollment::Pending);
    }
}

#[cfg(test)]
#[path = "../../../../sdk-libs/client/tests/common/origin.rs"]
pub(crate) mod origin_fixture;

#[cfg(test)]
mod tests {
    use bytemuck::{bytes_of, Pod};
    use custom_ring_interface::{RING_POLICY, RING_POLICY_PDA_SEED};

    use super::*;

    #[test]
    fn malformed_confirmed_signature_aborts_a_deposit_page() {
        assert!(confirmed_signature("not a Solana signature").is_err());
        let valid = Signature::from([7; 64]);
        assert_eq!(confirmed_signature(&valid.to_string()).unwrap(), valid);
    }

    fn account<T: Pod>(owner: Address, value: &T) -> Account {
        Account {
            lamports: 1,
            data: bytes_of(value).to_vec(),
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    const AUTHORITY: Address = Address::new_from_array([7; 32]);

    fn config_account(ring: Address, key: [u8; 33], bump: u8) -> Account {
        let mut config: Box<RingPolicy> = bytemuck::zeroed_box();
        config.discriminator = RING_POLICY;
        config.roles.policy = AUTHORITY;
        config.auditor_pubkey = key;
        config.bump = bump;
        account(ring, &*config)
    }

    #[test]
    fn config_accounts_require_the_canonical_layout() {
        let ring = Address::new_from_array([9; 32]);
        let bump = Address::find_program_address(&[RING_POLICY_PDA_SEED], &ring).1;
        let key = spr_keypair::X25519Keypair::new().pubkey();
        let valid = config_account(ring, *key.as_bytes(), bump);
        let configuration = |account: &Account, bump| {
            CanonicalAccount {
                account,
                ring,
                bump,
            }
            .configuration()
        };
        let config = configuration(&valid, bump).expect("config");
        assert_eq!(config.auditor_pubkey, key);
        assert_eq!(config.roles.policy, AUTHORITY);

        let mut wrong_owner = valid.clone();
        wrong_owner.owner = Address::new_from_array([8; 32]);
        let mut wrong_size = valid.clone();
        wrong_size.data.push(0);
        let mut wrong_discriminator = valid.clone();
        wrong_discriminator.data[0] = 0;
        for invalid in [wrong_owner, wrong_size, wrong_discriminator] {
            assert!(configuration(&invalid, bump).is_err());
        }
        assert!(configuration(&valid, bump.wrapping_add(1)).is_err());
        for invalid_key in [[2; 33], [0; 33]] {
            let invalid = config_account(ring, invalid_key, bump);
            assert!(configuration(&invalid, bump).is_err());
        }
    }

    struct ConfirmedOrigin(RingOrigin);

    impl TransactionOrigin for ConfirmedOrigin {
        async fn origin(&self, _: Signature, _: u16, _: Address) -> Result<RingOrigin, AuditError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn public_deposit_history_rejects_forged_amount_asset_context_and_signature() {
        use spr_transaction::{OutputContext, OutputSlot, ShieldedTransaction};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../sdk-libs/client/tests/fixtures/confirmed-deposit-event.json"
        ))
        .unwrap();
        let ring: Address = fixture["ring"].as_str().unwrap().parse().unwrap();
        let output = &fixture["expected"]["outputs"][0];
        let bytes = |key: &str| hex::decode(output[key].as_str().unwrap()).unwrap();
        let signature = Signature::from([7; 64]);
        let indexed = IndexedShieldedTransaction {
            event_index: 0,
            transaction: ShieldedTransaction {
                slot: 99,
                tx_signature: signature,
                event_index: Some(0),
                tx_viewing_pk: None,
                salt: None,
                proofless: true,
                ring_config: None,
                ring_program_id: Some(ring),
                messages: Vec::new(),
                nullifiers: Vec::new(),
                output_slots: vec![OutputSlot {
                    view_tag: bytes("viewTagHex").try_into().unwrap(),
                    output_context: OutputContext {
                        hash: bytes("hashHex").try_into().unwrap(),
                        tree_id: output["treeId"].as_u64().unwrap() as u16,
                        leaf_index: output["leafIndex"].as_u64().unwrap(),
                    },
                    payload: bytes("payloadHex"),
                }],
            },
        };
        let origin = ConfirmedOrigin(RingOrigin {
            ring_invoked: true,
            event: super::origin_fixture::event(&indexed.transaction).with_slot(99),
            signers: Vec::new(),
            withdrawals: Vec::new(),
            deposits: Vec::new(),
            merge_disclosure: None,
            transact: None,
            pool_accounts: Vec::new(),
        });
        let records = |origin, indexed| ConfirmedDepositRecords {
            origin,
            signature,
            ring,
            indexed,
        };
        let opened = records(&origin, indexed.clone()).read().await.unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].amount, 123);
        type Mutation = fn(&mut IndexedShieldedTransaction);
        let mutations: &[Mutation] = &[
            |tx| tx.transaction.tx_signature = Signature::from([8; 64]),
            |tx| tx.transaction.event_index = Some(1),
            |tx| tx.transaction.slot += 1,
            |tx| tx.transaction.proofless = false,
            |tx| tx.transaction.output_slots[0].output_context.leaf_index += 1,
            // Borsh outer tag + Vec length + scheme, then owner hash and asset.
            |tx| tx.transaction.output_slots[0].payload[6 + 32] ^= 1,
            |tx| tx.transaction.output_slots[0].payload[6 + 32 + 32] ^= 1,
        ];
        for mutate in mutations {
            let mut forged = indexed.clone();
            mutate(&mut forged);
            assert!(records(&origin, forged).read().await.is_err());
        }
        let foreign = ConfirmedOrigin(RingOrigin {
            ring_invoked: false,
            ..origin.0.clone()
        });
        assert!(records(&foreign, indexed).read().await.unwrap().is_empty());
    }
}
