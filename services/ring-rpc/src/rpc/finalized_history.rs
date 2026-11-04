use std::{
    collections::{BTreeMap, HashMap, HashSet},
    num::NonZeroU32,
    sync::Arc,
};

use async_trait::async_trait;
use serde_json::json;
use solana_address::Address;
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client_api::{
    request::RpcRequest, response::RpcConfirmedTransactionStatusWithSignature,
};
use solana_signature::Signature;
use spr_client::{
    AsyncRpc, AsyncSolanaRpc, AsyncZolanaIndexer, ClientError,
    GetShieldedTransactionsBySignatureResponse, GetShieldedTransactionsByTagsResponse,
    IndexedShieldedTransaction,
};
use spr_indexer_api::{Context, PaginationToken, TransactionEvents};
use spr_transaction::ShieldedTransaction;
use tokio::sync::Mutex;
use zolana_ring_client::{
    history::HistoryPosition, AuditError, ConfirmedRingOrigins, RingOrigin,
    ORIGIN_TRANSACTION_CONFIG,
};

const SIGNATURE_PAGE_SIZE: usize = 1_000;

type CachedManifest = Arc<Mutex<Option<Manifest>>>;

#[derive(Default)]
pub(crate) struct FinalizedHistory {
    rings: Mutex<HashMap<Address, CachedManifest>>,
}

#[derive(Clone, Copy)]
pub(crate) enum HistorySelection {
    Ring,
    Tag([u8; 32]),
}

pub(crate) struct FinalizedPage {
    pub ring: Address,
    pub position: HistoryPosition,
    pub limit: NonZeroU32,
    pub selection: HistorySelection,
}

pub(crate) struct FinalizedUpstreams<'a> {
    pub rpc: &'a AsyncSolanaRpc,
    pub indexer: &'a AsyncZolanaIndexer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignatureEntry {
    signature: Signature,
    slot: u64,
    succeeded: bool,
}

struct SignatureRead {
    ring: Address,
    before: Option<Signature>,
    snapshot: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct OriginRead {
    pub ring: Address,
    pub signature: Signature,
}

pub(crate) struct CanonicalOrigins {
    slot: u64,
    pub origins: BTreeMap<u16, RingOrigin>,
}

#[derive(Clone)]
struct Manifest {
    floor: Option<u64>,
    context: Context,
    signatures: Vec<SignatureEntry>,
}

#[async_trait]
trait FinalizedSource: Sync {
    async fn context(&self) -> Result<Context, ClientError>;
    async fn signatures(&self, read: SignatureRead) -> Result<Vec<SignatureEntry>, ClientError>;
    async fn origins(&self, read: OriginRead) -> Result<CanonicalOrigins, AuditError>;
    async fn indexed(
        &self,
        signature: Signature,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError>;
}

impl FinalizedHistory {
    pub(crate) async fn page(
        &self,
        request: FinalizedPage,
        source: &FinalizedUpstreams<'_>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.read(request, source).await
    }

    async fn read<S: FinalizedSource>(
        &self,
        request: FinalizedPage,
        source: &S,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let ring = self
            .rings
            .lock()
            .await
            .entry(request.ring)
            .or_default()
            .clone();
        let mut cached = ring.lock().await;
        let floor = request.position.token().map_or_else(
            || request.position.filters().slot.floor(),
            |token| token.slot().checked_sub(1),
        );
        let continues = request.position.token().is_some()
            && cached
                .as_ref()
                .is_some_and(|manifest| manifest.covers(floor));
        if !continues {
            let context = source.context().await?;
            if floor.is_some_and(|floor| context.slot < floor)
                || request
                    .position
                    .token()
                    .is_some_and(|token| token.slot() > context.slot)
            {
                return Err(invalid_history());
            }
            let previous = cached.as_ref().filter(|manifest| manifest.floor <= floor);
            if previous.is_some_and(|manifest| manifest.context.slot > context.slot) {
                return Err(invalid_history());
            }
            let from = previous.map_or(floor, |manifest| Some(manifest.context.slot));
            let mut signatures = if from == Some(context.slot) {
                Vec::new()
            } else {
                collect_signatures(
                    source,
                    SignatureRange {
                        ring: request.ring,
                        floor: from,
                        context,
                    },
                )
                .await?
            };
            if let Some(previous) = previous {
                signatures.extend(previous.signatures.iter().copied());
            }
            let floor = previous.map_or(floor, |manifest| manifest.floor);
            signatures.sort_unstable_by_key(SignatureEntry::position);
            *cached = Some(Manifest {
                floor,
                context,
                signatures,
            });
        }
        let manifest = cached.as_ref().ok_or_else(invalid_history)?;
        let mut data: Vec<TransactionEvents<ShieldedTransaction, Signature>> = Vec::new();
        let mut remaining = manifest
            .signatures
            .iter()
            .filter(|entry| request.includes(entry));
        for entry in remaining.by_ref().take(request.limit.get() as usize) {
            let mut events = if entry.succeeded {
                let mut canonical = source
                    .origins(OriginRead {
                        ring: request.ring,
                        signature: entry.signature,
                    })
                    .await
                    .map_err(history_error)?;
                if canonical.slot != entry.slot {
                    return Err(invalid_history());
                }
                canonical.origins.retain(|_, origin| origin.ring_invoked);
                if canonical.origins.is_empty() {
                    Vec::new()
                } else {
                    let indexed = source.indexed(entry.signature).await?;
                    BoundEvents {
                        ring: request.ring,
                        entry: *entry,
                        canonical,
                        indexed: indexed.transactions,
                    }
                    .read()?
                }
            } else {
                Vec::new()
            };
            events.retain(|transaction| request.selection.includes(transaction));
            data.push(TransactionEvents {
                slot: entry.slot,
                signature: entry.signature,
                events,
            });
        }
        let more = remaining.next().is_some();
        let pagination_token = if more {
            data.last()
                .map(|row| PaginationToken::new(row.slot, row.signature))
        } else {
            None
        };
        Ok(GetShieldedTransactionsByTagsResponse {
            context: manifest.context,
            output_tree_id: None,
            data,
            pagination_token,
        })
    }
}

impl FinalizedPage {
    fn includes(&self, entry: &SignatureEntry) -> bool {
        self.position.filters().slot.contains(entry.slot)
            && self
                .position
                .token()
                .is_none_or(|token| entry.position() > token)
    }
}

impl HistorySelection {
    fn includes(self, transaction: &ShieldedTransaction) -> bool {
        match self {
            Self::Ring => true,
            Self::Tag(tag) => {
                transaction
                    .messages
                    .iter()
                    .any(|message| message.view_tag == tag)
                    || transaction
                        .output_slots
                        .iter()
                        .any(|output| output.view_tag == tag)
            }
        }
    }
}

impl SignatureEntry {
    fn position(&self) -> PaginationToken {
        PaginationToken::new(self.slot, self.signature)
    }
}

impl Manifest {
    fn covers(&self, floor: Option<u64>) -> bool {
        self.floor <= floor && floor.is_none_or(|floor| floor <= self.context.slot)
    }
}

struct SignatureRange {
    ring: Address,
    floor: Option<u64>,
    context: Context,
}

async fn collect_signatures<S: FinalizedSource>(
    source: &S,
    range: SignatureRange,
) -> Result<Vec<SignatureEntry>, ClientError> {
    let mut before = None;
    let mut previous_slot = None;
    let mut seen = HashSet::new();
    let mut signatures = Vec::new();
    loop {
        let page = source
            .signatures(SignatureRead {
                ring: range.ring,
                before,
                snapshot: range.context.slot,
            })
            .await?;
        if page.len() > SIGNATURE_PAGE_SIZE {
            return Err(invalid_history());
        }
        let ended = page.len() < SIGNATURE_PAGE_SIZE;
        for entry in page {
            if previous_slot.is_some_and(|slot| entry.slot > slot) || !seen.insert(entry.signature)
            {
                return Err(invalid_history());
            }
            previous_slot = Some(entry.slot);
            before = Some(entry.signature);
            if range.floor.is_some_and(|floor| entry.slot <= floor) {
                return Ok(signatures);
            }
            if entry.slot <= range.context.slot {
                signatures.push(entry);
            }
        }
        if ended {
            return Ok(signatures);
        }
    }
}

struct BoundEvents {
    ring: Address,
    entry: SignatureEntry,
    canonical: CanonicalOrigins,
    indexed: Vec<IndexedShieldedTransaction>,
}

impl BoundEvents {
    fn read(mut self) -> Result<Vec<ShieldedTransaction>, ClientError> {
        let mut events = BTreeMap::new();
        let mut seen = HashSet::new();
        for indexed in self.indexed {
            let mut transaction = indexed.transaction;
            if !seen.insert(indexed.event_index)
                || transaction.event_index != Some(indexed.event_index)
                || transaction.tx_signature != self.entry.signature
                || transaction.slot != self.entry.slot
            {
                return Err(invalid_history());
            }
            match self.canonical.origins.remove(&indexed.event_index) {
                Some(origin) => {
                    origin
                        .bind_transaction(&mut transaction, self.ring)
                        .map_err(history_error)?;
                    events.insert(indexed.event_index, transaction);
                }
                None if transaction.ring_program_id == Some(self.ring) => {
                    return Err(invalid_history())
                }
                None => {}
            }
        }
        if !self.canonical.origins.is_empty() {
            return Err(invalid_history());
        }
        Ok(events.into_values().collect())
    }
}

impl FinalizedUpstreams<'_> {
    pub(crate) async fn origins(&self, read: OriginRead) -> Result<CanonicalOrigins, AuditError> {
        <Self as FinalizedSource>::origins(self, read).await
    }
}

#[async_trait]
impl FinalizedSource for FinalizedUpstreams<'_> {
    async fn context(&self) -> Result<Context, ClientError> {
        let slot = self
            .rpc
            .client()
            .get_slot_with_commitment(CommitmentConfig::finalized())
            .await
            .map_err(rpc_error)?;
        let block_time = self
            .rpc
            .client()
            .get_block_time(slot)
            .await
            .map_err(rpc_error)?;
        Ok(Context { slot, block_time })
    }

    async fn signatures(&self, read: SignatureRead) -> Result<Vec<SignatureEntry>, ClientError> {
        let entries: Vec<RpcConfirmedTransactionStatusWithSignature> = self
            .rpc
            .client()
            .send(
                RpcRequest::GetSignaturesForAddress,
                json!([read.ring.to_string(), {
                    "commitment": "finalized",
                    "minContextSlot": read.snapshot,
                    "limit": SIGNATURE_PAGE_SIZE,
                    "before": read.before.map(|signature| signature.to_string()),
                }]),
            )
            .await
            .map_err(rpc_error)?;
        entries
            .into_iter()
            .map(|entry| {
                Ok(SignatureEntry {
                    signature: entry.signature.parse().map_err(|_| invalid_history())?,
                    slot: entry.slot,
                    succeeded: entry.err.is_none(),
                })
            })
            .collect()
    }

    async fn origins(&self, read: OriginRead) -> Result<CanonicalOrigins, AuditError> {
        let mut config = ORIGIN_TRANSACTION_CONFIG;
        config.commitment = Some(CommitmentConfig::finalized());
        let transaction = self
            .rpc
            .client()
            .get_transaction_with_config(&read.signature, config)
            .await
            .map_err(|error| AuditError::Unavailable {
                signature: read.signature,
                message: error.to_string(),
            })?;
        let slot = transaction.slot;
        let origins = ConfirmedRingOrigins {
            signature: read.signature,
            transaction,
            ring: read.ring,
        }
        .read()?;
        Ok(CanonicalOrigins { slot, origins })
    }

    async fn indexed(
        &self,
        signature: Signature,
    ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
        self.indexer
            .get_shielded_transactions_by_signature(signature, None)
            .await
    }
}

fn history_error(error: impl std::fmt::Display) -> ClientError {
    ClientError::Rpc(format!("finalized ring history refused because {error}"))
}

fn rpc_error(error: impl std::fmt::Display) -> ClientError {
    ClientError::Rpc(format!("finalized history RPC failed because {error}"))
}

fn invalid_history() -> ClientError {
    ClientError::Rpc("finalized ring history is incomplete or inconsistent".into())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex as StdMutex,
    };

    use super::*;
    use crate::upstream::origin_fixture;

    const RING: Address = Address::new_from_array([8; 32]);

    struct Source {
        through: AtomicU64,
        signatures: StdMutex<Vec<SignatureEntry>>,
        transactions: HashMap<Signature, Vec<ShieldedTransaction>>,
        indexed: StdMutex<HashMap<Signature, Vec<IndexedShieldedTransaction>>>,
        signature_calls: AtomicUsize,
        origin_calls: AtomicUsize,
    }

    impl Source {
        fn new(entries: &[SignatureEntry]) -> Self {
            let transactions: HashMap<_, _> = entries
                .iter()
                .map(|entry| (entry.signature, vec![transaction(*entry)]))
                .collect();
            let indexed = transactions
                .iter()
                .map(|(signature, transactions)| {
                    (
                        *signature,
                        transactions
                            .iter()
                            .map(|transaction| IndexedShieldedTransaction {
                                event_index: transaction.event_index.unwrap(),
                                transaction: transaction.clone(),
                            })
                            .collect(),
                    )
                })
                .collect();
            Self {
                through: AtomicU64::new(entries.iter().map(|entry| entry.slot).max().unwrap_or(0)),
                signatures: StdMutex::new(entries.to_vec()),
                transactions,
                indexed: StdMutex::new(indexed),
                signature_calls: AtomicUsize::new(0),
                origin_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl FinalizedSource for Source {
        async fn context(&self) -> Result<Context, ClientError> {
            Ok(Context {
                slot: self.through.load(Ordering::SeqCst),
                block_time: 0,
            })
        }

        async fn signatures(
            &self,
            read: SignatureRead,
        ) -> Result<Vec<SignatureEntry>, ClientError> {
            self.signature_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(read.ring, RING);
            assert!(read.snapshot <= self.through.load(Ordering::SeqCst));
            let mut entries = self.signatures.lock().unwrap().clone();
            entries.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.position()));
            let start = read.before.map_or(0, |before| {
                entries
                    .iter()
                    .position(|entry| entry.signature == before)
                    .unwrap()
                    + 1
            });
            Ok(entries
                .into_iter()
                .skip(start)
                .take(SIGNATURE_PAGE_SIZE)
                .collect())
        }

        async fn origins(&self, read: OriginRead) -> Result<CanonicalOrigins, AuditError> {
            self.origin_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(read.ring, RING);
            let transactions = &self.transactions[&read.signature];
            Ok(CanonicalOrigins {
                slot: transactions[0].slot,
                origins: transactions
                    .iter()
                    .map(|transaction| {
                        (
                            transaction.event_index.unwrap(),
                            RingOrigin {
                                ring_invoked: true,
                                event: origin_fixture::event(transaction)
                                    .with_slot(transaction.slot),
                                signers: Vec::new(),
                                withdrawals: Vec::new(),
                                deposits: Vec::new(),
                                merge_disclosure: None,
                                transact: None,
                                pool_accounts: Vec::new(),
                            },
                        )
                    })
                    .collect(),
            })
        }

        async fn indexed(
            &self,
            signature: Signature,
        ) -> Result<GetShieldedTransactionsBySignatureResponse, ClientError> {
            Ok(GetShieldedTransactionsBySignatureResponse {
                context: self.context().await?,
                output_tree_id: None,
                transactions: self
                    .indexed
                    .lock()
                    .unwrap()
                    .get(&signature)
                    .cloned()
                    .unwrap_or_default(),
            })
        }
    }

    fn entry(index: u8) -> SignatureEntry {
        SignatureEntry {
            signature: Signature::from([index; 64]),
            slot: u64::from(index),
            succeeded: true,
        }
    }

    fn transaction(entry: SignatureEntry) -> ShieldedTransaction {
        ShieldedTransaction {
            slot: entry.slot,
            tx_signature: entry.signature,
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: Vec::new(),
            messages: Vec::new(),
            nullifiers: Vec::new(),
            proofless: true,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }

    fn request(position: HistoryPosition) -> FinalizedPage {
        FinalizedPage {
            ring: RING,
            position,
            limit: NonZeroU32::new(1).unwrap(),
            selection: HistorySelection::Ring,
        }
    }

    #[tokio::test]
    async fn continuation_reuses_the_canonical_manifest() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1), entry(2), entry(3)]);
        let mut position = HistoryPosition::default();
        for slot in 1..=3 {
            let page = history.read(request(position), &source).await.unwrap();
            assert_eq!(page.data[0].slot, slot);
            let _ = position.advance(&page, 1).unwrap();
        }
        assert_eq!(position.checkpoint(), Some(3));
        assert_eq!(source.signature_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_newer_backfill_does_not_evict_an_older_reader() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1), entry(2), entry(3), entry(4)]);
        source.through.store(3, Ordering::SeqCst);
        let first = history
            .read(request(HistoryPosition::default()), &source)
            .await
            .unwrap();
        let old_cursor = first.pagination_token.unwrap();
        source.through.store(4, Ordering::SeqCst);
        let new = history
            .read(request(HistoryPosition::after_slot(3)), &source)
            .await
            .unwrap();
        assert_eq!(new.data[0].slot, 4);
        let old = history
            .read(request(HistoryPosition::resume(old_cursor)), &source)
            .await
            .unwrap();
        assert_eq!(old.data[0].slot, 2);
        assert_eq!(source.signature_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn tag_pages_bound_work_by_examined_signatures() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1), entry(2), entry(3)]);
        let mut page = request(HistoryPosition::default());
        page.selection = HistorySelection::Tag([9; 32]);
        let page = history.read(page, &source).await.unwrap();
        assert_eq!(page.data.len(), 1);
        assert!(page.data[0].events.is_empty());
        assert_eq!(page.pagination_token, Some(entry(1).position()));
        assert_eq!(source.origin_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_omitted_event_stops_the_page_and_can_retry() {
        let history = FinalizedHistory::default();
        let mut source = Source::new(&[entry(1)]);
        let mut second = transaction(entry(1));
        second.event_index = Some(1);
        source
            .transactions
            .get_mut(&entry(1).signature)
            .unwrap()
            .push(second.clone());
        assert!(history
            .read(request(HistoryPosition::default()), &source)
            .await
            .is_err());
        source
            .indexed
            .lock()
            .unwrap()
            .get_mut(&entry(1).signature)
            .unwrap()
            .push(IndexedShieldedTransaction {
                event_index: 1,
                transaction: second,
            });
        let page = history
            .read(request(HistoryPosition::default()), &source)
            .await
            .unwrap();
        assert_eq!(page.data[0].events.len(), 2);
        assert_eq!(source.signature_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_duplicate_indexed_event_stops_the_page() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(1)]);
        {
            let mut indexed = source.indexed.lock().unwrap();
            let rows = indexed.get_mut(&entry(1).signature).unwrap();
            rows.push(rows[0].clone());
        }
        assert!(history
            .read(request(HistoryPosition::default()), &source)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn an_orphaned_index_row_cannot_replace_a_canonical_event() {
        let history = FinalizedHistory::default();
        let source = Source::new(&[entry(2)]);
        source.indexed.lock().unwrap().insert(
            entry(2).signature,
            vec![IndexedShieldedTransaction {
                event_index: 0,
                transaction: transaction(entry(1)),
            }],
        );
        assert!(history
            .read(request(HistoryPosition::default()), &source)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn restart_reads_only_canonical_signatures_after_the_checkpoint() {
        let source = Source::new(&[entry(1), entry(3)]);
        source.indexed.lock().unwrap().insert(
            entry(2).signature,
            vec![IndexedShieldedTransaction {
                event_index: 0,
                transaction: transaction(entry(2)),
            }],
        );
        let page = FinalizedHistory::default()
            .read(request(HistoryPosition::after_slot(1)), &source)
            .await
            .unwrap();
        assert_eq!(page.data[0].signature, entry(3).signature);
        assert_eq!(page.context.slot, 3);
        assert!(page.pagination_token.is_none());
    }

    #[tokio::test]
    async fn a_finalized_snapshot_excludes_later_signatures() {
        let source = Source::new(&[entry(1), entry(2)]);
        source.through.store(1, Ordering::SeqCst);
        let page = FinalizedHistory::default()
            .read(request(HistoryPosition::default()), &source)
            .await
            .unwrap();
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.data[0].slot, 1);
        assert!(page.pagination_token.is_none());
        assert_eq!(page.context.slot, 1);
    }
    #[tokio::test]
    async fn production_reads_require_finality_and_the_snapshot_slot() {
        use jsonrpsee::{server::ServerBuilder, types::ErrorObjectOwned, RpcModule};

        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut module = RpcModule::new(());
        module
            .register_method("getSlot", |params, _, _| {
                let value: serde_json::Value = params.parse().unwrap();
                assert_eq!(value[0]["commitment"], "finalized");
                Ok::<_, ErrorObjectOwned>(9u64)
            })
            .unwrap();
        module
            .register_method("getBlockTime", |params, _, _| {
                let value: serde_json::Value = params.parse().unwrap();
                assert_eq!(value[0], 9);
                Ok::<_, ErrorObjectOwned>(99i64)
            })
            .unwrap();
        module
            .register_method("getSignaturesForAddress", |params, _, _| {
                let value: serde_json::Value = params.parse().unwrap();
                assert_eq!(value[0], RING.to_string());
                assert_eq!(value[1]["commitment"], "finalized");
                assert_eq!(value[1]["minContextSlot"], 9);
                Ok::<_, ErrorObjectOwned>(json!([{
                    "signature": entry(1).signature.to_string(), "slot": 1,
                    "err": null, "memo": null, "blockTime": 1,
                    "confirmationStatus": "finalized"
                }]))
            })
            .unwrap();
        module.register_method("getTransaction", |params, _, _| {
            let value: serde_json::Value = params.parse().unwrap();
            assert_eq!(value[0], entry(1).signature.to_string());
            assert_eq!(value[1]["commitment"], "finalized");
            assert_eq!(value[1]["maxSupportedTransactionVersion"], 1);
            Ok::<_, ErrorObjectOwned>(json!({
                "slot": 1, "blockTime": 1,
                "transaction": {
                    "signatures": [entry(1).signature.to_string()],
                    "message": {
                        "header": {"numRequiredSignatures": 1, "numReadonlySignedAccounts": 0, "numReadonlyUnsignedAccounts": 0},
                        "accountKeys": [RING.to_string()],
                        "recentBlockhash": Address::default().to_string(),
                        "instructions": []
                    }
                },
                "meta": {"err": null, "status": {"Ok": null}, "fee": 0, "preBalances": [1], "postBalances": [1], "innerInstructions": []},
                "version": "legacy"
            }))
        }).unwrap();
        let handle = server.start(module);
        let url = format!("http://{address}");
        let rpc = AsyncSolanaRpc::new(&url);
        let indexer = AsyncZolanaIndexer::new(&url);
        let page = FinalizedHistory::default()
            .page(
                request(HistoryPosition::default()),
                &FinalizedUpstreams {
                    rpc: &rpc,
                    indexer: &indexer,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            page.context,
            Context {
                slot: 9,
                block_time: 99
            }
        );
        assert_eq!(page.data.len(), 1);
        assert!(page.data[0].events.is_empty());
        handle.stop().unwrap();
        handle.stopped().await;
    }
}
