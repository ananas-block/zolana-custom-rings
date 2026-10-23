use std::{
    collections::HashMap,
    ops::RangeInclusive,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use custom_ring_interface::{
    instruction::{accounts, tag},
    pda, KeyRegistryRoot, PolicyConfig, KEY_REGISTRY_EMPTY_ROOT, KEY_REGISTRY_ROOT, POLICY_CONFIG,
};
use futures::{stream, StreamExt};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use solana_account::Account;
use solana_address::Address;
use solana_transaction_status_client_types::TransactionDetails;
use thiserror::Error;
use zolana_hasher::HasherError;
use zolana_interface::state::{
    discriminator::{RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
    read_tree_id, tree_account_size, RingConfig,
};

use crate::{
    block::{BlockInfo, BlockMetadata, Instruction, TransactionInfo},
    event::{ParsedTransaction, SppEvent, Subtree},
    key_registry::{self, MemberKey, Step},
    rpc::{RpcError, SolanaRpc},
    spend_record::{self, SpendRing, SpendStore, SpendUndo},
    storage::{
        self, BlockJournal, BlockUndo, LeafWrite, PendingRing, PredecessorError, RingCursor,
        RingRoot, RingStore, Undo,
    },
};

const MAX_RETRY_DELAY_SECS: u64 = 15;
const GET_BLOCKS_PAGE: u64 = 4096;
/// Lower bound on the blocks fetched before a batch is applied.
pub(crate) const MIN_BLOCK_BATCH: usize = 32;
const ACCOUNTS_PER_REQUEST: usize = 100;
/// Journal rows older than the deepest confirmed fork are pruned.
const JOURNAL_RETENTION_SLOTS: u64 = 8_192;
/// A ring activated after its pending root expired needs a reindex.
const PENDING_TTL_SLOTS: u64 = 43_200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartSlot {
    /// Refused when the stored cursor started elsewhere.
    Slot(u64),
    /// The confirmed slot when the index is created.
    Latest,
}

impl FromStr for StartSlot {
    type Err = std::num::ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "latest" => Ok(Self::Latest),
            slot => slot.parse().map(Self::Slot),
        }
    }
}

/// Set once the index first reaches the confirmed tip.
#[derive(Clone, Debug, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn mark(&self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(crate) struct Indexer {
    pub db: Arc<DatabaseConnection>,
    pub rpc: Arc<SolanaRpc>,
    /// `None` resumes the stored cursor only.
    pub start: Option<StartSlot>,
    /// Concurrent `getBlock` requests.
    pub block_fetches: usize,
    pub readiness: Readiness,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Progress {
    CaughtUp,
    Behind,
}

impl Indexer {
    /// Two rounds of fetches per batch bound the blocks held in memory.
    fn batch_len(&self) -> usize {
        MIN_BLOCK_BATCH.max(self.block_fetches.saturating_mul(2))
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut delay = 1;
            loop {
                match self.synchronize().await {
                    Ok(Progress::Behind) => {
                        delay = 1;
                        continue;
                    }
                    Ok(Progress::CaughtUp) => {
                        self.readiness.mark();
                        delay = 1;
                    }
                    Err(error) => {
                        log::error!("ring indexer failed ({error:#})");
                        if let Err(error) = self.suspend().await {
                            log::error!("cannot mark ring lookups unavailable ({error:#})");
                        }
                        delay = (delay * 2).min(MAX_RETRY_DELAY_SECS);
                    }
                }
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        })
    }

    pub(crate) async fn synchronize(&self) -> Result<Progress> {
        let db = self.db.as_ref();
        let mut cursor = self.cursor().await?;
        // Orphaned commits rewind before any per-ring replay resumes.
        while let Some(tip) = &cursor.tip {
            if self.canonical(tip).await? {
                break;
            }
            self.rewind_tip(&mut cursor).await?;
        }
        self.replay_pending(&cursor).await?;
        // Scanning from the canonical tip includes slots a fork filled.
        cursor.scanned_slot = cursor
            .tip
            .as_ref()
            .map_or(cursor.start_slot, |tip| tip.slot);
        let target = self.rpc.get_slot().await?;
        if cursor.scanned_slot < target {
            cursor.suspend(db).await?;
            let batch = block_batch(
                &self.rpc,
                cursor.scanned_slot + 1..=target,
                self.batch_len(),
            )
            .await?;
            for block in self.fetch_blocks(batch.slots).await {
                let block = block?;
                if cursor
                    .tip
                    .as_ref()
                    .is_some_and(|tip| !tip.is_parent_of(&block.metadata))
                {
                    bail!("ring block parent mismatch");
                }
                let tx = db.begin().await?;
                self.apply_block(&tx, &block, &mut cursor).await?;
                tx.commit().await?;
            }
            cursor.scanned_slot = batch.scanned_slot;
            storage::save_cursor(db, &cursor).await?;
            let pruned_below = cursor.scanned_slot.saturating_sub(JOURNAL_RETENTION_SLOTS);
            storage::prune_journal(db, pruned_below).await?;
        }
        if cursor.scanned_slot < target {
            return Ok(Progress::Behind);
        }
        // Invalid ring accounts must not serve proofs.
        self.check_roots(&cursor, target).await?;
        cursor.resume(db).await?;
        Ok(Progress::CaughtUp)
    }

    /// The cursor stores the last scanned slot, one before the first indexed one.
    pub(crate) async fn cursor(&self) -> Result<RingCursor> {
        let db = self.db.as_ref();
        match (storage::cursor(db).await?, self.start) {
            (Some(cursor), Some(StartSlot::Slot(slot)))
                if cursor.start_slot != slot.saturating_sub(1) =>
            {
                bail!(
                    "the stored ring index starts after slot {}, not before slot {slot}",
                    cursor.start_slot
                )
            }
            (Some(cursor), _) => Ok(cursor),
            (None, start) => {
                let scanned = match start.context("the ring index is empty, pass a start slot")? {
                    StartSlot::Slot(slot) => slot.saturating_sub(1),
                    StartSlot::Latest => self.rpc.get_slot().await?,
                };
                let cursor = RingCursor::new(scanned);
                storage::save_cursor(db, &cursor).await?;
                Ok(cursor)
            }
        }
    }

    async fn suspend(&self) -> Result<()> {
        let db = self.db.as_ref();
        if let Some(mut cursor) = storage::cursor(db).await? {
            cursor.suspend(db).await?;
        }
        Ok(())
    }

    pub(crate) async fn rewind_tip(&self, cursor: &mut RingCursor) -> Result<()> {
        let db = self.db.as_ref();
        cursor.suspend(db).await?;
        let tx = db.begin().await?;
        storage::rollback(&tx, cursor).await?;
        tx.commit().await?;
        Ok(())
    }

    /// A pruned slot reads as noncanonical.
    async fn canonical(&self, meta: &BlockMetadata) -> Result<bool> {
        match self
            .rpc
            .get_block(meta.slot, TransactionDetails::None)
            .await
        {
            Ok(block) => Ok(block.blockhash == meta.blockhash.to_string()),
            Err(error) if error.is_slot_skipped() => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn replay_pending(&self, cursor: &RingCursor) -> Result<()> {
        let db = self.db.as_ref();
        let Some(tip) = &cursor.tip else {
            return Ok(());
        };
        let pending = storage::pending(db).await?;
        let programs = pending
            .iter()
            .map(|candidate| Address::new_from_array(candidate.program))
            .collect::<Vec<_>>();
        let registered = registered_rings(&self.rpc, &programs).await?;
        for (candidate, registered) in pending.into_iter().zip(registered) {
            if !registered {
                if candidate.replayed_tip.is_none()
                    && candidate.slot < tip.slot.saturating_sub(PENDING_TTL_SLOTS)
                {
                    storage::delete_pending(db, &candidate.program).await?;
                }
                continue;
            }
            if let Err(error) = self.replay_ring(&candidate, tip).await {
                // The checkpoint confines replay retries to the affected ring.
                log::warn!(
                    "ring {} replay paused ({error:#})",
                    Address::new_from_array(candidate.program)
                );
            }
        }
        Ok(())
    }

    /// Other rings keep serving, only the candidate's instructions are applied.
    async fn replay_ring(&self, candidate: &PendingRing, tip: &BlockMetadata) -> Result<()> {
        let db = self.db.as_ref();
        let mut candidate = candidate.clone();
        // Resume only while the last durable replay block remains canonical.
        if let Some(checkpoint) = &candidate.replayed_tip {
            if !self.canonical(checkpoint).await? {
                bail!("ring replay checkpoint is no longer canonical, waiting for rollback");
            }
        }
        let mut start = candidate
            .replayed_tip
            .as_ref()
            .map_or(Ok(candidate.slot), |tip| {
                tip.slot.checked_add(1).context("slot overflow")
            })?;
        while start <= tip.slot {
            let end = tip.slot.min(start.saturating_add(GET_BLOCKS_PAGE - 1));
            let page = confirmed_page(&self.rpc, start..=end).await?;
            if candidate.replayed_tip.is_none() && page.first() != Some(&candidate.slot) {
                bail!("ring initialization is missing from archive history");
            }
            for chunk in page.chunks(self.batch_len()) {
                for block in self.fetch_blocks(chunk.to_vec()).await {
                    let block = block?;
                    if candidate.replayed_tip.is_none()
                        && block.metadata.blockhash != candidate.blockhash
                    {
                        bail!("ring initialization is no longer canonical");
                    }
                    if candidate
                        .replayed_tip
                        .as_ref()
                        .is_some_and(|checkpoint| !checkpoint.is_parent_of(&block.metadata))
                    {
                        bail!("ring replay parent mismatch");
                    }
                    let journal = storage::journal(db, block.metadata.slot).await?;
                    if journal.as_ref().is_some_and(|journal| {
                        journal.metadata.blockhash != block.metadata.blockhash
                    }) {
                        bail!("ring replay crossed a confirmed fork");
                    }
                    // Replay progress and undo data must commit together.
                    let tx = db.begin().await?;
                    let undo = self
                        .index_block(&tx, &block, Scope::Ring(candidate.program))
                        .await?;
                    if let Some(mut journal) = journal {
                        journal.undo.extend(undo);
                        storage::save_journal(&tx, &journal).await?;
                    }
                    candidate.replayed_tip = Some(block.metadata.clone());
                    storage::checkpoint_pending(&tx, &candidate).await?;
                    tx.commit().await?;
                }
            }
            start = end.checked_add(1).context("slot overflow")?;
        }
        // Serve the ring only after replay reaches the global tip.
        if !candidate.replayed_tip.as_ref().is_some_and(|checkpoint| {
            checkpoint.slot == tip.slot && checkpoint.blockhash == tip.blockhash
        }) {
            bail!("ring replay has not reached the confirmed ring tip");
        }
        storage::delete_pending(db, &candidate.program).await
    }

    async fn fetch_blocks(&self, slots: Vec<u64>) -> Vec<Result<BlockInfo>> {
        stream::iter(slots)
            .map(|slot| async move {
                let block = self.rpc.get_block(slot, TransactionDetails::Full).await?;
                Ok(BlockInfo::parse(block, slot)?)
            })
            .buffered(self.block_fetches.max(1))
            .collect()
            .await
    }

    pub(crate) async fn apply_block(
        &self,
        tx: &DatabaseTransaction,
        block: &BlockInfo,
        cursor: &mut RingCursor,
    ) -> Result<()> {
        let undo = self.index_block(tx, block, Scope::Every).await?;
        storage::save_journal(
            tx,
            &BlockJournal {
                metadata: block.metadata.clone(),
                previous_tip: cursor.tip.clone(),
                undo,
            },
        )
        .await?;
        cursor.tip = Some(block.metadata.clone());
        cursor.scanned_slot = block.metadata.slot;
        cursor.suspend(tx).await
    }

    async fn index_block(
        &self,
        tx: &DatabaseTransaction,
        block: &BlockInfo,
        scope: Scope,
    ) -> Result<BlockUndo> {
        BlockWork {
            tx,
            block,
            scope,
            env: BlockEnv {
                rpc: &self.rpc,
                policies: HashMap::new(),
                tree_ids: HashMap::new(),
            },
        }
        .run()
        .await
    }

    async fn check_roots(&self, cursor: &RingCursor, target: u64) -> Result<()> {
        let db = self.db.as_ref();
        for root in storage::roots(db).await? {
            if root.fault.is_some() || storage::pending_ring(db, &root.program).await?.is_some() {
                continue;
            }
            match load_root(&self.rpc, &Address::new_from_array(root.program)).await {
                // Each proof request checks the exact current root.
                Ok(_) => {}
                Err(ApplyError::Retry(error)) => return Err(error),
                Err(ApplyError::Fault(reason)) => {
                    if self.rpc.get_slot().await? > target {
                        continue;
                    }
                    let tip = cursor
                        .tip
                        .as_ref()
                        .context("root exists without a ring index tip")?;
                    let tx = db.begin().await?;
                    let mut journal = storage::journal(&tx, tip.slot)
                        .await?
                        .context("ring journal gap")?;
                    let undo = RingStore::new(&tx, root.program)
                        .quarantine(root, reason)
                        .await?;
                    journal.undo.key_registry.push(undo);
                    storage::save_journal(&tx, &journal).await?;
                    tx.commit().await?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Scope {
    Every,
    Ring([u8; 32]),
}

impl Scope {
    fn covers(self, program: &[u8; 32]) -> bool {
        match self {
            Self::Every => true,
            Self::Ring(ring) => ring == *program,
        }
    }
}

pub(crate) fn instruction_view(
    instruction: &Instruction,
) -> zolana_ring_indexer::InstructionView<'_> {
    zolana_ring_indexer::InstructionView {
        program_id: &instruction.program_id,
        accounts: &instruction.accounts,
        data: &instruction.data,
    }
}

#[derive(Debug, Error)]
pub(crate) enum ApplyError {
    /// Confined to one ring.
    #[error("{0}")]
    Fault(String),
    #[error(transparent)]
    Retry(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for ApplyError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Retry(error.into())
    }
}

impl From<RpcError> for ApplyError {
    fn from(error: RpcError) -> Self {
        Self::Retry(error.into())
    }
}

impl From<HasherError> for ApplyError {
    fn from(error: HasherError) -> Self {
        fault(format!("hashing failed ({error:?})"))
    }
}

impl From<PredecessorError> for ApplyError {
    fn from(error: PredecessorError) -> Self {
        match error {
            PredecessorError::NotAbsent => fault(error.to_string()),
            PredecessorError::Storage(error) => Self::Retry(error),
        }
    }
}

pub(crate) fn fault(reason: impl Into<String>) -> ApplyError {
    ApplyError::Fault(reason.into())
}

/// A missing or foreign ring account is the ring's fault.
fn ring_account(result: Result<Account, RpcError>) -> Result<Account, ApplyError> {
    match result {
        Err(RpcError::InvalidAccount(reason)) => Err(fault(reason)),
        other => Ok(other?),
    }
}

pub(crate) struct ChainRoot {
    pub root: [u8; 32],
    pub next_index: u64,
}

pub(crate) async fn load_root(rpc: &SolanaRpc, program: &Address) -> Result<ChainRoot, ApplyError> {
    let (address, bump) = pda::key_registry_root(program);
    let account = ring_account(rpc.get_account(&address).await)?;
    if account.owner != *program {
        return Err(fault("key registry root has the wrong owner"));
    }
    let root = bytemuck::try_from_bytes::<KeyRegistryRoot>(&account.data)
        .map_err(|_| fault("key registry root has the wrong layout"))?;
    if root.discriminator != KEY_REGISTRY_ROOT || root.bump != bump {
        return Err(fault(
            "key registry root has the wrong discriminator or bump",
        ));
    }
    let current = root
        .root()
        .ok_or_else(|| fault("key registry root has no current root"))?;
    Ok(ChainRoot {
        root: current,
        next_index: root.next_index(),
    })
}

pub(crate) struct BlockEnv<'a> {
    rpc: &'a SolanaRpc,
    policies: HashMap<[u8; 32], PolicyConfig>,
    tree_ids: HashMap<[u8; 32], u16>,
}

impl BlockEnv<'_> {
    /// One read per ring and block, a ring without a policy is at fault.
    pub(crate) async fn policy(&mut self, program: &Address) -> Result<PolicyConfig, ApplyError> {
        if let Some(policy) = self.policies.get(&program.to_bytes()) {
            return Ok(*policy);
        }
        let address = Address::find_program_address(&[PolicyConfig::SEED], program).0;
        let account = ring_account(self.rpc.get_account(&address).await)?;
        if account.owner != *program {
            return Err(fault("policy config has the wrong owner"));
        }
        let policy = bytemuck::try_from_bytes::<PolicyConfig>(&account.data)
            .map_err(|_| fault("policy config has the wrong layout"))?;
        if policy.discriminator != POLICY_CONFIG {
            return Err(fault("policy config has the wrong discriminator"));
        }
        self.policies.insert(program.to_bytes(), *policy);
        Ok(*policy)
    }

    /// A leaf hashes under the id of the tree it lands in.
    pub(crate) async fn tree_id(&mut self, tree: &Address) -> Result<u16, ApplyError> {
        if let Some(id) = self.tree_ids.get(&tree.to_bytes()) {
            return Ok(*id);
        }
        let account = ring_account(self.rpc.get_account(tree).await)?;
        let id = spp_tree_id(&account)
            .filter(|id| zolana_interface::pda::tree(*id).to_bytes() == tree.to_bytes())
            .ok_or_else(|| fault("output tree is not the SPP tree of its id"))?;
        self.tree_ids.insert(tree.to_bytes(), id);
        Ok(id)
    }
}

fn spp_tree_id(account: &Account) -> Option<u16> {
    (account.owner == zolana_interface::pda::shielded_pool_program_id()
        && account.data.len() == tree_account_size()
        && account.data.first() == Some(&TREE_ACCOUNT_DISCRIMINATOR))
    .then(|| read_tree_id(&account.data))
    .flatten()
}

pub(crate) struct Invocation<'a> {
    pub instruction: &'a Instruction,
    transaction: &'a TransactionInfo,
    subtree: Subtree,
    slot: u64,
}

impl Invocation<'_> {
    /// Sibling invocations cannot supply a transition's SPP event.
    pub(crate) fn event(&self) -> Result<SppEvent, ApplyError> {
        let events = ParsedTransaction::new(self.transaction)
            .and_then(|parsed| parsed.events(&self.subtree, self.transaction.signature, self.slot))
            .map_err(|error| fault(error.to_string()))?;
        let [event] = <[SppEvent; 1]>::try_from(events)
            .map_err(|_| fault("record update must have exactly one descendant SPP event"))?;
        Ok(event)
    }

    #[cfg(test)]
    pub(crate) fn descendants(&self) -> &[Instruction] {
        &self.transaction.instruction_groups[self.subtree.group].inner_instructions
            [self.subtree.span.clone()]
    }
}

#[derive(Clone, Copy)]
struct Position {
    group: usize,
    /// `None` for the outer instruction.
    inner: Option<usize>,
}

pub(crate) struct Invocations<'a> {
    transaction: &'a TransactionInfo,
    instructions: Vec<(Position, &'a Instruction)>,
    slot: u64,
}

impl<'a> Invocations<'a> {
    pub(crate) fn new(transaction: &'a TransactionInfo, slot: u64) -> Self {
        let instructions = transaction
            .instruction_groups
            .iter()
            .enumerate()
            .flat_map(|(group, instructions)| {
                std::iter::once((
                    Position { group, inner: None },
                    &instructions.outer_instruction,
                ))
                .chain(instructions.inner_instructions.iter().enumerate().map(
                    move |(inner, instruction)| {
                        (
                            Position {
                                group,
                                inner: Some(inner),
                            },
                            instruction,
                        )
                    },
                ))
            })
            .collect();
        Self {
            transaction,
            instructions,
            slot,
        }
    }

    fn instructions(&self) -> impl Iterator<Item = (usize, &'a Instruction)> + '_ {
        self.instructions
            .iter()
            .map(|(_, instruction)| *instruction)
            .enumerate()
    }

    pub(crate) fn invocation(&self, index: usize) -> Result<Invocation<'a>, ApplyError> {
        let &(position, instruction) = self
            .instructions
            .get(index)
            .context("invocation position out of range")?;
        let depth = instruction
            .stack_height
            .ok_or_else(|| fault("invocation has no stack height"))?;
        let start = position.inner.map_or(0, |inner| inner + 1);
        let mut end = start;
        for child in self.transaction.instruction_groups[position.group]
            .inner_instructions
            .get(start..)
            .unwrap_or_default()
        {
            let child_depth = child
                .stack_height
                .ok_or_else(|| fault("descendant has no stack height"))?;
            if child_depth <= depth {
                break;
            }
            end += 1;
        }
        Ok(Invocation {
            instruction,
            transaction: self.transaction,
            subtree: Subtree {
                group: position.group,
                span: start..end,
            },
            slot: self.slot,
        })
    }
}

struct BlockWork<'a> {
    tx: &'a DatabaseTransaction,
    block: &'a BlockInfo,
    scope: Scope,
    env: BlockEnv<'a>,
}

impl BlockWork<'_> {
    async fn run(mut self) -> Result<BlockUndo> {
        let mut undo = BlockUndo::default();
        for transaction in &self.block.transactions {
            if transaction.error.is_some() {
                continue;
            }
            self.index_spend_records(transaction, &mut undo.spend_records)
                .await?;
            self.index_key_registry(transaction, &mut undo.key_registry)
                .await?;
        }
        Ok(undo)
    }

    async fn index_key_registry(
        &mut self,
        transaction: &TransactionInfo,
        undo: &mut Vec<Undo>,
    ) -> Result<()> {
        let tx = self.tx;
        let invocations = Invocations::new(transaction, self.block.metadata.slot);
        for (position, instruction) in invocations.instructions() {
            let program = instruction.program_id.to_bytes();
            if !self.scope.covers(&program) {
                continue;
            }
            let initializes = match instruction.data.first() {
                Some(&tag::CREATE_KEY_REGISTRY_ROOT) => true,
                Some(&tag::REGISTER_KEY) => false,
                _ => continue,
            };
            if matches!(self.scope, Scope::Every)
                && storage::pending_ring(tx, &program).await?.is_some()
            {
                continue;
            }
            let store = RingStore::new(tx, program);
            if initializes {
                if let Some(address) = initialization(instruction) {
                    undo.extend(self.initialize(&store, address).await?);
                }
                continue;
            }
            let Some(root) = store.root().await? else {
                continue;
            };
            if root.fault.is_some() {
                continue;
            }
            let outcome = async {
                let invocation = invocations.invocation(position)?;
                self.advance(&root, invocation).await
            }
            .await;
            match outcome {
                Ok(Some(entry)) => undo.push(entry),
                Ok(None) => {}
                Err(ApplyError::Fault(reason)) => {
                    undo.push(store.quarantine(root, reason).await?);
                }
                Err(ApplyError::Retry(error)) => return Err(error),
            }
        }
        Ok(())
    }

    async fn index_spend_records(
        &mut self,
        transaction: &TransactionInfo,
        undo: &mut Vec<SpendUndo>,
    ) -> Result<()> {
        let tx = self.tx;
        let invocations = Invocations::new(transaction, self.block.metadata.slot);
        for (position, instruction) in invocations.instructions() {
            let program = instruction.program_id.to_bytes();
            let Some(first) = instruction.data.first().copied() else {
                continue;
            };
            if !self.scope.covers(&program) || !spend_record::TAGS.contains(&first) {
                continue;
            }
            if matches!(self.scope, Scope::Every)
                && storage::pending_ring(tx, &program).await?.is_some()
            {
                continue;
            }
            let store = SpendStore::new(tx, program);
            // A ring's first registration opens its records.
            let ring = match store.ring().await? {
                Some(ring) => ring,
                None if first == tag::REGISTER_SPEND => {
                    if !self.admit(program).await? {
                        continue;
                    }
                    undo.push(store.open().await?);
                    SpendRing { fault: None }
                }
                None => continue,
            };
            if ring.fault.is_some() {
                continue;
            }
            let outcome = async {
                let invocation = invocations.invocation(position)?;
                store.advance(&invocation, &mut self.env).await
            }
            .await;
            match outcome {
                Ok(Some(entry)) => undo.push(entry),
                Ok(None) => {}
                Err(ApplyError::Fault(reason)) => undo.push(store.quarantine(reason).await?),
                Err(ApplyError::Retry(error)) => return Err(error),
            }
        }
        Ok(())
    }

    /// `false` parks an inactive ring for replay once it activates.
    async fn admit(&mut self, program: [u8; 32]) -> Result<bool> {
        if registered_ring(self.env.rpc, &Address::new_from_array(program)).await? {
            return Ok(true);
        }
        if matches!(self.scope, Scope::Ring(_)) {
            bail!("ring became inactive during replay");
        }
        storage::save_pending(
            self.tx,
            &PendingRing {
                program,
                slot: self.block.metadata.slot,
                blockhash: self.block.metadata.blockhash.clone(),
                replayed_tip: None,
            },
        )
        .await?;
        Ok(false)
    }

    async fn initialize(
        &mut self,
        store: &RingStore<'_, DatabaseTransaction>,
        address: [u8; 32],
    ) -> Result<Option<Undo>> {
        let program = Address::new_from_array(store.program());
        if !self.admit(store.program()).await? {
            return Ok(None);
        }
        if let Some(existing) = store.root().await? {
            return Ok(Some(
                store
                    .quarantine(existing, "initialized twice".into())
                    .await?,
            ));
        }
        let root = RingRoot {
            program: store.program(),
            address,
            root: KEY_REGISTRY_EMPTY_ROOT,
            next_index: 1,
            fault: None,
        };
        match load_root(self.env.rpc, &program).await {
            Ok(_) => {}
            Err(ApplyError::Fault(reason)) => {
                let mut created = store.quarantine(root, reason).await?;
                created.before = None;
                return Ok(Some(created));
            }
            Err(ApplyError::Retry(error)) => return Err(error),
        }
        let sentinel = MemberKey::sentinel();
        let computed = store
            .tree()
            .write(&[LeafWrite {
                index: 0,
                hash: sentinel.hash()?,
            }])
            .await?;
        if computed != KEY_REGISTRY_EMPTY_ROOT {
            bail!("key registry sentinel root mismatch");
        }
        store.save_root(&root).await?;
        store.save_member(&sentinel).await?;
        Ok(Some(Undo {
            program: root.program,
            before: None,
            members: vec![],
            leaves: vec![],
        }))
    }

    async fn advance(
        &mut self,
        root: &RingRoot,
        invocation: Invocation<'_>,
    ) -> Result<Option<Undo>, ApplyError> {
        let Some(transition) = key_registry::transition(&invocation)? else {
            return Ok(None);
        };
        let savepoint = self.tx.begin().await?;
        let applied = key_registry::apply(
            &RingStore::new(&savepoint, root.program),
            Step { root, transition },
        )
        .await;
        match applied {
            Ok(entry) => {
                savepoint.commit().await?;
                Ok(Some(entry))
            }
            Err(error) => {
                savepoint.rollback().await?;
                Err(error)
            }
        }
    }
}

fn initialization(instruction: &Instruction) -> Option<[u8; 32]> {
    let root = pda::key_registry_root(&instruction.program_id).0;
    let named = instruction
        .accounts
        .get(accounts::CREATE_KEY_REGISTRY_ROOT_ROOT);
    (named == Some(&root)).then_some(root.to_bytes())
}

async fn registered_ring(rpc: &SolanaRpc, program: &Address) -> Result<bool> {
    Ok(registered_rings(rpc, std::slice::from_ref(program)).await? == [true])
}

async fn registered_rings(rpc: &SolanaRpc, programs: &[Address]) -> Result<Vec<bool>> {
    let mut registered = Vec::with_capacity(programs.len());
    for chunk in programs.chunks(ACCOUNTS_PER_REQUEST) {
        let addresses = chunk
            .iter()
            .map(|program| zolana_interface::pda::ring_auth(program).0)
            .collect::<Vec<_>>();
        let accounts = rpc.get_multiple_accounts(&addresses).await?;
        registered.extend(chunk.iter().zip(accounts).map(|(program, account)| {
            account.is_some_and(|account| activated_ring_config(&account, program))
        }));
    }
    Ok(registered)
}

fn activated_ring_config(account: &Account, program: &Address) -> bool {
    account.owner == zolana_interface::pda::shielded_pool_program_id()
        && bytemuck::try_from_bytes::<RingConfig>(&account.data).is_ok_and(|config| {
            config.discriminator == RING_CONFIG
                && config.program_id == *program
                && config.is_activated()
        })
}

pub(crate) struct BlockBatch {
    pub slots: Vec<u64>,
    pub scanned_slot: u64,
}

pub(crate) async fn block_batch(
    rpc: &SolanaRpc,
    slots: RangeInclusive<u64>,
    batch_len: usize,
) -> Result<BlockBatch> {
    let mut start = *slots.start();
    let target = *slots.end();
    let mut batch = Vec::new();
    loop {
        let end = target.min(start.saturating_add(GET_BLOCKS_PAGE - 1));
        let page = confirmed_page(rpc, start..=end).await?;
        let available = batch_len - batch.len();
        if page.len() > available {
            batch.extend(page.into_iter().take(available));
            let scanned = *batch.last().context("empty block batch")?;
            return Ok(BlockBatch {
                slots: batch,
                scanned_slot: scanned,
            });
        }
        batch.extend(page);
        if end == target || batch.len() == batch_len {
            return Ok(BlockBatch {
                slots: batch,
                scanned_slot: end,
            });
        }
        start = end.checked_add(1).context("slot overflow")?;
    }
}

async fn confirmed_page(rpc: &SolanaRpc, range: RangeInclusive<u64>) -> Result<Vec<u64>> {
    let page = rpc.get_blocks(range.clone()).await?;
    if page.iter().any(|slot| !range.contains(slot))
        || page.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("invalid confirmed block order");
    }
    Ok(page)
}
