//! The notes a ring's auditor opened, their nullifiers, and the keys its credentials hold.
//!
//! Each page also names the notes it moved in an owner's active set, the page commit writes them
//! to `storage/owner_notes.rs`. Wallet reads page over that set.
//!
//! Beside a database the mirror is a bounded cache of the projection. A page records its steps,
//! then `PageWork::finish` replays them against the page's delta, the rows it loaded and the cache.
//! A replay that meets a key the cache may have evicted loads it and replays again, so every
//! decision reads the row storage holds. Only commits and reloads fill the cache, a read never does.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{PoisonError, RwLock},
    time::Duration,
};

use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::{Context, Hash};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{NullifierKey, PublicKey};
use spr_transaction::{Data, Mint, Utxo, WalletUtxo};
use tokio::sync::Mutex as AsyncMutex;
use zolana_ring_client::{
    history::HistoryPosition,
    rpc::{
        AuditedUtxoView, DecryptedInput, DecryptedInputClass, GetSpendCoverageResponse,
        GetWalletStatusResponse, InputParty, SpendCoverageFrame, SpendCoverageRow, WalletBalance,
        WalletEnrollment, WalletNote, WalletNoteStatus,
    },
    AuditedMergeOutput, ConfirmedMerge, CreatedUtxo, DepositOwner, DepositOwners, KnownUtxo,
    UtxoOwner,
};
use zolana_ring_policy::Member;
use zolana_ring_transaction::RingAssets;

use crate::{
    bounded_map::{BoundedMap, Cached},
    credentials::{CredentialRefusal, HeldCredential, HeldCredentials},
    database::Store,
    error::RingRpcError,
    frame_repairs::RepairBook,
    owner_notes::OwnerNotesRead,
    projection_lease::ProjectionLease,
    projection_reads::ProjectionReads,
    spend_machine::{InputRead, NoteRead, Observation, SpendRow, SpendState, Transition},
    spent_index::{state_name, Checkpoint, HistoryScope, LoadedSpends, NoteSeal},
};

pub const UTXO_BACKFILL_INTERVAL: Duration = Duration::from_secs(30);

/// Pages one backfill run reads, the next run resumes from its position.
pub(crate) const MAX_BACKFILL_PAGES: usize = 64;

/// Entries the mirror keeps of each history map beside a database, the rest read from storage.
pub(crate) const MAX_CACHED_ENTRIES: usize = 65_536;

/// Each round loads every key the last replay missed, a later round meets only keys an earlier
/// load revealed.
const MAX_LOAD_ROUNDS: usize = 4;

/// The guards are never held across an await, a commit writes the mirror after its transaction.
#[derive(Default)]
pub(crate) struct AuditStore {
    book: RwLock<SpendBook>,
    credentials: RwLock<HeldCredentials>,
    /// The registry last named on the notes, a different one names them again.
    assets: RwLock<Option<RingAssets>>,
    /// Owners whose key arrived, kept until a committed page derived their notes.
    late_owners: RwLock<BTreeSet<[u8; 32]>>,
    /// One backfill and key refresh at a time.
    pub(crate) backfill: AsyncMutex<Backfill>,
    backing: Backing,
}

#[derive(Default)]
pub(crate) enum Backing {
    /// No database, the mirror is the only copy.
    #[default]
    Memory,
    Database {
        store: Store,
        ring: Address,
        seal: Box<NoteSeal>,
        capacity: usize,
    },
    /// The ring's seal failed to derive, every read beyond the mirror refuses.
    Unavailable,
}

#[derive(Default)]
pub(crate) struct Backfill {
    /// `None` until the durable tables load.
    pub history: Option<HistoryPosition>,
    /// Durable on the lease holder, a restart resumes the scan where its last page committed.
    pub credentials: HistoryPosition,
    pub repairs: RepairBook,
    /// The lease the last claim returned, `None` while another replica writes the ring.
    pub writer: Option<ProjectionLease>,
}

/// The three history maps hold every entry without a database and a bounded cache beside one.
#[derive(Default)]
struct SpendBook {
    notes: BoundedMap<[u8; 32], StoredUtxo>,
    /// The note index, a late secret fills it for that owner's notes.
    by_nullifier: BoundedMap<[u8; 32], [u8; 32]>,
    rows: BoundedMap<[u8; 32], SpendRow>,
    /// Kept only by a complete mirror, a database holds the owner index of a cache.
    active: ActiveIndex,
    unread: BTreeSet<CreatedIn>,
    faults: Vec<SpendRow>,
    context: Context,
    position_slot: Option<u64>,
    /// The projection revision every cached entry is current at, `None` before the first load.
    revision: Option<i64>,
}

/// What one page changes, the mirror takes it after its database transaction commits.
#[derive(Default)]
pub(crate) struct PageDelta {
    notes: BTreeMap<[u8; 32], StoredUtxo>,
    by_nullifier: HashMap<[u8; 32], [u8; 32]>,
    rows: BTreeMap<[u8; 32], SpendRow>,
    unread: BTreeSet<CreatedIn>,
    read: BTreeSet<CreatedIn>,
    faults: Vec<SpendRow>,
    checkpoint: Option<Checkpoint>,
    late_owners: Vec<[u8; 32]>,
    owners: Vec<OwnerChange>,
    /// The history slot before the page, a spend at or before it leaves the index.
    prune_through: u64,
    /// Set once the page commits, the cache is current through it.
    revision: Option<i64>,
}

/// The keys of each owner's live notes and of spends past the pruned slot.
#[derive(Default)]
struct ActiveIndex {
    by_owner: HashMap<[u8; 32], BTreeMap<[u8; 32], Option<u64>>>,
    settling: BTreeSet<(u64, [u8; 32], [u8; 32])>,
}

/// One note's whole index row as a page leaves it, keyed by its owner's member tag.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OwnerChange {
    pub member: [u8; 32],
    pub note: IndexedNote,
}

/// `key` orders a wallet page and names its cursor, the commitment in memory and the note tag on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IndexedNote {
    pub key: [u8; 32],
    pub commitment: [u8; 32],
    pub note: StoredUtxo,
    pub spent_at: Option<u64>,
}

/// The steps of one page, replayed by `finish` once every key they read is at hand.
#[must_use]
pub(crate) struct PageWork<'a> {
    store: &'a AuditStore,
    steps: Vec<PageStep>,
    opener: &'a (dyn Fn(&[u8; 32]) -> Option<NullifierKey> + Sync),
}

enum PageStep {
    Open {
        created_in: CreatedIn,
        utxos: Vec<CreatedUtxo>,
    },
    Observe(Observation),
    MarkRead(CreatedIn),
    MarkUnread(CreatedIn),
    LateKeys,
    Checkpoint {
        position: HistoryPosition,
        terminal: Option<Context>,
    },
}

/// One replay's overlay, a later step reads what an earlier step opened.
struct Replay<'a> {
    store: &'a AuditStore,
    loaded: &'a Loaded,
    delta: PageDelta,
    /// Read to derive and dropped with the page, never persisted.
    keys: HashMap<[u8; 32], Option<NullifierKey>>,
    opener: &'a (dyn Fn(&[u8; 32]) -> Option<NullifierKey> + Sync),
    missed: Missed,
}

/// Storage's answer for each key a replay missed, `None` where storage holds no row.
#[derive(Default)]
struct Loaded {
    notes: HashMap<[u8; 32], Option<StoredUtxo>>,
    by_nullifier: HashMap<[u8; 32], Option<[u8; 32]>>,
    rows: HashMap<[u8; 32], Option<SpendRow>>,
    owners: HashMap<[u8; 32], Vec<[u8; 32]>>,
}

#[derive(Default)]
struct Missed {
    notes: BTreeSet<[u8; 32]>,
    by_nullifier: BTreeSet<[u8; 32]>,
    rows: BTreeSet<[u8; 32]>,
    owners: BTreeSet<[u8; 32]>,
}

/// The inputs of a page that resolved to the reading wallet's notes.
#[derive(Debug, Default)]
pub(crate) struct InputParties {
    own: HashSet<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CreatedIn {
    pub slot: u64,
    pub tx_signature: Signature,
    pub event_index: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct WalletStatusQuery {
    pub enrollment: WalletEnrollment,
    pub wallet: Address,
    pub after: Option<[u8; 32]>,
    pub limit: usize,
}

#[must_use]
pub(crate) struct SpendableNotes<'a> {
    pub ring: Address,
    pub owner_key: [u8; 32],
    pub mint: Mint,
    pub nullifier_key: &'a NullifierKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredUtxo {
    pub utxo: KnownUtxo,
    pub created_in: CreatedIn,
    pub slot_index: u32,
    pub leaf_index: u64,
    /// False on an exit, its note leaves the ring.
    pub ring_note: bool,
    /// `None` until the owner's secret names it.
    pub nullifier: Option<[u8; 32]>,
}

impl SpendBook {
    fn bounded(capacity: usize) -> Self {
        Self {
            notes: BoundedMap::bounded(capacity),
            by_nullifier: BoundedMap::bounded(capacity),
            rows: BoundedMap::bounded(capacity),
            ..Self::default()
        }
    }

    const fn is_complete(&self) -> bool {
        self.notes.is_complete()
    }

    fn absorb(&mut self, delta: PageDelta) {
        if self.is_complete() {
            self.active.apply(&delta.owners, delta.prune_through);
        }
        self.notes.extend(delta.notes);
        self.by_nullifier.extend(delta.by_nullifier);
        self.rows.extend(delta.rows);
        for frame in delta.read {
            self.unread.remove(&frame);
        }
        self.unread.extend(delta.unread);
        for fault in delta.faults {
            if !self.faults.contains(&fault) {
                self.faults.push(fault);
            }
        }
        if let Some(checkpoint) = delta.checkpoint {
            self.position_slot = checkpoint.position.checkpoint();
            if checkpoint.through.slot >= self.context.slot {
                self.context = checkpoint.through;
            }
        }
        if delta.revision.is_some() {
            self.revision = delta.revision;
        }
    }

    fn history_through(&self) -> u64 {
        history_through(self.unread.first(), self.context.slot)
    }

    fn history_scope(&self) -> HistoryScope {
        match (self.is_complete(), self.revision) {
            (true, _) => HistoryScope::Everything,
            (false, Some(revision)) => HistoryScope::ChangedSince(revision),
            (false, None) => HistoryScope::Cold,
        }
    }

    fn owner_notes(&self, member: &[u8; 32]) -> Vec<IndexedNote> {
        let Some(keys) = self.active.by_owner.get(member) else {
            return Vec::new();
        };
        keys.iter()
            .filter_map(|(commitment, spent_at)| {
                Some(IndexedNote {
                    key: *commitment,
                    commitment: *commitment,
                    note: *self.notes.get(commitment)?,
                    spent_at: *spent_at,
                })
            })
            .collect()
    }
}

/// Only an unreadable frame holds the claim back, an unresolved row never does.
fn history_through(first_unread: Option<&CreatedIn>, context_slot: u64) -> u64 {
    first_unread.map_or(context_slot, |frame| {
        context_slot.min(frame.slot.saturating_sub(1))
    })
}

impl ActiveIndex {
    fn apply(&mut self, changes: &[OwnerChange], prune_through: u64) {
        for change in changes {
            let IndexedNote {
                commitment,
                spent_at,
                ..
            } = change.note;
            self.by_owner
                .entry(change.member)
                .or_default()
                .insert(commitment, spent_at);
            if let Some(slot) = spent_at {
                self.settling.insert((slot, change.member, commitment));
            }
        }
        while let Some(&(slot, member, commitment)) = self.settling.first() {
            if slot > prune_through {
                break;
            }
            self.settling.pop_first();
            if let Some(keys) = self.by_owner.get_mut(&member) {
                keys.remove(&commitment);
                if keys.is_empty() {
                    self.by_owner.remove(&member);
                }
            }
        }
    }
}

impl IndexedNote {
    /// Reads one note's own spend and no other row.
    fn status(&self, through: u64) -> WalletNoteStatus {
        let utxo = &self.note.utxo;
        NoteRead {
            nullifier_known: self.note.nullifier.is_some(),
            spent_at: self.spent_at,
            zero_key_wallet: utxo.owner.nullifier_pk() == Some(ZERO_NULLIFIER_PUBKEY)
                && Address::new_from_array(utxo.owner_key).is_on_curve(),
            history_through: through,
        }
        .status()
    }
}

/// Balances over every listed note, the page holds those after the cursor in key order.
fn wallet_page(
    notes: &[IndexedNote],
    query: WalletStatusQuery,
    through: u64,
) -> GetWalletStatusResponse {
    let mut balances: BTreeMap<[u8; 32], WalletBalance> = BTreeMap::new();
    let mut listed = Vec::new();
    let mut last_key = None;
    let mut cursor = None;
    for indexed in notes {
        let note = &indexed.note;
        // A spent input and its change never both count.
        if note.created_in.slot > through {
            continue;
        }
        let status = indexed.status(through);
        if status == WalletNoteStatus::Spent {
            continue;
        }
        if status == WalletNoteStatus::Unspent {
            let balance = balances
                .entry(note.utxo.asset)
                .or_insert_with(|| WalletBalance {
                    asset: Hash(note.utxo.asset),
                    mint: note.utxo.mint.map(Into::into),
                    amount: 0,
                });
            balance.amount = balance.amount.saturating_add(note.utxo.amount);
        }
        if query.after.is_some_and(|after| indexed.key <= after) {
            continue;
        }
        if listed.len() == query.limit {
            cursor = last_key.map(|key: [u8; 32]| key.to_vec().into());
            continue;
        }
        last_key = Some(indexed.key);
        listed.push(note.wallet_note(&indexed.commitment, status));
    }
    GetWalletStatusResponse {
        history_through: through,
        enrollment: query.enrollment,
        balances: balances.into_values().collect(),
        notes: listed,
        cursor,
    }
}

impl PageDelta {
    pub(crate) fn notes(&self) -> impl Iterator<Item = (&[u8; 32], &StoredUtxo)> {
        self.notes.iter()
    }

    pub(crate) fn rows(&self) -> impl Iterator<Item = &SpendRow> {
        self.rows.values()
    }

    pub(crate) fn faults(&self) -> &[SpendRow] {
        &self.faults
    }

    pub(crate) fn read_frames(&self) -> impl Iterator<Item = &CreatedIn> {
        self.read.iter()
    }

    pub(crate) fn unread_frames(&self) -> impl Iterator<Item = &CreatedIn> {
        self.unread.iter()
    }

    pub(crate) const fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoint.as_ref()
    }

    pub(crate) fn owner_changes(&self) -> &[OwnerChange] {
        &self.owners
    }

    pub(crate) const fn prune_through(&self) -> u64 {
        self.prune_through
    }

    /// The revision its commit wrote, the cache is current through it once the mirror takes it.
    #[must_use]
    pub(crate) const fn at_revision(mut self, revision: i64) -> Self {
        self.revision = Some(revision);
        self
    }
}

impl<'a> PageWork<'a> {
    pub(crate) fn new(
        store: &'a AuditStore,
        opener: &'a (dyn Fn(&[u8; 32]) -> Option<NullifierKey> + Sync),
    ) -> Self {
        Self {
            store,
            steps: Vec::new(),
            opener,
        }
    }

    /// A later opening of a known commitment changes it only to name its mint.
    pub(crate) fn open(
        &mut self,
        created_in: CreatedIn,
        utxos: impl IntoIterator<Item = CreatedUtxo>,
    ) {
        self.steps.push(PageStep::Open {
            created_in,
            utxos: utxos.into_iter().collect(),
        });
    }

    pub(crate) fn observe(&mut self, observation: Observation) {
        self.steps.push(PageStep::Observe(observation));
    }

    /// Retries with every other frame the backfill keeps.
    pub(crate) fn mark_unread(&mut self, frame: CreatedIn) {
        self.steps.push(PageStep::MarkUnread(frame));
    }

    pub(crate) fn mark_read(&mut self, frame: CreatedIn) {
        self.steps.push(PageStep::MarkRead(frame));
    }

    /// A late key recomputes that owner's notes, a failed page leaves the owner to the next.
    pub(crate) fn late_keys(&mut self) {
        self.steps.push(PageStep::LateKeys);
    }

    /// Reads the next position with the terminal page's context, when the page ended the read.
    pub(crate) fn checkpoint(&mut self, position: HistoryPosition, terminal: Option<Context>) {
        self.steps.push(PageStep::Checkpoint { position, terminal });
    }

    /// Replays the steps until no read misses, each round loading what the last one missed.
    pub(crate) async fn finish(self) -> Result<PageDelta, RingRpcError> {
        let mut loaded = Loaded::default();
        for _ in 0..MAX_LOAD_ROUNDS {
            let mut replay = Replay {
                store: self.store,
                loaded: &loaded,
                delta: PageDelta::default(),
                keys: HashMap::new(),
                opener: self.opener,
                missed: Missed::default(),
            };
            for step in &self.steps {
                replay.run(step);
            }
            replay.close();
            if replay.missed.is_empty() {
                let delta = replay.delta;
                for fault in &delta.faults {
                    log::error!(
                        "nullifier {} of {}:{} repeats a settled row",
                        Hash(fault.nullifier).to_base58(),
                        fault.frame.tx_signature,
                        fault.frame.event_index
                    );
                }
                return Ok(delta);
            }
            let missed = replay.missed;
            self.store.load(missed, &mut loaded).await?;
        }
        Err(RingRpcError::StateUnavailable)
    }
}

impl Missed {
    fn is_empty(&self) -> bool {
        self.notes.is_empty()
            && self.by_nullifier.is_empty()
            && self.rows.is_empty()
            && self.owners.is_empty()
    }
}

impl Replay<'_> {
    fn run(&mut self, step: &PageStep) {
        match step {
            PageStep::Open { created_in, utxos } => self.open(*created_in, utxos),
            PageStep::Observe(observation) => self.observe(*observation),
            PageStep::MarkRead(frame) => {
                if !self.delta.unread.contains(frame) {
                    self.delta.read.insert(*frame);
                }
            }
            PageStep::MarkUnread(frame) => {
                self.delta.read.remove(frame);
                self.delta.unread.insert(*frame);
            }
            PageStep::LateKeys => self.late_keys(),
            PageStep::Checkpoint { position, terminal } => {
                let through = terminal.unwrap_or_else(|| self.store.context());
                self.delta.checkpoint = Some(Checkpoint {
                    position: *position,
                    through,
                });
            }
        }
    }

    /// The delta first, then storage's answer, then the cache, a cache miss records the key.
    fn note(&mut self, commitment: &[u8; 32]) -> Option<StoredUtxo> {
        if let Some(note) = self.delta.notes.get(commitment) {
            return Some(*note);
        }
        if let Some(note) = self.loaded.notes.get(commitment) {
            return *note;
        }
        let cached = self.store.read_book().notes.cached(commitment);
        self.answer(cached, |missed| missed.notes.insert(*commitment))
    }

    fn note_of_nullifier(&mut self, nullifier: &[u8; 32]) -> Option<[u8; 32]> {
        if let Some(commitment) = self.delta.by_nullifier.get(nullifier) {
            return Some(*commitment);
        }
        if let Some(commitment) = self.loaded.by_nullifier.get(nullifier) {
            return *commitment;
        }
        let cached = self.store.read_book().by_nullifier.cached(nullifier);
        self.answer(cached, |missed| missed.by_nullifier.insert(*nullifier))
    }

    fn row(&mut self, nullifier: &[u8; 32]) -> Option<SpendRow> {
        if let Some(row) = self.delta.rows.get(nullifier) {
            return Some(*row);
        }
        if let Some(row) = self.loaded.rows.get(nullifier) {
            return *row;
        }
        let cached = self.store.read_book().rows.cached(nullifier);
        self.answer(cached, |missed| missed.rows.insert(*nullifier))
    }

    fn answer<V>(
        &mut self,
        cached: Cached<V>,
        miss: impl FnOnce(&mut Missed) -> bool,
    ) -> Option<V> {
        match cached {
            Cached::Hit(value) => Some(value),
            Cached::Absent => None,
            Cached::Unknown => {
                miss(&mut self.missed);
                None
            }
        }
    }

    /// A complete mirror keeps the owner index, a cache reads it from storage.
    fn owner_commitments(&mut self, member: &[u8; 32]) -> Vec<[u8; 32]> {
        let book = self.store.read_book();
        if book.is_complete() {
            return book
                .active
                .by_owner
                .get(member)
                .map(|keys| keys.keys().copied().collect())
                .unwrap_or_default();
        }
        drop(book);
        match self.loaded.owners.get(member) {
            Some(commitments) => commitments.clone(),
            None => {
                self.missed.owners.insert(*member);
                Vec::new()
            }
        }
    }

    /// The zero key's secret is public, every other opens from the owner's credential.
    fn key_of(&mut self, utxo: &KnownUtxo) -> Option<&NullifierKey> {
        let nullifier_pk = utxo.owner.nullifier_pk()?;
        if nullifier_pk == ZERO_NULLIFIER_PUBKEY {
            return self
                .keys
                .entry(ZERO_NULLIFIER_PUBKEY)
                .or_insert_with(|| Some(NullifierKey::from_secret([0; 31])))
                .as_ref();
        }
        let opener = self.opener;
        let key = self
            .keys
            .entry(utxo.owner_key)
            .or_insert_with(|| opener(&utxo.owner_key));
        key.as_ref().filter(|key| {
            key.pubkey()
                .is_ok_and(|registered| registered == nullifier_pk)
        })
    }

    fn open(&mut self, created_in: CreatedIn, utxos: &[CreatedUtxo]) {
        let assets = self
            .store
            .assets
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for created in utxos {
            let held = self.note(&created.commitment);
            let mint = created
                .utxo
                .mint
                .or(held.and_then(|held| held.utxo.mint))
                .or_else(|| Some(assets.as_ref()?.by_field(&created.utxo.asset)?.asset));
            let note = match held {
                Some(held) => StoredUtxo {
                    utxo: KnownUtxo { mint, ..held.utxo },
                    ..held
                },
                None => StoredUtxo {
                    utxo: KnownUtxo {
                        mint,
                        ..created.utxo
                    },
                    created_in,
                    slot_index: created.slot_index,
                    leaf_index: created.leaf_index,
                    ring_note: created.ring_note,
                    nullifier: None,
                },
            };
            if held != Some(note) {
                self.delta.notes.insert(created.commitment, note);
            }
            self.derive(&created.commitment);
        }
    }

    /// Fills the index when the secret is readable, then moves the row it names.
    fn derive(&mut self, commitment: &[u8; 32]) {
        let Some(mut note) = self.note(commitment) else {
            return;
        };
        if note.ring_note && note.nullifier.is_none() {
            let blinding = note.utxo.blinding;
            note.nullifier = self
                .key_of(&note.utxo)
                .and_then(|key| key.nullifier(commitment, &blinding).ok());
            if note.nullifier.is_some() {
                self.delta.notes.insert(*commitment, note);
            }
        }
        if let Some(nullifier) = note.nullifier {
            self.delta.by_nullifier.insert(nullifier, *commitment);
            if let Some(row) = self.row(&nullifier) {
                self.apply(row.opened(*commitment));
            }
        }
    }

    fn apply(&mut self, transition: Transition) {
        match transition {
            Transition::Unchanged => {}
            Transition::Write(row) => {
                self.delta.rows.insert(row.nullifier, row);
            }
            Transition::Integrity(row) => self.delta.faults.push(row),
        }
    }

    fn observe(&mut self, observation: Observation) {
        let hit = match observation.read {
            InputRead::Real => self.note_of_nullifier(&observation.nullifier),
            InputRead::Unreadable
            | InputRead::Padding
            | InputRead::Address
            | InputRead::External => None,
        };
        let existing = self.row(&observation.nullifier);
        self.apply(Observation { hit, ..observation }.apply(existing.as_ref()));
    }

    fn late_keys(&mut self) {
        let owners: Vec<[u8; 32]> = self
            .store
            .late_owners
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .copied()
            .collect();
        for owner in &owners {
            let Ok(member) = Member::owner_tag(owner) else {
                continue;
            };
            for commitment in self.owner_commitments(member.as_bytes()) {
                if self
                    .note(&commitment)
                    .is_some_and(|note| note.nullifier.is_none())
                {
                    self.derive(&commitment);
                }
            }
        }
        self.delta.late_owners = owners;
    }

    /// Names the owner rows the page moves and the slot its commit prunes through.
    fn close(&mut self) {
        let spent: Vec<[u8; 32]> = self
            .delta
            .rows
            .keys()
            .copied()
            .collect::<Vec<_>>()
            .iter()
            .filter_map(|nullifier| self.note_of_nullifier(nullifier))
            .collect();
        let touched: BTreeSet<[u8; 32]> = self.delta.notes.keys().copied().chain(spent).collect();
        let mut owners = Vec::new();
        for commitment in touched {
            let Some(stored) = self.note(&commitment) else {
                continue;
            };
            // An exit leaves the ring, its note never enters an owner's set.
            if !stored.ring_note {
                continue;
            }
            let Ok(member) = Member::owner_tag(&stored.utxo.owner_key) else {
                continue;
            };
            let spent_at = stored
                .nullifier
                .and_then(|nullifier| self.row(&nullifier))
                .map(|row| row.frame.slot);
            owners.push(OwnerChange {
                member: *member.as_bytes(),
                note: IndexedNote {
                    key: commitment,
                    commitment,
                    note: stored,
                    spent_at,
                },
            });
        }
        self.delta.owners = owners;
        self.delta.prune_through = self.store.read_book().history_through();
    }
}

impl AuditStore {
    pub(crate) fn new(backing: Backing) -> Self {
        let book = match &backing {
            Backing::Database { capacity, .. } => SpendBook::bounded(*capacity),
            Backing::Memory | Backing::Unavailable => SpendBook::default(),
        };
        Self {
            book: RwLock::new(book),
            backing,
            ..Self::default()
        }
    }

    fn read_book(&self) -> std::sync::RwLockReadGuard<'_, SpendBook> {
        self.book.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// `None` for a complete mirror, it never misses.
    fn reads(&self) -> Result<Option<ProjectionReads<'_>>, RingRpcError> {
        match &self.backing {
            Backing::Memory => Ok(None),
            Backing::Database {
                store, ring, seal, ..
            } => Ok(Some(ProjectionReads {
                db: store.connection(),
                ring: *ring,
                seal,
            })),
            Backing::Unavailable => Err(RingRpcError::StateUnavailable),
        }
    }

    /// What the next reload reads, a cache reads only rows past the revision it holds.
    pub(crate) fn history_scope(&self) -> HistoryScope {
        self.read_book().history_scope()
    }

    /// Takes one snapshot's rows. Unread frames and faults are replaced whole, a frame the
    /// holder read since leaves with them.
    pub(crate) fn refresh(&self, loaded: LoadedSpends, revision: i64) {
        let LoadedSpends {
            checkpoint,
            notes,
            rows,
            unread,
            faults,
        } = loaded;
        let unread: BTreeSet<CreatedIn> = unread.into_iter().collect();
        let mut book = self.book.write().unwrap_or_else(PoisonError::into_inner);
        let mut delta = PageDelta {
            by_nullifier: notes
                .iter()
                .filter_map(|(commitment, note)| Some((note.nullifier?, *commitment)))
                .collect(),
            notes: notes.into_iter().collect(),
            rows: rows.into_iter().map(|row| (row.nullifier, row)).collect(),
            prune_through: history_through(unread.first(), checkpoint.through.slot),
            checkpoint: Some(checkpoint),
            revision: Some(revision),
            ..PageDelta::default()
        };
        // A complete mirror rebuilds its owner index from the notes and rows it loaded.
        if book.is_complete() {
            delta.owners = owner_changes_of(&delta);
        }
        book.absorb(delta);
        book.unread = unread;
        book.faults = faults;
    }

    /// Runs after the page's transaction commits, a crash before it replays the page.
    pub(crate) fn commit(&self, delta: PageDelta) {
        let mut late = self
            .late_owners
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        for owner in &delta.late_owners {
            late.remove(owner);
        }
        drop(late);
        self.book
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .absorb(delta);
    }

    /// Storage's answer for every key a replay missed.
    async fn load(&self, missed: Missed, loaded: &mut Loaded) -> Result<(), RingRpcError> {
        let Missed {
            notes,
            by_nullifier,
            rows,
            owners,
        } = missed;
        let notes: Vec<[u8; 32]> = notes.into_iter().collect();
        let mut found = self.notes(&notes).await?;
        for commitment in notes {
            loaded.notes.insert(commitment, found.remove(&commitment));
        }
        let by_nullifier: Vec<[u8; 32]> = by_nullifier.into_iter().collect();
        let mut found = self.notes_of_nullifiers(&by_nullifier).await?;
        for nullifier in by_nullifier {
            let hit = found.remove(&nullifier);
            if let Some((commitment, note)) = hit {
                loaded.notes.entry(commitment).or_insert(Some(note));
            }
            loaded
                .by_nullifier
                .insert(nullifier, hit.map(|(commitment, _)| commitment));
        }
        let rows: Vec<[u8; 32]> = rows.into_iter().collect();
        let mut found = self.spend_rows(&rows).await?;
        for nullifier in rows {
            loaded.rows.insert(nullifier, found.remove(&nullifier));
        }
        for member in owners {
            let mut commitments = Vec::new();
            for indexed in self.indexed_notes(&member).await? {
                loaded
                    .notes
                    .entry(indexed.commitment)
                    .or_insert(Some(indexed.note));
                commitments.push(indexed.commitment);
            }
            loaded.owners.insert(member, commitments);
        }
        Ok(())
    }

    /// The cache answers first, storage answers each key the cache may have evicted.
    pub(crate) async fn notes(
        &self,
        commitments: &[[u8; 32]],
    ) -> Result<HashMap<[u8; 32], StoredUtxo>, RingRpcError> {
        let (mut found, unknown) = self.cached(commitments, |book, key| book.notes.cached(key));
        if let Some(reads) = self.reads()?.filter(|_| !unknown.is_empty()) {
            found.extend(reads.notes(&unknown).await?);
        }
        Ok(found)
    }

    pub(crate) async fn notes_of_nullifiers(
        &self,
        nullifiers: &[[u8; 32]],
    ) -> Result<HashMap<[u8; 32], ([u8; 32], StoredUtxo)>, RingRpcError> {
        let (commitments, unknown) =
            self.cached(nullifiers, |book, key| book.by_nullifier.cached(key));
        let (mut found, evicted) = {
            let book = self.read_book();
            let mut found = HashMap::new();
            let mut evicted = Vec::new();
            for (nullifier, commitment) in commitments {
                match book.notes.cached(&commitment) {
                    Cached::Hit(note) => {
                        found.insert(nullifier, (commitment, note));
                    }
                    Cached::Absent => {}
                    Cached::Unknown => evicted.push(nullifier),
                }
            }
            (found, evicted)
        };
        let unknown: Vec<[u8; 32]> = unknown.into_iter().chain(evicted).collect();
        if let Some(reads) = self.reads()?.filter(|_| !unknown.is_empty()) {
            for (commitment, note) in reads.notes_by_nullifier(&unknown).await? {
                if let Some(nullifier) = note.nullifier {
                    found.insert(nullifier, (commitment, note));
                }
            }
        }
        Ok(found)
    }

    pub(crate) async fn spend_rows(
        &self,
        nullifiers: &[[u8; 32]],
    ) -> Result<HashMap<[u8; 32], SpendRow>, RingRpcError> {
        let (mut found, unknown) = self.cached(nullifiers, |book, key| book.rows.cached(key));
        if let Some(reads) = self.reads()?.filter(|_| !unknown.is_empty()) {
            found.extend(
                reads
                    .rows(&unknown)
                    .await?
                    .into_iter()
                    .map(|row| (row.nullifier, row)),
            );
        }
        Ok(found)
    }

    /// Splits keys into cache hits and keys only storage can answer.
    fn cached<V>(
        &self,
        keys: &[[u8; 32]],
        lookup: impl Fn(&SpendBook, &[u8; 32]) -> Cached<V>,
    ) -> (HashMap<[u8; 32], V>, Vec<[u8; 32]>) {
        let book = self.read_book();
        let mut found = HashMap::new();
        let mut unknown = Vec::new();
        for key in keys {
            match lookup(&book, key) {
                Cached::Hit(value) => {
                    found.insert(*key, value);
                }
                Cached::Absent => {}
                Cached::Unknown => unknown.push(*key),
            }
        }
        (found, unknown)
    }

    #[cfg(test)]
    pub(crate) fn row_state(&self, nullifier: &[u8; 32]) -> Option<SpendState> {
        self.read_book().rows.get(nullifier).map(|row| row.state)
    }

    /// The owner's live notes and unsettled spends, never another owner's row or a settled spend.
    async fn indexed_notes(&self, member: &[u8; 32]) -> Result<Vec<IndexedNote>, RingRpcError> {
        match &self.backing {
            Backing::Memory => Ok(self.read_book().owner_notes(member)),
            Backing::Database {
                store, ring, seal, ..
            } => Ok(OwnerNotesRead {
                db: store.connection(),
                ring: *ring,
                seal,
                member: *member,
            }
            .read()
            .await?),
            Backing::Unavailable => Err(RingRpcError::StateUnavailable),
        }
    }

    async fn owner_notes(&self, owner_key: &[u8; 32]) -> Result<Vec<IndexedNote>, RingRpcError> {
        match Member::owner_tag(owner_key) {
            Ok(member) => self.indexed_notes(member.as_bytes()).await,
            Err(_) => Ok(Vec::new()),
        }
    }

    pub(crate) async fn wallet_status(
        &self,
        query: WalletStatusQuery,
    ) -> Result<GetWalletStatusResponse, RingRpcError> {
        let notes = self.owner_notes(query.wallet.as_array()).await?;
        // Read after the rows, a commit deletes a spend only at or before the slot it found.
        let through = self.read_book().history_through();
        Ok(wallet_page(&notes, query, through))
    }

    /// A cache counts the rows storage holds, a complete mirror counts its own.
    pub(crate) async fn spend_coverage(&self) -> Result<GetSpendCoverageResponse, RingRpcError> {
        let (counts, unresolved) = match self.reads()? {
            Some(reads) => (reads.state_counts().await?, reads.unresolved().await?),
            None => {
                let book = self.read_book();
                let mut counts: HashMap<String, u64> = HashMap::new();
                for row in book.rows.values() {
                    *counts.entry(state_name(row.state).to_owned()).or_default() += 1;
                }
                let unresolved = book
                    .rows
                    .values()
                    .filter(|row| matches!(row.state, SpendState::UnresolvedReal))
                    .copied()
                    .collect();
                (counts, unresolved)
            }
        };
        let count = |state: SpendState| counts.get(state_name(state)).copied().unwrap_or(0);
        let frame = |frame: &CreatedIn| SpendCoverageFrame {
            slot: frame.slot,
            tx_signature: frame.tx_signature.into(),
            event_index: frame.event_index,
        };
        let row = |row: &SpendRow| SpendCoverageRow {
            nullifier: Hash(row.nullifier),
            frame: frame(&row.frame),
        };
        let mut unresolved_real: Vec<_> = unresolved.iter().map(row).collect();
        unresolved_real.sort_by_key(|row| (row.frame.slot, row.frame.event_index));
        let book = self.read_book();
        Ok(GetSpendCoverageResponse {
            position_slot: book.position_slot,
            history_through: book.history_through(),
            observed: count(SpendState::Observed),
            padding: count(SpendState::Padding),
            address: count(SpendState::Address),
            external: count(SpendState::External),
            resolved: count(SpendState::Resolved { note: [0; 32] }),
            unresolved_real,
            unreadable: book.unread.iter().map(frame).collect(),
            integrity_faults: book.faults.iter().map(row).collect(),
        })
    }

    pub(crate) fn unread_frames(&self) -> Vec<CreatedIn> {
        self.read_book().unread.iter().copied().collect()
    }

    /// Reads the owner's index, an unrelated unresolved spend hides no note, a published row always does.
    pub(crate) async fn spendable(
        &self,
        notes: SpendableNotes<'_>,
    ) -> Result<Vec<WalletUtxo>, RingRpcError> {
        let owner = UtxoOwner::Keyed {
            nullifier_pk: notes.nullifier_key.pubkey()?,
        };
        let candidates = self
            .owner_notes(&notes.owner_key)
            .await?
            .iter()
            .filter(|indexed| {
                let utxo = &indexed.note.utxo;
                utxo.owner_key == notes.owner_key
                    && utxo.owner == owner
                    && utxo.mint == Some(notes.mint.asset)
                    && utxo.data_hash == [0; 32]
            })
            .map(|indexed| indexed.note.wallet_utxo(&indexed.commitment, &notes))
            .collect::<Result<Vec<_>, _>>()?;
        let nullifiers: Vec<[u8; 32]> = candidates.iter().map(|note| note.nullifier).collect();
        let spent = self.spend_rows(&nullifiers).await?;
        Ok(candidates
            .into_iter()
            .filter(|note| !spent.contains_key(&note.nullifier))
            .collect())
    }

    pub(crate) fn credential(&self, member: &[u8; 32]) -> Option<HeldCredential> {
        self.credentials
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .by_member(member)
            .copied()
    }

    pub(crate) fn credential_by_list_key(&self, list_key: &[u8; 32]) -> Option<HeldCredential> {
        self.credentials
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .by_list_key(list_key)
            .copied()
    }

    /// A refused page holds nothing, a new owner's notes derive on the next page.
    pub(crate) fn admit_credentials(
        &self,
        found: Vec<HeldCredential>,
    ) -> Result<(), CredentialRefusal> {
        let owners = self
            .credentials
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .admit(found)?;
        self.late_owners
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(owners);
        Ok(())
    }

    pub(crate) fn context(&self) -> Context {
        self.read_book().context
    }

    pub(crate) async fn view(
        &self,
        utxo_hash: &Hash,
    ) -> Result<Option<AuditedUtxoView>, RingRpcError> {
        let Some(stored) = self.notes(&[utxo_hash.0]).await?.remove(&utxo_hash.0) else {
            return Ok(None);
        };
        Ok(Some(AuditedUtxoView {
            utxo_hash: Hash(utxo_hash.0),
            utxo: stored.utxo.into(),
            slot: stored.created_in.slot,
            tx_signature: stored.created_in.tx_signature.into(),
            event_index: stored.created_in.event_index,
            slot_index: stored.slot_index,
        }))
    }

    /// The audit view of a merge the checkpoint opened.
    pub(crate) async fn merge_output(
        &self,
        merge: &ConfirmedMerge,
    ) -> Result<Option<AuditedMergeOutput>, RingRpcError> {
        let commitment = merge.output_commitment();
        let opened = self.notes(&[commitment]).await?.contains_key(&commitment);
        Ok(opened.then(|| merge.output().ok()).flatten())
    }

    /// The real inputs among `inputs` whose resolved note `wallet` owns.
    pub(crate) async fn input_parties<'i>(
        &self,
        wallet: &Address,
        inputs: impl IntoIterator<Item = &'i DecryptedInput>,
    ) -> Result<InputParties, RingRpcError> {
        let nullifiers: Vec<[u8; 32]> = inputs
            .into_iter()
            .filter(|input| {
                input.class == DecryptedInputClass::Note && input.default_input.is_none()
            })
            .map(|input| input.nullifier.0)
            .collect();
        let resolved: Vec<([u8; 32], [u8; 32])> = self
            .spend_rows(&nullifiers)
            .await?
            .into_values()
            .filter_map(|row| match row.state {
                SpendState::Resolved { note } => Some((row.nullifier, note)),
                _ => None,
            })
            .collect();
        let commitments: Vec<[u8; 32]> = resolved.iter().map(|(_, note)| *note).collect();
        let notes = self.notes(&commitments).await?;
        Ok(InputParties {
            own: resolved
                .into_iter()
                .filter(|(_, note)| {
                    notes
                        .get(note)
                        .is_some_and(|note| note.utxo.owner_key == wallet.to_bytes())
                })
                .map(|(nullifier, _)| nullifier)
                .collect(),
        })
    }
}

impl InputParties {
    /// Fails closed, a note no row names to `wallet` reads as another party's and an address as no party's.
    pub(crate) fn party(&self, wallet: &Address, input: &DecryptedInput) -> InputParty {
        if input.class != DecryptedInputClass::Note {
            return InputParty::Padding;
        }
        if let Some(default_input) = &input.default_input {
            return match default_input.utxo.owner_key.0 == *wallet {
                true => InputParty::Own,
                false => InputParty::Other,
            };
        }
        match self.own.contains(&input.nullifier.0) {
            true => InputParty::Own,
            false => InputParty::Other,
        }
    }
}

/// Every loaded note as an owner row, for a complete mirror rebuilding its index.
fn owner_changes_of(delta: &PageDelta) -> Vec<OwnerChange> {
    delta
        .notes
        .iter()
        .filter(|(_, note)| note.ring_note)
        .filter_map(|(commitment, note)| {
            let member = Member::owner_tag(&note.utxo.owner_key).ok()?;
            Some(OwnerChange {
                member: *member.as_bytes(),
                note: IndexedNote {
                    key: *commitment,
                    commitment: *commitment,
                    note: *note,
                    spent_at: note
                        .nullifier
                        .and_then(|nullifier| delta.rows.get(&nullifier))
                        .map(|row| row.frame.slot),
                },
            })
        })
        .collect()
}

impl StoredUtxo {
    fn wallet_note(&self, commitment: &[u8; 32], status: WalletNoteStatus) -> WalletNote {
        let utxo = &self.utxo;
        WalletNote {
            utxo_hash: Hash(*commitment),
            status,
            nullifier_pk: utxo.owner.nullifier_pk().map(Hash),
            asset: Hash(utxo.asset),
            mint: utxo.mint.map(Into::into),
            amount: utxo.amount,
            blinding: Hash(utxo.blinding),
            data_hash: Hash(utxo.data_hash),
            ring_data_hash: Hash(utxo.ring_data_hash),
            tree_id: utxo.tree_id,
            leaf_index: self.leaf_index,
            slot: self.created_in.slot,
            tx_signature: self.created_in.tx_signature.into(),
            event_index: self.created_in.event_index,
            slot_index: self.slot_index,
        }
    }

    fn wallet_utxo(
        &self,
        commitment: &[u8; 32],
        notes: &SpendableNotes<'_>,
    ) -> Result<WalletUtxo, RingRpcError> {
        let utxo = &self.utxo;
        Ok(WalletUtxo {
            utxo: Utxo {
                owner: PublicKey::from_ed25519(&utxo.owner_key),
                asset: notes.mint,
                amount: utxo.amount,
                blinding: utxo.blinding,
                ring_program_id: Some(notes.ring),
                data: Data::default(),
            },
            nullifier_pubkey: notes.nullifier_key.pubkey()?,
            utxo_hash: *commitment,
            nullifier: notes.nullifier_key.nullifier(commitment, &utxo.blinding)?,
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: (utxo.ring_data_hash != [0; 32]).then_some(utxo.ring_data_hash),
            tree_id: utxo.tree_id,
            leaf_index: self.leaf_index,
            latest_tree_id: None,
            slot: self.created_in.slot,
            tx_signature: self.created_in.tx_signature,
            slot_index: self.slot_index,
        })
    }
}

impl DepositOwners for AuditStore {
    fn deposit_owner(&self, owner_hash: &[u8; 32]) -> Option<DepositOwner> {
        let credentials = self
            .credentials
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let held = credentials.by_owner_hash(owner_hash)?;
        Some(DepositOwner {
            owner_key: held.owner_key,
            nullifier_pk: held.credential.nullifier_pk,
        })
    }
}

/// Decoded state in a fixed order, sealed rows differ in their nonces alone.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StoreDump {
    pub notes: BTreeMap<[u8; 32], StoredUtxo>,
    pub rows: BTreeMap<[u8; 32], SpendRow>,
    pub unread: BTreeSet<CreatedIn>,
    pub faults: BTreeSet<([u8; 32], CreatedIn)>,
    pub context: Context,
    pub position_slot: Option<u64>,
}

#[cfg(test)]
impl AuditStore {
    /// Notes opened with no secret.
    pub(crate) async fn record(
        &self,
        created_in: CreatedIn,
        utxos: impl IntoIterator<Item = CreatedUtxo>,
    ) {
        let opener = |_: &[u8; 32]| None;
        let mut work = PageWork::new(self, &opener);
        work.open(created_in, utxos);
        let delta = work.finish().await.expect("fixture page");
        self.commit_fixture(delta).await;
    }

    /// A store with a database reads wallets from its tables, the page writes them first.
    async fn commit_fixture(&self, delta: PageDelta) {
        if let Backing::Database {
            store, ring, seal, ..
        } = &self.backing
        {
            let clock = crate::hub::Clock::System;
            let lease = crate::projection_lease::LeaseClaim {
                db: store.connection(),
                ring: *ring,
                holder: store.lease_holder(),
                now: clock.now().expect("clock"),
            }
            .claim()
            .await
            .expect("claim")
            .expect("the fixture replica holds the lease");
            let revision = crate::spent_index::ProjectionWriter {
                db: store.connection(),
                ring: *ring,
                seal,
                lease,
                clock,
            }
            .commit_page(&delta)
            .await
            .expect("fixture page");
            self.commit(delta.at_revision(revision));
            return;
        }
        self.commit(delta);
    }

    /// Published rows with no frame the test reads.
    pub(crate) async fn spend(&self, nullifiers: impl IntoIterator<Item = [u8; 32]>) {
        use crate::spend_machine::InputRead;
        let opener = |_: &[u8; 32]| None;
        let mut work = PageWork::new(self, &opener);
        for nullifier in nullifiers {
            work.observe(Observation {
                nullifier,
                frame: CreatedIn {
                    slot: 1,
                    tx_signature: Signature::from(
                        nullifier.repeat(2).try_into().unwrap_or([0; 64]),
                    ),
                    event_index: 0,
                },
                position: 0,
                read: InputRead::Real,
                hit: None,
            });
        }
        let delta = work.finish().await.expect("fixture page");
        self.commit_fixture(delta).await;
    }

    /// Entries the cache holds of notes, the note index and spend rows.
    pub(crate) fn cached_entries(&self) -> [usize; 3] {
        let book = self.read_book();
        [book.notes.len(), book.by_nullifier.len(), book.rows.len()]
    }

    pub(crate) fn dump(&self) -> StoreDump {
        let book = self.read_book();
        StoreDump {
            notes: book.notes.iter().map(|(key, note)| (*key, *note)).collect(),
            rows: book.rows.iter().map(|(key, row)| (*key, *row)).collect(),
            unread: book.unread.clone(),
            faults: book
                .faults
                .iter()
                .map(|fault| (fault.nullifier, fault.frame))
                .collect(),
            context: book.context,
            position_slot: book.position_slot,
        }
    }
}

/// Runs a page future from a sync test, a complete mirror never awaits storage.
#[cfg(test)]
pub(crate) fn block_on<T>(work: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(work)
}

#[cfg(test)]
#[path = "spend_store_tests.rs"]
mod spend_store_tests;
