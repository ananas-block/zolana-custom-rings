//! The notes a ring's auditor opened, their nullifiers, and the keys its credentials hold.
//!
//! Each page also names the notes it moved in an owner's active set, the page commit writes them
//! to `storage/owner_notes.rs` and the mirror keeps their keys. Wallet reads page over that set.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
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
    credentials::{CredentialRefusal, HeldCredential, HeldCredentials},
    database::Store,
    error::RingRpcError,
    owner_notes::OwnerNotesRead,
    spend_machine::{NoteRead, Observation, SpendRow, SpendState, Transition},
    spent_index::{Checkpoint, LoadedSpends, NoteSeal},
};

pub const UTXO_BACKFILL_INTERVAL: Duration = Duration::from_secs(30);

/// Pages one backfill run reads, the next run resumes from its position.
pub(crate) const MAX_BACKFILL_PAGES: usize = 64;

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
    index: OwnerIndex,
}

#[derive(Default)]
pub(crate) enum OwnerIndex {
    /// No database, the mirror is the only copy.
    #[default]
    Memory,
    Database {
        store: Store,
        ring: Address,
        seal: Box<NoteSeal>,
    },
    /// The ring's seal failed to derive, every wallet read refuses.
    Unavailable,
}

#[derive(Default)]
pub(crate) struct Backfill {
    /// `None` until the durable tables load.
    pub history: Option<HistoryPosition>,
    /// In memory, a restart scans every credential from the first finalized slot.
    pub credentials: HistoryPosition,
}

#[derive(Default)]
struct SpendBook {
    notes: HashMap<[u8; 32], StoredUtxo>,
    /// The note index, a late secret fills it for that owner's notes.
    by_nullifier: HashMap<[u8; 32], [u8; 32]>,
    active: ActiveIndex,
    rows: HashMap<[u8; 32], SpendRow>,
    unread: BTreeSet<CreatedIn>,
    faults: Vec<SpendRow>,
    context: Context,
    position_slot: Option<u64>,
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

/// A page's overlay on the book, a later row reads what an earlier row opened.
#[must_use]
pub(crate) struct PageWork<'a> {
    store: &'a AuditStore,
    delta: PageDelta,
    /// Read to derive and dropped with the page, never persisted.
    keys: HashMap<[u8; 32], Option<NullifierKey>>,
    opener: &'a (dyn Fn(&[u8; 32]) -> Option<NullifierKey> + Sync),
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
    fn absorb(&mut self, delta: PageDelta) {
        self.active.apply(&delta.owners, delta.prune_through);
        self.notes.extend(delta.notes);
        self.by_nullifier.extend(delta.by_nullifier);
        for (nullifier, row) in delta.rows {
            self.rows.insert(nullifier, row);
        }
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
    }

    fn history_through(&self) -> u64 {
        history_through(self.unread.first(), self.context.slot)
    }

    /// Every note the delta opened or spent, each read through the delta over the book.
    fn owner_changes(&self, delta: &PageDelta) -> Vec<OwnerChange> {
        let note = |commitment: &[u8; 32]| {
            delta
                .notes
                .get(commitment)
                .or_else(|| self.notes.get(commitment))
        };
        let row = |nullifier: &[u8; 32]| {
            delta
                .rows
                .get(nullifier)
                .or_else(|| self.rows.get(nullifier))
        };
        let spent: Vec<&[u8; 32]> = delta
            .rows
            .keys()
            .filter_map(|nullifier| {
                delta
                    .by_nullifier
                    .get(nullifier)
                    .or_else(|| self.by_nullifier.get(nullifier))
            })
            .collect();
        let touched: BTreeSet<&[u8; 32]> = delta.notes.keys().chain(spent).collect();
        touched
            .into_iter()
            .filter_map(|commitment| {
                let stored = *note(commitment)?;
                // An exit leaves the ring, its note never enters an owner's set.
                if !stored.ring_note {
                    return None;
                }
                let member = Member::owner_tag(&stored.utxo.owner_key).ok()?;
                Some(OwnerChange {
                    member: *member.as_bytes(),
                    note: IndexedNote {
                        key: *commitment,
                        commitment: *commitment,
                        note: stored,
                        spent_at: stored
                            .nullifier
                            .and_then(|nullifier| row(&nullifier))
                            .map(|row| row.frame.slot),
                    },
                })
            })
            .collect()
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
}

impl<'a> PageWork<'a> {
    pub(crate) fn new(
        store: &'a AuditStore,
        opener: &'a (dyn Fn(&[u8; 32]) -> Option<NullifierKey> + Sync),
    ) -> Self {
        Self {
            store,
            delta: PageDelta::default(),
            keys: HashMap::new(),
            opener,
        }
    }

    pub(crate) fn note(&self, commitment: &[u8; 32]) -> Option<StoredUtxo> {
        self.delta
            .notes
            .get(commitment)
            .copied()
            .or_else(|| self.store.read_book().notes.get(commitment).copied())
    }

    pub(crate) fn note_of_nullifier(&self, nullifier: &[u8; 32]) -> Option<[u8; 32]> {
        self.delta
            .by_nullifier
            .get(nullifier)
            .copied()
            .or_else(|| self.store.read_book().by_nullifier.get(nullifier).copied())
    }

    fn row(&self, nullifier: &[u8; 32]) -> Option<SpendRow> {
        self.delta
            .rows
            .get(nullifier)
            .copied()
            .or_else(|| self.store.read_book().rows.get(nullifier).copied())
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

    /// A later opening of a known commitment changes it only to name its mint.
    pub(crate) fn open(
        &mut self,
        created_in: CreatedIn,
        utxos: impl IntoIterator<Item = CreatedUtxo>,
    ) {
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
            self.settle(&nullifier, commitment);
        }
    }

    fn settle(&mut self, nullifier: &[u8; 32], commitment: &[u8; 32]) {
        let Some(row) = self.row(nullifier) else {
            return;
        };
        self.apply(row.opened(*commitment));
    }

    fn apply(&mut self, transition: Transition) {
        match transition {
            Transition::Unchanged => {}
            Transition::Write(row) => {
                self.delta.rows.insert(row.nullifier, row);
            }
            Transition::Integrity(row) => {
                log::error!(
                    "nullifier {} of {}:{} repeats a settled row",
                    Hash(row.nullifier).to_base58(),
                    row.frame.tx_signature,
                    row.frame.event_index
                );
                self.delta.faults.push(row);
            }
        }
    }

    pub(crate) fn observe(&mut self, observation: Observation) {
        use crate::spend_machine::InputRead;
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

    /// Retries with every other frame the backfill keeps.
    pub(crate) fn mark_unread(&mut self, frame: CreatedIn) {
        self.delta.read.remove(&frame);
        self.delta.unread.insert(frame);
    }

    pub(crate) fn mark_read(&mut self, frame: CreatedIn) {
        if !self.delta.unread.contains(&frame) {
            self.delta.read.insert(frame);
        }
    }

    /// A late key recomputes that owner's notes, a failed page leaves the owner to the next.
    pub(crate) fn late_keys(&mut self) {
        let owners: Vec<[u8; 32]> = self
            .store
            .late_owners
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .copied()
            .collect();
        let pending: Vec<[u8; 32]> = {
            let book = self.store.read_book();
            owners
                .iter()
                .filter_map(|owner| Member::owner_tag(owner).ok())
                .filter_map(|member| book.active.by_owner.get(member.as_bytes()))
                .flat_map(BTreeMap::keys)
                .filter(|commitment| {
                    book.notes
                        .get(*commitment)
                        .is_some_and(|note| note.nullifier.is_none())
                })
                .copied()
                .collect()
        };
        for commitment in pending {
            self.derive(&commitment);
        }
        self.delta.late_owners = owners;
    }

    /// Reads the next position with the terminal page's context, when the page ended the read.
    pub(crate) fn checkpoint(&mut self, position: HistoryPosition, terminal: Option<Context>) {
        let through = terminal.unwrap_or_else(|| self.store.context());
        self.delta.checkpoint = Some(Checkpoint { position, through });
    }

    /// Names the owner rows the page moves, against the book the page read.
    pub(crate) fn finish(mut self) -> PageDelta {
        let store = self.store;
        let book = store.read_book();
        self.delta.owners = book.owner_changes(&self.delta);
        self.delta.prune_through = book.history_through();
        drop(book);
        self.delta
    }
}

impl AuditStore {
    pub(crate) fn new(index: OwnerIndex) -> Self {
        Self {
            index,
            ..Self::default()
        }
    }

    fn read_book(&self) -> std::sync::RwLockReadGuard<'_, SpendBook> {
        self.book.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn seed(&self, loaded: LoadedSpends) {
        let LoadedSpends {
            checkpoint,
            notes,
            rows,
            unread,
            faults,
        } = loaded;
        let unread: BTreeSet<CreatedIn> = unread.into_iter().collect();
        let mut delta = PageDelta {
            by_nullifier: notes
                .iter()
                .filter_map(|(commitment, note)| Some((note.nullifier?, *commitment)))
                .collect(),
            notes: notes.into_iter().collect(),
            rows: rows.into_iter().map(|row| (row.nullifier, row)).collect(),
            prune_through: history_through(unread.first(), checkpoint.through.slot),
            unread,
            faults,
            checkpoint: Some(checkpoint),
            ..PageDelta::default()
        };
        let mut book = self.book.write().unwrap_or_else(PoisonError::into_inner);
        // The index keys rebuild from the loaded notes and rows, a spend the tables settled stays out.
        delta.owners = book.owner_changes(&delta);
        book.absorb(delta);
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

    /// Any published row of the nullifier, no slot bound applies.
    pub(crate) fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.read_book().rows.contains_key(nullifier)
    }

    pub(crate) fn note_of_nullifier(&self, nullifier: &[u8; 32]) -> Option<([u8; 32], StoredUtxo)> {
        let book = self.read_book();
        let commitment = *book.by_nullifier.get(nullifier)?;
        book.notes.get(&commitment).map(|note| (commitment, *note))
    }

    #[cfg(test)]
    pub(crate) fn row_state(&self, nullifier: &[u8; 32]) -> Option<SpendState> {
        self.read_book().rows.get(nullifier).map(|row| row.state)
    }

    /// The owner's live notes and unsettled spends, never another owner's row or a settled spend.
    async fn owner_notes(&self, owner_key: &[u8; 32]) -> Result<Vec<IndexedNote>, RingRpcError> {
        let Ok(member) = Member::owner_tag(owner_key) else {
            return Ok(Vec::new());
        };
        match &self.index {
            OwnerIndex::Memory => Ok(self.read_book().owner_notes(member.as_bytes())),
            OwnerIndex::Database { store, ring, seal } => Ok(OwnerNotesRead {
                db: store.connection(),
                ring: *ring,
                seal,
                member: *member.as_bytes(),
            }
            .read()
            .await?),
            OwnerIndex::Unavailable => Err(RingRpcError::StateUnavailable),
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

    pub(crate) fn spend_coverage(&self) -> GetSpendCoverageResponse {
        let book = self.read_book();
        let count = |state: fn(&SpendState) -> bool| {
            book.rows.values().filter(|row| state(&row.state)).count() as u64
        };
        let frame = |frame: &CreatedIn| SpendCoverageFrame {
            slot: frame.slot,
            tx_signature: frame.tx_signature.into(),
            event_index: frame.event_index,
        };
        let row = |row: &SpendRow| SpendCoverageRow {
            nullifier: Hash(row.nullifier),
            frame: frame(&row.frame),
        };
        let mut unresolved_real: Vec<_> = book
            .rows
            .values()
            .filter(|row| matches!(row.state, SpendState::UnresolvedReal))
            .map(row)
            .collect();
        unresolved_real.sort_by_key(|row| (row.frame.slot, row.frame.event_index));
        GetSpendCoverageResponse {
            position_slot: book.position_slot,
            history_through: book.history_through(),
            observed: count(|state| matches!(state, SpendState::Observed)),
            padding: count(|state| matches!(state, SpendState::Padding)),
            address: count(|state| matches!(state, SpendState::Address)),
            external: count(|state| matches!(state, SpendState::External)),
            resolved: count(|state| matches!(state, SpendState::Resolved { .. })),
            unresolved_real,
            unreadable: book.unread.iter().map(frame).collect(),
            integrity_faults: book.faults.iter().map(row).collect(),
        }
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
        let indexed = self.owner_notes(&notes.owner_key).await?;
        indexed
            .iter()
            .filter(|indexed| {
                let utxo = &indexed.note.utxo;
                utxo.owner_key == notes.owner_key
                    && utxo.owner == owner
                    && utxo.mint == Some(notes.mint.asset)
                    && utxo.data_hash == [0; 32]
            })
            .map(|indexed| indexed.note.wallet_utxo(&indexed.commitment, &notes))
            .filter(|note| !matches!(note, Ok(note) if self.is_spent(&note.nullifier)))
            .collect()
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

    pub(crate) fn view(&self, utxo_hash: &Hash) -> Option<AuditedUtxoView> {
        let stored = self.read_book().notes.get(&utxo_hash.0).copied()?;
        Some(AuditedUtxoView {
            utxo_hash: Hash(utxo_hash.0),
            utxo: stored.utxo.into(),
            slot: stored.created_in.slot,
            tx_signature: stored.created_in.tx_signature.into(),
            event_index: stored.created_in.event_index,
            slot_index: stored.slot_index,
        })
    }

    /// The audit view of a merge the checkpoint opened.
    pub(crate) fn merge_output(&self, merge: &ConfirmedMerge) -> Option<AuditedMergeOutput> {
        let opened = self
            .read_book()
            .notes
            .contains_key(&merge.output_commitment());
        opened.then(|| merge.output().ok()).flatten()
    }

    /// Fails closed, a note no row names to `wallet` reads as another party's and an address as no party's.
    pub(crate) fn input_party(&self, wallet: &Address, input: &DecryptedInput) -> InputParty {
        if input.class != DecryptedInputClass::Note {
            return InputParty::Padding;
        }
        if let Some(default_input) = &input.default_input {
            return match default_input.utxo.owner_key.0 == *wallet {
                true => InputParty::Own,
                false => InputParty::Other,
            };
        }
        let book = self.read_book();
        match book.rows.get(&input.nullifier.0).map(|row| row.state) {
            Some(SpendState::Resolved { note })
                if book
                    .notes
                    .get(&note)
                    .is_some_and(|note| note.utxo.owner_key == wallet.to_bytes()) =>
            {
                InputParty::Own
            }
            _ => InputParty::Other,
        }
    }
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
        let delta = work.finish();
        self.commit_fixture(delta).await;
    }

    /// A store with a database reads wallets from its tables, the page writes them first.
    async fn commit_fixture(&self, delta: PageDelta) {
        if let OwnerIndex::Database { store, ring, seal } = &self.index {
            crate::spent_index::PageCommit {
                db: store.connection(),
                ring: *ring,
                seal,
                delta: &delta,
            }
            .commit()
            .await
            .expect("fixture page");
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
        let delta = work.finish();
        self.commit_fixture(delta).await;
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

#[cfg(test)]
#[path = "spend_store_tests.rs"]
mod spend_store_tests;
