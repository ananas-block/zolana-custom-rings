//! The notes a ring's auditor opened, their nullifiers, and the keys its registry tracks.

use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        PoisonError, RwLock,
    },
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
        AuditedUtxoView, DecryptedInput, GetSpendCoverageResponse, GetWalletStatusResponse,
        InputParty, SpendCoverageFrame, SpendCoverageRow, WalletBalance, WalletNote,
        WalletNoteStatus,
    },
    AuditedMergeOutput, ConfirmedMerge, CreatedUtxo, DepositOwner, DepositOwners, EscrowedKeys,
    KnownUtxo, KnownUtxos, SealedNullifierKey, UtxoOwner,
};
use zolana_ring_policy::Member;
use zolana_ring_transaction::{historical::InputPrefix, RingAssets};

use crate::{
    error::RingRpcError,
    spend_machine::{NoteRead, Observation, SpendRow, SpendState, Transition},
    spent_index::{Checkpoint, LoadedSpends, SpentCommitment},
};

pub const UTXO_BACKFILL_INTERVAL: Duration = Duration::from_secs(30);

/// Pages one backfill run reads, the next run resumes from its position.
pub(crate) const MAX_BACKFILL_PAGES: usize = 64;

/// The guards are never held across an await, a commit writes the mirror after its transaction.
#[derive(Default)]
pub(crate) struct AuditStore {
    book: RwLock<SpendBook>,
    escrow: RwLock<EscrowMap>,
    /// The registry last named on the notes, a different one names them again.
    assets: RwLock<Option<RingAssets>>,
    /// Owners whose key arrived, kept until a committed page derived their notes.
    late_owners: RwLock<BTreeSet<[u8; 32]>>,
    /// Set once the book holds the table's rows.
    loaded: AtomicBool,
    /// One backfill and escrow refresh at a time.
    pub(crate) backfill: AsyncMutex<HistoryPosition>,
}

#[derive(Default)]
struct SpendBook {
    notes: HashMap<[u8; 32], StoredUtxo>,
    /// The note index, a late secret fills it for that owner's notes.
    by_nullifier: HashMap<[u8; 32], [u8; 32]>,
    /// An unresolved row whose frame names a commitment, by that commitment.
    awaiting: HashMap<[u8; 32], [u8; 32]>,
    owned: HashMap<[u8; 32], BTreeSet<[u8; 32]>>,
    rows: HashMap<[u8; 32], SpendRow>,
    unread: BTreeSet<CreatedIn>,
    faults: Vec<SpendRow>,
    historical: HashMap<[u8; 32], SpentCommitment>,
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
    historical: Vec<SpentCommitment>,
    checkpoint: Option<Checkpoint>,
    late_owners: Vec<[u8; 32]>,
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
    pub wallet: Address,
    pub after: Option<[u8; 32]>,
    pub limit: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EscrowRoot {
    pub registry: Address,
    pub root: [u8; 32],
    pub revision: u64,
}

impl EscrowRoot {
    /// A lagging RPC node answers an older root, revisions order one registry alone.
    pub(crate) fn settles(&self, read: &EscrowRoot) -> bool {
        self.registry == read.registry && (self.root == read.root || read.revision < self.revision)
    }
}

/// Verified under the registry root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EscrowedOwner {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub owner_hash: [u8; 32],
    pub sealed: SealedNullifierKey,
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
    /// `None` until the owner's secret or a frame's evidence names it.
    pub nullifier: Option<[u8; 32]>,
}

#[derive(Default)]
struct EscrowMap {
    root: Option<EscrowRoot>,
    keys: HashMap<[u8; 32], EscrowedOwner>,
    /// Owner hash to owner key, over the owners of `keys`.
    owner_keys: HashMap<[u8; 32], [u8; 32]>,
}

impl SpendBook {
    fn absorb(&mut self, delta: PageDelta) {
        for (commitment, note) in delta.notes {
            if note.ring_note {
                if let Ok(member) = Member::owner_tag(&note.utxo.owner_key) {
                    self.owned
                        .entry(*member.as_bytes())
                        .or_default()
                        .insert(commitment);
                }
            }
            self.notes.insert(commitment, note);
        }
        self.by_nullifier.extend(delta.by_nullifier);
        for (nullifier, row) in delta.rows {
            match row.state {
                SpendState::UnresolvedReal {
                    evidence: Some(commitment),
                } => {
                    self.awaiting.insert(commitment, nullifier);
                }
                SpendState::Resolved { note } => {
                    self.awaiting.remove(&note);
                }
                _ => {}
            }
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
        for row in delta.historical {
            self.historical.entry(row.utxo_hash).or_insert(row);
        }
        if let Some(checkpoint) = delta.checkpoint {
            self.position_slot = checkpoint.position.checkpoint();
            if checkpoint.through.slot >= self.context.slot {
                self.context = checkpoint.through;
            }
        }
    }

    /// Only an unreadable frame holds the claim back, an unresolved row never does.
    fn history_through(&self) -> u64 {
        self.unread.first().map_or(self.context.slot, |frame| {
            self.context.slot.min(frame.slot.saturating_sub(1))
        })
    }

    fn spent_at(&self, commitment: &[u8; 32], note: &StoredUtxo) -> Option<u64> {
        let row = note
            .nullifier
            .and_then(|nullifier| self.rows.get(&nullifier));
        row.map(|row| row.frame.slot)
            .or_else(|| self.historical.get(commitment).map(|row| row.slot))
    }

    /// Reads one note's own nullifier and no other row.
    fn status(&self, commitment: &[u8; 32], note: &StoredUtxo, through: u64) -> WalletNoteStatus {
        NoteRead {
            nullifier_known: note.nullifier.is_some(),
            spent_at: self.spent_at(commitment, note),
            zero_key_wallet: note.utxo.owner.nullifier_pk() == Some(ZERO_NULLIFIER_PUBKEY)
                && Address::new_from_array(note.utxo.owner_key).is_on_curve(),
            history_through: through,
        }
        .status()
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

    pub(crate) fn historical(&self) -> &[SpentCommitment] {
        &self.historical
    }

    pub(crate) const fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoint.as_ref()
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

    /// The zero key's secret is public, every other opens from the owner's tracked record.
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
            return;
        }
        let awaiting = self
            .delta
            .rows
            .values()
            .find(|row| {
                row.state
                    == SpendState::UnresolvedReal {
                        evidence: Some(*commitment),
                    }
            })
            .map(|row| row.nullifier)
            .or_else(|| self.store.read_book().awaiting.get(commitment).copied());
        if let Some(nullifier) = awaiting {
            self.link(commitment, nullifier);
            self.settle(&nullifier, commitment);
        }
    }

    fn link(&mut self, commitment: &[u8; 32], nullifier: [u8; 32]) {
        if let Some(mut note) = self.note(commitment) {
            if note.nullifier.is_none() {
                note.nullifier = Some(nullifier);
                self.delta.notes.insert(*commitment, note);
            }
        }
        self.delta.by_nullifier.insert(nullifier, *commitment);
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

    /// A frame's evidence wins over the index, which it also fills.
    pub(crate) fn observe(&mut self, observation: Observation) {
        use crate::spend_machine::InputRead;
        let hit = match observation.read {
            InputRead::Real {
                evidence: Some(commitment),
            } => match self.note(&commitment) {
                Some(_) => {
                    self.link(&commitment, observation.nullifier);
                    Some(commitment)
                }
                None => self.note_of_nullifier(&observation.nullifier),
            },
            InputRead::Real { evidence: None } => self.note_of_nullifier(&observation.nullifier),
            InputRead::Unreadable | InputRead::Padding | InputRead::External => None,
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

    pub(crate) fn record_historical(&mut self, rows: Vec<SpentCommitment>) {
        self.delta.historical.extend(rows);
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
                .filter_map(|member| book.owned.get(member.as_bytes()))
                .flatten()
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

    /// The owner's tracked key, dropped with the page.
    pub(crate) fn open_key(&self, owner_key: &[u8; 32]) -> Option<NullifierKey> {
        (self.opener)(owner_key)
    }

    /// The notes a version 2 prefix can name, under `owner` when the row binds one.
    pub(crate) fn prefixed(&self, prefix: InputPrefix, owner: Option<[u8; 32]>) -> Vec<[u8; 32]> {
        let named = |commitment: &[u8; 32], stored: &StoredUtxo| {
            InputPrefix::of(commitment) == Some(prefix)
                && owner.is_none_or(|owner| stored.utxo.owner_key == owner)
        };
        let mut found: BTreeSet<[u8; 32]> = self
            .delta
            .notes
            .iter()
            .filter(|(commitment, stored)| named(commitment, stored))
            .map(|(commitment, _)| *commitment)
            .collect();
        found.extend(
            self.store
                .read_book()
                .notes
                .iter()
                .filter(|(commitment, stored)| named(commitment, stored))
                .map(|(commitment, _)| *commitment),
        );
        found.into_iter().collect()
    }

    /// Reads the next position with the terminal page's context, when the page ended the read.
    pub(crate) fn checkpoint(&mut self, position: HistoryPosition, terminal: Option<Context>) {
        let through = terminal.unwrap_or_else(|| self.store.context());
        self.delta.checkpoint = Some(Checkpoint { position, through });
    }

    pub(crate) fn finish(self) -> PageDelta {
        self.delta
    }
}

impl KnownUtxos for PageWork<'_> {
    fn utxo(&self, commitment: &[u8; 32]) -> Option<KnownUtxo> {
        self.note(commitment).map(|stored| stored.utxo)
    }
}

impl AuditStore {
    fn read_book(&self) -> std::sync::RwLockReadGuard<'_, SpendBook> {
        self.book.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// `true` once per store, the caller reads the tables into the book.
    pub(crate) fn loads_tables(&self) -> bool {
        !self.loaded.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn seed(&self, loaded: LoadedSpends) {
        let LoadedSpends {
            checkpoint,
            notes,
            rows,
            unread,
            faults,
        } = loaded;
        let delta = PageDelta {
            by_nullifier: notes
                .iter()
                .filter_map(|(commitment, note)| Some((note.nullifier?, *commitment)))
                .collect(),
            notes: notes.into_iter().collect(),
            rows: rows.into_iter().map(|row| (row.nullifier, row)).collect(),
            unread: unread.into_iter().collect(),
            faults,
            checkpoint: Some(checkpoint),
            ..PageDelta::default()
        };
        self.book
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .absorb(delta);
    }

    pub(crate) fn seed_historical(&self, rows: Vec<SpentCommitment>) {
        self.book
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .absorb(PageDelta {
                historical: rows,
                ..PageDelta::default()
            });
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

    /// A different registry names the notes stored without a mint.
    pub(crate) fn name_assets(&self, assets: &RingAssets) {
        {
            let mut current = self.assets.write().unwrap_or_else(PoisonError::into_inner);
            if current.as_ref() == Some(assets) {
                return;
            }
            *current = Some(assets.clone());
        }
        let mut book = self.book.write().unwrap_or_else(PoisonError::into_inner);
        for note in book.notes.values_mut() {
            if note.utxo.mint.is_none() {
                note.utxo.mint = assets.by_field(&note.utxo.asset).map(|mint| mint.asset);
            }
        }
    }

    /// Any published row of this nullifier, reads no slot bound.
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

    pub(crate) fn note(&self, commitment: &[u8; 32]) -> Option<StoredUtxo> {
        self.read_book().notes.get(commitment).copied()
    }

    pub(crate) fn wallet_status(&self, query: WalletStatusQuery) -> GetWalletStatusResponse {
        let member = Member::owner_tag(query.wallet.as_array()).ok();
        let book = self.read_book();
        let through = book.history_through();
        let commitments = member
            .and_then(|member| book.owned.get(member.as_bytes()))
            .into_iter()
            .flatten();
        let mut balances: BTreeMap<[u8; 32], WalletBalance> = BTreeMap::new();
        let mut notes = Vec::new();
        let mut cursor = None;
        for commitment in commitments {
            let Some(note) = book.notes.get(commitment) else {
                continue;
            };
            // A spent input and its change never both count.
            if note.created_in.slot > through {
                continue;
            }
            let status = book.status(commitment, note, through);
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
            if query.after.is_some_and(|after| *commitment <= after) {
                continue;
            }
            if notes.len() == query.limit {
                cursor = notes
                    .last()
                    .map(|note: &WalletNote| note.utxo_hash.0.to_vec().into());
                continue;
            }
            notes.push(note.wallet_note(commitment, status));
        }
        GetWalletStatusResponse {
            history_through: through,
            balances: balances.into_values().collect(),
            notes,
            cursor,
        }
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
            .filter(|row| matches!(row.state, SpendState::UnresolvedReal { .. }))
            .map(row)
            .collect();
        unresolved_real.sort_by_key(|row| (row.frame.slot, row.frame.event_index));
        GetSpendCoverageResponse {
            position_slot: book.position_slot,
            history_through: book.history_through(),
            observed: count(|state| matches!(state, SpendState::Observed)),
            padding: count(|state| matches!(state, SpendState::Padding)),
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

    /// Reads wallet status, an unrelated unresolved spend hides no note, a published row always does.
    pub(crate) fn spendable(
        &self,
        notes: SpendableNotes<'_>,
    ) -> Result<Vec<WalletUtxo>, RingRpcError> {
        let owner = UtxoOwner::Keyed {
            nullifier_pk: notes.nullifier_key.pubkey()?,
        };
        let book = self.read_book();
        book.notes
            .iter()
            .filter(|(commitment, stored)| {
                let utxo = &stored.utxo;
                stored.ring_note
                    && !book.historical.contains_key(*commitment)
                    && utxo.owner_key == notes.owner_key
                    && utxo.owner == owner
                    && utxo.mint == Some(notes.mint.asset)
                    && utxo.data_hash == [0; 32]
            })
            .map(|(commitment, stored)| stored.wallet_utxo(commitment, &notes))
            .filter(|note| !matches!(note, Ok(note) if book.rows.contains_key(&note.nullifier)))
            .collect()
    }

    pub(crate) fn escrowed(&self, owner_key: &[u8; 32]) -> Option<EscrowedOwner> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .get(owner_key)
            .copied()
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

    pub(crate) fn escrow_root(&self) -> Option<EscrowRoot> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .root
    }

    /// Every key the registry escrows under `root`, a new owner's notes derive on the next page.
    pub(crate) fn replace_escrow(
        &self,
        root: EscrowRoot,
        owners: HashMap<[u8; 32], EscrowedOwner>,
    ) {
        let mut escrow = self.escrow.write().unwrap_or_else(PoisonError::into_inner);
        self.late_owners
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(
                owners
                    .values()
                    .filter(|owner| !escrow.keys.contains_key(&owner.owner_key))
                    .map(|owner| owner.owner_key),
            );
        escrow.owner_keys = owners
            .values()
            .map(|owner| (owner.owner_hash, owner.owner_key))
            .collect();
        escrow.keys = owners
            .into_values()
            .map(|owner| (owner.owner_key, owner))
            .collect();
        escrow.root = Some(root);
    }

    /// The audit view of a merge the checkpoint opened.
    pub(crate) fn merge_output(&self, merge: &ConfirmedMerge) -> Option<AuditedMergeOutput> {
        let book = self.read_book();
        let note = book.notes.get(&merge.output_commitment)?;
        Some(AuditedMergeOutput {
            commitment: merge.output_commitment,
            slot: merge.slot,
            tx_signature: merge.tx_signature,
            event_index: merge.event_index,
            tree_id: merge.tree_id,
            leaf_index: merge.leaf_index,
            first_nullifier: merge.first_nullifier,
            ring_data_hash: merge.ring_data_hash,
            owner_key: note.utxo.owner_key,
            owner: note.utxo.owner,
            asset: note.utxo.asset,
            mint: note.utxo.mint,
            amount: note.utxo.amount,
            inputs: merge.inputs.clone(),
        })
    }

    /// Fails closed, an input no row names to this wallet reads as another party's.
    pub(crate) fn input_party(&self, wallet: &Address, input: &DecryptedInput) -> InputParty {
        let book = self.read_book();
        let owned_by = |commitment: &[u8; 32]| {
            book.notes
                .get(commitment)
                .is_some_and(|note| note.utxo.owner_key == wallet.to_bytes())
        };
        match book.rows.get(&input.nullifier.0).map(|row| row.state) {
            Some(SpendState::Padding) => InputParty::Padding,
            Some(SpendState::Resolved { note }) if owned_by(&note) => InputParty::Own,
            Some(_) => InputParty::Other,
            None if input.hash.is_none() && input.opening.is_none() && input.merged.is_none() => {
                match input.unseen {
                    true => InputParty::Other,
                    false => InputParty::Padding,
                }
            }
            None => match &input.hash {
                Some(hash) if owned_by(&hash.0) => InputParty::Own,
                _ => InputParty::Other,
            },
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

impl Borrow<KnownUtxo> for StoredUtxo {
    fn borrow(&self) -> &KnownUtxo {
        &self.utxo
    }
}

impl KnownUtxos for AuditStore {
    fn utxo(&self, commitment: &[u8; 32]) -> Option<KnownUtxo> {
        self.read_book().notes.get(commitment).map(|note| note.utxo)
    }
}

impl EscrowedKeys for AuditStore {
    fn nullifier_pk(&self, owner_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .get(owner_key)
            .map(|owner| owner.nullifier_pk)
    }
}

impl DepositOwners for AuditStore {
    fn deposit_owner(&self, owner_hash: &[u8; 32]) -> Option<DepositOwner> {
        let escrow = self.escrow.read().unwrap_or_else(PoisonError::into_inner);
        let owner = escrow.keys.get(escrow.owner_keys.get(owner_hash)?)?;
        Some(DepositOwner {
            owner_key: owner.owner_key,
            nullifier_pk: owner.nullifier_pk,
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
    /// Notes opened with no secret, a commit with no database.
    pub(crate) fn record(
        &self,
        created_in: CreatedIn,
        utxos: impl IntoIterator<Item = CreatedUtxo>,
    ) {
        let opener = |_: &[u8; 32]| None;
        let mut work = PageWork::new(self, &opener);
        work.open(created_in, utxos);
        self.commit(work.finish());
    }

    /// Published rows with no frame the test reads.
    pub(crate) fn spend(&self, nullifiers: impl IntoIterator<Item = [u8; 32]>) {
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
                read: InputRead::Real { evidence: None },
                hit: None,
            });
        }
        self.commit(work.finish());
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
