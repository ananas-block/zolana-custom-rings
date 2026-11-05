//! Records one page's steps, then replays them once every key they read is at hand.
//!
//! Beside a database the mirror is a bounded cache of the projection. `PageWork::finish` replays the
//! steps against the page's delta, the rows it loaded and the cache. A replay that meets a key the
//! cache may have evicted loads it and replays again, so every decision reads the row storage
//! holds. Only commits and reloads fill the cache, a replay never does.
//!
//! Read after `operations/spend_machine.rs`, each replayed step drives it. Read before
//! `storage/spent_index.rs`, its page commit writes the delta `finish` returns.

use std::{
    collections::{BTreeSet, HashMap},
    sync::PoisonError,
};

use spr_indexer_api::{Context, Hash};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::NullifierKey;
use zolana_ring_client::{history::HistoryPosition, CreatedUtxo, KnownUtxo};
use zolana_ring_policy::Member;

use super::{AuditStore, CreatedIn, IndexedNote, OwnerChange, PageDelta, StoredUtxo};
use crate::{
    bounded_map::Cached,
    error::RingRpcError,
    spend_machine::{InputRead, Observation, SpendRow, Transition},
    spent_index::Checkpoint,
};

/// Each round loads every key the last replay missed, a later round meets only keys an earlier
/// load revealed.
const MAX_LOAD_ROUNDS: usize = 4;

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
            loaded.fetch(self.store, missed).await?;
        }
        Err(RingRpcError::StateUnavailable)
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

    fn apply(&mut self, transition: Transition) {
        match transition {
            Transition::Unchanged => {}
            Transition::Write(row) => {
                self.delta.rows.insert(row.nullifier, row);
            }
            Transition::Integrity(row) => self.delta.faults.push(row),
        }
    }
}

impl Loaded {
    /// Storage's answer for every key a replay missed.
    async fn fetch(&mut self, store: &AuditStore, missed: Missed) -> Result<(), RingRpcError> {
        let Missed {
            notes,
            by_nullifier,
            rows,
            owners,
        } = missed;
        let notes: Vec<[u8; 32]> = notes.into_iter().collect();
        let mut found = store.notes(&notes).await?;
        for commitment in notes {
            self.notes.insert(commitment, found.remove(&commitment));
        }
        let by_nullifier: Vec<[u8; 32]> = by_nullifier.into_iter().collect();
        let mut found = store.notes_of_nullifiers(&by_nullifier).await?;
        for nullifier in by_nullifier {
            let hit = found.remove(&nullifier);
            if let Some((commitment, note)) = hit {
                self.notes.entry(commitment).or_insert(Some(note));
            }
            self.by_nullifier
                .insert(nullifier, hit.map(|(commitment, _)| commitment));
        }
        let rows: Vec<[u8; 32]> = rows.into_iter().collect();
        let mut found = store.spend_rows(&rows).await?;
        for nullifier in rows {
            self.rows.insert(nullifier, found.remove(&nullifier));
        }
        for member in owners {
            let mut commitments = Vec::new();
            for indexed in store.indexed_notes(&member).await? {
                self.notes
                    .entry(indexed.commitment)
                    .or_insert(Some(indexed.note));
                commitments.push(indexed.commitment);
            }
            self.owners.insert(member, commitments);
        }
        Ok(())
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
