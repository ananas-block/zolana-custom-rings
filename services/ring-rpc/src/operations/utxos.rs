//! The UTXOs a ring's auditor opened and the nullifier keys its registry escrows.

use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        PoisonError, RwLock, RwLockReadGuard,
    },
    time::Duration,
};

use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::{Context, Hash};
use spr_keypair::{NullifierKey, PublicKey};
use spr_transaction::{Data, Mint, Utxo, WalletUtxo};
use tokio::sync::Mutex as AsyncMutex;
use zolana_ring_client::{
    history::HistoryPosition,
    rpc::{
        AuditedUtxoView, Coverage, UnresolvedHistory, UnresolvedReason, UnspentUtxoKind,
        UnspentUtxoView,
    },
    AuditedMergeOutput, AuditedOutput, ConfirmedMerge, CreatedUtxo, DepositNote, DepositOwner,
    DepositOwners, EscrowedKeys, KnownUtxo, KnownUtxoIndex, KnownUtxos, MergeInput, MergeLedger,
    OutputResolution, SealedNullifierKey, UnresolvedOutput, UtxoOwner,
};
use zolana_ring_policy::Member;
use zolana_ring_transaction::{historical::InputPrefix, RingAssets};

use crate::{error::RingRpcError, spent_index::SpentCommitment};

pub const UTXO_BACKFILL_INTERVAL: Duration = Duration::from_secs(30);

/// Pages one backfill run reads, the next run resumes from its position.
pub(crate) const MAX_BACKFILL_PAGES: usize = 64;

/// The guards are never held across an await, the audit reads them synchronously.
#[derive(Default)]
pub(crate) struct AuditStore {
    utxos: RwLock<KnownUtxoIndex<StoredUtxo>>,
    escrow: RwLock<EscrowMap>,
    /// Notes by commitment that wait for an escrow key or a mint.
    held: RwLock<HashMap<[u8; 32], (CreatedIn, HeldNote)>>,
    /// The registry last tried on the held notes, a different one retries them.
    assets: RwLock<Option<RingAssets>>,
    /// Only finalized ring events contribute nullifiers.
    spent: RwLock<HashSet<[u8; 32]>>,
    /// Mirrors `finalized_spent_commitments`.
    spent_commitments: RwLock<HashMap<[u8; 32], SpentCommitment>>,
    merges: RwLock<MergeLedger>,
    /// Rows whose evidence the auditor could not name, kept until each input opens.
    history: RwLock<BTreeMap<EventKey, UnnamedSpend>>,
    /// Notes of one record member, ordered by commitment for the unspent cursor.
    owned: RwLock<HashMap<[u8; 32], BTreeSet<[u8; 32]>>>,
    coverage: RwLock<CoverageStart>,
    /// The context of the backfill's newest terminal page.
    context: RwLock<Context>,
    /// Set once the spent mirror holds the table's rows.
    spent_seeded: AtomicBool,
    /// One backfill and escrow refresh at a time, a restart loses the position with the held notes and replays the history.
    pub(crate) backfill: AsyncMutex<HistoryPosition>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CreatedIn {
    pub slot: u64,
    pub tx_signature: Signature,
    pub event_index: u16,
}

type EventKey = (u64, Signature, u16);

/// One row with inputs the auditor has not named, permanent on a reason with no input list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnnamedSpend {
    pub reason: UnresolvedReason,
    pub inputs: Vec<[u8; 32]>,
}

impl UnnamedSpend {
    pub(crate) const fn of(reason: UnresolvedReason) -> Self {
        Self {
            reason,
            inputs: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CoverageStart {
    oldest_row: Option<u64>,
    newest_historical: Option<u64>,
    /// The newest backfill pass failed or hit its page cap, cleared at the next terminal page.
    pass_unfinished: bool,
}

/// One page of `getUnspentUtxos`, every note listed only as not seen spent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UnspentPage {
    pub utxos: Vec<UnspentUtxoView>,
    pub coverage: Coverage,
    pub unresolved: Vec<UnresolvedHistory>,
    pub cursor: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UnspentQuery<'a> {
    pub owner: &'a [u8; 32],
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

#[derive(Clone, Debug)]
pub(crate) enum HeldNote {
    Deposit(DepositNote),
    Output(UnresolvedOutput),
}

enum HeldOpening {
    Waits,
    Opened(Box<CreatedUtxo>),
    Refused,
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
    utxo: KnownUtxo,
    created_in: CreatedIn,
    slot_index: u32,
    leaf_index: u64,
}

#[derive(Default)]
struct EscrowMap {
    root: Option<EscrowRoot>,
    keys: HashMap<[u8; 32], EscrowedOwner>,
    /// Owner hash to owner key, over the owners of `keys`.
    owner_keys: HashMap<[u8; 32], [u8; 32]>,
}

impl AuditStore {
    pub(crate) fn record(
        &self,
        created_in: CreatedIn,
        utxos: impl IntoIterator<Item = CreatedUtxo>,
    ) {
        let assets = self.assets.read().unwrap_or_else(PoisonError::into_inner);
        let mut stored = self.utxos.write().unwrap_or_else(PoisonError::into_inner);
        for created in utxos {
            // A read under an older registry never unnames a stored note.
            let mint = created
                .utxo
                .mint
                .or_else(|| stored.get(&created.commitment)?.utxo.mint)
                .or_else(|| Some(assets.as_ref()?.by_field(&created.utxo.asset)?.asset));
            stored.insert(
                created.commitment,
                StoredUtxo {
                    utxo: KnownUtxo {
                        mint,
                        ..created.utxo
                    },
                    created_in,
                    slot_index: created.slot_index,
                    leaf_index: created.leaf_index,
                },
            );
            if created.ring_note {
                self.own(&created.utxo.owner_key, created.commitment);
            }
        }
        drop(stored);
        self.resolve_merges();
    }

    /// Tries each note under the current keys and registry, a read's snapshot can be older.
    pub(crate) fn hold(&self, created_in: CreatedIn, notes: impl IntoIterator<Item = HeldNote>) {
        let mut opened = Vec::new();
        {
            let mut held = self.held.write().unwrap_or_else(PoisonError::into_inner);
            let assets = self.assets.read().unwrap_or_else(PoisonError::into_inner);
            for note in notes {
                match note.open(self, assets.as_ref(), created_in) {
                    HeldOpening::Waits => {
                        held.insert(note.commitment(), (created_in, note));
                    }
                    HeldOpening::Opened(utxo) => opened.push(*utxo),
                    HeldOpening::Refused => {}
                }
            }
        }
        self.record(created_in, opened);
    }

    /// A different registry names the notes stored without a mint and retries the held ones.
    pub(crate) fn name_assets(&self, assets: &RingAssets) {
        {
            let mut current = self.assets.write().unwrap_or_else(PoisonError::into_inner);
            if current.as_ref() == Some(assets) {
                return;
            }
            *current = Some(assets.clone());
        }
        {
            let mut stored = self.utxos.write().unwrap_or_else(PoisonError::into_inner);
            let named: Vec<_> = stored
                .iter()
                .filter(|(_, stored)| stored.utxo.mint.is_none())
                .filter_map(|(commitment, stored)| {
                    let mint = assets.by_field(&stored.utxo.asset)?;
                    let utxo = KnownUtxo {
                        mint: Some(mint.asset),
                        ..stored.utxo
                    };
                    Some((*commitment, StoredUtxo { utxo, ..*stored }))
                })
                .collect();
            stored.extend(named);
        }
        self.merges
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .name_assets(assets);
        self.open_held();
    }

    /// Only a confirmed event's nullifiers enter, a note stays spendable past a rejected row.
    pub(crate) fn spend(&self, nullifiers: impl IntoIterator<Item = [u8; 32]>) {
        self.spent
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(nullifiers);
    }

    pub(crate) fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.spent
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(nullifier)
    }

    /// The first event that names a commitment holds its row.
    pub(crate) fn spend_commitments(&self, rows: impl IntoIterator<Item = SpentCommitment>) {
        let mut spent = self
            .spent_commitments
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        for row in rows {
            spent.entry(row.utxo_hash).or_insert(row);
        }
    }

    /// `true` once per store, the caller reads the table into the mirror.
    pub(crate) fn seeds_spent(&self) -> bool {
        !self.spent_seeded.swap(true, Ordering::AcqRel)
    }

    #[cfg(test)]
    pub(crate) fn spent_commitment(&self, commitment: &[u8; 32]) -> Option<SpentCommitment> {
        self.spent_commitments
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(commitment)
            .copied()
    }

    /// Applied once per confirmed merge, its inputs already sit in the spend index.
    pub(crate) fn apply_merge(&self, merge: ConfirmedMerge) {
        let known = self.known();
        let mut merges = self.merges.write().unwrap_or_else(PoisonError::into_inner);
        let transition = merges.apply(merge, |commitment| {
            known
                .get(commitment)
                .map(|stored| MergeInput::from(&stored.utxo))
        });
        drop(known);
        drop(merges);
        self.own_merge_outputs(&transition.resolved);
    }

    /// A new opening can complete a held merge and each of its descendants.
    fn resolve_merges(&self) {
        let known = self.known();
        let mut merges = self.merges.write().unwrap_or_else(PoisonError::into_inner);
        let resolved = merges.resolve(|commitment| {
            known
                .get(commitment)
                .map(|stored| MergeInput::from(&stored.utxo))
        });
        drop(known);
        drop(merges);
        self.own_merge_outputs(&resolved);
    }

    fn own_merge_outputs(&self, outputs: &[AuditedMergeOutput]) {
        for output in outputs {
            self.own(&output.owner_key, output.commitment);
        }
    }

    /// The notes a version 2 prefix can name, under `owner` when the row binds one.
    pub(crate) fn prefixed(&self, prefix: InputPrefix, owner: Option<[u8; 32]>) -> Vec<[u8; 32]> {
        self.known()
            .iter()
            .filter(|(commitment, stored)| {
                InputPrefix::of(commitment) == Some(prefix)
                    && owner.is_none_or(|owner| stored.utxo.owner_key == owner)
            })
            .map(|(commitment, _)| *commitment)
            .collect()
    }

    pub(crate) fn note_owner(&self, commitment: &[u8; 32]) -> Option<[u8; 32]> {
        self.known()
            .get(commitment)
            .map(|stored| stored.utxo.owner_key)
    }

    fn own(&self, owner_key: &[u8; 32], commitment: [u8; 32]) {
        // A key no identity hash takes owns no listed note.
        let Ok(member) = Member::owner_tag(owner_key) else {
            return;
        };
        self.owned
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(*member.as_bytes())
            .or_default()
            .insert(commitment);
    }

    /// An audit record of a merge output, `None` until every input opened.
    pub(crate) fn merged(&self, commitment: &[u8; 32]) -> Option<AuditedMergeOutput> {
        self.merges
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .output(commitment)
            .cloned()
    }

    /// Coverage opens past the newest row the historical reader decoded.
    pub(crate) fn saw_row(&self, slot: u64, historical: bool) {
        let mut coverage = self
            .coverage
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        coverage.oldest_row = Some(coverage.oldest_row.map_or(slot, |oldest| oldest.min(slot)));
        if historical {
            coverage.newest_historical = Some(
                coverage
                    .newest_historical
                    .map_or(slot, |newest| newest.max(slot)),
            );
        }
    }

    /// Keeps the first reason of a row, its inputs narrow as openings land.
    pub(crate) fn hold_unnamed(&self, key: CreatedIn, spend: UnnamedSpend) {
        self.history
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((key.slot, key.tx_signature, key.event_index))
            .or_insert(spend);
    }

    /// Absence from the index stays "not seen spent", a covered row names its through slot.
    pub(crate) fn unspent(&self, query: UnspentQuery<'_>) -> UnspentPage {
        let coverage = self.coverage();
        let unresolved = self.unresolved_history();
        let window = coverage.from_slot..=coverage.through_slot;
        // The note store comes first, `record` writes it before the owner index.
        let known = self.known();
        let owned = self.owned.read().unwrap_or_else(PoisonError::into_inner);
        let merges = self.merges.read().unwrap_or_else(PoisonError::into_inner);
        let spent = self
            .spent_commitments
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let listed = owned
            .get(query.owner)
            .into_iter()
            .flatten()
            .filter(|commitment| query.after.is_none_or(|after| **commitment > after))
            .filter(|commitment| !spent.contains_key(*commitment))
            .filter_map(|commitment| {
                let view = match known.get(commitment) {
                    Some(stored) => stored.unspent_view(commitment),
                    None => merge_output_view(merges.output(commitment)?),
                };
                window.contains(&view.slot).then_some((*commitment, view))
            });
        let mut utxos = Vec::new();
        let mut cursor = None;
        for (commitment, view) in listed {
            if utxos.len() == query.limit {
                cursor = utxos.last().map(|view: &UnspentUtxoView| view.utxo_hash.0);
                debug_assert!(cursor.is_some_and(|last| last < commitment));
                break;
            }
            utxos.push(view);
        }
        UnspentPage {
            utxos,
            coverage,
            unresolved,
            cursor,
        }
    }

    fn coverage(&self) -> Coverage {
        let start = *self.coverage.read().unwrap_or_else(PoisonError::into_inner);
        let through_slot = self.context().slot;
        let unresolved = !self.unresolved_history().is_empty();
        Coverage {
            from_slot: start
                .newest_historical
                .map_or(start.oldest_row.unwrap_or(through_slot), |newest| {
                    newest.saturating_add(1)
                }),
            through_slot,
            // No terminal page reached means nothing in the window has been looked at.
            complete: through_slot != 0 && !start.pass_unfinished && !unresolved,
        }
    }

    fn unresolved_history(&self) -> Vec<UnresolvedHistory> {
        let known = self.known();
        let merges = self.merges.read().unwrap_or_else(PoisonError::into_inner);
        let history = self.history.read().unwrap_or_else(PoisonError::into_inner);
        let named = |commitment: &[u8; 32]| {
            known.get(commitment).is_some() || merges.output(commitment).is_some()
        };
        let spends = history
            .iter()
            .filter_map(|((slot, signature, event), spend)| {
                let inputs: Vec<Hash> = spend
                    .inputs
                    .iter()
                    .filter(|input| !named(input))
                    .map(|input| Hash(*input))
                    .collect();
                // A row with no input list stays until a reset.
                (spend.inputs.is_empty() || !inputs.is_empty()).then_some(UnresolvedHistory {
                    slot: *slot,
                    tx_signature: (*signature).into(),
                    event_index: *event,
                    reason: spend.reason,
                    inputs,
                })
            });
        let held = merges.unresolved().map(|merge| UnresolvedHistory {
            slot: merge.slot,
            tx_signature: merge.tx_signature.into(),
            event_index: merge.event_index,
            reason: UnresolvedReason::UnknownMergeInput,
            inputs: merge
                .inputs
                .iter()
                .filter(|input| !named(input))
                .map(|input| Hash(*input))
                .collect(),
        });
        let mut rows: Vec<_> = spends.chain(held).collect();
        rows.sort_by_key(|row| (row.slot, row.event_index));
        rows
    }

    /// A stale row hides funds from merge selection and authority transfers, no limit reads it.
    pub(crate) fn spendable(
        &self,
        notes: SpendableNotes<'_>,
    ) -> Result<Vec<WalletUtxo>, RingRpcError> {
        let owner = UtxoOwner::Keyed {
            nullifier_pk: notes.nullifier_key.pubkey()?,
        };
        let spent = self.spent.read().unwrap_or_else(PoisonError::into_inner);
        let spent_commitments = self
            .spent_commitments
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let known = self.known();
        let mut selected = known
            .iter()
            .filter(|(commitment, stored)| {
                let utxo = &stored.utxo;
                !spent_commitments.contains_key(*commitment)
                    && utxo.owner_key == notes.owner_key
                    && utxo.owner == owner
                    && utxo.mint == Some(notes.mint.asset)
                    && utxo.data_hash == [0; 32]
            })
            .map(|(commitment, stored)| stored.wallet_utxo(commitment, &notes))
            .filter(|note| !matches!(note, Ok(note) if spent.contains(&note.nullifier)))
            .collect::<Result<Vec<_>, _>>()?;
        let merges = self.merges.read().unwrap_or_else(PoisonError::into_inner);
        for output in merges.outputs().filter(|output| {
            !spent_commitments.contains_key(&output.commitment)
                && known.get(&output.commitment).is_none()
                && output.owner_key == notes.owner_key
                && output.mint == Some(notes.mint.asset)
        }) {
            let Some(utxo) = output.opening(notes.ring, notes.nullifier_key)? else {
                continue;
            };
            let opening = StoredUtxo {
                utxo,
                created_in: CreatedIn {
                    slot: output.slot,
                    tx_signature: output.tx_signature,
                    event_index: output.event_index,
                },
                slot_index: 0,
                leaf_index: output.leaf_index,
            };
            let note = opening.wallet_utxo(&output.commitment, &notes)?;
            if !spent.contains(&note.nullifier) {
                selected.push(note);
            }
        }
        Ok(selected)
    }

    pub(crate) fn escrowed(&self, owner_key: &[u8; 32]) -> Option<EscrowedOwner> {
        self.escrow
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys
            .get(owner_key)
            .copied()
    }

    pub(crate) fn pass_unfinished(&self) {
        self.coverage
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .pass_unfinished = true;
    }

    /// Only the backfill's terminal page moves the claim.
    pub(crate) fn absorbed(&self, context: Context) {
        self.coverage
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .pass_unfinished = false;
        let mut newest = self.context.write().unwrap_or_else(PoisonError::into_inner);
        if context.slot >= newest.slot {
            *newest = context;
        }
    }

    pub(crate) fn context(&self) -> Context {
        *self.context.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn view(&self, utxo_hash: &Hash) -> Option<AuditedUtxoView> {
        let stored = self.stored(&utxo_hash.0)?;
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

    /// Every key the registry escrows under `root`, the map read under an older root goes.
    pub(crate) fn replace_escrow(
        &self,
        root: EscrowRoot,
        owners: HashMap<[u8; 32], EscrowedOwner>,
    ) {
        {
            let mut escrow = self.escrow.write().unwrap_or_else(PoisonError::into_inner);
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
        self.open_held();
    }

    /// An audit holds the guard for its full run, no UTXO enters between two of its lookups.
    pub(crate) fn known(&self) -> RwLockReadGuard<'_, KnownUtxoIndex<StoredUtxo>> {
        self.utxos.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn open_held(&self) {
        let assets = self
            .assets
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut opened = Vec::new();
        self.held
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(
                |_, (created_in, note)| match note.open(self, assets.as_ref(), *created_in) {
                    HeldOpening::Waits => true,
                    HeldOpening::Opened(utxo) => {
                        opened.push((*created_in, *utxo));
                        false
                    }
                    HeldOpening::Refused => false,
                },
            );
        for (created_in, utxo) in opened {
            self.record(created_in, [utxo]);
        }
    }

    fn stored(&self, utxo_hash: &[u8; 32]) -> Option<StoredUtxo> {
        self.known().get(utxo_hash).copied()
    }
}

impl HeldNote {
    fn commitment(&self) -> [u8; 32] {
        match self {
            Self::Deposit(note) => note.commitment,
            Self::Output(output) => output.context.hash,
        }
    }

    fn open(
        &self,
        store: &AuditStore,
        assets: Option<&RingAssets>,
        created_in: CreatedIn,
    ) -> HeldOpening {
        match self {
            Self::Deposit(note) => note.created(store).map_or(HeldOpening::Waits, |utxo| {
                HeldOpening::Opened(Box::new(utxo))
            }),
            Self::Output(output) => {
                let Some(assets) = assets else {
                    return HeldOpening::Waits;
                };
                match output.resolve(store, assets) {
                    Ok(OutputResolution::AwaitsKey | OutputResolution::AwaitsAsset) => {
                        HeldOpening::Waits
                    }
                    Ok(OutputResolution::Opened(opening)) => AuditedOutput {
                        slot_index: output.slot_index,
                        context: output.context.clone(),
                        opening: *opening,
                    }
                    .created()
                    .map_or(HeldOpening::Refused, |utxo| {
                        HeldOpening::Opened(Box::new(utxo))
                    }),
                    Ok(OutputResolution::Refused(_)) | Err(_) => {
                        log::warn!(
                            "held output {} of {}:{} rebuilds no commitment",
                            output.slot_index,
                            created_in.tx_signature,
                            created_in.event_index
                        );
                        HeldOpening::Refused
                    }
                }
            }
        }
    }
}

fn merge_output_view(output: &AuditedMergeOutput) -> UnspentUtxoView {
    UnspentUtxoView {
        utxo_hash: Hash(output.commitment),
        asset: Hash(output.asset),
        mint: output.mint.map(Into::into),
        amount: output.amount,
        kind: UnspentUtxoKind::MergeOutput,
        slot: output.slot,
        tx_signature: output.tx_signature.into(),
        event_index: output.event_index,
        slot_index: 0,
    }
}

impl StoredUtxo {
    fn unspent_view(&self, commitment: &[u8; 32]) -> UnspentUtxoView {
        UnspentUtxoView {
            utxo_hash: Hash(*commitment),
            asset: Hash(self.utxo.asset),
            mint: self.utxo.mint.map(Into::into),
            amount: self.utxo.amount,
            kind: UnspentUtxoKind::Opened {
                blinding: Hash(self.utxo.blinding),
                tree_id: self.utxo.tree_id,
            },
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
        self.stored(commitment).map(|stored| stored.utxo)
    }

    fn merged(&self, commitment: &[u8; 32]) -> Option<MergeInput> {
        self.merged(commitment).as_ref().map(MergeInput::from)
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

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use spr_keypair::X25519Keypair;
    use zolana_ring_client::{NullifierKeyEnvelope, UtxoOwner};

    use super::*;

    fn created(mint: Option<Address>) -> CreatedUtxo {
        CreatedUtxo {
            commitment: [1; 32],
            slot_index: 0,
            leaf_index: 0,
            utxo: KnownUtxo {
                owner_key: [2; 32],
                owner: UtxoOwner::Keyed {
                    nullifier_pk: [3; 32],
                },
                asset: [4; 32],
                mint,
                amount: 10,
                blinding: [5; 32],
                data_hash: [0; 32],
                ring_data_hash: [0; 32],
                tree_id: 1,
            },
            ring_note: true,
        }
    }

    #[test]
    fn a_stored_utxo_changes_only_to_gain_its_mint() {
        let store = AuditStore::default();
        let created_in = CreatedIn {
            slot: 1,
            tx_signature: Signature::from([7; 64]),
            event_index: 0,
        };
        let mint = Some(Address::new_from_array([6; 32]));
        let stored_mint = || store.stored(&[1; 32]).map(|stored| stored.utxo.mint);
        store.record(created_in, [created(None)]);
        store.record(created_in, [created(mint)]);
        assert_eq!(stored_mint(), Some(mint));
        store.record(created_in, [created(None)]);
        assert_eq!(stored_mint(), Some(mint));
    }

    #[test]
    fn a_note_from_an_older_registry_snapshot_stays_named() {
        let store = AuditStore::default();
        let created_in = CreatedIn {
            slot: 1,
            tx_signature: Signature::from([7; 64]),
            event_index: 0,
        };
        let mint = Address::new_from_array([6; 32]);
        let assets = RingAssets::new([Mint::new(mint, 6)]).unwrap();
        store.name_assets(&assets);
        let mut stale = created(None);
        stale.utxo.asset = assets
            .fields()
            .find(|(_, registered)| registered.asset == mint)
            .unwrap()
            .0;
        store.record(created_in, [stale]);
        assert_eq!(
            store.stored(&[1; 32]).map(|stored| stored.utxo.mint),
            Some(Some(mint))
        );
    }

    #[test]
    fn a_new_registry_names_a_stored_mint() {
        let store = AuditStore::default();
        let created_in = CreatedIn {
            slot: 1,
            tx_signature: Signature::from([7; 64]),
            event_index: 0,
        };
        let mint = Address::new_from_array([6; 32]);
        let assets = RingAssets::new([Mint::new(mint, 3)]).expect("assets");
        let mut unnamed = created(None);
        unnamed.utxo.asset = spr_hasher::primitives::hash_bytes(mint.as_array()).unwrap();
        store.record(created_in, [unnamed]);
        store.name_assets(&assets);
        assert_eq!(store.stored(&[1; 32]).unwrap().utxo.mint, Some(mint));
    }

    #[test]
    fn a_registry_refresh_names_resolved_merges_and_their_descendants() {
        let store = AuditStore::default();
        let mint = Address::new_from_array([6; 32]);
        let assets = RingAssets::new([Mint::new(mint, 3)]).unwrap();
        let mut input = created(None);
        input.utxo.asset = spr_hasher::primitives::hash_bytes(mint.as_array()).unwrap();
        store.record(created_in(10), [input]);
        for (slot, input, output) in [(11, [1; 32], [2; 32]), (12, [2; 32], [3; 32])] {
            store.apply_merge(ConfirmedMerge {
                slot,
                tx_signature: Signature::from([slot as u8; 64]),
                event_index: 0,
                output_commitment: output,
                tree_id: 1,
                leaf_index: slot,
                first_nullifier: [9; 32],
                ring_data_hash: [0; 32],
                inputs: vec![input],
            });
            store.spend_commitments([spent(input)]);
            assert_eq!(store.merged(&output).unwrap().mint, None);
        }
        store.name_assets(&assets);
        store.name_assets(&RingAssets::new([]).unwrap());
        assert_eq!(store.stored(&[1; 32]).unwrap().utxo.mint, Some(mint));
        for commitment in [[2; 32], [3; 32]] {
            assert_eq!(store.merged(&commitment).unwrap().mint, Some(mint));
        }
        store.saw_row(10, false);
        store.absorbed(frontier(20));
        let owner = owner_member();
        let page = store.unspent(UnspentQuery {
            owner: &owner,
            after: None,
            limit: 10,
        });
        let [output] = page.utxos.as_slice() else {
            panic!("one merge output");
        };
        assert_eq!(output.utxo_hash.0, [3; 32]);
        assert_eq!(output.mint, Some(mint.into()));
        assert_eq!(output.amount, input.utxo.amount);
    }

    #[test]
    fn revisions_order_one_registry_alone() {
        let current = EscrowRoot {
            registry: Address::new_from_array([1; 32]),
            root: [1; 32],
            revision: 100,
        };
        let older = EscrowRoot {
            root: [2; 32],
            revision: 99,
            ..current
        };
        let newer = EscrowRoot {
            root: [3; 32],
            revision: 101,
            ..current
        };
        let replaced = EscrowRoot {
            registry: Address::new_from_array([2; 32]),
            root: [4; 32],
            revision: 1,
        };
        assert!(current.settles(&current));
        assert!(current.settles(&older));
        assert!(!current.settles(&newer));
        assert!(!current.settles(&replaced));
        assert!(!current.settles(&EscrowRoot {
            root: current.root,
            ..replaced
        }));
    }

    #[test]
    fn an_escrowed_owner_opens_the_deposits_audited_before_its_key() {
        let store = AuditStore::default();
        let created_in = CreatedIn {
            slot: 1,
            tx_signature: Signature::from([7; 64]),
            event_index: 0,
        };
        let note = DepositNote {
            commitment: [1; 32],
            slot_index: 0,
            leaf_index: 0,
            owner_hash: [8; 32],
            owner_key: [2; 32],
            asset: [4; 32],
            mint: Address::new_from_array([6; 32]),
            amount: 10,
            blinding: [5; 32],
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
            tree_id: 1,
        };
        let owner = EscrowedOwner {
            owner_key: note.owner_key,
            nullifier_pk: [3; 32],
            owner_hash: note.owner_hash,
            sealed: NullifierKeyEnvelope::new(
                &NullifierKey::from_secret([9; 31]),
                &X25519Keypair::new().pubkey(),
            )
            .expect("envelope")
            .sealed,
        };
        store.hold(created_in, [HeldNote::Deposit(note)]);
        assert!(store.stored(&note.commitment).is_none());
        store.replace_escrow(
            EscrowRoot {
                registry: Address::new_from_array([1; 32]),
                root: [1; 32],
                revision: 1,
            },
            HashMap::from([(owner.owner_key, owner)]),
        );
        let opened = store.stored(&note.commitment).expect("reopened deposit");
        assert_eq!(opened.created_in, created_in);
        assert_eq!(opened.utxo.owner_key, owner.owner_key);
        assert_eq!(
            opened.utxo.owner,
            UtxoOwner::Keyed {
                nullifier_pk: owner.nullifier_pk
            }
        );
    }

    fn created_in(slot: u64) -> CreatedIn {
        CreatedIn {
            slot,
            tx_signature: Signature::from([slot as u8; 64]),
            event_index: 0,
        }
    }

    fn owner_member() -> [u8; 32] {
        *Member::owner_tag(&[2; 32]).unwrap().as_bytes()
    }

    fn spent(commitment: [u8; 32]) -> SpentCommitment {
        SpentCommitment {
            utxo_hash: commitment,
            slot: 12,
            tx_signature: Signature::from([12; 64]),
            event_index: 0,
            first_nullifier: [9; 32],
            source: crate::spent_index::SpentSource::Transfer,
        }
    }

    fn frontier(slot: u64) -> Context {
        Context {
            slot,
            block_time: 0,
        }
    }

    #[test]
    fn absence_from_the_spend_index_never_reads_as_unspent() {
        let store = AuditStore::default();
        let owner = owner_member();
        let query = UnspentQuery {
            owner: &owner,
            after: None,
            limit: 10,
        };
        store.saw_row(10, false);
        store.record(created_in(10), [created(None)]);
        // No frontier reached, nothing is claimed about the note.
        let before = store.unspent(query);
        assert!(before.utxos.is_empty());
        assert!(!before.coverage.complete);
        store.absorbed(frontier(20));
        let covered = store.unspent(query);
        assert_eq!(covered.utxos.len(), 1);
        assert_eq!(
            covered.coverage,
            Coverage {
                from_slot: 10,
                through_slot: 20,
                complete: true,
            }
        );
        // A spend the auditor cannot name leaves the note listed and takes the claim away.
        let unnamed = [7; 32];
        store.hold_unnamed(
            created_in(11),
            UnnamedSpend {
                reason: UnresolvedReason::UnknownSpend,
                inputs: vec![unnamed],
            },
        );
        let held = store.unspent(query);
        assert_eq!(held.utxos.len(), 1);
        assert!(!held.coverage.complete);
        assert_eq!(held.unresolved[0].inputs, [Hash(unnamed)]);
        // Its opening names the input, the claim returns.
        store.record(
            created_in(11),
            [CreatedUtxo {
                commitment: unnamed,
                ..created(None)
            }],
        );
        assert!(store.unspent(query).coverage.complete);
        store.spend_commitments([spent([1; 32]), spent(unnamed)]);
        assert!(store.unspent(query).utxos.is_empty());
    }

    #[test]
    fn a_row_with_no_input_list_keeps_the_claim_false_for_good() {
        let store = AuditStore::default();
        store.saw_row(10, false);
        store.absorbed(frontier(20));
        store.hold_unnamed(
            created_in(10),
            UnnamedSpend::of(UnresolvedReason::UnreadableRow),
        );
        store.record(created_in(11), [created(None)]);
        let owner = owner_member();
        let page = store.unspent(UnspentQuery {
            owner: &owner,
            after: None,
            limit: 10,
        });
        assert!(!page.coverage.complete);
        assert_eq!(page.unresolved[0].reason, UnresolvedReason::UnreadableRow);
    }

    #[test]
    fn a_note_at_or_below_the_newest_historical_row_stays_outside_coverage() {
        let store = AuditStore::default();
        store.saw_row(15, true);
        store.record(created_in(15), [created(None)]);
        store.record(
            created_in(16),
            [CreatedUtxo {
                commitment: [8; 32],
                ..created(None)
            }],
        );
        store.absorbed(frontier(20));
        let owner = owner_member();
        let page = store.unspent(UnspentQuery {
            owner: &owner,
            after: None,
            limit: 10,
        });
        assert_eq!(page.coverage.from_slot, 16);
        let listed: Vec<_> = page.utxos.iter().map(|view| view.utxo_hash.0).collect();
        assert_eq!(listed, [[8; 32]]);
    }

    #[test]
    fn a_merge_spends_its_inputs_once_and_its_output_lists_after_every_input_opens() {
        let store = AuditStore::default();
        store.saw_row(10, false);
        store.absorbed(frontier(20));
        store.record(created_in(10), [created(None)]);
        let merge = ConfirmedMerge {
            slot: 11,
            tx_signature: Signature::from([11; 64]),
            event_index: 0,
            output_commitment: [0x20; 32],
            tree_id: 1,
            leaf_index: 4,
            first_nullifier: [9; 32],
            ring_data_hash: [0; 32],
            inputs: vec![[1; 32], [0x10; 32]],
        };
        store.apply_merge(merge.clone());
        store.apply_merge(merge.clone());
        let owner = owner_member();
        let query = UnspentQuery {
            owner: &owner,
            after: None,
            limit: 10,
        };
        let held = store.unspent(query);
        assert!(!held.coverage.complete);
        assert_eq!(held.unresolved[0].inputs, [Hash([0x10; 32])]);
        assert!(store.merged(&[0x20; 32]).is_none());
        store.record(
            created_in(10),
            [CreatedUtxo {
                commitment: [0x10; 32],
                ..created(None)
            }],
        );
        let output = store.merged(&[0x20; 32]).expect("every input opened");
        assert_eq!(output.amount, 20);
        store.spend_commitments(merge.inputs.iter().copied().map(spent));
        let page = store.unspent(query);
        assert!(page.coverage.complete);
        let [view] = page.utxos.as_slice() else {
            panic!("the output alone stays listed");
        };
        assert_eq!(view.kind, UnspentUtxoKind::MergeOutput);
    }
}
