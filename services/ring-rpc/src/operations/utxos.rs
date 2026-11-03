//! The UTXOs a ring's auditor opened and the nullifier keys its registry escrows.

use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    sync::{PoisonError, RwLock, RwLockReadGuard},
    time::Duration,
};

use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::{Context, Hash};
use spr_keypair::{NullifierKey, PublicKey};
use spr_transaction::{Data, Mint, Utxo, WalletUtxo};
use tokio::sync::Mutex as AsyncMutex;
use zolana_ring_client::{
    rpc::AuditedUtxoView, AuditedOutput, CreatedUtxo, DepositNote, DepositOwner, DepositOwners,
    EscrowedKeys, KnownUtxo, KnownUtxoIndex, OutputResolution, SealedNullifierKey,
    UnresolvedOutput, UtxoOwner,
};
use zolana_ring_transaction::RingAssets;

use crate::error::RingRpcError;

pub const UTXO_BACKFILL_INTERVAL: Duration = Duration::from_secs(30);

/// Pages one backfill run reads, the next run resumes from its cursor.
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
    /// Every nullifier a confirmed event of the ring history published.
    spent: RwLock<HashSet<[u8; 32]>>,
    /// The indexer context when the backfill last reached the scan frontier.
    context: RwLock<Context>,
    /// The next backfill's position, one backfill and escrow refresh at a time, a restart loses it with the held notes and replays the history.
    pub(crate) backfill: AsyncMutex<Option<Vec<u8>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CreatedIn {
    pub slot: u64,
    pub tx_signature: Signature,
    pub event_index: u16,
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
        }
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

    pub(crate) fn spendable(
        &self,
        notes: SpendableNotes<'_>,
    ) -> Result<Vec<WalletUtxo>, RingRpcError> {
        let owner = UtxoOwner::Keyed {
            nullifier_pk: notes.nullifier_key.pubkey()?,
        };
        let spent = self.spent.read().unwrap_or_else(PoisonError::into_inner);
        let known = self.known();
        known
            .iter()
            .filter(|(_, stored)| {
                let utxo = &stored.utxo;
                utxo.owner_key == notes.owner_key
                    && utxo.owner == owner
                    && utxo.mint == Some(notes.mint.asset)
                    && utxo.data_hash == [0; 32]
            })
            .map(|(commitment, stored)| stored.wallet_utxo(commitment, &notes))
            .filter(|note| !matches!(note, Ok(note) if spent.contains(&note.nullifier)))
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

    pub(crate) fn absorbed(&self, context: Context) {
        let mut newest = self.context.write().unwrap_or_else(PoisonError::into_inner);
        if context.slot >= newest.slot {
            *newest = context;
        }
    }

    pub(crate) fn context(&self) -> Context {
        self.context
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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

impl StoredUtxo {
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
}
