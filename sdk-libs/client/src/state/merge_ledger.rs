//! The auditor's merge transitions, applied once per confirmed merge and resolved to a fixed point.

use std::collections::{BTreeMap, HashMap, HashSet};

use solana_address::Address;
use solana_signature::Signature;
use spr_hasher::primitives::hash_bytes;
use spr_keypair::NullifierKey;
use spr_transaction::instructions::merge::{merge_output_blinding, MergeSeed};
use zolana_ring_transaction::RingAssets;

use crate::{
    types::{KnownUtxo, UtxoOwner},
    AuditError, REDACTED,
};

/// `(tx_signature, event_index)`, one confirmed merge.
pub type MergeId = (Signature, u16);

/// One confirmed merge, the published count never reads as a count of real inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedMerge {
    pub slot: u64,
    pub tx_signature: Signature,
    pub event_index: u16,
    pub output_commitment: [u8; 32],
    pub tree_id: u16,
    pub leaf_index: u64,
    pub first_nullifier: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub disclosed: MergeDisclosed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeDisclosed {
    /// Tag 47, a zero entry of the disclosed list left out as a dummy.
    Inputs(Vec<[u8; 32]>),
    /// Tag 57.
    Record(MergeRecordOutput),
}

/// A rebuilt tag 57 record.
#[derive(Clone, PartialEq, Eq)]
pub struct MergeRecordOutput {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub mint: Address,
    pub amount: u64,
    pub seed: [u8; 32],
    /// Published nullifiers no seed derivation names as padding.
    pub real_nullifiers: Vec<[u8; 32]>,
}

impl core::fmt::Debug for MergeRecordOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            owner_key,
            nullifier_pk,
            mint,
            amount,
            seed: _,
            real_nullifiers,
        } = self;
        f.debug_struct("MergeRecordOutput")
            .field("owner_key", owner_key)
            .field("nullifier_pk", nullifier_pk)
            .field("mint", mint)
            .field("amount", amount)
            .field("seed", &REDACTED)
            .field("real_nullifiers", real_nullifiers)
            .finish()
    }
}

/// The fields a merge output inherits, an audit record and no wallet opening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedMergeOutput {
    pub commitment: [u8; 32],
    pub slot: u64,
    pub tx_signature: Signature,
    pub event_index: u16,
    pub tree_id: u16,
    pub leaf_index: u64,
    pub first_nullifier: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub owner_key: [u8; 32],
    pub owner: UtxoOwner,
    pub asset: [u8; 32],
    pub mint: Option<Address>,
    /// The record's, a tag 47 merge's sum of its inputs.
    pub amount: u64,
    /// Tag 47 alone.
    pub inputs: Vec<[u8; 32]>,
    /// Tag 57 alone.
    pub real_nullifiers: Vec<[u8; 32]>,
    /// Tag 57 alone.
    pub seed: Option<[u8; 32]>,
}

/// The fields of one spent commitment, from an opening or an earlier merge output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeInput {
    pub owner_key: [u8; 32],
    pub owner: UtxoOwner,
    pub asset: [u8; 32],
    pub mint: Option<Address>,
    pub amount: u64,
}

impl From<&KnownUtxo> for MergeInput {
    fn from(utxo: &KnownUtxo) -> Self {
        Self {
            owner_key: utxo.owner_key,
            owner: utxo.owner,
            asset: utxo.asset,
            mint: utxo.mint,
            amount: utxo.amount,
        }
    }
}

impl From<&AuditedMergeOutput> for MergeInput {
    fn from(output: &AuditedMergeOutput) -> Self {
        Self {
            owner_key: output.owner_key,
            owner: output.owner,
            asset: output.asset,
            mint: output.mint,
            amount: output.amount,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeTransition {
    /// The inputs a first application marked spent, empty on a repeat.
    pub spent: Vec<[u8; 32]>,
    /// Every merge output that resolved, descendants included.
    pub resolved: Vec<AuditedMergeOutput>,
}

/// Keeps one state per ring, a later opening moves it only forward.
#[derive(Clone, Debug, Default)]
pub struct MergeLedger {
    applied: HashSet<MergeId>,
    outputs: HashMap<[u8; 32], AuditedMergeOutput>,
    /// Oldest first, a descendant follows the merge it spends.
    unresolved: BTreeMap<(u64, Signature, u16), ConfirmedMerge>,
}

impl MergeLedger {
    /// `known` reads the auditor's openings, a repeated merge changes nothing.
    pub fn apply(
        &mut self,
        merge: ConfirmedMerge,
        known: impl Fn(&[u8; 32]) -> Option<MergeInput>,
    ) -> MergeTransition {
        if !self.applied.insert((merge.tx_signature, merge.event_index)) {
            return MergeTransition::default();
        }
        let spent = merge.inputs().to_vec();
        self.unresolved
            .insert((merge.slot, merge.tx_signature, merge.event_index), merge);
        MergeTransition {
            spent,
            resolved: self.resolve(known),
        }
    }

    /// Runs after every new opening, a resolved output can complete its descendant.
    pub fn resolve(
        &mut self,
        known: impl Fn(&[u8; 32]) -> Option<MergeInput>,
    ) -> Vec<AuditedMergeOutput> {
        let mut resolved = Vec::new();
        loop {
            let outputs = &self.outputs;
            let opened: Vec<_> = self
                .unresolved
                .iter()
                .filter_map(|(key, merge)| {
                    let output = merge.resolved(|commitment| {
                        known(commitment).or_else(|| outputs.get(commitment).map(MergeInput::from))
                    })?;
                    Some((*key, output))
                })
                .collect();
            if opened.is_empty() {
                return resolved;
            }
            for (key, output) in opened {
                self.unresolved.remove(&key);
                self.outputs.insert(output.commitment, output.clone());
                resolved.push(output);
            }
        }
    }

    pub fn output(&self, commitment: &[u8; 32]) -> Option<&AuditedMergeOutput> {
        self.outputs.get(commitment)
    }

    pub fn outputs(&self) -> impl Iterator<Item = &AuditedMergeOutput> {
        self.outputs.values()
    }

    pub fn unresolved(&self) -> impl Iterator<Item = &ConfirmedMerge> {
        self.unresolved.values()
    }

    pub fn name_assets(&mut self, assets: &RingAssets) {
        for output in self.outputs.values_mut() {
            output.mint = output
                .mint
                .or_else(|| assets.by_field(&output.asset).map(|mint| mint.asset));
        }
    }
}

impl AuditedMergeOutput {
    pub fn opening(
        &self,
        ring: Address,
        nullifier_key: &NullifierKey,
    ) -> Result<Option<KnownUtxo>, AuditError> {
        if self
            .mint
            .map(|mint| spr_hasher::primitives::hash_bytes(mint.as_array()))
            .transpose()?
            .is_some_and(|asset| asset != self.asset)
        {
            return Ok(None);
        }
        let inherited = KnownUtxo {
            owner_key: self.owner_key,
            owner: self.owner,
            asset: self.asset,
            mint: self.mint,
            amount: self.amount,
            blinding: match self.seed {
                Some(seed) => {
                    MergeSeed::from_bytes(seed)?.output_blinding(&self.first_nullifier)?
                }
                None => merge_output_blinding(nullifier_key, &self.first_nullifier)?,
            },
            data_hash: [0; 32],
            ring_data_hash: self.ring_data_hash,
            tree_id: self.tree_id,
        };
        let opening = KnownUtxo {
            owner: UtxoOwner::Keyed {
                nullifier_pk: nullifier_key.pubkey()?,
            },
            ..inherited
        };
        Ok((opening.owner_hash()? == inherited.owner_hash()?
            && opening.commitment(Some(ring))? == self.commitment)
            .then_some(opening))
    }
}

impl ConfirmedMerge {
    /// Leaves out every dummy of the decrypted list, published or not.
    pub fn real_inputs(list: &[[u8; 32]]) -> Vec<[u8; 32]> {
        list.iter()
            .filter(|entry| **entry != [0; 32])
            .copied()
            .collect()
    }

    /// Empty on a record.
    pub fn inputs(&self) -> &[[u8; 32]] {
        match &self.disclosed {
            MergeDisclosed::Inputs(inputs) => inputs,
            MergeDisclosed::Record(_) => &[],
        }
    }

    /// `None` while an input is unknown, on inputs of two owners or assets and on an overflow.
    fn resolved(
        &self,
        input: impl Fn(&[u8; 32]) -> Option<MergeInput>,
    ) -> Option<AuditedMergeOutput> {
        let inputs = match &self.disclosed {
            MergeDisclosed::Inputs(inputs) => inputs,
            MergeDisclosed::Record(record) => {
                return Some(self.output(MergedFields {
                    owner_key: record.owner_key,
                    owner: UtxoOwner::Keyed {
                        nullifier_pk: record.nullifier_pk,
                    },
                    asset: hash_bytes(record.mint.as_array()).ok()?,
                    mint: Some(record.mint),
                    amount: record.amount,
                    inputs: Vec::new(),
                    real_nullifiers: record.real_nullifiers.clone(),
                    seed: Some(record.seed),
                }));
            }
        };
        let list = inputs;
        let inputs = list.iter().map(&input).collect::<Option<Vec<_>>>()?;
        let first = inputs.first()?;
        let owner_hash = first.owner.hash(&first.owner_key).ok()?;
        let same_note_kind = inputs.iter().all(|input| {
            input.owner_key == first.owner_key
                && input.owner.hash(&input.owner_key).ok() == Some(owner_hash)
                && input.asset == first.asset
        });
        let owner = inputs
            .iter()
            .find(|input| matches!(input.owner, UtxoOwner::Keyed { .. }))
            .unwrap_or(first)
            .owner;
        let amount = inputs
            .iter()
            .try_fold(0u64, |sum, input| sum.checked_add(input.amount))?;
        same_note_kind.then(|| {
            self.output(MergedFields {
                owner_key: first.owner_key,
                owner,
                asset: first.asset,
                mint: inputs.iter().find_map(|input| input.mint),
                amount,
                inputs: list.clone(),
                real_nullifiers: Vec::new(),
                seed: None,
            })
        })
    }

    fn output(&self, fields: MergedFields) -> AuditedMergeOutput {
        let MergedFields {
            owner_key,
            owner,
            asset,
            mint,
            amount,
            inputs,
            real_nullifiers,
            seed,
        } = fields;
        AuditedMergeOutput {
            commitment: self.output_commitment,
            slot: self.slot,
            tx_signature: self.tx_signature,
            event_index: self.event_index,
            tree_id: self.tree_id,
            leaf_index: self.leaf_index,
            first_nullifier: self.first_nullifier,
            ring_data_hash: self.ring_data_hash,
            owner_key,
            owner,
            asset,
            mint,
            amount,
            inputs,
            real_nullifiers,
            seed,
        }
    }
}

struct MergedFields {
    owner_key: [u8; 32],
    owner: UtxoOwner,
    asset: [u8; 32],
    mint: Option<Address>,
    amount: u64,
    inputs: Vec<[u8; 32]>,
    real_nullifiers: Vec<[u8; 32]>,
    seed: Option<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASSET: [u8; 32] = [7; 32];

    fn note(amount: u64) -> MergeInput {
        MergeInput {
            owner_key: [1; 32],
            owner: UtxoOwner::Keyed {
                nullifier_pk: [2; 32],
            },
            asset: ASSET,
            mint: Some(Address::new_from_array([3; 32])),
            amount,
        }
    }

    fn merge(id: u8, inputs: &[[u8; 32]], output: [u8; 32]) -> ConfirmedMerge {
        ConfirmedMerge {
            slot: u64::from(id),
            tx_signature: Signature::from([id; 64]),
            event_index: 0,
            output_commitment: output,
            tree_id: 1,
            leaf_index: u64::from(id),
            first_nullifier: [id; 32],
            ring_data_hash: [0; 32],
            disclosed: MergeDisclosed::Inputs(inputs.to_vec()),
        }
    }

    #[test]
    fn a_merge_of_known_inputs_records_the_sum_under_the_inherited_owner() {
        let mut ledger = MergeLedger::default();
        let transition = ledger.apply(merge(1, &[[10; 32], [11; 32]], [20; 32]), |commitment| {
            Some(note(u64::from(commitment[0])))
        });
        assert_eq!(transition.spent, [[10; 32], [11; 32]]);
        let output = ledger.output(&[20; 32]).expect("resolved");
        assert_eq!(output.amount, 21);
        assert_eq!(output.owner_key, note(0).owner_key);
        assert_eq!(output.asset, ASSET);
    }

    #[test]
    fn a_record_merge_resolves_alone_and_spends_no_named_input() {
        let mint = Address::new_from_array([3; 32]);
        let record = MergeRecordOutput {
            owner_key: [1; 32],
            nullifier_pk: [2; 32],
            mint,
            amount: 9,
            seed: [0; 32],
            real_nullifiers: vec![[8; 32]],
        };
        let mut ledger = MergeLedger::default();
        let transition = ledger.apply(
            ConfirmedMerge {
                disclosed: MergeDisclosed::Record(record),
                ..merge(1, &[], [20; 32])
            },
            |_| None,
        );
        assert!(transition.spent.is_empty());
        let output = ledger.output(&[20; 32]).expect("resolved");
        assert_eq!((output.amount, output.mint), (9, Some(mint)));
        assert_eq!(output.asset, hash_bytes(mint.as_array()).unwrap());
        assert_eq!(output.real_nullifiers, [[8; 32]]);
    }

    #[test]
    fn a_repeated_merge_applies_once() {
        let mut ledger = MergeLedger::default();
        let known = |_: &[u8; 32]| Some(note(5));
        let first = merge(1, &[[10; 32]], [20; 32]);
        assert_eq!(ledger.apply(first.clone(), known).spent, [[10; 32]]);
        assert_eq!(ledger.apply(first, known), MergeTransition::default());
    }

    #[test]
    fn equal_deposited_and_keyed_owners_resolve_in_both_orders_and_through_descendants() {
        let keyed = note(5);
        let deposited = MergeInput {
            owner: UtxoOwner::Deposited {
                owner_hash: keyed.owner.hash(&keyed.owner_key).unwrap(),
            },
            ..keyed
        };
        for inputs in [[[10; 32], [11; 32]], [[11; 32], [10; 32]]] {
            let mut ledger = MergeLedger::default();
            ledger.apply(merge(2, &[[20; 32], [12; 32]], [30; 32]), |_| None);
            ledger.apply(merge(1, &inputs, [20; 32]), |_| None);
            let resolved = ledger.resolve(|commitment| match commitment[0] {
                10 => Some(deposited),
                11 => Some(keyed),
                12 => Some(note(7)),
                _ => None,
            });
            assert_eq!(resolved.len(), 2);
            let parent = ledger.output(&[20; 32]).unwrap();
            assert_eq!(parent.owner, keyed.owner);
            assert_eq!(parent.amount, 10);
            let descendant = ledger.output(&[30; 32]).unwrap();
            assert_eq!(descendant.owner, keyed.owner);
            assert_eq!(descendant.amount, 17);
            assert_eq!(ledger.unresolved().count(), 0);
        }
    }

    #[test]
    fn deposited_and_keyed_owners_with_different_hashes_never_resolve() {
        let keyed = note(5);
        let deposited = MergeInput {
            owner: UtxoOwner::Deposited {
                owner_hash: UtxoOwner::Keyed {
                    nullifier_pk: [3; 32],
                }
                .hash(&keyed.owner_key)
                .unwrap(),
            },
            ..keyed
        };
        let mut ledger = MergeLedger::default();
        let transition = ledger.apply(merge(1, &[[10; 32], [11; 32]], [20; 32]), |commitment| {
            Some(if commitment[0] == 10 {
                deposited
            } else {
                keyed
            })
        });
        assert!(transition.resolved.is_empty());
        assert_eq!(ledger.unresolved().count(), 1);
    }

    #[test]
    fn a_noncanonical_nullifier_key_stays_unresolved_until_a_valid_opening() {
        let invalid = MergeInput {
            owner: UtxoOwner::Keyed {
                nullifier_pk: spr_hasher::primitives::BN254_SCALAR_MODULUS_BE,
            },
            ..note(5)
        };
        let mut ledger = MergeLedger::default();
        let transition = ledger.apply(merge(1, &[[10; 32]], [20; 32]), |_| Some(invalid));
        assert!(transition.resolved.is_empty());
        assert!(ledger.outputs().next().is_none());
        assert_eq!(ledger.unresolved().count(), 1);
        let resolved = ledger.resolve(|_| Some(note(5)));
        assert_eq!(resolved.len(), 1);
        assert_eq!(ledger.unresolved().count(), 0);
    }

    #[test]
    fn an_unknown_input_holds_the_merge_and_its_descendants_until_it_opens() {
        let mut ledger = MergeLedger::default();
        let nothing = |_: &[u8; 32]| None;
        // The descendant lands first, a page can read it before its parent.
        ledger.apply(merge(2, &[[20; 32], [12; 32]], [30; 32]), nothing);
        let parent = ledger.apply(merge(1, &[[10; 32]], [20; 32]), nothing);
        assert_eq!(parent.spent, [[10; 32]], "an unknown input is still spent");
        assert!(parent.resolved.is_empty());
        assert_eq!(ledger.unresolved().count(), 2);

        let only_ten = |commitment: &[u8; 32]| (*commitment == [10; 32]).then(|| note(5));
        assert!(ledger.resolve(only_ten).len() == 1, "the parent alone");
        assert_eq!(ledger.unresolved().count(), 1);

        let resolved = ledger.resolve(|commitment| match commitment[0] {
            10 => Some(note(5)),
            12 => Some(note(6)),
            _ => None,
        });
        assert_eq!(resolved.len(), 1);
        assert_eq!(ledger.output(&[30; 32]).expect("descendant").amount, 11);
        assert_eq!(ledger.unresolved().count(), 0);
    }

    #[test]
    fn a_fixed_point_runs_through_a_chain_in_one_pass() {
        let mut ledger = MergeLedger::default();
        let nothing = |_: &[u8; 32]| None;
        ledger.apply(merge(1, &[[10; 32]], [20; 32]), nothing);
        ledger.apply(merge(2, &[[20; 32]], [30; 32]), nothing);
        ledger.apply(merge(3, &[[30; 32]], [40; 32]), nothing);
        let resolved = ledger.resolve(|commitment| (*commitment == [10; 32]).then(|| note(9)));
        assert_eq!(resolved.len(), 3);
        assert_eq!(ledger.output(&[40; 32]).expect("last").amount, 9);
    }

    #[test]
    fn a_zero_list_entry_is_a_dummy_and_never_a_spent_input() {
        let list = [[10; 32], [0; 32], [11; 32], [0; 32]];
        let inputs = ConfirmedMerge::real_inputs(&list);
        assert_eq!(inputs, [[10; 32], [11; 32]]);
        let mut ledger = MergeLedger::default();
        let transition = ledger.apply(merge(1, &inputs, [20; 32]), |_| Some(note(4)));
        assert_eq!(transition.spent, inputs);
        assert_eq!(ledger.output(&[20; 32]).expect("resolved").amount, 8);
    }

    #[test]
    fn inputs_of_two_owners_or_an_overflow_never_resolve() {
        let mut ledger = MergeLedger::default();
        ledger.apply(merge(1, &[[10; 32], [11; 32]], [20; 32]), |commitment| {
            Some(MergeInput {
                owner_key: [commitment[0]; 32],
                ..note(1)
            })
        });
        assert_eq!(ledger.unresolved().count(), 1);
        ledger.apply(merge(2, &[[12; 32], [13; 32]], [21; 32]), |_| {
            Some(note(u64::MAX))
        });
        assert_eq!(ledger.unresolved().count(), 2);
    }
}
