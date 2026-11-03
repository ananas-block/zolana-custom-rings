//! The auditor's merge transitions, applied once per confirmed merge and resolved to a fixed point.

use std::collections::{BTreeMap, HashMap, HashSet};

use solana_address::Address;
use solana_signature::Signature;

use crate::types::{KnownUtxo, UtxoOwner};

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
    /// The real inputs, a zero entry of the disclosed list is a dummy.
    pub inputs: Vec<[u8; 32]>,
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
    pub owner_key: [u8; 32],
    pub owner: UtxoOwner,
    pub asset: [u8; 32],
    pub mint: Option<Address>,
    /// The sum of its inputs.
    pub amount: u64,
    pub inputs: Vec<[u8; 32]>,
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
        let spent = merge.inputs.clone();
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
}

impl ConfirmedMerge {
    /// Leaves out every dummy of the decrypted list, published or not.
    pub fn real_inputs(list: &[[u8; 32]]) -> Vec<[u8; 32]> {
        list.iter()
            .filter(|entry| **entry != [0; 32])
            .copied()
            .collect()
    }

    /// `None` while an input is unknown, on inputs of two owners or assets and on an overflow.
    fn resolved(
        &self,
        input: impl Fn(&[u8; 32]) -> Option<MergeInput>,
    ) -> Option<AuditedMergeOutput> {
        let inputs = self.inputs.iter().map(&input).collect::<Option<Vec<_>>>()?;
        let first = inputs.first()?;
        let same_note_kind = inputs.iter().all(|input| {
            input.owner_key == first.owner_key
                && input.owner == first.owner
                && input.asset == first.asset
        });
        let amount = inputs
            .iter()
            .try_fold(0u64, |sum, input| sum.checked_add(input.amount))?;
        same_note_kind.then(|| AuditedMergeOutput {
            commitment: self.output_commitment,
            slot: self.slot,
            tx_signature: self.tx_signature,
            event_index: self.event_index,
            tree_id: self.tree_id,
            leaf_index: self.leaf_index,
            owner_key: first.owner_key,
            owner: first.owner,
            asset: first.asset,
            mint: inputs.iter().find_map(|input| input.mint),
            amount,
            inputs: self.inputs.clone(),
        })
    }
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
            inputs: inputs.to_vec(),
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
    fn a_repeated_merge_applies_once() {
        let mut ledger = MergeLedger::default();
        let known = |_: &[u8; 32]| Some(note(5));
        let first = merge(1, &[[10; 32]], [20; 32]);
        assert_eq!(ledger.apply(first.clone(), known).spent, [[10; 32]]);
        assert_eq!(ledger.apply(first, known), MergeTransition::default());
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
