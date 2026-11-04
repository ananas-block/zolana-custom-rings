//! The address ceiling of one compiled transaction, merging first takes several transactions and loses atomicity, so only a caller chooses it.

use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::v1;
use spr_client::{transaction_size, ClientError, ComputeBudgetConfig, TransactionSize};
use spr_interface::{pda, ZERO_NULLIFIER_PUBKEY};
use spr_keypair::PublicKey;
use spr_transaction::utxo::SppProofInputUtxo;
use thiserror::Error;

#[cfg(test)]
#[path = "../tests/validation/address_ceiling.rs"]
mod tests;

/// One real input of the transaction, as SPP merge groups it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpentInput {
    pub owner: PublicKey,
    pub asset: Address,
    pub nullifier_pubkey: [u8; 32],
    pub data_hash: Option<[u8; 32]>,
    pub ring_program_id: Option<Address>,
    pub tree_id: u16,
    pub nullifier_pda: Address,
}

impl SpentInput {
    /// `tree` holds the input.
    pub fn of(input: &SppProofInputUtxo, tree: &Address) -> Self {
        Self {
            owner: input.utxo.owner,
            asset: input.utxo.asset.asset,
            nullifier_pubkey: input.nullifier_pubkey,
            data_hash: input.data_hash,
            ring_program_id: input.utxo.ring_program_id,
            tree_id: input.tree_id,
            nullifier_pda: pda::nullifier_pda(tree, &input.nullifier()).0,
        }
    }

    /// SPP merge refuses a note with a data hash.
    fn carries_data(&self) -> bool {
        self.data_hash.is_some_and(|hash| hash != [0; 32])
    }

    fn merges_with(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.asset == other.asset
            && self.nullifier_pubkey == other.nullifier_pubkey
            && self.ring_program_id == other.ring_program_id
            && self.tree_id == other.tree_id
    }
}

#[must_use]
pub struct AddressCeiling<'a> {
    pub payer: Address,
    pub instruction: &'a Instruction,
    pub budget: ComputeBudgetConfig,
    pub inputs: &'a [SpentInput],
    pub merge_capacity: MergeCapacity,
}

/// [`crate::FittedMerge`]'s published inputs per kind of merge, a zero-key merge adds its signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeCapacity {
    pub keyed: usize,
    pub zero_key: usize,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CeilingDecision {
    UnderCeiling(TransactionSize),
    MergeFirst {
        /// The fewest merges that bring the compiled count under the ceiling.
        groups: Vec<MergeGroup>,
        /// With one nullifier PDA left per merged note.
        addresses: usize,
    },
}

/// One executable merge, one transaction carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeGroup {
    pub owner: PublicKey,
    pub asset: Address,
    pub nullifier_pubkey: [u8; 32],
    pub ring_program_id: Option<Address>,
    pub tree_id: u16,
    /// Positions in [`AddressCeiling::inputs`].
    pub inputs: Vec<usize>,
}

#[derive(Debug, Error)]
pub enum AddressCeilingError {
    #[error("{compiled} addresses pass the limit of {limit}, merging every valid group reaches {after_merging} and {data_notes} data notes cannot merge")]
    Unsupported {
        compiled: usize,
        limit: usize,
        after_merging: usize,
        data_notes: usize,
    },
    #[error(transparent)]
    Compile(#[from] ClientError),
}

impl AddressCeiling<'_> {
    pub fn decide(self) -> Result<CeilingDecision, AddressCeilingError> {
        let limit = usize::from(v1::MAX_ADDRESSES);
        let compiled = self.compiled(&[])?;
        if compiled.addresses <= limit {
            return Ok(CeilingDecision::UnderCeiling(compiled));
        }
        let mut merged_away = Vec::new();
        let mut chosen = Vec::new();
        let mut after_merging = compiled.addresses;
        for group in self.groups() {
            // The merged note's own nullifier PDA replaces one of the group's.
            merged_away.extend(
                group.inputs[1..]
                    .iter()
                    .map(|position| self.inputs[*position].nullifier_pda),
            );
            chosen.push(group);
            after_merging = self.compiled(&merged_away)?.addresses;
            if after_merging <= limit {
                return Ok(CeilingDecision::MergeFirst {
                    groups: chosen,
                    addresses: after_merging,
                });
            }
        }
        Err(AddressCeilingError::Unsupported {
            compiled: compiled.addresses,
            limit,
            after_merging,
            data_notes: self
                .inputs
                .iter()
                .filter(|input| input.carries_data())
                .count(),
        })
    }

    fn compiled(&self, merged_away: &[Address]) -> Result<TransactionSize, ClientError> {
        let mut instruction = self.instruction.clone();
        instruction
            .accounts
            .retain(|account| !merged_away.contains(&account.pubkey));
        transaction_size(
            &self.payer,
            core::slice::from_ref(&instruction),
            self.budget,
        )
    }

    /// Widest first, a run of one consolidates nothing.
    fn groups(&self) -> Vec<MergeGroup> {
        let mut groups: Vec<MergeGroup> = Vec::new();
        for (position, input) in self.inputs.iter().enumerate() {
            if input.carries_data() {
                continue;
            }
            let held = groups
                .iter_mut()
                .find(|group| input.merges_with(&self.inputs[group.inputs[0]]));
            match held {
                Some(group) => group.inputs.push(position),
                None => groups.push(MergeGroup {
                    owner: input.owner,
                    asset: input.asset,
                    nullifier_pubkey: input.nullifier_pubkey,
                    ring_program_id: input.ring_program_id,
                    tree_id: input.tree_id,
                    inputs: vec![position],
                }),
            }
        }
        let mut merges: Vec<MergeGroup> = groups
            .iter()
            .flat_map(|group| {
                group
                    .inputs
                    .chunks(self.capacity_of(group).max(1))
                    .filter(|run| run.len() > 1)
                    .map(|run| MergeGroup {
                        inputs: run.to_vec(),
                        ..group.clone()
                    })
            })
            .collect();
        merges.sort_by_key(|merge| core::cmp::Reverse(merge.inputs.len()));
        merges
    }

    fn capacity_of(&self, group: &MergeGroup) -> usize {
        match group.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY {
            true => self.merge_capacity.zero_key,
            false => self.merge_capacity.keyed,
        }
    }
}
