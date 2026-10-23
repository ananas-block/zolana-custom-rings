use std::ops::Range;

use solana_address::Address;
use solana_signature::Signature;
use thiserror::Error;
use zolana_event::{tag, GeneralEvent};
use zolana_event_parser::{
    event_parent, reconstruct_general_event_from_payload, EventDecodeError, InstructionGroup,
    ParsedInstruction,
};
use zolana_indexer_api::{
    Base64String, Hash, RingsMessage, RingsOutputContext, RingsOutputSlot, ShieldedTransaction,
};

use crate::block::{Instruction, TransactionInfo};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SppEvent {
    pub signature: Signature,
    /// Position among the shielded-pool events of the whole transaction.
    pub event_index: u16,
    pub slot: u64,
    pub source_instruction_tag: u8,
    pub ring_config: Option<Address>,
    pub general: GeneralEvent,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EventError {
    #[error("instruction of program {0} has no stack height")]
    MissingStackHeight(Address),
    #[error("shielded-pool event parent has no instruction tag")]
    MissingSourceTag,
    #[error("shielded-pool event {index} does not rebuild ({error:?})")]
    Reconstruct {
        index: usize,
        error: EventDecodeError,
    },
    #[error("shielded-pool event index overflows")]
    IndexOverflow,
}

pub struct ParsedTransaction {
    groups: Vec<InstructionGroup>,
}

/// The inner instructions `span` of group `group` descend from one invocation.
pub struct Subtree {
    pub group: usize,
    pub span: Range<usize>,
}

impl ParsedTransaction {
    pub fn new(transaction: &TransactionInfo) -> Result<Self, EventError> {
        let parsed = |instruction: &Instruction| {
            Ok(ParsedInstruction::new(
                instruction.program_id,
                instruction.accounts.clone(),
                instruction.data.clone(),
                instruction
                    .stack_height
                    .ok_or(EventError::MissingStackHeight(instruction.program_id))?,
            ))
        };
        Ok(Self {
            groups: transaction
                .instruction_groups
                .iter()
                .map(|group| {
                    Ok(InstructionGroup {
                        outer: parsed(&group.outer_instruction)?,
                        inner: group
                            .inner_instructions
                            .iter()
                            .map(parsed)
                            .collect::<Result<_, EventError>>()?,
                    })
                })
                .collect::<Result<_, EventError>>()?,
        })
    }

    /// An event counts only under a state transitioning shielded-pool parent.
    pub fn events(
        &self,
        subtree: &Subtree,
        signature: Signature,
        slot: u64,
    ) -> Result<Vec<SppEvent>, EventError> {
        let pool = zolana_interface::pda::shielded_pool_program_id();
        let mut events = Vec::new();
        let mut index = 0usize;
        for (group_index, group) in self.groups.iter().enumerate() {
            for (position, instruction) in group.inner.iter().enumerate() {
                if instruction.program_id != pool
                    || instruction.data.first() != Some(&tag::EMIT_EVENT)
                {
                    continue;
                }
                let Some(parent) = event_parent(group, position) else {
                    continue;
                };
                if parent.program_id != pool {
                    continue;
                }
                let source_instruction_tag =
                    *parent.data.first().ok_or(EventError::MissingSourceTag)?;
                if !is_general_event_source(source_instruction_tag) {
                    continue;
                }
                if group_index == subtree.group && subtree.span.contains(&position) {
                    let general = reconstruct_general_event_from_payload(
                        parent,
                        instruction.data.get(1..).unwrap_or_default(),
                    )
                    .map_err(|error| EventError::Reconstruct { index, error })?;
                    events.push(SppEvent {
                        signature,
                        event_index: u16::try_from(index).map_err(|_| EventError::IndexOverflow)?,
                        slot,
                        source_instruction_tag,
                        ring_config: ring_config_position(source_instruction_tag)
                            .and_then(|account| parent.accounts.get(account).copied()),
                        general,
                    });
                }
                index = index.checked_add(1).ok_or(EventError::IndexOverflow)?;
            }
        }
        Ok(events)
    }
}

impl SppEvent {
    pub fn nullifiers(&self) -> Vec<[u8; 32]> {
        self.general
            .inputs
            .iter()
            .map(|input| input.nullifier)
            .collect()
    }

    pub fn output_tree(&self) -> Address {
        Address::new_from_array(self.general.output_tree)
    }

    /// `output_tree_id` is the id the output tree account stores.
    pub fn transaction(
        &self,
        ring_program_id: Address,
        output_tree_id: u16,
    ) -> Result<ShieldedTransaction, EventError> {
        let general = &self.general;
        let nonzero = |bytes: &[u8]| {
            bytes
                .iter()
                .any(|byte| *byte != 0)
                .then(|| Base64String(bytes.to_vec()))
        };
        Ok(ShieldedTransaction {
            slot: self.slot,
            tx_signature: self.signature.into(),
            event_index: Some(self.event_index),
            tx_viewing_pk: nonzero(&general.tx_viewing_pk),
            salt: nonzero(&general.salt),
            output_slots: general
                .outputs
                .iter()
                .zip(0u64..)
                .map(|(output, position)| {
                    Ok(RingsOutputSlot {
                        view_tag: Hash(output.view_tag),
                        output_context: RingsOutputContext {
                            hash: Hash(output.utxo_hash),
                            tree: self.output_tree().into(),
                            tree_id: output_tree_id,
                            leaf_index: general
                                .first_output_leaf_index
                                .checked_add(position)
                                .ok_or(EventError::IndexOverflow)?,
                        },
                        payload: Base64String(output.data.clone()),
                    })
                })
                .collect::<Result<_, EventError>>()?,
            messages: general
                .messages
                .iter()
                .map(|message| RingsMessage {
                    view_tag: Hash(message.view_tag),
                    payload: Base64String(message.data.clone()),
                })
                .collect(),
            nullifiers: self.nullifiers().into_iter().map(Hash).collect(),
            proofless: matches!(
                self.source_instruction_tag,
                tag::DEPOSIT | tag::RING_DEPOSIT
            ),
            ring_config: self.ring_config.map(Into::into),
            ring_program_id: Some(ring_program_id.into()),
        })
    }
}

fn is_general_event_source(source_instruction_tag: u8) -> bool {
    matches!(
        source_instruction_tag,
        tag::TRANSACT
            | tag::RING_TRANSACT
            | tag::RING_AUTHORITY_TRANSACT
            | tag::MERGE_TRANSACT
            | tag::RING_MERGE_TRANSACT
            | tag::DEPOSIT
            | tag::RING_DEPOSIT
    )
}

/// Must match the account the pool reads the ring identity from.
fn ring_config_position(source_instruction_tag: u8) -> Option<usize> {
    match source_instruction_tag {
        tag::RING_TRANSACT | tag::RING_AUTHORITY_TRANSACT => Some(4),
        tag::RING_DEPOSIT | tag::RING_MERGE_TRANSACT => Some(2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::InstructionGroup as BlockGroup;

    fn pool() -> Address {
        zolana_interface::pda::shielded_pool_program_id()
    }

    fn ix(program_id: Address, data: Vec<u8>, accounts: Vec<Address>, depth: u32) -> Instruction {
        Instruction {
            program_id,
            data,
            accounts,
            stack_height: Some(depth),
        }
    }

    fn numbered(count: u8) -> Vec<Address> {
        (0..count)
            .map(|i| Address::new_from_array([i; 32]))
            .collect()
    }

    fn transaction(groups: Vec<BlockGroup>) -> TransactionInfo {
        TransactionInfo {
            instruction_groups: groups,
            signature: Signature::from([1; 64]),
            error: None,
        }
    }

    /// A malformed payload under a genuine parent surfaces its global index.
    fn rebuild_index(transaction: &TransactionInfo, subtree: Subtree) -> Option<usize> {
        match ParsedTransaction::new(transaction).unwrap().events(
            &subtree,
            transaction.signature,
            1,
        ) {
            Err(EventError::Reconstruct { index, .. }) => Some(index),
            Ok(events) => {
                assert!(events.is_empty());
                None
            }
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn events_keep_their_index_across_the_transaction() {
        let emit = || ix(pool(), vec![tag::EMIT_EVENT, 0], vec![], 3);
        let ring = Address::new_from_array([9; 32]);
        let transaction = transaction(vec![
            BlockGroup {
                outer_instruction: ix(ring, vec![0], vec![], 1),
                inner_instructions: vec![ix(pool(), vec![tag::TRANSACT], numbered(8), 2), emit()],
            },
            BlockGroup {
                outer_instruction: ix(ring, vec![0], vec![], 1),
                inner_instructions: vec![
                    ix(pool(), vec![tag::RING_TRANSACT], numbered(8), 2),
                    emit(),
                ],
            },
        ]);
        assert_eq!(
            rebuild_index(
                &transaction,
                Subtree {
                    group: 1,
                    span: 0..2
                }
            ),
            Some(1)
        );
        assert_eq!(
            rebuild_index(
                &transaction,
                Subtree {
                    group: 0,
                    span: 0..2
                }
            ),
            Some(0)
        );
    }

    #[test]
    fn forged_events_never_count() {
        let foreign = Address::new_from_array([9; 32]);
        let transaction = transaction(vec![BlockGroup {
            outer_instruction: ix(foreign, vec![0], vec![], 1),
            inner_instructions: vec![
                ix(foreign, vec![tag::TRANSACT], vec![], 2),
                ix(pool(), vec![tag::EMIT_EVENT, 0], vec![], 3),
                ix(pool(), vec![tag::EMIT_EVENT, 0], vec![], 2),
            ],
        }]);
        assert_eq!(
            rebuild_index(
                &transaction,
                Subtree {
                    group: 0,
                    span: 0..3
                }
            ),
            None
        );
    }

    #[test]
    fn ring_config_comes_from_each_instruction_own_position() {
        for (source_tag, position) in [
            (tag::RING_TRANSACT, Some(4u8)),
            (tag::RING_AUTHORITY_TRANSACT, Some(4)),
            (tag::RING_DEPOSIT, Some(2)),
            (tag::RING_MERGE_TRANSACT, Some(2)),
            (tag::TRANSACT, None),
            (tag::DEPOSIT, None),
        ] {
            assert_eq!(
                ring_config_position(source_tag)
                    .and_then(|account| numbered(8).get(account).copied()),
                position.map(|index| Address::new_from_array([index; 32])),
                "tag {source_tag}"
            );
        }
        assert_eq!(
            ring_config_position(tag::RING_TRANSACT)
                .and_then(|account| numbered(4).get(account).copied()),
            None
        );
    }

    #[test]
    fn an_instruction_without_stack_height_is_refused() {
        let mut instruction = ix(pool(), vec![tag::TRANSACT], vec![], 1);
        instruction.stack_height = None;
        assert!(matches!(
            ParsedTransaction::new(&transaction(vec![BlockGroup {
                outer_instruction: instruction,
                inner_instructions: vec![],
            }])),
            Err(EventError::MissingStackHeight(_))
        ));
    }
}
