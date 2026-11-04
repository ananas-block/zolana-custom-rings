use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1;
use spr_client::ComputeBudgetConfig;
use spr_transaction::Mint;

use super::*;
use crate::tests::support::keypair;

const LIMIT: usize = v1::MAX_ADDRESSES as usize;

fn address(seed: u32) -> Address {
    let mut bytes = [0xaa; 32];
    bytes[..4].copy_from_slice(&seed.to_be_bytes());
    Address::new_from_array(bytes)
}

fn note(owner: u8, seed: u32) -> SpentInput {
    SpentInput {
        owner: keypair(owner).signing_pubkey(),
        asset: Mint::SOL.asset,
        nullifier_pubkey: [owner; 32],
        data_hash: None,
        ring_program_id: Some(address(0)),
        tree_id: 1,
        nullifier_pda: address(1000 + seed),
    }
}

/// Payer, program, one nullifier PDA per input and `other` accounts.
fn decide(inputs: &[SpentInput], other: u32) -> Result<CeilingDecision, AddressCeilingError> {
    let accounts = inputs
        .iter()
        .map(|input| input.nullifier_pda)
        .chain((0..other).map(|seed| address(5000 + seed)))
        .map(|account| AccountMeta::new(account, false))
        .collect();
    AddressCeiling {
        payer: address(1),
        instruction: &Instruction {
            program_id: address(2),
            accounts,
            data: Vec::new(),
        },
        budget: ComputeBudgetConfig::new(1_000_000),
        inputs,
    }
    .decide()
}

#[test]
fn a_transaction_at_the_ceiling_stays_one_transaction() {
    let inputs: Vec<_> = (0..10).map(|seed| note(1, seed)).collect();
    let other = LIMIT as u32 - 2 - 10;
    let Ok(CeilingDecision::UnderCeiling(size)) = decide(&inputs, other) else {
        panic!("under the ceiling");
    };
    assert_eq!(size.addresses, LIMIT);
}

/// The compiled count passes by two, the wider group alone reaches the ceiling.
#[test]
fn merging_first_names_only_the_groups_the_ceiling_needs() {
    let inputs: Vec<_> = (0..4)
        .map(|seed| note(1, seed))
        .chain((4..6).map(|seed| note(2, seed)))
        .collect();
    let other = LIMIT as u32 - 2 - 6 + 2;
    let Ok(CeilingDecision::MergeFirst(groups)) = decide(&inputs, other) else {
        panic!("merge first");
    };
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].inputs, [0, 1, 2, 3]);
    assert_eq!(groups[0].owner, inputs[0].owner);
}

#[test]
fn mixed_owners_form_no_group_and_report_the_compiled_count() {
    let inputs: Vec<_> = (0..4).map(|seed| note(seed as u8 + 1, seed)).collect();
    let other = LIMIT as u32 - 2 - 4 + 1;
    let Err(AddressCeilingError::Unsupported {
        compiled,
        limit,
        after_merging,
        data_notes,
    }) = decide(&inputs, other)
    else {
        panic!("unsupported");
    };
    assert_eq!((compiled, limit), (LIMIT + 1, LIMIT));
    assert_eq!((after_merging, data_notes), (LIMIT + 1, 0));
}

#[test]
fn a_data_note_stays_out_of_every_group() {
    let inputs: Vec<_> = (0..4)
        .map(|seed| SpentInput {
            data_hash: Some([9; 32]),
            ..note(1, seed)
        })
        .collect();
    let other = LIMIT as u32 - 2 - 4 + 1;
    let Err(AddressCeilingError::Unsupported {
        after_merging,
        data_notes,
        ..
    }) = decide(&inputs, other)
    else {
        panic!("unsupported");
    };
    assert_eq!((after_merging, data_notes), (LIMIT + 1, 4));
}

#[test]
fn notes_of_another_asset_or_key_or_tree_do_not_merge() {
    let first = note(1, 0);
    let unlike = [
        SpentInput {
            asset: address(7),
            ..note(1, 1)
        },
        SpentInput {
            nullifier_pubkey: [9; 32],
            ..note(1, 2)
        },
        SpentInput {
            tree_id: 2,
            ..note(1, 3)
        },
    ];
    let inputs = [&[first][..], &unlike].concat();
    let other = LIMIT as u32 - 2 - 4 + 1;
    assert!(matches!(
        decide(&inputs, other),
        Err(AddressCeilingError::Unsupported { .. })
    ));
}

#[test]
fn consolidation_short_of_the_ceiling_is_refused_with_how_far_it_reached() {
    let inputs: Vec<_> = (0..4).map(|seed| note(1, seed)).collect();
    let other = LIMIT as u32 - 2 - 4 + 5;
    let Err(AddressCeilingError::Unsupported {
        compiled,
        after_merging,
        ..
    }) = decide(&inputs, other)
    else {
        panic!("unsupported");
    };
    assert_eq!((compiled, after_merging), (LIMIT + 5, LIMIT + 2));
}
