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
    decide_under(
        inputs,
        other,
        MergeCapacity {
            keyed: 45,
            zero_key: 45,
        },
    )
}

fn decide_under(
    inputs: &[SpentInput],
    other: u32,
    merge_capacity: MergeCapacity,
) -> Result<CeilingDecision, AddressCeilingError> {
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
        merge_capacity,
    }
    .decide()
}

#[test]
fn a_transaction_at_the_ceiling_stays_one_transaction() {
    let inputs: Vec<_> = (0..10).map(|seed| note(1, seed)).collect();
    let other = LIMIT as u32 - 2 - 10;
    let Ok(CeilingDecision::Inline(size)) = decide(&inputs, other) else {
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
    let Ok(CeilingDecision::MergeFirst { groups, addresses }) = decide(&inputs, other) else {
        panic!("merge first");
    };
    assert_eq!(addresses, LIMIT - 1);
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

/// A group past one merge's capacity leaves one note per merge, the count reads each.
#[tokio::test]
async fn an_oversized_group_splits_and_the_count_keeps_every_note_left() {
    use crate::{
        tests::support::{ring, ring_utxo, Chain, RingSettings, TREE_ID},
        FittedMerge, MergeProofInput,
    };
    use custom_ring_interface::RingMode;
    use spr_interface::pda;

    let owner = keypair(1);
    let notes: Vec<_> = (0..49)
        .map(|leaf| ring_utxo(&owner, Mint::SOL, 5, leaf))
        .collect();
    let keyed = FittedMerge {
        ring: ring(),
        inputs: notes,
        output_tree_id: TREE_ID,
        keys: &owner,
        proof_input: &MergeProofInput {
            nullifier_key: owner.nullifier_key.clone(),
            input_tree: pda::tree(TREE_ID),
            output_tree: pda::tree(TREE_ID),
        },
        payer: address(1),
    }
    .prepare(&Chain::ring(RingSettings::new(RingMode::Confidential)))
    .await
    .unwrap()
    .published_inputs();
    assert!(keyed < 49);
    let capacity = MergeCapacity {
        keyed,
        zero_key: keyed,
    };

    let inputs: Vec<_> = (0..49).map(|seed| note(1, seed)).collect();
    // Past the first merge alone, two notes left reach the ceiling exactly.
    let reachable = LIMIT as u32 - 2 - 2;
    let Ok(CeilingDecision::MergeFirst { groups, addresses }) =
        decide_under(&inputs, reachable, capacity)
    else {
        panic!("merge first");
    };
    assert_eq!(addresses, LIMIT);
    let widths: Vec<usize> = groups.iter().map(|group| group.inputs.len()).collect();
    assert_eq!(widths, [keyed, 49 - keyed]);
    assert!(widths.iter().all(|width| *width <= keyed));

    // One more account, an unsplit group of one PDA would still read as under the ceiling.
    let Err(AddressCeilingError::Unsupported { after_merging, .. }) =
        decide_under(&inputs, reachable + 1, capacity)
    else {
        panic!("unsupported");
    };
    assert_eq!(after_merging, LIMIT + 1);
}

/// One input past a capacity is a run of one, it stays a note of its own and merges nothing.
#[test]
fn a_lone_note_past_the_capacity_is_named_by_no_merge() {
    let inputs: Vec<_> = (0..4).map(|seed| note(1, seed)).collect();
    let capacity = MergeCapacity {
        keyed: 3,
        zero_key: 3,
    };
    let Ok(CeilingDecision::MergeFirst { groups, addresses }) =
        decide_under(&inputs, LIMIT as u32 - 2 - 4 + 1, capacity)
    else {
        panic!("merge first");
    };
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].inputs, [0, 1, 2]);
    assert_eq!(addresses, LIMIT - 1);
}

/// The owner's signature and account leave a zero-key merge narrower, pinned from its own selection.
#[tokio::test]
async fn a_zero_key_group_splits_at_the_zero_key_capacity() {
    use crate::{
        tests::support::{ring, ring_utxo, zero_key, Chain, RingSettings, TREE_ID},
        FittedMerge, MergeProofInput,
    };
    use custom_ring_interface::RingMode;
    use spr_interface::{pda, ZERO_NULLIFIER_PUBKEY};

    let owner = keypair(1);
    let notes: Vec<_> = (0..52)
        .map(|leaf| zero_key(ring_utxo(&owner, Mint::SOL, 5, leaf)))
        .collect();
    let carried = FittedMerge {
        ring: ring(),
        inputs: notes,
        output_tree_id: TREE_ID,
        keys: &owner,
        proof_input: &MergeProofInput {
            nullifier_key: owner.nullifier_key.clone(),
            input_tree: pda::tree(TREE_ID),
            output_tree: pda::tree(TREE_ID),
        },
        payer: address(1),
    }
    .prepare(&Chain::ring(RingSettings::new(RingMode::Confidential)))
    .await
    .unwrap()
    .published_inputs();
    assert_eq!(carried, WIDEST_ZERO_KEY_MERGE);

    let inputs: Vec<_> = (0..4)
        .map(|seed| SpentInput {
            nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
            ..note(1, seed)
        })
        .collect();
    let capacity = MergeCapacity {
        keyed: 45,
        zero_key: 2,
    };
    let Ok(CeilingDecision::MergeFirst { groups, .. }) =
        decide_under(&inputs, LIMIT as u32 - 2 - 4 + 1, capacity)
    else {
        panic!("merge first");
    };
    assert_eq!(groups[0].inputs, [0, 1]);
}

/// Inputs a zero-key merge carries in one v1 transaction, measured here.
const WIDEST_ZERO_KEY_MERGE: usize = 44;

fn decide_frame(frame_len: usize) -> Result<CeilingDecision, AddressCeilingError> {
    let mut data = vec![0; frame_len];
    data[0] = custom_ring_interface::tag::TRANSFER;
    AddressCeiling {
        payer: address(1),
        instruction: &Instruction {
            program_id: address(2),
            accounts: vec![AccountMeta::new(address(1), true)],
            data,
        },
        budget: ComputeBudgetConfig::new(1_000_000),
        inputs: &[],
        merge_capacity: MergeCapacity {
            keyed: 45,
            zero_key: 45,
        },
    }
    .decide()
}

#[test]
fn past_the_byte_ceiling_a_frame_goes_buffered_and_past_the_cpi_limit_it_is_refused() {
    use custom_ring_interface::MAX_FRAME_LEN;
    assert!(matches!(
        decide_frame(1000),
        Ok(CeilingDecision::Inline(size)) if size.bytes < v1::MAX_TRANSACTION_SIZE
    ));
    assert!(matches!(
        decide_frame(v1::MAX_TRANSACTION_SIZE),
        Ok(CeilingDecision::Buffered(size)) if size.bytes < v1::MAX_TRANSACTION_SIZE
    ));
    assert!(matches!(
        decide_frame(MAX_FRAME_LEN),
        Ok(CeilingDecision::Buffered(_))
    ));
    assert!(matches!(
        decide_frame(MAX_FRAME_LEN + 1),
        Err(AddressCeilingError::Fit(FitError::FrameTooLarge { bytes, limit: MAX_FRAME_LEN }))
            if bytes == MAX_FRAME_LEN + 1
    ));
}
