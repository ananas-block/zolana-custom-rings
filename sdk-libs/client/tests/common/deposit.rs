use custom_ring_interface::{CredentialRead, CustomRingProof, DepositPrefix, PlainGroth16Proof};
use solana_address::Address;
use spr_event::{tag, EncryptedRingDepositData};
use spr_event_parser::{InstructionGroup, ParsedInstruction};
use spr_interface::{
    instruction::instruction_data::deposit::{
        DepositAssetKind, RingDepositEntry, RingDepositIxData,
    },
    SHIELDED_POOL_PROGRAM_ID,
};

/// Trusted execution metadata, supplied separately from indexed ciphertexts.
pub fn group(ring: Address, audited: bool, deposits: Vec<([u8; 32], Vec<u8>)>) -> InstructionGroup {
    let pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let deposit = RingDepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits: deposits
            .into_iter()
            .map(|(owner_utxo_hash, ciphertext)| RingDepositEntry {
                asset_index: 0,
                view_tag: [0; 32],
                owner_utxo_hash,
                amount: 1,
                ring_data_hash: [0; 32],
                encrypted: EncryptedRingDepositData {
                    tx_viewing_pk: [0; 33],
                    salt: [0; 16],
                    ciphertext,
                },
            })
            .collect(),
    };
    let mut data = vec![tag::RING_DEPOSIT];
    data.extend(deposit.serialize().unwrap());
    let mut outer_data = if audited {
        DepositPrefix {
            tag: custom_ring_interface::tag::DEPOSIT,
            key_capacity: 1,
            proof: CustomRingProof {
                groth16: PlainGroth16Proof {
                    proof_a: [0; 32],
                    proof_b: [0; 64],
                    proof_c: [0; 32],
                },
                commitment: [0; 32],
                commitment_pok: [0; 32],
            },
            credential_read: CredentialRead::new_state(0),
            own_revision: Default::default(),
            curator_revision: Default::default(),
        }
        .encode()
        .unwrap()
    } else {
        Vec::new()
    };
    outer_data.extend_from_slice(&data);
    InstructionGroup {
        outer: ParsedInstruction::new(ring, Vec::new(), outer_data, 1),
        inner: vec![
            ParsedInstruction::new(pool, Vec::new(), data, 2),
            ParsedInstruction::new(
                pool,
                Vec::new(),
                [
                    vec![tag::EMIT_EVENT, spr_event::EventKind::Deposit as u8],
                    borsh::to_vec(&spr_event::GeneralEvent {
                        inputs: Vec::new(),
                        outputs: Vec::new(),
                        messages: Vec::new(),
                        tx_viewing_pk: [0; 33],
                        salt: [0; 16],
                        first_output_leaf_index: 0,
                        output_tree: [0; 32],
                        spl_transfers: Vec::new(),
                    })
                    .unwrap(),
                ]
                .concat(),
                3,
            ),
        ],
    }
}
