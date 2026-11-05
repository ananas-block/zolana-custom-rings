//! Pins credential creation bytes and address checkpoint results for SDK implementations.
//!
//! Read after `src/accounts/credential.rs` and `src/proof/credential_read.rs`.
//! Read before `tests/credential_layout_parity.rs`.

use std::{fs, path::PathBuf};

use bytemuck::Zeroable;
use custom_ring_interface::{
    AddressRootSelection, CustomRingProof, EnrollIxData, EnrollRequest, Enrollment, InstructionTag,
    credential::CredentialAuthority, tagged_x25519,
};
use serde_json::{Value, json};
use solana_address::Address;
use spr_hasher::primitives::right_align;
use spr_instruction::derivation::{derive_output_blinding_seed, derive_transact_output_blinding};
use spr_interface::instruction::{
    TransactProof, TreeContext, instruction_data::transact::NO_UTXO_ROOT,
};
use spr_program::{
    ADDRESS_TREE_ID,
    program::{ACCOUNT_BLINDING_SEED, SppTransactCpi, UniqueDataUtxo},
};
use spr_tree::nullifier_tree::{
    constants::NULLIFIER_TREE_ZKP_BATCHES, layout::NullifierTreeLayout,
};
use zolana_ring_policy::ring_id_field;

#[derive(Clone, Copy)]
struct RootSequenceCase {
    name: &'static str,
    tree_id: u16,
    root_index: u16,
    sequence_number: u64,
    current_index: u64,
    floor: u64,
}

#[test]
fn credential_vectors_match_production_helpers() {
    let committed: Value = serde_json::from_slice(&fs::read(vector_path()).unwrap()).unwrap();
    assert_eq!(committed, vectors());
}

#[test]
#[ignore = "writes the shared credential fixture"]
fn write_credential_vectors() {
    let mut encoded = serde_json::to_vec_pretty(&vectors()).unwrap();
    encoded.push(b'\n');
    fs::write(vector_path(), encoded).unwrap();
}

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/registry/credential.json")
}

fn vectors() -> Value {
    json!({
        "schema_version": 1,
        "description": "Public hash and encoding fixture. Proof bytes and ciphertext are synthetic.",
        "byte_encoding": "lowercase hex without a prefix",
        "enrollment": enrollment_vector(),
        "root_sequence": root_sequence_vectors(),
    })
}

fn enrollment_vector() -> Value {
    let ring_program = Address::new_from_array([0x71; 32]);
    let owner = Address::new_from_array([0x32; 32]);
    let ring_id = ring_id_field(ring_program.as_array()).unwrap();
    let mut auditor_u = [0; 32];
    auditor_u[0] = 9;
    let auditor_pubkey = tagged_x25519(&auditor_u);
    let ix = EnrollIxData {
        nullifier_pk: [0x13; 32],
        list_tag: [0x24; 32],
        eph_u: [0x35; 32],
        ciphertext: core::array::from_fn(|index| index as u8),
    };
    let credential = Enrollment {
        ring_id: &ring_id,
        auditor_pubkey: &auditor_pubkey,
        owner: &owner,
        ix: &ix,
    }
    .credential()
    .unwrap();
    let authority = CredentialAuthority::derive(&ring_program).unwrap();
    let address_root_index = 17;
    let output_tree_id = 0x4567;
    let mut output = UniqueDataUtxo::new_init(
        authority.owner(),
        credential.seed().unwrap(),
        TreeContext {
            utxo_tree_root_index: NO_UTXO_ROOT,
            nullifier_tree_root_index: address_root_index,
        },
    )
    .unwrap();
    *output = credential;
    let address = *output.address();
    let data_hash = output.data_hash().unwrap();
    let output_blinding_seed =
        derive_output_blinding_seed(&address, &ACCOUNT_BLINDING_SEED).unwrap();
    let blinding = derive_transact_output_blinding(&address, &output_blinding_seed, 0).unwrap();
    let transact = SppTransactCpi::new(TransactProof::zeroed())
        .with_unique_data_utxo(output)
        .unwrap()
        .into_ix_data(output_tree_id)
        .unwrap();
    let register_key = CustomRingProof::zeroed();
    let request = EnrollRequest {
        ix: &ix,
        register_key: &register_key,
        transact: TransactProof::zeroed(),
        address_root_index,
    };
    let payload = request.encode().unwrap();
    let mut instruction = vec![InstructionTag::Enroll as u8];
    instruction.extend_from_slice(&payload);
    json!({
        "ring_program": hex::encode(ring_program.as_array()),
        "owner": hex::encode(owner.as_array()),
        "ring_id": hex::encode(credential.ring_id),
        "member": hex::encode(credential.member),
        "nullifier_pk": hex::encode(credential.nullifier_pk),
        "list_tag": hex::encode(credential.list_tag),
        "auditor_pubkey": hex::encode(credential.auditor_pubkey),
        "eph_u": hex::encode(credential.eph_u),
        "ciphertext": hex::encode(credential.ciphertext),
        "credential_pda": hex::encode(authority.owner().pda().as_array()),
        "credential_pda_bump": authority.bump(),
        "credential_owner_hash": hex::encode(authority.owner().owner_hash()),
        "credential_borsh": hex::encode(borsh::to_vec(&credential).unwrap()),
        "register_key_hash": hex::encode(credential.register_key_hash().unwrap()),
        "state_hash": hex::encode(credential.state_hash().unwrap()),
        "seed": hex::encode(credential.seed().unwrap().as_bytes()),
        "address_tree_id": ADDRESS_TREE_ID,
        "address": hex::encode(address),
        "address_root_index": address_root_index,
        "data_hash": hex::encode(data_hash),
        "account_blinding_seed": hex::encode(ACCOUNT_BLINDING_SEED),
        "output_blinding_seed": hex::encode(output_blinding_seed),
        "output_index": 0,
        "blinding": hex::encode(blinding),
        "output_tree_id": output_tree_id,
        "utxo_hash": hex::encode(transact.outputs[0].utxo_hash),
        "output_data": hex::encode(transact.outputs[0].data.as_ref().unwrap()),
        "private_tx_hash": hex::encode(transact.private_tx_hash),
        "proof_bytes": "dummy_encoding_only",
        "enroll_tag": InstructionTag::Enroll as u8,
        "enroll_payload": hex::encode(payload),
        "enroll_instruction": hex::encode(instruction),
        "spp_transact_payload": hex::encode(transact.serialize().unwrap()),
    })
}

fn root_sequence_vectors() -> Value {
    let roots = core::array::from_fn(|index| right_align(&(index as u64 + 1).to_be_bytes()));
    let latest = RootSequenceCase {
        name: "latest_after_wrap",
        tree_id: ADDRESS_TREE_ID,
        root_index: 0,
        sequence_number: NULLIFIER_TREE_ZKP_BATCHES as u64,
        current_index: 1,
        floor: NULLIFIER_TREE_ZKP_BATCHES as u64,
    };
    let cases = [
        latest,
        RootSequenceCase {
            name: "previous_across_wrap",
            root_index: (NULLIFIER_TREE_ZKP_BATCHES - 1) as u16,
            floor: NULLIFIER_TREE_ZKP_BATCHES as u64 - 1,
            ..latest
        },
        RootSequenceCase {
            name: "oldest_retained",
            root_index: 1,
            floor: 1,
            ..latest
        },
        RootSequenceCase {
            name: "below_floor",
            root_index: (NULLIFIER_TREE_ZKP_BATCHES - 1) as u16,
            ..latest
        },
        RootSequenceCase {
            name: "index_outside_history",
            root_index: NULLIFIER_TREE_ZKP_BATCHES as u16,
            ..latest
        },
        RootSequenceCase {
            name: "invalid_write_cursor",
            current_index: NULLIFIER_TREE_ZKP_BATCHES as u64,
            ..latest
        },
        RootSequenceCase {
            name: "sequence_underflow",
            root_index: (NULLIFIER_TREE_ZKP_BATCHES - 1) as u16,
            sequence_number: 0,
            ..latest
        },
        RootSequenceCase {
            name: "wrong_address_tree",
            tree_id: ADDRESS_TREE_ID + 1,
            ..latest
        },
    ];
    json!({
        "capacity": NULLIFIER_TREE_ZKP_BATCHES,
        "roots": roots.map(hex::encode).to_vec(),
        "cases": cases.map(|case| case.vector(&roots)).to_vec(),
    })
}

impl RootSequenceCase {
    fn vector(self, roots: &[[u8; 32]; NULLIFIER_TREE_ZKP_BATCHES]) -> Value {
        let zeroes =
            vec![0; core::mem::size_of::<NullifierTreeLayout<NULLIFIER_TREE_ZKP_BATCHES>>()];
        let mut history: NullifierTreeLayout<NULLIFIER_TREE_ZKP_BATCHES> =
            wincode::deserialize(&zeroes).unwrap();
        history.sequence_number = self.sequence_number;
        history.root_history.current_index = self.current_index;
        history.root_history.roots = *roots;
        let result = match (AddressRootSelection {
            tree_id: self.tree_id,
            root_index: self.root_index,
            history: &history,
        })
        .checkpoint()
        {
            Ok(checkpoint) => {
                let floor_result = match checkpoint.above(self.floor) {
                    Ok(root) => json!({ "root": hex::encode(root) }),
                    Err(error) => json!({ "error_code": error as u32 }),
                };
                json!({
                    "root": hex::encode(checkpoint.root()),
                    "sequence": checkpoint.sequence(),
                    "floor_result": floor_result,
                })
            }
            Err(error) => json!({ "error_code": error as u32 }),
        };
        json!({
            "name": self.name,
            "tree_id": self.tree_id,
            "root_index": self.root_index,
            "sequence_number": self.sequence_number,
            "current_index": self.current_index,
            "floor": self.floor,
            "expected": result,
        })
    }
}
