//! The TS terms test checks the same vector.

use custom_ring_sdk::{RelayTransferTerms, TokenAccountCreate};
use serde_json::{json, Value};
use solana_address::Address;

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/rpc/relay_transfer_terms.json"
);

fn address(byte: u8) -> spr_indexer_api::SerializablePubkey {
    Address::new_from_array([byte; 32]).into()
}

fn bytes(byte: u8, length: usize) -> spr_indexer_api::Base64String {
    vec![byte; length].into()
}

fn compute_vector() -> Value {
    let terms = RelayTransferTerms {
        ring: address(1),
        fee_payer: address(2),
        // The clamped secret of the 0x06 viewing key, the authority transfer vector's.
        tx_viewing_key: serde_json::from_value(json!(
            "AAYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBkY="
        ))
        .unwrap(),
        signers: vec![address(3), address(4)],
        records: vec![bytes(5, 133), bytes(6, 133)],
        tails: vec![bytes(7, 48), bytes(8, 48)],
        nullifiers: vec![bytes(9, 32)],
        legs: vec![bytes(10, 41)],
        setup: vec![TokenAccountCreate {
            owner: address(11),
            mint: address(12),
            token_program: address(13),
        }],
    };
    json!({
        "description": "One RelayTransferTerms the sealing wallet hands a public signer. The field bytes repeat one value each and carry no meaning, the viewing key is the clamped secret of the 0x06 key. wire is the exact JSON text Rust and TypeScript write and read.",
        "wire": serde_json::to_string(&terms).unwrap(),
    })
}

#[test]
fn the_terms_are_the_shared_vector() {
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap();
    assert_eq!(committed, compute_vector());
}

#[test]
#[ignore = "rewrites test-vectors/rpc/relay_transfer_terms.json"]
fn write_relay_terms_vector() {
    let json = serde_json::to_string_pretty(&compute_vector()).unwrap() + "\n";
    std::fs::write(VECTOR, json).unwrap();
}
