//! Pins `test-vectors/rpc/unspent_utxos.json`, the attested read and the flat response both languages decode.

use serde_json::{json, Value};
use solana_address::Address;
use spr_indexer_api::Hash;
use zolana_ring_client::rpc::{
    Attestation, Coverage, GetUnspentUtxosResponse, ReadTarget, UnresolvedHistory,
    UnresolvedReason, UnspentUtxoKind, UnspentUtxoView, UnspentUtxosAttestation, GET_UNSPENT_UTXOS,
};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/rpc/unspent_utxos.json"
);
const TIMESTAMP: u64 = 1_700_000_000;

fn target() -> ReadTarget {
    ReadTarget {
        cluster: [1; 32],
        service: Address::new_from_array([2; 32]),
        ring: Address::new_from_array([7; 32]),
    }
}

fn view(hash: u8, kind: UnspentUtxoKind) -> UnspentUtxoView {
    UnspentUtxoView {
        utxo_hash: Hash([hash; 32]),
        asset: Hash(spr_hasher::primitives::hash_bytes(&[3; 32]).expect("asset")),
        mint: Some(Address::new_from_array([3; 32]).into()),
        amount: 9,
        kind,
        slot: 11,
        tx_signature: solana_signature::Signature::from([5; 64]).into(),
        event_index: 0,
        slot_index: 1,
    }
}

fn responses() -> Vec<(&'static str, GetUnspentUtxosResponse)> {
    vec![
        (
            "a complete window lists an opened note and a merge output",
            GetUnspentUtxosResponse {
                utxos: vec![
                    view(
                        1,
                        UnspentUtxoKind::Opened {
                            blinding: Hash([6; 32]),
                            tree_id: 1,
                        },
                    ),
                    view(2, UnspentUtxoKind::MergeOutput),
                ],
                coverage: Coverage {
                    from_slot: 10,
                    through_slot: 20,
                    complete: true,
                },
                unresolved: Vec::new(),
                cursor: None,
            },
        ),
        (
            "an unnamed input keeps a listed note and takes the claim",
            GetUnspentUtxosResponse {
                utxos: vec![view(2, UnspentUtxoKind::MergeOutput)],
                coverage: Coverage {
                    from_slot: 10,
                    through_slot: 20,
                    complete: false,
                },
                unresolved: vec![UnresolvedHistory {
                    slot: 15,
                    tx_signature: solana_signature::Signature::from([8; 64]).into(),
                    event_index: 2,
                    reason: UnresolvedReason::UnknownMergeInput,
                    inputs: vec![Hash([9; 32])],
                }],
                cursor: Some(vec![2; 32].into()),
            },
        ),
        (
            "a wallet read carries the flag and no row",
            GetUnspentUtxosResponse {
                utxos: Vec::new(),
                coverage: Coverage {
                    from_slot: 10,
                    through_slot: 20,
                    complete: false,
                },
                unresolved: Vec::new(),
                cursor: None,
            },
        ),
    ]
}

fn attestations() -> Value {
    let message = |wallet: Option<Address>, cursor: Option<Vec<u8>>| {
        let attestation = UnspentUtxosAttestation {
            target: target(),
            owner: [9; 32],
            cursor: cursor.map(Into::into),
            wallet,
        };
        String::from_utf8(attestation.message(TIMESTAMP, &[0x0a; 32])).expect("utf-8")
    };
    json!([
        {"name": "a ring read", "message": message(None, None)},
        {"name": "a wallet read with a cursor", "message": message(Some(Address::new_from_array([0x0b; 32])), Some(vec![2; 32]))},
    ])
}

/// `UPDATE_RING_VECTORS=1` rewrites the file.
#[test]
fn the_unspent_vector_holds() {
    let built = json!({
        "method": GET_UNSPENT_UTXOS,
        "timestamp": TIMESTAMP,
        "nonce": hex::encode([0x0a; 32]),
        "cluster": hex::encode([1; 32]),
        "service": Address::new_from_array([2; 32]).to_string(),
        "ring": Address::new_from_array([7; 32]).to_string(),
        "owner": hex::encode([9; 32]),
        "attestations": attestations(),
        "responses": responses().iter().map(|(name, response)| json!({
            "name": name,
            "wire": response,
        })).collect::<Vec<_>>(),
    });
    if std::env::var_os("UPDATE_RING_VECTORS").is_some() {
        let pretty = serde_json::to_string_pretty(&built).expect("json");
        std::fs::write(VECTOR, pretty + "\n").expect("vector");
    }
    let pinned: Value =
        serde_json::from_str(&std::fs::read_to_string(VECTOR).expect("vector")).expect("json");
    assert_eq!(built, pinned);
    for (case, (_, response)) in pinned["responses"]
        .as_array()
        .expect("responses")
        .iter()
        .zip(responses())
    {
        let parsed: GetUnspentUtxosResponse =
            serde_json::from_value(case["wire"].clone()).expect("wire");
        assert_eq!(parsed, response);
    }
}
