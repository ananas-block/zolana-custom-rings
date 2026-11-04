//! Pins the transfer key catalog and the shapes it serves in `test-vectors/proof/ring_keyed_shapes.json` for the Go keys test and the TS SDK.

use custom_ring_interface::{
    key_catalog::{
        RingCircuit, TransferShape, TransferSpend, ANONYMOUS_TRANSFER_SHAPES,
        CONFIDENTIAL_TRANSFER_SHAPES, ENTRY_TRANSFER_SHAPES,
    },
    RingRail,
};
use serde_json::{json, Value};
use spr_interface::shape::SPP_SUPPORTED_SHAPES;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/proof/ring_keyed_shapes.json"
);

fn shapes(family: &[TransferShape]) -> Value {
    family
        .iter()
        .map(|shape| {
            json!({"outputs": shape.outputs, "inputs": shape.inputs, "withdrawals": shape.withdrawals.iter().filter(|capacity| **capacity != 0).collect::<Vec<_>>()})
        })
        .collect()
}

/// Every shape input counts as published.
fn served(rail: RingRail, spends_default_ring: bool) -> Value {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| {
            rail.supports(*shape)
                && RingCircuit::transfer(TransferSpend {
                    rail,
                    inputs: shape.n_inputs(),
                    outputs: shape.n_outputs(),
                    spends_default_ring,
                    legs: 0,
                    owners: 0,
                    has_data: false,
                    private_source: false,
                })
                .is_some()
        })
        .map(|shape| json!([shape.n_inputs(), shape.n_outputs()]))
        .collect()
}

fn compute_vector() -> Value {
    json!({
        "description": "Per ring rail, the SPP shapes a transfer key serves when every shape input is spent, each list in the cost order of SPP_SUPPORTED_SHAPES. confidential_ring is the signer and in-proof rails, anonymous_ring the anonymous rail over ring notes, anonymous_entry_ring the anonymous rail spending a default-ring note, ring_authority the RingAuthority rail. transfer_shapes lists every transfer key family, its input class and the withdrawal leg capacities keyed at each output count, mirrored by prover/circuits/transfer. Produced by program-libs/interface/tests/keyed_shapes.rs.",
        "confidential_ring": served(RingRail::Confidential, false),
        "anonymous_ring": served(RingRail::Anonymous, false),
        "anonymous_entry_ring": served(RingRail::Anonymous, true),
        "ring_authority": served(RingRail::Delegate, false),
        "transfer_shapes": {
            "confidential": shapes(&CONFIDENTIAL_TRANSFER_SHAPES),
            "anonymous": shapes(&ANONYMOUS_TRANSFER_SHAPES),
            "entry": shapes(&ENTRY_TRANSFER_SHAPES),
        },
    })
}

#[test]
fn the_keyed_shapes_are_the_shared_vector() {
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vector());
}

#[test]
#[ignore = "rewrites test-vectors/proof/ring_keyed_shapes.json"]
fn write_ring_keyed_shapes_vector() {
    let json = serde_json::to_string_pretty(&compute_vector()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}
