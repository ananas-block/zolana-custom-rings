//! Pins `test-vectors/audit/merge_ledger.json`, confirmed merge transitions in history order.

use std::collections::HashMap;

use serde_json::{json, Value};
use solana_address::Address;
use solana_signature::Signature;
use zolana_ring_client::{ConfirmedMerge, MergeDisclosed, MergeInput, MergeLedger, UtxoOwner};

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/audit/merge_ledger.json"
);
const ASSET: [u8; 32] = [7; 32];

struct Step {
    /// Openings that land before the step, as `(commitment byte, amount)`.
    opens: Vec<(u8, u64)>,
    /// `(id, inputs, output)`, a repeated id replays the merge.
    merge: Option<(u8, Vec<u8>, u8)>,
}

fn step(opens: &[(u8, u64)], merge: Option<(u8, &[u8], u8)>) -> Step {
    Step {
        opens: opens.to_vec(),
        merge: merge.map(|(id, inputs, output)| (id, inputs.to_vec(), output)),
    }
}

fn confirmed(id: u8, inputs: &[u8], output: u8) -> ConfirmedMerge {
    ConfirmedMerge {
        slot: u64::from(id),
        tx_signature: Signature::from([id; 64]),
        event_index: 0,
        output_commitment: [output; 32],
        tree_id: 1,
        leaf_index: u64::from(id),
        first_nullifier: [id; 32],
        ring_data_hash: [0; 32],
        disclosed: MergeDisclosed::Inputs(ConfirmedMerge::real_inputs(
            &inputs.iter().map(|byte| [*byte; 32]).collect::<Vec<_>>(),
        )),
    }
}

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

fn cases() -> Vec<(&'static str, Vec<Step>)> {
    vec![
        (
            "every input known resolves at once",
            vec![step(&[(10, 3), (11, 4)], Some((1, &[10, 11], 20)))],
        ),
        (
            "a zero list entry is a dummy, never a spent input",
            vec![step(&[(10, 3)], Some((1, &[10, 0, 0], 20)))],
        ),
        (
            "a repeated merge applies once",
            vec![
                step(&[(10, 3)], Some((1, &[10], 20))),
                step(&[], Some((1, &[10], 20))),
            ],
        ),
        (
            "an unknown input holds the merge until its opening",
            vec![
                step(&[(10, 3)], Some((1, &[10, 11], 20))),
                step(&[(11, 4)], None),
            ],
        ),
        (
            "a descendant resolves through its parent",
            vec![
                step(&[], Some((1, &[10], 20))),
                step(&[(30, 5)], Some((2, &[20, 30], 40))),
                step(&[(10, 3)], None),
            ],
        ),
    ]
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn run(steps: &[Step]) -> Value {
    let mut ledger = MergeLedger::default();
    let mut known: HashMap<[u8; 32], MergeInput> = HashMap::new();
    let mut seen = Vec::new();
    for current in steps {
        known.extend(
            current
                .opens
                .iter()
                .map(|(commitment, amount)| ([*commitment; 32], note(*amount))),
        );
        let lookup = |commitment: &[u8; 32]| known.get(commitment).copied();
        let (spent, resolved) = match &current.merge {
            Some((id, inputs, output)) => {
                let transition = ledger.apply(confirmed(*id, inputs, *output), lookup);
                (transition.spent, transition.resolved)
            }
            None => (Vec::new(), ledger.resolve(lookup)),
        };
        seen.push(json!({
            "opens": current.opens.iter().map(|(commitment, amount)| {
                json!({"commitment": hex32(&[*commitment; 32]), "amount": amount})
            }).collect::<Vec<_>>(),
            "merge": current.merge.as_ref().map(|(id, inputs, output)| json!({
                "slot": u64::from(*id),
                "txSignature": bs58::encode([*id; 64]).into_string(),
                "eventIndex": 0,
                "list": inputs.iter().map(|byte| hex32(&[*byte; 32])).collect::<Vec<_>>(),
                "outputCommitment": hex32(&[*output; 32]),
                "treeId": 1,
                "leafIndex": u64::from(*id),
                "firstNullifier": hex32(&[*id; 32]),
            })),
            "spent": spent.iter().map(hex32).collect::<Vec<_>>(),
            "resolved": resolved.iter().map(|output| json!({
                "commitment": hex32(&output.commitment),
                "ownerKey": hex32(&output.owner_key),
                "asset": hex32(&output.asset),
                "amount": output.amount,
            })).collect::<Vec<_>>(),
            "unresolved": ledger.unresolved().map(|merge| {
                hex32(&merge.output_commitment)
            }).collect::<Vec<_>>(),
        }));
    }
    Value::Array(seen)
}

/// `UPDATE_RING_VECTORS=1` rewrites the file.
#[test]
fn the_ledger_vector_holds() {
    let built = json!({
        "note": {
            "ownerKey": hex32(&[1; 32]),
            "nullifierPk": hex32(&[2; 32]),
            "asset": hex32(&ASSET),
            "mint": Address::new_from_array([3; 32]).to_string(),
        },
        "cases": cases().iter().map(|(name, steps)| json!({
            "name": name,
            "steps": run(steps),
        })).collect::<Vec<_>>(),
    });
    if std::env::var_os("UPDATE_RING_VECTORS").is_some() {
        let pretty = serde_json::to_string_pretty(&built).expect("json");
        std::fs::write(VECTOR, pretty + "\n").expect("vector");
    }
    let pinned: Value =
        serde_json::from_str(&std::fs::read_to_string(VECTOR).expect("vector")).expect("json");
    assert_eq!(built, pinned);
}
