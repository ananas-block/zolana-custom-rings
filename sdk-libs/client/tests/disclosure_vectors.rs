//! Version 4 streams from solved witnesses, version 3 frozen.

use custom_ring_interface::{
    encode_confidential_output, tag, tagged_x25519, AuditKey, AuditStreamLayout, AuditorMessage,
    RingMode, CONFIDENTIAL_DATA_FREE_BODY_LEN,
};
use serde_json::Value;
use solana_address::Address;
use solana_signature::Signature;
use spr_event::MessageData;
use spr_hasher::primitives::hash_bytes;
use spr_interface::shape::SPP_SUPPORTED_SHAPES;
use spr_keypair::{ViewingKey, X25519Keypair};
use spr_transaction::{Mint, OutputContext, OutputSlot, ShieldedTransaction};
use zolana_ring_client::{
    AuditFrame, HistoricalLayout, InputOpening, OutputOpening, OutputPayloadErrorKind,
    TransactionAudit,
};
use zolana_ring_transaction::RingAssets;

const STREAM_V4: &str = include_str!("../../../test-vectors/audit/audit-stream-v4.json");
const DELIVERED_V3: &str =
    include_str!("../../../test-vectors/audit/audit-disclosure-delivered.json");
const ANONYMOUS_V3: &str =
    include_str!("../../../test-vectors/audit/audit-disclosure-anonymous.json");
const RING: Address = Address::new_from_array([0x90; 32]);
/// The auditor of the Go fixtures.
const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn array<const N: usize>(value: &Value) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

fn list(value: &Value) -> Vec<Vec<u8>> {
    value
        .as_array()
        .map_or_else(Vec::new, |items| items.iter().map(bytes).collect())
}

fn auditor() -> X25519Keypair {
    X25519Keypair::from_bytes(&hex::decode(AUDITOR_SK).unwrap().try_into().unwrap())
}

#[test]
fn every_version_4_stream_rebuilds_its_published_hashes_with_no_mint_registry() {
    let vector: Value = serde_json::from_str(STREAM_V4).unwrap();
    assert_eq!(
        hash_bytes(RING.as_array()).unwrap(),
        array::<32>(&vector["ring_id"])
    );
    let tx_key = ViewingKey::from_canonical_bytes(&array(&vector["tx_viewing_sk"])).unwrap();
    let eph = X25519Keypair::from_bytes(&array(&vector["eph_sk"]));
    let first_nullifier = array::<32>(&vector["first_nullifier"]);
    let tree_id: u16 = vector["output_tree_id"].as_u64().unwrap() as u16;
    let no_assets = RingAssets::new([]).unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let bits = case["layout"].as_u64().unwrap();
        let layout = AuditStreamLayout {
            key: AuditKey {
                class: case["input_class"].as_u64().unwrap() as usize,
                entry: bits & 2 != 0,
            },
            inputs: case["input_count"].as_u64().unwrap() as usize,
            outputs: case["output_count"].as_u64().unwrap() as usize,
            capacity: case["outputs"].as_u64().unwrap() as usize,
            has_data: bits & 1 != 0,
        };
        let hashes = list(&case["output_hashes"]);
        let output_slots: Vec<OutputSlot> = hashes
            .iter()
            .enumerate()
            .map(|(leaf, hash)| OutputSlot {
                view_tag: [0x71 + leaf as u8; 32],
                output_context: OutputContext {
                    hash: hash.clone().try_into().unwrap(),
                    tree_id,
                    leaf_index: leaf as u64,
                },
                payload: Vec::new(),
            })
            .collect();
        let (records, tails) = (
            list(&case["record_ciphertexts"]),
            list(&case["tail_ciphertexts"]),
        );
        let envelope = bytes(&case["envelope_ciphertext"]);
        let parts = core::iter::once(envelope.as_slice())
            .chain(records.iter().map(Vec::as_slice))
            .chain(tails.iter().map(Vec::as_slice));
        let tx = ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: Some(tx_key.pubkey()),
            salt: Some(array(&vector["salt"])),
            output_slots,
            messages: vec![MessageData {
                view_tag: auditor().pubkey().u(),
                data: AuditorMessage::data(&eph.pubkey().u(), parts),
            }],
            nullifiers: (0..layout.inputs)
                .map(|input| match input {
                    0 => first_nullifier,
                    later => [later as u8; 32],
                })
                .collect(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        };
        let audited = TransactionAudit::new(&tx, layout)
            .run(&auditor(), &no_assets)
            .unwrap();
        assert!(
            audited.payload_errors.is_empty(),
            "{name}: {:?}",
            audited.payload_errors
        );
        assert_eq!(audited.outputs.len(), hashes.len(), "{name}");
        let plaintext = bytes(&case["envelope_plaintext"]);
        assert_eq!(audited.real_inputs, plaintext[32], "{name}");
        let blindings = list(&case["blindings"]);
        let plain_records = list(&case["records"]);
        for (index, output) in audited.outputs.iter().enumerate() {
            match plain_records[index][0] {
                0 => assert_eq!(output.opening, OutputOpening::Dummy, "{name} slot {index}"),
                1 => assert!(matches!(output.opening, OutputOpening::Ring { .. })),
                _ => assert!(matches!(output.opening, OutputOpening::Exit(_))),
            }
            if let Some(utxo) = output.opening.utxo() {
                assert_eq!(utxo.blinding.to_vec(), blindings[index]);
                assert!(utxo.mint.is_some(), "a record names its mint");
            }
        }
    }
}

fn held_assets(slots: &[Value]) -> RingAssets {
    let mut mints: Vec<Address> = slots
        .iter()
        .filter_map(|slot| slot.get("asset_address"))
        .map(|asset| Address::new_from_array(array(asset)))
        .collect();
    mints.sort();
    mints.dedup();
    RingAssets::new(
        mints
            .into_iter()
            .filter(|mint| *mint != Mint::SOL.asset)
            .zip(2u32..)
            .map(|(mint, id)| Mint::new(mint, id.into())),
    )
    .unwrap()
}

/// `tag || flags || shape || inputs || outputs`.
fn version_3_head(outputs: usize, inputs: usize, key_escrow: bool) -> [u8; 5] {
    let shape = SPP_SUPPORTED_SHAPES
        .iter()
        .position(|shape| shape.n_outputs() == outputs && shape.n_inputs() >= inputs)
        .unwrap();
    let input_byte = inputs as u8 | (u8::from(key_escrow) << 6);
    [
        tag::HISTORICAL_TRANSFER_V3,
        0,
        shape as u8,
        input_byte,
        outputs as u8,
    ]
}

/// Bit 7 of the inputs names the entry key.
fn anonymous_head(outputs: usize, inputs: usize, entry: bool) -> [u8; 5] {
    let mut head = version_3_head(outputs, inputs, false);
    head[3] |= u8::from(entry) << 7;
    head
}

/// `Encrypted(len || scheme 10 || body)`.
fn delivered_payload(body: &[u8]) -> Vec<u8> {
    let mut out = vec![spr_event::OutputDataEncoding::ENCRYPTED_TAG];
    out.extend_from_slice(&(body.len() as u32 + 1).to_le_bytes());
    out.push(10);
    out.extend_from_slice(body);
    out
}

#[test]
fn every_version_3_delivered_stream_opens_or_names_its_missing_key() {
    let vector: Value = serde_json::from_str(DELIVERED_V3).unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let slots = case["slots"].as_array().unwrap();
        let key_escrow = case["layout"].as_u64().unwrap() & 2 != 0;
        let inputs = case["input_count"].as_u64().unwrap() as usize;
        let assets = held_assets(slots);
        let tx_key = ViewingKey::from_canonical_bytes(&array(&case["tx_viewing_sk"])).unwrap();
        assert_eq!(
            tagged_x25519(&array(&case["tx_viewing_u"])),
            *tx_key.pubkey().as_bytes()
        );
        let tx = ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: Some(tx_key.pubkey()),
            salt: Some(array(&case["salt"])),
            output_slots: slots
                .iter()
                .enumerate()
                .map(|(leaf, slot)| OutputSlot {
                    view_tag: array(&slot["owner_tag"]),
                    output_context: OutputContext {
                        hash: array(&slot["output_hash"]),
                        tree_id: case["output_tree_id"].as_u64().unwrap() as u16,
                        leaf_index: leaf as u64,
                    },
                    payload: match slot["kind"].as_str().unwrap() {
                        "exit" => {
                            encode_confidential_output(&[0xe0; CONFIDENTIAL_DATA_FREE_BODY_LEN])
                                .unwrap()
                        }
                        _ => delivered_payload(&bytes(&slot["body"])),
                    },
                })
                .collect(),
            messages: vec![MessageData {
                view_tag: auditor().pubkey().u(),
                data: bytes(&case["message"]),
            }],
            nullifiers: core::iter::once(array(&case["first_nullifier"]))
                .chain((1..inputs).map(|input| [input as u8; 32]))
                .collect(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(Address::new_from_array(array(&case["ring_program_id"]))),
        };
        let head = version_3_head(slots.len(), inputs, key_escrow);
        let layout = HistoricalLayout::parse(&head, RingMode::Confidential).unwrap();
        let audited = TransactionAudit::new(&tx, AuditFrame::Historical(layout))
            .run(&auditor(), &assets)
            .unwrap();
        for (index, slot) in slots.iter().enumerate() {
            let opened = audited
                .outputs
                .iter()
                .find(|output| output.slot_index == index as u32);
            let refused = audited
                .payload_errors
                .iter()
                .find(|error| error.slot_index == index as u32);
            match (slot["kind"].as_str().unwrap(), key_escrow) {
                ("dummy", _) => assert_eq!(opened.unwrap().opening, OutputOpening::Dummy),
                (_, true) => {
                    assert_eq!(
                        refused.unwrap().kind,
                        OutputPayloadErrorKind::EscrowPending,
                        "{name} slot {index}"
                    );
                }
                (kind, false) => {
                    let utxo = opened.expect(name).opening.utxo().expect("a note");
                    assert_eq!(utxo.amount.to_string(), slot["amount"].to_string());
                    assert_eq!(utxo.owner_key, array::<32>(&slot["owner_key"]));
                    assert_eq!(
                        kind == "exit",
                        matches!(opened.unwrap().opening, OutputOpening::Exit(_))
                    );
                }
            }
        }
        let evidence = &bytes(&case["envelope_plaintext"])[32..];
        for (input, hash) in audited.inputs.iter().zip(evidence.chunks(32)) {
            assert_eq!(
                input.opening,
                match hash == [0; 32] {
                    true => InputOpening::Dummy,
                    false => InputOpening::Real,
                },
                "{name}"
            );
        }
    }
}

#[test]
fn every_version_3_anonymous_stream_opens_and_its_hash_evidence_reads_as_spent_notes() {
    let vector: Value = serde_json::from_str(ANONYMOUS_V3).unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let slots = case["slots"].as_array().unwrap();
        let inputs = case["inputs"].as_array().unwrap();
        let entry = case["layout"].as_u64().unwrap() & 8 != 0;
        let tree_id = case["output_tree_id"].as_u64().unwrap() as u16;
        let tx = ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: Some(
                ViewingKey::from_canonical_bytes(&array(&case["tx_viewing_sk"]))
                    .unwrap()
                    .pubkey(),
            ),
            salt: Some(array(&case["salt"])),
            output_slots: slots
                .iter()
                .enumerate()
                .map(|(leaf, slot)| OutputSlot {
                    view_tag: array(&slot["owner_tag"]),
                    output_context: OutputContext {
                        hash: array(&slot["output_hash"]),
                        tree_id,
                        leaf_index: leaf as u64,
                    },
                    payload: match slot["kind"].as_str().unwrap() {
                        "exit" => {
                            encode_confidential_output(&[0xe0; CONFIDENTIAL_DATA_FREE_BODY_LEN])
                                .unwrap()
                        }
                        _ => Vec::new(),
                    },
                })
                .collect(),
            messages: vec![MessageData {
                view_tag: auditor().pubkey().u(),
                data: bytes(&case["message"]),
            }],
            nullifiers: inputs
                .iter()
                .map(|input| array(&input["nullifier"]))
                .collect(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(Address::new_from_array(array(&case["ring_program_id"]))),
        };
        let head = anonymous_head(slots.len(), inputs.len(), entry);
        let layout = HistoricalLayout::parse(&head, RingMode::Anonymous).unwrap();
        let trees = vec![Some(tree_id); inputs.len()];
        let audited = TransactionAudit::new(&tx, AuditFrame::Historical(layout))
            .with_input_trees(&trees)
            .unwrap()
            .run(&auditor(), &held_assets(slots))
            .unwrap();
        assert!(audited.payload_errors.is_empty(), "{name}");
        assert_eq!(audited.outputs.len(), slots.len(), "{name}");
        for (output, slot) in audited.outputs.iter().zip(slots) {
            match slot["kind"].as_str().unwrap() {
                "dummy" => assert_eq!(output.opening, OutputOpening::Dummy, "{name}"),
                _ => {
                    let utxo = output.opening.utxo().expect(name);
                    assert_eq!(utxo.nullifier_pk, array::<32>(&slot["nullifier_pk"]));
                    assert_eq!(
                        utxo.mint,
                        Some(Address::new_from_array(array(&slot["asset_address"])))
                    );
                }
            }
        }
        for (read, input) in audited.inputs.iter().zip(inputs) {
            match input["ring"].as_str() {
                Some("default") => {
                    let opened = read.opening.default_input().expect(name);
                    assert_eq!(opened.commitment, Some(array(&input["commitment"])));
                }
                _ => assert_eq!(read.opening, InputOpening::Real, "{name}"),
            }
        }
    }
}

#[test]
fn a_version_3_head_off_every_key_or_a_row_off_its_head_is_refused() {
    let vector: Value = serde_json::from_str(DELIVERED_V3).unwrap();
    let case = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "pair_exits")
        .unwrap();
    let head = version_3_head(2, 1, true);
    let layout = HistoricalLayout::parse(&head, RingMode::Confidential).unwrap();
    let tx = ShieldedTransaction {
        slot: 1,
        tx_signature: Signature::default(),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: Some(array(&case["salt"])),
        output_slots: Vec::new(),
        messages: Vec::new(),
        nullifiers: vec![array(&case["first_nullifier"])],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    };
    assert!(TransactionAudit::new(&tx, AuditFrame::Historical(layout))
        .run(&auditor(), &RingAssets::new([]).unwrap())
        .is_err());
    assert!(
        HistoricalLayout::parse(&[tag::HISTORICAL_TRANSFER_V3], RingMode::Confidential).is_err()
    );
    let mut reserved = head;
    reserved[2] |= 1 << 7;
    assert!(HistoricalLayout::parse(&reserved, RingMode::Confidential).is_err());
}
