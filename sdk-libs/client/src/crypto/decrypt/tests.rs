use std::collections::HashMap;

use custom_ring_interface::{
    domain::AUDIT_STREAM_LABEL, encode_confidential_output, RingMode,
    CONFIDENTIAL_DATA_FREE_BODY_LEN, STREAM_FIRST_COUNTER,
};
use spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;
use spr_keypair::NullifierKey;
use spr_transaction::{Mint, OutputContext};

use super::{
    historical::{HistoricalLayout, KEY_ESCROW},
    *,
};
use crate::{
    encryption::sealing_ring_stream,
    types::{AwaitingKeyOutput, OutputPayloadError},
};

const RING: Address = Address::new_from_array([0x90; 32]);
const TREE: u16 = 9;
const MINT: Address = Address::new_from_array([0x0a; 32]);

fn field(byte: u8) -> [u8; 32] {
    let mut out = [byte; 32];
    out[0] = 0;
    out
}

fn assets() -> RingAssets {
    RingAssets::new([Mint::new(MINT, 7)]).unwrap()
}

fn commitment_layout() -> HistoricalLayout {
    let shape = spr_interface::shape::SPP_SUPPORTED_SHAPES
        .iter()
        .position(|shape| shape.n_outputs() == 4)
        .unwrap();
    let head = [
        custom_ring_interface::tag::HISTORICAL_TRANSFER_V3,
        0,
        shape as u8,
        1,
        1,
    ];
    HistoricalLayout::parse(&head, RingMode::Anonymous).unwrap()
}

struct Row {
    tx_key: ViewingKey,
    transfer: Transfer,
    salt: [u8; 16],
    first_nullifier: [u8; 32],
}

fn row() -> Row {
    let tx_key = ViewingKey::from_bytes(&[3; 32]);
    let salt = [5; 16];
    let first_nullifier = field(6);
    Row {
        transfer: Transfer::new(RING, first_nullifier, &tx_key, &salt).unwrap(),
        tx_key,
        salt,
        first_nullifier,
    }
}

impl Row {
    fn record_note(&self, slot: u32, nullifier_pk: [u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let asset = hash_bytes(MINT.as_array()).unwrap();
        let blinding =
            derive_transact_output_blinding(&self.first_nullifier, &self.transfer.seed_out, slot)
                .unwrap();
        let utxo = AuditedUtxo {
            owner_key: [0xb1; 32],
            nullifier_pk,
            asset,
            mint: Some(MINT),
            amount: 12,
            blinding,
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
        };
        let record = [
            &utxo.owner_key[..],
            &asset,
            &12u64.to_be_bytes(),
            &nullifier_pk,
        ]
        .concat();
        (record, utxo.commitment(TREE, Some(RING)).unwrap())
    }

    fn publish(
        &self,
        auditor: &X25519Keypair,
        layout: HistoricalLayout,
        evidence: &[u8],
        slots: Vec<(Vec<u8>, [u8; 32], Vec<u8>)>,
    ) -> ShieldedTransaction {
        let ephemeral = X25519Keypair::new();
        let stream =
            sealing_ring_stream(&ephemeral, &auditor.pubkey(), AUDIT_STREAM_LABEL).unwrap();
        let mut envelope = [&self.tx_key.secret_bytes()[..], evidence].concat();
        stream.apply_at(STREAM_FIRST_COUNTER, &mut envelope);
        let mut data = [
            &custom_ring_interface::tagged_x25519(&ephemeral.pubkey().u())[..],
            &envelope,
        ]
        .concat();
        let mut output_slots = Vec::new();
        for (index, (mut record, hash, payload)) in slots.into_iter().enumerate() {
            let counter = layout.key.first_record_counter()
                + index as u32 * layout.key.record_blocks() as u32;
            stream.apply_at(counter, &mut record);
            data.extend_from_slice(&record);
            output_slots.push(OutputSlot {
                view_tag: field(0x31 + index as u8),
                output_context: OutputContext {
                    hash,
                    tree_id: TREE,
                    leaf_index: index as u64,
                },
                payload,
            });
        }
        ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: Some(self.tx_key.pubkey()),
            salt: Some(self.salt),
            output_slots,
            messages: vec![MessageData {
                view_tag: auditor.pubkey().u(),
                data,
            }],
            nullifiers: vec![self.first_nullifier],
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }
}

#[test]
fn a_version_3_record_opens_and_its_hash_evidence_reads_as_a_spent_note() {
    let auditor = X25519Keypair::new();
    let row = row();
    let layout = commitment_layout();
    let (record, hash) = row.record_note(0, field(0x20));
    let tx = row.publish(
        &auditor,
        layout,
        &field(0x60),
        vec![(record, hash, Vec::new())],
    );
    let audited = TransactionAudit::new(&tx, AuditFrame::Historical(layout))
        .run(&auditor, &assets())
        .unwrap();
    let OutputOpening::Ring { utxo, .. } = &audited.outputs[0].opening else {
        panic!("a ring note")
    };
    assert_eq!(utxo.nullifier_pk, field(0x20));
    assert_eq!(utxo.mint, Some(MINT));
    assert_eq!(audited.real_inputs, 1);
    assert_eq!(audited.inputs[0].opening, InputOpening::Real);
}

#[test]
fn a_version_3_read_refuses_a_foreign_key_a_changed_record_and_a_hash_off_the_field() {
    let auditor = X25519Keypair::new();
    let row = row();
    let layout = commitment_layout();
    let (record, hash) = row.record_note(0, field(0x20));
    let run = |tx: &ShieldedTransaction| {
        TransactionAudit::new(tx, AuditFrame::Historical(layout)).run(&auditor, &assets())
    };
    // A nullifier key off the commitment rebuilds another note.
    let (other, _) = row.record_note(0, field(0x21));
    let forged = row.publish(
        &auditor,
        layout,
        &field(0x60),
        vec![(other, hash, Vec::new())],
    );
    assert_eq!(
        run(&forged).unwrap().payload_errors,
        [OutputPayloadError {
            slot_index: 0,
            kind: OutputPayloadErrorKind::Commitment,
        }]
    );
    let off_field = row.publish(
        &auditor,
        layout,
        &BN254_SCALAR_MODULUS_BE,
        vec![(record.clone(), hash, Vec::new())],
    );
    assert!(matches!(run(&off_field), Err(AuditError::DisclosureField)));
    let mut wrong_key = row.publish(
        &auditor,
        layout,
        &field(0x60),
        vec![(record, hash, Vec::new())],
    );
    wrong_key.tx_viewing_pk = Some(ViewingKey::new().pubkey());
    assert!(matches!(
        run(&wrong_key),
        Err(AuditError::TxViewingKeyMismatch)
    ));
}

/// Only the zero candidate can rebuild an escrowed exit.
#[test]
fn a_version_3_escrowed_slot_reports_its_missing_key_by_name() {
    let auditor = X25519Keypair::new();
    let row = row();
    let shape = spr_interface::shape::SPP_SUPPORTED_SHAPES
        .iter()
        .position(|shape| shape.n_outputs() == 2)
        .unwrap();
    let head = [
        custom_ring_interface::tag::HISTORICAL_TRANSFER_V3,
        0,
        shape as u8,
        1 | KEY_ESCROW,
        1,
    ];
    let layout = HistoricalLayout::parse(&head, RingMode::Confidential).unwrap();
    assert!(layout.key_escrow);
    let exit_record = [
        &hash_bytes(MINT.as_array()).unwrap()[..],
        &12u64.to_be_bytes(),
    ]
    .concat();
    let payload = encode_confidential_output(&[0xe0; CONFIDENTIAL_DATA_FREE_BODY_LEN]).unwrap();
    let tx = row.publish(
        &auditor,
        layout,
        &field(0x60),
        vec![(exit_record, field(0x71), payload)],
    );
    let audited = TransactionAudit::new(&tx, AuditFrame::Historical(layout))
        .run(&auditor, &assets())
        .unwrap();
    assert_eq!(
        audited.payload_errors,
        [OutputPayloadError {
            slot_index: 0,
            kind: OutputPayloadErrorKind::EscrowPending,
        }]
    );
}

/// One row of the historical vector and the amounts its encoder sealed.
type BaseFrame = (String, ShieldedTransaction, Vec<u8>, Vec<Option<u64>>);

fn base_frames() -> Vec<BaseFrame> {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../test-vectors/historical/frames_v3.json"
    ))
    .unwrap();
    let bytes = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
    let field = |value: &serde_json::Value| -> [u8; 32] { bytes(value).try_into().unwrap() };
    vector["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let tx = ShieldedTransaction {
                slot: 1,
                tx_signature: solana_signature::Signature::default(),
                event_index: Some(0),
                tx_viewing_pk: Some(
                    X25519Pubkey::from_bytes(bytes(&row["tx_viewing_pk"]).try_into().unwrap())
                        .unwrap(),
                ),
                salt: Some(bytes(&row["salt"]).try_into().unwrap()),
                output_slots: row["slots"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|slot| spr_transaction::OutputSlot {
                        view_tag: field(&slot["view_tag"]),
                        output_context: OutputContext {
                            hash: field(&slot["hash"]),
                            tree_id: slot["tree_id"].as_u64().unwrap() as u16,
                            leaf_index: slot["leaf"].as_u64().unwrap(),
                        },
                        payload: bytes(&slot["payload"]),
                    })
                    .collect(),
                messages: row["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|message| MessageData {
                        view_tag: field(&message["view_tag"]),
                        data: bytes(&message["data"]),
                    })
                    .collect(),
                nullifiers: row["nullifiers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(field)
                    .collect(),
                proofless: false,
                ring_config: None,
                ring_program_id: Some(Address::new_from_array(field(&row["ring_program_id"]))),
            };
            let amounts = row["expected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|note| note.get("amount").and_then(serde_json::Value::as_u64))
                .collect();
            (
                row["name"].as_str().unwrap().to_owned(),
                tx,
                bytes(&row["frame"]),
                amounts,
            )
        })
        .collect()
}

fn base_auditor() -> X25519Keypair {
    let mut secret: [u8; 32] = core::array::from_fn(|index| 0x33 ^ index as u8);
    secret[0] = 0x01;
    X25519Keypair::from_bytes(&secret)
}

fn audit_base(
    tx: &ShieldedTransaction,
    frame: &[u8],
    mode: RingMode,
    keys: Option<&dyn EscrowedKeys>,
) -> AuditedTransaction {
    let layout = HistoricalLayout::parse(frame, mode).unwrap();
    let trees = vec![Some(9); tx.nullifiers.len()];
    let audit = TransactionAudit::new(tx, AuditFrame::Historical(layout))
        .with_input_trees(&trees)
        .unwrap();
    let audit = match keys {
        Some(keys) => audit.with_escrowed_keys(keys),
        None => audit,
    };
    audit.run(&base_auditor(), &assets()).unwrap()
}

fn opened_amounts(audited: &AuditedTransaction) -> Vec<u64> {
    audited
        .outputs
        .iter()
        .filter_map(|output| match &output.opening {
            OutputOpening::Ring { utxo, .. } | OutputOpening::Exit(utxo) => Some(utxo.amount),
            OutputOpening::Dummy => None,
        })
        .collect()
}

#[test]
fn frames_the_base_commit_sealed_still_open() {
    for (name, tx, frame, amounts) in base_frames() {
        let mode = match name.as_str() {
            "delivered" | "authority" | "escrowed_keyed" => RingMode::Confidential,
            _ => RingMode::Anonymous,
        };
        if name == "escrowed_keyed" {
            continue;
        }
        let audited = audit_base(&tx, &frame, mode, None);
        assert!(audited.payload_errors.is_empty(), "{name}");
        assert_eq!(
            opened_amounts(&audited),
            amounts.into_iter().flatten().collect::<Vec<_>>(),
            "{name}"
        );
    }
}

/// A key the commitment refuses names no note, the slot stays with its waiting owner.
#[test]
fn an_escrowed_note_opens_only_under_the_key_its_commitment_holds() {
    let frames = base_frames();
    let (_, tx, frame, _) = frames
        .iter()
        .find(|(name, ..)| name == "escrowed_keyed")
        .unwrap();
    let owner = [0xb0; 32];
    let audit =
        |keys: Option<&dyn EscrowedKeys>| audit_base(tx, frame, RingMode::Confidential, keys);
    let pending = |audited: &AuditedTransaction| {
        assert_eq!(
            audited.payload_errors,
            [0, 2].map(|slot_index| OutputPayloadError {
                slot_index,
                kind: OutputPayloadErrorKind::EscrowPending,
            })
        );
        assert_eq!(
            audited.awaiting_key,
            [0, 2].map(|slot: usize| AwaitingKeyOutput {
                owner_key: owner,
                commitment: tx.output_slots[slot].output_context.hash,
            })
        );
        assert_eq!(opened_amounts(audited), [11]);
    };
    pending(&audit(None));
    let wrong = HashMap::from([(owner, NullifierKey::from_secret([8; 31]).pubkey().unwrap())]);
    pending(&audit(Some(&wrong)));

    let right = HashMap::from([(owner, NullifierKey::from_secret([7; 31]).pubkey().unwrap())]);
    let opened = audit(Some(&right));
    assert!(opened.payload_errors.is_empty());
    assert!(opened.awaiting_key.is_empty());
    assert_eq!(opened_amounts(&opened), [10, 11, 12]);
}
