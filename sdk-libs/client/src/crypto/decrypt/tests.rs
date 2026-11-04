use custom_ring_interface::{
    domain::AUDIT_STREAM_LABEL, encode_confidential_output, RingMode,
    CONFIDENTIAL_DATA_FREE_BODY_LEN, STREAM_FIRST_COUNTER,
};
use spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;
use spr_transaction::{Mint, OutputContext};

use super::{
    historical::{HistoricalLayout, KEY_ESCROW},
    *,
};
use crate::encryption::sealing_ring_stream;

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
