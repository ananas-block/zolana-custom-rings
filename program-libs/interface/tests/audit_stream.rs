//! Pins `test-vectors/audit/ring-disclosure-ranges.json` for the Go circuits and the TS SDK.

use custom_ring_interface::{
    key_catalog::{
        TransferShape, ANONYMOUS_TRANSFER_SHAPES, CONFIDENTIAL_TRANSFER_SHAPES,
        ENTRY_TRANSFER_SHAPES,
    },
    AnonymousAuditKey, AnonymousRecord, AuditEnvelope, AuditEvidence, AuditKey, AuditStreamLayout,
    CustomRingError, DeliveredBody, EntryInput, ExitRecord, RecipientBody, SenderBundle,
    ANONYMOUS_RECORD_LEN, DELIVERED_BODY_LEN, ENTRY_INPUT_LEN, ESCROWED_DELIVERED_BODY_LEN,
    ESCROWED_EXIT_RECORD_LEN, EXIT_RECORD_LEN, RECIPIENT_BODY_LEN, STREAM_BLOCK_LEN,
};
use serde_json::{json, Value};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/audit/ring-disclosure-ranges.json"
);

struct KeyCase {
    family: &'static str,
    rail: &'static str,
    key: AuditKey,
    key_escrow: bool,
    outputs: usize,
}

fn key_cases() -> Vec<KeyCase> {
    let mut cases = Vec::new();
    for shape in CONFIDENTIAL_TRANSFER_SHAPES {
        for key_escrow in [false, true] {
            cases.push(KeyCase {
                family: "confidential",
                rail: "signer_in_proof_or_authority",
                key: AuditKey::Confidential {
                    class: usize::from(shape.inputs),
                },
                key_escrow,
                outputs: usize::from(shape.outputs),
            });
        }
    }
    let anonymous = |shapes: &[TransferShape], rail, key: fn(usize) -> AnonymousAuditKey| {
        shapes
            .iter()
            .map(|shape| KeyCase {
                family: "anonymous",
                rail,
                key: AuditKey::Anonymous(key(usize::from(shape.inputs))),
                key_escrow: false,
                outputs: usize::from(shape.outputs),
            })
            .collect::<Vec<_>>()
    };
    cases.extend(anonymous(
        &ANONYMOUS_TRANSFER_SHAPES,
        "commitment",
        |class| AnonymousAuditKey::Commitment { class },
    ));
    cases.extend(anonymous(&ENTRY_TRANSFER_SHAPES, "entry", |class| {
        AnonymousAuditKey::Entry { class }
    }));
    cases
}

impl KeyCase {
    fn layout(&self, inputs: usize, exits: u64) -> AuditStreamLayout {
        AuditStreamLayout {
            key: self.key,
            key_escrow: self.key_escrow,
            inputs,
            outputs: self.outputs,
            capacity: self.outputs,
            exits,
        }
    }

    fn inputs(&self) -> impl Iterator<Item = usize> {
        1..=self.key.class()
    }

    fn vector(&self) -> Value {
        let every_exit = (1u64 << self.outputs) - 1;
        let bare = self.layout(1, 0);
        let exits = self.layout(1, every_exit);
        json!({
            "family": self.family,
            "rail": self.rail,
            "key_escrow": self.key_escrow,
            "class": self.key.class(),
            "outputs": self.outputs,
            "max_evidence_blocks": self.key.max_evidence_blocks(),
            "record_blocks": self.key.record_blocks(),
            "first_record_counter": self.key.first_record_counter(),
            "capacity_blocks": bare.capacity_blocks(),
            "ring_slot_ciphertext_len": bare.ciphertext_len(0),
            "ring_slot_record_len": bare.record_len(0),
            "exit_record_len": exits.record_len(0),
            "record_start_counters": (0..self.outputs)
                .map(|slot| bare.record(slot).start_counter)
                .collect::<Vec<_>>(),
            "envelope_len_by_input_count": self.inputs()
                .map(|inputs| self.layout(inputs, 0).envelope().len)
                .collect::<Vec<_>>(),
            "message_len_no_exit_by_input_count": self.inputs()
                .map(|inputs| self.layout(inputs, 0).message_len())
                .collect::<Vec<_>>(),
            "message_len_every_exit_by_input_count": self.inputs()
                .map(|inputs| self.layout(inputs, every_exit).message_len())
                .collect::<Vec<_>>(),
        })
    }
}

fn compute_vector() -> Value {
    json!({
        "description": "Auditor stream ranges per transfer key and layout at m = N. Regions are zero padded to 16-byte blocks: the envelope starts at counter 2 with max_evidence_blocks + 2 blocks, slot i at first_record_counter + i * record_blocks. ring_slot_ciphertext_len is the slot's ring disclosure ciphertext, a delivered body on the confidential family and a record on the anonymous family, ring_slot_record_len its bytes in the auditor message, exit_record_len an exit's record. Each by_input_count list starts at n = 1 and ends at the class, every length in bytes. message_len is 33 + envelope + records with no exit or every slot an exit. Produced by program-libs/interface/tests/audit_stream.rs.",
        "keys": key_cases().iter().map(KeyCase::vector).collect::<Vec<_>>(),
    })
}

#[test]
fn the_ranges_are_the_shared_vector() {
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vector());
}

#[test]
#[ignore = "rewrites test-vectors/audit/ring-disclosure-ranges.json"]
fn write_ring_disclosure_ranges_vector() {
    let json = serde_json::to_string_pretty(&compute_vector()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}

const fn block_bytes(blocks: usize) -> usize {
    blocks * STREAM_BLOCK_LEN
}

#[test]
fn the_contract_counts_each_family_at_its_class() {
    let confidential = |class| AuditKey::Confidential { class };
    let commitment = |class| AuditKey::Anonymous(AnonymousAuditKey::Commitment { class });
    let entry = |class| AuditKey::Anonymous(AnonymousAuditKey::Entry { class });
    for (key, evidence_blocks, record_blocks, signer_slots) in [
        (confidential(5), 10, 5, 5),
        (confidential(24), 48, 5, 24),
        (commitment(5), 10, 7, 5),
        (commitment(24), 48, 7, 24),
        // 64 + 104 * 2 and 64 + 104 * 8 bytes.
        (entry(2), 17, 7, 0),
        (entry(8), 56, 7, 0),
    ] {
        assert_eq!(key.max_evidence_blocks(), evidence_blocks, "{key:?}");
        assert_eq!(key.record_blocks(), record_blocks, "{key:?}");
        assert_eq!(key.signer_slots(), signer_slots, "{key:?}");
        assert_eq!(
            key.first_record_counter() as usize,
            2 + 2 + evidence_blocks,
            "{key:?}"
        );
    }
}

/// Every region of every key at every `n`, in counter order with no shared counter.
#[test]
fn no_counter_serves_two_regions_and_every_region_holds_its_bytes() {
    for case in key_cases() {
        for inputs in case.inputs() {
            let every_exit = (1u64 << case.outputs) - 1;
            for exits in [0, 1, every_exit] {
                let layout = case.layout(inputs, exits);
                assert_eq!(layout.checked(), Ok(layout));
                let envelope = layout.envelope();
                assert_eq!(envelope.start_counter, 2);
                assert_eq!(envelope.keystream_offset(), 0);
                assert!(envelope.len <= block_bytes(envelope.max_blocks));
                let mut next = envelope.start_counter as usize + envelope.max_blocks;
                assert_eq!(next, layout.first_record_counter() as usize);
                for slot in 0..case.outputs {
                    let record = layout.record(slot);
                    assert_eq!(record.start_counter as usize, next);
                    assert_eq!(record.max_blocks, layout.record_blocks());
                    assert!(record.len <= block_bytes(record.max_blocks));
                    assert_eq!(
                        record.keystream_offset(),
                        block_bytes(next - layout.envelope().start_counter as usize)
                    );
                    next += record.max_blocks;
                }
                assert_eq!(next - 2, layout.capacity_blocks());
            }
        }
    }
}

/// A key's widest evidence fills its reserved blocks up to the last, one more input crosses into the records.
#[test]
fn the_input_past_the_class_would_cross_into_the_records_and_is_refused() {
    for case in key_cases() {
        let class = case.key.class();
        let widest = case.layout(class, 0).envelope();
        assert!(widest.len > block_bytes(widest.max_blocks - 1));
        let past = case.layout(class + 1, 0);
        assert_eq!(past.checked(), Err(CustomRingError::RingTransactLength));
        assert!(past.envelope().len > block_bytes(past.envelope().max_blocks));
        assert_eq!(
            case.layout(0, 0).checked(),
            Err(CustomRingError::RingTransactLength)
        );
    }
}

/// The largest record of a family takes its last block, one byte more would enter the next slot's range.
#[test]
fn the_record_that_would_cross_a_range_is_refused() {
    assert_eq!(ANONYMOUS_RECORD_LEN.div_ceil(STREAM_BLOCK_LEN), 7);
    assert_eq!(EXIT_RECORD_LEN.div_ceil(STREAM_BLOCK_LEN), 5);
    for (record, blocks) in [(ANONYMOUS_RECORD_LEN, 7), (EXIT_RECORD_LEN, 5)] {
        assert!(record > block_bytes(blocks - 1));
    }
    let over = [0; block_bytes(7) + 1];
    assert!(AnonymousRecord::decode(&over).is_err());
    assert!(AnonymousRecord::decode(&over[..ANONYMOUS_RECORD_LEN + 1]).is_err());
    assert!(AnonymousRecord::decode(&over[..ANONYMOUS_RECORD_LEN - 1]).is_err());
    assert!(ExitRecord::decode(&over[..EXIT_RECORD_LEN + 1], false).is_err());
    assert!(ExitRecord::decode(&over[..EXIT_RECORD_LEN], true).is_err());
    assert!(ExitRecord::decode(&over[..ESCROWED_EXIT_RECORD_LEN], false).is_err());
    assert!(DeliveredBody::decode(&over[..DELIVERED_BODY_LEN], true).is_err());
    assert!(DeliveredBody::decode(&over[..ESCROWED_DELIVERED_BODY_LEN], false).is_err());
    assert!(DeliveredBody::decode(&over[..DELIVERED_BODY_LEN + 1], false).is_err());
}

#[test]
fn slot_kinds_take_their_contract_lengths() {
    let layout = |key, key_escrow, exits| AuditStreamLayout {
        key,
        key_escrow,
        inputs: 1,
        outputs: 4,
        capacity: 4,
        exits,
    };
    let confidential = AuditKey::Confidential { class: 8 };
    let anonymous = AuditKey::Anonymous(AnonymousAuditKey::Commitment { class: 8 });
    let open = layout(confidential, false, 0b0010);
    let escrowed = layout(confidential, true, 0b0010);
    assert_eq!(open.ciphertext_len(0), 104);
    assert_eq!(open.record_len(0), 0);
    assert_eq!(open.ciphertext_len(1), 72);
    assert_eq!(open.record_len(1), 72);
    assert_eq!(escrowed.ciphertext_len(0), 72);
    assert_eq!(escrowed.ciphertext_len(1), 40);
    assert_eq!(open.records_len(), 72);
    assert_eq!(open.record(0).len, 0);
    let hidden = layout(anonymous, false, 0b0100);
    assert_eq!(hidden.ciphertext_len(0), 104);
    assert_eq!(hidden.record_len(0), 104);
    assert_eq!(hidden.record_len(2), 72);
    assert_eq!(hidden.records_len(), 3 * 104 + 72);
    assert_eq!(hidden.record_len(4), 0);
    assert_eq!(hidden.ciphertext_len(4), 0);
    assert_eq!(hidden.message_len(), 33 + 32 + 32 + 3 * 104 + 72);
    assert_eq!(
        layout(anonymous, false, 1 << 4).checked(),
        Err(CustomRingError::RingTransactLength)
    );
}

/// An omitted suffix leaves the frame, the stream still spans `N` so no slot's counter moves.
#[test]
fn a_compact_frame_keeps_every_counter_and_drops_the_suffix_records() {
    let key = AuditKey::Anonymous(AnonymousAuditKey::Commitment { class: 16 });
    let layout = |outputs| AuditStreamLayout {
        key,
        key_escrow: false,
        inputs: 1,
        outputs,
        capacity: 4,
        exits: 0,
    };
    let (compact, full) = (layout(2), layout(4));
    assert_eq!(compact.capacity_blocks(), full.capacity_blocks());
    assert_eq!(compact.record(1), full.record(1));
    assert_eq!(compact.record_len(2), 0);
    assert_eq!(compact.records_len(), 2 * ANONYMOUS_RECORD_LEN);
    for refused in [layout(0), layout(5)] {
        assert_eq!(refused.checked(), Err(CustomRingError::RingTransactLength));
    }
}

#[test]
fn the_anonymous_plaintexts_lay_out_their_contract_bytes() {
    let body = RecipientBody {
        blinding: [1; 32],
        amount: 0x0102_0304_0506_0708,
        mint: [2; 32],
    };
    let encoded = body.encode();
    assert_eq!(encoded.len(), RECIPIENT_BODY_LEN);
    assert_eq!(encoded[32..40], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(RecipientBody::decode(&encoded), Ok(body));
    assert!(RecipientBody::decode(&encoded[..71]).is_err());
    let bundle = SenderBundle {
        mint: [3; 32],
        amount: 5,
        sol_amount: 6,
        output_seed: [4; 32],
        recipient_keys: vec![[0; 32], [7; 32], [8; 32]],
    };
    let encoded = bundle.encode();
    assert_eq!(encoded.len(), custom_ring_interface::sender_bundle_len(3));
    assert_eq!(encoded.capacity(), encoded.len());
    assert_eq!(encoded[32..40], 5u64.to_be_bytes());
    assert_eq!(encoded[40..48], 6u64.to_be_bytes());
    assert_eq!(SenderBundle::decode(&encoded, 3).as_ref(), Ok(&bundle));
    assert!(SenderBundle::decode(&encoded, 2).is_err());
}

#[test]
fn plaintexts_read_back_at_their_lengths() {
    let delivered = DeliveredBody {
        blinding: [1; 32],
        amount: 0x0102_0304_0506_0708,
        owner_key: [2; 32],
        nullifier_pk: Some([3; 32]),
    };
    let encoded = delivered.encode();
    assert_eq!(encoded.len(), DELIVERED_BODY_LEN);
    assert_eq!(encoded.capacity(), encoded.len());
    assert_eq!(encoded[32..40], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(DeliveredBody::decode(&encoded, false), Ok(delivered));
    let escrowed = DeliveredBody {
        nullifier_pk: None,
        ..delivered
    };
    assert_eq!(escrowed.encode().len(), ESCROWED_DELIVERED_BODY_LEN);
    assert_eq!(
        DeliveredBody::decode(&escrowed.encode(), true),
        Ok(escrowed)
    );

    let anonymous = AnonymousRecord {
        owner_key: [4; 32],
        asset: [5; 32],
        amount: 9,
        nullifier_pk: [6; 32],
    };
    assert_eq!(anonymous.encode().len(), ANONYMOUS_RECORD_LEN);
    assert_eq!(AnonymousRecord::decode(&anonymous.encode()), Ok(anonymous));
    assert_eq!(
        AnonymousRecord::default().encode(),
        vec![0; ANONYMOUS_RECORD_LEN]
    );

    let exit = ExitRecord {
        asset: [7; 32],
        amount: 11,
        nullifier_pk: Some([8; 32]),
    };
    assert_eq!(exit.encode().len(), EXIT_RECORD_LEN);
    assert_eq!(ExitRecord::decode(&exit.encode(), false), Ok(exit));
    let escrowed_exit = ExitRecord {
        nullifier_pk: None,
        ..exit
    };
    assert_eq!(escrowed_exit.encode().len(), ESCROWED_EXIT_RECORD_LEN);
    assert_eq!(
        ExitRecord::decode(&escrowed_exit.encode(), true),
        Ok(escrowed_exit)
    );
}

#[test]
fn envelopes_read_back_at_their_layout_length() {
    let tx_viewing_secret = [0x33; 32];
    let entry_input = EntryInput {
        hash: [0x45; 32],
        amount: 5,
        asset: [0x43; 32],
        blinding: [0x44; 32],
    };
    assert_eq!(ENTRY_INPUT_LEN, 104);
    let hashes = AuditEvidence::InputHashes(vec![[0x21; 32], [0; 32], [0x23; 32]]);
    let cases = [
        (AuditKey::Confidential { class: 8 }, 3, hashes.clone(), 96),
        (
            AuditKey::Anonymous(AnonymousAuditKey::Commitment { class: 8 }),
            3,
            hashes,
            96,
        ),
        (
            AuditKey::Anonymous(AnonymousAuditKey::Entry { class: 8 }),
            2,
            AuditEvidence::Entry {
                sender_key: [0x41; 32],
                sender_nullifier_pk: [0x42; 32],
                inputs: vec![entry_input, EntryInput::default()],
            },
            64 + 208,
        ),
    ];
    for (key, inputs, evidence, evidence_len) in cases {
        let layout = AuditStreamLayout {
            key,
            key_escrow: false,
            inputs,
            outputs: 2,
            capacity: 2,
            exits: 0,
        };
        let envelope = AuditEnvelope {
            tx_viewing_secret,
            evidence,
        };
        let encoded = envelope.encode();
        assert_eq!(encoded.len(), 32 + evidence_len, "{key:?}");
        assert_eq!(encoded.capacity(), encoded.len(), "{key:?}");
        assert_eq!(encoded.len(), layout.envelope().len, "{key:?}");
        assert_eq!(
            AuditEnvelope::decode(&encoded, layout),
            Ok(envelope),
            "{key:?}"
        );
        let longer = [&encoded[..], &[0]].concat();
        assert!(AuditEnvelope::decode(&longer, layout).is_err(), "{key:?}");
        assert!(
            AuditEnvelope::decode(&encoded[..encoded.len() - 1], layout).is_err(),
            "{key:?}"
        );
    }
}
