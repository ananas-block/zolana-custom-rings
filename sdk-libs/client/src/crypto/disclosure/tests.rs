use custom_ring_interface::{
    AuditEvidence, AuditKey, AuditRecord, AuditStreamLayout, DataTail, EntryInput, RecordKind,
};
use spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;

use super::*;

const SALT: [u8; 16] = [7; 16];

fn field(byte: u8) -> [u8; 32] {
    let mut field = [byte; 32];
    field[0] = 0;
    field
}

fn plain_layout() -> AuditStreamLayout {
    AuditStreamLayout {
        key: AuditKey {
            class: 2,
            entry: false,
        },
        inputs: 1,
        outputs: 2,
        capacity: 2,
        has_data: false,
    }
}

fn entry_layout() -> AuditStreamLayout {
    AuditStreamLayout {
        key: AuditKey {
            class: 8,
            entry: true,
        },
        inputs: 2,
        outputs: 2,
        capacity: 2,
        has_data: false,
    }
}

fn data_layout() -> AuditStreamLayout {
    AuditStreamLayout {
        has_data: true,
        ..plain_layout()
    }
}

fn ring_record(byte: u8) -> AuditRecord {
    AuditRecord {
        kind: RecordKind::Ring,
        amount: u64::from(byte),
        owner_key: [byte; 32],
        mint: [byte ^ 1; 32],
        nullifier_pk: field(byte),
    }
}

fn entry_evidence() -> AuditEvidence {
    AuditEvidence::Entry {
        default_input_bits: 0b01,
        inputs: vec![
            EntryInput {
                owner_key: [0xa1; 32],
                nullifier_pk: field(0x5a),
                amount: 5000,
                mint: [0x60; 32],
                blinding: field(0x61),
                data_hash: [0; 32],
                ring_data_hash: [0; 32],
            },
            EntryInput::default(),
        ],
    }
}

fn opened_envelope(
    sealed: &SealedAuditStream,
    auditor: &X25519Keypair,
    layout: AuditStreamLayout,
) -> Result<OpenedAudit, AuditError> {
    AuditEnvelope {
        eph_u: sealed.eph_u,
        salt: &SALT,
        ciphertext: &sealed.envelope,
    }
    .open(auditor, layout)
}

/// Seals raw bytes as the envelope plaintext, no clamping runs on the way in.
fn raw_envelope(plaintext: &[u8], auditor: &X25519Keypair) -> SealedAuditStream {
    let ephemeral = X25519Keypair::new();
    let mut envelope = plaintext.to_vec();
    sealing_salted_stream(&ephemeral, &auditor.pubkey(), &SALT, AUDIT_STREAM_LABEL)
        .unwrap()
        .apply_at(STREAM_FIRST_COUNTER, &mut envelope);
    SealedAuditStream {
        eph_u: ephemeral.pubkey().u(),
        envelope,
        records: Vec::new(),
        tails: Vec::new(),
    }
}

#[test]
fn the_envelope_opens_to_the_sealed_key_and_a_resend_seals_another_stream() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let seal = |salt: &[u8; 16]| {
        AuditStreamSeal {
            layout: plain_layout(),
            tx_viewing_key: &tx_viewing_key,
            salt,
            real_inputs: 1,
            evidence: AuditEvidence::None,
            records: vec![ring_record(1), AuditRecord::default()],
            tails: Vec::new(),
        }
        .seal(&auditor.pubkey())
        .unwrap()
    };
    let first = seal(&SALT);
    assert_eq!(first.eph_u, tx_viewing_key.pubkey().u());
    assert_ne!(first.envelope, seal(&[8; 16]).envelope);
    let opened = opened_envelope(&first, &auditor, plain_layout()).unwrap();
    assert_eq!(opened.tx_viewing_key.pubkey(), tx_viewing_key.pubkey());
    assert_eq!(opened.real_inputs, 1);
    assert_eq!(opened.evidence, AuditEvidence::None);
    assert!(first.tails.is_empty());
}

#[test]
fn an_unclamped_envelope_secret_is_refused() {
    let auditor = X25519Keypair::new();
    let canonical = ViewingKey::new();
    let mut unclamped = *canonical.secret_bytes();
    unclamped[0] |= 0b111;
    let sealed = raw_envelope(&[&unclamped[..], &[1]].concat(), &auditor);
    assert!(matches!(
        opened_envelope(&sealed, &auditor, plain_layout()),
        Err(AuditError::NonCanonicalViewingKey)
    ));
    let sealed = raw_envelope(&[&canonical.secret_bytes()[..], &[1]].concat(), &auditor);
    assert_eq!(
        opened_envelope(&sealed, &auditor, plain_layout())
            .unwrap()
            .tx_viewing_key
            .pubkey(),
        canonical.pubkey()
    );
}

/// Each record sits at its own counter, read at another it opens to other bytes.
#[test]
fn a_record_opens_only_at_the_counter_of_its_slot() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let record = ring_record(0x15);
    let sealed = AuditStreamSeal {
        layout: plain_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        real_inputs: 1,
        evidence: AuditEvidence::None,
        records: vec![record, AuditRecord::default()],
        tails: Vec::new(),
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, plain_layout()).unwrap();
    assert_eq!(opened.record(0, &sealed.records[0]).unwrap(), record);
    assert_eq!(
        opened.record(1, &sealed.records[1]).unwrap(),
        AuditRecord::default()
    );
    assert!(!matches!(
        opened.record(1, &sealed.records[0]),
        Ok(moved) if moved == record
    ));
}

#[test]
fn a_tail_opens_only_at_the_counter_of_its_slot() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let tail = DataTail {
        data_hash: field(0x31),
        ring_data_hash: field(0x32),
    };
    let sealed = AuditStreamSeal {
        layout: data_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        real_inputs: 1,
        evidence: AuditEvidence::None,
        records: vec![ring_record(1), AuditRecord::default()],
        tails: vec![tail, DataTail::default()],
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, data_layout()).unwrap();
    assert_eq!(opened.tail(0, &sealed.tails[0]).unwrap(), tail);
    assert_eq!(
        opened.tail(1, &sealed.tails[1]).unwrap(),
        DataTail::default()
    );
    assert_ne!(opened.tail(1, &sealed.tails[0]).unwrap(), tail);
}

#[test]
fn the_entry_evidence_and_records_round_their_own_regions() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let sealed = AuditStreamSeal {
        layout: entry_layout(),
        tx_viewing_key: &tx_viewing_key,
        salt: &SALT,
        real_inputs: 1,
        evidence: entry_evidence(),
        records: vec![AuditRecord::default(), ring_record(0x27)],
        tails: Vec::new(),
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, entry_layout()).unwrap();
    assert_eq!(opened.evidence, entry_evidence());
    assert_eq!(
        opened.record(0, &sealed.records[0]).unwrap(),
        AuditRecord::default()
    );
    assert_eq!(
        opened.record(1, &sealed.records[1]).unwrap(),
        ring_record(0x27)
    );
}

#[test]
fn a_seal_off_its_layout_is_refused() {
    let auditor = X25519Keypair::new().pubkey();
    let tx_viewing_key = ViewingKey::new();
    let seal = |layout, evidence, records, tails| {
        AuditStreamSeal {
            layout,
            tx_viewing_key: &tx_viewing_key,
            salt: &SALT,
            real_inputs: 1,
            evidence,
            records,
            tails,
        }
        .seal(&auditor)
    };
    let two = vec![AuditRecord::default(); 2];
    let tail = DataTail::default();
    let cases = [
        (
            plain_layout(),
            AuditEvidence::None,
            vec![AuditRecord::default()],
            vec![],
        ),
        (plain_layout(), entry_evidence(), two.clone(), vec![]),
        (plain_layout(), AuditEvidence::None, two.clone(), vec![tail]),
        (data_layout(), AuditEvidence::None, two.clone(), vec![tail]),
        (entry_layout(), AuditEvidence::None, two, vec![]),
    ];
    for (layout, evidence, records, tails) in cases {
        assert!(matches!(
            seal(layout, evidence, records, tails),
            Err(AuditError::DisclosureLayout)
        ));
    }
}

/// The proof binds canonical evidence, bytes it cannot have bound stop the audit.
#[test]
fn evidence_outside_the_field_is_refused() {
    let auditor = X25519Keypair::new();
    let secret = *ViewingKey::new().secret_bytes();
    let plaintext = |evidence: AuditEvidence| {
        custom_ring_interface::AuditEnvelope {
            tx_viewing_secret: secret,
            real_inputs: 1,
            evidence,
        }
        .encode()
    };
    type Spoil = fn(&mut EntryInput);
    let spoiled: [Spoil; 4] = [
        |input| input.nullifier_pk = BN254_SCALAR_MODULUS_BE,
        |input| input.blinding = BN254_SCALAR_MODULUS_BE,
        |input| input.data_hash = BN254_SCALAR_MODULUS_BE,
        |input| input.ring_data_hash = BN254_SCALAR_MODULUS_BE,
    ];
    for spoil in spoiled {
        let mut entry = entry_evidence();
        let AuditEvidence::Entry { inputs, .. } = &mut entry else {
            unreachable!("the entry evidence");
        };
        spoil(&mut inputs[1]);
        let sealed = raw_envelope(&plaintext(entry), &auditor);
        assert!(matches!(
            opened_envelope(&sealed, &auditor, entry_layout()),
            Err(AuditError::DisclosureField)
        ));
    }
    let sealed = raw_envelope(&plaintext(entry_evidence()), &auditor);
    assert!(opened_envelope(&sealed, &auditor, entry_layout()).is_ok());
}

#[test]
fn the_merge_pad_masks_every_field_and_unmasks_to_the_plaintext() {
    let pad = DisclosurePad::keyed(&field(1), &[2; 32], &[3; 16]).unwrap();
    let plaintext = [field(4), field(5)];
    let published = pad.encrypt(&plaintext).unwrap();
    assert_ne!(published[0], plaintext[0]);
    assert_ne!(
        published[0], published[1],
        "each index draws its own pad value"
    );
    assert_eq!(pad.decrypt(&published).unwrap(), plaintext);
    assert!(matches!(
        pad.encrypt(&[BN254_SCALAR_MODULUS_BE]),
        Err(AuditError::DisclosureField)
    ));
}
