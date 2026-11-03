use custom_ring_interface::{
    AnonymousAuditKey, AnonymousRecord, AuditEvidence, AuditKey, AuditStreamLayout, EntryInput,
    ExitRecord,
};
use spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;

use super::*;
use crate::encryption::{seal_stream, StreamSchedule};

fn field(byte: u8) -> [u8; 32] {
    let mut field = [byte; 32];
    field[0] = 0;
    field
}

fn signer_layout(exits: u64) -> AuditStreamLayout {
    AuditStreamLayout {
        key: AuditKey::Confidential {
            class: 2,
            input_prefixes: false,
        },
        key_escrow: false,
        inputs: 1,
        outputs: 2,
        exits,
    }
}

fn entry_layout() -> AuditStreamLayout {
    AuditStreamLayout {
        key: AuditKey::Anonymous(AnonymousAuditKey::Entry { class: 8 }),
        key_escrow: false,
        inputs: 2,
        outputs: 2,
        exits: 0b10,
    }
}

fn exit_record(key_escrow: bool) -> OutputRecord {
    OutputRecord::Exit(ExitRecord {
        asset: field(0x27),
        amount: 40,
        nullifier_pk: (!key_escrow).then_some(field(0x26)),
    })
}

fn entry_evidence() -> AuditEvidence {
    AuditEvidence::Entry {
        sender_key: [0xa1; 32],
        sender_nullifier_pk: field(0x5a),
        inputs: vec![
            EntryInput {
                amount: 5000,
                asset: field(0x60),
                blinding: field(0x61),
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
        ciphertext: &sealed.envelope,
    }
    .open(auditor, layout)
}

/// Seals raw bytes as the envelope plaintext, no clamping runs on the way in.
fn raw_envelope(plaintext: &[u8], auditor: &X25519Keypair) -> SealedAuditStream {
    let ephemeral = X25519Keypair::new();
    let mut envelope = plaintext.to_vec();
    seal_stream(
        &ephemeral,
        &auditor.pubkey(),
        StreamSchedule::Ring(AUDIT_STREAM_LABEL),
        &mut envelope,
    )
    .unwrap();
    SealedAuditStream {
        eph_u: ephemeral.pubkey().u(),
        envelope,
        records: Vec::new(),
        ephemeral_sk: ephemeral.secret_bytes(),
    }
}

#[test]
fn the_envelope_opens_to_the_sealed_key_under_a_fresh_ephemeral_key() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let seal = || {
        AuditStreamSeal {
            layout: signer_layout(0),
            tx_viewing_key: &tx_viewing_key,
            evidence: AuditEvidence::None,
            records: vec![OutputRecord::Delivered; 2],
        }
        .seal(&auditor.pubkey())
        .unwrap()
    };
    let (first, second) = (seal(), seal());
    assert_ne!(first.eph_u, second.eph_u);
    assert_ne!(first.envelope, second.envelope);
    let opened = opened_envelope(&first, &auditor, signer_layout(0)).unwrap();
    assert_eq!(opened.tx_viewing_key.pubkey(), tx_viewing_key.pubkey());
    assert_eq!(opened.evidence, AuditEvidence::None);
    assert!(first.records.iter().all(Vec::is_empty));
}

#[test]
fn an_unclamped_envelope_secret_is_refused() {
    let auditor = X25519Keypair::new();
    let canonical = ViewingKey::new();
    let mut unclamped = *canonical.secret_bytes();
    unclamped[0] |= 0b111;
    let sealed = raw_envelope(&unclamped, &auditor);
    assert!(matches!(
        opened_envelope(&sealed, &auditor, signer_layout(0)),
        Err(AuditError::NonCanonicalViewingKey)
    ));
    let sealed = raw_envelope(&*canonical.secret_bytes(), &auditor);
    assert_eq!(
        opened_envelope(&sealed, &auditor, signer_layout(0))
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
    let layout = AuditStreamLayout {
        key: AuditKey::Anonymous(AnonymousAuditKey::Commitment { class: 4 }),
        inputs: 1,
        exits: 0,
        ..signer_layout(0)
    };
    let record = OutputRecord::Anonymous(AnonymousRecord {
        owner_key: [0xb5; 32],
        asset: field(0x15),
        amount: 70,
        nullifier_pk: field(0x25),
    });
    let sealed = AuditStreamSeal {
        layout,
        tx_viewing_key: &tx_viewing_key,
        evidence: AuditEvidence::Commitment {
            first_input_hash: field(0x70),
            later_prefixes: Vec::new(),
        },
        records: vec![record, record],
    }
    .seal(&auditor.pubkey())
    .unwrap();
    assert_ne!(sealed.records[0], sealed.records[1]);
    let opened = opened_envelope(&sealed, &auditor, layout).unwrap();
    assert_eq!(opened.record(0, &sealed.records[0]).unwrap(), record);
    assert_eq!(opened.record(1, &sealed.records[1]).unwrap(), record);
    assert_ne!(opened.record(0, &sealed.records[1]).unwrap(), record);
}

#[test]
fn the_entry_evidence_and_an_exit_record_read_back() {
    let auditor = X25519Keypair::new();
    let tx_viewing_key = ViewingKey::new();
    let dummy = OutputRecord::Anonymous(AnonymousRecord::default());
    let sealed = AuditStreamSeal {
        layout: entry_layout(),
        tx_viewing_key: &tx_viewing_key,
        evidence: entry_evidence(),
        records: vec![dummy, exit_record(false)],
    }
    .seal(&auditor.pubkey())
    .unwrap();
    let opened = opened_envelope(&sealed, &auditor, entry_layout()).unwrap();
    assert_eq!(opened.evidence, entry_evidence());
    assert_eq!(opened.record(0, &sealed.records[0]).unwrap(), dummy);
    assert_eq!(
        opened.record(1, &sealed.records[1]).unwrap(),
        exit_record(false)
    );
}

#[test]
fn a_seal_off_its_layout_is_refused() {
    let auditor = X25519Keypair::new().pubkey();
    let tx_viewing_key = ViewingKey::new();
    let seal = |layout, evidence, records| {
        AuditStreamSeal {
            layout,
            tx_viewing_key: &tx_viewing_key,
            evidence,
            records,
        }
        .seal(&auditor)
    };
    let delivered = vec![OutputRecord::Delivered; 2];
    for (layout, evidence, records) in [
        (
            signer_layout(0),
            AuditEvidence::None,
            vec![OutputRecord::Delivered],
        ),
        (
            signer_layout(0),
            AuditEvidence::InputPrefixes(vec![None]),
            delivered.clone(),
        ),
        (signer_layout(0b10), AuditEvidence::None, delivered),
        (
            signer_layout(0b10),
            AuditEvidence::None,
            vec![OutputRecord::Delivered, exit_record(true)],
        ),
    ] {
        assert!(matches!(
            seal(layout, evidence, records),
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
            evidence,
        }
        .encode()
    };
    let commitment = AuditStreamLayout {
        key: AuditKey::Anonymous(AnonymousAuditKey::Commitment { class: 4 }),
        inputs: 2,
        ..signer_layout(0)
    };
    let prefixes = |first_input_hash| AuditEvidence::Commitment {
        first_input_hash,
        later_prefixes: vec![None],
    };
    for (first, error) in [
        ([0; 32], AuditError::DisclosureLayout),
        (BN254_SCALAR_MODULUS_BE, AuditError::DisclosureField),
    ] {
        let sealed = raw_envelope(&plaintext(prefixes(first)), &auditor);
        let refused = opened_envelope(&sealed, &auditor, commitment)
            .err()
            .unwrap();
        assert_eq!(refused.to_string(), error.to_string());
    }
    let mut over = plaintext(prefixes(field(0x70)));
    over[64..80].fill(0xff);
    let sealed = raw_envelope(&over, &auditor);
    assert!(matches!(
        opened_envelope(&sealed, &auditor, commitment),
        Err(AuditError::DisclosureField)
    ));
    let mut entry = entry_evidence();
    let AuditEvidence::Entry { inputs, .. } = &mut entry else {
        unreachable!("the entry evidence");
    };
    inputs[1].blinding = BN254_SCALAR_MODULUS_BE;
    let sealed = raw_envelope(&plaintext(entry), &auditor);
    assert!(matches!(
        opened_envelope(&sealed, &auditor, entry_layout()),
        Err(AuditError::DisclosureField)
    ));
}

#[test]
fn a_real_input_hash_without_a_prefix_is_refused() {
    let mut short = [0; 32];
    short[31] = 1;
    assert!(matches!(
        prefix_evidence(&[Some(short)]),
        Err(AuditError::DisclosureField)
    ));
    assert!(matches!(
        commitment_evidence(&[None]),
        Err(AuditError::DisclosureLayout)
    ));
    assert_eq!(
        prefix_evidence(&[Some(field(0x70)), None]).unwrap(),
        AuditEvidence::InputPrefixes(vec![InputPrefix::of(&field(0x70)), None])
    );
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
