//! The key holder reads the tags the Go witnesses prove.

use serde::Deserialize;
use spr_keypair::{viewing_key::ViewTag, ShieldedKeypair, SigningKey, ViewingKey, X25519Pubkey};
use zolana_ring_keys::{RingKeys, RingTagFrame, RingTagKind, RingTagProbe, RotatingRingKeys};

const RECIPIENT_SLOT: usize = 1;

#[derive(Deserialize)]
struct Bodies {
    tx_viewing_sk: String,
    recipient_viewing_sk: String,
    sender_viewing_sk: String,
    sender_viewing_key: String,
    recipient_keys: Vec<String>,
    salt: String,
    first_nullifier: String,
    output_count: u32,
    body_index: u32,
    body_tag: String,
    body_slot_secret: String,
    bundle_tag: String,
    bundle_slot_secret: String,
    dummy_tag: String,
}

#[derive(Deserialize)]
struct Statements {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    family: String,
    tx_viewing_u: String,
    salt: String,
    first_nullifier: String,
    output_count: u32,
    outputs: Vec<CaseOutput>,
    sender_bundle_tag: Option<String>,
}

#[derive(Deserialize)]
struct CaseOutput {
    kind: String,
    tag: Option<String>,
    recipient_body: Option<String>,
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn bodies() -> Bodies {
    serde_json::from_str(include_str!(
        "../../../test-vectors/audit/anonymous_bodies.json"
    ))
    .unwrap()
}

/// The production holder, the sender's key current and the recipient's retired.
fn holder(vector: &Bodies) -> (RotatingRingKeys, X25519Pubkey, X25519Pubkey) {
    let sender = ViewingKey::from_canonical_bytes(&array(&vector.sender_viewing_sk)).unwrap();
    let recipient = ViewingKey::from_canonical_bytes(&array(&vector.recipient_viewing_sk)).unwrap();
    let sender_key = sender.pubkey();
    let recipient_key = recipient.pubkey();
    assert_eq!(sender_key.u(), array::<32>(&vector.sender_viewing_key));
    assert_eq!(
        recipient_key.u(),
        array::<32>(&vector.recipient_keys[RECIPIENT_SLOT])
    );
    let mut identity =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7; 32])).unwrap();
    identity.viewing_key = sender;
    let keys = RotatingRingKeys::new(&identity)
        .unwrap()
        .with_retired(vec![recipient])
        .unwrap();
    (keys, sender_key, recipient_key)
}

fn probe(kind: RingTagKind, output_index: u32, tag: ViewTag) -> RingTagProbe {
    RingTagProbe {
        kind,
        output_index,
        tag,
    }
}

#[test]
fn the_holder_reads_the_body_and_bundle_tags_and_no_dummy_or_change_tag() {
    let vector = bodies();
    let (keys, sender, recipient) = holder(&vector);
    let tx_viewing_pk = ViewingKey::from_canonical_bytes(&array(&vector.tx_viewing_sk))
        .unwrap()
        .pubkey();
    let frame = |viewing_pubkey, probes| RingTagFrame {
        viewing_pubkey,
        tx_viewing_pk,
        salt: array(&vector.salt),
        first_nullifier: array(&vector.first_nullifier),
        probes,
    };
    let recipient_probes = vec![
        probe(
            RingTagKind::Recipient,
            vector.body_index,
            array(&vector.body_tag),
        ),
        probe(
            RingTagKind::Recipient,
            vector.body_index,
            array(&vector.dummy_tag),
        ),
        probe(RingTagKind::Recipient, 0, [0; 32]),
    ];
    let sender_probes = vec![
        probe(
            RingTagKind::SenderBundle,
            vector.output_count,
            array(&vector.bundle_tag),
        ),
        probe(RingTagKind::Recipient, 0, [0; 32]),
        probe(
            RingTagKind::Recipient,
            vector.output_count,
            array(&vector.bundle_tag),
        ),
    ];
    let answers = keys
        .ring_tag_matches(&[
            frame(recipient, recipient_probes),
            frame(sender, sender_probes),
        ])
        .unwrap();
    let hits =
        |answers: &[Option<custom_ring_interface::stream::SlotSecret>]| -> Vec<Option<String>> {
            answers
                .iter()
                .map(|answer| answer.as_ref().map(|secret| hex::encode(secret.as_bytes())))
                .collect()
        };
    assert_eq!(
        hits(&answers[0]),
        [Some(vector.body_slot_secret.clone()), None, None],
        "a dummy and a zero change tag open nothing"
    );
    assert_eq!(
        hits(&answers[1]),
        [Some(vector.bundle_slot_secret.clone()), None, None],
        "the bundle answers only under its own domain"
    );
}

#[test]
fn the_holder_reads_every_proven_tag_of_the_anonymous_statements() {
    let vector = bodies();
    let (keys, sender, recipient) = holder(&vector);
    let statements: Statements = serde_json::from_str(include_str!(
        "../../../test-vectors/audit/transfer_statement_v3.json"
    ))
    .unwrap();
    let mut read = 0;
    for case in statements
        .cases
        .iter()
        .filter(|case| case.family == "anonymous")
    {
        let frame = |viewing_pubkey, probes| RingTagFrame {
            viewing_pubkey,
            tx_viewing_pk: X25519Pubkey::from_u(array(&case.tx_viewing_u)).unwrap(),
            salt: array(&case.salt),
            first_nullifier: array(&case.first_nullifier),
            probes,
        };
        let mut recipient_probes = Vec::new();
        for (index, output) in case.outputs.iter().enumerate() {
            let index = u32::try_from(index).unwrap();
            match (output.kind.as_str(), &output.tag) {
                ("anonymous", Some(tag)) => {
                    assert!(output.recipient_body.is_some(), "{}", case.name);
                    recipient_probes.push(probe(RingTagKind::Recipient, index, array(tag)));
                }
                // A change slot carries no tag and no body, an exit no view tag.
                _ => assert!(output.recipient_body.is_none(), "{}", case.name),
            }
        }
        let bundle = case.sender_bundle_tag.as_deref().unwrap();
        let answers = keys
            .ring_tag_matches(&[
                frame(recipient, recipient_probes),
                frame(
                    sender,
                    vec![probe(
                        RingTagKind::SenderBundle,
                        case.output_count,
                        array(bundle),
                    )],
                ),
            ])
            .unwrap();
        assert!(
            answers.iter().flatten().all(Option::is_some),
            "{}",
            case.name
        );
        read += answers[0].len();
    }
    assert!(read >= 6, "every anonymous case holds a live tag");
}
