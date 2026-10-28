//! Pins `test-vectors/wallet/ring-tags.json` and `test-vectors/wallet/ring-secrets.json` for the Go circuits and the TS SDK.

use std::collections::BTreeSet;

use custom_ring_interface::blinding::{anonymous_ring_data, ring_blinding_seed};
use custom_ring_interface::{
    domain,
    stream::{
        tag_epoch, DeliveredSlot, InboxKey, PairKey, RingTag, SenderCommitment, SlotSecret,
        TagIndex, EPOCH_SLOTS, J_INBOX, J_PAIR, K_PAIR_EPOCHS, TAG_LEN,
    },
    RING_DELIVERED_BODY_LEN,
};
use serde_json::{json, Value};
use spr_hasher::primitives::{hash_bytes, solana_owner_identity, BN254_SCALAR_MODULUS_BE};
use spr_instruction::derivation::{
    derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
    DOMAIN_PRIVATE_TX_BLINDING_V1, DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
    DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
};
use spr_keypair::X25519Keypair;

const RING_TAGS_JSON: &str = include_str!("../../../test-vectors/wallet/ring-tags.json");
const RING_SECRETS_JSON: &str = include_str!("../../../test-vectors/wallet/ring-secrets.json");

/// The epoch the anonymous outputs of the secrets vector are tagged in.
const TAG_EPOCH: u64 = 6_734;
const OUTPUT_INDEXES: [u32; 3] = [0, 1, 15];

#[test]
fn ring_derivation_vectors() {
    let scenario = Scenario::new();
    assert_eq!(committed(RING_TAGS_JSON), scenario.tag_vectors());
    assert_eq!(committed(RING_SECRETS_JSON), scenario.secret_vectors());
}

#[test]
fn domains_are_their_ascii_tags() {
    let table: [(u32, &[u8; 4]); 17] = [
        (domain::AUDIT_STATEMENT, b"CRAU"),
        (domain::DELIVERED_SLOT_SECRET, b"CRDS"),
        (domain::BLINDING_SEED, b"CRBS"),
        (domain::ANONYMOUS_RING_DATA, b"CRAT"),
        (domain::INBOX_KEY, b"CRIK"),
        (domain::INBOX_TAG, b"CRIT"),
        (domain::PAIR_KEY, b"CRPK"),
        (domain::PAIR_TAG, b"CRPT"),
        (domain::SENDER_COMMITMENT, b"CRSC"),
        (domain::DISCLOSURE_PAD, b"CROD"),
        (domain::POLICY_STATEMENT, b"CRPO"),
        (domain::POLICY_TABLE, b"CRTB"),
        (domain::QUEUE_WRITE, b"CRQW"),
        (domain::APPLY_RECORDS, b"CRAP"),
        (domain::REGISTER_KEY, b"CRRG"),
        (domain::DEPOSIT_BLINDING, b"CRDB"),
        (domain::WITHDRAWAL_EXEMPTION, b"CRWX"),
    ];
    for (value, ascii) in table {
        assert_eq!(
            value,
            u32::from_be_bytes(*ascii),
            "{}",
            String::from_utf8_lossy(ascii)
        );
    }
    let kept = [
        DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
        DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
        DOMAIN_PRIVATE_TX_BLINDING_V1,
    ];
    let distinct: BTreeSet<u32> = table.iter().map(|(value, _)| *value).chain(kept).collect();
    assert_eq!(distinct.len(), table.len() + kept.len());
}

#[test]
#[ignore = "regenerates test-vectors/wallet/ring-tags.json, run with --nocapture and commit the output"]
fn print_ring_tag_vectors() {
    let vectors = Scenario::new().tag_vectors();
    println!("{}", serde_json::to_string_pretty(&vectors).expect("json"));
}

#[test]
#[ignore = "regenerates test-vectors/wallet/ring-secrets.json, run with --nocapture and commit the output"]
fn print_ring_secret_vectors() {
    let vectors = Scenario::new().secret_vectors();
    println!("{}", serde_json::to_string_pretty(&vectors).expect("json"));
}

struct Scenario {
    ring_program_id: [u8; 32],
    tx_viewing_secret: [u8; 32],
    recipient_viewing_secret: [u8; 32],
    salt: [u8; 16],
    first_nullifier: [u8; 32],
    sender_key: [u8; 32],
    deposit_blinding_secret: [u8; 32],
}

impl Scenario {
    fn new() -> Self {
        let mut tx_viewing_secret = pattern(0x17);
        tx_viewing_secret[0] &= 248;
        tx_viewing_secret[31] = (tx_viewing_secret[31] & 127) | 64;
        Self {
            ring_program_id: pattern(0xa1),
            tx_viewing_secret,
            recipient_viewing_secret: pattern(0x5c),
            salt: pattern(0x3e),
            first_nullifier: field(0x2b),
            sender_key: pattern(0x61),
            deposit_blinding_secret: field(0x08),
        }
    }

    fn tag_vectors(&self) -> Value {
        let inbox_key = self.inbox_key();
        let first_contact = self.delivered_secret(0);
        let pair_key = PairKey::derive(&first_contact).expect("pair key");
        let inbox_tags: Vec<Value> = [(0, 0), (TAG_EPOCH, 17), (tag_epoch(u64::MAX), J_INBOX - 1)]
            .into_iter()
            .map(|(epoch, index)| {
                let index = TagIndex::new(index).expect("index");
                tag_entry(
                    epoch,
                    index,
                    inbox_key.tag(epoch, index).expect("inbox tag"),
                )
            })
            .collect();
        let pair_tags: Vec<Value> = [(TAG_EPOCH, 0), (TAG_EPOCH + K_PAIR_EPOCHS - 1, J_PAIR - 1)]
            .into_iter()
            .map(|(epoch, index)| {
                let index = TagIndex::new(index).expect("index");
                tag_entry(epoch, index, pair_key.tag(epoch, index).expect("pair tag"))
            })
            .collect();
        let mut below_modulus = BN254_SCALAR_MODULUS_BE;
        below_modulus[31] -= 1;
        let mut two_pow_128 = [0; 32];
        two_pow_128[32 - TAG_LEN - 1] = 1;
        let mut below_two_pow_128 = [0; 32];
        below_two_pow_128[32 - TAG_LEN..].fill(0xff);
        let low128: Vec<Value> = [
            [0; 32],
            below_two_pow_128,
            two_pow_128,
            below_modulus,
            *inbox_key.as_bytes(),
        ]
        .iter()
        .map(|value| {
            let tag = RingTag::from_field(value).expect("canonical");
            json!({ "value": hex::encode(value), "tag": hex::encode(tag.as_bytes()) })
        })
        .collect();
        let epochs: Vec<Value> = [
            0,
            EPOCH_SLOTS - 1,
            EPOCH_SLOTS,
            TAG_EPOCH * EPOCH_SLOTS + 12_345,
            u64::MAX,
        ]
        .into_iter()
        .map(|slot| json!({ "slot": slot.to_string(), "epoch": tag_epoch(slot) }))
        .collect();
        json!({
            "description": "Ring tag streams. ring_id = hash_bytes(ring_program_id), \
                inbox_key = Poseidon(CRIK, ring_id, pack_be(viewing_pk)), an inbox tag is \
                low128(Poseidon(CRIT, inbox_key, epoch, index)), pair_key = Poseidon(CRPK, \
                first_contact_secret), a pair tag is low128(Poseidon(CRPT, pair_key, epoch, \
                index)). low128 is the low 16 bytes of a canonical field, the owner tag is \
                0^16 || tag, epoch = slot / epoch_slots. Produced by \
                program-libs/interface/tests/vectors.rs print_ring_tag_vectors.",
            "constants": {
                "epoch_slots": EPOCH_SLOTS,
                "j_inbox": J_INBOX,
                "j_pair": J_PAIR,
                "k_pair_epochs": K_PAIR_EPOCHS,
                "tag_len": TAG_LEN,
                "body_len": RING_DELIVERED_BODY_LEN,
            },
            "ring_program_id": hex::encode(self.ring_program_id),
            "ring_id": hex::encode(self.ring_id()),
            "viewing_pk": hex::encode(self.recipient_viewing_pk()),
            "inbox_key": hex::encode(inbox_key.as_bytes()),
            "inbox_tags": inbox_tags,
            "first_contact_secret": hex::encode(first_contact.as_bytes()),
            "pair_key": hex::encode(pair_key.as_bytes()),
            "pair_tags": pair_tags,
            "low128": low128,
            "epochs": epochs,
        })
    }

    fn secret_vectors(&self) -> Value {
        let inbox_key = self.inbox_key();
        let blinding_seed = self.blinding_seed();
        let output_blinding_seed =
            derive_output_blinding_seed(&self.first_nullifier, &blinding_seed)
                .expect("output blinding seed");
        let outputs: Vec<Value> = OUTPUT_INDEXES
            .into_iter()
            .map(|output_index| {
                let delivered = self.delivered_secret(output_index);
                let index =
                    TagIndex::new(u8::try_from(output_index).expect("index")).expect("index");
                let tag = inbox_key.tag(TAG_EPOCH, index).expect("tag");
                let ring_data = anonymous_ring_data(&delivered, &tag).expect("anonymous ring data");
                let blinding = derive_transact_output_blinding(
                    &self.first_nullifier,
                    &output_blinding_seed,
                    output_index,
                )
                .expect("output blinding");
                json!({
                    "output_index": output_index,
                    "delivered_slot_secret": hex::encode(delivered.as_bytes()),
                    "tag": hex::encode(tag.as_bytes()),
                    "anonymous_ring_data": hex::encode(ring_data),
                    "blinding": hex::encode(blinding),
                })
            })
            .collect();
        let sender_pk_hash = solana_owner_identity(&self.sender_key).expect("sender pk hash");
        let private_tx_blinding = derive_private_tx_blinding(&self.first_nullifier, &blinding_seed)
            .expect("private tx blinding");
        let sender_commitment = SenderCommitment {
            sender_pk_hash,
            private_tx_blinding,
        }
        .derive()
        .expect("sender commitment");
        let deposit_blinding =
            domain::deposit_blinding(&self.deposit_blinding_secret).expect("deposit blinding");
        json!({
            "description": "Ring output blindings of one transaction. blinding_seed is \
                Poseidon(CRBS, pack_be(tx_viewing_secret), salt), every output blinding \
                Poseidon(TXOB, first_nullifier, output_blinding_seed, output_index) with \
                output_blinding_seed = Poseidon(TXOS, first_nullifier, blinding_seed). A \
                delivered slot secret is Poseidon(CRDS, pack_be(agreement), pack_be(tx_viewing_pk), \
                pack_be(recipient_viewing_pk), salt, output_index, first_nullifier) with agreement \
                = X25519(tx_viewing_secret, recipient_viewing_pk). An anonymous ring output's \
                ring_data_hash is Poseidon(CRAT, delivered slot secret, 0^16 || tag) with tag the \
                inbox tag of ring-tags.json at epoch 6734 and index output_index. The deposit \
                blinding is Poseidon(CRDB, deposit_blinding_secret). The sender commitment is \
                Poseidon(CRSC, sender_pk_hash, private_tx_blinding) with sender_pk_hash = \
                owner_identity(sender_key) and private_tx_blinding = Poseidon(TXPB, \
                first_nullifier, blinding_seed). Produced by \
                program-libs/interface/tests/vectors.rs print_ring_secret_vectors.",
            "tx_viewing_secret": hex::encode(self.tx_viewing_secret),
            "tx_viewing_pk": hex::encode(self.tx_viewing_pk()),
            "recipient_viewing_secret": hex::encode(self.recipient_viewing_secret),
            "recipient_viewing_pk": hex::encode(self.recipient_viewing_pk()),
            "agreement": hex::encode(self.agreement()),
            "salt": hex::encode(self.salt),
            "first_nullifier": hex::encode(self.first_nullifier),
            "blinding_seed": hex::encode(blinding_seed),
            "output_blinding_seed": hex::encode(output_blinding_seed),
            "outputs": outputs,
            "sender_key": hex::encode(self.sender_key),
            "sender_pk_hash": hex::encode(sender_pk_hash),
            "private_tx_blinding": hex::encode(private_tx_blinding),
            "sender_commitment": hex::encode(sender_commitment),
            "deposit_blinding_secret": hex::encode(self.deposit_blinding_secret),
            "deposit_blinding": hex::encode(deposit_blinding),
        })
    }

    fn ring_id(&self) -> [u8; 32] {
        hash_bytes(&self.ring_program_id).expect("ring id")
    }

    fn tx_viewing_pk(&self) -> [u8; 33] {
        *X25519Keypair::from_bytes(&self.tx_viewing_secret)
            .pubkey()
            .as_bytes()
    }

    fn recipient_viewing_pk(&self) -> [u8; 33] {
        *X25519Keypair::from_bytes(&self.recipient_viewing_secret)
            .pubkey()
            .as_bytes()
    }

    fn agreement(&self) -> [u8; 32] {
        let recipient = X25519Keypair::from_bytes(&self.recipient_viewing_secret).pubkey();
        *X25519Keypair::from_bytes(&self.tx_viewing_secret)
            .ecdh(&recipient)
            .expect("agreement")
    }

    fn inbox_key(&self) -> InboxKey {
        InboxKey::derive(&self.ring_id(), &self.recipient_viewing_pk()).expect("inbox key")
    }

    fn delivered_secret(&self, output_index: u32) -> SlotSecret {
        DeliveredSlot {
            agreement: &self.agreement(),
            tx_viewing_pk: &self.tx_viewing_pk(),
            recipient_viewing_pk: &self.recipient_viewing_pk(),
            salt: &self.salt,
            output_index,
            first_nullifier: &self.first_nullifier,
        }
        .secret()
        .expect("delivered slot secret")
    }

    fn blinding_seed(&self) -> [u8; 32] {
        ring_blinding_seed(&self.tx_viewing_secret, &self.salt).expect("blinding seed")
    }
}

fn tag_entry(epoch: u64, index: TagIndex, tag: RingTag) -> Value {
    json!({ "epoch": epoch, "index": index.get(), "tag": hex::encode(tag.as_bytes()) })
}

fn pattern<const N: usize>(seed: u8) -> [u8; N] {
    core::array::from_fn(|i| seed.wrapping_add((i as u8).wrapping_mul(0x1d)))
}

/// Canonical, the top byte is zero.
fn field(seed: u8) -> [u8; 32] {
    let mut value = pattern(seed);
    value[0] = 0;
    value
}

fn committed(json: &str) -> Value {
    serde_json::from_str(json).expect("committed vector json")
}
