//! Reads `test-vectors/wallet/anonymous-bodies.json`, a sealed four-output transfer of scheme 1 and 2.

use custom_ring_interface::blinding::ring_blinding_seed;
use serde::Deserialize;
use solana_address::Address;
use spr_keypair::{PublicKey, ShieldedAddress, ViewingKey, X25519Pubkey};
use spr_transaction::{Mint, OutputContext, OutputSlot, ShieldedTransaction};

use super::{
    AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext, HistoricalBody,
    HistoricalOutput, HistoricalReader, HistoricalSite, DUMMY_RECIPIENT_VIEWING_PK,
};
use crate::{OutputBlindings, RingAssets};

/// A recipient plaintext with empty data, the length of every dummy body.
const RECIPIENT_BODY_LEN: usize = spr_keypair::constants::PUBLIC_KEY_LEN
    + 32
    + 8
    + spr_keypair::x25519::X25519_PUBKEY_LEN
    + 32
    + 1;

const VECTORS: &str = include_str!("../../../../test-vectors/wallet/anonymous-bodies.json");

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct Vectors {
    description: String,
    ring_program_id: String,
    tree_id: u16,
    /// Registered beside SOL.
    mints: Vec<MintJson>,
    salt: String,
    first_nullifier: String,
    tx_viewing_pk: String,
    blinding_seed: String,
    sender: Party,
    recipients: Vec<Party>,
    outputs: Vec<OutputCase>,
    sender_bundle: BundleCase,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct Party {
    ed25519_seed: String,
    viewing_secret: String,
    viewing_pubkey: String,
    owner_pubkey: String,
    nullifier_pubkey: String,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct MintJson {
    asset: String,
    asset_id: u64,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct OutputCase {
    position: u32,
    tag: String,
    utxo_hash: String,
    /// Absent on a change output.
    ciphertext: Option<String>,
    /// Absent on the change and the dummy.
    opened: Option<Opened>,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct Opened {
    sealed_to: String,
    plaintext: String,
    owner_pubkey: String,
    sender_pubkey: String,
    mint: MintJson,
    amount: u64,
    blinding: String,
    rebuilt_hash: String,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct BundleCase {
    tag: String,
    slot_index: u32,
    ciphertext: String,
    plaintext: String,
    recipient_viewing_pks: Vec<String>,
    output_seed: String,
    change: Vec<ChangeCase>,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct ChangeCase {
    position: u32,
    mint: MintJson,
    amount: u64,
    blinding: String,
    rebuilt_hash: String,
}

fn mint_json(mint: Mint) -> MintJson {
    MintJson {
        asset: hex::encode(mint.asset.as_array()),
        asset_id: mint.asset_id,
    }
}

fn committed() -> Vectors {
    serde_json::from_str(VECTORS).expect("vector json")
}

fn bytes<const N: usize>(text: &str) -> [u8; N] {
    hex::decode(text).unwrap().try_into().unwrap()
}

/// Reads the committed bytes alone, as the TS mirror does.
#[test]
fn the_committed_bodies_decode_and_rebuild_their_hashes() {
    let vectors = committed();
    let first_nullifier = bytes(&vectors.first_nullifier);
    let salt = bytes(&vectors.salt);
    let ring = Address::new_from_array(bytes(&vectors.ring_program_id));
    let assets = RingAssets::new(vectors.mints.iter().map(|mint| Mint {
        asset: Address::new_from_array(bytes(&mint.asset)),
        asset_id: mint.asset_id,
    }))
    .unwrap();
    let parties: Vec<(ViewingKey, ShieldedAddress)> = std::iter::once(&vectors.sender)
        .chain(&vectors.recipients)
        .map(|party| {
            let viewing_key = ViewingKey::from_bytes(&bytes(&party.viewing_secret));
            let address = ShieldedAddress {
                signing_pubkey: PublicKey::from_bytes(bytes(&party.owner_pubkey)).unwrap(),
                nullifier_pubkey: bytes(&party.nullifier_pubkey),
                viewing_pubkey: X25519Pubkey::from_bytes(bytes(&party.viewing_pubkey)).unwrap(),
            };
            assert_eq!(viewing_key.pubkey(), address.viewing_pubkey);
            (viewing_key, address)
        })
        .collect();
    let tx_viewing_key = parties[0]
        .0
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    assert_eq!(
        hex::encode(tx_viewing_key.pubkey().as_bytes()),
        vectors.tx_viewing_pk
    );
    let blinding_seed = ring_blinding_seed(&tx_viewing_key.secret_bytes(), &salt).unwrap();
    assert_eq!(hex::encode(blinding_seed), vectors.blinding_seed);
    let output = |owner, utxo_hash| HistoricalOutput {
        owner,
        assets: &assets,
        ring,
        tree_id: vectors.tree_id,
        utxo_hash,
    };
    let hashes: Vec<[u8; 32]> = vectors
        .outputs
        .iter()
        .map(|case| bytes(&case.utxo_hash))
        .collect();
    for (case, utxo_hash) in vectors.outputs.iter().zip(&hashes) {
        let Some(ciphertext) = &case.ciphertext else {
            assert!(case.opened.is_none());
            continue;
        };
        let ciphertext = hex::decode(ciphertext).unwrap();
        let Some(opened) = &case.opened else {
            assert_eq!(ciphertext.len(), RECIPIENT_BODY_LEN);
            assert_eq!(case.tag.get(..2), Some("00"));
            continue;
        };
        let (viewing_key, owner) = parties
            .iter()
            .find(|(_, address)| hex::encode(address.viewing_pubkey.as_bytes()) == opened.sealed_to)
            .unwrap();
        let plaintext = viewing_key
            .decrypt_utxo(&ciphertext, &tx_viewing_key.pubkey(), salt, case.position)
            .unwrap();
        assert_eq!(hex::encode(&plaintext), opened.plaintext);
        let sent = tx_viewing_key
            .decrypt_slot_ephemeral(&owner.viewing_pubkey, &ciphertext, salt, case.position)
            .unwrap();
        assert_eq!(sent, plaintext, "the sender reads its own payment");
        let note = AnonymousTransferRecipientPlaintext::deserialize(&plaintext).unwrap();
        assert_eq!(note.uncommitted.sender_pubkey, parties[0].1.viewing_pubkey);
        let utxo = output(owner, utxo_hash)
            .open_recipient(note)
            .unwrap()
            .unwrap();
        assert_eq!(utxo.amount, opened.amount);
        assert_eq!(hex::encode(utxo_hash), opened.rebuilt_hash);
        assert_eq!(mint_json(utxo.asset), opened.mint);
    }
    let bundle = &vectors.sender_bundle;
    assert_eq!(bundle.slot_index as usize, vectors.outputs.len());
    let plaintext = parties[0]
        .0
        .decrypt_utxo(
            &hex::decode(&bundle.ciphertext).unwrap(),
            &tx_viewing_key.pubkey(),
            salt,
            bundle.slot_index,
        )
        .unwrap();
    assert_eq!(hex::encode(&plaintext), bundle.plaintext);
    let plaintext = AnonymousTransferSenderPlaintext::deserialize(&plaintext).unwrap();
    let blindings = OutputBlindings::new(&first_nullifier, &blinding_seed).unwrap();
    assert_eq!(&plaintext.committed.blinding_seed, blindings.output_seed());
    let listed: Vec<X25519Pubkey> = parties[1..]
        .iter()
        .map(|(_, address)| address.viewing_pubkey)
        .chain([X25519Pubkey::from_bytes(DUMMY_RECIPIENT_VIEWING_PK).unwrap()])
        .collect();
    assert_eq!(plaintext.uncommitted.recipient_viewing_pks, listed);
    let sender = &parties[0].1;
    let change = output(sender, &hashes[0])
        .sender_change(plaintext, &first_nullifier)
        .unwrap();
    assert_eq!(change.len(), bundle.change.len());
    for (utxo, case) in change.iter().zip(&bundle.change) {
        let position = case.position as usize;
        assert!(output(sender, &hashes[position]).rebuilds(utxo));
        assert_eq!(hex::encode(utxo.blinding), case.blinding);
        assert_eq!(utxo.blinding, blindings.at(case.position).unwrap());
    }
}

fn encrypted_site(scheme: u8, body: &[u8]) -> Vec<u8> {
    let framed = [&[scheme], body].concat();
    [
        &[spr_event::OutputDataEncoding::ENCRYPTED_TAG],
        &(framed.len() as u32).to_le_bytes()[..],
        &framed,
    ]
    .concat()
}

/// A row of the committed bodies, the tree hashes every commitment.
fn committed_row(vectors: &Vectors) -> ShieldedTransaction {
    let outputs = vectors.outputs.iter().map(|case| OutputSlot {
        view_tag: bytes(&case.tag),
        output_context: OutputContext {
            hash: bytes(&case.utxo_hash),
            tree_id: vectors.tree_id,
            leaf_index: u64::from(case.position),
        },
        payload: case
            .ciphertext
            .as_ref()
            .map(|body| {
                encrypted_site(
                    spr_event::ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG,
                    &hex::decode(body).unwrap(),
                )
            })
            .unwrap_or_default(),
    });
    ShieldedTransaction {
        slot: 1,
        tx_signature: solana_signature::Signature::default(),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: Some(bytes(&vectors.salt)),
        output_slots: outputs.collect(),
        messages: vec![spr_event::MessageData {
            view_tag: bytes(&vectors.sender_bundle.tag),
            data: encrypted_site(
                spr_event::ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG,
                &hex::decode(&vectors.sender_bundle.ciphertext).unwrap(),
            ),
        }],
        nullifiers: vec![bytes(&vectors.first_nullifier)],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(Address::new_from_array(bytes(&vectors.ring_program_id))),
    }
}

fn party_address(party: &Party) -> ShieldedAddress {
    ShieldedAddress {
        signing_pubkey: PublicKey::from_bytes(bytes(&party.owner_pubkey)).unwrap(),
        nullifier_pubkey: bytes(&party.nullifier_pubkey),
        viewing_pubkey: X25519Pubkey::from_bytes(bytes(&party.viewing_pubkey)).unwrap(),
    }
}

#[test]
fn a_reader_takes_only_the_notes_its_keys_rebuild_from_each_site() {
    let vectors = committed();
    let tx = committed_row(&vectors);
    let assets = RingAssets::new(vectors.mints.iter().map(|mint| Mint {
        asset: Address::new_from_array(bytes(&mint.asset)),
        asset_id: mint.asset_id,
    }))
    .unwrap();
    let first_nullifier = bytes(&vectors.first_nullifier);
    let ring = Address::new_from_array(bytes(&vectors.ring_program_id));
    let sender = party_address(&vectors.sender);
    let recipients: Vec<ShieldedAddress> = vectors.recipients.iter().map(party_address).collect();
    let reader = |owner| HistoricalReader {
        owner,
        assets: &assets,
        ring,
        first_nullifier: &first_nullifier,
    };
    let bundle = HistoricalBody::of(&tx, HistoricalSite::Message(0)).expect("scheme 2");
    assert_eq!(bundle.slot_index, vectors.sender_bundle.slot_index);
    let plaintext = hex::decode(&vectors.sender_bundle.plaintext).unwrap();
    let change = reader(&sender).notes(&tx, bundle.site, &plaintext);
    assert_eq!(change.len(), vectors.sender_bundle.change.len());
    for (note, case) in change.iter().zip(&vectors.sender_bundle.change) {
        assert_eq!(note.position, case.position as usize);
        assert_eq!(note.utxo.amount, case.amount);
    }
    let recipient = party_address(&vectors.recipients[0]);
    assert!(
        reader(&recipient)
            .notes(&tx, bundle.site, &plaintext)
            .is_empty(),
        "another owner's bundle"
    );
    for case in &vectors.outputs {
        let site = HistoricalSite::Output(case.position as usize);
        let Some(opened) = &case.opened else {
            assert!(case.ciphertext.is_none() || HistoricalBody::of(&tx, site).is_some());
            continue;
        };
        assert_eq!(
            HistoricalBody::of(&tx, site).unwrap().slot_index,
            case.position
        );
        let plaintext = hex::decode(&opened.plaintext).unwrap();
        let party = recipients
            .iter()
            .find(|party| hex::encode(party.viewing_pubkey.as_bytes()) == opened.sealed_to)
            .unwrap();
        let [note] = reader(party)
            .notes(&tx, site, &plaintext)
            .try_into()
            .expect("its reader rebuilds it");
        assert_eq!(note.utxo.amount, opened.amount);
        assert!(reader(&sender).notes(&tx, site, &plaintext).is_empty());
    }
}
