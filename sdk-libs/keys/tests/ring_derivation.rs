//! The ring address and change keys against the `ring_derivation` key derivation vector.

use serde::Deserialize;
use solana_address::Address;
use zolana_keypair::ViewingKey;
use zolana_ring_keys::RingViewingKey;

const VECTOR: &str = include_str!("fixtures/ring_derivation.json");

#[derive(Deserialize)]
struct RingDerivation {
    viewing_secret: String,
    viewing_pubkey: String,
    recipient_viewing_secret: String,
    recipient_viewing_pubkey: String,
    ring_program_id: String,
    address_keys: Vec<RingAddressKeyCase>,
    change_key: RingKeyCase,
    shared_view_tags: Vec<CounterTag>,
}

#[derive(Deserialize)]
struct RingAddressKeyCase {
    index: u32,
    #[serde(flatten)]
    key: RingKeyCase,
}

#[derive(Deserialize, PartialEq, Debug)]
struct RingKeyCase {
    secret: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct CounterTag {
    counter: String,
    tag: String,
}

fn key(hex_secret: &str) -> ViewingKey {
    ViewingKey::from_bytes(&hex::decode(hex_secret).unwrap().try_into().unwrap())
}

fn case(derived: ViewingKey) -> RingKeyCase {
    RingKeyCase {
        secret: hex::encode(derived.secret_bytes().as_slice()),
        pubkey: hex::encode(derived.pubkey().as_bytes()),
    }
}

#[test]
fn ring_keys_match_the_derivation_vector() {
    let vector: RingDerivation = serde_json::from_str(VECTOR).unwrap();
    let viewing = key(&vector.viewing_secret);
    let recipient = key(&vector.recipient_viewing_secret);
    assert_eq!(
        hex::encode(viewing.pubkey().as_bytes()),
        vector.viewing_pubkey
    );
    assert_eq!(
        hex::encode(recipient.pubkey().as_bytes()),
        vector.recipient_viewing_pubkey
    );
    let ring: Address = vector.ring_program_id.parse().unwrap();
    for address in vector.address_keys {
        assert_eq!(
            case(viewing.ring_address_key(&ring, address.index).unwrap()),
            address.key,
            "address {}",
            address.index
        );
    }
    assert_eq!(
        case(viewing.ring_change_key(&ring).unwrap()),
        vector.change_key
    );
    for tag in vector.shared_view_tags {
        let counter = tag.counter.parse().unwrap();
        let sent = viewing
            .get_send_shared_view_tag(&recipient.pubkey(), counter)
            .unwrap();
        assert_eq!(hex::encode(sent), tag.tag);
    }
}
