use serde::Deserialize;
use solana_address::Address;
use spr_keypair::{NullifierKey, ShieldedKeypair, SigningKey};
use zolana_ring_keys::{list_salt, list_tag, RingAddress, RingKeyError, RotatingRingKeys};
use zolana_ring_policy::ring_id_field;

#[derive(Deserialize)]
struct ListVector {
    signing_secret: String,
    nullifier_secret: String,
    ring_id: String,
    list_salt: String,
    list_tag: String,
}

const RING_ID: [u8; 32] = [0x0c; 32];

fn array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

#[test]
fn the_wallet_secret_gives_the_list_salt_and_tag_the_go_host_pins() {
    let vector: ListVector = serde_json::from_str(include_str!(
        "../../../test-vectors/registry/list_salt.json"
    ))
    .unwrap();
    let owner = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&array(
        &vector.signing_secret,
    )))
    .unwrap();
    let ring_id = array::<32>(&vector.ring_id);
    assert_eq!(
        hex::encode(owner.nullifier_key.secret().as_slice()),
        vector.nullifier_secret[2..]
    );
    assert_eq!(
        list_salt(&owner.nullifier_key, &ring_id).unwrap(),
        array::<32>(&vector.list_salt)
    );
    assert_eq!(
        list_tag(&owner.nullifier_key, &ring_id).unwrap(),
        array::<32>(&vector.list_tag)
    );
}

#[test]
fn another_secret_has_another_salt() {
    let first = NullifierKey::from_secret([1; 31]);
    let second = NullifierKey::from_secret([2; 31]);
    assert_ne!(
        list_salt(&first, &RING_ID).unwrap(),
        list_salt(&second, &RING_ID).unwrap()
    );
}

#[test]
fn another_ring_has_another_salt_and_tag() {
    let key = NullifierKey::from_secret([1; 31]);
    let other = [0x0d; 32];
    assert_ne!(
        list_salt(&key, &RING_ID).unwrap(),
        list_salt(&key, &other).unwrap()
    );
    assert_ne!(
        list_tag(&key, &RING_ID).unwrap(),
        list_tag(&key, &other).unwrap()
    );
}

#[test]
fn the_reader_holds_the_wallet_address_and_its_nullifier_key() {
    use spr_transaction::ShieldedKeys;

    let owner = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7; 32])).unwrap();
    let keys = RotatingRingKeys::new(&owner).unwrap();
    assert_eq!(keys.address().unwrap(), owner.shielded_address().unwrap());
}

#[test]
fn an_enrolled_address_carries_the_wallet_salt_and_a_zero_secret_has_none() {
    let ring = Address::new_from_array([4; 32]);
    let mut owner =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7; 32])).unwrap();
    let address = RingAddress::enrolled(&owner, ring).unwrap();
    assert_eq!(address.recipient, owner.shielded_address().unwrap());
    assert_eq!(
        address.list_salt,
        list_salt(
            &owner.nullifier_key,
            &ring_id_field(ring.as_array()).unwrap()
        )
        .unwrap()
    );
    owner.nullifier_key = NullifierKey::from_secret([0; 31]);
    assert_eq!(
        RingAddress::enrolled(&owner, ring).err(),
        Some(RingKeyError::InvalidRingAddressListSalt)
    );
}
