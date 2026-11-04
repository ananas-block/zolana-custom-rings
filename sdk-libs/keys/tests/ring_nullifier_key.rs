use serde::Deserialize;
use solana_address::Address;
use spr_keypair::{
    KeypairError, NullifierKey, ShieldedKeypair, ShieldedKeypairTrait, ShieldedPda, SigningKey,
    ViewingKey,
};
use zolana_ring_keys::{RingKeyError, RingNullifierKey, RotatingRingKeys};

const RING_A: Address = Address::new_from_array([0xa1; 32]);
const RING_B: Address = Address::new_from_array([0xb2; 32]);

fn wallet(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

fn pubkey(holder: &impl ShieldedKeypairTrait, ring: &Address) -> [u8; 32] {
    RingNullifierKey::derive(holder, ring)
        .unwrap()
        .nullifier_pubkey()
        .unwrap()
}

#[derive(Deserialize)]
struct ListVector {
    signing_secret: String,
    ring_program_id: String,
    nullifier_secret: String,
    list_salt: String,
    list_tag: String,
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

#[test]
fn the_list_salt_and_tag_match_the_go_host() {
    let vector: ListVector = serde_json::from_str(include_str!(
        "../../../test-vectors/registry/list_salt.json"
    ))
    .unwrap();
    let owner = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&array(
        &vector.signing_secret,
    )))
    .unwrap();
    let key = RingNullifierKey::derive(
        &owner,
        &Address::new_from_array(array(&vector.ring_program_id)),
    )
    .unwrap();
    assert_eq!(
        hex::encode(key.nullifier_key().secret().as_slice()),
        vector.nullifier_secret[2..]
    );
    assert_eq!(key.list_salt().unwrap(), array::<32>(&vector.list_salt));
    assert_eq!(key.list_tag().unwrap(), array::<32>(&vector.list_tag));
}

#[test]
fn one_wallet_holds_one_key_per_ring_and_none_is_its_default_key() {
    let owner = wallet(7);
    let default_key = owner.nullifier_key.pubkey().unwrap();
    let on_a = pubkey(&owner, &RING_A);
    assert_eq!(on_a, pubkey(&owner, &RING_A));
    assert_ne!(on_a, pubkey(&owner, &RING_B));
    assert_ne!(on_a, pubkey(&wallet(8), &RING_A));
    assert_ne!(on_a, default_key);
}

#[test]
fn the_list_salt_differs_per_ring_and_from_its_secret() {
    let owner = wallet(7);
    let on_a = RingNullifierKey::derive(&owner, &RING_A).unwrap();
    let on_b = RingNullifierKey::derive(&owner, &RING_B).unwrap();
    assert_ne!(on_a.list_salt().unwrap(), on_b.list_salt().unwrap());
    assert_ne!(on_a.list_salt().unwrap(), on_a.list_tag().unwrap());
    let mut secret = [0u8; 32];
    secret[1..].copy_from_slice(on_a.nullifier_key().secret().as_slice());
    assert_ne!(on_a.list_salt().unwrap(), secret);
}

#[test]
fn a_program_identity_derives_through_the_same_call() {
    let holder = ViewingKey::from_bytes(&[5; 32]);
    let pda = ShieldedPda::from_viewing_key(Address::new_from_array([3; 32]), &holder).unwrap();
    let other = ShieldedPda::from_viewing_key(Address::new_from_array([4; 32]), &holder).unwrap();
    assert_ne!(pubkey(&pda, &RING_A), pubkey(&other, &RING_A));
    assert_ne!(pubkey(&pda, &RING_A), pubkey(&pda, &RING_B));
}

#[test]
fn a_zero_root_and_supplied_pda_roles_are_refused() {
    let supplied = ShieldedPda::with_viewing_key(
        Address::new_from_array([3; 32]),
        NullifierKey::from_secret([9; 31]),
        ViewingKey::new(),
    );
    assert_eq!(
        RingNullifierKey::derive(&supplied, &RING_A).err(),
        Some(RingKeyError::Keypair(KeypairError::PdaRootNotHeld))
    );
    let mut zero = wallet(7);
    zero.nullifier_key = NullifierKey::from_secret([0; 31]);
    assert_eq!(
        RingNullifierKey::derive(&zero, &RING_A).err(),
        Some(RingKeyError::Keypair(KeypairError::ZeroNullifierSecret))
    );
}

#[test]
fn the_reader_holds_the_ring_key_and_its_address() {
    use spr_transaction::ShieldedKeys;

    let owner = wallet(7);
    let keys = RotatingRingKeys::new(&owner, &RING_A).unwrap();
    let address = keys.address().unwrap();
    assert_eq!(address.nullifier_pubkey, pubkey(&owner, &RING_A));
    assert_eq!(address.signing_pubkey, owner.signing_pubkey());
    assert_eq!(address.viewing_pubkey, owner.viewing_pubkey());
}
