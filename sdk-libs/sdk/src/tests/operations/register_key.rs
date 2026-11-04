use custom_ring_interface::{
    storage_instruction::{tag, EnrollIxData},
    tracking::TrackingAuthorization,
    REGISTER_KEY_CIPHERTEXT_LEN, STORAGE_PROGRAM_ID,
};
use solana_address::Address;

use super::support::{keypair, owner_identity, ring, Chain, Registry, RingSettings, TRACKING};
use crate::{EnrollInstruction, MemberRecords, RingMode};

#[tokio::test]
async fn member_records_come_back_in_member_order() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Confidential)
    })
    .with_registry(Registry::new(&[(&registered, 1)]), &super::pipeline_rules())
    .client();
    let reads = MemberRecords {
        ring: ring(),
        members: &[owner_identity(&stranger), owner_identity(&registered)],
    }
    .read(client.zolana())
    .await
    .unwrap();
    assert!(reads[0].record().is_none());
    assert_eq!(reads[1].record().unwrap().lists, 1);
}

/// A first enrollment carries its proof and a rotation none, the owner's authorization names both.
#[test]
fn an_enrollment_writes_the_owner_authorization_on_the_pinned_registry() {
    let owner = Address::new_from_array([3; 32]);
    let payer = Address::new_from_array([7; 32]);
    let data = EnrollIxData {
        nullifier_pk: [1; 32],
        list_tag: [2; 32],
        viewing_u: [3; 32],
        eph_u: [4; 32],
        ciphertext: [5; REGISTER_KEY_CIPHERTEXT_LEN],
    };
    let enroll = |proof| {
        EnrollInstruction {
            payer,
            owner,
            tracking_registry: TRACKING,
            data,
            proof,
        }
        .instruction()
    };
    let rotation = enroll(None);
    let first = enroll(Some(bytemuck::Zeroable::zeroed()));
    assert_eq!(rotation.program_id, STORAGE_PROGRAM_ID);
    assert_eq!(rotation.data[0], tag::ENROLL);
    assert_eq!(rotation.data.len(), 1 + EnrollIxData::SIZE);
    assert!(first.data.len() > rotation.data.len());
    let (authorization, _) = TrackingAuthorization::find_address(&TRACKING, &owner);
    assert_eq!(rotation.accounts[1].pubkey, owner);
    assert!(rotation.accounts[1].is_signer);
    assert_eq!(rotation.accounts[2].pubkey, TRACKING);
    assert_eq!(rotation.accounts[3].pubkey, authorization);
}
