use custom_ring_interface::RingMode;

use super::support::{keypair, owner_identity, ring, Chain, Registry, RingSettings};
use crate::{EscrowedRecipients, MemberRecords, RingError};

fn escrowed() -> RingSettings {
    RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    }
}

#[tokio::test]
async fn member_records_come_back_in_member_order_with_the_escrowed_key() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let client = Chain::ring(escrowed())
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
    let registered = registered.shielded_address().unwrap();
    assert!(reads[1]
        .escrowed(&registered.nullifier_pubkey)
        .unwrap()
        .is_some());
    assert!(reads[1]
        .escrowed(&stranger.shielded_address().unwrap().nullifier_pubkey)
        .unwrap()
        .is_none());
}

/// A recipient without an escrowed key is refused on a key escrow ring alone.
#[tokio::test]
async fn a_recipient_without_an_escrowed_key_is_refused_before_any_proof() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let recipients = [
        registered.shielded_address().unwrap(),
        stranger.shielded_address().unwrap(),
    ];
    let escrowing = Chain::ring(escrowed())
        .with_registry(Registry::new(&[(&registered, 1)]), &super::pipeline_rules())
        .client();
    assert!(EscrowedRecipients {
        ring: ring(),
        recipients: &recipients[..1],
    }
    .check(escrowing.zolana())
    .await
    .is_ok());
    assert!(matches!(
        EscrowedRecipients {
            ring: ring(),
            recipients: &recipients,
        }
        .check(escrowing.zolana())
        .await,
        Err(RingError::UnregisteredOutputKey { owner }) if owner == owner_identity(&stranger)
    ));
    let confidential = Chain::ring(RingSettings::new(RingMode::Confidential)).client();
    assert!(EscrowedRecipients {
        ring: ring(),
        recipients: &recipients,
    }
    .check(confidential.zolana())
    .await
    .is_ok());
}

mod enrollment {
    use custom_ring_interface::RingMode;
    use solana_address::Address;

    use crate::{
        storage::EnrollAddress,
        tests::support::{keypair, Chain, Registry, RingSettings},
        RingError,
    };

    #[tokio::test]
    async fn an_enrollment_key_that_disagrees_with_the_record_is_refused_before_the_owner_signs() {
        let member = keypair(1);
        let stranger = keypair(2);
        let chain = Chain::ring(RingSettings {
            has_policy: true,
            ..RingSettings::new(RingMode::ConfidentialEscrow)
        })
        .with_records(Registry::new(&[(&member, 0)]));
        let registry = crate::tests::support::RECORDS;
        let client = chain.client();
        let enroll = |owner: &spr_keypair::ShieldedKeypair, nullifier_pk| EnrollAddress {
            payer: Address::new_from_array([7; 32]),
            owner: owner.shielded_address().unwrap().solana_address().unwrap(),
            registry,
            nullifier_pk,
            viewing_u: [3; 32],
        };
        let held = member.shielded_address().unwrap().nullifier_pubkey;
        enroll(&member, held)
            .checked_instruction(client.zolana())
            .await
            .unwrap();
        assert!(matches!(
            enroll(&member, [7; 32])
                .checked_instruction(client.zolana())
                .await,
            Err(RingError::EnrollmentKeyMismatch)
        ));
        // No leaf holds a key to disagree with.
        enroll(&stranger, [7; 32])
            .checked_instruction(client.zolana())
            .await
            .unwrap();
    }
}
