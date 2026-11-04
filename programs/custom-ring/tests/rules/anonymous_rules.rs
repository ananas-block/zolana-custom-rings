//! The pre-proof refusals an anonymous policy ring adds to the confidential rail.

use custom_ring_interface::{
    tag, CustomRingError, FramedSenderBundle, RingOutput, RingRail, RingTransactData,
    RECIPIENT_BODY_LEN,
};
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};

use crate::{
    common::{reaches_verification, refused, Ring, Sent, Setup},
    forward_rules::{deposit_instruction, ring_deposit},
    transact_rules::{send, spp_list, Fixture},
};

/// An anonymous policy transfer, `prefix` after the ring account, the payer signing.
fn transfer(ring: &mut Ring, prefix: Vec<AccountMeta>, data: &RingTransactData<'_>) -> Sent {
    let spp = spp_list(&ring.payer.pubkey(), data, &[]);
    send(
        ring,
        tag::TRANSFER,
        prefix,
        data.encode().unwrap(),
        spp,
        &[],
    )
}

#[test]
fn an_anonymous_policy_transfer_passing_every_check_reaches_its_keys() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    reaches_verification(transfer(
        &mut ring,
        Vec::new(),
        &fixture.transfer(RingRail::Anonymous, 2, 2, true),
    ));
}

#[test]
fn an_anonymous_policy_transfer_takes_public_co_owners_in_the_run() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, true);
    let owner = Keypair::new();
    let spp = spp_list(
        &ring.payer.pubkey(),
        &data,
        &[AccountMeta::new_readonly(owner.pubkey(), true)],
    );
    reaches_verification(send(
        &mut ring,
        tag::TRANSFER,
        Vec::new(),
        data.encode().unwrap(),
        spp,
        &[&owner],
    ));
}

/// Only the proof judges a canonical tag, the program holds the range and the change rule.
#[test]
fn an_anonymous_transfer_reaches_its_keys_under_any_canonical_tags() {
    let fixture = Fixture::new();
    let tags = [[0; 32], [0x2f; 32]];
    let body = [0x3c; RECIPIENT_BODY_LEN];
    for (setup, policy) in [(Setup::AnonymousPolicy, true), (Setup::Anonymous, false)] {
        let mut ring = Ring::new(setup);
        let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, policy);
        for (output, (tag, body)) in data
            .outputs
            .iter_mut()
            .zip([(&tags[0], None), (&tags[1], Some(&body))])
        {
            let RingOutput::Anonymous { hash, record, .. } = *output else {
                panic!("an anonymous transfer publishes anonymous slots");
            };
            *output = RingOutput::Anonymous {
                hash,
                tag,
                body,
                record,
            };
        }
        data.sender = data.sender.map(|sender| FramedSenderBundle {
            tag: &tags[1],
            ..sender
        });
        let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
        reaches_verification(send(
            &mut ring,
            tag::TRANSFER,
            Vec::new(),
            data.encode().unwrap(),
            spp,
            &[],
        ));
    }
}

/// `m` fixes the bundle, a byte fewer shifts every later section.
#[test]
fn a_short_sender_bundle_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let sender = data.sender.unwrap();
    let mut compact = data.encode().unwrap();
    let body = compact
        .windows(32)
        .position(|window| window == sender.tag)
        .unwrap()
        + 32;
    compact.remove(body);
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(&mut ring, tag::TRANSFER, Vec::new(), compact, spp, &[]),
        CustomRingError::RingTransactLength,
    );
}

fn tag_offset(compact: &[u8], hash: &[u8; 32]) -> usize {
    compact
        .windows(32)
        .position(|window| window == hash)
        .unwrap()
        + 32
}

#[test]
fn a_view_tag_off_the_field_or_on_change_is_refused() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Anonymous);
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let compact = data.encode().unwrap();
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    let bundle = compact
        .windows(32)
        .position(|window| window == data.sender.unwrap().tag)
        .unwrap();
    for (offset, tag, refusal) in [
        (
            tag_offset(&compact, data.outputs[1].hash()),
            [0xff; 32],
            CustomRingError::ViewTagNotCanonical,
        ),
        (bundle, [0xff; 32], CustomRingError::ViewTagNotCanonical),
        (
            tag_offset(&compact, data.outputs[0].hash()),
            [0x2f; 32],
            CustomRingError::ChangeTagNotZero,
        ),
    ] {
        let mut bytes = compact.clone();
        bytes[offset..offset + 32].copy_from_slice(&tag);
        refused(
            send(
                &mut ring,
                tag::TRANSFER,
                Vec::new(),
                bytes,
                spp.clone(),
                &[],
            ),
            refusal,
        );
    }
}

#[test]
fn an_anonymous_policy_ring_escrows_no_key() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut data = fixture.transfer(RingRail::Anonymous, 2, 2, true);
    data.key_escrow = true;
    fixture.fit_stream(&mut data);
    refused(
        transfer(&mut ring, Vec::new(), &data),
        CustomRingError::FlagNotAllowed,
    );
}

#[test]
fn an_anonymous_policy_ring_refuses_the_delegate_rail() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let data = fixture.transfer(RingRail::Delegate, 2, 2, true);
    let delegate = Keypair::new();
    let spp = spp_list(&ring.payer.pubkey(), &data, &[]);
    refused(
        send(
            &mut ring,
            tag::AUTHORITY_TRANSFER,
            vec![AccountMeta::new_readonly(delegate.pubkey(), true)],
            data.encode().unwrap(),
            spp,
            &[&delegate],
        ),
        CustomRingError::AnonymousRingRefused,
    );
}

#[test]
fn an_anonymous_policy_deposit_names_no_recipient() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut named = ring_deposit();
    named.deposits[0].ring_data_hash = [1; 32];
    let instruction = deposit_instruction(&ring, Some(0), &named);
    refused(
        ring.send(instruction, &[]),
        CustomRingError::AnonymousRingDataNotZero,
    );
    let instruction = deposit_instruction(&ring, Some(0), &ring_deposit());
    reaches_verification(ring.send(instruction, &[]));
}

#[test]
fn an_anonymous_policy_ring_refuses_a_confidential_transfer() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    fixture.fit_stream(&mut data);
    let sent = transfer(&mut ring, Vec::new(), &data);
    assert!(
        sent.is_err(),
        "a confidential transfer reached an anonymous ring's keys"
    );
}
