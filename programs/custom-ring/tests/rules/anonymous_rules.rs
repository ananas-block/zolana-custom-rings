//! The pre-proof refusals an anonymous policy ring adds to the confidential rail.

use custom_ring_interface::{
    tag, CustomRingError, FramedSenderBundle, RingOutput, RingRail, RingTransactData,
    RECIPIENT_BODY_LEN,
};
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};

use crate::{
    common::{reaches_verification, refused, Ring, Sent, Setup},
    forward_rules::{deposit_instruction, merge_data, merge_instruction_with, ring_deposit},
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

#[test]
fn an_anonymous_policy_merge_discloses_its_owner_to_the_auditor_alone() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut merge = |data| {
        let instruction = merge_instruction_with(&ring, &data);
        ring.send(instruction, &[])
    };
    let disclosed = |registry, inputs| {
        let mut data = merge_data(registry, inputs);
        data.output_ring_data_hash = [0; 32];
        data
    };
    refused(
        merge(disclosed(Some(1), 8)),
        CustomRingError::UnexpectedMemberRegistryRoot,
    );
    let mut narrow = disclosed(None, 8);
    narrow.disclosure.fields.pop();
    refused(merge(narrow), CustomRingError::MergeDisclosureWidth);
    let mut untagged = disclosed(None, 8);
    untagged.disclosure.eph_pk[0] = 0;
    refused(merge(untagged), CustomRingError::InvalidMergeDisclosure);
    refused(
        merge(disclosed(None, 25)),
        CustomRingError::UnsupportedCircuit,
    );
    let mut ring_data = disclosed(None, 8);
    ring_data.output_ring_data_hash = [8; 32];
    refused(merge(ring_data), CustomRingError::AnonymousRingDataNotZero);
    reaches_verification(merge(disclosed(None, 8)));
}

/// A salted commitment is the SDK's duty, the proof cannot read it.
#[test]
fn an_anonymous_policy_deposit_carries_ring_data() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let mut named = ring_deposit();
    named.deposits[0].ring_data_hash = [1; 32];
    let instruction = deposit_instruction(&ring, Some(0), &named);
    reaches_verification(ring.send(instruction, &[]));
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
