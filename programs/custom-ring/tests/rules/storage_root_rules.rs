//! Policy transfers read every root from the live registries they pass, each bound to the ring.

use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Revision, StorageRegistry},
    storage_instruction::{InitializeIxData as StorageInitialize, InitializeTrackingIxData},
    tag,
    tracking::TrackingRegistry,
    CustomRingError, PolicyTableIxData, RingPolicy, RingRail, RingRole, RingTransactData,
    SourceSpec, UpdatePolicyIxData, STORAGE_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::AccountMeta;
use solana_keypair::{Keypair, Signer};
use zolana_ring_policy::{ring_id_field, ListId, ListSet};

use crate::{
    common::{
        allow_list_table, auditor_pubkey, policy_pda, reaches_verification, refused, retired, root,
        tracking_registry, transact, Ring, Sent, Setup, UpdatePolicyIx, PROGRAM, RECORDS,
    },
    transact_rules::{spp_list, Fixture},
};

const CURATOR: Address = Address::new_from_array([0x5c; 32]);

/// A confidential transfer from the payer naming `registries` after the ring account.
fn transfer_reading(ring: &mut Ring, registries: &[Address], data: &RingTransactData<'_>) -> Sent {
    let owner = [AccountMeta::new_readonly(ring.payer.pubkey(), true)];
    let accounts = [
        vec![AccountMeta::new_readonly(policy_pda(), false)],
        registries
            .iter()
            .chain(&[tracking_registry()])
            .map(|registry| AccountMeta::new_readonly(*registry, false))
            .collect(),
        spp_list(&ring.payer.pubkey(), data, &owner),
    ]
    .concat();
    ring.send(
        transact(tag::TRANSFER, accounts, data.encode().unwrap()),
        &[],
    )
}

/// A policy ring whose allow list the `CURATOR` registry of another authority serves at revision 4.
fn subscriber_ring() -> Ring {
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.holder(RingRole::Policy);
    ring.store_registry(CURATOR, &Keypair::new().pubkey(), &[root(4, [0x0c; 32])]);
    let curated = PolicyTableIxData {
        sources: vec![SourceSpec {
            list_id: ListId::Allow as u8,
            source: 1,
        }],
        ..allow_list_table(Vec::new())
    };
    ring.send(
        UpdatePolicyIx {
            authority: authority.pubkey(),
            update: UpdatePolicyIxData::Rules(curated),
            trailing: &[CURATOR],
        }
        .instruction(),
        &[&authority],
    )
    .unwrap();
    ring
}

#[test]
fn a_policy_transfer_proves_under_a_live_storage_root() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let policy_key = ring.roles.policy.pubkey();
    ring.store_registry(
        RECORDS,
        &policy_key,
        &[root(1, [0x0d; 32]), retired(0, [0x0e; 32], 1_000)],
    );
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.own_revision = Some(Revision::from(1));
    reaches_verification(transfer_reading(&mut ring, &[RECORDS], &data));
    // A retired root verifies until its registry expiry.
    data.own_revision = Some(Revision::from(0));
    ring.warp(999);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS], &data));
    ring.warp(1_000);
    refused(
        transfer_reading(&mut ring, &[RECORDS], &data),
        CustomRingError::RootNotServed,
    );
}

#[test]
fn a_curator_revocation_refuses_the_next_subscriber_transfer() {
    let fixture = Fixture::new();
    let mut ring = subscriber_ring();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy.as_mut().unwrap().curator_revision = Some(Revision::from(4));
    reaches_verification(transfer_reading(&mut ring, &[RECORDS, CURATOR], &data));
    ring.apply_immediate(CURATOR, [0x0b; 32]);
    refused(
        transfer_reading(&mut ring, &[RECORDS, CURATOR], &data),
        CustomRingError::RootNotServed,
    );
}

#[test]
fn a_registry_the_ring_does_not_bind_is_refused() {
    let fixture = Fixture::new();
    let mut ring = subscriber_ring();
    let stranger = Address::new_from_array([0x5d; 32]);
    ring.store_registry(stranger, &Keypair::new().pubkey(), &[root(4, [0x0c; 32])]);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.policy.as_mut().unwrap().curator_revision = Some(Revision::from(4));
    for registries in [[stranger, CURATOR], [RECORDS, stranger], [CURATOR, RECORDS]] {
        refused(
            transfer_reading(&mut ring, &registries, &data),
            CustomRingError::UnboundRegistry,
        );
    }
}

#[test]
fn update_policy_rebinds_the_records_to_a_registry_of_any_authority() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let authority = ring.holder(RingRole::Policy);
    let rebind = |records: Address| {
        UpdatePolicyIx {
            authority: authority.pubkey(),
            update: UpdatePolicyIxData::Records,
            trailing: &[records],
        }
        .instruction()
    };
    refused(
        ring.send(rebind(policy_pda()), &[&authority]),
        CustomRingError::InvalidStorageRegistry,
    );
    let records = Address::new_from_array([0x5b; 32]);
    ring.store_registry(records, &Keypair::new().pubkey(), &[root(3, [0x0f; 32])]);
    let before: RingPolicy = ring.read(&policy_pda());
    ring.send(rebind(records), &[&authority]).unwrap();
    let after: RingPolicy = ring.read(&policy_pda());
    assert_eq!(after.records, records);
    assert_eq!(after.policy_hash, before.policy_hash);
    assert_eq!(after.generation(), before.generation() + 1);
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.own_revision = Some(Revision::from(3));
    refused(
        transfer_reading(&mut ring, &[RECORDS], &data),
        CustomRingError::UnboundRegistry,
    );
    reaches_verification(transfer_reading(&mut ring, &[records], &data));
}

/// The registry state a creator other than the ring PDA holds, valid but for its address.
fn forged_tracking() -> Vec<u8> {
    let registry = TrackingRegistry::new(
        254,
        &InitializeTrackingIxData {
            ring_id: ring_id_field(PROGRAM.as_array()).unwrap(),
            auditor_pubkey: auditor_pubkey(),
        },
    );
    bytemuck::bytes_of(&registry).to_vec()
}

#[test]
fn a_forged_tracking_registry_with_a_matching_ring_id_and_an_empty_root_fails_at_load() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let forged = Address::new_from_array([0x5e; 32]);
    ring.store(forged, STORAGE_PROGRAM_ID, forged_tracking());
    let pinned: TrackingRegistry = ring.read(&tracking_registry());
    let copy: TrackingRegistry = ring.read(&forged);
    assert_eq!(copy.ring_id, pinned.ring_id);
    assert_eq!(copy.roots[0].hash, pinned.roots[0].hash);
    let data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    let owner = [AccountMeta::new_readonly(ring.payer.pubkey(), true)];
    let reading = |tracking: Address, ring: &mut Ring| {
        let accounts = [
            vec![
                AccountMeta::new_readonly(policy_pda(), false),
                AccountMeta::new_readonly(RECORDS, false),
                AccountMeta::new_readonly(tracking, false),
            ],
            spp_list(&ring.payer.pubkey(), &data, &owner),
        ]
        .concat();
        ring.send(
            transact(tag::TRANSFER, accounts, data.encode().unwrap()),
            &[],
        )
    };
    refused(reading(forged, &mut ring), CustomRingError::UnboundRegistry);
    reaches_verification(reading(tracking_registry(), &mut ring));
}

const PRIVATE: Address = Address::new_from_array([0x5f; 32]);

/// A private registry paired with `pair`, holding one root at revision 2 and `floor`.
fn store_private(ring: &mut Ring, pair: Address, floor: u64) {
    let mut registry = StorageRegistry::new(
        Keypair::new().pubkey(),
        &StorageInitialize {
            ring_id: ring_id_field(PROGRAM.as_array()).unwrap(),
            tracking_registry: pair,
            ..Zeroable::zeroed()
        },
    );
    registry.roots[0] = root(2, [0x0a; 32]);
    registry.tracking_floor = Revision::from(floor);
    ring.store(
        PRIVATE,
        STORAGE_PROGRAM_ID,
        bytemuck::bytes_of(&registry).to_vec(),
    );
}

fn name_private_source(ring: &mut Ring) -> Sent {
    let authority = ring.holder(RingRole::Policy);
    let update = UpdatePolicyIx {
        authority: authority.pubkey(),
        update: UpdatePolicyIxData::PrivateSource {
            owner_lists: ListSet::single(ListId::Block).bits(),
        },
        trailing: &[PRIVATE],
    }
    .instruction();
    ring.send(update, &[&authority])
}

/// The pinned registry at revision 3 with revision 2 still in its grace.
fn store_tracking_history(ring: &mut Ring) {
    let mut tracking: TrackingRegistry = ring.read(&tracking_registry());
    tracking.roots[0] = root(3, [0x09; 32]);
    tracking.roots[1] = retired(2, [0x08; 32], u64::MAX);
    ring.store(
        tracking_registry(),
        STORAGE_PROGRAM_ID,
        bytemuck::bytes_of(&tracking).to_vec(),
    );
}

#[test]
fn a_private_source_names_only_a_registry_paired_with_the_pin() {
    let mut ring = Ring::new(Setup::Policy);
    store_private(&mut ring, Address::new_from_array([0x61; 32]), 0);
    refused(
        name_private_source(&mut ring),
        CustomRingError::PrivateSourceOtherTracking,
    );
    store_private(&mut ring, Address::default(), 0);
    refused(
        name_private_source(&mut ring),
        CustomRingError::PublicRegistryAsPrivateSource,
    );
    store_private(&mut ring, tracking_registry(), 0);
    name_private_source(&mut ring).unwrap();
    let account: RingPolicy = ring.read(&policy_pda());
    assert_eq!(account.private_source, PRIVATE);
}

#[test]
fn a_tracking_root_below_the_private_floor_is_refused_at_load() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    store_tracking_history(&mut ring);
    store_private(&mut ring, tracking_registry(), 3);
    name_private_source(&mut ring).unwrap();
    let mut data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    data.extensions.private_revision = Some(Revision::from(2));
    data.tracking_revision = Revision::from(2);
    refused(
        transfer_reading(&mut ring, &[RECORDS, PRIVATE], &data),
        CustomRingError::TrackingRootBelowFloor,
    );
    data.tracking_revision = Revision::from(3);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS, PRIVATE], &data));
    store_private(&mut ring, tracking_registry(), 2);
    data.tracking_revision = Revision::from(2);
    reaches_verification(transfer_reading(&mut ring, &[RECORDS, PRIVATE], &data));
}

#[test]
fn a_frame_names_the_private_root_exactly_when_the_ring_has_a_private_source() {
    let fixture = Fixture::new();
    let mut ring = Ring::new(Setup::Policy);
    let mut named = fixture.transfer(RingRail::Confidential, 2, 2, true);
    named.extensions.private_revision = Some(Revision::from(2));
    refused(
        transfer_reading(&mut ring, &[RECORDS], &named),
        CustomRingError::FlagNotAllowed,
    );
    store_private(&mut ring, tracking_registry(), 0);
    name_private_source(&mut ring).unwrap();
    let omitted = fixture.transfer(RingRail::Confidential, 2, 2, true);
    refused(
        transfer_reading(&mut ring, &[RECORDS, PRIVATE], &omitted),
        CustomRingError::FlagNotAllowed,
    );
    refused(
        transfer_reading(&mut ring, &[RECORDS], &named),
        CustomRingError::UnboundRegistry,
    );
    named.extensions.private_revision = Some(Revision::from(9));
    refused(
        transfer_reading(&mut ring, &[RECORDS, PRIVATE], &named),
        CustomRingError::RootNotServed,
    );
}
