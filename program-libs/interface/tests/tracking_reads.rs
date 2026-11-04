//! What a transfer reads of the tracking registry, the pin and a private source's floor.

use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Revision, Root, StorageRegistry},
    tracking::TrackingRegistry,
    CustomRingError, LiveRoots, NewRing, PrivateSourceWrite, RingMode, RingPolicy, RingRoles,
    RootRead,
};
use solana_address::Address;
use zolana_ring_policy::{ListId, ListSet};

fn key(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}

fn ring() -> Box<RingPolicy> {
    NewRing {
        bump: 254,
        mode: RingMode::Confidential,
        roles: RingRoles {
            admin: key(1),
            policy: key(2),
            pauser: key(3),
            cosign_admin: key(4),
        },
        auditor_pubkey: [4; 33],
        created_slot: 0,
        records: Address::default(),
        tracking: key(9),
    }
    .account()
}

fn tracking_at(revisions: &[u64]) -> TrackingRegistry {
    let mut registry = TrackingRegistry::zeroed();
    for (slot, revision) in revisions.iter().enumerate() {
        registry.roots[slot] = Root {
            hash: [*revision as u8 + 1; 32],
            revision: Revision::from(*revision),
            expires_at: 100u64.to_le_bytes(),
        };
    }
    registry
}

fn source(paired: Address, floor: u64) -> StorageRegistry {
    let mut source = StorageRegistry::zeroed();
    source.tracking_registry = paired;
    source.tracking_floor = Revision::from(floor);
    source
}

fn read(
    tracking: &TrackingRegistry,
    own: &StorageRegistry,
    revision: u64,
) -> Result<[u8; 32], CustomRingError> {
    LiveRoots {
        own: Some(own),
        curator: None,
        tracking,
        private_source: None,
        slot: 1,
    }
    .tracking(Revision::from(revision))
}

#[test]
fn a_served_root_below_a_private_floor_is_refused() {
    let tracking = tracking_at(&[5, 4]);
    let private = source(key(9), 5);
    assert_eq!(read(&tracking, &private, 5), Ok([6; 32]));
    assert_eq!(
        read(&tracking, &private, 4),
        Err(CustomRingError::TrackingRootBelowFloor)
    );
}

#[test]
fn a_public_source_keeps_the_tracking_grace() {
    let tracking = tracking_at(&[5, 4]);
    assert_eq!(
        read(&tracking, &source(Address::default(), 0), 4),
        Ok([5; 32])
    );
}

#[test]
fn a_floor_above_the_named_root_refuses_a_curator_source_too() {
    let tracking = tracking_at(&[5, 4]);
    let private = source(key(9), 5);
    let live = LiveRoots {
        own: None,
        curator: Some(&private),
        tracking: &tracking,
        private_source: None,
        slot: 1,
    };
    assert_eq!(
        live.tracking(Revision::from(4)),
        Err(CustomRingError::TrackingRootBelowFloor)
    );
}

#[test]
fn a_private_source_pairs_with_the_pinned_registry_alone() {
    let ring = ring();
    assert_eq!(ring.check_source_pair(&source(key(9), 0)), Ok(()));
    assert_eq!(
        ring.check_source_pair(&source(key(8), 0)),
        Err(CustomRingError::PrivateSourceOtherTracking)
    );
    assert_eq!(
        ring.check_source_pair(&source(Address::default(), 0)),
        Ok(())
    );
}

#[test]
fn a_private_source_needs_a_policy_list_and_its_pair() {
    let block = ListSet::single(ListId::Block);
    let write = |owner_lists, source| PrivateSourceWrite {
        owner_lists,
        source,
    };
    let paired = source(key(9), 0);
    let mut ring = *ring();
    let unwritten_hash = ring.policy_hash;
    assert_eq!(
        ring.set_private_source(write(block, Some((key(7), &paired))), 5),
        Ok(())
    );
    assert_eq!(ring.private_source, key(7));
    assert_eq!(ring.private_lists, block.bits());
    assert_ne!(ring.policy_hash, unwritten_hash);
    assert_eq!(ring.generation(), 1);
    let refused = |owner_lists, source, error| {
        let mut untouched = ring;
        assert_eq!(
            untouched.set_private_source(write(owner_lists, source), 6),
            Err(error)
        );
        assert_eq!(untouched, ring);
    };
    let (public, foreign) = (source(Address::default(), 0), source(key(8), 0));
    refused(
        block,
        Some((key(7), &public)),
        CustomRingError::PublicRegistryAsPrivateSource,
    );
    refused(
        block,
        Some((key(7), &foreign)),
        CustomRingError::PrivateSourceOtherTracking,
    );
    refused(
        ListSet::single(ListId::Reader),
        Some((key(7), &paired)),
        CustomRingError::ListNotPolicyReadable,
    );
    refused(block, None, CustomRingError::InvalidSource);
    refused(
        ListSet::EMPTY,
        Some((key(7), &paired)),
        CustomRingError::InvalidSource,
    );
    assert_eq!(
        ring.set_private_source(write(ListSet::EMPTY, None), 7),
        Ok(())
    );
    assert_eq!(ring.private_source, Address::default());
}

#[test]
fn a_transfer_reads_the_private_source_before_the_pinned_tracking_registry() {
    let mut ring = *ring();
    ring.records = key(5);
    ring.private_source = key(7);
    assert_eq!(
        ring.root_registries(RootRead::Policy).collect::<Vec<_>>(),
        vec![key(5), key(7), key(9)]
    );
    assert_eq!(
        ring.root_registries(RootRead::None).collect::<Vec<_>>(),
        vec![key(9)]
    );
}
