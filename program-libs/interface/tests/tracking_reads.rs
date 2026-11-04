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
