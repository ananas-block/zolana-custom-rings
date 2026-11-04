use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Revision, Root, StorageRegistry},
    tracking::TrackingRegistry,
    CustomRingError, LiveRoots, NewRing, PolicyUpdate, RingMode, RingPolicy, RingRoles, RootRead,
    SourceSlot, N_SOURCE_SLOTS,
};
use solana_address::Address;
use zolana_ring_policy::{ListId, ListSet, Rule, RuleTable, Subject};

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
        slot: 1,
    }
    .tracking(Revision::from(revision))
}

#[test]
fn a_served_root_below_a_salted_floor_is_refused() {
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
        slot: 1,
    };
    assert_eq!(
        live.tracking(Revision::from(4)),
        Err(CustomRingError::TrackingRootBelowFloor)
    );
}

fn salted_ring(curator: Address) -> RingPolicy {
    let mut ring = *ring();
    ring.records = key(5);
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    sources[ListId::Block.slot()] = SourceSlot {
        list_id: ListId::Block as u8,
        registry: curator,
    };
    ring.set_policy(PolicyUpdate {
        sources,
        salted_lists: ListSet::single(ListId::Block),
        rules: RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Block))
            .build()
            .encode(),
        slot: 5,
    })
    .unwrap();
    ring
}

#[test]
fn a_source_serving_a_salted_list_pins_the_tracking_registry() {
    let other = CustomRingError::SaltedSourceOtherTracking;
    for (ring, serving) in [
        (salted_ring(Address::default()), key(5)),
        (salted_ring(key(7)), key(7)),
    ] {
        assert_eq!(ring.check_source_pair(&serving, &source(key(9), 0)), Ok(()));
        for unpaired in [key(8), Address::default()] {
            assert_eq!(
                ring.check_source_pair(&serving, &source(unpaired, 0)),
                Err(other)
            );
        }
    }
}

#[test]
fn a_source_serving_no_salted_list_needs_no_pin_and_no_foreign_one() {
    let ring = salted_ring(key(7));
    assert_eq!(
        ring.check_source_pair(&key(5), &source(Address::default(), 0)),
        Ok(())
    );
    assert_eq!(
        ring.check_source_pair(&key(5), &source(key(8), 0)),
        Err(CustomRingError::SaltedSourceOtherTracking)
    );
}

#[test]
fn a_salted_bit_survives_only_on_a_list_a_rule_reads() {
    let mut ring = salted_ring(Address::default());
    assert_eq!(ring.salted(), ListSet::single(ListId::Block));
    let salted_hash = ring.policy_hash;
    let unsalted = PolicyUpdate {
        sources: ring.sources,
        salted_lists: ListSet::EMPTY,
        rules: ring.rules,
        slot: 6,
    };
    ring.set_policy(unsalted).unwrap();
    assert_ne!(ring.policy_hash, salted_hash);
    ring.set_policy(PolicyUpdate {
        salted_lists: ListSet::single(ListId::Frozen),
        ..unsalted
    })
    .unwrap();
    assert_eq!(ring.salted(), ListSet::EMPTY);
}

#[test]
fn a_transfer_reads_the_own_and_curator_roots_before_the_pinned_tracking_registry() {
    let ring = salted_ring(key(7));
    assert_eq!(
        ring.root_registries(RootRead::Policy).collect::<Vec<_>>(),
        vec![key(5), key(7), key(9)]
    );
    assert_eq!(
        ring.root_registries(RootRead::None).collect::<Vec<_>>(),
        vec![key(9)]
    );
}
