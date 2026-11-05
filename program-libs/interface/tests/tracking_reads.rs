use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::StorageRegistry, NewRing, PolicyUpdate, RingMode, RingPolicy, RingRoles, RootRead,
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
    }
    .account()
}

fn source(floor: u64) -> StorageRegistry {
    let mut source = StorageRegistry::zeroed();
    source.absence_floor = floor.to_le_bytes();
    source
}

fn salted_ring(curator: Address) -> RingPolicy {
    let mut ring = *ring();
    ring.records = key(5);
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    sources[ListId::PrivateBlock.slot()] = SourceSlot {
        list_id: ListId::PrivateBlock as u8,
        registry: curator,
    };
    ring.set_policy(PolicyUpdate {
        sources,
        rules: RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::PrivateBlock))
            .build()
            .encode(),
        slot: 5,
    })
    .unwrap();
    ring
}

fn public_ring(curator: Address) -> RingPolicy {
    let mut ring = *ring();
    ring.records = key(5);
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    sources[ListId::Block.slot()] = SourceSlot {
        list_id: ListId::Block as u8,
        registry: curator,
    };
    ring.set_policy(PolicyUpdate {
        sources,
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
fn a_public_read_answers_to_no_floor_of_its_source() {
    let foreign = source(100);
    assert_eq!(public_ring(key(7)).absence_floor(&key(7), &foreign), 0);
    let own = source(100);
    assert_eq!(
        public_ring(Address::default()).absence_floor(&key(5), &own),
        0
    );
}

#[test]
fn a_salted_read_answers_to_its_source_floor_and_no_other() {
    let ring = salted_ring(key(7));
    let source_floor = source(100);
    assert_eq!(ring.absence_floor(&key(7), &source_floor), 100);
    assert_eq!(ring.absence_floor(&key(5), &source_floor), 0);
    assert_eq!(
        salted_ring(Address::default()).absence_floor(&key(5), &source_floor),
        100
    );
}

#[test]
fn the_salted_set_reads_the_slots_and_matches_the_source_map() {
    let mut ring = salted_ring(Address::default());
    assert_eq!(ring.salted(), ListSet::single(ListId::PrivateBlock));
    assert_eq!(ring.salted(), ring.source_map().unwrap().salted());
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    sources[ListId::Block.slot()].list_id = ListId::Block as u8;
    ring.set_policy(PolicyUpdate {
        sources,
        rules: RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Block))
            .build()
            .encode(),
        slot: 6,
    })
    .unwrap();
    assert_eq!(ring.salted(), ListSet::EMPTY);
    assert_eq!(ring.source_map().unwrap().salted(), ListSet::EMPTY);
}

#[test]
fn policy_roots_remain_in_own_then_curator_order() {
    let ring = salted_ring(key(7));
    assert_eq!(
        ring.root_registries(RootRead::Policy).collect::<Vec<_>>(),
        vec![key(5), key(7)]
    );
    assert_eq!(
        ring.root_registries(RootRead::None).collect::<Vec<_>>(),
        Vec::<Address>::new()
    );
}

#[test]
fn the_salted_registries_name_the_source_of_each_salted_list() {
    assert_eq!(salted_ring(key(9)).salted_registries(), vec![key(9)]);
}
