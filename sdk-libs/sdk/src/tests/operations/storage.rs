use bytemuck::Zeroable;
use custom_ring_interface::{storage_instruction::tag as storage_tag, RecordWriteData};
use zolana_ring_policy::ListId;

use super::*;
use crate::tests::support::ring;

const AUTHORITY: Address = Address::new_from_array([3; 32]);
const REGISTRY: Address = Address::new_from_array([4; 32]);
const TRACKING: Address = Address::new_from_array([5; 32]);

fn pinned_to(tracking_registry: Address) -> StorageRegistry {
    StorageRegistry {
        tracking_registry,
        ..StorageRegistry::zeroed()
    }
}

fn write_of(list: ListId) -> RecordWriteData {
    let mut write = RecordWriteData::zeroed();
    write.lists.mask = list.record_bit().to_le_bytes();
    write
}

fn update_accounts(state: &StorageRegistry, list: ListId) -> Vec<AccountMeta> {
    let apply = ApplyRecordsIxData::zeroed();
    UpdateStorage {
        authority: AUTHORITY,
        registry: REGISTRY,
        state,
        data: StorageUpdateIxData {
            revision: Revision::from(1),
            writes: vec![write_of(list)],
            apply: &apply,
        },
    }
    .instruction()
    .unwrap()
    .accounts
}

#[test]
fn a_rings_records_pin_its_tracking_registry_at_their_own_address() {
    let storage = InitializeStorage::records(ring(), AUTHORITY);
    assert_eq!(
        storage.tracking_registry,
        ring().tracking_registry().unwrap()
    );
    assert_eq!(
        storage.registry(),
        StorageRegistry::find_address(&AUTHORITY, &RegistryId(ring().program_id().to_bytes())).0
    );
    let data = storage.instruction().data;
    assert_eq!(data[0], storage_tag::INITIALIZE);
    let sent: &InitializeIxData = bytemuck::from_bytes(&data[1..]);
    assert_eq!(sent.tracking_registry, storage.tracking_registry);
}

#[test]
fn a_zero_grace_update_of_a_pinned_source_carries_the_pinned_registry() {
    let accounts = update_accounts(&pinned_to(TRACKING), ListId::Block);
    assert_eq!(accounts.len(), 3);
    assert_eq!(accounts[2].pubkey, TRACKING);
    assert!(!accounts[2].is_writable && !accounts[2].is_signer);
}

#[test]
fn a_graced_write_or_an_unpinned_source_carries_no_floor_account() {
    assert_eq!(
        update_accounts(&pinned_to(TRACKING), ListId::Reader).len(),
        2
    );
    assert_eq!(
        update_accounts(&pinned_to(Address::default()), ListId::Block).len(),
        2
    );
}
