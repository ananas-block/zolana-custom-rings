use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Revision, StorageError},
    storage_instruction::tag as storage_tag,
    CredentialRead, RecordWriteData,
};
use zolana_ring_policy::ListId;

use super::*;
use crate::tests::support::ring;

const AUTHORITY: Address = Address::new_from_array([3; 32]);
const REGISTRY: Address = Address::new_from_array([4; 32]);

fn write_of(list: ListId) -> RecordWriteData {
    let mut write = RecordWriteData::zeroed();
    write.lists.mask = list.record_bit().to_le_bytes();
    write
}

fn update(list: ListId) -> Result<Instruction, RingError> {
    let apply = ApplyRecordsIxData::zeroed();
    UpdateStorage {
        authority: AUTHORITY,
        registry: REGISTRY,
        data: StorageUpdateIxData {
            revision: Revision::from(1),
            writes: vec![write_of(list)],
            asset_writes: Vec::new(),
            credential_read: CredentialRead::empty(),
            ring_program: None,
            apply: &apply,
        },
    }
    .instruction()
}

#[test]
fn a_rings_records_bind_its_own_credentials_at_their_own_address() {
    let storage = InitializeStorage::records(ring(), AUTHORITY);
    assert_eq!(storage.private_ring_id, ring().ring_id().unwrap());
    assert_eq!(
        storage.registry(),
        StorageRegistry::find_address(&AUTHORITY, &RegistryId(ring().program_id().to_bytes())).0
    );
    let data = storage.instruction().data;
    assert_eq!(data[0], storage_tag::INITIALIZE);
    let sent: &InitializeIxData = bytemuck::from_bytes(&data[1..]);
    assert_eq!(sent.private_ring_id, storage.private_ring_id);
}

#[test]
fn a_public_write_names_the_authority_and_registry_alone() {
    let accounts = update(ListId::Block).unwrap().accounts;
    assert_eq!(
        accounts.iter().map(|meta| meta.pubkey).collect::<Vec<_>>(),
        [AUTHORITY, REGISTRY]
    );
}

#[test]
fn a_private_write_without_its_credential_read_is_refused() {
    assert!(matches!(
        update(ListId::PrivateBlock),
        Err(RingError::Storage(StorageError::InvalidCredentialRead))
    ));
}
