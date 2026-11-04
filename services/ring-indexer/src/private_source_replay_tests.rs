use std::sync::{Arc, Mutex};

use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{RegistryId, Revision, StorageRegistry},
    storage_instruction::{
        tag, ApplyPrivateListIxData, InitializeIxData, InitializeTrackingIxData,
        PrivateListWriteData, PrivateUpdateIxData,
    },
    tracking::TrackingRegistry,
    STORAGE_PROGRAM_ID, VIEWING_PUBKEY_TAG,
};
use serde_json::Value;
use solana_address::Address;
use spr_indexer_api::Hash;
use zolana_ring_indexer::{
    private_list::GetPrivateListWritesRequest, rpc::GetStorageMemberOpeningsRequest,
};
use zolana_ring_member_registry::PrivateListTree;

use super::{account, block, replay_indexer, rpc, transaction, Chain, Progress};
use crate::{
    api,
    error::RingApiError,
    storage::StorageStore,
    tests::{database, field},
};

const CREATOR: Address = Address::new_from_array([41; 32]);

fn list_write(position: u8, counter: u64) -> PrivateListWriteData {
    PrivateListWriteData {
        position: field(position),
        leaf: field(position + 100),
        write_counter: counter.to_le_bytes(),
    }
}

/// One tracking registry and its paired private source, created at slot 1.
struct Pair {
    tracking: Address,
    source: Address,
    created: Vec<Value>,
}

fn pair() -> Pair {
    let ring_id = field(9);
    let (tracking, _) = TrackingRegistry::find_address(&CREATOR, &ring_id);
    let mut auditor_pubkey = [9; 33];
    auditor_pubkey[0] = VIEWING_PUBKEY_TAG;
    let tracking_data = InitializeTrackingIxData {
        ring_id,
        auditor_pubkey,
    };
    let registry_id = RegistryId([42; 32]);
    let (source, _) = StorageRegistry::find_address(&CREATOR, &registry_id);
    let source_data = InitializeIxData {
        registry_id,
        grace_slots: 100u64.to_le_bytes(),
        ring_id,
        tracking_registry: tracking,
    };
    let created = vec![
        transaction(
            STORAGE_PROGRAM_ID,
            &[CREATOR, CREATOR, tracking],
            &[
                &[tag::INITIALIZE_TRACKING][..],
                bytemuck::bytes_of(&tracking_data),
            ]
            .concat(),
        ),
        transaction(
            STORAGE_PROGRAM_ID,
            &[CREATOR, CREATOR, source],
            &[&[tag::INITIALIZE][..], bytemuck::bytes_of(&source_data)].concat(),
        ),
    ];
    Pair {
        tracking,
        source,
        created,
    }
}

#[must_use]
struct SentUpdate {
    source: Address,
    tracking: Address,
    revision: u64,
    restrictive: bool,
    writes: Vec<PrivateListWriteData>,
    new_root: [u8; 32],
}

impl SentUpdate {
    fn transaction(self) -> Value {
        let apply = ApplyPrivateListIxData {
            proof: Zeroable::zeroed(),
            new_root: self.new_root,
        };
        let data = PrivateUpdateIxData {
            revision: Revision::from(self.revision),
            restrictive: self.restrictive,
            writes: self.writes,
            apply: &apply,
        };
        transaction(
            STORAGE_PROGRAM_ID,
            &[CREATOR, self.source, self.tracking],
            &[&[tag::UPDATE_PRIVATE][..], &data.encode().unwrap()].concat(),
        )
    }
}

#[tokio::test]
async fn a_reader_rebuilds_a_private_source_from_its_published_writes_alone() {
    let Pair {
        tracking,
        source,
        created,
    } = pair();
    let writes = vec![list_write(1, 1), list_write(2, 2)];
    let published = writes
        .iter()
        .map(PrivateListWriteData::published)
        .collect::<Vec<_>>();
    let root = PrivateListTree::rebuild(&published).unwrap().root();
    let chain = Arc::new(Mutex::new(Chain {
        blocks: [
            (1, block(1, created)),
            (
                2,
                block(
                    2,
                    vec![SentUpdate {
                        source,
                        tracking,
                        revision: 0,
                        restrictive: true,
                        writes,
                        new_root: root,
                    }
                    .transaction()],
                ),
            ),
        ]
        .into(),
        ..Default::default()
    }));
    let (rpc, handle) = rpc(chain.clone()).await;
    let indexer = replay_indexer(Arc::new(database().await), rpc);
    while indexer.synchronize().await.unwrap() == Progress::Behind {}
    let (db, rpc) = (indexer.db.as_ref(), indexer.rpc.as_ref());
    let state = StorageStore::new(db, source.to_bytes())
        .state()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.fault, None);
    assert_eq!(state.account.newest().hash, root);
    chain.lock().unwrap().accounts.insert(
        source.to_string(),
        account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&*state.account)),
    );
    let page = api::private_list_writes(
        db,
        rpc,
        GetPrivateListWritesRequest {
            registry: source.into(),
            expected_root: Hash(root),
            start: 0,
            limit: 16,
        },
    )
    .await
    .unwrap();
    let served = page
        .writes
        .iter()
        .zip(&published)
        .map(|(view, write)| {
            assert_eq!(view.position, Hash(write.position.0));
            assert_eq!(view.leaf, Hash(write.leaf));
            assert_eq!(view.write_counter, write.write_counter);
        })
        .count();
    assert_eq!(served, 2);
    let policy_read = api::storage_member_openings(
        db,
        rpc,
        GetStorageMemberOpeningsRequest {
            registry: source.into(),
            members: vec![Hash(field(4))],
            expected_root: Hash(root),
        },
    )
    .await;
    assert!(matches!(policy_read, Err(RingApiError::InvalidRequest(_))));
    handle.stop().unwrap();
    handle.stopped().await;
}

/// The source's fault after `update` lands at slot 2.
async fn fault_after(update: impl FnOnce(&Pair) -> Value) -> Option<String> {
    let created = pair();
    let update = update(&created);
    let source = created.source;
    let chain = Arc::new(Mutex::new(Chain {
        blocks: [(1, block(1, created.created)), (2, block(2, vec![update]))].into(),
        ..Default::default()
    }));
    let (rpc, handle) = rpc(chain).await;
    let indexer = replay_indexer(Arc::new(database().await), rpc);
    while indexer.synchronize().await.unwrap() == Progress::Behind {}
    let state = StorageStore::new(indexer.db.as_ref(), source.to_bytes())
        .state()
        .await
        .unwrap()
        .unwrap();
    handle.stop().unwrap();
    handle.stopped().await;
    state.fault
}

#[tokio::test]
async fn a_private_update_naming_another_tracking_registry_stops_the_projection() {
    let foreign = Address::new_from_array([60; 32]);
    let fault = fault_after(|pair| {
        SentUpdate {
            source: pair.source,
            tracking: foreign,
            revision: 0,
            restrictive: false,
            writes: vec![list_write(1, 1)],
            new_root: field(9),
        }
        .transaction()
    })
    .await
    .unwrap();
    assert!(fault.contains("another tracking registry"), "{fault}");
}

#[tokio::test]
async fn a_private_update_at_another_revision_stops_the_projection() {
    let fault = fault_after(|pair| {
        SentUpdate {
            source: pair.source,
            tracking: pair.tracking,
            revision: 5,
            restrictive: false,
            writes: vec![list_write(1, 1)],
            new_root: field(9),
        }
        .transaction()
    })
    .await
    .unwrap();
    assert!(fault.contains("update refused"), "{fault}");
}

#[tokio::test]
async fn a_private_write_counter_that_does_not_increase_stops_the_projection() {
    let fault = fault_after(|pair| {
        SentUpdate {
            source: pair.source,
            tracking: pair.tracking,
            revision: 0,
            restrictive: false,
            writes: vec![list_write(1, 5), list_write(2, 5)],
            new_root: field(9),
        }
        .transaction()
    })
    .await
    .unwrap();
    assert!(fault.contains("does not increase"), "{fault}");
}
