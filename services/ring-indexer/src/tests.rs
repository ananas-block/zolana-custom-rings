use std::sync::Arc;

use custom_ring_interface::{instruction::tag, pda, KEY_REGISTRY_EMPTY_ROOT};
use sea_orm::{Database, DatabaseConnection, TransactionTrait};
use sea_orm_migration::MigratorTrait;
use solana_address::Address;
use solana_signature::Signature;
use zolana_indexer_api::Hash;
use zolana_ring_indexer::{key_registry::MemberKey, rpc::RingMemberProofRequest};

use crate::{
    block::{BlockInfo, BlockMetadata, Instruction, InstructionGroup, TransactionInfo},
    error::RingApiError,
    indexer::{block_batch, Indexer, Readiness, StartSlot, MIN_BLOCK_BATCH},
    key_registry,
    migration::Migrator,
    rpc::SolanaRpc,
    storage::{self, LeafWrite, RingCursor, RingRoot, RingStore},
};

pub(crate) fn field(value: u8) -> [u8; 32] {
    let mut field = [0; 32];
    field[31] = value;
    field
}

pub(crate) fn member(value: u8) -> [u8; 32] {
    *zolana_ring_policy::Member::owner_tag(&[value; 32])
        .unwrap()
        .as_bytes()
}

pub(crate) async fn database() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    db
}

pub(crate) async fn fixture() -> (DatabaseConnection, RingRoot, RingCursor) {
    let db = database().await;
    let cursor = RingCursor::new(0);
    let root = initialize_root(&db, [11; 32]).await;
    storage::save_cursor(&db, &cursor).await.unwrap();
    (db, root, cursor)
}

pub(crate) async fn initialize_root(db: &DatabaseConnection, program: [u8; 32]) -> RingRoot {
    let root = RingRoot {
        program,
        address: pda::key_registry_root(&Address::new_from_array(program))
            .0
            .to_bytes(),
        root: KEY_REGISTRY_EMPTY_ROOT,
        next_index: 1,
        fault: None,
    };
    let sentinel = MemberKey::sentinel();
    let tx = db.begin().await.unwrap();
    let store = RingStore::new(&tx, program);
    let computed = store
        .tree()
        .write(&[LeafWrite {
            index: 0,
            hash: sentinel.hash().unwrap(),
        }])
        .await
        .unwrap();
    assert_eq!(computed, root.root);
    store.save_root(&root).await.unwrap();
    store.save_member(&sentinel).await.unwrap();
    tx.commit().await.unwrap();
    root
}

pub(crate) fn indexer(db: &DatabaseConnection, start: Option<StartSlot>) -> Indexer {
    Indexer {
        db: Arc::new(db.clone()),
        rpc: Arc::new(SolanaRpc::new("http://127.0.0.1:1".into())),
        start,
        block_fetches: 4,
        readiness: Readiness::default(),
    }
}

#[tokio::test]
async fn block_batches_cross_skipped_pages_without_skipping_live_blocks() {
    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("getBlocks", |params, _, _| {
            let (start, end, commitment): (u64, u64, serde_json::Value) = params.parse()?;
            assert_eq!(commitment["commitment"], "confirmed");
            Ok::<_, jsonrpsee::types::ErrorObjectOwned>(
                (5000..=5040)
                    .filter(|slot| (start..=end).contains(slot))
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap();
    let handle = server.start(module);
    let rpc = SolanaRpc::new(format!("http://{address}"));
    let first = block_batch(&rpc, 1..=5100, MIN_BLOCK_BATCH).await.unwrap();
    assert_eq!(first.slots, (5000..=5031).collect::<Vec<_>>());
    assert_eq!(first.scanned_slot, 5031);
    let second = block_batch(&rpc, 5032..=5100, MIN_BLOCK_BATCH)
        .await
        .unwrap();
    assert_eq!(second.slots, (5032..=5040).collect::<Vec<_>>());
    assert_eq!(second.scanned_slot, 5100);
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn an_explicit_start_slot_must_match_the_stored_cursor() {
    let (db, _, _) = fixture().await;
    assert!(indexer(&db, Some(StartSlot::Slot(6)))
        .cursor()
        .await
        .is_err());
    for start in [
        Some(StartSlot::Slot(1)),
        Some(StartSlot::Slot(0)),
        Some(StartSlot::Latest),
        None,
    ] {
        let cursor = indexer(&db, start).cursor().await.unwrap();
        assert_eq!(cursor.start_slot, 0, "{start:?}");
    }
}

#[tokio::test]
async fn an_empty_index_needs_a_start_slot() {
    let db = database().await;
    assert!(indexer(&db, None).cursor().await.is_err());
    assert!(storage::cursor(&db).await.unwrap().is_none());
    let cursor = indexer(&db, Some(StartSlot::Slot(10)))
        .cursor()
        .await
        .unwrap();
    assert_eq!((cursor.start_slot, cursor.scanned_slot), (9, 9));
    assert_eq!(
        indexer(&db, None).cursor().await.unwrap().start_slot,
        cursor.start_slot
    );
}

#[test]
fn start_slots_parse_a_slot_or_latest() {
    assert_eq!("latest".parse(), Ok(StartSlot::Latest));
    assert_eq!("42".parse(), Ok(StartSlot::Slot(42)));
    assert!("soon".parse::<StartSlot>().is_err());
}

#[tokio::test]
async fn an_invalid_instruction_quarantines_only_its_ring_until_rollback() {
    let (db, faulty, mut cursor) = fixture().await;
    let healthy = initialize_root(&db, [12; 32]).await;
    let garbage = |program: [u8; 32], error: Option<String>| TransactionInfo {
        signature: Signature::from([1; 64]),
        error,
        instruction_groups: vec![InstructionGroup {
            outer_instruction: Instruction {
                program_id: Address::new_from_array(program),
                data: vec![tag::REGISTER_KEY, 1, 2, 3],
                accounts: vec![],
                stack_height: Some(1),
            },
            inner_instructions: vec![],
        }],
    };
    let block = BlockInfo {
        metadata: BlockMetadata {
            slot: 3,
            blockhash: Hash(field(3)),
            ..Default::default()
        },
        transactions: vec![
            garbage(faulty.program, None),
            garbage(healthy.program, Some("failed".into())),
        ],
    };
    let indexer = indexer(&db, None);
    let tx = db.begin().await.unwrap();
    indexer.apply_block(&tx, &block, &mut cursor).await.unwrap();
    tx.commit().await.unwrap();

    assert!(fault_of(&db, faulty.program).await.is_some());
    assert!(fault_of(&db, healthy.program).await.is_none());
    cursor.resume(&db).await.unwrap();
    let request = |program: [u8; 32]| RingMemberProofRequest {
        ring_program_id: Address::new_from_array(program).into(),
        member: Hash(member(4)),
        expected_root: Hash(KEY_REGISTRY_EMPTY_ROOT),
        expected_next_index: 1,
    };
    assert!(matches!(
        key_registry::lookup(&db, &indexer.rpc, request(faulty.program)).await,
        Err(RingApiError::OutOfSync(_))
    ));
    assert_eq!(
        key_registry::lookup(&db, &indexer.rpc, request(healthy.program)).await,
        Err(RingApiError::MemberUnregistered)
    );

    let mut restarted = storage::cursor(&db).await.unwrap().unwrap();
    let tx = db.begin().await.unwrap();
    storage::rollback(&tx, &mut restarted).await.unwrap();
    tx.commit().await.unwrap();
    assert!(fault_of(&db, faulty.program).await.is_none());
    assert!(restarted.tip.is_none());
}

async fn fault_of(db: &DatabaseConnection, program: [u8; 32]) -> Option<String> {
    RingStore::new(db, program)
        .root()
        .await
        .unwrap()
        .unwrap()
        .fault
}

#[test]
fn ring_errors_keep_their_wire_codes() {
    for (error, code) in [
        (RingApiError::OutOfSync(String::new()), -32070),
        (RingApiError::RootChanged, -32071),
        (RingApiError::MemberUnregistered, -32072),
        (RingApiError::MemberAlreadyRegistered, -32073),
        (RingApiError::SpendRecordOutOfSync(String::new()), -32074),
        (RingApiError::InvalidRequest(String::new()), -32600),
        (RingApiError::Internal(String::new()), -32603),
    ] {
        assert_eq!(jsonrpsee::types::ErrorObjectOwned::from(error).code(), code);
    }
}

#[tokio::test]
#[ignore = "needs RING_INDEXER_TEST_POSTGRES_URL"]
async fn postgres_migrates_both_ways_and_serves_the_ring_queries() {
    let url = std::env::var("RING_INDEXER_TEST_POSTGRES_URL").unwrap();
    let db = Database::connect(url).await.unwrap();
    Migrator::reset(&db).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    Migrator::down(&db, None).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let root = initialize_root(&db, [11; 32]).await;
    let store = RingStore::new(&db, root.program);
    let path = store.tree().path(&root.root, 0).await.unwrap();
    assert_eq!(path.leaf, MemberKey::sentinel().hash().unwrap());
    assert_eq!(store.predecessor(&member(4)).await.unwrap().index, 0);
    let row = crate::spend_record::tests::row(4, 1);
    let spend = crate::spend_record::SpendStore::new(&db, root.program);
    spend.open().await.unwrap();
    spend.save(&row).await.unwrap();
    assert_eq!(spend.record(&row.member).await.unwrap(), Some(row.clone()));
    let mut cursor = RingCursor::new(0);
    cursor.resume(&db).await.unwrap();
    let tx = storage::begin_read(&db).await.unwrap();
    assert!(storage::cursor(&tx).await.unwrap().unwrap().is_ready());
    tx.commit().await.unwrap();
    Migrator::reset(&db).await.unwrap();
}
