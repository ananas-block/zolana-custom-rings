//! From a tag 5 instruction to the opening a reader verifies under its root.

use std::net::SocketAddr;

use custom_ring_interface::{storage_instruction::AddressWriteData, QueueEntry};
use custom_ring_sdk::{EnrollAddress, UpdateStorage};
use sea_orm::{ConnectionTrait, Database, Statement, Value as SqlValue};
use sea_orm_migration::MigratorTrait;
use spr_indexer_api::RpcMethod;
use zolana_ring_client::RecordPoolCheck;
use zolana_ring_indexer::rpc::{
    method::{GetStorageMemberOpenings, GetStorageMemberRecords, GetStorageRecordPool},
    GetStorageMemberRecordsResponse, GetStorageRecordPoolResponse,
};

use super::*;
use crate::{indexer::Readiness, migration::Migrator, server::Server};

const CREATOR: Address = Address::new_from_array([41; 32]);
const ALICE: Address = Address::new_from_array([0x51; 32]);
const BOB: Address = Address::new_from_array([0x52; 32]);
const POOL_OPENINGS: u64 = 4;
/// `initialize_transaction` sets it.
const GRACE_SLOTS: u64 = 100;

fn member_of(owner: Address) -> [u8; 32] {
    *Member::owner_tag(owner.as_array()).unwrap().as_bytes()
}

/// The stranger's low record is `member`'s.
fn just_above(member: [u8; 32]) -> [u8; 32] {
    let mut above = member;
    above[31] = above[31].checked_add(1).unwrap();
    above
}

/// One ring's own registry, projected from what the SDK builders send.
struct Ledger {
    indexer: Indexer,
    handle: ServerHandle,
    chain: Arc<Mutex<Chain>>,
    registry: Address,
    tree: MemberRegistryTree,
    ring_id: [u8; 32],
    nullifier_pk: [u8; 32],
}

/// The address a reader expects, `None` off an enrolled record.
#[derive(Clone, Copy)]
struct Expected {
    present: bool,
    address: Option<AuthorizedAddress>,
}

#[derive(Clone, Copy)]
enum Tamper {
    ViewingKey,
    Revision,
    Removed,
    AddedToUnenrolled,
    LeafHash,
}

impl Ledger {
    async fn sqlite() -> Self {
        Self::open(database().await).await
    }

    async fn open(db: DatabaseConnection) -> Self {
        let ring_id = field(0x77);
        let (registry, initialize) = initialize_transaction(CREATOR, [42; 32], ring_id);
        let chain = Arc::new(Mutex::new(Chain {
            blocks: BTreeMap::from([(1, block(1, vec![initialize]))]),
            ..Default::default()
        }));
        let (rpc, handle) = rpc(chain.clone()).await;
        let ledger = Self {
            indexer: replay_indexer(Arc::new(db), rpc),
            handle,
            chain,
            registry,
            tree: MemberRegistryTree::new().unwrap(),
            ring_id,
            nullifier_pk: field(0x61),
        };
        ledger.synchronize().await;
        ledger
    }

    async fn land(&self, transactions: Vec<Value>) {
        {
            let mut chain = self.chain.lock().unwrap();
            let slot = chain.blocks.last_key_value().unwrap().0 + 1;
            chain.blocks.insert(slot, block(slot, transactions));
        }
        self.synchronize().await;
    }

    /// The chain takes the projected account, as an honest program writes it.
    async fn synchronize(&self) {
        while self.indexer.synchronize().await.unwrap() == Progress::Behind {}
        let projected = self.store().state().await.unwrap().unwrap();
        assert_eq!(projected.fault, None);
        let image = account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&*projected.account));
        self.chain
            .lock()
            .unwrap()
            .accounts
            .insert(self.registry.to_string(), image);
    }

    fn store(&self) -> StorageStore<'_, DatabaseConnection> {
        StorageStore::new(self.indexer.db.as_ref(), self.registry.to_bytes())
    }

    fn enrollment(&self, owner: Address, viewing_byte: u8) -> Instruction {
        EnrollAddress {
            payer: Address::new_from_array([1; 32]),
            owner,
            registry: self.registry,
            nullifier_pk: self.nullifier_pk,
            viewing_u: [viewing_byte; 32],
        }
        .instruction()
    }

    async fn enroll(&self, owner: Address, viewing_byte: u8) {
        self.land(vec![sent(&self.enrollment(owner, viewing_byte))])
            .await;
    }

    fn address(&self, viewing_byte: u8, address_revision: u64) -> AuthorizedAddress {
        AuthorizedAddress {
            ring_id: self.ring_id,
            nullifier_pk: self.nullifier_pk,
            viewing_u: [viewing_byte; 32],
            address_revision,
        }
    }

    /// Lands `writes` as the next graced update and returns its root.
    async fn update(&mut self, writes: Vec<(StorageWriteData, QueueEntry)>) -> [u8; 32] {
        let revision = self
            .store()
            .state()
            .await
            .unwrap()
            .unwrap()
            .account
            .newest()
            .revision;
        let chain_start = chain_start(&self.registry, revision).unwrap();
        let (writes, entries): (Vec<_>, Vec<_>) = writes.into_iter().unzip();
        let inputs = self.tree.apply(chain_start, &entries).unwrap();
        let update = UpdateStorage {
            authority: CREATOR,
            registry: self.registry,
            mode: UpdateMode::Graced,
            data: StorageUpdateIxData {
                revision,
                writes,
                apply: &apply_data(inputs.new_root, inputs.new_next_index),
            },
        }
        .instruction()
        .unwrap();
        self.land(vec![sent(&update)]).await;
        inputs.new_root
    }

    fn address_write(
        &self,
        owner: Address,
        address: &AuthorizedAddress,
    ) -> (StorageWriteData, QueueEntry) {
        let write = AddressWriteData {
            owner,
            address_revision: address.address_revision.to_le_bytes(),
        };
        let entry = write.entry(address).unwrap();
        (StorageWriteData::Address(write), entry)
    }

    fn openings_request(
        &self,
        member: &[u8; 32],
        root: &[u8; 32],
    ) -> GetStorageMemberOpeningsRequest {
        GetStorageMemberOpeningsRequest {
            registry: self.registry.into(),
            members: vec![Hash(*member)],
            expected_root: Hash(*root),
        }
    }

    fn pool_request(&self, member: &[u8; 32], root: &[u8; 32]) -> GetStorageRecordPoolRequest {
        GetStorageRecordPoolRequest {
            registry: self.registry.into(),
            members: vec![Hash(*member)],
            expected_root: Hash(*root),
            openings: POOL_OPENINGS,
        }
    }

    fn page_request(&self, root: &[u8; 32]) -> GetStorageMemberRecordsRequest {
        GetStorageMemberRecordsRequest {
            registry: self.registry.into(),
            expected_root: Hash(*root),
            start_index: 1,
            limit: 16,
        }
    }

    /// Every opening API serves `expected`, each read verified as a reader or the prover verifies it.
    async fn assert_serves(&self, member: &[u8; 32], root: &[u8; 32], expected: Expected) {
        let (db, rpc) = (self.indexer.db.as_ref(), self.indexer.rpc.as_ref());
        let opened = api::storage_member_openings(db, rpc, self.openings_request(member, root))
            .await
            .unwrap();
        assert_reader_agrees(&opened.openings[0], member, root, expected);
        let pool = api::storage_record_pool(db, rpc, self.pool_request(member, root))
            .await
            .unwrap();
        assert_prover_agrees(&pool, member, root, expected);
        let page = api::storage_member_records(db, rpc, self.page_request(root))
            .await
            .unwrap();
        assert_page_agrees(&page, member, root, expected);
    }

    async fn tamper(&self, member: &[u8; 32], tamper: Tamper) {
        let (set, value) = match tamper {
            Tamper::ViewingKey => ("address_viewing_u=$1", SqlValue::from(vec![0x99u8; 32])),
            Tamper::Revision => ("address_revision=$1", SqlValue::BigInt(Some(9))),
            Tamper::Removed => ("address_revision=$1", SqlValue::BigInt(None)),
            Tamper::LeafHash => ("address_hash=$1", SqlValue::from(vec![0x99u8; 32])),
            Tamper::AddedToUnenrolled => {
                return self.tamper_added(member).await;
            }
        };
        self.execute(
            &format!("{set} WHERE program=$2 AND member=$3"),
            value,
            member,
        )
        .await;
    }

    async fn tamper_added(&self, member: &[u8; 32]) {
        let bytes = SqlValue::from(vec![0x99u8; 32]);
        for column in [
            "address_ring_id",
            "address_nullifier_pk",
            "address_viewing_u",
        ] {
            self.execute(
                &format!("{column}=$1 WHERE program=$2 AND member=$3"),
                bytes.clone(),
                member,
            )
            .await;
        }
        self.execute(
            "address_revision=$1 WHERE program=$2 AND member=$3",
            SqlValue::BigInt(Some(1)),
            member,
        )
        .await;
    }

    async fn execute(&self, set: &str, value: SqlValue, member: &[u8; 32]) {
        let db = self.indexer.db.as_ref();
        db.execute(Statement::from_sql_and_values(
            db.get_database_backend(),
            format!("UPDATE ring_records SET {set}"),
            vec![
                value,
                SqlValue::from(self.registry.to_bytes().to_vec()),
                SqlValue::from(member.to_vec()),
            ],
        ))
        .await
        .unwrap();
    }

    /// No opening API answers once the stored row leaves its leaf hash.
    async fn assert_every_api_refuses(&self, member: &[u8; 32], root: &[u8; 32]) {
        let (db, rpc) = (self.indexer.db.as_ref(), self.indexer.rpc.as_ref());
        let internal =
            |error: Option<RingApiError>| matches!(error, Some(RingApiError::Internal(_)));
        assert!(internal(
            api::storage_member_openings(db, rpc, self.openings_request(member, root))
                .await
                .err()
        ));
        assert!(internal(
            api::storage_record_pool(db, rpc, self.pool_request(member, root))
                .await
                .err()
        ));
        assert!(internal(
            api::storage_member_records(db, rpc, self.page_request(root))
                .await
                .err()
        ));
    }

    async fn stop(self) {
        self.handle.stop().unwrap();
        self.handle.stopped().await;
    }
}

fn assert_reader_agrees(
    opening: &RingMemberOpening,
    member: &[u8; 32],
    root: &[u8; 32],
    expected: Expected,
) {
    let read = MemberOpeningRead::verify(opening, root, member).unwrap();
    assert_eq!(read.record().is_some(), expected.present);
    assert_eq!(read.address, expected.address);
    if let Some(record) = read.record() {
        let leaf_hash = expected
            .address
            .map_or([0; 32], |address| address.hash(member).unwrap());
        assert_eq!(record.address_hash, leaf_hash);
    }
}

/// `PoolRead` in `custom_ring_sdk`, the source of every record the transfer witness opens.
fn assert_prover_agrees(
    pool: &GetStorageRecordPoolResponse,
    member: &[u8; 32],
    root: &[u8; 32],
    expected: Expected,
) {
    let read = RecordPoolCheck {
        response: pool,
        root,
        members: &[*member],
        openings: POOL_OPENINGS as usize,
    }
    .verify()
    .unwrap();
    assert_eq!(read.record(member).is_some(), expected.present);
    assert_eq!(read.address(member).copied(), expected.address);
}

fn assert_page_agrees(
    page: &GetStorageMemberRecordsResponse,
    member: &[u8; 32],
    root: &[u8; 32],
    expected: Expected,
) {
    let row = page
        .records
        .iter()
        .find(|row| row.record.member.0 == *member);
    assert_eq!(row.is_some(), expected.present);
    if let Some(row) = row {
        let opening = RingMemberOpening {
            present: true,
            record: row.record.clone(),
            path: row.path.clone(),
        };
        assert_reader_agrees(&opening, member, root, expected);
    }
}

fn enrolled(address: AuthorizedAddress) -> Expected {
    Expected {
        present: true,
        address: Some(address),
    }
}

const UNENROLLED: Expected = Expected {
    present: true,
    address: None,
};
const ABSENT: Expected = Expected {
    present: false,
    address: None,
};

fn listed(member: [u8; 32]) -> (StorageWriteData, QueueEntry) {
    let write = StorageWriteData::Record(RecordWriteData {
        member,
        lists: WriteRecordsIxData {
            mask: 1u64.to_le_bytes(),
            value: 1u64.to_le_bytes(),
        },
        ..Zeroable::zeroed()
    });
    let entry = write.entry().unwrap();
    (write, entry)
}

/// An enrollment is the owner's alone, a rotation serves its new revision, older roots serve the older one.
async fn assert_ingested_addresses_open_under_each_root(db: DatabaseConnection) {
    let mut ledger = Ledger::open(db).await;
    let alice = member_of(ALICE);
    let bob = member_of(BOB);
    let (first, second) = (ledger.address(0x71, 1), ledger.address(0x72, 2));

    ledger.enroll(ALICE, 0x71).await;
    let enrolled_alone = ledger.tree.root().unwrap();
    ledger.assert_serves(&alice, &enrolled_alone, ABSENT).await;

    let writes = vec![ledger.address_write(ALICE, &first), listed(bob)];
    let first_root = ledger.update(writes).await;
    ledger
        .assert_serves(&alice, &first_root, enrolled(first))
        .await;
    ledger.assert_serves(&bob, &first_root, UNENROLLED).await;
    ledger
        .assert_serves(&member_of(CREATOR), &first_root, ABSENT)
        .await;

    ledger.enroll(ALICE, 0x72).await;
    ledger
        .assert_serves(&alice, &first_root, enrolled(first))
        .await;

    let writes = vec![ledger.address_write(ALICE, &second)];
    let second_root = ledger.update(writes).await;
    ledger
        .assert_serves(&alice, &second_root, enrolled(second))
        .await;
    ledger
        .assert_serves(&alice, &first_root, enrolled(first))
        .await;
    ledger.assert_serves(&bob, &second_root, UNENROLLED).await;

    // Inserted above alice, the relink rewrites her leaf and keeps her address.
    let writes = vec![listed(just_above(alice))];
    let relinked_root = ledger.update(writes).await;
    ledger
        .assert_serves(&alice, &relinked_root, enrolled(second))
        .await;
    ledger
        .assert_serves(&just_above(alice), &relinked_root, UNENROLLED)
        .await;
    ledger
        .assert_serves(&alice, &second_root, enrolled(second))
        .await;
    ledger
        .assert_serves(&alice, &first_root, enrolled(first))
        .await;

    ledger.tamper(&alice, Tamper::ViewingKey).await;
    ledger
        .assert_every_api_refuses(&alice, &relinked_root)
        .await;
    ledger.stop().await;
}

#[tokio::test]
async fn an_enrolled_address_reaches_a_verified_opening_under_each_root() {
    assert_ingested_addresses_open_under_each_root(database().await).await;
}

#[tokio::test]
#[ignore = "needs RING_INDEXER_TEST_POSTGRES_URL"]
async fn an_enrolled_address_reaches_a_verified_opening_under_each_root_on_postgres() {
    let url = std::env::var("RING_INDEXER_TEST_POSTGRES_URL").unwrap();
    let db = Database::connect(url).await.unwrap();
    Migrator::reset(&db).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    assert_ingested_addresses_open_under_each_root(db.clone()).await;
    Migrator::reset(&db).await.unwrap();
}

#[tokio::test]
async fn a_stored_row_off_its_leaf_hash_fails_every_opening_api() {
    let (alice, bob) = (member_of(ALICE), member_of(BOB));
    for (tamper, member) in [
        (Tamper::ViewingKey, alice),
        (Tamper::Revision, alice),
        (Tamper::Removed, alice),
        (Tamper::LeafHash, alice),
        (Tamper::AddedToUnenrolled, bob),
    ] {
        let mut ledger = Ledger::sqlite().await;
        let address = ledger.address(0x71, 1);
        ledger.enroll(ALICE, 0x71).await;
        let writes = vec![ledger.address_write(ALICE, &address), listed(bob)];
        let root = ledger.update(writes).await;
        ledger
            .assert_serves(
                &member,
                &root,
                match member == alice {
                    true => enrolled(address),
                    false => UNENROLLED,
                },
            )
            .await;
        ledger.tamper(&member, tamper).await;
        ledger.assert_every_api_refuses(&member, &root).await;
        ledger.stop().await;
    }
}

#[tokio::test]
async fn a_forged_wire_address_fails_the_reader_and_the_prover() {
    let mut ledger = Ledger::sqlite().await;
    let (alice, bob) = (member_of(ALICE), member_of(BOB));
    let address = ledger.address(0x71, 1);
    ledger.enroll(ALICE, 0x71).await;
    let writes = vec![ledger.address_write(ALICE, &address), listed(bob)];
    let root = ledger.update(writes).await;
    let (db, rpc) = (ledger.indexer.db.as_ref(), ledger.indexer.rpc.as_ref());
    let opened = api::storage_member_openings(db, rpc, ledger.openings_request(&alice, &root))
        .await
        .unwrap();
    let pool = api::storage_record_pool(db, rpc, ledger.pool_request(&alice, &root))
        .await
        .unwrap();
    let forge = |forgery: &dyn Fn(&mut RingAuthorizedAddressView)| {
        let mut opening = opened.openings[0].clone();
        forgery(opening.record.address.as_mut().unwrap());
        assert!(MemberOpeningRead::verify(&opening, &root, &alice).is_err());
        let mut forged = pool.clone();
        let row = forged
            .records
            .iter_mut()
            .find(|row| row.record.member.0 == alice)
            .unwrap();
        forgery(row.record.address.as_mut().unwrap());
        assert!(RecordPoolCheck {
            response: &forged,
            root: &root,
            members: &[alice],
            openings: POOL_OPENINGS as usize,
        }
        .verify()
        .is_err());
    };
    forge(&|view| view.viewing_u = Hash([0x99; 32]));
    forge(&|view| view.nullifier_pk = Hash([0x99; 32]));
    forge(&|view| view.ring_id = Hash([0x99; 32]));
    forge(&|view| view.address_revision += 1);

    let mut withheld = opened.openings[0].clone();
    withheld.record.address = None;
    assert!(MemberOpeningRead::verify(&withheld, &root, &alice).is_err());

    let unenrolled = api::storage_member_openings(db, rpc, ledger.openings_request(&bob, &root))
        .await
        .unwrap();
    let mut invented = unenrolled.openings[0].clone();
    invented.record.address = opened.openings[0].record.address.clone();
    assert!(MemberOpeningRead::verify(&invented, &root, &bob).is_err());
    ledger.stop().await;
}

#[tokio::test]
async fn an_absent_member_reads_no_address_from_its_low_record() {
    let mut ledger = Ledger::sqlite().await;
    let alice = member_of(ALICE);
    let address = ledger.address(0x71, 1);
    ledger.enroll(ALICE, 0x71).await;
    let writes = vec![ledger.address_write(ALICE, &address)];
    let root = ledger.update(writes).await;
    let stranger = just_above(alice);
    let (db, rpc) = (ledger.indexer.db.as_ref(), ledger.indexer.rpc.as_ref());
    let opened = api::storage_member_openings(db, rpc, ledger.openings_request(&stranger, &root))
        .await
        .unwrap();
    assert_eq!(opened.openings[0].record.member.0, alice);
    assert_eq!(
        opened.openings[0].record.address.as_ref().map(wire_address),
        Some(address)
    );
    ledger.assert_serves(&stranger, &root, ABSENT).await;
    ledger.stop().await;
}

#[tokio::test]
async fn a_read_past_the_root_history_is_refused_and_the_newest_root_still_opens() {
    let mut ledger = Ledger::sqlite().await;
    let alice = member_of(ALICE);
    let (first, second) = (ledger.address(0x71, 1), ledger.address(0x72, 2));
    ledger.enroll(ALICE, 0x71).await;
    let writes = vec![ledger.address_write(ALICE, &first)];
    let first_root = ledger.update(writes).await;
    ledger.enroll(ALICE, 0x72).await;
    let writes = vec![ledger.address_write(ALICE, &second)];
    let second_root = ledger.update(writes).await;
    ledger
        .assert_serves(&alice, &first_root, enrolled(first))
        .await;

    for _ in 0..=GRACE_SLOTS {
        ledger.land(Vec::new()).await;
    }

    let (db, rpc) = (ledger.indexer.db.as_ref(), ledger.indexer.rpc.as_ref());
    assert_eq!(
        api::storage_member_openings(db, rpc, ledger.openings_request(&alice, &first_root))
            .await
            .err(),
        Some(RingApiError::RootChanged)
    );
    assert_eq!(
        api::storage_record_pool(db, rpc, ledger.pool_request(&alice, &first_root))
            .await
            .err(),
        Some(RingApiError::RootChanged)
    );
    assert_eq!(
        api::storage_member_records(db, rpc, ledger.page_request(&first_root))
            .await
            .err(),
        Some(RingApiError::RootChanged)
    );
    ledger
        .assert_serves(&alice, &second_root, enrolled(second))
        .await;
    ledger.stop().await;
}

/// `ALICE` enrolls through a program that signs for her, the storage call at stack height 2.
fn invoked_enrollment(enrollment: &Instruction) -> Value {
    let wrapper = Address::new_from_array([0x88; 32]);
    let mut accounts: Vec<Address> = enrollment.accounts.iter().map(|meta| meta.pubkey).collect();
    accounts.push(STORAGE_PROGRAM_ID);
    let mut sent = transaction(wrapper, &accounts, &[]);
    sent["meta"]["innerInstructions"] = json!([{
        "index": 0,
        "instructions": [{
            "programIdIndex": enrollment.accounts.len(),
            "accounts": (0..enrollment.accounts.len()).collect::<Vec<_>>(),
            "data": bs58::encode(&enrollment.data).into_string(),
            "stackHeight": 2,
        }],
    }]);
    sent
}

#[tokio::test]
async fn an_enrollment_invoked_by_a_program_owner_is_ingested() {
    let mut ledger = Ledger::sqlite().await;
    let alice = member_of(ALICE);
    let address = ledger.address(0x71, 1);
    let enrollment = ledger.enrollment(ALICE, 0x71);
    ledger.land(vec![invoked_enrollment(&enrollment)]).await;
    assert_eq!(
        ledger.store().newest_enrollment(&alice).await.unwrap(),
        Some(address)
    );
    let writes = vec![ledger.address_write(ALICE, &address)];
    let root = ledger.update(writes).await;
    ledger.assert_serves(&alice, &root, enrolled(address)).await;
    ledger.stop().await;
}

#[tokio::test]
async fn a_failed_enrollment_leaves_no_address_and_takes_no_revision() {
    let ledger = Ledger::sqlite().await;
    let alice = member_of(ALICE);
    let mut failed = sent(&ledger.enrollment(ALICE, 0x71));
    let refusal = json!({"InstructionError": [0, {"Custom": 9016}]});
    failed["meta"]["err"] = refusal.clone();
    failed["meta"]["status"] = json!({ "Err": refusal });
    ledger.land(vec![failed]).await;
    assert_eq!(
        ledger.store().newest_enrollment(&alice).await.unwrap(),
        None
    );

    ledger.enroll(ALICE, 0x72).await;
    assert_eq!(
        ledger.store().newest_enrollment(&alice).await.unwrap(),
        Some(ledger.address(0x72, 1))
    );
    ledger.stop().await;
}

async fn call<M: RpcMethod>(
    client: &reqwest::Client,
    url: &str,
    request: &M::Request,
) -> M::Response
where
    M::Request: serde::Serialize,
    M::Response: serde::de::DeserializeOwned,
{
    let answer: Value = client
        .post(format!("{url}/v1/zolana/{}", M::NAME))
        .json(&json!({"jsonrpc": "2.0", "id": 7, "method": M::NAME, "params": request}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    serde_json::from_value(answer["result"].clone()).unwrap_or_else(|_| panic!("{answer}"))
}

#[tokio::test]
async fn the_served_json_verifies_on_the_wire_types_the_sdk_reads() {
    let mut ledger = Ledger::sqlite().await;
    let (alice, bob) = (member_of(ALICE), member_of(BOB));
    let address = ledger.address(0x71, 1);
    ledger.enroll(ALICE, 0x71).await;
    let writes = vec![ledger.address_write(ALICE, &address), listed(bob)];
    let root = ledger.update(writes).await;
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (served, server) = Server {
        db: ledger.indexer.db.clone(),
        rpc: ledger.indexer.rpc.clone(),
        photon: "http://127.0.0.1:1".parse().unwrap(),
        readiness: Readiness::default(),
        max_connections: 4,
    }
    .start(bind)
    .await
    .unwrap();
    let url = format!("http://{served}");
    let client = reqwest::Client::new();
    for (member, expected) in [(alice, enrolled(address)), (bob, UNENROLLED)] {
        let opened = call::<GetStorageMemberOpenings>(
            &client,
            &url,
            &ledger.openings_request(&member, &root),
        )
        .await;
        assert_reader_agrees(&opened.openings[0], &member, &root, expected);
        let pool =
            call::<GetStorageRecordPool>(&client, &url, &ledger.pool_request(&member, &root)).await;
        assert_prover_agrees(&pool, &member, &root, expected);
        let page =
            call::<GetStorageMemberRecords>(&client, &url, &ledger.page_request(&root)).await;
        assert_page_agrees(&page, &member, &root, expected);
    }
    server.stop().unwrap();
    server.stopped().await;
    ledger.stop().await;
}
