use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use bytemuck::Zeroable;
use custom_ring_interface::{
    member_registry::AuthorizedAddress,
    storage::{chain_start, RegistryId, Revision, StorageRegistry},
    storage_instruction::{
        tag, EnrollAddressIxData, InitializeIxData, StorageUpdateIxData, StorageWriteData,
        UpdateMode,
    },
    ApplyRecordsIxData, RecordWriteData, WriteRecordsIxData, STORAGE_PROGRAM_ID,
};
use custom_ring_sdk::UpdateStorage;
use jsonrpsee::{server::ServerHandle, types::ErrorObjectOwned};
use sea_orm::DatabaseConnection;
use serde_json::{json, Value};
use solana_address::Address;
use solana_transaction::Instruction;
use spr_indexer_api::Hash;
use spr_keypair::{NullifierKey, X25519Keypair};
use zolana_ring_client::{
    rpc::{EscrowRegistration, RecordUpdateEntry},
    MemberOpeningRead, NullifierKeyEnvelope,
};
use zolana_ring_indexer::{
    rpc::{
        GetStorageApplyProofInputsRequest, GetStorageMemberOpeningsRequest,
        GetStorageMemberOpeningsResponse, GetStorageMemberRecordsRequest,
        GetStorageRecordPoolRequest, RingAuthorizedAddressView, RingEscrowPreimageView,
        RingMemberOpening, RingMemberRecordView, RingRecordPathView, StorageRootView,
        StorageWriteView,
    },
    tree::{MemberRecord, OpeningCheck, QuadPath, RecordOpening, RecordTree},
};
use zolana_ring_member_registry::MemberRegistryTree;
use zolana_ring_policy::Member;

use crate::{
    api,
    error::RingApiError,
    indexer::{Indexer, Progress, Readiness, StartSlot},
    rpc::SolanaRpc,
    storage::StorageStore,
    tests::{database, field},
};

#[path = "address_response_tests.rs"]
mod address_response;
#[path = "tracking_replay_tests.rs"]
mod tracking_replay;

/// Mutable confirmed RPC history, including failures between replay commits.
#[derive(Default)]
struct Chain {
    blocks: BTreeMap<u64, Value>,
    accounts: HashMap<String, Value>,
    failed_block: Option<u64>,
    /// Account reads answer from a bank that many slots behind the newest block.
    accounts_lag: u64,
    /// Every `getBlock` and `getMultipleAccounts` answered.
    upstream_calls: u64,
}

impl Chain {
    fn accounts_slot(&self) -> u64 {
        let newest = self.blocks.last_key_value().map_or(0, |(slot, _)| *slot);
        newest.saturating_sub(self.accounts_lag)
    }
}

async fn rpc(chain: Arc<Mutex<Chain>>) -> (Arc<SolanaRpc>, ServerHandle) {
    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let mut module = jsonrpsee::RpcModule::new(chain);
    module
        .register_method("getSlot", |_, chain, _| {
            *chain.lock().unwrap().blocks.last_key_value().unwrap().0
        })
        .unwrap();
    module
        .register_method("getBlocks", |params, chain, _| {
            let (start, end, _): (u64, u64, Value) = params.parse()?;
            Ok::<_, ErrorObjectOwned>(
                chain
                    .lock()
                    .unwrap()
                    .blocks
                    .range(start..=end)
                    .map(|(slot, _)| *slot)
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap();
    module
        .register_method("getBlock", |params, chain, _| {
            let (slot, options): (u64, Value) = params.parse()?;
            let mut chain = chain.lock().unwrap();
            chain.upstream_calls += 1;
            if chain.failed_block == Some(slot) && options["transactionDetails"] == "full" {
                return Err(ErrorObjectOwned::owned(
                    -32000,
                    "temporary archive failure",
                    None::<()>,
                ));
            }
            chain
                .blocks
                .get(&slot)
                .cloned()
                .ok_or_else(|| ErrorObjectOwned::owned(-32007, "skipped", None::<()>))
        })
        .unwrap();
    module
        .register_method("getMultipleAccounts", |params, chain, _| {
            let (addresses, config): (Vec<String>, Value) = params.parse()?;
            let mut chain = chain.lock().unwrap();
            chain.upstream_calls += 1;
            let slot = chain.accounts_slot();
            if config["minContextSlot"].as_u64() > Some(slot) {
                return Err(ErrorObjectOwned::owned(
                    -32016,
                    "Minimum context slot has not been reached",
                    None::<()>,
                ));
            }
            let accounts = addresses
                .iter()
                .map(|address| chain.accounts.get(address))
                .collect::<Vec<_>>();
            Ok(json!({ "context": { "slot": slot }, "value": accounts }))
        })
        .unwrap();
    (
        Arc::new(SolanaRpc::new(format!("http://{address}"))),
        server.start(module),
    )
}

fn account(owner: Address, data: &[u8]) -> Value {
    json!({"lamports": 1, "owner": owner.to_string(), "data": [STANDARD.encode(data), "base64"], "executable": false, "rentEpoch": 0})
}

fn block(slot: u64, transactions: Vec<Value>) -> Value {
    json!({"blockhash": Hash(field(slot as u8)).to_string(),
        "previousBlockhash": Hash(field(slot.saturating_sub(1) as u8)).to_string(),
        "parentSlot": slot.saturating_sub(1), "blockTime": slot, "blockHeight": slot, "transactions": transactions})
}

/// Archived transactions must pass the production RPC decoder.
fn transaction(program: Address, accounts: &[Address], data: &[u8]) -> Value {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&[1; 64]);
    bytes.extend_from_slice(&[1, 0, 1, (accounts.len() + 1) as u8]);
    for key in accounts.iter().chain(std::iter::once(&program)) {
        bytes.extend_from_slice(key.as_ref());
    }
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&[1, accounts.len() as u8, accounts.len() as u8]);
    bytes.extend(0..accounts.len() as u8);
    let mut length = data.len();
    loop {
        let byte = (length & 127) as u8;
        length >>= 7;
        bytes.push(byte | if length == 0 { 0 } else { 128 });
        if length == 0 {
            break;
        }
    }
    bytes.extend_from_slice(data);
    json!({"transaction": [STANDARD.encode(bytes), "base64"], "version": "legacy", "meta": {
        "err": null, "status": {"Ok": null}, "fee": 0,
        "preBalances": vec![1; accounts.len()+1], "postBalances": vec![1; accounts.len()+1],
        "innerInstructions": [], "logMessages": [], "loadedAddresses": {"readonly": [], "writable": []}
    }})
}

fn apply_data(new_root: [u8; 32], new_next_index: u64) -> ApplyRecordsIxData {
    ApplyRecordsIxData {
        proof: Zeroable::zeroed(),
        new_root,
        new_next_index: u32::try_from(new_next_index).unwrap().to_le_bytes(),
    }
}

fn wire_record(record: &RingMemberRecordView) -> MemberRecord {
    MemberRecord {
        mint_policy: record.mint_policy,
        member: record.member.0,
        next: record.next.0,
        lists: record.lists,
        escrow_key: record.escrow_key.0,
        address_hash: record.address_hash.0,
    }
}

fn wire_path(path: &RingRecordPathView) -> QuadPath {
    QuadPath {
        index: path.index,
        siblings: core::array::from_fn(|level| {
            path.siblings[level].clone().map(|sibling| sibling.0)
        }),
    }
}

fn record_opening(opening: &RingMemberOpening) -> RecordOpening {
    let (record, path) = (wire_record(&opening.record), wire_path(&opening.path));
    if opening.present {
        RecordOpening::Present { record, path }
    } else {
        RecordOpening::Absent { low: record, path }
    }
}

fn replay_indexer(db: Arc<DatabaseConnection>, rpc: Arc<SolanaRpc>) -> Indexer {
    Indexer {
        db,
        rpc,
        start: Some(StartSlot::Slot(0)),
        block_fetches: 4,
        readiness: Readiness::default(),
    }
}

fn sent(instruction: &Instruction) -> Value {
    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| meta.pubkey)
        .collect::<Vec<_>>();
    transaction(instruction.program_id, &accounts, &instruction.data)
}

fn initialize_transaction(
    creator: Address,
    registry_id: [u8; 32],
    ring_id: [u8; 32],
) -> (Address, Value) {
    let registry_id = RegistryId(registry_id);
    let (registry, _) = StorageRegistry::find_address(&creator, &registry_id);
    let data = InitializeIxData {
        registry_id,
        grace_slots: 100u64.to_le_bytes(),
        ring_id,
    };
    let wire = [&[tag::INITIALIZE][..], bytemuck::bytes_of(&data)].concat();
    let accounts = [
        Address::new_from_array([1; 32]),
        creator,
        registry,
        Address::new_from_array([0; 32]),
    ];
    (registry, transaction(STORAGE_PROGRAM_ID, &accounts, &wire))
}

/// One registry the indexer projected through `Initialize` and one graced `Update`.
struct StorageReplay {
    indexer: Indexer,
    handle: ServerHandle,
    registry: Address,
    root: [u8; 32],
    next_index: u64,
}

impl StorageReplay {
    async fn updated(writes: Vec<StorageWriteData>) -> Self {
        let creator = Address::new_from_array([41; 32]);
        let (registry, initialize) = initialize_transaction(creator, [42; 32], [0; 32]);
        let chain_start = chain_start(&registry, Revision::default()).unwrap();
        let entries: Vec<_> = writes.iter().map(|write| write.entry().unwrap()).collect();
        let inputs = MemberRegistryTree::new()
            .unwrap()
            .apply(chain_start, &entries)
            .unwrap();
        let update = UpdateStorage {
            authority: creator,
            registry,
            mode: UpdateMode::Graced,
            data: StorageUpdateIxData {
                revision: Revision::default(),
                writes,
                apply: &apply_data(inputs.new_root, inputs.new_next_index),
            },
        }
        .instruction()
        .unwrap();
        let chain = Arc::new(Mutex::new(Chain {
            blocks: BTreeMap::from([
                (1, block(1, vec![initialize])),
                (2, block(2, vec![sent(&update)])),
            ]),
            ..Default::default()
        }));
        let (rpc, handle) = rpc(chain.clone()).await;
        let indexer = replay_indexer(Arc::new(database().await), rpc);
        while indexer.synchronize().await.unwrap() == Progress::Behind {}
        // The chain takes the projected account, as an honest program writes it.
        let projected = StorageStore::new(indexer.db.as_ref(), registry.to_bytes())
            .state()
            .await
            .unwrap()
            .unwrap();
        let image = account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&*projected.account));
        chain
            .lock()
            .unwrap()
            .accounts
            .insert(registry.to_string(), image);
        Self {
            indexer,
            handle,
            registry,
            root: inputs.new_root,
            next_index: inputs.new_next_index,
        }
    }

    async fn openings(&self, members: &[[u8; 32]]) -> GetStorageMemberOpeningsResponse {
        api::storage_member_openings(
            self.indexer.db.as_ref(),
            self.indexer.rpc.as_ref(),
            GetStorageMemberOpeningsRequest {
                registry: self.registry.into(),
                members: members.iter().copied().map(Hash).collect(),
                expected_root: Hash(self.root),
            },
        )
        .await
        .unwrap()
    }

    async fn stop(self) {
        self.handle.stop().unwrap();
        self.handle.stopped().await;
    }
}

#[tokio::test]
async fn a_storage_update_serves_openings_under_its_new_root() {
    let member = *Member::owner_tag(&[43; 32]).unwrap().as_bytes();
    let write = StorageWriteData::Record(RecordWriteData {
        member,
        lists: WriteRecordsIxData {
            mask: 1u64.to_le_bytes(),
            value: 1u64.to_le_bytes(),
        },
        ..Zeroable::zeroed()
    });
    let replay = StorageReplay::updated(vec![write]).await;
    let response = replay.openings(&[member]).await;
    let served = StorageRootView {
        root: Hash(replay.root),
        revision: 1,
        next_index: replay.next_index,
    };
    assert_eq!(response.root, served);
    let [opening] = response.openings.as_slice() else {
        panic!("one member opens once");
    };
    let opened = OpeningCheck {
        opening: &record_opening(opening),
        root: &replay.root,
        member: &member,
    }
    .verify()
    .unwrap();
    assert_eq!(opened.map(|record| record.lists), Some(1));
    replay.stop().await;
}

#[tokio::test]
async fn a_storage_escrow_write_serves_an_envelope_the_auditor_opens() {
    let auditor = X25519Keypair::new();
    let owner = Address::new_from_array([43; 32]);
    let member = *Member::owner_tag(owner.as_array()).unwrap().as_bytes();
    let envelope =
        NullifierKeyEnvelope::new(&NullifierKey::from_secret([7; 31]), &auditor.pubkey()).unwrap();
    let registration = EscrowRegistration {
        member: Hash(member),
        nullifier_pk: Hash(envelope.nullifier_pk),
        eph_pk: envelope.sealed.eph_pk.as_bytes().to_vec().into(),
        ciphertext: envelope.sealed.ciphertext.to_vec().into(),
        proof: Vec::new().into(),
    };
    let write = RecordUpdateEntry::Escrow(registration)
        .write(&owner)
        .unwrap();
    let replay = StorageReplay::updated(vec![write]).await;
    let page = api::storage_member_records(
        replay.indexer.db.as_ref(),
        replay.indexer.rpc.as_ref(),
        GetStorageMemberRecordsRequest {
            registry: replay.registry.into(),
            expected_root: Hash(replay.root),
            start_index: 1,
            limit: 16,
        },
    )
    .await
    .unwrap();
    let [row] = page.records.as_slice() else {
        panic!("one record past the sentinel, {:?}", page.records);
    };
    let [opening] = replay
        .openings(&[member])
        .await
        .openings
        .try_into()
        .unwrap();
    assert_eq!(opening.record, row.record);
    let read = MemberOpeningRead::verify(&opening, &replay.root, &member).unwrap();
    assert_eq!(read.owner_pubkey, Some(owner));
    let escrowed = read.escrowed(&envelope.nullifier_pk).unwrap().unwrap();
    let opened = escrowed.sealed.open(&auditor).unwrap();
    assert_eq!(opened.pubkey().unwrap(), envelope.nullifier_pk);
    replay.stop().await;
}

const ADDRESS_VECTOR: &str = include_str!("../../../test-vectors/registry/address_record.json");

fn hex_field(value: &Value) -> [u8; 32] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn hex_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

/// `test-vectors/registry/address_record.json` projected through the indexer.
struct AddressReplay {
    indexer: Indexer,
    handle: ServerHandle,
    registry: Address,
    updates: Vec<Value>,
    enrollments: Vec<Value>,
    chain: Arc<Mutex<Chain>>,
}

impl AddressReplay {
    /// `Initialize` at slot 1, then one slot per step of the vector.
    async fn through(steps: usize) -> Self {
        let vector: Value = serde_json::from_str(ADDRESS_VECTOR).unwrap();
        let creator = Address::new_from_array(hex_field(&vector["creator"]));
        let (registry, initialize) = initialize_transaction(
            creator,
            hex_field(&vector["registry_id"]),
            hex_field(&vector["ring_id"]),
        );
        assert_eq!(registry.to_bytes(), hex_field(&vector["registry"]));
        let mut blocks = BTreeMap::from([(1, block(1, vec![initialize]))]);
        let steps_json = vector["steps"].as_array().unwrap();
        for (slot, step) in (2..).zip(&steps_json[..steps]) {
            let mut transactions = enrollment_transactions(&step["enrollments"], registry);
            transactions.push(update_transaction(creator, registry, &step["update"]));
            blocks.insert(slot, block(slot, transactions));
        }
        let chain = Arc::new(Mutex::new(Chain {
            blocks,
            ..Default::default()
        }));
        let (rpc, handle) = rpc(chain.clone()).await;
        let replay = Self {
            indexer: replay_indexer(Arc::new(database().await), rpc),
            handle,
            registry,
            updates: steps_json
                .iter()
                .map(|step| step["update"].clone())
                .collect(),
            enrollments: steps_json
                .iter()
                .map(|step| step["enrollments"].clone())
                .collect(),
            chain,
        };
        replay.synchronize().await;
        replay
    }

    /// Lands `step`'s enrollments alone, its update still to come.
    async fn land_enrollments(&self, step: usize) {
        let transactions = enrollment_transactions(&self.enrollments[step], self.registry);
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

    async fn stop(self) {
        self.handle.stop().unwrap();
        self.handle.stopped().await;
    }
}

fn enrollment_transactions(enrollments: &Value, registry: Address) -> Vec<Value> {
    enrollments
        .as_array()
        .unwrap()
        .iter()
        .map(|enrollment| {
            enroll_transaction(
                Address::new_from_array(hex_field(&enrollment["owner"])),
                registry,
                &hex_bytes(&enrollment["instruction_data"]),
            )
        })
        .collect()
}

fn enroll_transaction(owner: Address, registry: Address, data: &[u8]) -> Value {
    let authorization = Address::new_from_array([7; 32]);
    let accounts = [
        Address::new_from_array([1; 32]),
        owner,
        registry,
        authorization,
        Address::new_from_array([0; 32]),
    ];
    transaction(STORAGE_PROGRAM_ID, &accounts, data)
}

fn update_transaction(authority: Address, registry: Address, update: &Value) -> Value {
    let revision: u64 = update["batch_revision"].as_str().unwrap().parse().unwrap();
    let apply = apply_data(
        hex_field(&update["new_root"]),
        update["new_next_index"].as_u64().unwrap(),
    );
    let data = StorageUpdateIxData {
        revision: Revision::from(revision),
        writes: StorageWriteData::parse_all(&hex_bytes(&update["writes_wire"])).unwrap(),
        apply: &apply,
    };
    let wire = [&[UpdateMode::Graced.tag()][..], &data.encode().unwrap()].concat();
    transaction(STORAGE_PROGRAM_ID, &[authority, registry], &wire)
}

fn wire_address(view: &RingAuthorizedAddressView) -> AuthorizedAddress {
    AuthorizedAddress {
        ring_id: view.ring_id.0,
        nullifier_pk: view.nullifier_pk.0,
        viewing_u: view.viewing_u.0,
        address_revision: view.address_revision,
    }
}

/// The served opening reaches the vector's root and its address hashes to the leaf.
fn assert_served_opening(opening: &RingMemberOpening, expected: &Value) {
    let member = hex_field(&expected["member"]);
    let root = hex_field(&expected["root"]);
    let record = wire_record(&opening.record);
    OpeningCheck {
        opening: &record_opening(opening),
        root: &root,
        member: &member,
    }
    .verify()
    .unwrap();
    assert_eq!(opening.present, expected["present"].as_bool().unwrap());
    assert_eq!(
        record.hash().unwrap(),
        hex_field(&expected["record"]["leaf_hash"])
    );
    let address = opening.record.address.as_ref().map(wire_address);
    record.check_address(address.as_ref()).unwrap();
    assert_eq!(
        opening
            .record
            .ciphertext
            .as_ref()
            .map(|sealed| hex::encode(&sealed.0)),
        expected["escrow"]["ciphertext"]
            .as_str()
            .map(str::to_string)
    );
    assert_eq!(
        address.map(|address| {
            (
                hex::encode(address.viewing_u),
                address.address_revision.to_string(),
            )
        }),
        expected["address"].as_object().map(|bound| {
            (
                bound["viewing_u"].as_str().unwrap().to_string(),
                bound["address_revision"].as_str().unwrap().to_string(),
            )
        })
    );
}

#[tokio::test]
async fn every_opening_api_serves_the_authorized_address_under_each_vector_root() {
    let replay = AddressReplay::through(8).await;
    let (db, rpc) = (replay.indexer.db.as_ref(), replay.indexer.rpc.as_ref());
    for update in &replay.updates {
        for expected in update["openings"].as_array().unwrap() {
            let member = Hash(hex_field(&expected["member"]));
            let root = Hash(hex_field(&expected["root"]));
            let registry = replay.registry.into();
            let opened = api::storage_member_openings(
                db,
                rpc,
                GetStorageMemberOpeningsRequest {
                    registry,
                    members: vec![member.clone()],
                    expected_root: root.clone(),
                },
            )
            .await
            .unwrap();
            assert_served_opening(&opened.openings[0], expected);
            let pool = api::storage_record_pool(
                db,
                rpc,
                GetStorageRecordPoolRequest {
                    registry,
                    members: vec![member],
                    expected_root: root.clone(),
                    openings: 4,
                },
            )
            .await
            .unwrap();
            assert_eq!(pool.records[0].record, opened.openings[0].record);
            let page = api::storage_member_records(
                db,
                rpc,
                GetStorageMemberRecordsRequest {
                    registry,
                    expected_root: root,
                    start_index: 1,
                    limit: 16,
                },
            )
            .await
            .unwrap();
            if opened.openings[0].present {
                assert!(page
                    .records
                    .iter()
                    .any(|row| row.record == opened.openings[0].record));
            }
        }
    }
    replay.stop().await;
}

fn address_only_view(entry: &Value) -> StorageWriteView {
    StorageWriteView {
        member: Hash(hex_field(&entry["member"])),
        mask: 0,
        value: 0,
        escrow_key: Hash([0; 32]),
        mint_policy: None,
        address_hash: Hash(hex_field(&entry["address_hash"])),
        escrow_preimage: None,
    }
}

#[tokio::test]
async fn apply_proof_inputs_reach_the_vector_root_of_an_address_write() {
    let replay = AddressReplay::through(1).await;
    let (db, rpc) = (replay.indexer.db.as_ref(), replay.indexer.rpc.as_ref());
    let next = &replay.updates[1];
    let write = address_only_view(&next["entries"][0]);
    let request = |write: StorageWriteView| GetStorageApplyProofInputsRequest {
        registry: replay.registry.into(),
        writes: vec![write],
    };
    let refused = RingApiError::InvalidRequest("an address write has no enrollment".into());
    assert_eq!(
        api::storage_apply_proof_inputs(db, rpc, request(write.clone())).await,
        Err(refused)
    );
    replay.land_enrollments(1).await;
    let mixed = StorageWriteView {
        mask: 1,
        value: 1,
        ..write.clone()
    };
    assert!(matches!(
        api::storage_apply_proof_inputs(db, rpc, request(mixed)).await,
        Err(RingApiError::InvalidRequest(_))
    ));
    let inputs = api::storage_apply_proof_inputs(db, rpc, request(write.clone()))
        .await
        .unwrap();
    assert_eq!(inputs.new_root, Hash(hex_field(&next["new_root"])));
    assert_eq!(inputs.chain_end, Hash(hex_field(&next["chain_end"])));
    assert_eq!(inputs.writes[0].address_hash, write.address_hash);
    assert_eq!(inputs.writes[0].old_address_hash, Hash([0; 32]));
    assert_eq!(inputs.writes[0].pair, None);
    replay.stop().await;
}

/// The stored or requested escrow preimage reaches the witness under the vector's hash.
#[tokio::test]
async fn apply_proof_inputs_return_both_preimages_of_a_pair() {
    let replay = AddressReplay::through(3).await;
    let (db, rpc) = (replay.indexer.db.as_ref(), replay.indexer.rpc.as_ref());
    let next = &replay.updates[3];
    let entry = &next["entries"][0];
    let expected = &next["writes"][0]["pair"];
    let bound = &next["openings"][0]["escrow"];
    let write = StorageWriteView {
        member: Hash(hex_field(&entry["member"])),
        mask: entry["mask"].as_str().unwrap().parse().unwrap(),
        value: entry["value"].as_str().unwrap().parse().unwrap(),
        escrow_key: Hash(hex_field(&entry["escrow_key"])),
        mint_policy: None,
        address_hash: Hash([0; 32]),
        escrow_preimage: None,
    };
    let request = |write: StorageWriteView| GetStorageApplyProofInputsRequest {
        registry: replay.registry.into(),
        writes: vec![write],
    };
    assert!(matches!(
        api::storage_apply_proof_inputs(db, rpc, request(write.clone())).await,
        Err(RingApiError::InvalidRequest(_))
    ));
    let preimage = RingEscrowPreimageView {
        nullifier_pk: Hash(hex_field(&bound["nullifier_pk"])),
        ciphertext: hex_bytes(&bound["ciphertext"]).into(),
    };
    let wrong = RingEscrowPreimageView {
        nullifier_pk: Hash(field(9)),
        ..preimage.clone()
    };
    assert!(matches!(
        api::storage_apply_proof_inputs(
            db,
            rpc,
            request(StorageWriteView {
                escrow_preimage: Some(wrong),
                ..write.clone()
            })
        )
        .await,
        Err(RingApiError::InvalidRequest(_))
    ));
    let inputs = api::storage_apply_proof_inputs(
        db,
        rpc,
        request(StorageWriteView {
            escrow_preimage: Some(preimage),
            ..write
        }),
    )
    .await
    .unwrap();
    assert_eq!(inputs.new_root, Hash(hex_field(&next["new_root"])));
    let pair = inputs.writes[0].pair.as_ref().unwrap();
    assert_eq!(
        pair.escrow_ciphertext_hash,
        Hash(hex_field(&expected["escrow_ciphertext_hash"]))
    );
    assert_eq!(
        pair.address.nullifier_pk,
        Hash(hex_field(&expected["nullifier_pk"]))
    );
    assert_eq!(
        pair.address.ring_id,
        Hash(hex_field(&expected["address_ring"]))
    );
    replay.stop().await;
    // An address write beside a stored escrow key takes the stored seal.
    let replay = AddressReplay::through(5).await;
    replay.land_enrollments(5).await;
    let (db, rpc) = (replay.indexer.db.as_ref(), replay.indexer.rpc.as_ref());
    let applied = &replay.updates[5];
    let inputs = api::storage_apply_proof_inputs(
        db,
        rpc,
        GetStorageApplyProofInputsRequest {
            registry: replay.registry.into(),
            writes: vec![address_only_view(&applied["entries"][0])],
        },
    )
    .await
    .unwrap();
    assert_eq!(inputs.new_root, Hash(hex_field(&applied["new_root"])));
    let pair = inputs.writes[0].pair.as_ref().unwrap();
    assert_eq!(
        pair.escrow_ciphertext_hash,
        Hash(hex_field(
            &applied["writes"][0]["pair"]["escrow_ciphertext_hash"]
        ))
    );
    replay.stop().await;
}

#[tokio::test]
async fn a_rolled_back_enrollment_replays_to_the_same_revision_and_root() {
    let replay = AddressReplay::through(2).await;
    let member = hex_field(&replay.updates[1]["entries"][0]["member"]);
    let enrolled = replay.store().newest_enrollment(&member).await.unwrap();
    assert_eq!(enrolled.map(|address| address.address_revision), Some(1));
    let mut cursor = replay.indexer.cursor().await.unwrap();
    replay.indexer.rewind_tip(&mut cursor).await.unwrap();
    assert_eq!(
        replay.store().newest_enrollment(&member).await.unwrap(),
        None
    );
    let root = |state: crate::storage::StorageState| state.account.roots[0].hash;
    let rewound = replay.store().state().await.unwrap().unwrap();
    assert_eq!(root(rewound), hex_field(&replay.updates[0]["new_root"]));
    replay.synchronize().await;
    assert_eq!(
        replay.store().newest_enrollment(&member).await.unwrap(),
        enrolled
    );
    let replayed = replay.store().state().await.unwrap().unwrap();
    assert_eq!(root(replayed), hex_field(&replay.updates[1]["new_root"]));
    replay.stop().await;
}

/// The registry's fault after one block of `transactions` past `Initialize`.
async fn projected_fault(
    ring_id: [u8; 32],
    transactions: impl FnOnce(Address, Address) -> Vec<Value>,
) -> Option<String> {
    let creator = Address::new_from_array([41; 32]);
    let (registry, initialize) = initialize_transaction(creator, [42; 32], ring_id);
    let chain = Arc::new(Mutex::new(Chain {
        blocks: BTreeMap::from([
            (1, block(1, vec![initialize])),
            (2, block(2, transactions(creator, registry))),
        ]),
        ..Default::default()
    }));
    let (rpc, handle) = rpc(chain).await;
    let indexer = replay_indexer(Arc::new(database().await), rpc);
    while indexer.synchronize().await.unwrap() == Progress::Behind {}
    let state = StorageStore::new(indexer.db.as_ref(), registry.to_bytes())
        .state()
        .await
        .unwrap()
        .unwrap();
    handle.stop().unwrap();
    handle.stopped().await;
    state.fault
}

fn enrollment_data(nullifier_pk: u8) -> Vec<u8> {
    let data = EnrollAddressIxData {
        nullifier_pk: field(nullifier_pk),
        viewing_u: [9; 32],
    };
    [&[tag::ENROLL_ADDRESS][..], bytemuck::bytes_of(&data)].concat()
}

#[tokio::test]
async fn an_address_write_without_an_enrollment_stops_the_projection() {
    let vector: Value = serde_json::from_str(ADDRESS_VECTOR).unwrap();
    let update = vector["steps"][1]["update"].clone();
    let fault = projected_fault([1; 32], |creator, registry| {
        vec![update_transaction(
            creator,
            registry,
            &json!({
                "batch_revision": "0",
                "new_root": update["new_root"],
                "new_next_index": 2,
                "writes_wire": update["writes_wire"],
            }),
        )]
    })
    .await;
    assert_eq!(fault.as_deref(), Some("an address write has no enrollment"));
}

#[tokio::test]
async fn an_enrollment_changing_the_nullifier_key_stops_the_projection() {
    let owner = Address::new_from_array([5; 32]);
    let fault = projected_fault([1; 32], |_, registry| {
        vec![
            enroll_transaction(owner, registry, &enrollment_data(1)),
            enroll_transaction(owner, registry, &enrollment_data(2)),
        ]
    })
    .await;
    assert_eq!(
        fault.as_deref(),
        Some("enrollment changes the nullifier key")
    );
}

#[tokio::test]
async fn an_enrollment_on_a_registry_serving_no_ring_stops_the_projection() {
    let owner = Address::new_from_array([5; 32]);
    let fault = projected_fault([0; 32], |_, registry| {
        vec![enroll_transaction(owner, registry, &enrollment_data(1))]
    })
    .await;
    assert_eq!(fault.as_deref(), Some("the registry serves no ring"));
}
