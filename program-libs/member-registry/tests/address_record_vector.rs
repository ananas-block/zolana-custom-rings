//! Pins `test-vectors/registry/address_record.json` and `empty_root.json` for Go, TS and the indexer.

use std::collections::BTreeMap;

use custom_ring_interface::{
    domain,
    member_registry::EscrowKey,
    mint_policy_write,
    storage::{chain_start, RegistryId, StorageRegistry},
    storage_instruction::{
        tag, AddressWriteData, EnrollAddressIxData, EscrowWriteData, StorageWriteData,
    },
    QueueEntry, RecordWriteData, WriteRecordsIxData, MEMBER_REGISTRY_EMPTY_ROOT,
};
use serde_json::{json, Value};
use solana_address::Address;
use spr_hasher::primitives::{hash_bytes, pack_be, solana_owner_identity};
use zolana_ring_member_registry::{
    AuthorizedAddress, MemberRecord, MemberRegistryTree, OpeningCheck, QuadPath, RecordOpening,
    RecordTree, RecordWriteProofInput, ZERO_SUBTREES,
};
use zolana_ring_policy::{ListChange, ListId, ListSet};

const ADDRESS_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/address_record.json"
);
const EMPTY_ROOT_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/empty_root.json"
);

const CREATOR: [u8; 32] = [41; 32];
const REGISTRY_ID: [u8; 32] = [42; 32];
const RING_PROGRAM: [u8; 32] = [0x44; 32];
const ADDRESS_FIRST: [u8; 32] = [0x21; 32];
const ESCROW_FIRST: [u8; 32] = [0x23; 32];
const SAME_BATCH: [u8; 32] = [0x25; 32];
const NEIGHBOR: [u8; 32] = [0x31; 32];
const FIRST_VIEWING_KEY: [u8; 32] = [0x51; 32];
const ROTATED_VIEWING_KEY: [u8; 32] = [0x52; 32];
const OWNERS: [[u8; 32]; 3] = [ADDRESS_FIRST, ESCROW_FIRST, SAME_BATCH];

fn identity(owner: &[u8; 32]) -> [u8; 32] {
    solana_owner_identity(owner).unwrap()
}

/// The member `owner`'s record relinks to, nothing sorts between them.
fn member_above(owner: &[u8; 32]) -> [u8; 32] {
    let mut member = identity(owner);
    member[31] = member[31].checked_add(1).unwrap();
    member
}

fn nullifier_pk(owner: &[u8; 32]) -> [u8; 32] {
    hash_bytes(&[owner[0] ^ 0x40; 32]).unwrap()
}

fn allow(member: [u8; 32]) -> StorageWriteData {
    let change = ListChange {
        set: ListSet::of(&[ListId::Allow]),
        clear: ListSet::EMPTY,
    };
    StorageWriteData::Record(RecordWriteData {
        member,
        lists: WriteRecordsIxData::new(change.check().unwrap()),
        mint_policy: mint_policy_write(None),
    })
}

fn address_write(owner: [u8; 32], address_revision: u64) -> StorageWriteData {
    StorageWriteData::Address(AddressWriteData {
        owner: Address::new_from_array(owner),
        address_revision: address_revision.to_le_bytes(),
    })
}

fn escrow_write(owner: [u8; 32]) -> StorageWriteData {
    StorageWriteData::Escrow(EscrowWriteData {
        owner: Address::new_from_array(owner),
        nullifier_pk: nullifier_pk(&owner),
        eph_u: [owner[0] ^ 0x66; 32],
        ciphertext: [owner[0] ^ 0x77; 32],
    })
}

fn entry_json(entry: &QueueEntry) -> Value {
    let policy = entry.mint_policy.unwrap_or_default();
    json!({
        "member": hex::encode(entry.member),
        "mask": entry.mask.to_string(),
        "value": entry.value.to_string(),
        "escrow_key": hex::encode(entry.escrow_key),
        "mint_policy": hex::encode(entry.mint_policy_field()),
        "withdrawal_threshold": policy.withdrawal_threshold.to_string(),
        "limits": policy.limits.fields().map(hex::encode),
        "address_hash": hex::encode(entry.address_hash),
        "entry_hash": hex::encode(entry.hash().unwrap()),
    })
}

fn record_json(record: &MemberRecord) -> Value {
    json!({
        "member": hex::encode(record.member),
        "next": hex::encode(record.next),
        "lists": record.lists.to_string(),
        "escrow_key": hex::encode(record.escrow_key),
        "mint_policy": hex::encode(record.mint_policy.field()),
        "withdrawal_threshold": record.mint_policy.withdrawal_threshold.to_string(),
        "limits": record.mint_policy.limits.fields().map(hex::encode),
        "address_hash": hex::encode(record.address_hash),
        "leaf_hash": hex::encode(record.hash().unwrap()),
    })
}

fn path_json(path: &QuadPath) -> Value {
    let siblings: Vec<Vec<String>> = path
        .siblings
        .iter()
        .map(|level| level.iter().map(hex::encode).collect())
        .collect();
    json!({"index": path.index, "siblings": siblings})
}

fn write_input_json(input: &RecordWriteProofInput) -> Value {
    json!({
        "member": hex::encode(input.entry.member),
        "exists": input.exists,
        "old_next": hex::encode(input.old_next),
        "old_lists": input.old_lists.to_string(),
        "old_escrow": hex::encode(input.old_escrow),
        "old_address_hash": hex::encode(input.old_address_hash),
        "slot": path_json(&input.slot),
        "low": record_json(&input.low),
        "low_path": path_json(&input.low_path),
        "pair": input.pair.map(|pair| json!({
            "nullifier_pk": hex::encode(pair.address.nullifier_pk),
            "address_ring": hex::encode(pair.address.ring_id),
            "view0": hex::encode(pack_be::<32, 2>(&pair.address.viewing_u)[0]),
            "view1": hex::encode(pack_be::<32, 2>(&pair.address.viewing_u)[1]),
            "address_revision": pair.address.address_revision.to_string(),
            "escrow_ciphertext_hash": hex::encode(pair.escrow_ciphertext_hash),
        })),
    })
}

fn address_json(address: &AuthorizedAddress, member: &[u8; 32]) -> Value {
    let [view0, view1] = pack_be::<32, 2>(&address.viewing_u);
    json!({
        "domain": hex::encode(domain::field(domain::AUTHORIZED_ADDRESS)),
        "ring_id": hex::encode(address.ring_id),
        "member": hex::encode(member),
        "nullifier_pk": hex::encode(address.nullifier_pk),
        "viewing_u": hex::encode(address.viewing_u),
        "view0": hex::encode(view0),
        "view1": hex::encode(view1),
        "address_revision": address.address_revision.to_string(),
        "address_hash": hex::encode(address.hash(member).unwrap()),
    })
}

#[derive(Clone, Copy, Default)]
struct Hidden {
    address: Option<AuthorizedAddress>,
    escrow: Option<EscrowWriteData>,
}

fn escrow_key(write: &EscrowWriteData) -> EscrowKey<'_> {
    EscrowKey {
        nullifier_pk: &write.nullifier_pk,
        ciphertext: &write.ciphertext,
    }
}

struct Registry {
    tree: MemberRegistryTree,
    address: Address,
    ring_id: [u8; 32],
    revision: u64,
    /// Newest enrollment per member.
    enrolled: BTreeMap<[u8; 32], AuthorizedAddress>,
    hidden: BTreeMap<[u8; 32], Hidden>,
}

impl Registry {
    fn enroll(&mut self, owner: [u8; 32], viewing_u: [u8; 32]) -> Value {
        let member = identity(&owner);
        let address_revision = self
            .enrolled
            .get(&member)
            .map_or(1, |held| held.address_revision + 1);
        self.enrolled.insert(
            member,
            AuthorizedAddress {
                ring_id: self.ring_id,
                nullifier_pk: nullifier_pk(&owner),
                viewing_u,
                address_revision,
            },
        );
        let data = EnrollAddressIxData {
            nullifier_pk: nullifier_pk(&owner),
            viewing_u,
        };
        let wire = [&[tag::ENROLL_ADDRESS], bytemuck::bytes_of(&data)].concat();
        json!({
            "owner": hex::encode(owner),
            "address_revision": address_revision.to_string(),
            "instruction_data": hex::encode(wire),
        })
    }

    fn entry(&self, write: &StorageWriteData) -> QueueEntry {
        match write {
            StorageWriteData::Address(write) => write
                .entry(&self.enrolled[&write.member().unwrap()])
                .unwrap(),
            write => write.entry().unwrap(),
        }
    }

    /// The running hidden fields fill each write's pair, as the indexer serves them.
    fn fill_pairs(&mut self, inputs: &mut [RecordWriteProofInput], writes: &[StorageWriteData]) {
        for (input, write) in inputs.iter_mut().zip(writes) {
            let member = input.entry.member;
            let hidden = self.hidden.entry(member).or_default();
            match write {
                StorageWriteData::Address(_) => hidden.address = Some(self.enrolled[&member]),
                StorageWriteData::Escrow(write) if input.old_escrow == [0; 32] => {
                    hidden.escrow = Some(*write);
                }
                StorageWriteData::Escrow(_) | StorageWriteData::Record(_) => {}
            }
            let key = hidden.escrow.as_ref().map(escrow_key);
            input.pair = input
                .pair_witness(hidden.address.as_ref(), key.as_ref())
                .unwrap();
        }
    }

    fn update(&mut self, name: &str, writes: &[StorageWriteData]) -> Value {
        let entries: Vec<_> = writes.iter().map(|write| self.entry(write)).collect();
        let start = chain_start(&self.address, self.revision.into()).unwrap();
        let mut inputs = self.tree.apply(start, &entries).unwrap();
        self.fill_pairs(&mut inputs.writes, writes);
        let statement = inputs.statement().unwrap();
        let step = json!({
            "name": name,
            "batch_revision": self.revision.to_string(),
            "writes_wire": hex::encode(StorageWriteData::encode_all(writes)),
            "entries": entries.iter().map(entry_json).collect::<Vec<_>>(),
            "old_root": hex::encode(inputs.old_root),
            "new_root": hex::encode(inputs.new_root),
            "old_next_index": inputs.old_next_index,
            "new_next_index": inputs.new_next_index,
            "chain_start": hex::encode(inputs.chain_start),
            "chain_end": hex::encode(inputs.chain_end),
            "count": statement.count,
            "statement_hash": hex::encode(statement.hash().unwrap()),
            "writes": inputs.writes.iter().map(write_input_json).collect::<Vec<_>>(),
            "openings": OWNERS.map(|owner| self.opening(&owner)),
        });
        self.revision += 1;
        step
    }

    /// Verifies under the step's root before it is written.
    fn opening(&self, owner: &[u8; 32]) -> Value {
        let member = identity(owner);
        let root = self.tree.root().unwrap();
        let opening = self.tree.opening(&member).unwrap();
        OpeningCheck {
            opening: &opening,
            root: &root,
            member: &member,
        }
        .verify()
        .unwrap();
        let (present, record, path) = match opening {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        let hidden = self.hidden.get(&record.member).copied().unwrap_or_default();
        record.check_address(hidden.address.as_ref()).unwrap();
        let key = hidden.escrow.as_ref().map(escrow_key);
        let expected_escrow = key.map_or([0; 32], |key| key.hash().unwrap());
        assert_eq!(record.escrow_key, expected_escrow);
        json!({
            "member": hex::encode(member),
            "root": hex::encode(root),
            "present": present,
            "record": record_json(&record),
            "address": hidden.address.as_ref().map(|address| address_json(address, &record.member)),
            "escrow": hidden.escrow.as_ref().map(|escrow| json!({
                "nullifier_pk": hex::encode(escrow.nullifier_pk),
                "ciphertext": hex::encode(escrow.ciphertext),
                "ciphertext_hash": hex::encode(hash_bytes(&escrow.ciphertext).unwrap()),
            })),
            "path": path_json(&path),
        })
    }
}

fn address_vector() -> Value {
    let (registry, _) =
        StorageRegistry::find_address(&Address::new_from_array(CREATOR), &RegistryId(REGISTRY_ID));
    let ring_id = zolana_ring_policy::ring_id_field(&RING_PROGRAM).unwrap();
    let mut tree = Registry {
        tree: MemberRegistryTree::new().unwrap(),
        address: registry,
        ring_id,
        revision: 0,
        enrolled: BTreeMap::new(),
        hidden: BTreeMap::new(),
    };
    let step = |enrollments: Vec<Value>, update: Value| json!({"enrollments": enrollments, "update": update});
    let mut steps = vec![step(
        vec![],
        tree.update("authority_lists_a_neighbor", &[allow(identity(&NEIGHBOR))]),
    )];
    let enrollment = tree.enroll(ADDRESS_FIRST, FIRST_VIEWING_KEY);
    steps.push(step(
        vec![enrollment],
        tree.update(
            "an_address_only_write_inserts_the_record",
            &[address_write(ADDRESS_FIRST, 1)],
        ),
    ));
    steps.push(step(
        vec![],
        tree.update(
            "an_unrelated_write_and_a_predecessor_relink_keep_the_address",
            &[
                allow(identity(&ADDRESS_FIRST)),
                allow(member_above(&ADDRESS_FIRST)),
            ],
        ),
    ));
    steps.push(step(
        vec![],
        tree.update(
            "an_escrow_write_beside_an_address_proves_both_preimages",
            &[escrow_write(ADDRESS_FIRST)],
        ),
    ));
    steps.push(step(
        vec![],
        tree.update(
            "an_escrow_write_without_an_address_proves_no_preimage",
            &[escrow_write(ESCROW_FIRST)],
        ),
    ));
    let enrollment = tree.enroll(ESCROW_FIRST, FIRST_VIEWING_KEY);
    steps.push(step(
        vec![enrollment],
        tree.update(
            "an_address_write_beside_an_escrow_key_proves_both_preimages",
            &[address_write(ESCROW_FIRST, 1)],
        ),
    ));
    let enrollment = tree.enroll(SAME_BATCH, FIRST_VIEWING_KEY);
    steps.push(step(
        vec![enrollment],
        tree.update(
            "address_and_escrow_in_one_batch_prove_at_the_second_write",
            &[address_write(SAME_BATCH, 1), escrow_write(SAME_BATCH)],
        ),
    ));
    let enrollment = tree.enroll(ADDRESS_FIRST, ROTATED_VIEWING_KEY);
    steps.push(step(
        vec![enrollment],
        tree.update(
            "rotation_moves_the_owner_revision_and_replaces_the_hash",
            &[address_write(ADDRESS_FIRST, 2), allow(identity(&NEIGHBOR))],
        ),
    ));
    json!({
        "description": "One storage registry's authorized address round trip. Replay in order: \
            each enrollment is the storage instruction of tag 5 the owner signs, its ring_id \
            comes from the registry. Each step is one Update whose writes_wire is the \
            StorageWriteData::encode_all bytes. Write kind 2 takes its hash from the enrollment \
            at address_revision, never from instruction data. address_hash = Poseidon(CRAD, \
            ring_id, member, nullifier_pk, view0, view1, address_revision). entry_hash = \
            Poseidon(CRQW, member, mask, value, escrow_key, mint_policy, withdrawal_threshold, \
            limits_0, limits_1, limits_2, address_hash). leaf_hash = Poseidon(member, next, \
            lists, escrow_key, mint_policy, withdrawal_threshold, limits_0, limits_1, limits_2, \
            address_hash). A write's pair is the ApplyRecords preimage witness, null when the \
            write creates or changes no address and escrow pair. escrow_key = \
            Poseidon(nullifier_pk, ciphertext_hash). chain_start binds the registry and \
            batch_revision, a separate counter from address_revision. Every opening verifies \
            under its step's new_root, in the order of owners, and an absent owner's address and \
            escrow are those of its low record. u64 values are decimal strings, \
            paths list three siblings per level, leaf level first. Produced by \
            program-libs/member-registry/tests/address_record_vector.rs.",
        "creator": hex::encode(CREATOR),
        "registry_id": hex::encode(REGISTRY_ID),
        "registry": hex::encode(registry),
        "ring_program": hex::encode(RING_PROGRAM),
        "ring_id": hex::encode(ring_id),
        "owners": OWNERS.map(hex::encode),
        "empty_root": hex::encode(MEMBER_REGISTRY_EMPTY_ROOT),
        "steps": steps,
    })
}

fn empty_root_vector() -> Value {
    json!({
        "description": "The sentinel leaf and the root of the tree holding only it, a new \
            registry's first root. Produced by \
            program-libs/member-registry/tests/address_record_vector.rs.",
        "sentinel": record_json(&MemberRecord::SENTINEL),
        "empty_root": hex::encode(MEMBER_REGISTRY_EMPTY_ROOT),
        "zero_subtrees": ZERO_SUBTREES.iter().map(hex::encode).collect::<Vec<_>>(),
    })
}

fn committed(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn rewrite(path: &str, vector: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(vector).unwrap() + "\n").unwrap();
}

#[test]
fn an_authorized_update_matches_the_shared_vector() {
    assert_eq!(address_vector(), committed(ADDRESS_VECTOR));
}

#[test]
fn the_sentinel_matches_the_shared_vector() {
    assert_eq!(empty_root_vector(), committed(EMPTY_ROOT_VECTOR));
}

#[test]
#[ignore = "rewrites test-vectors/registry/address_record.json and empty_root.json"]
fn write_address_vectors() {
    rewrite(ADDRESS_VECTOR, &address_vector());
    rewrite(EMPTY_ROOT_VECTOR, &empty_root_vector());
}
