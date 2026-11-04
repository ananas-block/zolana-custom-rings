//! Pins `test-vectors/registry/private-list.json` for the Go circuits.

use custom_ring_interface::{
    private_list::{
        private_list_chain_start, ApplyPrivateListStatement, BlindChange, BlindWrite, ListSalt,
        WriteTarget, PRIVATE_LIST_DEPTH,
    },
    storage::{Revision, PRIVATE_SOURCE_EMPTY_ROOT},
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use zolana_ring_member_registry::PrivateListTree;
use zolana_ring_policy::{ListId, ListSet};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/private-list.json"
);

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Vectors {
    description: String,
    depth: usize,
    empty_root: String,
    nullifier_secret: String,
    list_salt: String,
    list_tag: String,
    batches: Vec<Batch>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Batch {
    registry: String,
    revision: u64,
    chain_start: String,
    old_root: String,
    new_root: String,
    chain_end: String,
    restrictive: bool,
    statement_hash: String,
    writes: Vec<Write>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Write {
    owner: String,
    enrolled: bool,
    mask: u8,
    value: u8,
    write_counter: u64,
    position: String,
    leaf: String,
    entry_hash: String,
    root: String,
}

fn field(byte: u8) -> [u8; 32] {
    let mut out = [0; 32];
    out[31] = byte;
    out
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn compute() -> Vectors {
    let secret = field(0x5e);
    let list_salt = ListSalt::derive(&secret).unwrap();
    let list_tag = list_salt.tag().unwrap();
    let enrolled = WriteTarget::Enrolled {
        list_tag,
        list_salt,
    };
    let allow = ListSet::single(ListId::Allow);
    let block = ListSet::single(ListId::Block);
    let (alice, bob) = (field(0xa1), field(0xb0));
    let plan: [&[([u8; 32], WriteTarget, ListSet, ListSet, ListSet)]; 3] = [
        &[
            (alice, enrolled, ListSet::EMPTY, block, block),
            (bob, WriteTarget::Unenrolled, ListSet::EMPTY, allow, allow),
        ],
        &[(alice, enrolled, block, allow, allow)],
        &[(alice, enrolled, allow.union(block), block, ListSet::EMPTY)],
    ];
    let mut tree = PrivateListTree::new().unwrap();
    let registry = Address::new_from_array([0x44; 32]);
    let mut counter = 0;
    let batches = plan
        .iter()
        .enumerate()
        .map(|(index, batch)| {
            let revision = index as u64 + 1;
            let chain_start =
                private_list_chain_start(&registry, Revision(revision.to_le_bytes())).unwrap();
            let mut chain = chain_start;
            let old_root = tree.root();
            let mut restrictive = false;
            let writes = batch
                .iter()
                .map(|(owner, target, old_lists, mask, value)| {
                    counter += 1;
                    let change = BlindChange {
                        mask: *mask,
                        value: *value,
                    };
                    restrictive |= change.restrictive();
                    let published = BlindWrite {
                        owner: *owner,
                        target: *target,
                        old_lists: *old_lists,
                        change,
                        write_counter: counter,
                    }
                    .published()
                    .unwrap();
                    chain = published.chain(&chain).unwrap();
                    tree.publish(&published).unwrap();
                    Write {
                        owner: hex32(owner),
                        enrolled: *target != WriteTarget::Unenrolled,
                        mask: mask.bits(),
                        value: value.bits(),
                        write_counter: counter,
                        position: hex32(&published.position.0),
                        leaf: hex32(&published.leaf),
                        entry_hash: hex32(&published.entry_hash().unwrap()),
                        root: hex32(&tree.root()),
                    }
                })
                .collect();
            let statement = ApplyPrivateListStatement {
                old_root,
                new_root: tree.root(),
                chain_start,
                chain_end: chain,
                count: batch.len() as u64,
                restrictive,
            };
            Batch {
                registry: hex32(registry.as_array()),
                revision,
                chain_start: hex32(&chain_start),
                old_root: hex32(&old_root),
                new_root: hex32(&statement.new_root),
                chain_end: hex32(&chain),
                restrictive,
                statement_hash: hex32(&statement.hash().unwrap()),
                writes,
            }
        })
        .collect();
    Vectors {
        description: "Curator writes on the private list tree, one salted owner and one salt 0 owner. Produced by program-libs/member-registry/tests/private_list_vector.rs.".into(),
        depth: PRIVATE_LIST_DEPTH,
        empty_root: hex32(&PrivateListTree::new().unwrap().root()),
        nullifier_secret: hex32(&secret),
        list_salt: hex32(&list_salt.0),
        list_tag: hex32(&list_tag.0),
        batches,
    }
}

#[test]
fn the_vector_file_matches() {
    let committed: Vectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("json");
    assert_eq!(committed, compute());
}

#[test]
fn the_tree_starts_at_the_private_source_empty_root() {
    assert_eq!(
        PrivateListTree::new().unwrap().root(),
        PRIVATE_SOURCE_EMPTY_ROOT
    );
}

#[test]
fn a_reader_rebuilds_the_root_from_published_writes() {
    let list_salt = ListSalt::derive(&field(1)).unwrap();
    let target = WriteTarget::Enrolled {
        list_tag: list_salt.tag().unwrap(),
        list_salt,
    };
    let block = ListSet::single(ListId::Block);
    let writes = [(block, block), (block, ListSet::EMPTY)].map(|(mask, value)| (mask, value));
    let mut old_lists = ListSet::EMPTY;
    let published: Vec<_> = writes
        .iter()
        .enumerate()
        .map(|(i, (mask, value))| {
            let change = BlindChange {
                mask: *mask,
                value: *value,
            };
            let write = BlindWrite {
                owner: field(2),
                target,
                old_lists,
                change,
                write_counter: i as u64 + 1,
            }
            .published()
            .unwrap();
            old_lists = change.applied_to(old_lists);
            write
        })
        .collect();
    let mut live = PrivateListTree::new().unwrap();
    for write in &published {
        live.publish(write).unwrap();
    }
    assert_eq!(
        PrivateListTree::rebuild(&published).unwrap().root(),
        live.root()
    );
    assert_eq!(published[1].open(&list_salt), Ok(Some(ListSet::EMPTY)));
}

#[test]
fn a_dictionary_finds_a_salt_zero_entry_and_no_enrolled_owner() {
    let list_salt = ListSalt::derive(&field(1)).unwrap();
    let (enrolled_owner, public_owner) = (field(2), field(3));
    let block = ListSet::single(ListId::Block);
    let change = BlindChange {
        mask: block,
        value: block,
    };
    let write = |owner, target| {
        BlindWrite {
            owner,
            target,
            old_lists: ListSet::EMPTY,
            change,
            write_counter: 1,
        }
        .published()
        .unwrap()
    };
    let writes = [
        write(
            enrolled_owner,
            WriteTarget::Enrolled {
                list_tag: list_salt.tag().unwrap(),
                list_salt,
            },
        ),
        write(public_owner, WriteTarget::Unenrolled),
    ];
    let unsalted = |owner: &[u8; 32]| ListSalt::UNENROLLED.position(owner).unwrap();
    assert!(!writes
        .iter()
        .any(|w| w.position == unsalted(&enrolled_owner)));
    let found = writes
        .iter()
        .find(|w| w.position == unsalted(&public_owner))
        .unwrap();
    assert_eq!(found.open(&ListSalt::UNENROLLED), Ok(Some(block)));
}

#[test]
#[ignore = "rewrites test-vectors/registry/private-list.json"]
fn write_vector() {
    let json = serde_json::to_string_pretty(&compute()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}
