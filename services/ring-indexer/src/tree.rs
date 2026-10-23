use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use custom_ring_interface::{KEY_REGISTRY_CAPACITY, KEY_REGISTRY_HEIGHT};
use sea_orm::{ConnectionTrait, Value};
use zolana_hasher::{Hasher, Poseidon};
use zolana_ring_indexer::proof::LeafPath;

use crate::storage::{statement, LeafWrite};

const NODES_TABLE: &str = "ring_registry_nodes";
/// Leaf `i` is node `KEY_REGISTRY_CAPACITY + i`, the parent of node `n` is `n / 2`.
const ROOT_NODE: u64 = 1;

/// Absent nodes hash as empty subtrees.
pub(crate) struct RegistryTree<'c, C> {
    conn: &'c C,
    program: [u8; 32],
}

impl<'c, C: ConnectionTrait> RegistryTree<'c, C> {
    pub fn new(conn: &'c C, program: [u8; 32]) -> Self {
        Self { conn, program }
    }

    /// Returns the root after the writes.
    pub async fn write(&self, leaves: &[LeafWrite]) -> Result<[u8; 32]> {
        let mut path = BTreeSet::new();
        let mut siblings = BTreeSet::new();
        for leaf in leaves {
            let mut node = leaf_node(leaf.index)?;
            while node > ROOT_NODE {
                path.insert(node);
                siblings.insert(node ^ 1);
                node >>= 1;
            }
            path.insert(ROOT_NODE);
        }
        let mut hashes = self.nodes(&siblings).await?;
        for leaf in leaves {
            hashes.insert(leaf_node(leaf.index)?, leaf.hash);
        }
        // Children carry larger indices, so a descending walk hashes them first.
        for &node in path.iter().rev() {
            if node >= KEY_REGISTRY_CAPACITY {
                continue;
            }
            let child = |node| {
                hashes
                    .get(&node)
                    .copied()
                    .unwrap_or_else(|| zero_hash(level(node)))
            };
            let parent = Poseidon::hashv(&[&child(2 * node), &child(2 * node + 1)])
                .map_err(|error| anyhow::anyhow!("key registry parent hash failed ({error:?})"))?;
            hashes.insert(node, parent);
        }
        self.save(path.iter().map(|node| (*node, hashes[node])))
            .await?;
        Ok(hashes[&ROOT_NODE])
    }

    /// The path of leaf `index`, refused unless it opens to `root`.
    pub async fn path(&self, root: &[u8; 32], index: u64) -> Result<LeafPath> {
        let leaf = leaf_node(index)?;
        let siblings = (0..KEY_REGISTRY_HEIGHT)
            .map(|level| (leaf >> level) ^ 1)
            .collect::<Vec<_>>();
        let hashes = self
            .nodes(&siblings.iter().copied().chain([leaf]).collect())
            .await?;
        let hash = |node| {
            hashes
                .get(&node)
                .copied()
                .unwrap_or_else(|| zero_hash(level(node)))
        };
        let path = LeafPath {
            leaf: hash(leaf),
            siblings: siblings.into_iter().map(hash).collect(),
        };
        if path.root(index)? != *root {
            bail!("persisted key registry path does not match its root");
        }
        Ok(path)
    }

    pub async fn delete(&self) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!("DELETE FROM {NODES_TABLE} WHERE program=$1"),
                vec![self.program.to_vec().into()],
            ))
            .await?;
        Ok(())
    }

    async fn nodes(&self, nodes: &BTreeSet<u64>) -> Result<BTreeMap<u64, [u8; 32]>> {
        if nodes.is_empty() {
            return Ok(BTreeMap::new());
        }
        let placeholders = (2..nodes.len() + 2)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(",");
        let mut values = vec![self.program.to_vec().into()];
        for node in nodes {
            values.push(i64::try_from(*node)?.into());
        }
        self.conn
            .query_all(statement(
                self.conn,
                &format!(
                    "SELECT node_idx,hash FROM {NODES_TABLE} \
                     WHERE program=$1 AND node_idx IN ({placeholders})"
                ),
                values,
            ))
            .await?
            .into_iter()
            .map(|row| {
                let node = u64::try_from(row.try_get::<i64>("", "node_idx")?)?;
                let hash: Vec<u8> = row.try_get("", "hash")?;
                let hash = hash
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("stored key registry node is not 32 bytes"))?;
                Ok((node, hash))
            })
            .collect()
    }

    async fn save(&self, nodes: impl Iterator<Item = (u64, [u8; 32])>) -> Result<()> {
        let mut rows = Vec::new();
        let mut values: Vec<Value> = Vec::new();
        for (node, hash) in nodes {
            let first = values.len() + 1;
            rows.push(format!("(${first},${},${})", first + 1, first + 2));
            values.extend([
                self.program.to_vec().into(),
                i64::try_from(node)?.into(),
                hash.to_vec().into(),
            ]);
        }
        if rows.is_empty() {
            return Ok(());
        }
        self.conn
            .execute(statement(
                self.conn,
                &format!(
                    "INSERT INTO {NODES_TABLE}(program,node_idx,hash) VALUES {} \
                     ON CONFLICT(program,node_idx) DO UPDATE SET hash=excluded.hash",
                    rows.join(",")
                ),
                values,
            ))
            .await?;
        Ok(())
    }
}

fn leaf_node(index: u64) -> Result<u64> {
    if index >= KEY_REGISTRY_CAPACITY {
        bail!("key registry index out of range");
    }
    KEY_REGISTRY_CAPACITY
        .checked_add(index)
        .context("key registry node overflow")
}

/// Leaves sit at level 0 and the root at `KEY_REGISTRY_HEIGHT`.
fn level(node: u64) -> usize {
    KEY_REGISTRY_HEIGHT.saturating_sub(node.ilog2() as usize)
}

fn zero_hash(level: usize) -> [u8; 32] {
    Poseidon::zero_bytes()[level]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::Migrator;
    use custom_ring_interface::KEY_REGISTRY_EMPTY_ROOT;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;
    use zolana_ring_indexer::key_registry::MemberKey;
    use zolana_ring_key_registry::{KeyRegistryTree, Registration};

    #[test]
    fn levels_span_leaf_to_root() {
        assert_eq!(level(KEY_REGISTRY_CAPACITY), 0);
        assert_eq!(level(2 * KEY_REGISTRY_CAPACITY - 1), 0);
        assert_eq!(level(ROOT_NODE), KEY_REGISTRY_HEIGHT);
    }

    /// Every root matches the reference tree the on-chain registry mirrors.
    #[tokio::test]
    async fn roots_match_the_reference_registry_tree() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let tree = RegistryTree::new(&db, [11; 32]);
        let sentinel = MemberKey::sentinel();
        let root = tree
            .write(&[LeafWrite {
                index: 0,
                hash: sentinel.hash().unwrap(),
            }])
            .await
            .unwrap();
        assert_eq!(root, KEY_REGISTRY_EMPTY_ROOT);
        let mut reference = KeyRegistryTree::new().unwrap();
        assert_eq!(root, reference.root());
        for seed in [5u8, 9, 2] {
            let mut member = [0; 32];
            member[31] = seed;
            let inputs = reference
                .register(Registration {
                    member,
                    key: [seed; 32],
                })
                .unwrap();
            let low = tree
                .path(&root_of(&tree).await, inputs.low_index)
                .await
                .unwrap();
            assert_eq!(low.siblings, inputs.low_proof);
            let spliced = custom_ring_interface::KeyRegistryLeaf {
                member: &inputs.low_member,
                next: &member,
                key: &inputs.low_key,
            }
            .hash()
            .unwrap();
            let added = custom_ring_interface::KeyRegistryLeaf {
                member: &member,
                next: &inputs.low_next,
                key: &[seed; 32],
            }
            .hash()
            .unwrap();
            let root = tree
                .write(&[
                    LeafWrite {
                        index: inputs.low_index,
                        hash: spliced,
                    },
                    LeafWrite {
                        index: inputs.new_index,
                        hash: added,
                    },
                ])
                .await
                .unwrap();
            assert_eq!(root, inputs.new_root);
            assert_eq!(root, reference.root());
        }
        assert!(tree.path(&[1; 32], 0).await.is_err());
        tree.delete().await.unwrap();
        assert_eq!(root_of(&tree).await, zero_hash(KEY_REGISTRY_HEIGHT));
    }

    async fn root_of(tree: &RegistryTree<'_, sea_orm::DatabaseConnection>) -> [u8; 32] {
        tree.nodes(&BTreeSet::from([ROOT_NODE]))
            .await
            .unwrap()
            .get(&ROOT_NODE)
            .copied()
            .unwrap_or_else(|| zero_hash(KEY_REGISTRY_HEIGHT))
    }
}
