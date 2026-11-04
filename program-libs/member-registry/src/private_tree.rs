use std::collections::BTreeMap;

use custom_ring_interface::private_list::{ListPosition, PublishedListWrite, PRIVATE_LIST_DEPTH};
use spr_hasher::{Hasher, Poseidon};

use crate::RecordTreeError;

/// Public, holds no salt and no list bits.
#[derive(Clone, Debug)]
pub struct PrivateListTree {
    nodes: BTreeMap<(usize, u128), [u8; 32]>,
    zeros: [[u8; 32]; PRIVATE_LIST_DEPTH + 1],
}

impl PrivateListTree {
    pub fn new() -> Result<Self, RecordTreeError> {
        let mut zeros = [[0; 32]; PRIVATE_LIST_DEPTH + 1];
        for level in 0..PRIVATE_LIST_DEPTH {
            zeros[level + 1] = parent(&zeros[level], &zeros[level])?;
        }
        Ok(Self {
            nodes: BTreeMap::new(),
            zeros,
        })
    }

    pub fn rebuild<'a>(
        writes: impl IntoIterator<Item = &'a PublishedListWrite>,
    ) -> Result<Self, RecordTreeError> {
        let mut tree = Self::new()?;
        for write in writes {
            tree.publish(write)?;
        }
        Ok(tree)
    }

    pub fn root(&self) -> [u8; 32] {
        self.node(PRIVATE_LIST_DEPTH, 0)
    }

    /// Leaf level first.
    pub fn siblings(&self, position: &ListPosition) -> [[u8; 32]; PRIVATE_LIST_DEPTH] {
        let route = position.route();
        core::array::from_fn(|level| self.node(level, (route >> level) ^ 1))
    }

    pub fn publish(&mut self, write: &PublishedListWrite) -> Result<(), RecordTreeError> {
        let route = write.position.route();
        let mut node = write.leaf;
        self.nodes.insert((0, route), node);
        for level in 0..PRIVATE_LIST_DEPTH {
            let prefix = route >> level;
            let neighbour = self.node(level, prefix ^ 1);
            node = if prefix & 1 == 0 {
                parent(&node, &neighbour)?
            } else {
                parent(&neighbour, &node)?
            };
            self.nodes.insert((level + 1, prefix >> 1), node);
        }
        Ok(())
    }

    fn node(&self, level: usize, prefix: u128) -> [u8; 32] {
        self.nodes
            .get(&(level, prefix))
            .copied()
            .unwrap_or(self.zeros[level])
    }
}

fn parent(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], RecordTreeError> {
    Poseidon::hashv(&[left, right]).map_err(|_| RecordTreeError::Hashing)
}
