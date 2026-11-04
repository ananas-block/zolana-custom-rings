//! Mirrors `prover/circuits/privatelist`.

use solana_address::Address;
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice, primitives::right_align, Hasher, HasherError,
    Poseidon,
};
use thiserror::Error;
use zolana_ring_policy::{registry_field, ListId, ListSet};

use crate::{domain, storage::Revision};

pub const PRIVATE_LIST_DEPTH: usize = 96;
pub const PRIVATE_LIST_APPLY_WIDTHS: [u8; 3] = [2, 8, 16];

const GRANT_LISTS: ListSet = ListSet::of(&[ListId::Allow, ListId::Approval]);
const DENY_LISTS: ListSet = ListSet::of(&[ListId::Block, ListId::Frozen]);

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PrivateListError {
    #[error("private list hashing failed")]
    Hashing,
    #[error("a list value leaves its mask")]
    ValueOutsideMask,
    #[error("a mask names a list the authority does not write")]
    ListNotWritable,
    #[error("the salt does not open the tracking row's list tag")]
    SaltOffListTag,
}

impl From<HasherError> for PrivateListError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}

/// Zero for a subject with no tracking row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListSalt(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListTag(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListPosition(pub [u8; 32]);

impl ListSalt {
    pub const UNENROLLED: Self = Self([0; 32]);

    /// One way, a disclosed salt reveals no nullifier secret.
    pub fn derive(nullifier_secret: &[u8; 32]) -> Result<Self, HasherError> {
        domain::list_salt(nullifier_secret).map(Self)
    }

    pub fn tag(&self) -> Result<ListTag, HasherError> {
        domain::list_tag(&self.0).map(ListTag)
    }

    pub fn position(&self, owner: &[u8; 32]) -> Result<ListPosition, HasherError> {
        Poseidon::hashv(&[&domain::field(domain::LIST_POSITION), owner, &self.0]).map(ListPosition)
    }

    pub fn leaf_salt(&self, write_counter: u64) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &domain::field(domain::LIST_LEAF_SALT),
            &self.0,
            &right_align(&write_counter.to_be_bytes()),
        ])
    }
}

impl ListPosition {
    /// Low [`PRIVATE_LIST_DEPTH`] bits, bit `l` set is a right child at level `l` above the leaves.
    pub fn route(&self) -> u128 {
        let [.., b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15] = self.0;
        u128::from_be_bytes([
            0, 0, 0, 0, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15,
        ])
    }

    pub fn leaf(&self, lists: ListSet, leaf_salt: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &domain::field(domain::LIST_LEAF),
            &self.0,
            &right_align(&[lists.bits()]),
            leaf_salt,
        ])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTarget {
    /// Fully public, every reader opens the entry.
    Unenrolled,
    /// The tracking row must be applied.
    Enrolled {
        list_tag: ListTag,
        list_salt: ListSalt,
    },
}

impl WriteTarget {
    pub fn salt(&self) -> Result<ListSalt, PrivateListError> {
        match self {
            Self::Unenrolled => Ok(ListSalt::UNENROLLED),
            Self::Enrolled {
                list_tag,
                list_salt,
            } if list_salt.tag()? == *list_tag => Ok(*list_salt),
            Self::Enrolled { .. } => Err(PrivateListError::SaltOffListTag),
        }
    }
}

/// The program reads neither mask nor value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindChange {
    pub mask: ListSet,
    pub value: ListSet,
}

impl BlindChange {
    pub fn checked(self) -> Result<Self, PrivateListError> {
        if !self.value.is_subset(self.mask) {
            return Err(PrivateListError::ValueOutsideMask);
        }
        if !self.mask.is_subset(ListSet::AUTHORITY_WRITES) {
            return Err(PrivateListError::ListNotWritable);
        }
        Ok(self)
    }

    pub fn applied_to(&self, lists: ListSet) -> ListSet {
        lists.difference(self.mask).union(self.value)
    }

    /// Clearing a grant or setting a deny narrows who passes, older roots then stop serving.
    pub fn restrictive(&self) -> bool {
        self.mask.difference(self.value).intersects(GRANT_LISTS)
            || self.value.intersects(DENY_LISTS)
    }
}

/// All a write shows, a reader rebuilds the tree from these alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublishedListWrite {
    pub position: ListPosition,
    pub leaf: [u8; 32],
    pub write_counter: u64,
}

impl PublishedListWrite {
    pub fn entry_hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[
            &domain::field(domain::LIST_WRITE),
            &self.position.0,
            &self.leaf,
            &right_align(&self.write_counter.to_be_bytes()),
        ])
    }

    pub fn chain(&self, previous: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[previous, &self.entry_hash()?])
    }

    pub fn open(&self, list_salt: &ListSalt) -> Result<Option<ListSet>, HasherError> {
        let leaf_salt = list_salt.leaf_salt(self.write_counter)?;
        for bits in 0..=u8::MAX {
            let lists = ListSet::from_bits(bits);
            if self.position.leaf(lists, &leaf_salt)? == self.leaf {
                return Ok(Some(lists));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindWrite {
    pub owner: [u8; 32],
    pub target: WriteTarget,
    pub old_lists: ListSet,
    pub change: BlindChange,
    pub write_counter: u64,
}

impl BlindWrite {
    pub fn published(&self) -> Result<PublishedListWrite, PrivateListError> {
        let list_salt = self.target.salt()?;
        let change = self.change.checked()?;
        let position = list_salt.position(&self.owner)?;
        Ok(PublishedListWrite {
            position,
            leaf: position.leaf(
                change.applied_to(self.old_lists),
                &list_salt.leaf_salt(self.write_counter)?,
            )?,
            write_counter: self.write_counter,
        })
    }
}

/// `restrictive` decides the root rotation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyPrivateListStatement {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub chain_start: [u8; 32],
    pub chain_end: [u8; 32],
    pub count: u64,
    pub restrictive: bool,
}

impl ApplyPrivateListStatement {
    pub fn elements(&self) -> [[u8; 32]; 7] {
        [
            domain::field(domain::APPLY_LIST),
            self.old_root,
            self.new_root,
            self.chain_start,
            self.chain_end,
            right_align(&self.count.to_be_bytes()),
            right_align(&[self.restrictive as u8]),
        ]
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements())
    }
}

/// `APPLY_LIST` binds the registry address and revision before the ordered writes.
pub fn private_list_chain_start(
    registry: &Address,
    revision: Revision,
) -> Result<[u8; 32], HasherError> {
    create_hash_chain_4_from_slice(&[
        domain::field(domain::APPLY_LIST),
        registry_field(registry.as_array())?,
        right_align(&revision.value().to_be_bytes()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: ListSet = ListSet::single(ListId::Allow);
    const BLOCK: ListSet = ListSet::single(ListId::Block);
    const READER: ListSet = ListSet::single(ListId::Reader);

    fn change(mask: ListSet, value: ListSet) -> BlindChange {
        BlindChange { mask, value }
    }

    #[test]
    fn an_invalid_change_is_refused() {
        assert_eq!(
            change(BLOCK, ALLOW).checked(),
            Err(PrivateListError::ValueOutsideMask)
        );
        let escrow = ListSet::single(ListId::Escrow);
        assert_eq!(
            change(escrow, ListSet::EMPTY).checked(),
            Err(PrivateListError::ListNotWritable)
        );
    }

    #[test]
    fn restriction_follows_list_polarity() {
        assert!(change(BLOCK, BLOCK).restrictive());
        assert!(change(ALLOW, ListSet::EMPTY).restrictive());
        assert!(!change(ALLOW, ALLOW).restrictive());
        assert!(!change(BLOCK, ListSet::EMPTY).restrictive());
        assert!(!change(READER, READER).restrictive());
        assert!(!change(READER, ListSet::EMPTY).restrictive());
    }

    #[test]
    fn a_curator_writes_an_enrolled_owner_only_under_its_list_tag() {
        let list_salt = ListSalt([7; 32]);
        let list_tag = list_salt.tag().unwrap();
        assert_eq!(
            WriteTarget::Enrolled {
                list_tag,
                list_salt
            }
            .salt(),
            Ok(list_salt)
        );
        assert_eq!(
            WriteTarget::Enrolled {
                list_tag,
                list_salt: ListSalt::UNENROLLED
            }
            .salt(),
            Err(PrivateListError::SaltOffListTag)
        );
        assert_eq!(WriteTarget::Unenrolled.salt(), Ok(ListSalt::UNENROLLED));
    }

    #[test]
    fn the_route_is_the_low_depth_bits() {
        let mut position = ListPosition([0xff; 32]);
        position.0[31] = 0x05;
        assert_eq!(position.route(), (1u128 << 96) - 1 - 0xfa);
    }

    #[test]
    fn a_salt_holder_opens_a_write_and_no_other_salt_does() {
        let list_salt = ListSalt([7; 32]);
        let written = BlindWrite {
            owner: [1; 32],
            target: WriteTarget::Enrolled {
                list_tag: list_salt.tag().unwrap(),
                list_salt,
            },
            old_lists: ALLOW,
            change: change(BLOCK, BLOCK),
            write_counter: 3,
        }
        .published()
        .unwrap();
        assert_eq!(written.open(&list_salt), Ok(Some(ALLOW.union(BLOCK))));
        assert_eq!(written.open(&ListSalt::UNENROLLED), Ok(None));
    }
}
