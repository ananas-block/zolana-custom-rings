use thiserror::Error;

use crate::{field_u8, ListSet};

/// A ring's one private registry and the slots owner rows read from it, asset rows keep the
/// public slot, mirror `prover/circuits/privatelist/source.go`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrivateSource {
    pub owner_lists: ListSet,
    /// A storage registry's `registry_field`, zero without a private source.
    pub registry: [u8; 32],
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PrivateSourceError {
    #[error("a private source serves a list outside the policy lists")]
    ListNotPolicyReadable,
    #[error("private lists and their registry must be set together")]
    UnpairedRegistry,
}

impl PrivateSource {
    pub fn new(owner_lists: ListSet, registry: [u8; 32]) -> Result<Self, PrivateSourceError> {
        if !owner_lists.is_subset(ListSet::POLICY_LISTS) {
            return Err(PrivateSourceError::ListNotPolicyReadable);
        }
        if owner_lists.is_empty() != (registry == [0; 32]) {
            return Err(PrivateSourceError::UnpairedRegistry);
        }
        Ok(Self {
            owner_lists,
            registry,
        })
    }

    /// Table hash order.
    pub fn fields(&self) -> [[u8; 32]; 2] {
        [field_u8(self.owner_lists.bits()), self.registry]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ListId;

    #[test]
    fn a_private_source_pairs_policy_lists_with_a_registry() {
        let block = ListSet::single(ListId::Block);
        assert!(PrivateSource::new(block, [1; 32]).is_ok());
        assert_eq!(
            PrivateSource::new(ListSet::EMPTY, [0; 32]),
            Ok(PrivateSource::default())
        );
        assert_eq!(
            PrivateSource::new(ListSet::single(ListId::Reader), [1; 32]),
            Err(PrivateSourceError::ListNotPolicyReadable)
        );
        assert_eq!(
            PrivateSource::new(block, [0; 32]),
            Err(PrivateSourceError::UnpairedRegistry)
        );
        assert_eq!(
            PrivateSource::new(ListSet::EMPTY, [1; 32]),
            Err(PrivateSourceError::UnpairedRegistry)
        );
    }
}
