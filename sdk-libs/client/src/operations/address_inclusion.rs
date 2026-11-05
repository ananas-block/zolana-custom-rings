//! Applied credential addresses under one tree 0 checkpoint, the address evidence of a proven private write.
//!
//! Photon serves no proof of a nullifier tree leaf (`getMerkleProofs` reads state trees only). The
//! indexed tree still answers it. No value lies strictly between `address` and `address + 1`, so the
//! gap of `address + 1` opens the leaf `(address, next)` exactly when an applied batch holds the
//! address. Any lower bound means the address is still queued, and the write waits.
//!
//! The served root counts only at the index tree 0 holds it. That history fixes the sequence Storage
//! compares to the write header and records as the absence floor.
//!
//! Read after `credential.rs`. Read before `custom_ring_sdk::PrivateStorageWrite`.

use custom_ring_interface::AddressCheckpoint;
use spr_client::{rpc::NULLIFIER_TREE_HEIGHT, AsyncRpc};
use spr_hasher::{Hasher, Poseidon};
use spr_interface::pda;
use spr_program::ADDRESS_TREE_ID;
use spr_tree::TreeAccount;

use super::{
    accepted_checkpoint, fixed_path, fold_path, one_root, spp_tree, AddressRoot, CredentialError,
};

/// Credential addresses of one private write, every one proven under the same root.
#[must_use]
pub struct AddressInclusions<'a> {
    pub addresses: &'a [[u8; 32]],
}

/// The indexed leaf `(address, next)` at `index` under the `Active` root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressInclusion {
    pub address: [u8; 32],
    pub next: [u8; 32],
    pub index: u64,
    pub path: [[u8; 32]; NULLIFIER_TREE_HEIGHT],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressActivation {
    /// In request order, under a root tree 0 holds with its sequence.
    Active {
        root: AddressRoot,
        /// `root` as the program reads it, for the statement's root selection.
        checkpoint: AddressCheckpoint,
        inclusions: Vec<AddressInclusion>,
    },
    /// No applied batch holds `address` yet.
    Queued { address: [u8; 32] },
}

impl AddressInclusions<'_> {
    pub async fn read<P, R>(self, photon: &P, rpc: &R) -> Result<AddressActivation, CredentialError>
    where
        P: AsyncRpc,
        R: AsyncRpc,
    {
        // 1. One gap request for every successor, step 3 refuses gaps under different roots.
        let tree = pda::tree(ADDRESS_TREE_ID);
        let successors = self
            .addresses
            .iter()
            .map(successor)
            .collect::<Option<Vec<_>>>()
            .ok_or(CredentialError::MalformedProof)?;
        let gaps = photon
            .get_non_inclusion_proofs(tree, successors.clone(), None)
            .await?
            .proofs;
        if gaps.len() != self.addresses.len() {
            return Err(CredentialError::MalformedProof);
        }
        // 2. Each gap must fold to its root before its lower bound counts as the address leaf.
        let mut inclusions = Vec::with_capacity(gaps.len());
        for ((address, successor), gap) in self.addresses.iter().zip(&successors).zip(&gaps) {
            if gap.leaf != *successor || gap.merkle_context.tree != tree {
                return Err(CredentialError::MalformedProof);
            }
            let path = fixed_path::<NULLIFIER_TREE_HEIGHT>(&gap.path, gap.low_element_index)?;
            let leaf = Poseidon::hashv(&[&gap.low_element, &gap.high_element])?;
            let brackets = gap.low_element < *successor && *successor < gap.high_element;
            if !brackets || fold_path(leaf, gap.low_element_index, &path)? != gap.root {
                return Err(CredentialError::InvalidAbsenceProof);
            }
            if gap.low_element != *address {
                return Ok(AddressActivation::Queued { address: *address });
            }
            inclusions.push(AddressInclusion {
                address: *address,
                next: gap.high_element,
                index: gap.low_element_index,
                path,
            });
        }
        // 3. One root for the whole write, accepted only where tree 0's history holds it.
        let (root_index, root) = one_root(gaps.iter().map(|gap| (gap.root_index, gap.root)))?
            .ok_or(CredentialError::MalformedProof)?;
        let mut data = spp_tree(tree, rpc.get_account(tree).await?)?;
        let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())?;
        if account.tree_id() != ADDRESS_TREE_ID {
            return Err(CredentialError::InvalidTree { address: tree });
        }
        let served = AddressRoot {
            root_index,
            root,
            sequence: 0,
        };
        let checkpoint = accepted_checkpoint(account.nullifier_tree(), &served)?;
        Ok(AddressActivation::Active {
            root: AddressRoot::held(root_index, &checkpoint),
            checkpoint,
            inclusions,
        })
    }
}

/// `address + 1` as a big endian integer, `None` past 256 bits.
fn successor(address: &[u8; 32]) -> Option<[u8; 32]> {
    let mut next = *address;
    for byte in next.iter_mut().rev() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            return Some(next);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use spr_client::rpc::{MerkleContext, NonInclusionProof};
    use spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;

    use super::*;
    use crate::credential::tests::{spp_account, tree_bytes, Ledger};

    const ADDRESS: [u8; 32] = [7; 32];
    const NEXT: [u8; 32] = [8; 32];
    const LEAF_INDEX: u64 = 5;
    const SEQUENCE: u64 = 12;

    /// Tree 0 holds `root` one apply behind its latest, at history index 1.
    fn ledger(root: [u8; 32], gap: NonInclusionProof) -> Ledger {
        let tree = pda::tree(ADDRESS_TREE_ID);
        let mut data = tree_bytes(ADDRESS_TREE_ID);
        {
            let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).unwrap();
            let history = account.nullifier_tree();
            history.root_history.roots[1] = root;
            history.root_history.roots[2] = [9; 32];
            history.root_history.current_index = 3;
            history.sequence_number = SEQUENCE + 1;
        }
        let mut ledger = Ledger::default();
        ledger.accounts.insert(tree, spp_account(data));
        ledger.gaps = vec![gap];
        ledger
    }

    /// The gap of `ADDRESS + 1` with lower bound `low`, folded at `LEAF_INDEX` over zero siblings.
    fn gap(low: [u8; 32], next: [u8; 32]) -> NonInclusionProof {
        let path = Poseidon::zero_bytes()[..NULLIFIER_TREE_HEIGHT].to_vec();
        let leaf = Poseidon::hashv(&[&low, &next]).unwrap();
        NonInclusionProof {
            leaf: successor(&ADDRESS).unwrap(),
            merkle_context: MerkleContext {
                tree_type: 0,
                tree: pda::tree(ADDRESS_TREE_ID),
            },
            root: fold_path(leaf, LEAF_INDEX, &path).unwrap(),
            path,
            low_element: low,
            low_element_index: LEAF_INDEX,
            high_element: next,
            high_element_index: 0,
            root_seq: SEQUENCE,
            root_index: 1,
        }
    }

    async fn read(ledger: &Ledger) -> Result<AddressActivation, CredentialError> {
        AddressInclusions {
            addresses: &[ADDRESS],
        }
        .read(ledger, ledger)
        .await
    }

    #[tokio::test]
    async fn an_applied_address_opens_its_leaf_under_the_tree_zero_sequence() {
        let served = gap(ADDRESS, NEXT);
        let AddressActivation::Active {
            root,
            checkpoint,
            inclusions,
        } = read(&ledger(served.root, served.clone())).await.unwrap()
        else {
            panic!("an applied address is active");
        };
        assert_eq!(
            root,
            AddressRoot {
                root_index: 1,
                root: served.root,
                sequence: SEQUENCE,
            }
        );
        assert_eq!(
            (*checkpoint.root(), checkpoint.sequence()),
            (served.root, SEQUENCE)
        );
        let [inclusion] = inclusions.as_slice() else {
            panic!("one address opens once");
        };
        assert_eq!(
            (inclusion.address, inclusion.next, inclusion.index),
            (ADDRESS, NEXT, LEAF_INDEX)
        );
    }

    #[tokio::test]
    async fn a_queued_address_waits_and_never_reads_as_active() {
        let mut high = BN254_SCALAR_MODULUS_BE;
        high[31] -= 1;
        let served = gap([1; 32], high);
        assert_eq!(
            read(&ledger(served.root, served)).await.unwrap(),
            AddressActivation::Queued { address: ADDRESS }
        );
    }

    #[tokio::test]
    async fn a_root_tree_zero_does_not_hold_is_refused() {
        let served = gap(ADDRESS, NEXT);
        assert!(matches!(
            read(&ledger([3; 32], served)).await,
            Err(CredentialError::AddressRootNotAccepted)
        ));
    }

    #[tokio::test]
    async fn a_gap_that_does_not_fold_to_its_root_is_refused() {
        let mut served = gap(ADDRESS, NEXT);
        served.high_element = [6; 32];
        assert!(matches!(
            read(&ledger(served.root, served)).await,
            Err(CredentialError::InvalidAbsenceProof)
        ));
    }
}
