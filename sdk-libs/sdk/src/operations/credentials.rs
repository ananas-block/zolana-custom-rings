//! The credential section of a transfer, deposit or merge proof, read once per frame.
//!
//! A proof opens one credential per live pool member, present by state inclusion or absent by an
//! address gap. Every opening folds to one address root and one state root per tree, the frame names
//! those roots by history index and the instruction carries tree 0 and each state tree, so the
//! program rebuilds the statement's root table from the accounts it reads.
//!
//! Read after `sdk-libs/client/src/operations/credential.rs` and
//! `program-libs/interface/src/proof/credential_read.rs`. Read before `pipeline/policy.rs`,
//! `deposit.rs` and `merge.rs`.

use custom_ring_interface::{
    domain, AddressCheckpoint, AuditCredential, CredentialRead, CredentialRootSelection,
    CredentialRoots, CredentialStateRoot, CredentialTreeRead,
};
use solana_address::Address;
use spr_client::{
    rpc::{NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT},
    AsyncRpc,
};
use spr_interface::pda;
use spr_program::ADDRESS_TREE_ID;
use zolana_ring_client::{
    CredentialOpening, CredentialReads, CredentialSnapshot, PresentCredential,
};

use crate::{
    request::{
        CredentialLeafRequest, CredentialOpeningRequest, CredentialParams, StateRootRequest,
    },
    CredentialTrees, CustomRing, RingError,
};

/// Distinct nonzero members, in the order their entries index them.
#[must_use]
pub(crate) struct CredentialPoolRead<'a> {
    pub ring: CustomRing,
    pub members: &'a [[u8; 32]],
}

/// The pool's openings and the roots they fold to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CredentialPool {
    ring: CustomRing,
    members: Vec<[u8; 32]>,
    snapshot: CredentialSnapshot,
    /// The address root with the sequence the program computes from tree 0's history.
    checkpoint: AddressCheckpoint,
    state_roots: Vec<CredentialStateRoot>,
}

/// The roots a frame names, `moved` once the chain stops serving one at its index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundCredentials {
    /// `None` on a merge, its statement holds no address root.
    pub address: Option<BoundTreeRoot>,
    pub state: Vec<BoundTreeRoot>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundTreeRoot {
    pub tree_id: u16,
    pub root_index: u16,
    pub root: [u8; 32],
}

impl CredentialPoolRead<'_> {
    pub async fn read<R: AsyncRpc>(self, rpc: &R) -> Result<CredentialPool, RingError> {
        // 1. One snapshot answers every member, a queued or partly served member fails the read.
        let snapshot = CredentialReads {
            ring: self.ring.program_id(),
            members: self.members,
        }
        .read(rpc, rpc)
        .await?;
        // 2. Tree 0's history read the way the program reads it fixes the address root's sequence,
        //    so the statement holds the checkpoint the program will rebuild.
        let address_tree = pda::tree(ADDRESS_TREE_ID);
        let account = rpc
            .get_account(address_tree)
            .await?
            .ok_or(RingError::MissingTree {
                address: address_tree,
            })?;
        let mut data = account.data;
        let checkpoint = CredentialTreeRead {
            address: &address_tree,
            owner: &account.owner,
            data: &mut data,
        }
        .checkpoint(snapshot.address_root.root_index)?;
        if *checkpoint.root() != snapshot.address_root.root {
            return Err(RingError::CredentialRootMoved);
        }
        if checkpoint.sequence() != snapshot.address_root.sequence {
            return Err(RingError::CredentialRootMoved);
        }
        let state_roots = snapshot
            .state_roots
            .iter()
            .map(|tree| CredentialStateRoot {
                tree_id: tree.tree_id,
                root: tree.root.root,
            })
            .collect();
        Ok(CredentialPool {
            ring: self.ring,
            members: self.members.to_vec(),
            snapshot,
            checkpoint,
            state_roots,
        })
    }
}

impl CredentialPool {
    /// `None` for an absent member or one outside the pool.
    pub fn credential(&self, member: &[u8; 32]) -> Option<&AuditCredential> {
        match self.opening(member)? {
            CredentialOpening::Present(present) => Some(&present.credential),
            CredentialOpening::Absent(_) => None,
        }
    }

    /// The frame's root indexes, the state trees in ascending id.
    pub fn read(&self) -> Result<CredentialRead, RingError> {
        let state: Vec<u16> = self
            .snapshot
            .state_roots
            .iter()
            .map(|tree| tree.root.root_index)
            .collect();
        Ok(CredentialRead::new(
            self.snapshot.address_root.root_index,
            &state,
        )?)
    }

    /// Tree 0, then each state tree, the accounts the frame's indexes read.
    pub fn trees(&self, capacity: usize) -> Result<CredentialTrees, RingError> {
        Ok(CredentialTrees::new(
            self.snapshot.state_roots.iter().map(|tree| tree.tree_id),
            capacity,
        )?)
    }

    /// The statement's root table padded to `capacity` with the first state root.
    pub fn roots(&self, capacity: usize) -> Result<CredentialRoots, RingError> {
        Ok(CredentialRootSelection {
            ring_program: &self.ring.program_id(),
            address_checkpoint: self.checkpoint,
            state_roots: &self.state_roots,
            capacity,
        }
        .roots()?)
    }

    pub fn bound(&self) -> BoundCredentials {
        BoundCredentials {
            address: Some(BoundTreeRoot {
                tree_id: ADDRESS_TREE_ID,
                root_index: self.snapshot.address_root.root_index,
                root: self.snapshot.address_root.root,
            }),
            state: self
                .snapshot
                .state_roots
                .iter()
                .map(|tree| BoundTreeRoot {
                    tree_id: tree.tree_id,
                    root_index: tree.root.root_index,
                    root: tree.root.root,
                })
                .collect(),
        }
    }

    /// Every opening at `capacity`, the rows and outputs indexing them.
    pub fn params(
        &self,
        capacity: usize,
        row_entries: Vec<u32>,
        output_entries: Vec<u32>,
    ) -> Result<CredentialParams, RingError> {
        let roots = self.roots(capacity)?;
        let mut openings = self
            .members
            .iter()
            .map(|member| self.opening_request(member))
            .collect::<Result<Vec<_>, _>>()?;
        if capacity < openings.len() {
            return Err(RingError::CredentialCapacity {
                members: openings.len(),
                capacity,
            });
        }
        // 1. Padding openings name member zero, the circuit gates both branches off for them.
        openings.resize_with(capacity, padding_opening);
        Ok(CredentialParams {
            credential_owner: *roots.owner_hash(),
            address_root: *roots.address_root(),
            state_roots: roots
                .state_roots()
                .iter()
                .map(StateRootRequest::from)
                .collect(),
            credential_openings: openings,
            row_entries,
            output_entries,
        })
    }

    fn opening(&self, member: &[u8; 32]) -> Option<&CredentialOpening> {
        let position = self.members.iter().position(|known| known == member)?;
        self.snapshot.openings.get(position)
    }

    fn opening_request(&self, member: &[u8; 32]) -> Result<CredentialOpeningRequest, RingError> {
        match self.opening(member).ok_or(RingError::CredentialNotRead)? {
            CredentialOpening::Present(present) => Ok(CredentialOpeningRequest {
                present: true,
                leaf: self.leaf(present)?,
                ..padding_opening()
            }),
            CredentialOpening::Absent(gap) => Ok(CredentialOpeningRequest {
                present: false,
                leaf: CredentialLeafRequest {
                    member: *member,
                    ..padding_leaf()
                },
                low_value: gap.low,
                low_next: gap.next,
                low_index: gap.low_index,
                low_path: gap.path.to_vec(),
            }),
        }
    }

    /// The leaf's tree slot is its tree's position in the frame's ascending table.
    pub fn leaf(&self, present: &PresentCredential) -> Result<CredentialLeafRequest, RingError> {
        let tree_slot = self
            .snapshot
            .state_roots
            .iter()
            .position(|tree| tree.tree_id == present.tree_id)
            .ok_or(RingError::CredentialNotRead)?;
        credential_leaf(present, tree_slot)
    }
}

/// The leaf's fields as the credential state hash orders them, past the domain, ring and member.
pub(crate) fn credential_leaf(
    present: &PresentCredential,
    tree_slot: usize,
) -> Result<CredentialLeafRequest, RingError> {
    let [_, _, member, nullifier_pk, list_tag, aud0, aud1, eph0, eph1, ct_hash] =
        present.credential.elements(domain::CREDENTIAL_STATE)?;
    Ok(CredentialLeafRequest {
        member,
        nullifier_pk,
        list_tag,
        aud: [aud0, aud1],
        eph: [eph0, eph1],
        ct_hash,
        blinding: present.blinding,
        tree_slot: u8::try_from(tree_slot).map_err(|_| RingError::CredentialNotRead)?,
        state_index: present.leaf_index,
        state_path: present.path.to_vec(),
    })
}

fn padding_leaf() -> CredentialLeafRequest {
    CredentialLeafRequest {
        state_path: vec![[0; 32]; STATE_TREE_HEIGHT],
        ..CredentialLeafRequest::default()
    }
}

fn padding_opening() -> CredentialOpeningRequest {
    CredentialOpeningRequest {
        leaf: padding_leaf(),
        low_path: vec![[0; 32]; NULLIFIER_TREE_HEIGHT],
        ..CredentialOpeningRequest::default()
    }
}

/// The one state root a hidden owner's merge reads, no address checkpoint enters its statement.
pub(crate) struct MergeCredential {
    pub read: CredentialRead,
    pub roots: CredentialRoots,
    pub tree: Address,
    pub leaf: CredentialLeafRequest,
    pub bound: BoundCredentials,
}

impl CredentialPool {
    /// `member`'s present credential under its tree's root, an absent one cannot merge keyed notes.
    pub fn merge(&self, member: &[u8; 32]) -> Result<MergeCredential, RingError> {
        let Some(CredentialOpening::Present(present)) = self.opening(member) else {
            return Err(RingError::InputKeyNotEnrolled { index: 0 });
        };
        let tree = self
            .snapshot
            .state_roots
            .iter()
            .find(|tree| tree.tree_id == present.tree_id)
            .ok_or(RingError::CredentialNotRead)?;
        let state_root = CredentialStateRoot {
            tree_id: tree.tree_id,
            root: tree.root.root,
        };
        let bound = BoundTreeRoot {
            tree_id: tree.tree_id,
            root_index: tree.root.root_index,
            root: tree.root.root,
        };
        Ok(MergeCredential {
            read: CredentialRead::new_state(tree.root.root_index),
            roots: CredentialRoots::state_only(&self.ring.program_id(), state_root)?,
            tree: pda::tree(tree.tree_id),
            leaf: credential_leaf(present, 0)?,
            bound: BoundCredentials {
                address: None,
                state: vec![bound],
            },
        })
    }
}
