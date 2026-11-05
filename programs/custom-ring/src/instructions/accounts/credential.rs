//! Reads credential roots from authenticated SPP trees without exposing an owner account.
//!
//! State roots prove immutable credentials under the ring's enrollment authority. The address root
//! proves absence only after every private source's floor. Paused state trees remain readable.
//!
//! Read after `program-libs/interface/src/proof/credential_read.rs`.
//! Read before `instructions/transfer/accounts.rs` and `instructions/settlement/forward.rs`.

use custom_ring_interface::{
    CredentialRead, CredentialRootSelection, CredentialRoots, CredentialStateRoot,
    CredentialTreeRead, CustomRingError,
};
use pinocchio::{error::ProgramError, AccountView, Address};

#[must_use]
pub struct CredentialAccounts<'a> {
    pub program_id: &'a Address,
    pub read: &'a CredentialRead,
    pub capacity: usize,
    pub absence_floor: u64,
}

impl CredentialAccounts<'_> {
    pub fn load<'a>(
        self,
        mut next: impl FnMut() -> Result<&'a AccountView, ProgramError>,
    ) -> Result<CredentialRoots, ProgramError> {
        // 1. The frame bounds the state table before any account or allocation is consumed.
        self.read.check_capacity(self.capacity)?;
        // 2. Tree zero fixes the address namespace, and its retained sequence meets each private source's floor.
        let checkpoint = read_tree(next()?, |tree| {
            tree.checkpoint(self.read.address_root_index())
        })?;
        checkpoint.above(self.absence_floor)?;
        // 3. Each credential tree root comes from SPP history, then distinct ascending ids fix the table order.
        let mut state_roots = Vec::with_capacity(self.read.state_root_indexes().len());
        for &root_index in self.read.state_root_indexes() {
            state_roots.push(read_state_root(next()?, root_index)?);
        }
        Ok(CredentialRootSelection {
            ring_program: self.program_id,
            address_checkpoint: checkpoint,
            state_roots: &state_roots,
            capacity: self.capacity,
        }
        .roots()?)
    }
}

#[must_use]
pub struct MergeCredentialAccounts<'a> {
    pub program_id: &'a Address,
    pub read: &'a CredentialRead,
}

impl MergeCredentialAccounts<'_> {
    pub fn load(self, tree: &AccountView) -> Result<CredentialRoots, ProgramError> {
        self.read.check_capacity(1)?;
        if self.read.address_root_index() != 0 {
            return Err(CustomRingError::InvalidAddressTree.into());
        }
        let state_root = read_state_root(tree, self.read.state_root_indexes()[0])?;
        Ok(CredentialRoots::state_only(self.program_id, state_root)?)
    }
}

fn read_state_root(
    account: &AccountView,
    root_index: u16,
) -> Result<CredentialStateRoot, ProgramError> {
    read_tree(account, |tree| tree.state_root(root_index))
}

fn read_tree<T>(
    account: &AccountView,
    read: impl FnOnce(CredentialTreeRead<'_>) -> Result<T, CustomRingError>,
) -> Result<T, ProgramError> {
    let address = *account.address();
    let owner = *account.owner();
    // The cloned handle shares runtime borrow tracking, and the byte loader permits paused trees.
    let mut account = account.clone();
    let mut data = account.try_borrow_mut()?;
    Ok(read(CredentialTreeRead {
        address: &address,
        owner: &owner,
        data: &mut data,
    })?)
}
