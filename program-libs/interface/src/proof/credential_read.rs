//! Credential root selection binds immutable SPP state reads and the address checkpoint for private absence.
//!
//! Positive reads need state inclusion alone. Private absence and private writes bind the address checkpoint.
//! Transfer and deposit selections include the address index, merge selections omit it.
//! Writes without credential proofs require zero address index and an empty state selection.
//!
//! Read after `program-libs/interface/src/accounts/credential.rs` and `program-libs/interface/src/accounts/state.rs`.
//! Read before `program-libs/interface/src/instructions/transact.rs` and `programs/custom-ring/src/instructions/accounts/loader.rs`.

use arrayvec::ArrayVec;
use solana_address::Address;
use spr_interface::{shape::MAX_TRANSACTION_ADDRESSES, tree_slot::tree_id_field};
use spr_program::ADDRESS_TREE_ID;
use spr_tree::{TreeAccount, nullifier_tree::layout::NullifierTreeLayout};

use crate::{CustomRingError, bytes::Bytes, credential::credential_owner};

pub const MAX_CREDENTIAL_READS: usize = MAX_TRANSACTION_ADDRESSES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRead {
    address_root_index: u16,
    state_root_indexes: ArrayVec<u16, MAX_CREDENTIAL_READS>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialStateRoot {
    pub tree_id: u16,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRoots {
    owner_hash: [u8; 32],
    address_root: [u8; 32],
    state_roots: Vec<CredentialStateRoot>,
}

pub struct CredentialTreeRead<'a> {
    pub address: &'a Address,
    pub owner: &'a Address,
    pub data: &'a mut [u8],
}

pub struct CredentialRootSelection<'a> {
    pub ring_program: &'a Address,
    pub address_checkpoint: AddressCheckpoint,
    pub state_roots: &'a [CredentialStateRoot],
    pub capacity: usize,
}

pub struct AddressRootSelection<'a, const N: usize> {
    pub tree_id: u16,
    pub root_index: u16,
    pub history: &'a NullifierTreeLayout<N>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressCheckpoint {
    root: [u8; 32],
    sequence: u64,
}

impl CredentialRead {
    /// An empty state selection requires address index zero.
    pub fn new(
        address_root_index: u16,
        state_root_indexes: &[u16],
    ) -> Result<Self, CustomRingError> {
        let mut indexes = ArrayVec::new();
        indexes
            .try_extend_from_slice(state_root_indexes)
            .map_err(|_| CustomRingError::InvalidCredentialRead)?;
        Self {
            address_root_index,
            state_root_indexes: indexes,
        }
        .checked()
    }

    pub const fn empty() -> Self {
        Self {
            address_root_index: 0,
            state_root_indexes: ArrayVec::new_const(),
        }
    }

    pub fn new_state(root_index: u16) -> Self {
        let mut state_root_indexes = ArrayVec::new();
        state_root_indexes.push(root_index);
        Self {
            address_root_index: 0,
            state_root_indexes,
        }
    }

    pub fn decode(data: &mut &[u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidCredentialRead);
        let read = Self::read(&mut bytes)?;
        *data = bytes.rest();
        Ok(read)
    }

    pub fn decode_state(data: &mut &[u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidCredentialRead);
        let read = Self::read_indexes(&mut bytes, 0)?;
        read.check_state()?;
        *data = bytes.rest();
        Ok(read)
    }

    pub fn encode_into(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&self.address_root_index.to_le_bytes());
        self.encode_indexes(data);
    }

    pub fn encode_state_into(&self, data: &mut Vec<u8>) -> Result<(), CustomRingError> {
        self.check_state()?;
        self.encode_indexes(data);
        Ok(())
    }

    pub const fn address_root_index(&self) -> u16 {
        self.address_root_index
    }
    pub fn state_root_indexes(&self) -> &[u16] {
        &self.state_root_indexes
    }
    pub fn is_empty(&self) -> bool {
        self.state_root_indexes.is_empty()
    }
    pub fn encoded_len(&self) -> usize {
        3 + 2 * self.state_root_indexes.len()
    }

    /// Requires a state root even when every credential opening proves absence.
    pub fn check_capacity(&self, capacity: usize) -> Result<(), CustomRingError> {
        check_capacity(capacity)?;
        if self.is_empty() || self.state_root_indexes.len() > capacity {
            return Err(CustomRingError::InvalidCredentialRead);
        }
        Ok(())
    }

    pub fn check_empty(&self) -> Result<(), CustomRingError> {
        if !self.is_empty() || self.address_root_index != 0 {
            return Err(CustomRingError::InvalidCredentialRead);
        }
        Ok(())
    }

    pub(crate) fn read(bytes: &mut Bytes<'_>) -> Result<Self, CustomRingError> {
        let address_root_index = bytes.u16()?;
        Self::read_indexes(bytes, address_root_index)
    }

    fn read_indexes(
        bytes: &mut Bytes<'_>,
        address_root_index: u16,
    ) -> Result<Self, CustomRingError> {
        let count = usize::from(bytes.byte()?);
        if count > MAX_CREDENTIAL_READS {
            return Err(CustomRingError::InvalidCredentialRead);
        }
        let mut state_root_indexes = ArrayVec::new();
        for _ in 0..count {
            state_root_indexes.push(bytes.u16()?);
        }
        Self {
            address_root_index,
            state_root_indexes,
        }
        .checked()
    }

    fn checked(self) -> Result<Self, CustomRingError> {
        if self.is_empty() && self.address_root_index != 0 {
            return Err(CustomRingError::InvalidCredentialRead);
        }
        Ok(self)
    }

    fn check_state(&self) -> Result<(), CustomRingError> {
        if self.address_root_index != 0 || self.state_root_indexes.len() > 1 {
            return Err(CustomRingError::InvalidCredentialRead);
        }
        Ok(())
    }

    fn encode_indexes(&self, data: &mut Vec<u8>) {
        data.push(self.state_root_indexes.len() as u8);
        for index in &self.state_root_indexes {
            data.extend_from_slice(&index.to_le_bytes());
        }
    }
}

impl CredentialRoots {
    pub fn empty(capacity: usize) -> Result<Self, CustomRingError> {
        check_capacity(capacity)?;
        Ok(Self {
            owner_hash: [0; 32],
            address_root: [0; 32],
            state_roots: vec![
                CredentialStateRoot {
                    tree_id: 0,
                    root: [0; 32]
                };
                capacity
            ],
        })
    }

    pub fn state_only(
        ring_program: &Address,
        state_root: CredentialStateRoot,
    ) -> Result<Self, CustomRingError> {
        check_roots(core::slice::from_ref(&state_root), 1)?;
        Ok(Self {
            owner_hash: credential_owner(ring_program)?,
            address_root: [0; 32],
            state_roots: vec![state_root],
        })
    }

    pub const fn owner_hash(&self) -> &[u8; 32] {
        &self.owner_hash
    }
    pub const fn address_root(&self) -> &[u8; 32] {
        &self.address_root
    }
    pub fn state_roots(&self) -> &[CredentialStateRoot] {
        &self.state_roots
    }
    pub fn capacity(&self) -> usize {
        self.state_roots.len()
    }

    pub fn elements(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        [self.owner_hash, self.address_root]
            .into_iter()
            .chain(self.state_elements())
    }

    pub fn state_elements(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.state_roots
            .iter()
            .flat_map(|entry| [tree_id_field(entry.tree_id), entry.root])
    }
}

impl<'a> CredentialTreeRead<'a> {
    pub fn state_root(self, index: u16) -> Result<CredentialStateRoot, CustomRingError> {
        let tree = self.load()?;
        let root = tree
            .get_utxo_tree_root(index)
            .map_err(|_| CustomRingError::RootNotServed)?;
        if root == [0; 32] {
            return Err(CustomRingError::RootNotServed);
        }
        Ok(CredentialStateRoot {
            tree_id: tree.tree_id(),
            root,
        })
    }

    pub fn checkpoint(self, index: u16) -> Result<AddressCheckpoint, CustomRingError> {
        let mut tree = self.load()?;
        AddressRootSelection {
            tree_id: tree.tree_id(),
            root_index: index,
            history: tree.nullifier_tree(),
        }
        .checkpoint()
    }

    fn load(self) -> Result<TreeAccount<'a>, CustomRingError> {
        // 1. Only canonical SPP tree accounts supply credential roots, account data alone cannot authenticate a tree identity.
        if self.owner.as_array() != &spr_interface::SHIELDED_POOL_PROGRAM_ID
            || self.data.first()
                != Some(&spr_interface::state::discriminator::TREE_ACCOUNT_DISCRIMINATOR)
        {
            return Err(CustomRingError::InvalidCredentialRoots);
        }
        let tree = TreeAccount::from_bytes(self.data, self.address.to_bytes())
            .map_err(|_| CustomRingError::InvalidCredentialRoots)?;
        if self.address != &spr_interface::pda::tree(tree.tree_id()) {
            return Err(CustomRingError::InvalidCredentialRoots);
        }
        // 2. Retained roots remain readable while paused, uninitialized tree state supplies no credential evidence.
        if !matches!(tree.state(), spr_tree::INITIALIZED | spr_tree::PAUSED) {
            return Err(CustomRingError::InvalidCredentialRoots);
        }
        Ok(tree)
    }
}

impl CredentialRootSelection<'_> {
    pub fn roots(self) -> Result<CredentialRoots, CustomRingError> {
        // 1. The loader supplies retained state roots, their identities must be distinct and sorted before padding.
        check_roots(self.state_roots, self.capacity)?;
        // 2. Only the ring's canonical credential PDA can authenticate a credential owner in the statement.
        let owner_hash = credential_owner(self.ring_program)?;
        let mut state_roots = Vec::with_capacity(self.capacity);
        state_roots.extend_from_slice(self.state_roots);
        state_roots.resize(self.capacity, self.state_roots[0]);
        Ok(CredentialRoots {
            owner_hash,
            address_root: self.address_checkpoint.root,
            state_roots,
        })
    }
}

impl<const N: usize> AddressRootSelection<'_, N> {
    pub fn checkpoint(self) -> Result<AddressCheckpoint, CustomRingError> {
        // 1. The caller authenticates the SPP account, only the fixed address tree can set an absence checkpoint.
        if self.tree_id != ADDRESS_TREE_ID {
            return Err(CustomRingError::InvalidAddressTree);
        }
        // 2. A nonzero retained root and a valid write cursor identify the root's distance from the latest append.
        let root = self
            .history
            .root_by_index(self.root_index)
            .ok_or(CustomRingError::InvalidAddressCheckpoint)?;
        let cursor = usize::try_from(self.history.root_history.current_index)
            .map_err(|_| CustomRingError::InvalidAddressCheckpoint)?;
        if N == 0 || cursor >= N {
            return Err(CustomRingError::InvalidAddressCheckpoint);
        }
        let latest = (cursor + N - 1) % N;
        let distance = (latest + N - usize::from(self.root_index)) % N;
        // 3. Each retained root corresponds to one append sequence, subtraction must not wrap into a false freshness claim.
        let sequence = self
            .history
            .sequence_number
            .checked_sub(distance as u64)
            .ok_or(CustomRingError::InvalidAddressCheckpoint)?;
        Ok(AddressCheckpoint { root, sequence })
    }
}

impl AddressCheckpoint {
    pub const fn root(&self) -> &[u8; 32] {
        &self.root
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn above(self, floor: u64) -> Result<[u8; 32], CustomRingError> {
        if self.sequence < floor {
            return Err(CustomRingError::AbsenceRootBelowFloor);
        }
        Ok(self.root)
    }
}

fn check_capacity(capacity: usize) -> Result<(), CustomRingError> {
    if capacity == 0 || capacity > MAX_CREDENTIAL_READS {
        return Err(CustomRingError::InvalidCredentialRead);
    }
    Ok(())
}

fn check_roots(roots: &[CredentialStateRoot], capacity: usize) -> Result<(), CustomRingError> {
    check_capacity(capacity)?;
    if roots.is_empty()
        || roots.len() > capacity
        || roots.iter().any(|entry| entry.root == [0; 32])
        || roots
            .windows(2)
            .any(|pair| pair[0].tree_id >= pair[1].tree_id)
    {
        return Err(CustomRingError::InvalidCredentialRoots);
    }
    Ok(())
}

const _: () = assert!(MAX_CREDENTIAL_READS > 0 && MAX_CREDENTIAL_READS <= u8::MAX as usize);
