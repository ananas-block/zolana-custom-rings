//! Moves a policy registry to a new root, the one write path of its lists and mint settings.
//!
//! An SPP note never changes once written, a policy record does. The program therefore keeps only the
//! root and verifies a proof of each batch of writes. Every write travels in instruction data, and a
//! reader rebuilds the tree from them.
//!
//! Read after `programs/storage/src/lib.rs`, `program-libs/interface/src/accounts/storage.rs`,
//! `program-libs/interface/src/instructions/storage.rs`. Read before
//! `prover/circuits/registry/apply_records.go`.
//!
//! Guarantees:
//! 1. The new root and next index follow from the current ones by exactly the instruction's writes, in order.
//! 2. A write a rule can read retires every earlier root in the instruction, any other write keeps the outgoing root for the registry's grace.
//! 3. Every salted owner write proves credential state and address inclusion under the pinned ring namespace.
//! 4. Proof acceptance precedes atomic publication of the new policy root and monotonic absence floor.
//!
//! Relies on:
//! 1. `RecordWriteData::storage_entry` keeps each value inside its mask and each mask inside the accepted list bits.
//! 2. `ApplyRecordsCircuit` keeps list bits outside each mask, moves mint settings only under the entry's flag and keeps the records sorted.

use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage::{chain_start, RootUpdate, StorageError, StorageRegistry},
    storage_instruction::StorageUpdateIxData,
    verifying_key, write_chain, ApplyRecordsStatement, CredentialRootSelection, CredentialRoots,
    CredentialTreeRead, CustomRingError, RingProof,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_ring_policy::ring_id_field;

use crate::loader::{check_authority, check_signer, load_registry_mut};

struct PrivateWriteRoots<'a, 'data> {
    registry: &'a StorageRegistry,
    ix: &'a StorageUpdateIxData<'data>,
    capacity: usize,
}

struct CheckedWriteRoots {
    credentials: CredentialRoots,
    absence_checkpoint: Option<u64>,
}

pub fn process_update_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = StorageUpdateIxData::parse(data)?;
    let [authority_account, registry_account, credential_accounts @ ..] = accounts else {
        return Err(StorageError::MissingAccounts.into());
    };
    // 1. The authority and current revision fix the registry state and the start of the write chain.
    check_signer(authority_account)?;
    let chain_start = chain_start(registry_account.address(), ix.revision)?;
    let mut registry = load_registry_mut(program_id, registry_account)?;
    check_authority(&registry, authority_account)?;
    if registry.newest().revision != ix.revision {
        return Err(StorageError::RevisionChanged.into());
    }
    let count = ix.writes.len() as u64;
    let circuit = RingCircuit::apply_records(count);
    let RingCircuit::ApplyRecords { writes } = circuit else {
        return Err(StorageError::UnsupportedBatch.into());
    };
    // 2. The host derives credential selection from private masks and authenticated asset preimages.
    // Account roots and the verified ring preimage bind the proof to the canonical credential owner.
    let credential_writes = ix.credential_writes()?;
    let checked = PrivateWriteRoots {
        registry: &registry,
        ix: &ix,
        capacity: usize::from(writes),
    }
    .load(credential_accounts)?;
    // 3. The chain binds every write in instruction order, including writes with unchanged leaves.
    let chain_end = ix.entries().try_fold(
        chain_start,
        |chain, entry| -> Result<[u8; 32], ProgramError> {
            let entry = entry.map_err(|_| StorageError::InvalidWrite)?;
            write_chain(&chain, &entry).map_err(|_| StorageError::HashingFailed.into())
        },
    )?;
    let statement = ApplyRecordsStatement {
        old_root: registry.newest().hash,
        new_root: ix.apply.new_root,
        old_next_index: registry.next_index(),
        new_next_index: ix.apply.new_next_index(),
        chain_start,
        chain_end,
        count,
        credential_writes,
        private_ring_id: if credential_writes == 0 {
            [0; 32]
        } else {
            registry.private_ring_id
        },
        credentials: checked.credentials,
    };
    // 4. One proof binds the policy transition and every required credential and address inclusion.
    RingProof {
        proof: &ix.apply.proof,
        statement: statement.hash().map_err(|_| StorageError::HashingFailed)?,
        key: verifying_key(circuit).ok_or(StorageError::UnsupportedBatch)?,
    }
    .verify()
    .map_err(|_| StorageError::ProofVerificationFailed)?;
    // 5. The policy root and maximum absence checkpoint become visible together after verification.
    registry.update(RootUpdate {
        slot: Clock::get()?.slot,
        data: &ix,
        absence_checkpoint: checked.absence_checkpoint,
    })?;
    Ok(())
}

impl PrivateWriteRoots<'_, '_> {
    fn load(self, accounts: &mut [AccountView]) -> Result<CheckedWriteRoots, ProgramError> {
        // 1. A public batch has no credential accounts and contributes an all zero statement suffix.
        if self.ix.credential_writes()? == 0 {
            self.ix
                .credential_read
                .check_empty()
                .map_err(|_| StorageError::InvalidCredentialRead)?;
            if !accounts.is_empty() || self.ix.ring_program.is_some() {
                return Err(StorageError::InvalidCredentialRead.into());
            }
            return Ok(CheckedWriteRoots {
                credentials: CredentialRoots::empty(self.capacity)
                    .map_err(|_| StorageError::InvalidCredentialRead)?,
                absence_checkpoint: None,
            });
        }
        // 2. The ring program preimage authenticates the credential signing PDA before roots enter the statement.
        if !self.registry.is_private() {
            return Err(StorageError::PrivateWriteWithoutRing.into());
        }
        let ring_program = self
            .ix
            .ring_program
            .as_ref()
            .ok_or(StorageError::InvalidPrivateRing)?;
        if ring_id_field(ring_program.as_array()).map_err(|_| StorageError::HashingFailed)?
            != self.registry.private_ring_id
        {
            return Err(StorageError::InvalidPrivateRing.into());
        }
        self.ix
            .credential_read
            .check_capacity(self.capacity)
            .map_err(|_| StorageError::InvalidCredentialRead)?;
        let (address_tree, state_trees) = accounts
            .split_first_mut()
            .ok_or(StorageError::MissingAccounts)?;
        let indexes = self.ix.credential_read.state_root_indexes();
        if state_trees.len() != indexes.len() {
            return Err(StorageError::InvalidCredentialRead.into());
        }
        // 3. Accepted tree roots establish the proof checkpoint and the state trees holding immutable credentials.
        let checkpoint = read_credential_tree(address_tree, |tree| {
            tree.checkpoint(self.ix.credential_read.address_root_index())
        })?;
        let state_roots = state_trees
            .iter_mut()
            .zip(indexes)
            .map(|(tree, index)| read_credential_tree(tree, |read| read.state_root(*index)))
            .collect::<Result<Vec<_>, _>>()?;
        let credentials = CredentialRootSelection {
            ring_program,
            address_checkpoint: checkpoint,
            state_roots: &state_roots,
            capacity: self.capacity,
        }
        .roots()
        .map_err(|_| StorageError::InvalidCredentialRead)?;
        Ok(CheckedWriteRoots {
            credentials,
            absence_checkpoint: Some(checkpoint.sequence()),
        })
    }
}

fn read_credential_tree<R>(
    account: &mut AccountView,
    read: impl FnOnce(CredentialTreeRead<'_>) -> Result<R, CustomRingError>,
) -> Result<R, ProgramError> {
    let address = *account.address();
    let owner = *account.owner();
    let mut data = account.try_borrow_mut()?;
    read(CredentialTreeRead {
        address: &address,
        owner: &owner,
        data: &mut data,
    })
    .map_err(Into::into)
}
