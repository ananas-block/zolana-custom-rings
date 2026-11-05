//! Stores authenticated policy roots and owner grants for ring readers.
//!
//! A ring reads policy records under roots loaded from its pinned storage registries.
//! The authority signature permits a root transition, and the apply proof binds its ordered writes.
//! Owner grants authorize readers in the namespace of the named ring program.
//!
//! Read after `program-libs/interface/src/accounts/storage.rs` and
//! `program-libs/interface/src/accounts/owner_grant.rs`.
//! Read before `programs/storage/src/instructions/update.rs` and
//! `programs/storage/src/instructions/owner_grant.rs`.
//!
//! 1. A root transition starts from the registry's current root and revision.
//! 2. The apply proof binds the new root to the ordered writes the program hashes.
//! 3. Each owner grant binds the ring program, owner and complete reader key at its canonical PDA.

use bytemuck::Pod;
use custom_ring_interface::{storage::StorageError, storage_instruction::tag};
use pinocchio::{AccountView, Address, ProgramResult};

use instructions::{
    process_initialize_ix, process_owner_grant_ix, process_update_authority_ix, process_update_ix,
};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

mod instructions;
mod loader;

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (instruction, data) = data
        .split_first()
        .ok_or(StorageError::InvalidInstructionData)?;
    match *instruction {
        tag::INITIALIZE => process_initialize_ix(program_id, accounts, data),
        tag::UPDATE => process_update_ix(program_id, accounts, data),
        tag::UPDATE_AUTHORITY => process_update_authority_ix(program_id, accounts, data),
        tag::OWNER_GRANT => process_owner_grant_ix(program_id, accounts, data),
        _ => Err(StorageError::InvalidInstructionData.into()),
    }
}

pub(crate) fn parse<T: Pod>(data: &[u8]) -> Result<&T, StorageError> {
    bytemuck::try_from_bytes(data).map_err(|_| StorageError::InvalidInstructionData)
}
