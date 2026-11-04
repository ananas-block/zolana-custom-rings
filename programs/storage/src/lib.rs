//! Transfer authorization remains the consumer's responsibility.

use bytemuck::Pod;
use custom_ring_interface::{storage::StorageError, storage_instruction::tag};
use pinocchio::{AccountView, Address, ProgramResult};

use instructions::{
    process_apply_enrollments_ix, process_enroll_ix, process_initialize_ix,
    process_initialize_tracking_ix, process_owner_grant_ix, process_update_authority_ix,
    process_update_ix, process_update_private_ix,
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
        tag::ENROLL => process_enroll_ix(program_id, accounts, data),
        tag::APPLY_ENROLLMENTS => process_apply_enrollments_ix(program_id, accounts, data),
        tag::OWNER_GRANT => process_owner_grant_ix(program_id, accounts, data),
        tag::INITIALIZE_TRACKING => process_initialize_tracking_ix(program_id, accounts, data),
        tag::UPDATE_PRIVATE => process_update_private_ix(program_id, accounts, data),
        _ => Err(StorageError::InvalidInstructionData.into()),
    }
}

pub(crate) fn parse<T: Pod>(data: &[u8]) -> Result<&T, StorageError> {
    bytemuck::try_from_bytes(data).map_err(|_| StorageError::InvalidInstructionData)
}
