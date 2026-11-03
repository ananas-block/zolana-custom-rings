use custom_ring_interface::{storage::StorageError, storage_instruction::EnrollAddressIxData};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    loader::{check_signer, load_registry, AddressEnrollment},
    parse,
};

/// The owner's signature alone authorizes, a program signs its PDA through CPI.
pub fn process_enroll_address_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &EnrollAddressIxData = parse(data)?;
    let [payer_account, owner_account, registry_account, authorization_account, system_program_account, ..] =
        accounts
    else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(payer_account)?;
    check_signer(owner_account)?;
    if !pinocchio_system::check_id(system_program_account.address()) {
        return Err(StorageError::InvalidSystemProgram.into());
    }
    ix.check()?;
    // The registry's immutable ring scopes the address, the owner names none.
    let ring_id = load_registry(program_id, registry_account)?.ring_id;
    if ring_id == [0; 32] {
        return Err(StorageError::RegistryServesNoRing.into());
    }
    AddressEnrollment {
        program_id,
        payer: payer_account,
        owner: owner_account.address(),
        registry: registry_account.address(),
        ring_id,
        ix,
    }
    .write(authorization_account)
}
