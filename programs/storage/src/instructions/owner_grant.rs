use custom_ring_interface::{storage::StorageError, storage_instruction::OwnerGrantIxData};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    loader::{check_signer, load_tracking_registry, OwnerGrantWrite},
    parse,
};

/// The owner's signature alone authorizes, a program signs its PDA through CPI.
pub fn process_owner_grant_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &OwnerGrantIxData = parse(data)?;
    let [payer_account, owner_account, registry_account, grant_account, system_program_account, ..] =
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
    load_tracking_registry(program_id, registry_account)?;
    OwnerGrantWrite {
        program_id,
        payer: payer_account,
        owner: owner_account.address(),
        registry: registry_account.address(),
        ix,
    }
    .write(grant_account)
}
