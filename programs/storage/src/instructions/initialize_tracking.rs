use custom_ring_interface::{
    storage::StorageError, storage_instruction::InitializeTrackingIxData,
};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    loader::{check_signer, TrackingRegistryInit},
    parse,
};

pub fn process_initialize_tracking_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &InitializeTrackingIxData = parse(data)?;
    let [payer_account, creator_account, registry_account, system_program_account, ..] = accounts
    else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(payer_account)?;
    check_signer(creator_account)?;
    if !pinocchio_system::check_id(system_program_account.address()) {
        return Err(StorageError::InvalidSystemProgram.into());
    }
    ix.check()?;
    TrackingRegistryInit {
        program_id,
        payer: payer_account,
        creator: creator_account.address(),
        ix,
    }
    .init(registry_account)
}
