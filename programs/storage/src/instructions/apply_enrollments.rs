use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage::StorageError,
    storage_instruction::ApplyEnrollmentsIxData,
    tracking::{tracking_chain_start, TrackingRootUpdate},
    verifying_key, ApplyEnrollmentsStatement, RingProof,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use crate::{
    loader::{load_owned_tracking_authorization_mut, load_tracking_registry_mut},
    parse,
};

/// Permissionless, the program reads every entry from the named account so an applier chooses only
/// which ones and in what order, a stale proof fails and the next applier reuses the accounts.
pub fn process_apply_enrollments_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: &ApplyEnrollmentsIxData = parse(data)?;
    let [registry_account, authorizations @ ..] = accounts else {
        return Err(StorageError::MissingAccounts.into());
    };
    ApplyEnrollmentsIxData::check_count(authorizations.len())?;
    let registry_address = *registry_account.address();
    let chain_start = tracking_chain_start(&registry_address, ix.revision)?;
    let mut registry = load_tracking_registry_mut(program_id, registry_account)?;
    let (old_root, old_next_index) = (registry.roots[0].hash, registry.next_index());
    registry.update(TrackingRootUpdate {
        revision: ix.revision,
        slot: Clock::get()?.slot,
        new_root: ix.apply.new_root,
        new_next_index: ix.apply.new_next_index(),
    })?;
    let count = authorizations.len() as u64;
    let chain_end = authorizations.iter_mut().try_fold(
        chain_start,
        |chain, account| -> Result<[u8; 32], ProgramError> {
            // A duplicate account reads its own apply and refuses.
            let entry = load_owned_tracking_authorization_mut(program_id, &registry_address, account)?
                .apply()?;
            entry
                .chained(&chain)
                .map_err(|_| StorageError::HashingFailed.into())
        },
    )?;
    let statement = ApplyEnrollmentsStatement {
        old_root,
        new_root: ix.apply.new_root,
        old_next_index,
        new_next_index: ix.apply.new_next_index(),
        chain_start,
        chain_end,
        count,
    };
    RingProof {
        proof: &ix.apply.proof,
        statement: statement.hash().map_err(|_| StorageError::HashingFailed)?,
        key: verifying_key(RingCircuit::apply_enrollments(count))
            .ok_or(StorageError::UnsupportedBatch)?,
    }
    .verify()
    .map_err(|_| StorageError::ProofVerificationFailed)?;
    Ok(())
}
