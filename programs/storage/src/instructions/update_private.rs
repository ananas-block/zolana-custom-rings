use custom_ring_interface::{
    key_catalog::RingCircuit,
    private_list::{private_list_chain_start, ApplyPrivateListStatement},
    storage::{PrivateRootUpdate, StorageError},
    storage_instruction::PrivateUpdateIxData,
    verifying_key, RingProof,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use crate::loader::{check_authority, check_signer, load_registry_mut, load_tracking_registry};

pub fn process_update_private_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = PrivateUpdateIxData::parse(data)?;
    let [authority_account, registry_account, tracking_account, ..] = accounts else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(authority_account)?;
    let chain_start = private_list_chain_start(registry_account.address(), ix.revision)
        .map_err(|_| StorageError::HashingFailed)?;
    let mut registry = load_registry_mut(program_id, registry_account)?;
    check_authority(&registry, authority_account)?;
    // The pinned pair, another registry's revision would set a floor no frame of this ring reads.
    if tracking_account.address() != &registry.tracking_registry {
        return Err(StorageError::InvalidTrackingRegistry.into());
    }
    let tracking_revision = load_tracking_registry(program_id, tracking_account)?
        .newest()
        .revision;
    let old_root = registry.roots[0].hash;
    registry.update_private(PrivateRootUpdate {
        revision: ix.revision,
        restrictive: ix.restrictive,
        slot: Clock::get()?.slot,
        new_root: ix.apply.new_root,
        tracking_revision,
    })?;
    let chain_end = ix.writes.iter().try_fold(
        chain_start,
        |chain, write| -> Result<[u8; 32], ProgramError> {
            let published = write.published();
            registry.advance_write_counter(published.write_counter)?;
            published
                .chain(&chain)
                .map_err(|_| StorageError::HashingFailed.into())
        },
    )?;
    let statement = ApplyPrivateListStatement {
        old_root,
        new_root: ix.apply.new_root,
        chain_start,
        chain_end,
        count: ix.writes.len() as u64,
        restrictive: ix.restrictive,
    };
    let circuit =
        RingCircuit::apply_private_list(statement.count).ok_or(StorageError::UnsupportedBatch)?;
    RingProof {
        proof: &ix.apply.proof,
        statement: statement.hash().map_err(|_| StorageError::HashingFailed)?,
        key: verifying_key(circuit).ok_or(StorageError::UnsupportedBatch)?,
    }
    .verify()
    .map_err(|_| StorageError::ProofVerificationFailed)?;
    Ok(())
}
