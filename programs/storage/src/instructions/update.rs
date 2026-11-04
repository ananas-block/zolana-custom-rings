use custom_ring_interface::{
    key_catalog::RingCircuit,
    queue_chain,
    storage::{chain_start, RootUpdate, StorageError},
    storage_instruction::StorageUpdateIxData,
    verifying_key, ApplyRecordsStatement, RingProof,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use crate::loader::{
    check_authority, check_signer, load_pinned_tracking_revision, load_registry_mut,
};

pub fn process_update_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = StorageUpdateIxData::parse(data)?;
    let [authority_account, registry_account, optional @ ..] = accounts else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(authority_account)?;
    let chain_start = chain_start(registry_account.address(), ix.revision)?;
    let mut registry = load_registry_mut(program_id, registry_account)?;
    check_authority(&registry, authority_account)?;
    let tracking_revision = registry
        .reads_tracking(&ix)
        .then(|| {
            let tracking = optional.first().ok_or(StorageError::MissingAccounts)?;
            load_pinned_tracking_revision(program_id, &registry, tracking)
        })
        .transpose()?;
    let (old_root, old_next_index) = (registry.roots[0].hash, registry.next_index());
    // A stale revision fails here, ahead of the proof made against its old root.
    registry.update(RootUpdate {
        slot: Clock::get()?.slot,
        data: &ix,
        tracking_revision,
    })?;
    let chain_end = ix.entries().try_fold(
        chain_start,
        |chain, entry| -> Result<[u8; 32], ProgramError> {
            let entry = entry.map_err(|_| StorageError::InvalidWrite)?;
            queue_chain(&chain, &entry).map_err(|_| StorageError::HashingFailed.into())
        },
    )?;
    let statement = ApplyRecordsStatement {
        old_root,
        new_root: ix.apply.new_root,
        old_next_index,
        new_next_index: ix.apply.new_next_index(),
        chain_start,
        chain_end,
        count: ix.writes.len() as u64,
    };
    RingProof {
        proof: &ix.apply.proof,
        statement: statement.hash().map_err(|_| StorageError::HashingFailed)?,
        key: verifying_key(RingCircuit::apply_records(statement.count))
            .ok_or(StorageError::UnsupportedBatch)?,
    }
    .verify()
    .map_err(|_| StorageError::ProofVerificationFailed)?;
    Ok(())
}
