use custom_ring_interface::{
    key_catalog::RingCircuit,
    queue_chain,
    storage::{chain_start, RootUpdate, StorageError},
    storage_instruction::{StorageUpdateIxData, StorageWriteData, UpdateMode},
    verifying_key, ApplyRecordsStatement, RingProof,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use crate::loader::{check_authority, check_signer, load_authorization_mut, load_registry_mut};

pub fn process_update_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    mode: UpdateMode,
) -> ProgramResult {
    let ix = StorageUpdateIxData::parse(data)?;
    let [authority_account, registry_account, authorizations @ ..] = accounts else {
        return Err(StorageError::MissingAccounts.into());
    };
    check_signer(authority_account)?;
    let chain_start = chain_start(registry_account.address(), ix.revision)?;
    let registry_address = *registry_account.address();
    let mut registry = load_registry_mut(program_id, registry_account)?;
    check_authority(&registry, authority_account)?;
    let (old_root, old_next_index) = (registry.roots[0].hash, registry.next_index());
    // A stale revision fails here, ahead of the proof made against its old root.
    registry.update(RootUpdate {
        mode,
        slot: Clock::get()?.slot,
        data: &ix,
    })?;
    let mut authorizations = authorizations.iter_mut();
    let chain_end = ix.writes.iter().try_fold(
        chain_start,
        |chain, write| -> Result<[u8; 32], ProgramError> {
            let entry = match write {
                // The hash comes from the owner-signed account, a batch can only delay it.
                StorageWriteData::Address(write) => load_authorization_mut(
                    program_id,
                    &registry_address,
                    &write.owner,
                    authorizations
                        .next()
                        .ok_or(StorageError::InvalidAddressAuthorization)?,
                )?
                .apply(write)?,
                _ => write.entry().map_err(|_| StorageError::InvalidWrite)?,
            };
            queue_chain(&chain, &entry).map_err(|_| StorageError::HashingFailed.into())
        },
    )?;
    if authorizations.next().is_some() {
        return Err(StorageError::InvalidAddressAuthorization.into());
    }
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
