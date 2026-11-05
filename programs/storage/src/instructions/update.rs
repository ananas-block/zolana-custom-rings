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
//! 3. A zero grace update on a pinned source stores the pinned registry's newest revision as the floor, and the instruction fails without that account.
//!
//! Relies on:
//! 1. `RecordWriteData::storage_entry` keeps each value inside its mask and each mask inside the eight list bits, the circuit takes the chained value as given.
//! 2. `ApplyRecordsCircuit` keeps list bits outside each mask, moves mint settings only under the entry's flag and keeps the records sorted.

use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage::{chain_start, RootUpdate, StorageError},
    storage_instruction::StorageUpdateIxData,
    verifying_key, write_chain, ApplyRecordsStatement, RingProof,
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
    // 1. The authority signs, and the chain starts from the registry and revision the proof names.
    check_signer(authority_account)?;
    let chain_start = chain_start(registry_account.address(), ix.revision)?;
    let mut registry = load_registry_mut(program_id, registry_account)?;
    check_authority(&registry, authority_account)?;
    // 2. A zero grace write on a pinned source reads the pin's newest revision, the floor `update` stores.
    let tracking_revision = registry
        .reads_tracking(&ix)
        .then(|| {
            let tracking = optional.first().ok_or(StorageError::MissingAccounts)?;
            load_pinned_tracking_revision(program_id, &registry, tracking)
        })
        .transpose()?;
    // 3. The statement's old values come from the account. A stale revision fails here, ahead of the proof made against its old root.
    let (old_root, old_next_index) = (registry.roots[0].hash, registry.next_index());
    registry.update(RootUpdate {
        slot: Clock::get()?.slot,
        data: &ix,
        tracking_revision,
    })?;
    // 4. Every write enters the chain in instruction order, a write the chain leaves out has no proof.
    let chain_end = ix.entries().try_fold(
        chain_start,
        |chain, entry| -> Result<[u8; 32], ProgramError> {
            let entry = entry.map_err(|_| StorageError::InvalidWrite)?;
            write_chain(&chain, &entry).map_err(|_| StorageError::HashingFailed.into())
        },
    )?;
    // 5. A failed proof reverts the root step 3 moved.
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
