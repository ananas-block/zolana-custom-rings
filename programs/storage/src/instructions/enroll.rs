use custom_ring_interface::{
    storage::StorageError, storage_instruction::EnrollRequest, RegisterKeyCheck,
};
use pinocchio::{AccountView, Address, ProgramResult};

use crate::loader::{
    check_signer, load_owned_tracking_authorization_mut, load_tracking_registry,
    TrackingAuthorizationInit,
};

/// The owner's signature authorizes, a program signs its PDA through CPI, any payer funds it.
pub fn process_enroll_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let EnrollRequest { ix, proof } = EnrollRequest::parse(data)?;
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
    if authorization_account.data_len() != 0 {
        if proof.is_some() {
            return Err(StorageError::EnrollmentProofShape.into());
        }
        let mut authorization = load_owned_tracking_authorization_mut(
            program_id,
            registry_account.address(),
            authorization_account,
        )?;
        if &authorization.owner != owner_account.address() {
            return Err(StorageError::InvalidTrackingAuthorization.into());
        }
        return authorization.rotate(ix).map_err(Into::into);
    }
    let proof = proof.ok_or(StorageError::EnrollmentProofShape)?;
    let registry = load_tracking_registry(program_id, registry_account)?;
    RegisterKeyCheck {
        ring_id: &registry.ring_id,
        auditor_pubkey: &registry.auditor_pubkey,
        owner: owner_account.address(),
        ix,
        proof,
    }
    .verify()?;
    TrackingAuthorizationInit {
        program_id,
        payer: payer_account,
        owner: owner_account.address(),
        registry: registry_account.address(),
        ix,
    }
    .init(authorization_account)
}
