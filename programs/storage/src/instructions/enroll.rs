use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage::StorageError,
    storage_instruction::{EnrollIxData, EnrollRequest},
    tracking::owner_member,
    verifying_key, CustomRingProof, RegisterKeyStatement, RingProof,
};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

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
    check_register_key(RegisterKeyCheck {
        ring_id: &registry.ring_id,
        list_scope: &registry.list_scope,
        auditor_pubkey: &registry.auditor_pubkey,
        owner: owner_account.address(),
        ix,
        proof,
    })?;
    TrackingAuthorizationInit {
        program_id,
        payer: payer_account,
        owner: owner_account.address(),
        registry: registry_account.address(),
        ix,
    }
    .init(authorization_account)
}

#[must_use]
struct RegisterKeyCheck<'a> {
    ring_id: &'a [u8; 32],
    list_scope: &'a [u8; 32],
    auditor_pubkey: &'a [u8; custom_ring_interface::TAGGED_X25519_KEY_LEN],
    owner: &'a Address,
    ix: &'a EnrollIxData,
    proof: &'a CustomRingProof,
}

/// The program supplies ring, member and auditor key, a proof for any other one fails here.
fn check_register_key(check: RegisterKeyCheck<'_>) -> Result<(), ProgramError> {
    let member = owner_member(check.owner)?;
    let statement = RegisterKeyStatement {
        ring_id: check.ring_id,
        member: &member,
        nullifier_pk: &check.ix.nullifier_pk,
        list_tag: &check.ix.list_tag,
        list_scope: check.list_scope,
        auditor_pubkey: check.auditor_pubkey,
        eph_u: &check.ix.eph_u,
        ciphertext: &check.ix.ciphertext,
    }
    .hash()
    .map_err(|_| StorageError::HashingFailed)?;
    RingProof {
        proof: check.proof,
        statement,
        key: verifying_key(RingCircuit::RegisterKey).ok_or(StorageError::UnsupportedBatch)?,
    }
    .verify()
    .map_err(|_| StorageError::ProofVerificationFailed.into())
}
