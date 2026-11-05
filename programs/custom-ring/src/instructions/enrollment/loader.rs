//! Enrollment account checks bind the signer, ring and canonical credential namespace.
//!
//! The credential PDA signs only a program-built address reservation and output.
//! An alternate PDA or address tree would create another enrollment identity.
//!
//! Read after `instructions/accounts/loader.rs`.
//! Read before `instructions/enrollment/enroll.rs`.

use custom_ring_interface::{
    credential::CREDENTIAL_PDA_SEED, CustomRingError, TAGGED_X25519_KEY_LEN,
};
use pinocchio::{error::ProgramError, AccountView, Address};
use spr_account_checks::AccountIterator;
use spr_program::{
    program::{load_tree_id, PdaOwner},
    ADDRESS_TREE_ID,
};

use crate::instructions::{
    instruction_runtime::{check_system_program, Pda},
    loader::{load_policy, validate_spp_program},
};

pub(super) struct EnrollmentAccounts<'a> {
    pub owner: Address,
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    pub credential_owner: PdaOwner,
    pub credential_bump: u8,
    pub transact: &'a [AccountView],
}

impl<'a> EnrollmentAccounts<'a> {
    pub fn load(
        program_id: &Address,
        accounts: &'a mut [AccountView],
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        // 1. Owner and payer signatures remain independent, including a program owner's CPI.
        let owner = *iter.next_signer("owner")?.address();
        let ring = iter.next_account("ring")?;
        iter.next_signer_mut("payer")?;
        iter.next_mut("output_tree")?;
        let spp_program = iter.next_account("spp_program")?;
        let system_program = iter.next_account("system_program")?;
        let address_tree = iter.next_mut("address_tree")?;
        iter.next_mut("nullifier_pda")?;
        let credential_pda = iter.next_account("credential_pda")?;
        if !iter.iterator_is_empty() {
            return Err(CustomRingError::InvalidEnrollmentAccounts.into());
        }
        check_system_program(system_program)?;
        validate_spp_program(core::slice::from_ref(spp_program))?;
        // 2. Ring ownership and discriminator authenticate its immutable auditor key.
        let auditor_pubkey = load_policy(program_id, ring)?.auditor_pubkey;
        // 3. Every enrollment reserves its identity in the same address tree namespace.
        if load_tree_id(address_tree)? != ADDRESS_TREE_ID {
            return Err(CustomRingError::InvalidAddressTree.into());
        }
        // 4. The canonical credential PDA remains distinct from the ring settlement signer.
        let credential_bump = Pda {
            program_id,
            seeds: &[CREDENTIAL_PDA_SEED],
        }
        .canonical(credential_pda.address())
        .ok_or(CustomRingError::InvalidCredentialPda)?;
        let credential_owner = PdaOwner::new(credential_pda.address())?;
        Ok(Self {
            owner,
            auditor_pubkey,
            credential_owner,
            credential_bump,
            transact: &accounts[2..],
        })
    }
}
