//! Enroll refusals ahead of the RegisterKey proof, sent with a zeroed proof.
//!
//! A substituted ciphertext and a second enrollment of one owner refuse only past that proof.

use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::StorageError, tag, CustomRingError, CustomRingProof, EnrollIxData, EnrollRequest,
    RingPolicy, CREDENTIAL_PDA_SEED,
};
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use spr_account_checks::error::AccountError;
use spr_interface::instruction::TransactProof;

use crate::{
    common::{
        address_tree, credential_tree, pda, policy_pda, refused, refused_with, Ring, Sent, Setup,
        PROGRAM, SYSTEM,
    },
    transact_rules::SPP,
};

/// Positions in the `EnrollmentAccounts::load` order.
const OWNER: usize = 0;
const RING: usize = 1;
const ADDRESS_TREE: usize = 6;
const CREDENTIAL_PDA: usize = 8;

fn field(byte: u8) -> [u8; 32] {
    let mut field = [0; 32];
    field[31] = byte;
    field
}

struct Enrollment {
    ring: Ring,
    owner: Keypair,
}

impl Enrollment {
    fn new() -> Self {
        Self {
            ring: Ring::new(Setup::AuditOnly),
            owner: Keypair::new_from_array([0x31; 32]),
        }
    }

    fn accounts(&self) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(self.owner.pubkey(), true),
            AccountMeta::new_readonly(policy_pda(), false),
            AccountMeta::new(self.ring.payer.pubkey(), true),
            AccountMeta::new(credential_tree(), false),
            AccountMeta::new_readonly(SPP, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new(address_tree(), false),
            // SPP derives the address reservation, the ring reads none before the proof.
            AccountMeta::new(Address::new_from_array([0x44; 32]), false),
            AccountMeta::new_readonly(pda(CREDENTIAL_PDA_SEED), false),
        ]
    }

    fn data() -> Vec<u8> {
        let ix = EnrollIxData {
            nullifier_pk: field(3),
            list_tag: field(4),
            eph_u: [5; 32],
            ciphertext: [6; 64],
        };
        let request = EnrollRequest {
            ix: &ix,
            register_key: &CustomRingProof::zeroed(),
            transact: TransactProof {
                a: [1; 32],
                b: [2; 128],
                c: [3; 32],
            },
            address_root_index: 0,
        };
        [&[tag::ENROLL][..], &request.encode().unwrap()].concat()
    }

    fn send(&mut self, accounts: Vec<AccountMeta>) -> Sent {
        let owner = self.owner.insecure_clone();
        let signers: Vec<&Keypair> = match accounts[OWNER].is_signer {
            true => vec![&owner],
            false => Vec::new(),
        };
        let instruction = Instruction {
            program_id: PROGRAM,
            accounts,
            data: Self::data(),
        };
        self.ring.send(instruction, &signers)
    }
}

#[test]
fn an_owner_enrollment_sponsored_by_another_payer_reaches_the_register_key_proof() {
    let mut enrollment = Enrollment::new();
    assert_ne!(enrollment.owner.pubkey(), enrollment.ring.payer.pubkey());
    let accounts = enrollment.accounts();
    refused_with(
        enrollment.send(accounts),
        InstructionError::Custom(StorageError::ProofVerificationFailed as u32),
    );
}

#[test]
fn an_owner_that_does_not_sign_is_refused() {
    let mut enrollment = Enrollment::new();
    let mut accounts = enrollment.accounts();
    accounts[OWNER].is_signer = false;
    refused_with(
        enrollment.send(accounts),
        InstructionError::Custom(AccountError::InvalidSigner.into()),
    );
}

#[test]
fn a_ring_account_of_another_program_is_refused() {
    let mut enrollment = Enrollment::new();
    let foreign = Address::new_from_array([0x61; 32]);
    let data: RingPolicy = enrollment.ring.read(&policy_pda());
    enrollment
        .ring
        .store(foreign, SPP, bytemuck::bytes_of(&data).to_vec());
    let mut accounts = enrollment.accounts();
    accounts[RING].pubkey = foreign;
    refused(
        enrollment.send(accounts),
        CustomRingError::InvalidRingPolicy,
    );
}

#[test]
fn a_credential_pda_off_the_canonical_seed_is_refused() {
    let mut enrollment = Enrollment::new();
    for substitute in [policy_pda(), pda(spr_interface::RING_AUTH_PDA_SEED)] {
        let mut accounts = enrollment.accounts();
        accounts[CREDENTIAL_PDA].pubkey = substitute;
        refused(
            enrollment.send(accounts),
            CustomRingError::InvalidCredentialPda,
        );
    }
}

#[test]
fn an_address_tree_other_than_tree_zero_is_refused() {
    let mut enrollment = Enrollment::new();
    let mut accounts = enrollment.accounts();
    accounts[ADDRESS_TREE].pubkey = credential_tree();
    refused(
        enrollment.send(accounts),
        CustomRingError::InvalidAddressTree,
    );
}

#[test]
fn a_trailing_account_is_refused() {
    let mut enrollment = Enrollment::new();
    let mut accounts = enrollment.accounts();
    accounts.push(AccountMeta::new_readonly(SYSTEM, false));
    refused(
        enrollment.send(accounts),
        CustomRingError::InvalidEnrollmentAccounts,
    );
}
