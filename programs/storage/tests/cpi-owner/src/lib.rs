//! Forwards one instruction to the storage program under its `owner` PDA.

use pinocchio::{
    address::address_eq,
    cpi::{invoke_signed_with_slice, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};

pinocchio::entrypoint!(process_instruction);

const STORAGE_PROGRAM_ID: Address = Address::new_from_array([0x53; 32]);
const OWNER_SEED: &[u8] = b"owner";

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (owner, bump) = Address::derive_program_address(&[OWNER_SEED], program_id)
        .ok_or(ProgramError::InvalidSeeds)?;
    let metas: Vec<InstructionAccount> = accounts
        .iter()
        .map(|account| {
            InstructionAccount::new(
                account.address(),
                account.is_writable(),
                account.is_signer() || address_eq(account.address(), &owner),
            )
        })
        .collect();
    let bump = [bump];
    let seeds = [Seed::from(OWNER_SEED), Seed::from(&bump)];
    let instruction = InstructionView {
        program_id: &STORAGE_PROGRAM_ID,
        accounts: &metas,
        data,
    };
    invoke_signed_with_slice(&instruction, accounts, &[Signer::from(seeds.as_slice())])
}
