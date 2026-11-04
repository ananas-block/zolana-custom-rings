//! Test stand-in for the ring without proof checks.

use pinocchio::{
    address::address_eq,
    cpi::{invoke_signed_with_slice, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};

pinocchio::entrypoint!(process_instruction);

const RING_AUTH_SEED: &[u8] = b"ring_auth";
const GROW_SEED: &[u8] = b"grow";

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((0, target)) => forward(program_id, accounts, target),
        Some((1, space)) => grow(program_id, accounts, space),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Signs as the ring PDA and sends the first account's data to `target` over the rest.
fn forward(program_id: &Address, accounts: &[AccountView], target: &[u8]) -> ProgramResult {
    let target: [u8; 32] = target
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let (payload, spp) = accounts
        .split_first()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (ring_auth, bump) = Address::find_program_address(&[RING_AUTH_SEED], program_id);
    let metas: Vec<InstructionAccount> = spp
        .iter()
        .map(|account| {
            let signer = account.is_signer() || address_eq(account.address(), &ring_auth);
            InstructionAccount::new(account.address(), account.is_writable(), signer)
        })
        .collect();
    let data = payload.try_borrow()?;
    let bump = [bump];
    let seeds = [Seed::from(RING_AUTH_SEED), Seed::from(&bump)];
    invoke_signed_with_slice(
        &InstructionView {
            program_id: &Address::new_from_array(target),
            accounts: &metas,
            data: &data,
        },
        spp,
        &[Signer::from(seeds.as_slice())],
    )
}

/// Creates an account of `space` bytes through CPI.
fn grow(program_id: &Address, accounts: &mut [AccountView], space: &[u8]) -> ProgramResult {
    let [payer, target, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let space = u64::from_le_bytes(
        space
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    let (_, bump) = Address::find_program_address(&[GROW_SEED], program_id);
    let bump = [bump];
    let seeds = [Seed::from(GROW_SEED), Seed::from(&bump)];
    pinocchio_system::create_account_with_minimum_balance_signed(
        target,
        space as usize,
        program_id,
        payer,
        None,
        &[Signer::from(&seeds)],
    )
}
