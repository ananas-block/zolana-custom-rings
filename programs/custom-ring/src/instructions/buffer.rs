use custom_ring_interface::{
    CreateFrameBufferIxData, CustomRingError, FrameBuffer, FrameBufferHeader, FrameBufferWrite,
    InstructionTag, RingMode, SettleBufferedIxData, WriteFrameIxData, FRAME_BUFFER_HEADER_LEN,
    FRAME_BUFFER_PDA_SEED, RING_MERGE_PAYER_INDEX, RING_MERGE_RING_CONFIG_INDEX,
    RING_TRANSACT_RING_CONFIG_INDEX, TRANSACT_PAYER_INDEX,
};
use pinocchio::{
    account::Ref,
    address::address_eq,
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use spr_interface::RING_AUTH_PDA_SEED;

use crate::instructions::{
    instruction_runtime::{check_system_program, close_into, no_data},
    loader::load_policy,
    process_deposit_ix, process_merge_ix, process_transfer_ix,
};

#[inline(never)]
pub fn process_create_frame_buffer_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix = CreateFrameBufferIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let rent_payer = iter.next_signer_mut("rent_payer")?;
    let writer = iter.next_signer("writer")?;
    let buffer = iter.next_mut("buffer")?;
    check_system_program(iter.next_account("system_program")?)?;
    let header = FrameBufferHeader::new(&ix, *writer.address(), *rent_payer.address())?;

    let nonce = ix.nonce.to_le_bytes();
    let seeds: [&[u8]; 3] = [
        FRAME_BUFFER_PDA_SEED,
        writer.address().as_ref(),
        nonce.as_ref(),
    ];
    let (derived, bump) = Address::derive_program_address(&seeds, program_id)
        .ok_or(CustomRingError::FrameBufferAddress)?;
    if !address_eq(buffer.address(), &derived) {
        return Err(CustomRingError::FrameBufferAddress.into());
    }
    if buffer.data_len() != 0 {
        return Err(CustomRingError::FrameBufferExists.into());
    }
    let bump = [bump];
    let signer_seeds = [
        Seed::from(seeds[0]),
        Seed::from(seeds[1]),
        Seed::from(seeds[2]),
        Seed::from(&bump),
    ];
    pinocchio_system::create_account_with_minimum_balance_signed(
        buffer,
        header.account_len(),
        program_id,
        rent_payer,
        None,
        &[Signer::from(&signer_seeds)],
    )?;
    buffer
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?[..FRAME_BUFFER_HEADER_LEN]
        .copy_from_slice(bytemuck::bytes_of(&header));
    Ok(())
}

#[inline(never)]
pub fn process_write_frame_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let write = WriteFrameIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let writer = iter.next_signer("writer")?;
    let buffer = iter.next_mut("buffer")?;
    check_buffer_owner(program_id, buffer)?;
    let mut held = buffer
        .try_borrow_mut()
        .map_err(|_| CustomRingError::InvalidFrameBuffer)?;
    FrameBufferWrite::of(&mut held)?.apply(writer.address(), &write)?;
    Ok(())
}

#[inline(never)]
pub fn process_close_frame_buffer_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let [closer, buffer, rent_payer, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    {
        let held = load_frame_buffer(program_id, buffer)?;
        let header = FrameBuffer::of(&held)?.header;
        header.check_close(
            closer.address(),
            closer.is_signer(),
            Clock::get()?.unix_timestamp,
        )?;
        if !address_eq(&header.rent_payer, rent_payer.address()) {
            return Err(CustomRingError::FrameRentPayer.into());
        }
    }
    close_into(buffer, rent_payer, CustomRingError::FrameRentPayer)
}

#[inline(never)]
pub fn process_settle_buffered_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let settle = SettleBufferedIxData::parse(data)?;
    let inner_tag = settle.inner()?;
    let (fixed, inner) = accounts
        .split_at_mut_checked(3)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    // The event CPI resolves its callee here.
    let [buffer, rent_payer, _program] = fixed else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if buffer.address().as_array() != settle.buffer {
        return Err(CustomRingError::FrameBufferMismatch.into());
    }
    {
        let held = load_frame_buffer(program_id, buffer)?;
        let frame_buffer = FrameBuffer::of(&held)?;
        frame_buffer.check_settlement(
            &settle,
            rent_payer.address(),
            Clock::get()?.unix_timestamp,
        )?;
        let ring_auth = RingAuthSlot::find(program_id, inner)?;
        check_parties(
            program_id,
            frame_buffer.header,
            inner_tag,
            inner,
            ring_auth.index,
        )?;
        // A failed settlement reverts the event.
        ring_auth.emit(program_id, inner, frame_buffer.event_data())?;
        let frame = frame_buffer.frame();
        let body = frame.get(1..).unwrap_or_default();
        match inner_tag {
            InstructionTag::Merge => process_merge_ix(program_id, inner, body)?,
            // The deposit prefix layout starts at the tag byte.
            InstructionTag::Deposit => process_deposit_ix(program_id, inner, frame)?,
            transfer => process_transfer_ix(program_id, inner, body, transfer)?,
        }
    }
    close_into(buffer, rent_payer, CustomRingError::FrameRentPayer)
}

#[inline(never)]
pub fn process_frame_event_ix(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let authority = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (ring_auth, _) = Address::find_program_address(&[RING_AUTH_PDA_SEED], program_id);
    if !authority.is_signer() || !address_eq(authority.address(), &ring_auth) {
        return Err(CustomRingError::InvalidFrameEvent.into());
    }
    Ok(())
}

fn check_buffer_owner(program_id: &Address, account: &AccountView) -> Result<(), CustomRingError> {
    match account.owned_by(program_id) {
        true => Ok(()),
        false => Err(CustomRingError::InvalidFrameBuffer),
    }
}

fn load_frame_buffer<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, [u8]>, ProgramError> {
    check_buffer_owner(program_id, account)?;
    account
        .try_borrow()
        .map_err(|_| CustomRingError::InvalidFrameBuffer.into())
}

/// The inner handler checks the slot.
struct RingAuthSlot {
    index: usize,
    bump: u8,
}

impl RingAuthSlot {
    fn find(program_id: &Address, inner: &[AccountView]) -> Result<Self, CustomRingError> {
        let (address, bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], program_id);
        let index = inner
            .iter()
            .position(|account| address_eq(account.address(), &address))
            .ok_or(CustomRingError::MissingRingAuth)?;
        Ok(Self { index, bump })
    }

    fn emit(&self, program_id: &Address, inner: &[AccountView], event: &[u8]) -> ProgramResult {
        let ring_auth = &inner[self.index];
        let accounts = [InstructionAccount::new(
            ring_auth.address(),
            ring_auth.is_writable(),
            true,
        )];
        let bump = [self.bump];
        let seeds = [Seed::from(RING_AUTH_PDA_SEED), Seed::from(&bump)];
        invoke_signed::<1, _>(
            &InstructionView {
                program_id,
                accounts: &accounts,
                data: event,
            },
            &[ring_auth],
            &[Signer::from(&seeds)],
        )
    }
}

/// The anonymous proof excludes the payer from the hidden sender.
fn check_parties(
    program_id: &Address,
    header: &FrameBufferHeader,
    inner_tag: InstructionTag,
    inner: &[AccountView],
    ring_auth: usize,
) -> Result<(), ProgramError> {
    let ring = load_policy(
        program_id,
        inner.first().ok_or(ProgramError::NotEnoughAccountKeys)?,
    )?;
    if ring.mode()? != RingMode::Anonymous {
        return Ok(());
    }
    let (config_index, payer_index) = match inner_tag {
        InstructionTag::Merge => (RING_MERGE_RING_CONFIG_INDEX, RING_MERGE_PAYER_INDEX),
        InstructionTag::Deposit => return Ok(()),
        _ => (RING_TRANSACT_RING_CONFIG_INDEX, TRANSACT_PAYER_INDEX),
    };
    let payer = ring_auth
        .checked_sub(config_index)
        .and_then(|start| inner.get(start + payer_index))
        .ok_or(CustomRingError::MissingRingAuth)?;
    if !address_eq(payer.address(), &header.writer)
        || !address_eq(payer.address(), &header.rent_payer)
    {
        return Err(CustomRingError::FramePartyNotPayer.into());
    }
    Ok(())
}
