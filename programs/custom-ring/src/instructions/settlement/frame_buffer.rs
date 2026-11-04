use custom_ring_interface::{
    frame_digest, tag, CustomRingError, FrameBuffer, FrameBufferHeader, InstructionTag,
    WriteFrameIxData, FRAME_BUFFER_HEADER_LEN, FRAME_BUFFER_PDA_SEED, TRANSACT_PAYER_INDEX,
};
use pinocchio::{
    cpi::invoke, error::ProgramError, instruction::InstructionView, AccountView, Address,
    ProgramResult,
};
use spr_account_checks::AccountIterator;

use crate::instructions::{
    instruction_runtime::{check_system_program, close_into, no_data, Pda, PdaAllocation},
    loader::{load_frame_buffer, load_frame_buffer_mut},
    TransferRun,
};

#[inline(never)]
pub fn process_write_frame_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let write = WriteFrameIxData::parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let writer = iter.next_signer_mut("writer")?;
    let buffer = iter.next_mut("buffer")?;
    if buffer.data_len() == 0 {
        check_system_program(iter.next_account("system_program")?)?;
        let nonce = write.nonce.to_le_bytes();
        let seeds: [&[u8]; 3] = [FRAME_BUFFER_PDA_SEED, writer.address().as_ref(), &nonce];
        let pda = Pda {
            program_id,
            seeds: &seeds,
        };
        let bump = pda
            .canonical(buffer.address())
            .ok_or(CustomRingError::InvalidFrameBuffer)?;
        pda.allocate(PdaAllocation {
            payer: writer,
            account: buffer,
            space: FRAME_BUFFER_HEADER_LEN + write.checked_frame_len()?,
            bump,
        })?;
        load_frame_buffer_mut(program_id, buffer)?[..FRAME_BUFFER_HEADER_LEN].copy_from_slice(
            bytemuck::bytes_of(&FrameBufferHeader::new(*writer.address())),
        );
    } else {
        FrameBuffer::of(&load_frame_buffer(program_id, buffer)?)?.check_writer(writer.address())?;
    }
    write.apply(&mut load_frame_buffer_mut(program_id, buffer)?)?;
    Ok(())
}

#[inline(never)]
pub fn process_close_frame_buffer_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    no_data(data)?;
    let [writer, buffer, rent_recipient, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !writer.is_signer() {
        return Err(CustomRingError::UnauthorizedFrameWriter.into());
    }
    FrameBuffer::of(&load_frame_buffer(program_id, buffer)?)?.check_writer(writer.address())?;
    close_into(buffer, rent_recipient, CustomRingError::InvalidFrameBuffer)
}

/// The runtime requires the ring program among the accounts to self-CPI.
#[inline(never)]
pub fn process_settle_buffered_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let digest: &[u8; 32] = data
        .try_into()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    let [buffer, program, inner @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let spp = {
        let held = load_frame_buffer(program_id, buffer)?;
        let frame_buffer = FrameBuffer::of(&held)?;
        let frame = frame_buffer.frame();
        // 1. Every signer signed the digest.
        if frame_digest(frame)? != *digest {
            return Err(CustomRingError::FrameDigestMismatch.into());
        }
        let (&frame_tag, body) = frame.split_first().ok_or(CustomRingError::FrameLength)?;
        let transfer_tag = match frame_tag {
            tag::TRANSFER => InstructionTag::Transfer,
            tag::AUTHORITY_TRANSFER => InstructionTag::AuthorityTransfer,
            _ => return Err(CustomRingError::UnsupportedBufferedTag.into()),
        };
        // 2. The closed buffer leaves readers the event, valid once the transaction succeeds.
        invoke::<1, _>(
            &InstructionView {
                program_id,
                accounts: &[],
                data: frame_buffer.event_data(),
            },
            &[&*program],
        )?;
        TransferRun {
            program_id,
            accounts: inner,
            data: body,
            tag: transfer_tag,
            writer: Some(&frame_buffer.header.writer),
        }
        .run()?
    };
    let payer = inner
        .get_mut(spp + TRANSACT_PAYER_INDEX)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    // 3. The rent returns to the writer.
    close_into(buffer, payer, CustomRingError::InvalidFrameBuffer)
}
