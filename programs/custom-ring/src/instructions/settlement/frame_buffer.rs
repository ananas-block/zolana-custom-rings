//! Settles a transfer frame from a writer's buffer, for a frame past the transaction size limit.
//!
//! A writer loads the frame through `WriteFrame`, and the settling transaction carries only its digest.
//! SPP sees the same call as an inline transfer. The risks are a frame changed after signing and a frame readers cannot recover.
//!
//! The instructions guarantee:
//!
//! 1. Every signer of the settling message commits to the frame bytes through the digest.
//! 2. Only the writer changes or closes a buffer.
//! 3. The frame runs every check of an inline transfer, and the writer signs as SPP's payer.
//! 4. A settling transaction records the whole frame in its inner instructions, as `tag || frame`.
//! 5. A settled buffer closes, and its rent returns to the writer.
//!
//! Readers rely on `SettledFrame::frame`. It checks the outcome, the program ids, the tags and the digest.
//! The caller takes the event from the settle's inner instructions. The event instruction checks nothing, and a top-level `FrameEvent` leaves no state.
//!
//! Read after `instructions/transfer/processor.rs`, `instructions/accounts/loader.rs`. Read before `program-libs/interface/src/accounts/frame_buffer.rs`, `instructions/settlement/forward.rs`.

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
    // 1. The first write creates the buffer at the writer's canonical PDA, the nonce lets one writer
    // hold several frames. Any later write comes from that writer.
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
    // 2. A write lands anywhere inside the frame, unwritten bytes stay zero and the digest covers them.
    write.apply(&mut load_frame_buffer_mut(program_id, buffer)?)?;
    Ok(())
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
        // 1. Every signer signed the digest, the message holds no other trace of the frame. A rewrite
        // after signing fails here.
        if frame_digest(frame)? != *digest {
            return Err(CustomRingError::FrameDigestMismatch.into());
        }
        let (&frame_tag, body) = frame.split_first().ok_or(CustomRingError::FrameLength)?;
        let transfer_tag = match frame_tag {
            tag::TRANSFER => InstructionTag::Transfer,
            tag::AUTHORITY_TRANSFER => InstructionTag::AuthorityTransfer,
            _ => return Err(CustomRingError::UnsupportedBufferedTag.into()),
        };
        // 2. The closed buffer leaves readers the event, valid once the transaction succeeds. The account
        // is gone and the data holds only the digest, so the inner instruction is the one record of the frame.
        invoke::<1, _>(
            &InstructionView {
                program_id,
                accounts: &[],
                data: frame_buffer.event_data(),
            },
            &[&*program],
        )?;
        // 3. The frame runs as an inline transfer, and the SPP payer must be the writer.
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
    // 4. The rent returns to the writer, step 3 held the payer to it.
    close_into(buffer, payer, CustomRingError::InvalidFrameBuffer)
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
