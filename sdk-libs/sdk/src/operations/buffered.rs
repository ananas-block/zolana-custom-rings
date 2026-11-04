//! A frame past one transaction settles from a buffer its writer fills, chunk by chunk.

use custom_ring_interface::{
    frame_digest, settle_buffered_data, tag, CustomRingError, InstructionTag, WriteFrameIxData,
    FRAME_BUFFER_PDA_SEED, MAX_FRAME_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1;
use solana_signer::Signer;
use spr_client::{compile_message, sign_transaction, transaction_size, AsyncRpc};

use crate::{
    address_ceiling::AddressCeilingError,
    submission::{send_and_settle, send_budget, SettledSubmission},
    RingError,
};

#[cfg(test)]
#[path = "../tests/operations/buffered.rs"]
mod tests;

const SYSTEM_PROGRAM: Address = Address::new_from_array([0; 32]);

/// One proven inline transfer as its buffered instructions, its payer the writer.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BufferedFrame {
    ring_program: Address,
    writer: Address,
    nonce: u64,
    buffer: Address,
    digest: [u8; 32],
    frame: Vec<u8>,
    inner: Vec<AccountMeta>,
}

impl BufferedFrame {
    /// `inline` is the transfer as it would send without a buffer.
    pub fn new(
        inline: &Instruction,
        writer: Address,
        nonce: u64,
    ) -> Result<Self, AddressCeilingError> {
        if inline.data.len() > MAX_FRAME_LEN {
            return Err(AddressCeilingError::FrameTooLarge {
                bytes: inline.data.len(),
                limit: MAX_FRAME_LEN,
            });
        }
        if inline.data.first() != Some(&tag::TRANSFER) {
            return Err(CustomRingError::UnsupportedBufferedTag.into());
        }
        let (buffer, _) = Address::find_program_address(
            &[FRAME_BUFFER_PDA_SEED, writer.as_ref(), &nonce.to_le_bytes()],
            &inline.program_id,
        );
        Ok(Self {
            ring_program: inline.program_id,
            writer,
            nonce,
            buffer,
            digest: frame_digest(&inline.data)?,
            frame: inline.data.clone(),
            inner: inline.accounts.clone(),
        })
    }

    pub const fn buffer(&self) -> Address {
        self.buffer
    }

    /// In offset order, the first creates the buffer at the frame's full length.
    pub fn writes(&self) -> Result<Vec<Instruction>, RingError> {
        let empty = transaction_size(&self.writer, &[self.write(0, &[])?], write_budget())?;
        let chunk = v1::MAX_TRANSACTION_SIZE.saturating_sub(empty.bytes).max(1);
        self.frame
            .chunks(chunk)
            .enumerate()
            .map(|(index, bytes)| self.write(index * chunk, bytes))
            .collect()
    }

    /// Every signer signs the frame's digest, the program closes the buffer into the writer.
    pub fn settle(&self) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(self.buffer, false),
            AccountMeta::new_readonly(self.ring_program, false),
        ];
        accounts.extend(self.inner.iter().cloned());
        Instruction {
            program_id: self.ring_program,
            accounts,
            data: settle_buffered_data(&self.digest),
        }
    }

    /// Abandons an unsettled buffer, its rent returns to the writer.
    pub fn close(&self) -> Instruction {
        Instruction {
            program_id: self.ring_program,
            accounts: vec![
                AccountMeta::new(self.writer, true),
                AccountMeta::new(self.buffer, false),
                AccountMeta::new(self.writer, true),
            ],
            data: vec![tag::CLOSE_FRAME_BUFFER],
        }
    }

    /// Writes every chunk, then settles, a failed settlement leaves the buffer to [`Self::close`].
    pub async fn send<R: AsyncRpc + ?Sized>(
        &self,
        client: &R,
        writer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<SettledSubmission, RingError> {
        for write in self.writes()? {
            match land(client, writer, &[], write, InstructionTag::WriteFrame).await? {
                settled @ SettledSubmission::Failed { .. } => return Ok(settled),
                SettledSubmission::Confirmed { .. } => {}
            }
        }
        let settle = self.settle();
        land(
            client,
            writer,
            signers,
            settle,
            InstructionTag::SettleBuffered,
        )
        .await
    }

    fn write(&self, offset: usize, bytes: &[u8]) -> Result<Instruction, RingError> {
        let narrow = |_| CustomRingError::FrameLength;
        Ok(Instruction {
            program_id: self.ring_program,
            accounts: vec![
                AccountMeta::new(self.writer, true),
                AccountMeta::new(self.buffer, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data: WriteFrameIxData {
                nonce: self.nonce,
                frame_len: u16::try_from(self.frame.len()).map_err(narrow)?,
                offset: u16::try_from(offset).map_err(narrow)?,
                bytes,
            }
            .encode(),
        })
    }
}

fn write_budget() -> spr_client::ComputeBudgetConfig {
    send_budget(InstructionTag::WriteFrame, None)
}

async fn land<R: AsyncRpc + ?Sized>(
    client: &R,
    writer: &(dyn Signer + Sync),
    signers: &[&(dyn Signer + Sync)],
    instruction: Instruction,
    tag: InstructionTag,
) -> Result<SettledSubmission, RingError> {
    let (blockhash, last_valid_block_height) = client.get_latest_blockhash().await?;
    let message = compile_message(
        &writer.pubkey(),
        &[instruction],
        blockhash,
        send_budget(tag, None),
    )?;
    let transaction = {
        let mut all: Vec<&dyn Signer> = vec![writer];
        all.extend(signers.iter().map(|signer| *signer as &dyn Signer));
        sign_transaction(message, &all)?
    };
    send_and_settle(client, &transaction, last_valid_block_height).await
}
