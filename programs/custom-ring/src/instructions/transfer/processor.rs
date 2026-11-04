use custom_ring_interface::{
    CustomRingError, InstructionTag, RailSigner, RingTransactData, TRANSACT_PAYER_INDEX,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};

use super::{accounts::TransactCheck, verify::RingStatements};
use crate::instructions::loader::{load_policy, validate_spp_program};

#[inline(never)]
pub fn process_transfer_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    tag: InstructionTag,
) -> ProgramResult {
    TransferRun {
        program_id,
        accounts,
        data,
        tag,
        writer: None,
    }
    .run()
    .map(|_| ())
}

#[must_use]
pub struct TransferRun<'a> {
    pub program_id: &'a Address,
    pub accounts: &'a [AccountView],
    pub data: &'a [u8],
    pub tag: InstructionTag,
    /// A buffered frame's writer, the SPP payer must be it.
    pub writer: Option<&'a Address>,
}

impl TransferRun<'_> {
    /// Returns where the SPP accounts start.
    #[inline(never)]
    pub fn run(self) -> Result<usize, ProgramError> {
        let Self {
            program_id,
            accounts,
            data,
            tag,
            writer,
        } = self;
        let slot = Clock::get()?.slot;
        // 1. The ring's mode and delegate fix the rail and the signer it trusts.
        let ring = load_policy(
            program_id,
            accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?,
        )?;
        let signer = RailSigner::new(tag, &ring)?;
        // 2. Every length follows from the flags and the shape, trailing bytes refused.
        let transfer = RingTransactData::parse(data, signer.rail())?;
        let data = transfer.data();
        // 3. Each account sits in the slot the statements and SPP read it from.
        let validated = TransactCheck {
            program_id,
            ring: &ring,
            transfer: &transfer,
            signer,
            slot,
        }
        .validate(accounts)?;
        // The party check covers the payer, a hidden sender cannot be the writer.
        if let Some(writer) = writer {
            let payer = accounts
                .get(validated.spp + TRANSACT_PAYER_INDEX)
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            if payer.address() != writer {
                return Err(CustomRingError::FramePayerNotWriter.into());
            }
        }
        // 4. A bad SPP proof point is refused before either pairing.
        let spp_data = data.spp_instruction_data(&ring)?;
        // 5. The ring proof verifies the frame's approval mask and spend bit before the SPP call.
        RingStatements {
            program_id,
            ring: &ring,
            transfer: &transfer,
            accounts: &validated,
        }
        .verify()?;
        // 6. SPP verifies its own proof over the expanded data the ring PDA signs.
        let spp = accounts
            .get(validated.spp..)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        validate_spp_program(spp)?;
        validated.ring_auth.invoke(spp, &spp_data)?;
        Ok(validated.spp)
    }
}
