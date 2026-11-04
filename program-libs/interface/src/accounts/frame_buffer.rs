//! A frame too wide for one transaction, written to an account and settled by its digest.

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spr_hasher::{Hasher, Sha256};

use crate::{bytes::Bytes, error::CustomRingError, tag, InstructionTag};

// Discriminators 14 and 15 are `CoSigner` and `RingPolicy`.
pub const FRAME_BUFFER: u8 = 16;
pub const FRAME_BUFFER_PDA_SEED: &[u8] = b"frame_buffer";
pub const FRAME_BUFFER_HEADER_LEN: usize = core::mem::size_of::<FrameBufferHeader>();
/// A create through CPI grows an account by at most 10 KiB.
pub const MAX_FRAME_LEN: usize = 10 * 1024 - FRAME_BUFFER_HEADER_LEN;

const _: () = assert!(core::mem::align_of::<FrameBufferHeader>() == 1);

/// The account data is this header followed by exactly `length` frame bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct FrameBufferHeader {
    discriminator: u8,
    sealed: u8,
    length: [u8; 2],
    expiry_unix_ts: [u8; 4],
    pub writer: Address,
    pub rent_payer: Address,
    pub digest: [u8; 32],
    /// Directly ahead of the frame, the event reads its data in place.
    event_tag: u8,
}

impl FrameBufferHeader {
    pub fn new(ix: &CreateFrameBufferIxData, rent_payer: Address) -> Result<Self, CustomRingError> {
        if !(1..=MAX_FRAME_LEN).contains(&usize::from(ix.length)) {
            return Err(CustomRingError::FrameLength);
        }
        Ok(Self {
            discriminator: FRAME_BUFFER,
            sealed: 0,
            length: ix.length.to_le_bytes(),
            expiry_unix_ts: ix.expiry_unix_ts.to_le_bytes(),
            writer: ix.writer,
            rent_payer,
            digest: ix.digest,
            event_tag: tag::FRAME_EVENT,
        })
    }

    pub const fn sealed(&self) -> bool {
        self.sealed != 0
    }

    pub const fn length(&self) -> usize {
        u16::from_le_bytes(self.length) as usize
    }

    pub const fn expiry_unix_ts(&self) -> u32 {
        u32::from_le_bytes(self.expiry_unix_ts)
    }

    pub const fn expired(&self, now_unix_ts: i64) -> bool {
        now_unix_ts >= self.expiry_unix_ts() as i64
    }

    pub const fn account_len(&self) -> usize {
        FRAME_BUFFER_HEADER_LEN + self.length()
    }

    /// The writer closes at any time, anyone at or past expiry.
    pub fn check_close(
        &self,
        closer: &Address,
        closer_signed: bool,
        now_unix_ts: i64,
    ) -> Result<(), CustomRingError> {
        match self.expired(now_unix_ts) || (closer_signed && closer == &self.writer) {
            true => Ok(()),
            false => Err(CustomRingError::UnauthorizedFrameCloser),
        }
    }
}

/// An initialized buffer, read from its account data.
#[derive(Clone, Copy, Debug)]
pub struct FrameBuffer<'a> {
    pub header: &'a FrameBufferHeader,
    event: &'a [u8],
}

impl<'a> FrameBuffer<'a> {
    pub fn of(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let invalid = CustomRingError::InvalidFrameBuffer;
        let head = data.get(..FRAME_BUFFER_HEADER_LEN).ok_or(invalid)?;
        let header: &FrameBufferHeader = bytemuck::from_bytes(head);
        if header.discriminator != FRAME_BUFFER || data.len() != header.account_len() {
            return Err(invalid);
        }
        Ok(Self {
            header,
            event: &data[FRAME_BUFFER_HEADER_LEN - 1..],
        })
    }

    pub fn frame(&self) -> &'a [u8] {
        &self.event[1..]
    }

    /// The tag and the frame, the event's whole instruction data.
    pub const fn event_data(&self) -> &'a [u8] {
        self.event
    }

    /// Fails unless the buffer can settle the signed `settle` now.
    pub fn check_settlement(
        &self,
        settle: &SettleBufferedIxData<'_>,
        rent_payer: &Address,
        now_unix_ts: i64,
    ) -> Result<(), CustomRingError> {
        let header = self.header;
        if !header.sealed() {
            return Err(CustomRingError::FrameBufferNotSealed);
        }
        if header.expired(now_unix_ts) {
            return Err(CustomRingError::FrameBufferExpired);
        }
        if &header.digest != settle.digest {
            return Err(CustomRingError::FrameDigestMismatch);
        }
        if &header.rent_payer != rent_payer {
            return Err(CustomRingError::FrameRentPayer);
        }
        if self.frame().first() != Some(&settle.inner_tag) {
            return Err(CustomRingError::FrameTagMismatch);
        }
        Ok(())
    }

    /// The frame a co-signer parses, its bytes checked against the digest it signs.
    pub fn inspect(
        owner: &Address,
        program: &Address,
        data: &'a [u8],
        signed_digest: &[u8; 32],
    ) -> Result<&'a [u8], CustomRingError> {
        if owner != program {
            return Err(CustomRingError::InvalidFrameBuffer);
        }
        let buffer = Self::of(data)?;
        if !buffer.header.sealed() {
            return Err(CustomRingError::FrameBufferNotSealed);
        }
        if &frame_digest(buffer.frame())? != signed_digest {
            return Err(CustomRingError::FrameDigestMismatch);
        }
        Ok(buffer.frame())
    }
}

/// A buffer open for one write.
#[derive(Debug)]
pub struct FrameBufferWrite<'a> {
    header: &'a mut FrameBufferHeader,
    frame: &'a mut [u8],
}

impl<'a> FrameBufferWrite<'a> {
    pub fn of(data: &'a mut [u8]) -> Result<Self, CustomRingError> {
        let invalid = CustomRingError::InvalidFrameBuffer;
        FrameBuffer::of(data)?;
        let (head, frame) = data
            .split_at_mut_checked(FRAME_BUFFER_HEADER_LEN)
            .ok_or(invalid)?;
        Ok(Self {
            header: bytemuck::from_bytes_mut(head),
            frame,
        })
    }

    /// A sealed buffer never changes, so a co-signer's inspected bytes are the settled bytes.
    pub fn apply(
        self,
        writer: &Address,
        write: &WriteFrameIxData<'_>,
    ) -> Result<(), CustomRingError> {
        if writer != &self.header.writer {
            return Err(CustomRingError::UnauthorizedFrameWriter);
        }
        if self.header.sealed() {
            return Err(CustomRingError::FrameBufferSealed);
        }
        let start = usize::from(write.offset);
        start
            .checked_add(write.bytes.len())
            .and_then(|end| self.frame.get_mut(start..end))
            .ok_or(CustomRingError::FrameWriteOutOfRange)?
            .copy_from_slice(write.bytes);
        if write.seal {
            if frame_digest(self.frame)? != self.header.digest {
                return Err(CustomRingError::FrameDigestMismatch);
            }
            self.header.sealed = 1;
        }
        Ok(())
    }
}

pub fn frame_digest(frame: &[u8]) -> Result<[u8; 32], CustomRingError> {
    Sha256::hash(frame).map_err(|_| CustomRingError::HashingFailed)
}

/// The frame a settlement carried, from the data of its tag 61 and of the tag 63 it emitted.
pub fn settled_frame<'a>(settle: &[u8], event: &'a [u8]) -> Result<&'a [u8], CustomRingError> {
    let invalid = CustomRingError::InvalidFrameEvent;
    let (&settle_tag, settle) = settle.split_first().ok_or(invalid)?;
    let (&event_tag, frame) = event.split_first().ok_or(invalid)?;
    if settle_tag != tag::SETTLE_BUFFERED || event_tag != tag::FRAME_EVENT {
        return Err(invalid);
    }
    let settle = SettleBufferedIxData::parse(settle)?;
    if &frame_digest(frame)? != settle.digest || frame.first() != Some(&settle.inner_tag) {
        return Err(invalid);
    }
    Ok(frame)
}

/// Tag 62.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateFrameBufferIxData {
    pub nonce: u64,
    pub writer: Address,
    pub digest: [u8; 32],
    pub length: u16,
    pub expiry_unix_ts: u32,
}

impl CreateFrameBufferIxData {
    pub const LEN: usize = 8 + 32 + 32 + 2 + 4;

    pub fn parse(data: &[u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidInstructionData);
        let parsed = Self {
            nonce: u64::from_le_bytes(*bytes.array()?),
            writer: Address::new_from_array(*bytes.array()?),
            digest: *bytes.array()?,
            length: bytes.u16()?,
            expiry_unix_ts: bytes.u32()?,
        };
        finished(bytes)?;
        Ok(parsed)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(self.writer.as_array());
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(&self.expiry_unix_ts.to_le_bytes());
        out
    }
}

/// Tag 59.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteFrameIxData<'a> {
    pub offset: u16,
    pub seal: bool,
    pub bytes: &'a [u8],
}

impl<'a> WriteFrameIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidInstructionData);
        let offset = bytes.u16()?;
        let seal = match bytes.byte()? {
            0 => false,
            1 => true,
            _ => return Err(CustomRingError::InvalidInstructionData),
        };
        Ok(Self {
            offset,
            seal,
            bytes: bytes.rest(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.bytes.len());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.push(u8::from(self.seal));
        out.extend_from_slice(self.bytes);
        out
    }
}

/// Tag 61, the message owners and co-signers sign commits to the frame through `digest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleBufferedIxData<'a> {
    pub digest: &'a [u8; 32],
    pub buffer: &'a [u8; 32],
    pub inner_tag: u8,
}

impl<'a> SettleBufferedIxData<'a> {
    pub const LEN: usize = 32 + 32 + 1;

    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidInstructionData);
        let parsed = Self {
            digest: bytes.array()?,
            buffer: bytes.array()?,
            inner_tag: bytes.byte()?,
        };
        finished(bytes)?;
        Ok(parsed)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(self.digest);
        out.extend_from_slice(self.buffer);
        out.push(self.inner_tag);
        out
    }

    /// The tags a buffer settles, each read by its inline handler.
    pub fn inner(&self) -> Result<InstructionTag, CustomRingError> {
        match InstructionTag::try_from(self.inner_tag)? {
            tag @ (InstructionTag::Transfer
            | InstructionTag::AuthorityTransfer
            | InstructionTag::Merge
            | InstructionTag::Deposit) => Ok(tag),
            _ => Err(CustomRingError::UnsupportedBufferedTag),
        }
    }
}

fn finished(bytes: Bytes<'_>) -> Result<(), CustomRingError> {
    match bytes.rest().is_empty() {
        true => Ok(()),
        false => Err(CustomRingError::InvalidInstructionData),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRITER: Address = Address::new_from_array([1; 32]);
    const RENT_PAYER: Address = Address::new_from_array([2; 32]);
    const EXPIRY: u32 = 1_000;

    fn account(frame: &[u8]) -> Vec<u8> {
        let create = CreateFrameBufferIxData {
            nonce: 7,
            writer: WRITER,
            digest: frame_digest(frame).unwrap(),
            length: frame.len() as u16,
            expiry_unix_ts: EXPIRY,
        };
        let header = FrameBufferHeader::new(&create, RENT_PAYER).unwrap();
        let mut data = bytemuck::bytes_of(&header).to_vec();
        data.resize(header.account_len(), 0);
        data
    }

    fn write(
        data: &mut [u8],
        offset: u16,
        seal: bool,
        bytes: &[u8],
    ) -> Result<(), CustomRingError> {
        FrameBufferWrite::of(data)?.apply(
            &WRITER,
            &WriteFrameIxData {
                offset,
                seal,
                bytes,
            },
        )
    }

    #[test]
    fn frame_length_stays_within_one_create() {
        let create = |length| CreateFrameBufferIxData {
            nonce: 0,
            writer: WRITER,
            digest: [0; 32],
            length,
            expiry_unix_ts: EXPIRY,
        };
        let refused = Err(CustomRingError::FrameLength);
        assert_eq!(FrameBufferHeader::new(&create(0), RENT_PAYER), refused);
        assert_eq!(
            FrameBufferHeader::new(&create(MAX_FRAME_LEN as u16 + 1), RENT_PAYER),
            refused
        );
        let widest = FrameBufferHeader::new(&create(MAX_FRAME_LEN as u16), RENT_PAYER).unwrap();
        assert_eq!(widest.account_len(), 10 * 1024);
    }

    #[test]
    fn only_a_complete_frame_seals_and_a_sealed_frame_never_changes() {
        let frame = [tag::TRANSFER, 2, 3, 4];
        let mut data = account(&frame);
        assert_eq!(
            write(&mut data, 0, true, &frame[..2]),
            Err(CustomRingError::FrameDigestMismatch)
        );
        assert_eq!(
            write(&mut data, 3, false, &frame[..2]),
            Err(CustomRingError::FrameWriteOutOfRange)
        );
        write(&mut data, 0, false, &frame[..2]).unwrap();
        write(&mut data, 2, true, &frame[2..]).unwrap();
        assert_eq!(FrameBuffer::of(&data).unwrap().frame(), frame);
        assert_eq!(
            write(&mut data, 0, false, &frame),
            Err(CustomRingError::FrameBufferSealed)
        );
    }

    #[test]
    fn a_stranger_cannot_write() {
        let mut data = account(&[1]);
        let stranger = Address::new_from_array([3; 32]);
        let write = WriteFrameIxData {
            offset: 0,
            seal: true,
            bytes: &[1],
        };
        assert_eq!(
            FrameBufferWrite::of(&mut data)
                .unwrap()
                .apply(&stranger, &write),
            Err(CustomRingError::UnauthorizedFrameWriter)
        );
    }

    #[test]
    fn close_waits_for_the_writer_or_expiry() {
        let data = account(&[1]);
        let header = FrameBuffer::of(&data).unwrap().header;
        let stranger = Address::new_from_array([3; 32]);
        let before = i64::from(EXPIRY) - 1;
        let refused = Err(CustomRingError::UnauthorizedFrameCloser);
        assert_eq!(header.check_close(&stranger, true, before), refused);
        assert_eq!(header.check_close(&WRITER, false, before), refused);
        assert_eq!(header.check_close(&WRITER, true, before), Ok(()));
        assert_eq!(
            header.check_close(&stranger, false, i64::from(EXPIRY)),
            Ok(())
        );
    }

    #[test]
    fn settlement_checks_each_field() {
        let frame = [tag::TRANSFER, 9];
        let digest = frame_digest(&frame).unwrap();
        let buffer_address = [5; 32];
        let settle = SettleBufferedIxData {
            digest: &digest,
            buffer: &buffer_address,
            inner_tag: tag::TRANSFER,
        };
        let now = i64::from(EXPIRY) - 1;
        let mut data = account(&frame);
        assert_eq!(
            FrameBuffer::of(&data)
                .unwrap()
                .check_settlement(&settle, &RENT_PAYER, now),
            Err(CustomRingError::FrameBufferNotSealed)
        );
        write(&mut data, 0, true, &frame).unwrap();
        let buffer = FrameBuffer::of(&data).unwrap();
        buffer.check_settlement(&settle, &RENT_PAYER, now).unwrap();
        assert_eq!(
            buffer.check_settlement(&settle, &RENT_PAYER, i64::from(EXPIRY)),
            Err(CustomRingError::FrameBufferExpired)
        );
        assert_eq!(
            buffer.check_settlement(
                &SettleBufferedIxData {
                    digest: &[0; 32],
                    ..settle
                },
                &RENT_PAYER,
                now
            ),
            Err(CustomRingError::FrameDigestMismatch)
        );
        assert_eq!(
            buffer.check_settlement(&settle, &WRITER, now),
            Err(CustomRingError::FrameRentPayer)
        );
        assert_eq!(
            buffer.check_settlement(
                &SettleBufferedIxData {
                    inner_tag: tag::MERGE,
                    ..settle
                },
                &RENT_PAYER,
                now
            ),
            Err(CustomRingError::FrameTagMismatch)
        );
    }

    #[test]
    fn inspection_refuses_unsealed_changed_and_foreign_buffers() {
        let program = Address::new_from_array([8; 32]);
        let frame = [tag::TRANSFER, 9];
        let signed = frame_digest(&frame).unwrap();
        let mut data = account(&frame);
        assert_eq!(
            FrameBuffer::inspect(&program, &program, &data, &signed),
            Err(CustomRingError::FrameBufferNotSealed)
        );
        write(&mut data, 0, true, &frame).unwrap();
        assert_eq!(
            FrameBuffer::inspect(&program, &program, &data, &signed).unwrap(),
            frame
        );
        assert_eq!(
            FrameBuffer::inspect(&WRITER, &program, &data, &signed),
            Err(CustomRingError::InvalidFrameBuffer)
        );
        let other = frame_digest(&[tag::TRANSFER, 8]).unwrap();
        assert_eq!(
            FrameBuffer::inspect(&program, &program, &data, &other),
            Err(CustomRingError::FrameDigestMismatch)
        );
    }

    #[test]
    fn a_settled_frame_reads_from_its_event_alone() {
        let frame = [tag::TRANSFER, 9];
        let digest = frame_digest(&frame).unwrap();
        let settle = [
            &[tag::SETTLE_BUFFERED][..],
            &SettleBufferedIxData {
                digest: &digest,
                buffer: &[5; 32],
                inner_tag: tag::TRANSFER,
            }
            .encode(),
        ]
        .concat();
        let event = [tag::FRAME_EVENT, tag::TRANSFER, 9];
        assert_eq!(settled_frame(&settle, &event).unwrap(), frame);
        let invalid = Err(CustomRingError::InvalidFrameEvent);
        assert_eq!(
            settled_frame(&settle, &[tag::FRAME_EVENT, tag::TRANSFER, 8]),
            invalid
        );
        assert_eq!(
            settled_frame(&settle, &[tag::MERGE, tag::TRANSFER, 9]),
            invalid
        );
        assert_eq!(settled_frame(&event, &event), invalid);
    }
}
