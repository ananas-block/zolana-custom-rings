use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spr_hasher::{Hasher, Sha256};

use crate::{bytes::Bytes, error::CustomRingError, tag, FRAME_BUFFER};

pub const FRAME_BUFFER_PDA_SEED: &[u8] = b"frame_buffer";
pub const FRAME_BUFFER_HEADER_LEN: usize = core::mem::size_of::<FrameBufferHeader>();
/// The runtime's ceiling on an inner create and on CPI instruction data.
pub const MAX_CPI_DATA_LEN: usize = 10 * 1024;
pub const MAX_FRAME_LEN: usize = MAX_CPI_DATA_LEN - FRAME_BUFFER_HEADER_LEN;

const _: () = assert!(core::mem::align_of::<FrameBufferHeader>() == 1);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct FrameBufferHeader {
    discriminator: u8,
    pub writer: Address,
    /// Sits against the frame, the event needs no heap copy.
    event_tag: u8,
}

impl FrameBufferHeader {
    pub fn new(writer: Address) -> Self {
        Self {
            discriminator: FRAME_BUFFER,
            writer,
            event_tag: tag::FRAME_EVENT,
        }
    }
}

/// The frame keeps its inline tag.
pub struct FrameBuffer<'a> {
    pub header: &'a FrameBufferHeader,
    event: &'a [u8],
}

impl<'a> FrameBuffer<'a> {
    pub fn of(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let head = data
            .get(..FRAME_BUFFER_HEADER_LEN)
            .ok_or(CustomRingError::InvalidFrameBuffer)?;
        let header: &FrameBufferHeader = bytemuck::from_bytes(head);
        if header.discriminator != FRAME_BUFFER {
            return Err(CustomRingError::InvalidFrameBuffer);
        }
        Ok(Self {
            header,
            event: &data[FRAME_BUFFER_HEADER_LEN - 1..],
        })
    }

    pub fn frame(&self) -> &'a [u8] {
        &self.event[1..]
    }

    /// `tag || frame`.
    pub const fn event_data(&self) -> &'a [u8] {
        self.event
    }

    pub fn check_writer(&self, writer: &Address) -> Result<(), CustomRingError> {
        match self.header.writer == *writer {
            true => Ok(()),
            false => Err(CustomRingError::UnauthorizedFrameWriter),
        }
    }
}

pub fn frame_digest(frame: &[u8]) -> Result<[u8; 32], CustomRingError> {
    Sha256::hash(frame).map_err(CustomRingError::from)
}

/// The first write creates the buffer at `[seed, writer, nonce]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteFrameIxData<'a> {
    pub nonce: u64,
    /// Read when the write creates the buffer.
    pub frame_len: u16,
    pub offset: u16,
    pub bytes: &'a [u8],
}

impl<'a> WriteFrameIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidInstructionData);
        Ok(Self {
            nonce: u64::from_le_bytes(*bytes.array()?),
            frame_len: bytes.u16()?,
            offset: bytes.u16()?,
            bytes: bytes.rest(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        [
            &[tag::WRITE_FRAME][..],
            &self.nonce.to_le_bytes(),
            &self.frame_len.to_le_bytes(),
            &self.offset.to_le_bytes(),
            self.bytes,
        ]
        .concat()
    }

    /// Unwritten bytes stay zero, the digest covers them.
    pub fn apply(&self, account: &mut [u8]) -> Result<(), CustomRingError> {
        let start = FRAME_BUFFER_HEADER_LEN + usize::from(self.offset);
        account
            .get_mut(start..start + self.bytes.len())
            .ok_or(CustomRingError::FrameWriteOutOfRange)?
            .copy_from_slice(self.bytes);
        Ok(())
    }

    pub const fn checked_frame_len(&self) -> Result<usize, CustomRingError> {
        let len = self.frame_len as usize;
        match len >= 1 && len <= MAX_FRAME_LEN {
            true => Ok(len),
            false => Err(CustomRingError::FrameLength),
        }
    }
}

/// Every signer of the message signs the digest.
pub fn settle_buffered_data(digest: &[u8; 32]) -> Vec<u8> {
    [&[tag::SETTLE_BUFFERED][..], digest].concat()
}

/// The caller takes `event` from the inner instructions of `settle`.
#[must_use]
pub struct SettledFrame<'a> {
    pub ring_program: &'a Address,
    pub settle_program: &'a Address,
    pub event_program: &'a Address,
    pub succeeded: bool,
    pub settle: &'a [u8],
    pub event: &'a [u8],
}

impl<'a> SettledFrame<'a> {
    pub fn frame(self) -> Result<&'a [u8], CustomRingError> {
        let invalid = CustomRingError::InvalidInstructionData;
        if !self.succeeded
            || self.settle_program != self.ring_program
            || self.event_program != self.ring_program
        {
            return Err(invalid);
        }
        let (&settle_tag, digest) = self.settle.split_first().ok_or(invalid)?;
        let (&event_tag, frame) = self.event.split_first().ok_or(invalid)?;
        if settle_tag != tag::SETTLE_BUFFERED || event_tag != tag::FRAME_EVENT {
            return Err(invalid);
        }
        if digest != frame_digest(frame)? {
            return Err(CustomRingError::FrameDigestMismatch);
        }
        Ok(frame)
    }
}
