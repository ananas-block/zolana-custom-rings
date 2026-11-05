//! Owner signatures authorize reader grants within one ring program namespace.
//!
//! Read after `program-libs/interface/src/instructions/storage.rs`.
//! Read before `programs/storage/src/instructions/owner_grant.rs`.

use bytemuck::{Pod, Zeroable};
use solana_address::Address;

use crate::{
    storage::StorageError, storage_instruction::OwnerGrantIxData, ReaderKeyBytes,
    READER_KEY_ED25519, READER_KEY_P256, STORAGE_PROGRAM_ID,
};

/// A program owner's on-chain consent to one reader, a PDA cannot sign off chain, the address names both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct OwnerGrant {
    pub discriminator: u8,
    /// Zero revokes.
    pub active: u8,
}

impl OwnerGrant {
    pub const DISCRIMINATOR: u8 = 5;
    pub const SEED: &'static [u8] = b"owner_grant";
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Ring program, owner and complete reader encoding bind the grant namespace.
    pub fn seeds<'a>(
        ring_program: &'a Address,
        owner: &'a Address,
        reader: &'a ReaderKeyBytes,
    ) -> [&'a [u8]; 5] {
        let (scheme, key) = reader.split_at(2);
        [
            Self::SEED,
            ring_program.as_ref(),
            owner.as_ref(),
            scheme,
            key,
        ]
    }

    pub fn find_address(
        ring_program: &Address,
        owner: &Address,
        reader: &ReaderKeyBytes,
    ) -> (Address, u8) {
        Address::find_program_address(
            &Self::seeds(ring_program, owner, reader),
            &STORAGE_PROGRAM_ID,
        )
    }

    pub fn from_data(data: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes::<Self>(data)
            .ok()
            .filter(|account| account.discriminator == Self::DISCRIMINATOR)
    }

    pub fn from_data_mut(data: &mut [u8]) -> Option<&mut Self> {
        bytemuck::try_from_bytes_mut::<Self>(data)
            .ok()
            .filter(|account| account.discriminator == Self::DISCRIMINATOR)
    }

    pub fn decode(owner: &Address, data: &[u8]) -> Option<Self> {
        (*owner == STORAGE_PROGRAM_ID)
            .then(|| Self::from_data(data).copied())
            .flatten()
    }

    pub const fn is_active(&self) -> bool {
        self.active == 1
    }
}

impl OwnerGrantIxData {
    pub fn check(&self) -> Result<(), StorageError> {
        if !matches!(self.reader[0], READER_KEY_ED25519 | READER_KEY_P256) {
            return Err(StorageError::InvalidReaderKey);
        }
        if self.active > 1 {
            return Err(StorageError::InvalidInstructionData);
        }
        Ok(())
    }
}

const _: () = assert!(core::mem::align_of::<OwnerGrant>() == 1);
const _: () = assert!(OwnerGrant::SIZE == 2);
