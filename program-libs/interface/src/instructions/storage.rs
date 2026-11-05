//! The storage program's tags, instruction data and write classification.
//!
//! The apply proof, and no authority label, decides whether an update retires the older roots. The
//! instruction carries the restrictive bit and the statement binds it, so a label the writes do not
//! prove fails verification. Private masks require credential proofs unless a mint preimage
//! authenticates an asset key at the same write position.
//!
//! Read after `program-libs/interface/src/accounts/storage.rs`, `program-libs/interface/src/accounts/owner_grant.rs`.
//! Read before `programs/storage/src/instructions/update.rs`.

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_ring_policy::{ListSet, Member};

use crate::{
    ApplyRecordsIxData, CredentialRead, ReaderKeyBytes, RecordWriteData,
    error::CustomRingError,
    instruction::{list_and_mint_entry, write_count},
    key_catalog::apply_width,
    member_registry::RecordWrite,
    storage::{RegistryId, Revision, StorageError},
};

pub mod tag {
    pub const INITIALIZE: u8 = 0;
    pub const UPDATE: u8 = 1;
    /// No data, the authority and the new authority both sign.
    pub const UPDATE_AUTHORITY: u8 = 4;
    pub const OWNER_GRANT: u8 = 8;
}

/// The creator signs and becomes the authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct InitializeIxData {
    pub registry_id: RegistryId,
    /// Little endian.
    pub grace_slots: [u8; 8],
    /// `ring_id_field` of the ring it serves, immutable, zero serves as a curator only.
    pub ring_id: [u8; 32],
    /// Nonzero binds salted writes to the ring credential namespace, immutable.
    pub private_ring_id: [u8; 32],
}

/// The owner signature authorizes a grant in the named ring program namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct OwnerGrantIxData {
    pub ring_program: Address,
    pub reader: ReaderKeyBytes,
    /// One grants, zero revokes.
    pub active: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct AssetWrite {
    pub write_index: u8,
    pub mint: Address,
}

#[must_use]
pub struct RecordWriteClassification<'a, I> {
    pub entries: I,
    pub asset_writes: &'a [AssetWrite],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateWriteCheckpoint {
    pub ring_program: Address,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageUpdateIxData<'a> {
    pub revision: Revision,
    pub writes: Vec<RecordWriteData>,
    pub asset_writes: Vec<AssetWrite>,
    pub credential_read: CredentialRead,
    pub private_write: Option<PrivateWriteCheckpoint>,
    pub apply: &'a ApplyRecordsIxData,
}

impl InitializeIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub const fn grace_slots(&self) -> u64 {
        u64::from_le_bytes(self.grace_slots)
    }
}

impl OwnerGrantIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<I> RecordWriteClassification<'_, I>
where
    I: Iterator<Item = Result<RecordWrite, CustomRingError>>,
{
    pub fn credential_writes(self) -> Result<u16, StorageError> {
        let mut assets = self.asset_writes.iter().peekable();
        let mut credential_writes = 0u16;
        let mut count = 0;
        for (index, entry) in self.entries.enumerate() {
            // 1. The batch bound fixes the bitmap width, private masks require inclusion regardless of written values.
            count = index + 1;
            storage_write_count(count)?;
            let entry = entry.map_err(|_| StorageError::InvalidInstructionData)?;
            let private = entry.mask & ListSet::PRIVATE_LISTS.record_bits() != 0;
            // 2. Mint preimages exempt only their matching private positions in strictly ascending order.
            if let Some(asset) = assets
                .peek()
                .filter(|asset| usize::from(asset.write_index) <= index)
            {
                if usize::from(asset.write_index) != index
                    || !private
                    || Member::asset(&asset.mint)
                        .map_err(|_| StorageError::InvalidAssetWrite)?
                        .as_bytes()
                        != &entry.member
                {
                    return Err(StorageError::InvalidAssetWrite);
                }
                assets.next();
            } else if private {
                credential_writes |= 1u16 << index;
            }
        }
        // 3. Empty batches and asset positions outside the consumed writes have no valid statement.
        storage_write_count(count)?;
        if assets.next().is_some() {
            return Err(StorageError::InvalidAssetWrite);
        }
        Ok(credential_writes)
    }
}

impl<'a> StorageUpdateIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, StorageError> {
        // 1. The bounded write count fixes every record boundary before optional proof metadata.
        let (revision, data) = data
            .split_first_chunk::<8>()
            .ok_or(StorageError::InvalidInstructionData)?;
        let (count, rest) = data
            .split_first()
            .ok_or(StorageError::InvalidInstructionData)?;
        let count = usize::from(storage_write_count(usize::from(*count))?);
        let (writes, rest) = rest
            .split_at_checked(count * core::mem::size_of::<RecordWriteData>())
            .ok_or(StorageError::InvalidInstructionData)?;
        // 2. Asset preimages name write positions, their hashes and ordering are checked with the derived bitmap.
        let (asset_count, rest) = rest
            .split_first()
            .ok_or(StorageError::InvalidInstructionData)?;
        if usize::from(*asset_count) > count {
            return Err(StorageError::InvalidAssetWrite);
        }
        let (assets, mut rest) = rest
            .split_at_checked(usize::from(*asset_count) * core::mem::size_of::<AssetWrite>())
            .ok_or(StorageError::InvalidInstructionData)?;
        let credential_read =
            CredentialRead::decode(&mut rest).map_err(|_| StorageError::InvalidCredentialRead)?;
        let private_write = if credential_read.state_root_indexes().is_empty() {
            None
        } else {
            let (program, remaining) = rest
                .split_first_chunk::<32>()
                .ok_or(StorageError::InvalidInstructionData)?;
            let (sequence, remaining) = remaining
                .split_first_chunk::<8>()
                .ok_or(StorageError::InvalidInstructionData)?;
            rest = remaining;
            Some(PrivateWriteCheckpoint {
                ring_program: Address::new_from_array(*program),
                sequence: u64::from_le_bytes(*sequence),
            })
        };
        let apply =
            ApplyRecordsIxData::parse(rest).map_err(|_| StorageError::InvalidInstructionData)?;
        // 3. The restrictive bit has one encoding, the statement binds it.
        if apply.restrictive > 1 {
            return Err(StorageError::InvalidInstructionData);
        }
        let ix = Self {
            revision: Revision(*revision),
            writes: writes
                .as_chunks::<{ core::mem::size_of::<RecordWriteData>() }>()
                .0
                .iter()
                .map(|bytes| bytemuck::pod_read_unaligned(bytes))
                .collect(),
            asset_writes: assets
                .as_chunks::<{ core::mem::size_of::<AssetWrite>() }>()
                .0
                .iter()
                .map(|bytes| bytemuck::pod_read_unaligned(bytes))
                .collect(),
            credential_read,
            private_write,
            apply,
        };
        // 4. The authenticated write classes decide whether the selected credential roots are required or forbidden.
        ix.check_credential_read()?;
        Ok(ix)
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let count = storage_write_count(self.writes.len())?;
        self.check_credential_read()?;
        let asset_count =
            u8::try_from(self.asset_writes.len()).map_err(|_| StorageError::InvalidAssetWrite)?;
        let mut data = Vec::new();
        data.extend_from_slice(&self.revision.0);
        data.push(count);
        data.extend_from_slice(bytemuck::cast_slice(&self.writes));
        data.push(asset_count);
        data.extend_from_slice(bytemuck::cast_slice(&self.asset_writes));
        self.credential_read.encode_into(&mut data);
        if let Some(checkpoint) = self.private_write {
            data.extend_from_slice(checkpoint.ring_program.as_array());
            data.extend_from_slice(&checkpoint.sequence.to_le_bytes());
        }
        data.extend_from_slice(bytemuck::bytes_of(self.apply));
        Ok(data)
    }

    pub fn credential_writes(&self) -> Result<u16, StorageError> {
        RecordWriteClassification {
            entries: self.entries(),
            asset_writes: &self.asset_writes,
        }
        .credential_writes()
    }

    /// The checkpoint declares the mode and the classified writes must agree, a private owner write never reaches a public key.
    pub fn check_credential_read(&self) -> Result<(), StorageError> {
        if self.credential_writes()? == 0 {
            self.credential_read
                .check_empty()
                .map_err(|_| StorageError::InvalidCredentialRead)?;
            if self.private_write.is_some() {
                return Err(StorageError::InvalidCredentialRead);
            }
        } else {
            self.credential_read
                .check_capacity(usize::from(apply_width(self.writes.len() as u64)))
                .map_err(|_| StorageError::InvalidCredentialRead)?;
            if self.private_write.is_none() {
                return Err(StorageError::InvalidCredentialRead);
            }
        }
        Ok(())
    }

    /// The leaf writes the apply proof hashes, a mint settings tag above 1 refused.
    pub fn entries(&self) -> impl Iterator<Item = Result<RecordWrite, CustomRingError>> + '_ {
        self.writes.iter().map(RecordWriteData::storage_entry)
    }
}

impl RecordWriteData {
    /// The authority's write, the storage program takes no other.
    pub fn storage_entry(&self) -> Result<RecordWrite, CustomRingError> {
        list_and_mint_entry(
            self.member,
            &self.lists,
            &self.mint_policy,
            ListSet::STORAGE_WRITES,
        )
    }
}

fn storage_write_count(count: usize) -> Result<u8, StorageError> {
    write_count(count).map_err(|error| match error {
        CustomRingError::AuthorityBatchTooLarge => StorageError::BatchTooLarge,
        _ => StorageError::InvalidInstructionData,
    })
}

const _: () = assert!(core::mem::align_of::<AssetWrite>() == 1);
const _: () = assert!(core::mem::size_of::<AssetWrite>() == 33);
const _: () = assert!(core::mem::align_of::<InitializeIxData>() == 1);
const _: () = assert!(InitializeIxData::SIZE == 104);
const _: () = assert!(core::mem::align_of::<OwnerGrantIxData>() == 1);
const _: () = assert!(OwnerGrantIxData::SIZE == 67);
