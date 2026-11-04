use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use zolana_ring_policy::ListSet;

use crate::{
    error::CustomRingError,
    instruction::{list_and_mint_entry, write_count},
    member_registry::QueueEntry,
    private_list::{ListPosition, PublishedListWrite},
    storage::{RegistryId, Revision, StorageError},
    ApplyRecordsIxData, CustomRingProof, ReaderKeyBytes, RecordWriteData,
    REGISTER_KEY_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};

pub mod tag {
    pub const INITIALIZE: u8 = 0;
    pub const UPDATE: u8 = 1;
    // 2, 3 and 5 retired.
    /// No data, the authority and the new authority both sign.
    pub const UPDATE_AUTHORITY: u8 = 4;
    pub const ENROLL: u8 = 6;
    /// Permissionless, the applier names the authorization accounts.
    pub const APPLY_ENROLLMENTS: u8 = 7;
    pub const OWNER_GRANT: u8 = 8;
    /// The ring program signs its ring PDA as creator through CPI.
    pub const INITIALIZE_TRACKING: u8 = 9;
    /// Accounts `authority, registry, tracking_registry`, the registry a private source pairs with.
    pub const UPDATE_PRIVATE: u8 = 10;
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
    /// Nonzero creates a private source paired with this tracking registry.
    pub tracking_registry: Address,
}

/// One write of a private source, the program reads no list bit from it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PrivateListWriteData {
    pub position: [u8; 32],
    pub leaf: [u8; 32],
    /// Little endian.
    pub write_counter: [u8; 8],
}

/// The proof that applies a private source's writes, the sparse tree has no next index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ApplyPrivateListIxData {
    pub proof: CustomRingProof,
    pub new_root: [u8; 32],
}

/// Tag 10, `revision || restrictive u8 || count u8 || count writes || ApplyPrivateListIxData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateUpdateIxData<'a> {
    pub revision: Revision,
    /// The apply proof holds it, a false value fails verification.
    pub restrictive: bool,
    pub writes: Vec<PrivateListWriteData>,
    pub apply: &'a ApplyPrivateListIxData,
}

/// Tag 9, accounts `payer, creator, tracking_registry, system_program`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct InitializeTrackingIxData {
    /// `ring_id_field` of the ring program.
    pub ring_id: [u8; 32],
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
}

/// Tag 6 ahead of a first enrollment's proof, accounts `payer, owner, tracking_registry, authorization, system_program`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct EnrollIxData {
    /// Final after the first enrollment, with `list_tag`, `eph_u` and `ciphertext`.
    pub nullifier_pk: [u8; 32],
    pub list_tag: [u8; 32],
    /// Canonical and nonzero, the owner's signature alone authorizes it.
    pub viewing_u: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

/// Tag 6 data, a first enrollment holds the `RegisterKey` proof and a rotation none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollRequest<'a> {
    pub ix: &'a EnrollIxData,
    pub proof: Option<&'a CustomRingProof>,
}

/// Tag 7, accounts `tracking_registry` then one to `APPLY_BATCH` authorizations in chain order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct ApplyEnrollmentsIxData {
    pub revision: Revision,
    pub apply: ApplyRecordsIxData,
}

/// Tag 8, accounts `payer, owner, tracking_registry, grant, system_program`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct OwnerGrantIxData {
    pub reader: ReaderKeyBytes,
    /// One grants, zero revokes.
    pub active: u8,
}

/// Tag 1, `revision || restrictive u8 || count u8 || count writes || ApplyRecordsIxData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageUpdateIxData<'a> {
    pub revision: Revision,
    /// The apply proof holds it, a false value fails verification.
    pub restrictive: bool,
    pub writes: Vec<RecordWriteData>,
    pub apply: &'a ApplyRecordsIxData,
}

impl InitializeIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub const fn grace_slots(&self) -> u64 {
        u64::from_le_bytes(self.grace_slots)
    }
}

impl InitializeTrackingIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl EnrollIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> EnrollRequest<'a> {
    /// Exactly the fields, or the fields and one proof.
    pub fn parse(data: &'a [u8]) -> Result<Self, StorageError> {
        let (ix, proof) = data
            .split_at_checked(EnrollIxData::SIZE)
            .ok_or(StorageError::InvalidInstructionData)?;
        Ok(Self {
            ix: bytemuck::try_from_bytes(ix).map_err(|_| StorageError::InvalidInstructionData)?,
            proof: match proof.is_empty() {
                true => None,
                false => Some(
                    bytemuck::try_from_bytes(proof)
                        .map_err(|_| StorageError::InvalidInstructionData)?,
                ),
            },
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let proof = self.proof.map_or(&[][..], bytemuck::bytes_of);
        [bytemuck::bytes_of(self.ix), proof].concat()
    }
}

impl ApplyEnrollmentsIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// One account per chained entry, an apply key serves up to `APPLY_BATCH`.
    pub fn check_count(authorizations: usize) -> Result<(), StorageError> {
        match authorizations {
            0 => Err(StorageError::NoEnrollmentsNamed),
            count => storage_write_count(count).map(|_| ()),
        }
    }
}

impl OwnerGrantIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> StorageUpdateIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, StorageError> {
        let (header, writes, apply) = UpdateHeader::split::<RecordWriteData>(data)?;
        Ok(Self {
            revision: header.revision,
            restrictive: header.restrictive,
            writes,
            apply: ApplyRecordsIxData::parse(apply)
                .map_err(|_| StorageError::InvalidInstructionData)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        encode_update(
            UpdateHeader {
                revision: self.revision,
                restrictive: self.restrictive,
            },
            &self.writes,
            bytemuck::bytes_of(self.apply),
        )
    }

    /// The leaf writes the apply proof hashes, a mint settings tag above 1 refused.
    pub fn entries(&self) -> impl Iterator<Item = Result<QueueEntry, CustomRingError>> + '_ {
        self.writes.iter().map(RecordWriteData::storage_entry)
    }
}

impl RecordWriteData {
    /// The authority's write, the storage program takes no other.
    pub fn storage_entry(&self) -> Result<QueueEntry, CustomRingError> {
        list_and_mint_entry(
            self.member,
            &self.lists,
            &self.mint_policy,
            ListSet::STORAGE_WRITES,
        )
    }
}

impl PrivateListWriteData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn published(&self) -> PublishedListWrite {
        PublishedListWrite {
            position: ListPosition(self.position),
            leaf: self.leaf,
            write_counter: u64::from_le_bytes(self.write_counter),
        }
    }
}

impl From<PublishedListWrite> for PrivateListWriteData {
    fn from(write: PublishedListWrite) -> Self {
        Self {
            position: write.position.0,
            leaf: write.leaf,
            write_counter: write.write_counter.to_le_bytes(),
        }
    }
}

impl ApplyPrivateListIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl<'a> PrivateUpdateIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, StorageError> {
        let (header, writes, apply) = UpdateHeader::split::<PrivateListWriteData>(data)?;
        Ok(Self {
            revision: header.revision,
            restrictive: header.restrictive,
            writes,
            apply: bytemuck::try_from_bytes(apply)
                .map_err(|_| StorageError::InvalidInstructionData)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        encode_update(
            UpdateHeader {
                revision: self.revision,
                restrictive: self.restrictive,
            },
            &self.writes,
            bytemuck::bytes_of(self.apply),
        )
    }
}

/// `revision || restrictive u8 || count u8`, ahead of the writes of tags 1 and 10.
struct UpdateHeader {
    revision: Revision,
    restrictive: bool,
}

impl UpdateHeader {
    fn split<W: Pod>(data: &[u8]) -> Result<(Self, Vec<W>, &[u8]), StorageError> {
        let (revision, data) = data
            .split_first_chunk::<8>()
            .ok_or(StorageError::InvalidInstructionData)?;
        let ([restrictive, count], rest) = data
            .split_first_chunk::<2>()
            .ok_or(StorageError::InvalidInstructionData)?;
        let restrictive = match *restrictive {
            0 => false,
            1 => true,
            _ => return Err(StorageError::InvalidInstructionData),
        };
        let count = usize::from(storage_write_count(usize::from(*count))?);
        let (writes, apply) = rest
            .split_at_checked(count * core::mem::size_of::<W>())
            .ok_or(StorageError::InvalidInstructionData)?;
        let writes = writes
            .chunks(core::mem::size_of::<W>())
            .map(bytemuck::pod_read_unaligned)
            .collect();
        Ok((
            Self {
                revision: Revision(*revision),
                restrictive,
            },
            writes,
            apply,
        ))
    }
}

fn encode_update<W: Pod>(
    header: UpdateHeader,
    writes: &[W],
    apply: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let count = storage_write_count(writes.len())?;
    Ok([
        &header.revision.0[..],
        &[u8::from(header.restrictive), count],
        bytemuck::cast_slice(writes),
        apply,
    ]
    .concat())
}

fn storage_write_count(count: usize) -> Result<u8, StorageError> {
    write_count(count).map_err(|error| match error {
        CustomRingError::AuthorityBatchTooLarge => StorageError::BatchTooLarge,
        _ => StorageError::InvalidInstructionData,
    })
}

const _: () = assert!(core::mem::align_of::<InitializeIxData>() == 1);
const _: () = assert!(InitializeIxData::SIZE == 104);
const _: () = assert!(core::mem::align_of::<PrivateListWriteData>() == 1);
const _: () = assert!(PrivateListWriteData::SIZE == 72);
const _: () = assert!(core::mem::align_of::<ApplyPrivateListIxData>() == 1);
const _: () = assert!(ApplyPrivateListIxData::SIZE == 224);
const _: () = assert!(core::mem::align_of::<InitializeTrackingIxData>() == 1);
const _: () = assert!(InitializeTrackingIxData::SIZE == 65);
const _: () = assert!(core::mem::align_of::<EnrollIxData>() == 1);
const _: () = assert!(EnrollIxData::SIZE == 160);
const _: () = assert!(core::mem::align_of::<ApplyEnrollmentsIxData>() == 1);
const _: () = assert!(ApplyEnrollmentsIxData::SIZE == 236);
const _: () = assert!(core::mem::align_of::<OwnerGrantIxData>() == 1);
const _: () = assert!(OwnerGrantIxData::SIZE == 35);
