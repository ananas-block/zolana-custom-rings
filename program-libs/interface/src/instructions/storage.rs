use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spr_hasher::primitives::solana_owner_identity;
use zolana_ring_policy::ListSet;

use crate::{
    error::CustomRingError,
    instruction::{list_and_mint_entry, mint_policy_write, write_count},
    member_registry::{AuthorizedAddress, EscrowKey, QueueEntry},
    storage::{RegistryId, Revision, StorageError},
    ApplyRecordsIxData, CustomRingProof, ReaderKeyBytes, RecordWriteData,
    REGISTER_KEY_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};

pub mod tag {
    pub const INITIALIZE: u8 = 0;
    pub const UPDATE: u8 = 1;
    pub const UPDATE_IMMEDIATE: u8 = 2;
    // 3 retired.
    /// No data, the authority and the new authority both sign.
    pub const UPDATE_AUTHORITY: u8 = 4;
    pub const ENROLL_ADDRESS: u8 = 5;
    pub const ENROLL: u8 = 6;
    /// Permissionless, the applier names the authorization accounts.
    pub const APPLY_ENROLLMENTS: u8 = 7;
    pub const OWNER_GRANT: u8 = 8;
    /// The ring program signs its ring PDA as creator through CPI.
    pub const INITIALIZE_TRACKING: u8 = 9;
}

/// The first byte of each write in an update.
pub mod write_kind {
    pub const RECORD: u8 = 0;
    pub const ESCROW: u8 = 1;
    pub const ADDRESS: u8 = 2;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateMode {
    /// The outgoing root stays readable for the grace period.
    Graced,
    /// Every earlier root stops verifying.
    Immediate,
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
}

/// Encoded as its `write_kind` byte and body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageWriteData {
    Record(RecordWriteData),
    Escrow(EscrowWriteData),
    Address(AddressWriteData),
}

/// The leaf binds every field except `eph_u`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct EscrowWriteData {
    /// Its owner identity is the leaf member.
    pub owner: Address,
    pub nullifier_pk: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

/// Tag 5, the owner's signature is the only authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct EnrollAddressIxData {
    /// Fixed after the first enrollment.
    pub nullifier_pk: [u8; 32],
    /// Canonical and nonzero.
    pub viewing_u: [u8; 32],
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

/// Names an enrollment, the address comes from the owner's authorization account and never from data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct AddressWriteData {
    pub owner: Address,
    /// Little endian, the revision the authorization holds.
    pub address_revision: [u8; 8],
}

/// Tags 1 and 2, `revision || count u8 || count writes || ApplyRecordsIxData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageUpdateIxData<'a> {
    pub revision: Revision,
    pub writes: Vec<StorageWriteData>,
    pub apply: &'a ApplyRecordsIxData,
}

impl UpdateMode {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Graced => tag::UPDATE,
            Self::Immediate => tag::UPDATE_IMMEDIATE,
        }
    }
}

impl InitializeIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub const fn grace_slots(&self) -> u64 {
        u64::from_le_bytes(self.grace_slots)
    }
}

impl EnrollAddressIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();
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

impl AddressWriteData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub const fn address_revision(&self) -> u64 {
        u64::from_le_bytes(self.address_revision)
    }

    pub fn member(&self) -> Result<[u8; 32], CustomRingError> {
        Ok(solana_owner_identity(self.owner.as_array())?)
    }

    /// The leaf write of `address`, the owner's authorized address at the named revision.
    pub fn entry(&self, address: &AuthorizedAddress) -> Result<QueueEntry, CustomRingError> {
        if address.address_revision != self.address_revision() {
            return Err(CustomRingError::AddressRevisionMismatch);
        }
        let member = self.member()?;
        QueueEntry::address(member, address.hash(&member)?)
    }
}

impl StorageWriteData {
    /// The leaf write the apply proof hashes, an address write reads its hash from the owner's
    /// authorization through [`AddressWriteData::entry`].
    pub fn entry(&self) -> Result<QueueEntry, CustomRingError> {
        match self {
            Self::Record(write) => list_and_mint_entry(
                write.member,
                &write.lists,
                &write.mint_policy,
                ListSet::STORAGE_WRITES,
            ),
            // The leaf binds the published envelope and no other key.
            Self::Escrow(write) => QueueEntry::escrow(write.member()?, &write.key()),
            Self::Address(_) => Err(CustomRingError::AddressWriteNeedsAuthorization),
        }
    }

    pub fn member(&self) -> Result<[u8; 32], CustomRingError> {
        match self {
            Self::Record(write) => Ok(write.member),
            Self::Escrow(write) => write.member(),
            Self::Address(write) => write.member(),
        }
    }

    pub fn encode_all(writes: &[Self]) -> Vec<u8> {
        let mut out = Vec::new();
        for write in writes {
            write.encode_into(&mut out);
        }
        out
    }

    /// Refuses a mint settings tag above 1 and nonzero settings under tag 0.
    pub fn parse_all(mut data: &[u8]) -> Result<Vec<Self>, CustomRingError> {
        let mut writes = Vec::new();
        while !data.is_empty() {
            let (write, rest) = Self::split(data)?;
            if let Self::Record(RecordWriteData { mint_policy, .. }) = &write {
                if mint_policy[0] != 1 && *mint_policy != mint_policy_write(None) {
                    return Err(CustomRingError::InvalidInstructionData);
                }
            }
            writes.push(write);
            data = rest;
        }
        Ok(writes)
    }

    fn split(data: &[u8]) -> Result<(Self, &[u8]), CustomRingError> {
        let (kind, rest) = data
            .split_first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        match *kind {
            write_kind::RECORD => leading(rest).map(|(write, rest)| (Self::Record(write), rest)),
            write_kind::ESCROW => leading(rest).map(|(write, rest)| (Self::Escrow(write), rest)),
            write_kind::ADDRESS => leading(rest).map(|(write, rest)| (Self::Address(write), rest)),
            _ => Err(CustomRingError::InvalidInstructionData),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        let (kind, body) = match self {
            Self::Record(write) => (write_kind::RECORD, bytemuck::bytes_of(write)),
            Self::Escrow(write) => (write_kind::ESCROW, bytemuck::bytes_of(write)),
            Self::Address(write) => (write_kind::ADDRESS, bytemuck::bytes_of(write)),
        };
        out.push(kind);
        out.extend_from_slice(body);
    }
}

impl EscrowWriteData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn member(&self) -> Result<[u8; 32], CustomRingError> {
        Ok(solana_owner_identity(self.owner.as_array())?)
    }

    pub fn key(&self) -> EscrowKey<'_> {
        EscrowKey {
            nullifier_pk: &self.nullifier_pk,
            ciphertext: &self.ciphertext,
        }
    }
}

impl<'a> StorageUpdateIxData<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, StorageError> {
        let (revision, data) = data
            .split_first_chunk::<8>()
            .ok_or(StorageError::InvalidInstructionData)?;
        let (count, mut rest) = data
            .split_first()
            .ok_or(StorageError::InvalidInstructionData)?;
        let count = storage_write_count(usize::from(*count))?;
        let mut writes = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let (write, tail) =
                StorageWriteData::split(rest).map_err(|_| StorageError::InvalidInstructionData)?;
            writes.push(write);
            rest = tail;
        }
        Ok(Self {
            revision: Revision(*revision),
            writes,
            apply: ApplyRecordsIxData::parse(rest)
                .map_err(|_| StorageError::InvalidInstructionData)?,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let count = storage_write_count(self.writes.len())?;
        Ok([
            &self.revision.0[..],
            &[count],
            &StorageWriteData::encode_all(&self.writes),
            bytemuck::bytes_of(self.apply),
        ]
        .concat())
    }
}

fn storage_write_count(count: usize) -> Result<u8, StorageError> {
    write_count(count).map_err(|error| match error {
        CustomRingError::AuthorityBatchTooLarge => StorageError::BatchTooLarge,
        _ => StorageError::InvalidInstructionData,
    })
}

fn leading<T: Pod>(data: &[u8]) -> Result<(T, &[u8]), CustomRingError> {
    let (body, rest) = data
        .split_at_checked(core::mem::size_of::<T>())
        .ok_or(CustomRingError::InvalidInstructionData)?;
    let value = bytemuck::try_pod_read_unaligned(body)
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    Ok((value, rest))
}

const _: () = assert!(core::mem::align_of::<InitializeIxData>() == 1);
const _: () = assert!(InitializeIxData::SIZE == 72);
const _: () = assert!(core::mem::align_of::<EscrowWriteData>() == 1);
const _: () = assert!(EscrowWriteData::SIZE == 128);
const _: () = assert!(core::mem::align_of::<EnrollAddressIxData>() == 1);
const _: () = assert!(EnrollAddressIxData::SIZE == 64);
const _: () = assert!(core::mem::align_of::<InitializeTrackingIxData>() == 1);
const _: () = assert!(InitializeTrackingIxData::SIZE == 65);
const _: () = assert!(core::mem::align_of::<EnrollIxData>() == 1);
const _: () = assert!(EnrollIxData::SIZE == 160);
const _: () = assert!(core::mem::align_of::<ApplyEnrollmentsIxData>() == 1);
const _: () = assert!(ApplyEnrollmentsIxData::SIZE == 236);
const _: () = assert!(core::mem::align_of::<OwnerGrantIxData>() == 1);
const _: () = assert!(OwnerGrantIxData::SIZE == 35);
const _: () = assert!(core::mem::align_of::<AddressWriteData>() == 1);
const _: () = assert!(AddressWriteData::SIZE == 40);
