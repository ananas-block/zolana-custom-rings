use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use solana_program_error::ProgramError;
use spr_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::right_align};
use thiserror::Error;
use zolana_ring_policy::registry_field;

use crate::{
    domain,
    member_registry::{MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT},
    state::ROOT_HISTORY,
    storage_instruction::{InitializeIxData, StorageUpdateIxData},
    STORAGE_PROGRAM_ID,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct Revision(pub [u8; 8]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct Root {
    pub hash: [u8; 32],
    pub revision: Revision,
    pub expires_at: [u8; 8],
}

/// Names one of a creator's registries in its address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct RegistryId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct StorageRegistry {
    pub discriminator: u8,
    pub authority: Address,
    pub grace_slots: [u8; 8],
    pub next_index: [u8; 4],
    /// Immutable, zero serves as a curator only.
    pub ring_id: [u8; 32],
    /// Immutable, zero on a source no salted list reads.
    pub tracking_registry: Address,
    /// The pinned registry's newest revision at the last zero grace update, frames name no older tracking root.
    pub tracking_floor: Revision,
    /// Newest first, only retired roots have an expiry.
    pub roots: [Root; ROOT_HISTORY],
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum StorageError {
    #[error("invalid registry")]
    InvalidRegistry = 9000,
    #[error("authority does not match")]
    Unauthorized = 9001,
    #[error("revision changed")]
    RevisionChanged = 9002,
    #[error("root expired or absent")]
    RootExpired = 9003,
    #[error("root history is full")]
    HistoryFull = 9004,
    #[error("instruction data is invalid")]
    InvalidInstructionData = 9005,
    #[error("update carries more writes than one apply proof takes")]
    BatchTooLarge = 9006,
    #[error("write is not a record write")]
    InvalidWrite = 9007,
    #[error("apply proof does not verify")]
    ProofVerificationFailed = 9008,
    #[error("hashing failed")]
    HashingFailed = 9009,
    #[error("accounts are missing")]
    MissingAccounts = 9010,
    #[error("required signer did not sign")]
    MissingSignature = 9011,
    #[error("registry account is not writable")]
    ReadOnlyRegistry = 9012,
    #[error("system program account is invalid")]
    InvalidSystemProgram = 9013,
    #[error("registry is already initialized")]
    AlreadyInitialized = 9014,
    #[error("revision overflows u64")]
    RevisionOverflow = 9015,
    #[error("no apply key serves the write count")]
    UnsupportedBatch = 9016,
    #[error("viewing key is zero or not canonical")]
    NonCanonicalViewingKey = 9021,
    #[error("tracking registry is invalid")]
    InvalidTrackingRegistry = 9022,
    #[error("tracking authorization is invalid")]
    InvalidTrackingAuthorization = 9023,
    #[error("the enrollment's revision is already applied")]
    EnrollmentAlreadyApplied = 9024,
    #[error("the enrolled nullifier key, list tag and ciphertext are final")]
    EnrollmentKeyFinal = 9025,
    #[error("a zero nullifier key does not enroll")]
    ZeroNullifierKey = 9028,
    #[error("a first enrollment carries a proof and a rotation none")]
    EnrollmentProofShape = 9029,
    #[error("an apply names no enrollment")]
    NoEnrollmentsNamed = 9030,
    #[error("owner grant account is invalid")]
    InvalidOwnerGrant = 9031,
    #[error("reader key names no scheme")]
    InvalidReaderKey = 9032,
    #[error("auditor key is untagged, zero or not canonical")]
    InvalidAuditorKey = 9033,
    #[error("the frame names a tracking root below the source's floor")]
    TrackingRootBelowFloor = 9034,
}

#[must_use]
pub struct RootUpdate<'a> {
    pub slot: u64,
    pub data: &'a StorageUpdateIxData<'a>,
    /// The pinned registry's newest revision, read when [`StorageRegistry::reads_tracking`] holds.
    pub tracking_revision: Option<Revision>,
}

impl From<u64> for Revision {
    fn from(value: u64) -> Self {
        Self(value.to_le_bytes())
    }
}

impl Revision {
    pub const fn value(self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

impl Root {
    pub const fn expires_at(&self) -> u64 {
        u64::from_le_bytes(self.expires_at)
    }
}

impl StorageRegistry {
    /// Zero marks an uninitialized account.
    pub const DISCRIMINATOR: u8 = 1;
    pub const SEED: &'static [u8] = b"storage";
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// The creator in the seeds keeps every other signer off its addresses.
    pub fn seeds<'a>(creator: &'a Address, registry_id: &'a RegistryId) -> [&'a [u8]; 3] {
        [Self::SEED, creator.as_ref(), &registry_id.0]
    }

    pub fn find_address(creator: &Address, registry_id: &RegistryId) -> (Address, u8) {
        Address::find_program_address(&Self::seeds(creator, registry_id), &STORAGE_PROGRAM_ID)
    }

    /// Holds only the sentinel root at revision zero.
    pub fn new(authority: Address, ix: &InitializeIxData) -> Self {
        let mut registry = Self::zeroed();
        registry.discriminator = Self::DISCRIMINATOR;
        registry.authority = authority;
        registry.grace_slots = ix.grace_slots;
        registry.ring_id = ix.ring_id;
        registry.tracking_registry = ix.tracking_registry;
        registry.next_index = 1u32.to_le_bytes();
        registry.roots[0].hash = MEMBER_REGISTRY_EMPTY_ROOT;
        registry
    }

    pub fn from_data(data: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes::<Self>(data)
            .ok()
            .filter(|registry| registry.valid())
    }

    pub fn decode(owner: &Address, data: &[u8]) -> Option<Self> {
        (*owner == STORAGE_PROGRAM_ID)
            .then(|| Self::from_data(data).copied())
            .flatten()
    }

    pub fn from_data_mut(data: &mut [u8]) -> Option<&mut Self> {
        bytemuck::try_from_bytes_mut::<Self>(data)
            .ok()
            .filter(|registry| registry.valid())
    }

    pub const fn grace_slots(&self) -> u64 {
        u64::from_le_bytes(self.grace_slots)
    }

    pub const fn next_index(&self) -> u32 {
        u32::from_le_bytes(self.next_index)
    }

    pub const fn newest(&self) -> Root {
        self.roots[0]
    }

    pub fn root(&self, revision: Revision, slot: u64) -> Result<[u8; 32], StorageError> {
        root_at(&self.roots, revision, slot)
    }

    /// A salted list may read it.
    pub fn is_private(&self) -> bool {
        self.tracking_registry != Address::default()
    }

    /// The one exception to tracking grace, a stale root could prove a blocked owner unenrolled.
    pub fn check_tracking_revision(&self, named: Revision) -> Result<(), StorageError> {
        if named.value() < self.tracking_floor.value() {
            return Err(StorageError::TrackingRootBelowFloor);
        }
        Ok(())
    }

    /// A zero grace write on a pinned source takes the pinned registry's revision as its floor.
    pub fn reads_tracking(&self, data: &StorageUpdateIxData<'_>) -> bool {
        data.reaches_policy() && self.is_private()
    }

    /// Writes nothing on a refusal.
    pub fn update(&mut self, update: RootUpdate<'_>) -> Result<(), StorageError> {
        let RootUpdate {
            slot,
            data,
            tracking_revision,
        } = update;
        let floor = self
            .reads_tracking(data)
            .then(|| tracking_revision.ok_or(StorageError::InvalidTrackingRegistry))
            .transpose()?;
        let retirement = match data.reaches_policy() {
            true => Retirement::Immediate,
            false => Retirement::Graced {
                slot,
                grace_slots: self.grace_slots(),
            },
        };
        advance_roots(
            &mut self.roots,
            data.revision,
            retirement,
            data.apply.new_root,
        )?;
        if let Some(floor) = floor {
            self.tracking_floor = floor;
        }
        self.next_index = data.apply.new_next_index;
        Ok(())
    }

    fn valid(&self) -> bool {
        self.discriminator == Self::DISCRIMINATOR
            && (1..=MEMBER_REGISTRY_CAPACITY).contains(&u64::from(self.next_index()))
    }
}

/// `APPLY_RECORDS` binds the registry address and revision before the ordered writes.
pub fn chain_start(registry: &Address, revision: Revision) -> Result<[u8; 32], StorageError> {
    let registry = registry_field(registry.as_array()).map_err(|_| StorageError::HashingFailed)?;
    create_hash_chain_4_from_slice(&[
        domain::field(domain::APPLY_RECORDS),
        registry,
        right_align(&revision.value().to_be_bytes()),
    ])
    .map_err(|_| StorageError::HashingFailed)
}

/// How an update treats the roots it replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Retirement {
    /// The outgoing root stays served for `grace_slots`, an unexpired oldest root refuses the update.
    Graced { slot: u64, grace_slots: u64 },
    /// Every earlier root stops being served.
    Immediate,
}

/// Writes nothing on a refusal, `revision` is the one the proof was made against.
pub(crate) fn advance_roots(
    roots: &mut [Root; ROOT_HISTORY],
    revision: Revision,
    retirement: Retirement,
    new_root: [u8; 32],
) -> Result<(), StorageError> {
    if revision != roots[0].revision {
        return Err(StorageError::RevisionChanged);
    }
    let next = revision
        .value()
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow)?;
    match retirement {
        Retirement::Graced { slot, .. } if slot < roots[ROOT_HISTORY - 1].expires_at() => {
            return Err(StorageError::HistoryFull);
        }
        Retirement::Graced { slot, grace_slots } => {
            // A saturated expiry never lapses.
            roots[0].expires_at = slot.saturating_add(grace_slots).to_le_bytes();
            roots.rotate_right(1);
        }
        Retirement::Immediate => roots.fill(Root::zeroed()),
    }
    roots[0] = Root {
        hash: new_root,
        revision: next.into(),
        expires_at: [0; 8],
    };
    Ok(())
}

/// The current root, or a retired one before its expiry.
pub(crate) fn root_at(
    roots: &[Root; ROOT_HISTORY],
    revision: Revision,
    slot: u64,
) -> Result<[u8; 32], StorageError> {
    roots
        .iter()
        .find(|root| {
            root.hash != [0; 32]
                && root.revision == revision
                && (revision == roots[0].revision || slot < root.expires_at())
        })
        .map(|root| root.hash)
        .ok_or(StorageError::RootExpired)
}

impl From<StorageError> for ProgramError {
    fn from(error: StorageError) -> Self {
        Self::Custom(error as u32)
    }
}

// Byte fields only, the `Pod` image is the account data with no padding.
const _: () = assert!(core::mem::align_of::<StorageRegistry>() == 1);
const _: () = assert!(StorageRegistry::SIZE == 1653);
