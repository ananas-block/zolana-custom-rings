//! A ring pins its tracking registry's address, `ring_id` and the seeds authenticate nothing.

use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice,
    primitives::{
        hash_bytes, is_canonical_bn254_scalar_be, is_canonical_x25519_public_key, pack_be,
        right_align, solana_owner_identity,
    },
    Hasher, HasherError, Poseidon,
};
pub use spr_interface::ZERO_NULLIFIER_PUBKEY;
use zolana_ring_policy::registry_field;

use crate::{
    domain,
    member_registry::GRACE_SLOTS,
    state::ROOT_HISTORY,
    storage::{advance_roots, root_at, Retirement, Revision, Root, StorageError},
    storage_instruction::{EnrollIxData, InitializeTrackingIxData, OwnerGrantIxData},
    ReaderKeyBytes, READER_KEY_ED25519, READER_KEY_P256, REGISTER_KEY_CIPHERTEXT_LEN,
    STORAGE_PROGRAM_ID, TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG,
};

pub const TRACKING_QUAD_HEIGHT: usize = 13;
pub const TRACKING_CAPACITY: u64 = 1 << (2 * TRACKING_QUAD_HEIGHT);
/// Fixed by the program, no write shortens a retired tracking root's service.
pub const TRACKING_GRACE_SLOTS: u64 = GRACE_SLOTS;

/// Root of the tree holding only the sentinel.
pub const TRACKING_EMPTY_ROOT: [u8; 32] = [
    0x06, 0x52, 0x15, 0x43, 0x90, 0x9e, 0xca, 0x81, 0xa7, 0x31, 0x13, 0x1d, 0x6a, 0x31, 0xf2, 0x39,
    0x69, 0xc6, 0x67, 0xc0, 0xf2, 0x8c, 0x8e, 0x7c, 0xb1, 0xa0, 0x03, 0x6b, 0x7b, 0x36, 0xb3, 0x76,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct TrackingRegistry {
    pub discriminator: u8,
    /// Immutable, enrollment proofs bind it.
    pub ring_id: [u8; 32],
    /// Immutable, enrollment proofs seal to it.
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    pub next_index: [u8; 4],
    /// Newest first, only retired roots have an expiry.
    pub roots: [Root; ROOT_HISTORY],
}

/// One owner's enrollment, retained so an auditor recovers every secret from accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct TrackingAuthorization {
    pub discriminator: u8,
    pub registry: Address,
    pub owner: Address,
    /// Final after creation, with `list_tag` and the ciphertext.
    pub nullifier_pk: [u8; 32],
    pub list_tag: [u8; 32],
    pub viewing_u: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
    /// Little endian, moves by one at every enrollment.
    pub revision: [u8; 8],
    /// Little endian, zero before the first apply, grants nothing while behind `revision`.
    pub applied_revision: [u8; 8],
}

/// A program owner's on-chain consent to one reader, a PDA cannot sign off chain, the address names both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct OwnerGrant {
    pub discriminator: u8,
    /// Zero revokes.
    pub active: u8,
}

/// The write an apply proof chains, computed from the owner's account and never from data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackingEntry {
    pub member: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub ct_hash: [u8; 32],
    pub viewing_u: [u8; 32],
    pub revision: u64,
    pub list_tag: [u8; 32],
}

/// The account state of a first enrollment, at revision 1 with nothing applied.
#[must_use]
pub struct FirstEnrollment<'a> {
    pub registry: Address,
    pub owner: Address,
    pub ix: &'a EnrollIxData,
}

/// A proven application of pending authorizations.
#[must_use]
pub struct TrackingRootUpdate {
    /// The revision the proof was made against.
    pub revision: Revision,
    pub slot: u64,
    pub new_root: [u8; 32],
    pub new_next_index: u32,
}

impl TrackingRegistry {
    pub const DISCRIMINATOR: u8 = 3;
    pub const SEED: &'static [u8] = b"tracking_registry";
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// The creator in the seeds keeps every other signer off its addresses.
    pub fn seeds<'a>(creator: &'a Address, ring_id: &'a [u8; 32]) -> [&'a [u8]; 3] {
        [Self::SEED, creator.as_ref(), ring_id]
    }

    pub fn find_address(creator: &Address, ring_id: &[u8; 32]) -> (Address, u8) {
        Address::find_program_address(&Self::seeds(creator, ring_id), &STORAGE_PROGRAM_ID)
    }

    /// Holds only the sentinel root at revision zero.
    pub fn new(ix: &InitializeTrackingIxData) -> Self {
        let mut registry = Self::zeroed();
        registry.discriminator = Self::DISCRIMINATOR;
        registry.ring_id = ix.ring_id;
        registry.auditor_pubkey = ix.auditor_pubkey;
        registry.next_index = 1u32.to_le_bytes();
        registry.roots[0].hash = TRACKING_EMPTY_ROOT;
        registry
    }

    pub fn from_data(data: &[u8]) -> Option<&Self> {
        bytemuck::try_from_bytes::<Self>(data)
            .ok()
            .filter(|registry| registry.valid())
    }

    pub fn from_data_mut(data: &mut [u8]) -> Option<&mut Self> {
        bytemuck::try_from_bytes_mut::<Self>(data)
            .ok()
            .filter(|registry| registry.valid())
    }

    pub fn decode(owner: &Address, data: &[u8]) -> Option<Self> {
        (*owner == STORAGE_PROGRAM_ID)
            .then(|| Self::from_data(data).copied())
            .flatten()
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

    /// Writes nothing on a refusal, a retired root stays served for its whole grace.
    pub fn update(&mut self, update: TrackingRootUpdate) -> Result<(), StorageError> {
        advance_roots(
            &mut self.roots,
            update.revision,
            Retirement::Graced {
                slot: update.slot,
                grace_slots: TRACKING_GRACE_SLOTS,
            },
            update.new_root,
        )?;
        self.next_index = update.new_next_index.to_le_bytes();
        Ok(())
    }

    fn valid(&self) -> bool {
        self.discriminator == Self::DISCRIMINATOR
            && (1..=TRACKING_CAPACITY).contains(&u64::from(self.next_index()))
    }
}

impl TrackingAuthorization {
    pub const DISCRIMINATOR: u8 = 4;
    pub const SEED: &'static [u8] = b"tracking";
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// One enrollment per owner per registry.
    pub fn seeds<'a>(registry: &'a Address, owner: &'a Address) -> [&'a [u8]; 3] {
        [Self::SEED, registry.as_ref(), owner.as_ref()]
    }

    pub fn find_address(registry: &Address, owner: &Address) -> (Address, u8) {
        Address::find_program_address(&Self::seeds(registry, owner), &STORAGE_PROGRAM_ID)
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

    pub const fn revision(&self) -> u64 {
        u64::from_le_bytes(self.revision)
    }

    pub const fn applied_revision(&self) -> u64 {
        u64::from_le_bytes(self.applied_revision)
    }

    /// Its newest revision has not reached a root yet.
    pub const fn is_pending(&self) -> bool {
        self.applied_revision() < self.revision()
    }

    /// Writes nothing on a refusal, only the viewing key and the revision move.
    pub fn rotate(&mut self, ix: &EnrollIxData) -> Result<(), StorageError> {
        if ix.nullifier_pk != self.nullifier_pk
            || ix.list_tag != self.list_tag
            || ix.eph_u != self.eph_u
            || ix.ciphertext != self.ciphertext
        {
            return Err(StorageError::EnrollmentKeyFinal);
        }
        let revision = self
            .revision()
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow)?;
        self.viewing_u = ix.viewing_u;
        self.revision = revision.to_le_bytes();
        Ok(())
    }

    pub fn entry(&self) -> Result<TrackingEntry, StorageError> {
        Ok(TrackingEntry {
            member: owner_member(&self.owner)?,
            nullifier_pk: self.nullifier_pk,
            ct_hash: hash_bytes(&self.ciphertext).map_err(|_| StorageError::HashingFailed)?,
            viewing_u: self.viewing_u,
            revision: self.revision(),
            list_tag: self.list_tag,
        })
    }

    /// The entry the apply proof chains, an applied revision refused so one account cannot chain twice.
    pub fn apply(&mut self) -> Result<TrackingEntry, StorageError> {
        if !self.is_pending() {
            return Err(StorageError::EnrollmentAlreadyApplied);
        }
        let entry = self.entry()?;
        self.applied_revision = self.revision;
        Ok(entry)
    }
}

impl FirstEnrollment<'_> {
    pub fn account(self) -> TrackingAuthorization {
        TrackingAuthorization {
            discriminator: TrackingAuthorization::DISCRIMINATOR,
            registry: self.registry,
            owner: self.owner,
            nullifier_pk: self.ix.nullifier_pk,
            list_tag: self.ix.list_tag,
            viewing_u: self.ix.viewing_u,
            eph_u: self.ix.eph_u,
            ciphertext: self.ix.ciphertext,
            revision: 1u64.to_le_bytes(),
            applied_revision: [0; 8],
        }
    }
}

impl OwnerGrant {
    pub const DISCRIMINATOR: u8 = 5;
    pub const SEED: &'static [u8] = b"owner_grant";
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// One account per owner per reader, the key splits because a seed holds 32 bytes.
    pub fn seeds<'a>(
        registry: &'a Address,
        owner: &'a Address,
        reader: &'a ReaderKeyBytes,
    ) -> [&'a [u8]; 5] {
        let (scheme, key) = reader.split_at(2);
        [Self::SEED, registry.as_ref(), owner.as_ref(), scheme, key]
    }

    pub fn find_address(
        registry: &Address,
        owner: &Address,
        reader: &ReaderKeyBytes,
    ) -> (Address, u8) {
        Address::find_program_address(&Self::seeds(registry, owner, reader), &STORAGE_PROGRAM_ID)
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

impl TrackingEntry {
    /// `Poseidon(CRTQ, member, nullifier_pk, ct_hash, view0, view1, revision, list_tag)`, mirror
    /// `prover/circuits/registry/apply_enrollments.go`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let [view0, view1] = pack_be(&self.viewing_u);
        Poseidon::hashv(&[
            &domain::field(domain::TRACKING_ENTRY),
            &self.member,
            &self.nullifier_pk,
            &self.ct_hash,
            &view0,
            &view1,
            &right_align(&self.revision.to_be_bytes()),
            &self.list_tag,
        ])
    }

    /// `Poseidon(previous, entry)`.
    pub fn chained(&self, previous: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[previous, &self.hash()?])
    }
}

impl InitializeTrackingIxData {
    /// A key no proof can seal to would lock enrollment for good.
    pub fn check(&self) -> Result<(), StorageError> {
        if self.ring_id == [0; 32] || !is_canonical_bn254_scalar_be(&self.ring_id) {
            return Err(StorageError::InvalidTrackingRegistry);
        }
        let (tag, key) = self.auditor_pubkey.split_at(1);
        let key: &[u8; 32] = key
            .try_into()
            .map_err(|_| StorageError::InvalidAuditorKey)?;
        if tag[0] != VIEWING_PUBKEY_TAG || *key == [0; 32] || !is_canonical_x25519_public_key(key) {
            return Err(StorageError::InvalidAuditorKey);
        }
        Ok(())
    }
}

impl EnrollIxData {
    /// A zero key has no secret to seal, a program owner stays unenrolled instead.
    pub fn check(&self) -> Result<(), StorageError> {
        if self.viewing_u == [0; 32] || !is_canonical_x25519_public_key(&self.viewing_u) {
            return Err(StorageError::NonCanonicalViewingKey);
        }
        if self.nullifier_pk == ZERO_NULLIFIER_PUBKEY {
            return Err(StorageError::ZeroNullifierKey);
        }
        if !is_canonical_bn254_scalar_be(&self.nullifier_pk)
            || !is_canonical_bn254_scalar_be(&self.list_tag)
        {
            return Err(StorageError::InvalidInstructionData);
        }
        Ok(())
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

/// The leaf member of a signer, a wallet or a PDA alike.
pub fn owner_member(owner: &Address) -> Result<[u8; 32], StorageError> {
    solana_owner_identity(owner.as_array()).map_err(|_| StorageError::HashingFailed)
}

/// `[CRTA, registry, revision]`, an apply proof serves one registry at one revision.
pub fn tracking_chain_start(
    registry: &Address,
    revision: Revision,
) -> Result<[u8; 32], StorageError> {
    let registry = registry_field(registry.as_array()).map_err(|_| StorageError::HashingFailed)?;
    create_hash_chain_4_from_slice(&[
        domain::field(domain::APPLY_ENROLLMENTS),
        registry,
        right_align(&revision.value().to_be_bytes()),
    ])
    .map_err(|_| StorageError::HashingFailed)
}

// Byte fields only, the `Pod` image is the account data with no padding.
const _: () = assert!(core::mem::align_of::<TrackingRegistry>() == 1);
const _: () = assert!(TrackingRegistry::SIZE == 1606);
const _: () = assert!(core::mem::align_of::<TrackingAuthorization>() == 1);
const _: () = assert!(TrackingAuthorization::SIZE == 273);
const _: () = assert!(core::mem::align_of::<OwnerGrant>() == 1);
const _: () = assert!(OwnerGrant::SIZE == 2);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_root_folds_the_sentinel_through_every_level() {
        let [view0, view1] = pack_be(&[0u8; 32]);
        let mut node = Poseidon::hashv(&[
            &domain::field(domain::TRACKING_LEAF),
            &[0; 32],
            &crate::FIELD_MAX,
            &[0; 32],
            &[0; 32],
            &view0,
            &view1,
            &[0; 32],
            &[0; 32],
        ])
        .unwrap();
        let mut zero = [0u8; 32];
        for _ in 0..TRACKING_QUAD_HEIGHT {
            node = Poseidon::hashv(&[&node, &zero, &zero, &zero]).unwrap();
            zero = Poseidon::hashv(&[&zero, &zero, &zero, &zero]).unwrap();
        }
        assert_eq!(node, TRACKING_EMPTY_ROOT);
    }
}
