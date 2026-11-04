use spr_hasher::{
    hash_chain::create_hash_chain_from_slice,
    primitives::{hash_bytes, pack_be},
    HasherError,
};
use spr_interface::instruction::{
    instruction_data::{merge_ring::MergeRingAuthority, merge_transact::MergeTransactIxData},
    tag::RING_MERGE_V2,
};
use wincode::{SchemaRead, SchemaWrite};

use crate::{
    bytes::Bytes, error::CustomRingError, storage::Revision, CustomRingProof, TAGGED_X25519_KEY_LEN,
};

/// `kind 1 | reserved 7 | amount 8 | owner_key 32 | mint 32 | nullifier_pk 32 | seed 32`, 9 AES blocks.
pub const MERGE_RECORD_LEN: usize = 144;
pub const MERGE_PUBLIC_INPUT_ELEMENTS: usize = 12;
/// The owner's slot in an SPP `merge_ring_v2` account list under `OwnerSigned`, past `ring_config`, payer and the two programs.
pub const RING_MERGE_OWNER_INDEX: usize = 6;
/// `expiry_unix_ts u64 || proof.a` open the SPP merge body ahead of `proof.b`.
const MERGE_B_OFFSET: usize = core::mem::size_of::<u64>() + 32;
const MERGE_RECORD_KIND_RING: u8 = 1;

/// What the auditor reads, the published output hash accepts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeRecord {
    pub amount: u64,
    pub owner_key: [u8; 32],
    pub mint: [u8; 32],
    pub nullifier_pk: [u8; 32],
    /// The nullifier secret off the zero key, the private merge seed under it.
    pub seed: [u8; 32],
}

impl MergeRecord {
    pub fn to_bytes(&self) -> [u8; MERGE_RECORD_LEN] {
        let mut record = [0; MERGE_RECORD_LEN];
        record[0] = MERGE_RECORD_KIND_RING;
        record[8..16].copy_from_slice(&self.amount.to_be_bytes());
        record[16..48].copy_from_slice(&self.owner_key);
        record[48..80].copy_from_slice(&self.mint);
        record[80..112].copy_from_slice(&self.nullifier_pk);
        record[112..].copy_from_slice(&self.seed);
        record
    }

    /// A kind or reserved byte the circuit never proves is `InvalidMergeRecord`.
    pub fn from_bytes(record: &[u8; MERGE_RECORD_LEN]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(record, CustomRingError::InvalidMergeRecord);
        let [kind, reserved @ ..] = bytes.array::<8>()?;
        if *kind != MERGE_RECORD_KIND_RING || reserved != &[0; 7] {
            return Err(CustomRingError::InvalidMergeRecord);
        }
        Ok(Self {
            amount: u64::from_be_bytes(*bytes.array()?),
            owner_key: *bytes.array()?,
            mint: *bytes.array()?,
            nullifier_pk: *bytes.array()?,
            seed: *bytes.array()?,
        })
    }
}

/// The record sealed to the auditor and proven over the SPP merge it precedes.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct SealedMergeRecord {
    pub proof: CustomRingProof,
    pub eph_pk: [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: [u8; MERGE_RECORD_LEN],
}

/// Tag 57, the SPP merge body with `proof.b` compressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingMergeIxData {
    /// Read under `MergeRingAuthority::Ring` alone.
    pub tracking_revision: Revision,
    pub output_ring_data_hash: [u8; 32],
    pub authority: MergeRingAuthority,
    pub sealed: SealedMergeRecord,
    pub merge: MergeTransactIxData,
}

#[cfg(not(target_os = "solana"))]
impl CustomRingMergeIxData {
    /// The bytes after the instruction tag.
    pub fn serialize(&self) -> Result<Vec<u8>, CustomRingError> {
        let body = self.merge.serialize().map_err(invalid_data)?;
        let (head, rest) = body
            .split_at_checked(MERGE_B_OFFSET)
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let tail = rest
            .get(self.merge.proof.b.len()..)
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let b = solana_bn254::compression::prelude::alt_bn128_g2_compress_be(&self.merge.proof.b)
            .map_err(|_| CustomRingError::InvalidSppProofPoint)?;
        Ok([
            &self.tracking_revision.0[..],
            &self.output_ring_data_hash,
            &[authority_byte(self.authority)],
            &wincode::serialize(&self.sealed).map_err(invalid_data)?,
            head,
            &b,
            tail,
        ]
        .concat())
    }
}

#[cfg(not(target_os = "solana"))]
fn invalid_data<E>(_: E) -> CustomRingError {
    CustomRingError::InvalidInstructionData
}

/// Borrowed view of the tag 57 request.
pub struct CustomRingMergeIxDataRef<'a> {
    pub tracking_revision: Revision,
    pub output_ring_data_hash: &'a [u8; 32],
    pub authority: MergeRingAuthority,
    pub proof: &'a CustomRingProof,
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; MERGE_RECORD_LEN],
    body: SppMergeBody<'a>,
}

impl<'a> CustomRingMergeIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidInstructionData);
        Ok(Self {
            tracking_revision: *bytes.pod()?,
            output_ring_data_hash: bytes.array()?,
            authority: match bytes.byte()? {
                0 => MergeRingAuthority::Ring,
                1 => MergeRingAuthority::OwnerSigned,
                _ => return Err(CustomRingError::InvalidInstructionData),
            },
            proof: bytes.pod()?,
            eph_pk: bytes.array()?,
            ciphertext: bytes.array()?,
            body: SppMergeBody::read(&mut bytes)?,
        })
    }

    /// The SPP merge body the program forwards, `proof.b` decompressed, SPP's parser reads the rest.
    pub fn spp_merge_body(&self) -> Result<Vec<u8>, CustomRingError> {
        self.body.decompressed()
    }

    /// `merge_ring_v2` data over `spp_body`.
    pub fn forwarded(&self, spp_body: &[u8]) -> Vec<u8> {
        [
            &[RING_MERGE_V2][..],
            self.output_ring_data_hash,
            &[authority_byte(self.authority)],
            spp_body,
        ]
        .concat()
    }
}

/// The wincode tag SPP's `MergeRingV2IxData` reads.
const fn authority_byte(authority: MergeRingAuthority) -> u8 {
    match authority {
        MergeRingAuthority::Ring => 0,
        MergeRingAuthority::OwnerSigned => 1,
    }
}

/// An SPP merge body around its compressed `proof.b`.
pub(crate) struct SppMergeBody<'a> {
    head: &'a [u8; MERGE_B_OFFSET],
    compressed_b: &'a [u8; 64],
    tail: &'a [u8],
}

impl<'a> SppMergeBody<'a> {
    pub(crate) fn read(bytes: &mut Bytes<'a>) -> Result<Self, CustomRingError> {
        Ok(Self {
            head: bytes.array()?,
            compressed_b: bytes.array()?,
            tail: bytes.rest(),
        })
    }

    pub(crate) fn decompressed(&self) -> Result<Vec<u8>, CustomRingError> {
        let b = groth16_solana::decompression::decompress_g2(self.compressed_b)
            .map_err(|_| CustomRingError::InvalidSppProofPoint)?;
        Ok([&self.head[..], &b, self.tail].concat())
    }
}

/// The merge statement, `prover/circuits/merge.go`.
pub struct MergePublicInput<'a> {
    pub output_utxo_hash: &'a [u8; 32],
    pub first_nullifier: &'a [u8; 32],
    /// `hash_bytes` of the ring program id, the value the merged notes commit.
    pub ring_id: &'a [u8; 32],
    pub auditor_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; MERGE_RECORD_LEN],
    /// The payer's Solana owner identity.
    pub payer: &'a [u8; 32],
    /// The signing owner's identity under `OwnerSigned`, zero under `Ring`.
    pub published_owner: &'a [u8; 32],
    /// Zero under `OwnerSigned`.
    pub tracking_root: &'a [u8; 32],
}

impl MergePublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_from_slice(&self.elements()?)
    }

    pub fn elements(&self) -> Result<[[u8; 32]; MERGE_PUBLIC_INPUT_ELEMENTS], HasherError> {
        let [auditor_lo, auditor_hi] = pack_be(self.auditor_pk);
        let [eph_lo, eph_hi] = pack_be(self.eph_pk);
        Ok([
            crate::domain::field(crate::domain::MERGE_STATEMENT),
            *self.output_utxo_hash,
            *self.first_nullifier,
            *self.ring_id,
            auditor_lo,
            auditor_hi,
            eph_lo,
            eph_hi,
            hash_bytes(self.ciphertext)?,
            *self.payer,
            *self.published_owner,
            *self.tracking_root,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn record() -> MergeRecord {
        MergeRecord {
            amount: 0x0102_0304_0506_0708,
            owner_key: [0xa1; 32],
            mint: [0xa2; 32],
            nullifier_pk: [0xa3; 32],
            seed: [0xa4; 32],
        }
    }

    #[test]
    fn the_record_is_kind_reserved_amount_then_four_words() {
        let bytes = record().to_bytes();
        assert_eq!(bytes[..8], [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bytes[8..16], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(MergeRecord::from_bytes(&bytes).unwrap(), record());
    }

    #[test]
    fn a_record_the_circuit_never_proves_is_refused() {
        for (index, value) in [(0, 0), (0, 2), (1, 1), (7, 1)] {
            let mut bytes = record().to_bytes();
            bytes[index] = value;
            assert_eq!(
                MergeRecord::from_bytes(&bytes),
                Err(CustomRingError::InvalidMergeRecord)
            );
        }
    }

    #[test]
    fn an_unknown_authority_byte_is_refused() {
        let mut data = vec![0; 8 + 32];
        data.push(2);
        assert!(matches!(
            CustomRingMergeIxDataRef::from_bytes(&data),
            Err(CustomRingError::InvalidInstructionData)
        ));
    }
}
