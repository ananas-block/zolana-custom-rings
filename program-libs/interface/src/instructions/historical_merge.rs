//! Tag 47 frames, read and never settled.

use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::{
    bytes::Bytes, error::CustomRingError, merge::SppMergeBody, storage::Revision, CustomRingProof,
    TAGGED_X25519_KEY_LEN,
};
use spr_hasher::primitives::pack_be_chunks;

/// AES-256-CTR ciphertext of the 32-byte disclosure key.
pub const MERGE_KEY_CIPHERTEXT_LEN: usize = 32;

pub const MERGE_DISCLOSURE_INFO: &[u8; 10] = b"CRING/mrg1";

/// `be32(hash_i)` per circuit slot, zero at a dummy.
pub const fn merge_disclosure_len(width: usize) -> usize {
    32 * width
}

/// Masked fields of the disclosure, the plaintext zero padded to whole 31-byte chunks.
pub const fn merge_disclosure_field_count(width: usize) -> usize {
    pack_be_chunks(merge_disclosure_len(width))
}

/// The auditor's opening of a tag 47 merge.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeDisclosure {
    pub proof: CustomRingProof,
    pub eph_pk: [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: [u8; MERGE_KEY_CIPHERTEXT_LEN],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub fields: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeDisclosureRef<'a> {
    pub proof: &'a CustomRingProof,
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; MERGE_KEY_CIPHERTEXT_LEN],
    pub fields: &'a [[u8; 32]],
}

/// Borrowed view of a tag 47 request.
pub struct HistoricalMergeIxDataRef<'a> {
    pub own_revision: Revision,
    pub output_ring_data_hash: &'a [u8; 32],
    pub disclosure: MergeDisclosureRef<'a>,
    body: SppMergeBody<'a>,
}

impl<'a> HistoricalMergeIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidInstructionData);
        let own_revision = *bytes.pod()?;
        let output_ring_data_hash = bytes.array()?;
        let proof = bytes.pod()?;
        let eph_pk = bytes.array()?;
        let ciphertext = bytes.array()?;
        let count = bytes.byte()?;
        let disclosure = MergeDisclosureRef {
            proof,
            eph_pk,
            ciphertext,
            fields: bytes.fields(usize::from(count))?,
        };
        Ok(Self {
            own_revision,
            output_ring_data_hash,
            disclosure,
            body: SppMergeBody::read(&mut bytes)?,
        })
    }

    pub fn spp_merge_body(&self) -> Result<Vec<u8>, CustomRingError> {
        self.body.decompressed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disclosure_widths_match_the_go_circuit() {
        assert_eq!([8, 24, 52].map(merge_disclosure_field_count), [9, 25, 54]);
    }
}
