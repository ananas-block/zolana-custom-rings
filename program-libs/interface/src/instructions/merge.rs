use spr_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_hash_chain_from_slice},
    primitives::{hash_bytes, pack_be, pack_be_chunks, right_align},
    HasherError,
};
use spr_interface::instruction::instruction_data::merge_transact::MergeTransactIxData;
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

use crate::{
    bytes::Bytes, error::CustomRingError, storage::Revision, CustomRingProof, TAGGED_X25519_KEY_LEN,
};

/// AES-256-CTR ciphertext of the 32-byte disclosure key.
pub const MERGE_KEY_CIPHERTEXT_LEN: usize = 32;

pub const MERGE_DISCLOSURE_INFO: &[u8; 10] = b"CRING/mrg1";
pub const MERGE_PUBLIC_INPUT_ELEMENTS: usize = 18;

/// SPP merge widths whose merge, disclosure and nullifier accounts fit one v1 transaction.
pub const MERGE_WIDTHS: [usize; 2] = [8, 24];
/// `expiry_unix_ts u64 || proof.a` open the SPP merge body ahead of `proof.b`.
const MERGE_B_OFFSET: usize = core::mem::size_of::<u64>() + 32;

/// `be32(hash_i)` per circuit slot, slot `i` of `PrivateTxHashCircuit`, zero at a dummy.
pub const fn merge_disclosure_len(width: usize) -> usize {
    32 * width
}

/// Masked fields of the disclosure, the plaintext zero padded to whole 31-byte chunks.
pub const fn merge_disclosure_field_count(width: usize) -> usize {
    pack_be_chunks(merge_disclosure_len(width))
}

/// The SPP merge body with `proof.b` compressed, the program resolves `own_revision` to its root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRingMergeIxData {
    /// Read on a key escrow ring alone, zero elsewhere.
    pub own_revision: Revision,
    pub output_ring_data_hash: [u8; 32],
    pub disclosure: MergeDisclosure,
    pub merge: MergeTransactIxData,
}

/// The auditor's opening of a merge, proven against the SPP merge it precedes.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct MergeDisclosure {
    pub proof: CustomRingProof,
    pub eph_pk: [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: [u8; MERGE_KEY_CIPHERTEXT_LEN],
    #[wincode(with = "containers::Vec<[u8; 32], FixIntLen<u8>>")]
    pub fields: Vec<[u8; 32]>,
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
            &self.own_revision.0[..],
            &self.output_ring_data_hash,
            &wincode::serialize(&self.disclosure).map_err(invalid_data)?,
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

/// Borrowed view of the compact request, the SPP merge body read around its compressed `b`.
pub struct CustomRingMergeIxDataRef<'a> {
    pub own_revision: Revision,
    pub output_ring_data_hash: &'a [u8; 32],
    pub disclosure: MergeDisclosureRef<'a>,
    head: &'a [u8; MERGE_B_OFFSET],
    compressed_b: &'a [u8; 64],
    tail: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeDisclosureRef<'a> {
    pub proof: &'a CustomRingProof,
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; MERGE_KEY_CIPHERTEXT_LEN],
    pub fields: &'a [[u8; 32]],
}

impl<'a> CustomRingMergeIxDataRef<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::InvalidInstructionData);
        let own_revision = *bytes.pod()?;
        let output_ring_data_hash = bytes.array()?;
        let disclosure = MergeDisclosureRef::read(&mut bytes)?;
        let head = bytes.array()?;
        let compressed_b = bytes.array()?;
        Ok(Self {
            own_revision,
            output_ring_data_hash,
            disclosure,
            head,
            compressed_b,
            tail: bytes.rest(),
        })
    }

    /// The SPP merge body the program forwards, `proof.b` decompressed, SPP's parser reads the rest.
    pub fn spp_merge_body(&self) -> Result<Vec<u8>, CustomRingError> {
        let b = groth16_solana::decompression::decompress_g2(self.compressed_b)
            .map_err(|_| CustomRingError::InvalidSppProofPoint)?;
        Ok([&self.head[..], &b, self.tail].concat())
    }
}

impl<'a> MergeDisclosureRef<'a> {
    /// The wincode disclosure ahead of the SPP body.
    fn read(bytes: &mut Bytes<'a>) -> Result<Self, CustomRingError> {
        let proof = bytes.pod()?;
        let eph_pk = bytes.array()?;
        let ciphertext = bytes.array()?;
        let count = bytes.byte()?;
        Ok(Self {
            proof,
            eph_pk,
            ciphertext,
            fields: bytes.fields(usize::from(count))?,
        })
    }
}

/// The merge statement, `prover/circuits/merge.go`.
pub struct MergePublicInput<'a> {
    pub party_identities: &'a [[u8; 32]; 3],
    pub private_tx_hash: &'a [u8; 32],
    pub output_utxo_hash: &'a [u8; 32],
    pub first_nullifier: &'a [u8; 32],
    /// `hash_bytes` of the ring program id, the value the merged notes commit.
    pub ring_id: &'a [u8; 32],
    pub auditor_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; MERGE_KEY_CIPHERTEXT_LEN],
    /// The SPP output ciphertext salt, the merge pad reuses it.
    pub salt: &'a [u8; 16],
    pub fields: &'a [[u8; 32]],
    /// `merge.nullifiers.len()`, a published slot may still be a hidden dummy.
    pub input_count: usize,
    /// The own root a key escrow ring binds, its owner's record escrows the merged key.
    pub member_registry_root: Option<&'a [u8; 32]>,
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
            *self.private_tx_hash,
            *self.output_utxo_hash,
            *self.first_nullifier,
            *self.ring_id,
            auditor_lo,
            auditor_hi,
            eph_lo,
            eph_hi,
            hash_bytes(self.ciphertext)?,
            right_align(self.salt),
            create_hash_chain_4_from_slice(self.fields)?,
            right_align(&(self.input_count as u64).to_be_bytes()),
            self.party_identities[0],
            self.party_identities[1],
            self.party_identities[2],
            right_align(&[u8::from(self.member_registry_root.is_some())]),
            self.member_registry_root.copied().unwrap_or_default(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement<'a>(root: Option<&'a [u8; 32]>, fields: &'a [[u8; 32]]) -> MergePublicInput<'a> {
        MergePublicInput {
            party_identities: &[[0x61; 32], [0x62; 32], [0; 32]],
            private_tx_hash: &[1; 32],
            output_utxo_hash: &[2; 32],
            first_nullifier: &[3; 32],
            ring_id: &[4; 32],
            auditor_pk: &[0x05; 33],
            eph_pk: &[0x06; 33],
            ciphertext: &[7; 32],
            salt: &[8; 16],
            fields,
            input_count: 5,
            member_registry_root: root,
        }
    }

    #[test]
    fn the_statement_closes_on_the_input_count_parties_and_escrow_root() {
        let fields = [[9; 32]; 9];
        let root = [0x0a; 32];
        let elements = statement(Some(&root), &fields).elements().unwrap();
        assert_eq!(
            elements[11],
            create_hash_chain_4_from_slice(&fields).unwrap()
        );
        assert_eq!(elements[12], right_align(&5u64.to_be_bytes()));
        assert_eq!(elements[13..16], [[0x61; 32], [0x62; 32], [0; 32]]);
        assert_eq!(elements[16], right_align(&[1]));
        assert_eq!(elements[17], root);
        let open = statement(None, &fields).elements().unwrap();
        assert_eq!(open[16..18], [[0; 32], [0; 32]]);
        assert_eq!(open[..16], elements[..16]);
    }

    #[test]
    fn disclosure_widths_match_the_go_circuit() {
        assert_eq!([8, 24, 52].map(merge_disclosure_field_count), [9, 25, 54]);
    }
}
