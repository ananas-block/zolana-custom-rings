//! Enrollment carries one RegisterKey proof and one SPP proof for an immutable credential output.
//!
//! The fixed prefix excludes viewing keys, the owner keeps those in the separate SPP user registry.
//! Both proofs and the address root index are mandatory, an incomplete or extended request is refused.
//!
//! Read after `program-libs/interface/src/accounts/credential.rs`. Read before
//! `programs/custom-ring/src/instructions/enrollment` and `program-libs/interface/src/proof/verification.rs`.

use bytemuck::{Pod, Zeroable};
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_interface::{instruction::TransactProof, ZERO_NULLIFIER_PUBKEY};
use wincode::{config::DefaultConfig, SchemaRead};

use crate::{
    bytes::Bytes, storage::StorageError, CustomRingError, CustomRingProof,
    REGISTER_KEY_CIPHERTEXT_LEN,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct EnrollIxData {
    pub nullifier_pk: [u8; 32],
    pub list_tag: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollRequest<'a> {
    pub ix: &'a EnrollIxData,
    pub register_key: &'a CustomRingProof,
    pub transact: TransactProof,
    pub address_root_index: u16,
}

impl EnrollIxData {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn check(&self) -> Result<(), StorageError> {
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

impl<'a> EnrollRequest<'a> {
    /// Reads the payload after the instruction tag, the SPP codec owns the proof point encoding.
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        // 1. Fixed fields and RegisterKey proof stay borrowed from the exact instruction payload.
        let mut bytes = Bytes::new(data, CustomRingError::InvalidInstructionData);
        let ix = bytes.pod()?;
        let register_key = bytes.pod()?;
        // 2. The canonical SPP proof is followed by one root index, no other trailing bytes are valid.
        let mut suffix = bytes.rest();
        let transact = <TransactProof as SchemaRead<'a, DefaultConfig>>::get(&mut suffix)
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let mut suffix = Bytes::new(suffix, CustomRingError::InvalidInstructionData);
        let address_root_index = suffix.u16()?;
        if !suffix.rest().is_empty() {
            return Err(CustomRingError::InvalidInstructionData);
        }
        Ok(Self {
            ix,
            register_key,
            transact,
            address_root_index,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CustomRingError> {
        let mut out = bytemuck::bytes_of(self.ix).to_vec();
        out.extend_from_slice(bytemuck::bytes_of(self.register_key));
        out.extend(
            wincode::serialize(&self.transact)
                .map_err(|_| CustomRingError::InvalidInstructionData)?,
        );
        out.extend_from_slice(&self.address_root_index.to_le_bytes());
        Ok(out)
    }
}

const _: () = assert!(core::mem::align_of::<EnrollIxData>() == 1);
const _: () = assert!(EnrollIxData::SIZE == 160);
