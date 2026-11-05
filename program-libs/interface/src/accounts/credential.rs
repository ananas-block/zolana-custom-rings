//! Permanent auditor credentials stored as SPP unique data accounts under the credential PDA.
//!
//! RegisterKey and stored state commit to one field order under distinct domains. The program builds
//! one credential, verifies its sealed secrets and passes that same value to the SPP output builder.
//! Only enrollment signs for the credential PDA, no instruction can replace or spend its credentials.
//!
//! Read after `program-libs/interface/src/proof/domain.rs` and `prover/circuits/registry/register_key.go`.
//! Read before `program-libs/interface/src/instructions/enrollment.rs` and `program-libs/interface/src/proof/verification.rs`.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_address::Address;
use spr_hasher::{
    Hasher, HasherError, Poseidon,
    hash_chain::create_hash_chain_4_from_slice,
    primitives::{hash_bytes, pack_be, solana_owner_identity},
};
use spr_program::{
    hasher::{DataHasher, unique_data_hash},
    program::{AddressSeed, CompressedAccountError, PdaOwner},
};

use crate::{
    CustomRingError, REGISTER_KEY_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN, domain,
    enrollment::EnrollIxData, storage::StorageError, tagged_x25519,
};

pub const CREDENTIAL_PDA_SEED: &[u8] = b"credential";

/// Borsh preserves the RegisterKey fields, the secret and list salt occur only inside the ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuditCredential {
    pub ring_id: [u8; 32],
    pub member: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub list_tag: [u8; 32],
    pub auditor_pubkey: [u8; TAGGED_X25519_KEY_LEN],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

pub struct Enrollment<'a> {
    pub ring_id: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub owner: &'a Address,
    pub ix: &'a EnrollIxData,
}

pub struct CredentialSeed<'a> {
    pub ring_id: &'a [u8; 32],
    pub member: &'a [u8; 32],
}

#[derive(Clone, Copy)]
pub struct CredentialAuthority {
    owner: PdaOwner,
    bump: u8,
}

impl Default for AuditCredential {
    fn default() -> Self {
        Self {
            ring_id: [0; 32],
            member: [0; 32],
            nullifier_pk: [0; 32],
            list_tag: [0; 32],
            auditor_pubkey: [0; TAGGED_X25519_KEY_LEN],
            eph_u: [0; 32],
            ciphertext: [0; REGISTER_KEY_CIPHERTEXT_LEN],
        }
    }
}

impl Enrollment<'_> {
    pub fn credential(self) -> Result<AuditCredential, StorageError> {
        // 1. The instruction supplies a canonical nullifier key and list tag, RegisterKey proves their secret opening.
        self.ix.check()?;
        // 2. The signed owner fixes the member, the loaded ring fixes the ring identity and auditor key.
        // The caller must verify the returned credential before storing it under the credential PDA.
        Ok(AuditCredential {
            ring_id: *self.ring_id,
            member: owner_member(self.owner)?,
            nullifier_pk: self.ix.nullifier_pk,
            list_tag: self.ix.list_tag,
            auditor_pubkey: *self.auditor_pubkey,
            eph_u: self.ix.eph_u,
            ciphertext: self.ix.ciphertext,
        })
    }
}

impl AuditCredential {
    pub const SIZE: usize = 5 * 32 + TAGGED_X25519_KEY_LEN + REGISTER_KEY_CIPHERTEXT_LEN;

    /// CRRG and CRCR share every field position, only the first element selects proof or state semantics.
    pub fn elements(&self, domain: u32) -> Result<[[u8; 32]; 10], HasherError> {
        let [aud0, aud1] = pack_be(&self.auditor_pubkey);
        let [eph0, eph1] = pack_be(&tagged_x25519(&self.eph_u));
        Ok([
            crate::domain::field(domain),
            self.ring_id,
            self.member,
            self.nullifier_pk,
            self.list_tag,
            aud0,
            aud1,
            eph0,
            eph1,
            hash_bytes(&self.ciphertext)?,
        ])
    }

    pub fn register_key_hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements(domain::REGISTER_KEY)?)
    }

    pub fn state_hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements(domain::CREDENTIAL_STATE)?)
    }

    /// UNIQ binds the state commitment to the reserved address through the SPP canonical hash.
    pub fn data_hash(&self, address: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        unique_data_hash(address, &self.state_hash()?)
    }

    pub fn seed(&self) -> Result<AddressSeed, CompressedAccountError> {
        CredentialSeed {
            ring_id: &self.ring_id,
            member: &self.member,
        }
        .derive()
    }
}

impl CredentialSeed<'_> {
    /// CRCA binds ring and member alone, a key or viewing change cannot create a second credential address.
    pub fn derive(self) -> Result<AddressSeed, CompressedAccountError> {
        AddressSeed::new(Poseidon::hashv(&[
            &domain::field(domain::CREDENTIAL_SEED),
            self.ring_id,
            self.member,
        ])?)
    }
}

impl CredentialAuthority {
    /// The canonical credential PDA fixes the SPP owner, a supplied owner hash cannot select another issuer.
    pub fn derive(ring_program: &Address) -> Result<Self, CustomRingError> {
        let (pda, bump) = Address::try_find_program_address(&[CREDENTIAL_PDA_SEED], ring_program)
            .ok_or(CustomRingError::InvalidCredentialPda)?;
        let owner = PdaOwner::new(&pda).map_err(|_| CustomRingError::HashingFailed)?;
        Ok(Self { owner, bump })
    }

    pub const fn owner(&self) -> &PdaOwner {
        &self.owner
    }

    pub const fn bump(&self) -> u8 {
        self.bump
    }
}

impl DataHasher for AuditCredential {
    fn hash(&self) -> Result<[u8; 32], HasherError> {
        self.state_hash()
    }
}

pub fn credential_owner(ring_program: &Address) -> Result<[u8; 32], CustomRingError> {
    Ok(*CredentialAuthority::derive(ring_program)?
        .owner()
        .owner_hash())
}

pub fn owner_member(owner: &Address) -> Result<[u8; 32], StorageError> {
    solana_owner_identity(owner.as_array()).map_err(|_| StorageError::HashingFailed)
}

const _: () = assert!(AuditCredential::SIZE == 257);
