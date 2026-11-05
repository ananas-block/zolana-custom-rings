//! The deposit statement and the key a deposit selects.
//!
//! SPP verifies no proof on a deposit, so the statement alone ties SPP's data, each owner commitment,
//! each auditor record, the deposited assets and the roots together. `DepositContext` hashes SPP's
//! data whole, a byte outside the hash would settle unproven.
//!
//! Read after `program-libs/interface/src/proof/statement.rs`. Read before `program-libs/interface/src/instructions/deposit_audit.rs`,
//! `programs/custom-ring/src/instructions/settlement/deposit_audit.rs`, `prover/circuits/deposit.go`.

use spr_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_hash_chain_from_slice},
    primitives::{hash_bytes, pack_be, right_align, PACK_BE_CHUNK_BYTES},
    HasherError,
};

use spr_interface::instruction::MAX_DEPOSIT_ASSETS;

use crate::{
    credential_read::CredentialRoots,
    deposit_audit::{MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN},
    key_catalog::RingCircuit,
    TAGGED_X25519_KEY_LEN,
};

pub struct DepositContext<'a> {
    pub program_id: &'a [u8; 32],
    pub tree: &'a [u8; 32],
    pub spp_data: &'a [u8],
}

impl DepositContext<'_> {
    /// The length separates byte strings whose 31-byte chunks pack to equal fields.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let chunks: Vec<_> = self
            .spp_data
            .chunks(PACK_BE_CHUNK_BYTES)
            .map(|chunk| {
                let mut field = [0; 32];
                field[32 - chunk.len()..].copy_from_slice(chunk);
                field
            })
            .collect();
        create_hash_chain_from_slice(&[
            hash_bytes(self.program_id)?,
            hash_bytes(self.tree)?,
            right_align(&(self.spp_data.len() as u64).to_be_bytes()),
            create_hash_chain_from_slice(&chunks)?,
        ])
    }
}

/// `asset` is SPP's asset field of the entry's group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositedAsset {
    pub asset: [u8; 32],
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositRegistry<'a> {
    pub own_root: &'a [u8; 32],
    /// `None` without a curator source.
    pub curator_root: Option<&'a [u8; 32]>,
    /// Its table's asset rules screen every deposited asset.
    pub policy_hash: &'a [u8; 32],
}

pub struct DepositPublicInput<'a> {
    pub context_hash: &'a [u8; 32],
    pub ring_id: &'a [u8; 32],
    pub owner_utxo_hashes: &'a [[u8; 32]],
    pub ciphertexts: &'a [[u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]],
    pub assets: &'a [DepositedAsset],
    pub auditor_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub credentials: &'a CredentialRoots,
    /// `None` off a policy ring.
    pub registry: Option<DepositRegistry<'a>>,
}

/// One deposit's distinct subjects, a salted key is an enrolled recipient on a ring reading a salted list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositSubjects {
    pub slots: u8,
    pub recipients: usize,
    pub assets: usize,
    pub salted_keys: usize,
}

impl DepositSubjects {
    /// Mirrors `depositSaltedKeys` and `NewDepositPolicy` in the Go circuits.
    pub const fn pool_width(capacity: u8) -> usize {
        let capacity = capacity as usize;
        let assets = if capacity < MAX_DEPOSIT_ASSETS {
            capacity
        } else {
            MAX_DEPOSIT_ASSETS
        };
        let salted = if capacity == MAX_RING_DEPOSIT_AUDIT_SLOTS {
            capacity
        } else {
            0
        };
        capacity + assets + salted
    }

    /// The narrowest key whose slots and pools hold the deposit, every subject taken as its own record.
    pub fn key_capacity(&self) -> Option<u8> {
        [1, 2, 4, 8].into_iter().find(|&capacity| {
            self.slots <= capacity
                && self.recipients + self.assets + self.salted_keys <= Self::pool_width(capacity)
        })
    }
}

const DEPOSIT_FIXED_ELEMENTS: usize = 4 + MAX_RING_DEPOSIT_AUDIT_SLOTS * 4 + 7;

impl DepositPublicInput<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements()?)
    }

    pub fn element_count(&self) -> usize {
        DEPOSIT_FIXED_ELEMENTS + self.credentials.elements().count()
    }

    pub fn elements(&self) -> Result<Vec<[u8; 32]>, HasherError> {
        // 1. The selected root table fixes K, published deposits fit that key and have one ciphertext and asset each.
        let count = self.owner_utxo_hashes.len();
        let capacity =
            u8::try_from(self.credentials.capacity()).map_err(|_| HasherError::InvalidNumFields)?;
        if !(1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).contains(&count)
            || count > usize::from(capacity)
            || (RingCircuit::Deposit { capacity })
                .credential_capacity()
                .is_none()
            || self.ciphertexts.len() != count
            || self.assets.len() != count
        {
            return Err(HasherError::InvalidNumFields);
        }
        // 2. CRDP binds the exact SPP bytes and the authenticated ring before the deposit count.
        let mut chain = Vec::with_capacity(self.element_count());
        chain.extend([
            crate::domain::field(crate::domain::DEPOSIT_STATEMENT),
            *self.context_hash,
            *self.ring_id,
            right_align(&(count as u64).to_be_bytes()),
        ]);
        for (owner, ciphertext) in self.owner_utxo_hashes.iter().zip(self.ciphertexts) {
            chain.extend([*owner, hash_bytes(ciphertext)?]);
        }
        chain.resize(4 + MAX_RING_DEPOSIT_AUDIT_SLOTS * 2, [0; 32]);
        // 3. The credential owner, address checkpoint and padded state roots precede the policy roots.
        chain.extend(pack_be::<TAGGED_X25519_KEY_LEN, 2>(self.auditor_pk));
        chain.extend(pack_be::<TAGGED_X25519_KEY_LEN, 2>(self.eph_pk));
        chain.extend(self.credentials.elements());
        let registry = self.registry.as_ref();
        chain.extend([
            registry.map_or([0; 32], |registry| *registry.own_root),
            registry
                .and_then(|registry| registry.curator_root)
                .copied()
                .unwrap_or_default(),
            registry.map_or([0; 32], |registry| *registry.policy_hash),
        ]);
        // 4. Asset and amount pairs retain published order, unused slots are zero through the fixed deposit maximum.
        for deposited in self.assets {
            chain.extend([
                deposited.asset,
                right_align(&deposited.amount.to_be_bytes()),
            ]);
        }
        chain.resize(self.element_count(), [0; 32]);
        Ok(chain)
    }
}
