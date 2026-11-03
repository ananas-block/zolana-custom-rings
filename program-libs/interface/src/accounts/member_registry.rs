//! Record tree constants and the record writes an apply proof chains, the tree
//! lives in `zolana-ring-member-registry`.

use spr_hasher::{
    primitives::{hash_bytes, pack_be, right_align, BN254_SCALAR_MODULUS_BE},
    Hasher, HasherError, Poseidon,
};
use zolana_ring_policy::{ListId, MintPolicy};

use crate::{domain, error::CustomRingError, REGISTER_KEY_CIPHERTEXT_LEN};

pub const QUAD_ARITY: usize = 4;
pub const QUAD_HEIGHT: usize = 10;
pub const MEMBER_REGISTRY_CAPACITY: u64 = 1 << (2 * QUAD_HEIGHT);
/// Writes the larger apply key proves.
pub const APPLY_BATCH: usize = 16;
/// Slots the ring's records keep an outgoing root readable.
pub const GRACE_SLOTS: u64 = 750;

/// `q - 1`, the sentinel's next, every member sorts strictly below it.
pub const FIELD_MAX: [u8; 32] = {
    let mut max = BN254_SCALAR_MODULUS_BE;
    max[31] -= 1;
    max
};

/// Root of the tree holding only the sentinel, the first history entry of a registry.
pub const MEMBER_REGISTRY_EMPTY_ROOT: [u8; 32] = [
    0x23, 0xe7, 0xf5, 0x5d, 0xac, 0x8a, 0xce, 0xcf, 0x4f, 0x3c, 0x2e, 0xe3, 0xcc, 0xea, 0x5b, 0xd3,
    0xb4, 0x2e, 0xd7, 0x8e, 0x23, 0x81, 0xe6, 0x7e, 0x0d, 0x75, 0x6d, 0x0f, 0x8c, 0xe3, 0xcb, 0x71,
];

/// The sentinel `(0, q - 1)` brackets every member in `[1, q - 2]` strictly.
pub fn check_member(member: &[u8; 32]) -> Result<(), CustomRingError> {
    if *member == [0; 32] || *member >= FIELD_MAX {
        return Err(CustomRingError::MemberOutOfRange);
    }
    Ok(())
}

/// The record field a registered key sets, `Poseidon(nullifier_pk, hash_bytes(ciphertext))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowKey<'a> {
    pub nullifier_pk: &'a [u8; 32],
    pub ciphertext: &'a [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

impl EscrowKey<'_> {
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        Poseidon::hashv(&[self.nullifier_pk, &hash_bytes(self.ciphertext)?])
    }
}

/// The owner-signed delivery address beside a record, the leaf holds its hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorizedAddress {
    /// `ring_id_field` of the ring program, a record of another ring does not open.
    pub ring_id: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub viewing_u: [u8; 32],
    pub address_revision: u64,
}

impl AuthorizedAddress {
    /// `Poseidon(CRAD, ring_id, member, nullifier_pk, view0, view1, address_revision)`, mirror
    /// `prover/circuits/registry`.
    pub fn hash(&self, member: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        let [view0, view1] = pack_be(&self.viewing_u);
        Poseidon::hashv(&[
            &domain::field(domain::AUTHORIZED_ADDRESS),
            &self.ring_id,
            member,
            &self.nullifier_pk,
            &view0,
            &view1,
            &right_align(&self.address_revision.to_be_bytes()),
        ])
    }
}

/// One queued masked write, `lists' = (lists & !mask) | value`, the escrow key fills once.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueEntry {
    pub member: [u8; 32],
    pub mask: u64,
    pub value: u64,
    pub escrow_key: [u8; 32],
    /// Only authority writes replace mint settings; list and key writes preserve them.
    pub mint_policy: Option<MintPolicy>,
    /// Zero keeps the bound address, only an owner-signed authorization sets one.
    pub address_hash: [u8; 32],
}

impl QueueEntry {
    pub fn escrow(member: [u8; 32], key: &EscrowKey<'_>) -> Result<Self, CustomRingError> {
        Self::escrow_hash(member, key.hash()?)
    }

    /// `escrow_key` is the [`EscrowKey::hash`] of a key checked elsewhere.
    pub fn escrow_hash(member: [u8; 32], escrow_key: [u8; 32]) -> Result<Self, CustomRingError> {
        check_member(&member)?;
        let bit = ListId::Escrow.record_bit();
        Ok(Self {
            member,
            mask: bit,
            value: bit,
            escrow_key,
            mint_policy: None,
            address_hash: [0; 32],
        })
    }

    /// `address_hash` is the [`AuthorizedAddress::hash`] of an owner-signed authorization.
    pub fn address(member: [u8; 32], address_hash: [u8; 32]) -> Result<Self, CustomRingError> {
        check_member(&member)?;
        Ok(Self {
            member,
            address_hash,
            ..Self::default()
        })
    }

    /// `Poseidon(CRQW, member, mask, value, escrow_key, mint_policy_write, withdrawal_threshold, limits_0, limits_1, limits_2, address_hash)`, mirror
    /// `prover/circuits/registry/apply_records.go`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let policy = self.mint_policy.unwrap_or_default();
        let [limits_0, limits_1, limits_2] = policy.limits.fields();
        Poseidon::hashv(&[
            &domain::field(domain::QUEUE_WRITE),
            &self.member,
            &right_align(&self.mask.to_be_bytes()),
            &right_align(&self.value.to_be_bytes()),
            &self.escrow_key,
            &self.mint_policy_field(),
            &right_align(&policy.withdrawal_threshold.to_be_bytes()),
            &limits_0,
            &limits_1,
            &limits_2,
            &self.address_hash,
        ])
    }

    /// Bit 192 distinguishes a replacement (including clearing) from no change.
    pub fn mint_policy_field(&self) -> [u8; 32] {
        self.mint_policy.map_or([0; 32], |policy| {
            let mut field = policy.field();
            field[7] = 1;
            field
        })
    }
}

/// `chain(p) = Poseidon(chain(p - 1), entry_p)` from `chain(-1) = 0`.
pub fn queue_chain(previous: &[u8; 32], entry: &QueueEntry) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[previous, &entry.hash()?])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(byte: u8) -> [u8; 32] {
        right_align(&[byte])
    }

    #[test]
    fn members_lie_strictly_between_the_sentinel_bounds() {
        // `q - 2`, the modulus ends in `f0000001`.
        let mut below_max = FIELD_MAX;
        below_max[28] -= 1;
        below_max[29..].fill(0xff);
        assert_eq!(check_member(&member(1)), Ok(()));
        assert_eq!(check_member(&below_max), Ok(()));
        for outside in [[0; 32], FIELD_MAX, BN254_SCALAR_MODULUS_BE] {
            assert_eq!(
                check_member(&outside),
                Err(CustomRingError::MemberOutOfRange)
            );
        }
    }

    #[test]
    fn an_escrow_entry_sets_the_escrow_bit_and_the_key() {
        let key = EscrowKey {
            nullifier_pk: &member(4),
            ciphertext: &[5; REGISTER_KEY_CIPHERTEXT_LEN],
        };
        let entry = QueueEntry::escrow(member(3), &key).unwrap();
        let bit = ListId::Escrow.record_bit();
        assert_eq!(
            (entry.mask, entry.value, entry.escrow_key),
            (bit, bit, key.hash().unwrap())
        );
        assert_ne!(
            entry.hash(),
            QueueEntry {
                escrow_key: [0; 32],
                ..entry
            }
            .hash()
        );
    }
}
