use custom_ring_interface::{
    member_registry::{AuthorizedAddress, EscrowKey},
    QueueEntry, FIELD_MAX,
};
use spr_hasher::{
    primitives::{hash_bytes, right_align},
    Hasher, HasherError, Poseidon,
};
use zolana_ring_policy::MintPolicy;

use crate::RecordTreeError;

/// One authenticated leaf, including packed mint settings and its withdrawal threshold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberRecord {
    pub member: [u8; 32],
    pub next: [u8; 32],
    /// Bit `id - 1` marks list `id`.
    pub lists: u64,
    /// `EscrowKey::hash` once registered, zero before.
    pub escrow_key: [u8; 32],
    pub mint_policy: MintPolicy,
    /// `AuthorizedAddress::hash` once enrolled, zero before.
    pub address_hash: [u8; 32],
}

/// The preimages a write proves when it sets an address or a first escrow key and the record then holds both, one nullifier key in both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressEscrowPair {
    pub address: AuthorizedAddress,
    pub escrow_ciphertext_hash: [u8; 32],
}

impl AddressEscrowPair {
    pub fn new(
        address: AuthorizedAddress,
        escrow: &EscrowKey<'_>,
    ) -> Result<Self, RecordTreeError> {
        if address.nullifier_pk != *escrow.nullifier_pk {
            return Err(RecordTreeError::PairNullifierMismatch);
        }
        Ok(Self {
            address,
            escrow_ciphertext_hash: hash_bytes(escrow.ciphertext)?,
        })
    }
}

impl MemberRecord {
    /// Leaf 0, every member sorts strictly between it and `FIELD_MAX`.
    pub const SENTINEL: Self = Self {
        member: [0; 32],
        next: FIELD_MAX,
        lists: 0,
        escrow_key: [0; 32],
        mint_policy: MintPolicy::EMPTY,
        address_hash: [0; 32],
    };

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let [limits_0, limits_1, limits_2] = self.mint_policy.limits.fields();
        Poseidon::hashv(&[
            &self.member,
            &self.next,
            &right_align(&self.lists.to_be_bytes()),
            &self.escrow_key,
            &self.mint_policy.field(),
            &right_align(&self.mint_policy.withdrawal_threshold.to_be_bytes()),
            &limits_0,
            &limits_1,
            &limits_2,
            &self.address_hash,
        ])
    }

    /// List bits outside the mask keep their value, a registered key is final, a zero address keeps the bound one.
    #[must_use]
    pub fn written(self, entry: &QueueEntry) -> Self {
        let escrow_key = if self.escrow_key == [0; 32] {
            entry.escrow_key
        } else {
            self.escrow_key
        };
        let address_hash = if entry.address_hash == [0; 32] {
            self.address_hash
        } else {
            entry.address_hash
        };
        Self {
            lists: (self.lists & !entry.mask) | entry.value,
            escrow_key,
            mint_policy: entry.mint_policy.unwrap_or(self.mint_policy),
            address_hash,
            ..self
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lists == 0
            && self.escrow_key == [0; 32]
            && self.mint_policy == MintPolicy::EMPTY
            && self.address_hash == [0; 32]
    }

    /// `address` is the preimage of the leaf's address hash, absent exactly while the hash is zero.
    pub fn check_address(
        &self,
        address: Option<&AuthorizedAddress>,
    ) -> Result<(), RecordTreeError> {
        let expected = match address {
            Some(address) => address.hash(&self.member)?,
            None => [0; 32],
        };
        if expected != self.address_hash {
            return Err(RecordTreeError::AddressMismatch);
        }
        Ok(())
    }

    pub fn brackets(&self, member: &[u8; 32]) -> bool {
        self.member < *member && *member < self.next
    }
}

pub(crate) fn check_member(member: &[u8; 32]) -> Result<(), RecordTreeError> {
    custom_ring_interface::check_member(member).map_err(|_| RecordTreeError::MemberOutOfRange)
}
