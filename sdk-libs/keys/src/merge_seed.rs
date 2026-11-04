//! The seed a ring merge keys its output and padding on, the nullifier secret or under the zero key a private value.

use hkdf::Hkdf;
use sha2::Sha256;
use solana_address::Address;
use spr_hasher::{
    primitives::{is_canonical_bn254_scalar_be, right_align},
    Hasher, Poseidon,
};
use spr_keypair::{shielded::ShieldedKeypair, ViewingKey, X25519Pubkey};
use spr_transaction::instructions::merge::{
    DOMAIN_MERGE_DUMMY_NULLIFIER, DOMAIN_MERGE_OUTPUT_BLINDING_V1, DOMAIN_MERGE_OUTPUT_KEY,
};
use zeroize::Zeroizing;

use crate::{keys::HeldKeys, RingKeyError, RotatingRingKeys};

/// Zolana's `DST_X25519_VIEW_ROOT`, a seed never shares a root with another reader.
const VIEW_ROOT_SALT: &[u8] = b"TSPP/view_root/x25519/v1";
const MERGE_SEED_INFO: &[u8] = b"CRING/mrg_seed/v1";
const SEED_ENTROPY_LEN: usize = 31;

/// A seed of zero would make every derivation public.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct RingMergeSeed(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for RingMergeSeed {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RingMergeSeed(..)")
    }
}

impl RingMergeSeed {
    /// A proof binds no seed to a viewing key, the record may carry any nonzero field element.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, RingKeyError> {
        if bytes == [0; 32] || !is_canonical_bn254_scalar_be(&bytes) {
            return Err(RingKeyError::InvalidMergeSeed);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// A zero top byte holds it in the field and a set low bit holds it off zero.
    fn derive(
        viewing_key: &ViewingKey,
        ring_program_id: &Address,
        first_nullifier: &[u8; 32],
    ) -> Result<Self, RingKeyError> {
        let secret = viewing_key.secret_bytes();
        let mut seed = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(VIEW_ROOT_SALT), secret.as_slice())
            .expand_multi_info(
                &[MERGE_SEED_INFO, ring_program_id.as_array(), first_nullifier],
                &mut seed[32 - SEED_ENTROPY_LEN..],
            )
            .map_err(|_| RingKeyError::InvalidMergeSeed)?;
        seed[31] |= 1;
        Ok(Self(seed))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn output_key(&self, first_nullifier: &[u8; 32]) -> Result<[u8; 32], RingKeyError> {
        self.keyed(DOMAIN_MERGE_OUTPUT_KEY, first_nullifier)
    }

    pub fn output_blinding(&self, first_nullifier: &[u8; 32]) -> Result<[u8; 32], RingKeyError> {
        self.keyed(DOMAIN_MERGE_OUTPUT_BLINDING_V1, first_nullifier)
    }

    /// A published nullifier equal to it at `slot_index` is padding.
    pub fn dummy_nullifier(
        &self,
        first_nullifier: &[u8; 32],
        slot_index: u32,
    ) -> Result<[u8; 32], RingKeyError> {
        Ok(Poseidon::hashv(&[
            &right_align(&DOMAIN_MERGE_DUMMY_NULLIFIER.to_be_bytes()),
            self.as_bytes(),
            first_nullifier,
            &right_align(&slot_index.to_be_bytes()),
        ])?)
    }

    fn keyed(&self, domain: u32, first_nullifier: &[u8; 32]) -> Result<[u8; 32], RingKeyError> {
        Ok(Poseidon::hashv(&[
            &right_align(&domain.to_be_bytes()),
            self.as_bytes(),
            first_nullifier,
        ])?)
    }
}

/// One merge under one held viewing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeSeedRequest {
    pub viewing_pubkey: X25519Pubkey,
    pub ring_program_id: Address,
    pub first_nullifier: [u8; 32],
}

/// No viewing key leaves the holder, one seed answers one merge.
pub trait MergeSeedHolder {
    fn merge_seeds(
        &self,
        requests: &[MergeSeedRequest],
    ) -> Result<Vec<RingMergeSeed>, RingKeyError>;
}

impl MergeSeedHolder for ShieldedKeypair {
    fn merge_seeds(
        &self,
        requests: &[MergeSeedRequest],
    ) -> Result<Vec<RingMergeSeed>, RingKeyError> {
        held_seeds(self, requests)
    }
}

impl MergeSeedHolder for RotatingRingKeys {
    fn merge_seeds(
        &self,
        requests: &[MergeSeedRequest],
    ) -> Result<Vec<RingMergeSeed>, RingKeyError> {
        held_seeds(self, requests)
    }
}

fn held_seeds<H: HeldKeys>(
    holder: &H,
    requests: &[MergeSeedRequest],
) -> Result<Vec<RingMergeSeed>, RingKeyError> {
    requests
        .iter()
        .map(|request| {
            RingMergeSeed::derive(
                holder.held(&request.viewing_pubkey)?,
                &request.ring_program_id,
                &request.first_nullifier,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;
    use spr_keypair::SigningKey;

    use super::*;

    const RING: Address = Address::new_from_array([4; 32]);
    const FIRST: [u8; 32] = [8; 32];

    fn wallet(byte: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[byte; 32])).unwrap()
    }

    fn seed(holder: &impl MergeSeedHolder, viewing_pubkey: X25519Pubkey) -> [u8; 32] {
        let answers = holder
            .merge_seeds(&[MergeSeedRequest {
                viewing_pubkey,
                ring_program_id: RING,
                first_nullifier: FIRST,
            }])
            .unwrap();
        *answers[0].as_bytes()
    }

    #[test]
    fn a_seed_binds_its_key_ring_and_merge_and_stays_a_nonzero_field_element() {
        let owner = wallet(3);
        let key = &owner.viewing_key;
        let seed = RingMergeSeed::derive(key, &RING, &FIRST).unwrap();
        assert_eq!(seed.as_bytes()[0], 0);
        assert_eq!(seed.as_bytes()[31] & 1, 1);
        for other in [
            RingMergeSeed::derive(&ViewingKey::new(), &RING, &FIRST).unwrap(),
            RingMergeSeed::derive(key, &Address::new_from_array([5; 32]), &FIRST).unwrap(),
            RingMergeSeed::derive(key, &RING, &[9; 32]).unwrap(),
        ] {
            assert_ne!(seed, other);
        }
    }

    #[test]
    fn a_rotated_holder_derives_under_each_key_and_refuses_another() {
        let owner = wallet(3);
        let first_key = owner.viewing_key.pubkey();
        let next = ViewingKey::new();
        let next_key = next.pubkey();
        let rotated = RotatingRingKeys::new(&owner, &RING)
            .unwrap()
            .rotate(next)
            .unwrap();
        assert_eq!(seed(&rotated, first_key), seed(&owner, first_key));
        assert_ne!(seed(&rotated, next_key), seed(&rotated, first_key));
        let refused = rotated.merge_seeds(&[MergeSeedRequest {
            viewing_pubkey: ViewingKey::new().pubkey(),
            ring_program_id: RING,
            first_nullifier: FIRST,
        }]);
        assert_eq!(refused.err(), Some(RingKeyError::UnknownViewingKey));
    }

    #[test]
    fn zero_and_a_value_off_the_field_are_refused() {
        for bytes in [[0; 32], [0xff; 32], BN254_SCALAR_MODULUS_BE] {
            assert_eq!(
                RingMergeSeed::from_bytes(bytes).err(),
                Some(RingKeyError::InvalidMergeSeed)
            );
        }
    }
}
