use custom_ring_interface::domain;
use solana_address::Address;
use spr_hasher::primitives::right_align;
use spr_keypair::{KeypairError, NullifierKey, ShieldedAddress, ShieldedKeypairTrait};
use zeroize::Zeroizing;

use crate::RingKeyError;

/// No constructor takes a secret, an enrollment never seals a default pool key by accident.
#[must_use]
#[derive(Clone)]
pub struct RingNullifierKey {
    key: NullifierKey,
}

impl RingNullifierKey {
    pub fn derive<H: ShieldedKeypairTrait + ?Sized>(
        holder: &H,
        ring_program_id: &Address,
    ) -> Result<Self, RingKeyError> {
        Ok(Self {
            key: holder.ring_nullifier_key(ring_program_id)?,
        })
    }

    pub fn nullifier_key(&self) -> &NullifierKey {
        &self.key
    }

    pub fn nullifier_pubkey(&self) -> Result<[u8; 32], RingKeyError> {
        Ok(self.key.pubkey()?)
    }

    /// The address a payer names on this ring.
    pub fn address_of(&self, wallet: ShieldedAddress) -> Result<ShieldedAddress, RingKeyError> {
        Ok(ShieldedAddress {
            nullifier_pubkey: self.nullifier_pubkey()?,
            ..wallet
        })
    }

    pub fn list_salt(&self) -> Result<[u8; 32], RingKeyError> {
        let secret = Zeroizing::new(right_align(&self.key.secret()));
        Ok(domain::list_salt(&secret).map_err(KeypairError::from)?)
    }

    pub fn list_tag(&self) -> Result<[u8; 32], RingKeyError> {
        Ok(domain::list_tag(&self.list_salt()?).map_err(KeypairError::from)?)
    }
}
