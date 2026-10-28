use custom_ring_interface::stream::DeliveredSlot;
use solana_address::Address;
use spr_keypair::{
    shielded::ShieldedKeypair,
    viewing_key::{Salt, ViewTag},
    X25519Pubkey,
};

use crate::{RingKeyError, RingViewingKey};

/// The viewing key a delivered ring output was agreed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RingRecipientKey {
    /// One of the wallet's viewing keys, the recipient of a confidential delivered output.
    Viewing(X25519Pubkey),
    /// Ring address `index` of `ring`, the recipient of an anonymous output.
    Address { ring: Address, index: u32 },
}

/// The public context of one delivered ring output slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveryRequest {
    pub recipient: RingRecipientKey,
    pub tx_viewing_pk: X25519Pubkey,
    pub salt: Salt,
    pub output_index: u32,
    pub first_nullifier: [u8; 32],
}

pub trait RingKeys {
    /// The keys of ring addresses `indexes` of `ring`, one per index.
    fn ring_address_keys(
        &self,
        ring: &Address,
        indexes: &[u32],
    ) -> Result<Vec<X25519Pubkey>, RingKeyError>;

    /// One CRDS slot secret per request, the viewing secret never leaves the holder.
    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, RingKeyError>;

    /// The key the sender's change in `ring` is delivered to, the sender agrees with it from `tx_sk`.
    fn ring_change_key(&self, ring: &Address) -> Result<X25519Pubkey, RingKeyError>;

    /// The deposit tags of the current viewing key, one per counter.
    fn sender_view_tags(&self, counters: &[u64]) -> Result<Vec<ViewTag>, RingKeyError>;
}

impl RingKeys for ShieldedKeypair {
    fn ring_address_keys(
        &self,
        ring: &Address,
        indexes: &[u32],
    ) -> Result<Vec<X25519Pubkey>, RingKeyError> {
        indexes
            .iter()
            .map(|index| Ok(self.viewing_key.ring_address_key(ring, *index)?.pubkey()))
            .collect()
    }

    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, RingKeyError> {
        requests
            .iter()
            .map(|request| {
                let recipient = match request.recipient {
                    RingRecipientKey::Viewing(pubkey) if pubkey == self.viewing_key.pubkey() => {
                        self.viewing_key.clone()
                    }
                    RingRecipientKey::Viewing(_) => return Err(RingKeyError::UnknownViewingKey),
                    RingRecipientKey::Address { ring, index } => {
                        self.viewing_key.ring_address_key(&ring, index)?
                    }
                };
                let agreement = recipient.ecdh(&request.tx_viewing_pk)?;
                let secret = DeliveredSlot {
                    agreement: &agreement,
                    tx_viewing_pk: request.tx_viewing_pk.as_bytes(),
                    recipient_viewing_pk: recipient.pubkey().as_bytes(),
                    salt: &request.salt,
                    output_index: request.output_index,
                    first_nullifier: &request.first_nullifier,
                }
                .secret()?;
                Ok(*secret.as_bytes())
            })
            .collect()
    }

    fn ring_change_key(&self, ring: &Address) -> Result<X25519Pubkey, RingKeyError> {
        Ok(self.viewing_key.ring_change_key(ring)?.pubkey())
    }

    fn sender_view_tags(&self, counters: &[u64]) -> Result<Vec<ViewTag>, RingKeyError> {
        counters
            .iter()
            .map(|counter| Ok(self.viewing_key.get_sender_view_tag(*counter)?))
            .collect()
    }
}
