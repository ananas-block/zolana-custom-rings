//! Delivered ring output bodies of scheme 10 under the stream of a CRDS slot secret, mirrored by
//! Go `prover/circuits/audit`.

use custom_ring_interface::{
    domain::DELIVERED_BODY_LABEL, stream::SlotSecret, DeliveredBody, ESCROWED_DELIVERED_BODY_LEN,
};
use solana_address::Address;
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{PublicKey, X25519Keypair, X25519Pubkey};
use spr_transaction::{Data, Mint, Utxo};
use zeroize::Zeroizing;
use zolana_ring_keys::symmetric_apply_audit;

use crate::{RingAssets, RingRailError};

/// One slot secret keys one body, the secret binds the slot and the first nullifier.
pub fn seal_delivered_body(
    body: &DeliveredBody,
    slot_secret: &SlotSecret,
) -> Result<Vec<u8>, RingRailError> {
    let mut ciphertext = body.encode();
    symmetric_apply_audit(
        slot_secret.as_bytes(),
        DELIVERED_BODY_LABEL,
        &mut ciphertext,
    )?;
    Ok(ciphertext)
}

/// The cipher is unauthenticated, the caller compares the opened keys and rebuilds the commitment.
pub fn open_delivered_body(
    ciphertext: &[u8],
    slot_secret: &SlotSecret,
) -> Result<DeliveredBody, RingRailError> {
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    symmetric_apply_audit(slot_secret.as_bytes(), DELIVERED_BODY_LABEL, &mut plaintext)?;
    let key_escrow = plaintext.len() == ESCROWED_DELIVERED_BODY_LEN;
    Ok(DeliveredBody::decode(&plaintext, key_escrow)?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingUtxoOwner<'a> {
    pub signing_pubkey: &'a PublicKey,
    pub nullifier_pubkey: &'a [u8; 32],
}

/// One published delivered body and the secret its recipient agreed for it.
#[derive(Clone, Copy)]
pub struct RingDeliveryOpening<'a> {
    pub ring: Address,
    pub body: &'a [u8],
    pub slot_secret: &'a SlotSecret,
    pub owner: RingUtxoOwner<'a>,
    /// The published commitment and the tree it was appended to.
    pub commitment: &'a [u8; 32],
    pub tree_id: u16,
}

/// A delivered note opened to everything its commitment binds but the asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDeliveredNote {
    pub owner: PublicKey,
    pub nullifier_pubkey: [u8; 32],
    pub ring: Address,
    pub body: DeliveredBody,
    pub utxo_hash: [u8; 32],
    pub tree_id: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDelivered {
    pub note: RingDeliveredNote,
    /// `None` while no held asset rebuilds the commitment.
    pub mint: Option<Mint>,
}

impl RingDeliveryOpening<'_> {
    /// `None` for keys other than the owner's and zero, a blinding outside the field or a zero
    /// amount in no held asset, a commitment rebuilt under a sender's choice of keys proves no ownership.
    pub fn open(self, assets: &RingAssets) -> Result<Option<RingDelivered>, RingRailError> {
        let body = open_delivered_body(self.body, self.slot_secret)?;
        let own_key = *self.owner.nullifier_pubkey;
        let foreign = body.owner_key != self.owner.signing_pubkey.confidential_view_tag()?
            || body.nullifier_pk.is_some_and(|nullifier_pk| {
                nullifier_pk != own_key && nullifier_pk != ZERO_NULLIFIER_PUBKEY
            });
        if foreign || !is_canonical_bn254_scalar_be(&body.blinding) {
            return Ok(None);
        }
        let note_under = |nullifier_pubkey| RingDeliveredNote {
            owner: *self.owner.signing_pubkey,
            nullifier_pubkey,
            ring: self.ring,
            body: body.clone(),
            utxo_hash: *self.commitment,
            tree_id: self.tree_id,
        };
        // An escrowed body names no key, an old zero-key note stays readable after enrollment.
        let candidates = match body.nullifier_pk {
            Some(named) => [named, named],
            None => [own_key, ZERO_NULLIFIER_PUBKEY],
        };
        for candidate in candidates {
            let note = note_under(candidate);
            if let Some(mint) = note.resolve(assets)? {
                return Ok(Some(RingDelivered {
                    note,
                    mint: Some(mint),
                }));
            }
        }
        let note = note_under(candidates[0]);
        Ok((note.body.amount != 0).then_some(RingDelivered { note, mint: None }))
    }
}

impl RingDeliveredNote {
    pub fn resolve(&self, assets: &RingAssets) -> Result<Option<Mint>, RingRailError> {
        for mint in assets.mints() {
            let utxo = self.utxo(*mint);
            let hash = utxo.hash(&self.nullifier_pubkey, &[0; 32], &[0; 32], self.tree_id)?;
            if hash == self.utxo_hash {
                return Ok(Some(*mint));
            }
        }
        Ok(None)
    }

    pub fn utxo(&self, asset: Mint) -> Utxo {
        Utxo {
            owner: self.owner,
            asset,
            amount: self.body.amount,
            blinding: self.body.blinding,
            ring_program_id: Some(self.ring),
            data: Data::default(),
        }
    }
}

/// False for a low-order transaction key, every clamped secret refuses the same keys.
pub fn is_contributory(tx_viewing_pk: &X25519Pubkey) -> bool {
    X25519Keypair::from_bytes(&[0; 32])
        .ecdh(tx_viewing_pk)
        .is_ok()
}
