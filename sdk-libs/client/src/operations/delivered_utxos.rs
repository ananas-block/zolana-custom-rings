//! Slot secrets of the ring outputs under a wallet's viewing keys.

use std::collections::HashMap;

use custom_ring_interface::{
    ring_body_output,
    stream::{slot_tag, SlotSecret},
};
use solana_address::Address;
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::{NullifierKey, X25519Pubkey};
use spr_transaction::{
    DeriveRequest, ShieldedKeys, ShieldedTransaction, TransactionError, WalletUtxo,
};
use zolana_ring_keys::{RingDeliveryRequest, RingKeys};
use zolana_ring_transaction::is_contributory;

use crate::{exactly_one_each, is_zero_key, AnonymousError};

/// One delivered ring output and the slot secret its recipient agreed for it.
#[derive(Clone)]
pub struct RingDeliveredCandidate<'a> {
    pub tx: &'a ShieldedTransaction,
    pub slot_index: u32,
    pub slot_secret: SlotSecret,
}

/// What every delivered slot secret of one ring transaction binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveryContext {
    pub ring: Address,
    pub tx_viewing_pk: X25519Pubkey,
    pub salt: [u8; 16],
    pub first_nullifier: [u8; 32],
}

impl RingDeliveryContext {
    /// `None` without a ring, a contributory key, a salt or a canonical first nullifier.
    #[must_use]
    pub fn of(tx: &ShieldedTransaction) -> Option<Self> {
        let context = Self {
            ring: tx.ring_program_id?,
            tx_viewing_pk: tx.tx_viewing_pk?,
            salt: tx.salt?,
            first_nullifier: *tx.nullifiers.first()?,
        };
        (is_contributory(&context.tx_viewing_pk)
            && is_canonical_bn254_scalar_be(&context.first_nullifier))
        .then_some(context)
    }
}

/// Scheme 13 slots under the wallet's viewing keys.
pub fn confidential_delivered<'a, K: ShieldedKeys + RingKeys + ?Sized>(
    shielded_keys: &K,
    transactions: &'a [ShieldedTransaction],
) -> Result<Vec<RingDeliveredCandidate<'a>>, AnonymousError> {
    let held: HashMap<[u8; 32], X25519Pubkey> = shielded_keys
        .viewing_public_keys()
        .into_iter()
        .map(|pubkey| (slot_tag(pubkey.u()), pubkey))
        .collect();
    let mut sites = Vec::new();
    let mut requests = Vec::new();
    for tx in transactions {
        let Some(RingDeliveryContext {
            tx_viewing_pk,
            salt,
            first_nullifier,
            ..
        }) = RingDeliveryContext::of(tx)
        else {
            continue;
        };
        for (position, slot) in tx.output_slots.iter().enumerate() {
            let Some(&viewing_pubkey) = held.get(&slot.view_tag) else {
                continue;
            };
            if ring_body_output(&slot.payload).is_none() {
                continue;
            }
            let output_index =
                u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?;
            sites.push((tx, output_index));
            requests.push(RingDeliveryRequest {
                viewing_pubkey,
                tx_viewing_pk,
                salt,
                output_index,
                first_nullifier,
            });
        }
    }
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let secrets = exactly_one_each(
        shielded_keys.ring_delivery_secrets(&requests)?,
        requests.len(),
    )?;
    sites
        .into_iter()
        .zip(secrets)
        .map(|((tx, slot_index), secret)| {
            Ok(RingDeliveredCandidate {
                tx,
                slot_index,
                slot_secret: SlotSecret::new(secret)?,
            })
        })
        .collect()
}

pub(crate) fn assign_nullifiers<K: ShieldedKeys + ?Sized>(
    shielded_keys: &K,
    utxos: &mut [WalletUtxo],
) -> Result<(), AnonymousError> {
    if utxos.is_empty() {
        return Ok(());
    }
    let requests: Vec<_> = utxos
        .iter()
        .map(|input| DeriveRequest::Nullifier {
            utxo_hash: input.utxo_hash,
            blinding: input.utxo.blinding,
        })
        .collect();
    let nullifiers = exactly_one_each(shielded_keys.derive(&requests)?, utxos.len())?;
    let zero_secret = NullifierKey::from_secret([0; 31]);
    for (input, nullifier) in utxos.iter_mut().zip(nullifiers) {
        // A zero-key note spends under secret zero, never the wallet's.
        input.nullifier = match is_zero_key(input) {
            true => zero_secret.nullifier(&input.utxo_hash, &input.utxo.blinding)?,
            false => nullifier,
        };
    }
    Ok(())
}

/// Mirrors spr-transaction's private publication order.
pub(crate) fn sort_by_publication(utxos: &mut [WalletUtxo]) {
    utxos.sort_by_key(|utxo| {
        (
            utxo.slot,
            utxo.tx_signature.as_ref().to_vec(),
            utxo.slot_index,
        )
    });
}
