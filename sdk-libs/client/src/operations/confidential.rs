//! Confidential ring notes of schemes 10 and 11 opened into a wallet, the pinned zolana scan skips both.

use std::collections::HashSet;

use custom_ring_interface::{ring_confidential_packed_output_body, RingPackedBody};
use spr_client::{AsyncRpc, IndexerRpcConfig};
use spr_keypair::{KeypairError, ShieldedAddress};
use zolana_ring_keys::RingKeys;
use zolana_ring_transaction::{RingAssets, RingPackedPlaintext};
use spr_transaction::{
    serialization::confidential::Confidential, verify_owned, DecryptLabel, DecryptRequest,
    DecryptionResult, OwnedUtxos, ShieldedKeys, ShieldedTransaction, TransactionError, Utxo,
    WalletUtxo,
};

use crate::{
    delivered::{confidential_delivered, open_delivered, PendingUtxo},
    exactly_one_each,
    tags::IndexerReads,
    AnonymousError,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingConfidentialNotes {
    pub owned: OwnedUtxos,
    /// Scheme 10 notes whose commitment no held mint rebuilds.
    pub pending: Vec<PendingUtxo>,
}

/// Reads the spends of the notes it opens, the scanned transactions alone miss a spend without change.
#[must_use]
pub struct RingConfidentialScan<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a RingAssets,
    config: Option<IndexerRpcConfig>,
}

impl<'a, K: ShieldedKeys + RingKeys + ?Sized> RingConfidentialScan<'a, K> {
    pub fn new(keys: &'a K, assets: &'a RingAssets) -> Self {
        Self {
            keys,
            assets,
            config: None,
        }
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub async fn fetch<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        transactions: &[ShieldedTransaction],
    ) -> Result<RingConfidentialNotes, AnonymousError> {
        let mut notes = open_ring_confidential(self.keys, self.assets, transactions)?;
        let unread: Vec<[u8; 32]> = notes
            .owned
            .utxos
            .iter()
            .map(|utxo| utxo.nullifier)
            .filter(|nullifier| !notes.owned.spent.contains(nullifier))
            .collect();
        if unread.is_empty() {
            return Ok(notes);
        }
        let spends = IndexerReads::configured(indexer, self.config)
            .spends(&unread)
            .await?;
        let read: HashSet<[u8; 32]> = spends
            .iter()
            .flat_map(|tx| tx.nullifiers.iter().copied())
            .collect();
        notes.owned.spent.extend(
            unread
                .into_iter()
                .filter(|nullifier| read.contains(nullifier)),
        );
        Ok(notes)
    }
}

/// Spent state covers `transactions` alone.
pub fn open_ring_confidential<K: ShieldedKeys + RingKeys + ?Sized>(
    keys: &K,
    assets: &RingAssets,
    transactions: &[ShieldedTransaction],
) -> Result<RingConfidentialNotes, AnonymousError> {
    let address = keys.address()?;
    let delivered = open_delivered(
        &address,
        assets,
        &confidential_delivered(keys, transactions)?,
    )?;
    let mut decrypted = DecryptionResult {
        utxos: delivered.found,
        spent_nullifiers: transactions
            .iter()
            .flat_map(|tx| tx.nullifiers.iter().copied())
            .collect(),
        ..DecryptionResult::default()
    };
    for tx in transactions {
        packed_notes(keys, &address, assets, tx, &mut decrypted)?;
    }
    Ok(RingConfidentialNotes {
        owned: verify_owned(keys, &decrypted)?,
        pending: delivered.pending,
    })
}

/// Scheme 3's key schedule under the embedded recipient key, `verify_owned` checks the commitment.
fn packed_notes<K: ShieldedKeys + ?Sized>(
    keys: &K,
    address: &ShieldedAddress,
    assets: &RingAssets,
    tx: &ShieldedTransaction,
    decrypted: &mut DecryptionResult,
) -> Result<(), AnonymousError> {
    let (Some(ring), Some(tx_viewing_pubkey), Some(salt)) =
        (tx.ring_program_id, tx.tx_viewing_pk, tx.salt)
    else {
        return Ok(());
    };
    let held = keys.viewing_public_keys();
    let mut sites = Vec::new();
    let mut requests = Vec::new();
    for (position, slot) in tx.output_slots.iter().enumerate() {
        let Some(RingPackedBody { key, ciphertext }) =
            ring_confidential_packed_output_body(&slot.payload)
        else {
            continue;
        };
        let Ok(viewing_pubkey) = Confidential::embedded_viewing_pk(key) else {
            continue;
        };
        if !held.contains(&viewing_pubkey) {
            continue;
        }
        let slot_index = u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?;
        sites.push((slot, slot_index));
        requests.push(DecryptRequest {
            ciphertext,
            viewing_pubkey,
            tx_viewing_pubkey,
            salt,
            slot_index,
            label: DecryptLabel::Utxo,
        });
    }
    if requests.is_empty() {
        return Ok(());
    }
    let plaintexts = match keys.decrypt(&requests) {
        Ok(plaintexts) => exactly_one_each(plaintexts, requests.len())?,
        // The sender picks `tx_viewing_pk`, a low-order one opens under no key.
        Err(TransactionError::Keypair(KeypairError::NonContributoryKey)) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for ((slot, slot_index), bytes) in sites.into_iter().zip(plaintexts) {
        let Ok(plaintext) = RingPackedPlaintext::deserialize(&bytes) else {
            continue;
        };
        let asset = match assets.registry().resolve(plaintext.asset_id) {
            Ok(asset) => asset,
            Err(TransactionError::UnknownAsset(asset_id)) => {
                decrypted.unknown_asset_ids.insert(asset_id);
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let context = &slot.output_context;
        decrypted.utxos.push(WalletUtxo {
            utxo: Utxo {
                owner: address.signing_pubkey,
                asset,
                amount: plaintext.amount,
                blinding: plaintext.blinding,
                ring_program_id: Some(ring),
                data: plaintext.data,
            },
            nullifier_pubkey: address.nullifier_pubkey,
            utxo_hash: context.hash,
            nullifier: [0; 32],
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: None,
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
            latest_tree_id: None,
            slot: tx.slot,
            tx_signature: tx.tx_signature,
            slot_index,
        });
    }
    Ok(())
}
