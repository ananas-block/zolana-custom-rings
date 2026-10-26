//! Confidential ring notes of scheme 10 opened into a wallet, the pinned zolana scan skips them.

use std::collections::HashSet;

use zolana_client::{AsyncRpc, IndexerRpcConfig};
use zolana_ring_keys::RingKeys;
use zolana_ring_transaction::RingAssets;
use zolana_transaction::{
    verify_owned, DecryptionResult, OwnedUtxos, ShieldedKeys, ShieldedTransaction,
};

use crate::{
    delivered::{confidential_delivered, open_delivered, PendingUtxo},
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
    let decrypted = DecryptionResult {
        utxos: delivered.found,
        spent_nullifiers: transactions
            .iter()
            .flat_map(|tx| tx.nullifiers.iter().copied())
            .collect(),
        ..DecryptionResult::default()
    };
    Ok(RingConfidentialNotes {
        owned: verify_owned(keys, &decrypted)?,
        pending: delivered.pending,
    })
}
