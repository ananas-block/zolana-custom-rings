//! A wallet of one anonymous ring, the default-ring scan and the ring's own streams kept in memory.

use anyhow::Result;
use solana_address::Address;
use zolana_client::{IndexerRpcConfig, Rpc, UtxoScan};
use zolana_keypair::ShieldedKeypair;
use zolana_ring_client::{AnonymousRingState, AnonymousRingSync};
use zolana_ring_transaction::RingAssets;
use zolana_transaction::{verify_owned, SpendableDecryptionResult, WalletUtxo};

use crate::shared::TestEnv;

pub struct RingWallet<'a> {
    keys: &'a ShieldedKeypair,
    assets: RingAssets,
    ring: Address,
    pub state: AnonymousRingState,
    kept: Vec<WalletUtxo>,
    spendable: SpendableDecryptionResult,
}

impl<'a> RingWallet<'a> {
    pub fn new(keys: &'a ShieldedKeypair, assets: RingAssets, state: AnonymousRingState) -> Self {
        Self {
            keys,
            ring: state.ring(),
            assets,
            state,
            kept: Vec::new(),
            spendable: SpendableDecryptionResult::default(),
        }
    }

    /// Reads the default ring and every stream of the ring at the indexer's tip.
    pub fn sync(&mut self, env: &TestEnv) -> Result<()> {
        let config = IndexerRpcConfig::at_slot(env.client.rpc().get_slot()?);
        let owned = UtxoScan::new(self.keys, self.assets.registry())
            .with_ring_deposit_payload(self.ring, zolana_ring_client::deposit_payload)
            .with_indexer_config(config)
            .fetch(env.client.indexer())?;
        let slot = env.client.rpc().get_slot()?;
        let synced = env.client.block_on(async {
            AnonymousRingSync::new(self.keys, &self.assets)
                .with_indexer_config(config)
                .with_deposit_payload(zolana_ring_client::deposit_payload)
                .with_held_utxos(owned.history.utxos.iter().chain(&self.kept))
                .with_default_ring_spends(owned.history.transactions.clone())
                .fetch(env.client.as_async().indexer(), &self.state, slot)
                .await
                .map_err(anyhow::Error::from)
        })?;
        let found = verify_owned(self.keys, &synced.decrypted)?.spendable();
        let spent = &synced.decrypted.spent_nullifiers;
        self.kept.retain(|utxo| !spent.contains(&utxo.nullifier));
        for utxo in found.utxos() {
            if !self
                .kept
                .iter()
                .any(|kept| kept.utxo_hash == utxo.utxo_hash)
            {
                self.kept.push(utxo.clone());
            }
        }
        self.state = synced.state;
        let mut spendable = owned.spendable;
        for utxo in &self.kept {
            if !spendable
                .utxos()
                .any(|held| held.utxo_hash == utxo.utxo_hash)
            {
                spendable.utxos_with_data.push(utxo.clone());
            }
        }
        self.spendable = spendable;
        Ok(())
    }

    pub fn unspent(&self) -> impl Iterator<Item = &WalletUtxo> {
        self.spendable.utxos()
    }

    pub fn is_spent(&self, utxo: &WalletUtxo) -> bool {
        !self.unspent().any(|held| held.utxo_hash == utxo.utxo_hash)
    }
}
