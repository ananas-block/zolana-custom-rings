//! Confidential ring notes of scheme 13 and ring deposits opened into a wallet, the pinned zolana scan skips them.

use std::collections::HashSet;

use custom_ring_interface::{ring_body_output, stream::slot_tag};
use solana_address::Address;
use spr_client::{AsyncRpc, IndexerRpcConfig};
use spr_keypair::{KeypairError, ShieldedAddress};
use spr_transaction::{
    verify_owned, DecryptionResult, OwnedUtxos, ShieldedKeys, ShieldedTransaction,
    TransactionError, WalletUtxo,
};
use zolana_ring_keys::{MergeSeedHolder, RingKeys};
use zolana_ring_transaction::{open_recipient_body, AnonymousOutput, OpenedBody, RingAssets};

use crate::{
    anonymous::{published_note, AnonymousSync, AuditorRecovery},
    anonymous_wallet::PendingNote,
    delivered::{
        assign_nullifiers, confidential_delivered, RingDeliveredCandidate, RingDeliveryContext,
    },
    deposit::{DepositOpener, OpenedDeposit},
    deposit_payload,
    exposed_notes::{verify_ring_owned, RingOwnedUtxos},
    tags::IndexerReads,
    viewing_history::ViewingHistory,
    AnonymousError,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingConfidentialNotes {
    pub owned: OwnedUtxos,
    /// Unspent zero-key notes, outside `owned` and every automatic path.
    pub exposed_if_spent: Vec<WalletUtxo>,
}

/// What a read of the whole ring opened with no tag read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingFullScan {
    pub owned: RingOwnedUtxos,
    pub pending: Vec<PendingNote>,
    pub auditor_recovery: AuditorRecovery,
}

/// Reads the spends of the notes it opens and the ring merges among them, the scanned transactions alone miss a spend without change.
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
        let mut reads = IndexerReads::configured(indexer, self.config);
        // A delivered slot publishes the short tag, a read by the full key never reaches it.
        let slot_tags: Vec<[u8; 32]> = self
            .keys
            .viewing_public_keys()
            .iter()
            .map(|key| slot_tag(key.u()))
            .collect();
        let delivered = reads.tagged(&slot_tags).await?;
        let read: Vec<ShieldedTransaction> = transactions
            .iter()
            .cloned()
            .chain(delivered.into_iter().filter(|tx| {
                !transactions
                    .iter()
                    .any(|known| known.tx_signature == tx.tx_signature)
            }))
            .collect();
        let mut notes = self.open(&read)?;
        let mut queried = HashSet::new();
        loop {
            let unread: Vec<[u8; 32]> = notes
                .owned
                .utxos
                .iter()
                .map(|utxo| utxo.nullifier)
                .filter(|nullifier| !notes.owned.spent.contains(nullifier))
                .chain(notes.exposed_if_spent.iter().map(|utxo| utxo.nullifier))
                .filter(|nullifier| queried.insert(*nullifier))
                .collect();
            if unread.is_empty() {
                return Ok(notes);
            }
            let spends = reads.spends(&unread).await?;
            let read: HashSet<[u8; 32]> = spends
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied())
                .collect();
            notes
                .exposed_if_spent
                .retain(|utxo| !read.contains(&utxo.nullifier));
            notes.owned.spent.extend(
                unread
                    .into_iter()
                    .filter(|nullifier| read.contains(nullifier)),
            );
            let merged = verify_owned(
                self.keys,
                &RingMerges::among(spends).open(self.keys, self.assets)?,
            )?;
            for utxo in merged.utxos {
                if !notes
                    .owned
                    .utxos
                    .iter()
                    .any(|held| held.utxo_hash == utxo.utxo_hash)
                {
                    notes.owned.utxos.push(utxo);
                }
            }
            notes
                .owned
                .unknown_asset_ids
                .extend(merged.unknown_asset_ids);
            notes.owned.unknown_mints.extend(merged.unknown_mints);
        }
    }

    /// Spent state covers `transactions` alone, a malformed audit capsule skips its deposit.
    pub fn open(
        &self,
        transactions: &[ShieldedTransaction],
    ) -> Result<RingConfidentialNotes, AnonymousError> {
        let address = self.keys.address()?;
        let candidates = confidential_delivered(self.keys, transactions)?;
        let mut decrypted = DecryptionResult {
            spent_nullifiers: transactions
                .iter()
                .flat_map(|tx| tx.nullifiers.iter().copied())
                .collect(),
            ..DecryptionResult::default()
        };
        for candidate in &candidates {
            match open_recipient_candidate(&address, self.assets, candidate)? {
                Some(OpenedBody::Note(note)) => decrypted.utxos.push(published_note(
                    candidate.tx,
                    candidate.slot_index as usize,
                    note,
                )?),
                Some(OpenedBody::UnknownMint(note)) => {
                    decrypted.unknown_mints.insert(note.utxo.asset.asset);
                }
                None => {}
            }
        }
        assign_nullifiers(self.keys, &mut decrypted.utxos)?;
        let opener = DepositOpener {
            keys: self.keys,
            address: &address,
            assets: self.assets.registry(),
            deposit_payload,
        };
        for opened in opener.open_held(transactions)? {
            match opened {
                OpenedDeposit::Note(utxo) => decrypted.utxos.push(*utxo),
                OpenedDeposit::UnknownMint(held) => {
                    decrypted.unknown_mints.insert(held.utxo.asset.asset);
                }
            }
        }
        let RingOwnedUtxos {
            owned,
            exposed_if_spent,
            ..
        } = verify_ring_owned(self.keys, &decrypted)?;
        Ok(RingConfidentialNotes {
            owned,
            exposed_if_spent,
        })
    }
}

impl<K: ShieldedKeys + RingKeys + MergeSeedHolder + ?Sized> RingConfidentialScan<'_, K> {
    /// A wrong tag hides nothing here, every held key tries every site of `ring`.
    pub async fn full_scan<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        ring: Address,
    ) -> Result<RingFullScan, AnonymousError> {
        let mut held = self.keys.viewing_public_keys().into_iter().rev();
        let current = held.next().ok_or(AnonymousError::HeldKeyNotInHistory)?;
        let history = held
            .zip(1..)
            .try_fold(
                ViewingHistory::new(current, 0),
                |history, (key, created_at)| history.with_rotated_key(key, created_at),
            )?
            .with_ring(ring, None);
        let sync = AnonymousSync::new(self.keys, self.assets);
        let sync = match self.config {
            Some(config) => sync.with_indexer_config(config),
            None => sync,
        };
        let scan = sync.full_scan(indexer, &history, ring).await?;
        Ok(RingFullScan {
            owned: verify_ring_owned(self.keys, scan.decrypted())?,
            pending: scan.pending_notes().to_vec(),
            auditor_recovery: scan.auditor_recovery,
        })
    }
}

/// Spent state covers `transactions` alone.
pub fn open_ring_confidential<K: ShieldedKeys + RingKeys + ?Sized>(
    keys: &K,
    assets: &RingAssets,
    transactions: &[ShieldedTransaction],
) -> Result<RingConfidentialNotes, AnonymousError> {
    RingConfidentialScan::new(keys, assets).open(transactions)
}

/// `None` off scheme 13 or on a body that rebuilds nothing.
fn open_recipient_candidate(
    address: &ShieldedAddress,
    assets: &RingAssets,
    candidate: &RingDeliveredCandidate<'_>,
) -> Result<Option<OpenedBody>, AnonymousError> {
    let tx = candidate.tx;
    let Some(slot) = tx.output_slots.get(candidate.slot_index as usize) else {
        return Ok(None);
    };
    let (Some((ciphertext, _)), Some(context)) =
        (ring_body_output(&slot.payload), RingDeliveryContext::of(tx))
    else {
        return Ok(None);
    };
    let Ok(body) = open_recipient_body(ciphertext, &candidate.slot_secret) else {
        return Ok(None);
    };
    Ok(AnonymousOutput {
        ring: context.ring,
        owner: address,
        utxo_hash: &slot.output_context.hash,
        tree_id: slot.output_context.tree_id,
        assets,
    }
    .open_body(&body)
    .unwrap_or(None))
}

pub(crate) struct RingMerges(pub Vec<ShieldedTransaction>);

impl RingMerges {
    pub(crate) fn among(spends: Vec<ShieldedTransaction>) -> Self {
        Self(
            spends
                .into_iter()
                .filter(|tx| tx.ring_program_id.is_some() && tx.may_be_merge())
                .collect(),
        )
    }

    pub(crate) fn open<K: ShieldedKeys + ?Sized>(
        &self,
        keys: &K,
        assets: &RingAssets,
    ) -> Result<DecryptionResult, AnonymousError> {
        let mut opened = DecryptionResult::default();
        for merge in &self.0 {
            match opened.extend(keys, core::slice::from_ref(merge), assets.registry()) {
                Ok(()) => {}
                // A merge output outside the field opens to nothing.
                Err(TransactionError::Keypair(KeypairError::Poseidon(_))) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(opened)
    }
}

#[cfg(test)]
mod tests {
    use solana_address::Address;
    use solana_signature::Signature;
    use spr_event::{encode_merge_output_data, MergeCiphertextBinding, MergeOutputDataRef};
    use spr_keypair::{ShieldedKeypair, SigningKey};
    use spr_transaction::{
        instructions::merge::{merge_output_blinding, merge_output_key, MergeOutputPlaintext},
        Mint, OutputContext, OutputSlot, Utxo,
    };

    use super::*;

    const RING: Address = Address::new_from_array([0x90; 32]);

    /// `merge_ring_v2` under a nonzero key, the proven encoding and its first nullifier tag.
    #[test]
    fn a_proven_ring_merge_opens_under_the_nullifier_secret() {
        let owner =
            ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[7; 32])).unwrap();
        let address = owner.shielded_address().unwrap();
        let first = [0x11; 32];
        let salt = [8; 16];
        let merged = Utxo {
            owner: address.signing_pubkey,
            asset: Mint::SOL,
            amount: 100,
            blinding: merge_output_blinding(&owner.nullifier_key, &first).unwrap(),
            ring_program_id: Some(RING),
            data: Default::default(),
        };
        let hash = merged
            .hash(&address.nullifier_pubkey, &[0; 32], &[0; 32], 9)
            .unwrap();
        let ciphertext = MergeOutputPlaintext {
            amount: 100,
            mint: Mint::SOL.asset,
        }
        .encrypt(
            &merge_output_key(&owner.nullifier_key, &first).unwrap(),
            &salt,
        )
        .unwrap();
        let row = ShieldedTransaction {
            slot: 1,
            tx_signature: Signature::from([1; 64]),
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: first,
                output_context: OutputContext {
                    hash,
                    tree_id: 9,
                    leaf_index: 0,
                },
                payload: encode_merge_output_data(MergeOutputDataRef {
                    salt: &salt,
                    ciphertext: &ciphertext,
                    prefix: &[[0; 32]],
                    binding: MergeCiphertextBinding::Proven,
                }),
            }],
            messages: Vec::new(),
            nullifiers: vec![first],
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        };
        let assets = RingAssets::new([]).unwrap();
        let opened = RingMerges::among(vec![row]).open(&owner, &assets).unwrap();
        assert_eq!(
            opened
                .utxos
                .iter()
                .map(|utxo| utxo.utxo_hash)
                .collect::<Vec<_>>(),
            [hash]
        );
    }
}
