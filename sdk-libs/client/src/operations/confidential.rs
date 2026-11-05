//! Confidential ring notes and ring deposits opened into a wallet, the pinned zolana scan skips them.

use std::collections::HashSet;

use custom_ring_interface::{ring_body_output, stream::slot_tag};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{AsyncRpc, IndexerRpcConfig};
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::ShieldedAddress;
use spr_transaction::{
    verify_owned, DecryptionResult, OwnedUtxos, ShieldedKeys, ShieldedTransaction, WalletUtxo,
};
use zolana_ring_keys::{MergeSeedHolder, RingKeys};
use zolana_ring_transaction::{open_recipient_body, AnonymousOutput, OpenedBody, RingAssets};

use crate::{
    anonymous::{published_note, AnonymousSync, AuditorRecovery, OwnerMergeOpener},
    anonymous_wallet::PendingNote,
    delivered::{
        assign_nullifiers, confidential_delivered, RingDeliveredCandidate, RingDeliveryContext,
    },
    deposit::{DepositOpener, OpenedDeposit},
    deposit_payload,
    exposed_notes::{verify_ring_owned, RingOwnedUtxos},
    merge_audit::RingMergeBody,
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

impl<'a, K: ShieldedKeys + RingKeys + MergeSeedHolder + ?Sized> RingConfidentialScan<'a, K> {
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
        // 1. A delivered slot publishes the short tag and a zero-key merge its owner tag, a read by the full key reaches neither.
        // The owner tag finds a seeded merge with no input history, a spend read would miss it without the spent note.
        let owner_tag = self
            .keys
            .address()?
            .signing_pubkey
            .owner_proof_input_hash()?;
        let tags: Vec<[u8; 32]> = self
            .keys
            .viewing_public_keys()
            .iter()
            .map(|key| slot_tag(key.u()))
            .chain([owner_tag])
            .collect();
        let tagged = reads.tagged(&tags).await?;
        // 2. Every event read so far opens once. Later rounds follow only the spends of what opened here.
        let read = union_events(transactions, tagged);
        let mut notes = self.open(&read)?;
        // 3. Each round reads the spends of the notes the last one opened, until no unread nullifier remains.
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
        // 1. Every opening below is a candidate until step 4, rows from the caller or the indexer earn no trust here.
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
            if let Some(opened) = open_recipient_candidate(&address, self.assets, candidate)? {
                keep_opened(
                    &mut decrypted,
                    candidate.tx,
                    candidate.slot_index as usize,
                    opened,
                )?;
            }
        }
        // 2. A seeded merge opens from its row alone, the spent input may be absent from `transactions`.
        self.open_owner_merges(transactions, &mut decrypted)?;
        assign_nullifiers(self.keys, &mut decrypted.utxos)?;
        // 3. Deposits carry the key their commitment rebuilt under, step 4 sorts zero-key notes by it.
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
        // 4. Only a commitment rebuilt here under the owner proves a note, and a zero-key note stays out of `owned`.
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

    /// A rotated wallet's merge sits under the seed of the key it held then, every held key tries each row.
    fn open_owner_merges(
        &self,
        transactions: &[ShieldedTransaction],
        decrypted: &mut DecryptionResult,
    ) -> Result<(), AnonymousError> {
        let owner = self.keys.address()?.signing_pubkey;
        let opener = OwnerMergeOpener::new(self.keys, owner, self.assets)?;
        let held = self.keys.viewing_public_keys();
        for merge in transactions.iter().filter_map(|tx| opener.candidate(tx)) {
            for viewing_pubkey in &held {
                if let Some(opened) = opener.open(&merge, *viewing_pubkey)? {
                    keep_opened(decrypted, merge.tx, 0, opened)?;
                    break;
                }
            }
        }
        Ok(())
    }

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
pub fn open_ring_confidential<K: ShieldedKeys + RingKeys + MergeSeedHolder + ?Sized>(
    keys: &K,
    assets: &RingAssets,
    transactions: &[ShieldedTransaction],
) -> Result<RingConfidentialNotes, AnonymousError> {
    RingConfidentialScan::new(keys, assets).open(transactions)
}

/// One transaction can emit several relevant events, only its signature and event index name one.
fn union_events(
    known: &[ShieldedTransaction],
    tagged: Vec<ShieldedTransaction>,
) -> Vec<ShieldedTransaction> {
    let identity = |tx: &ShieldedTransaction| -> (Signature, Option<u16>) {
        (tx.tx_signature, tx.event_index)
    };
    let mut seen: HashSet<_> = known.iter().map(identity).collect();
    known
        .iter()
        .cloned()
        .chain(tagged.into_iter().filter(|tx| seen.insert(identity(tx))))
        .collect()
}

/// A note under an unregistered mint stays out of `utxos` and names its mint.
fn keep_opened(
    decrypted: &mut DecryptionResult,
    tx: &ShieldedTransaction,
    position: usize,
    opened: OpenedBody,
) -> Result<(), AnonymousError> {
    match opened {
        OpenedBody::Note(note) => decrypted.utxos.push(published_note(tx, position, note)?),
        OpenedBody::UnknownMint(note) => {
            decrypted.unknown_mints.insert(note.utxo.asset.asset);
        }
    }
    Ok(())
}

/// `None` off a ring body output or on a body that rebuilds nothing.
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

/// A row the merge readers may decode. The first nullifier and each ring data hash are the only published values
/// that reach Poseidon unreduced in a merge rebuild. The decoder skips a ciphertext element outside the field, packs
/// the mint and ring id in chunks below the modulus, and only compares the commitment. A malformed row stops here and
/// fails no read. A Poseidon error past here comes from the holder and fails the read, because a skip would let the
/// history position pass a note a retry would open.
pub(crate) fn is_ring_merge(tx: &ShieldedTransaction) -> bool {
    tx.ring_program_id.is_some()
        && tx.may_be_merge()
        && tx
            .nullifiers
            .first()
            .is_none_or(is_canonical_bn254_scalar_be)
        && tx
            .output_slots
            .iter()
            .filter_map(RingMergeBody::of)
            .all(|body| is_canonical_bn254_scalar_be(&body.ring_data_hash))
}

pub(crate) struct RingMerges(pub Vec<ShieldedTransaction>);

impl RingMerges {
    pub(crate) fn among(spends: Vec<ShieldedTransaction>) -> Self {
        Self(spends.into_iter().filter(is_ring_merge).collect())
    }

    pub(crate) fn open<K: ShieldedKeys + ?Sized>(
        &self,
        keys: &K,
        assets: &RingAssets,
    ) -> Result<DecryptionResult, AnonymousError> {
        let mut opened = DecryptionResult::default();
        opened.extend(keys, &self.0, assets.registry())?;
        Ok(opened)
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use custom_ring_interface::{
        encode_ring_body_output,
        stream::{DeliveredSlot, SlotSecret},
        RecipientBody,
    };
    use spr_client::{
        rpc::{Context, GetShieldedTransactionsByNullifiersResponse, HistoryFilters, Page},
        ClientError, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse,
        GetShieldedTransactionsByTagsResponse, OutputContext, OutputSlot, PaginationToken,
        RingHistoryOptions, TransactionEvents, TransactionOutputs,
    };
    use spr_event::{encode_merge_output_data, MergeCiphertextBinding, MergeOutputDataRef};
    use spr_interface::ZERO_NULLIFIER_PUBKEY;
    use spr_keypair::{
        viewing_key::ViewTag, KeypairError, NullifierKey, ShieldedKeypair, ViewingKey, X25519Pubkey,
    };
    use spr_transaction::{
        instructions::merge::{
            merge_output_blinding, merge_output_key, MergeOutputPlaintext, MergeSeed,
        },
        DecryptRequest, DeriveRequest, Mint, TransactionError, TransactionKeyRequest,
    };
    use zolana_ring_keys::{
        MergeSeedRequest, RingDeliveryRequest, RingKeyError, RingTagFrame, ViewTagRequest,
    };
    use zolana_ring_transaction::seal_recipient_body;

    use super::*;
    use crate::deposit::tests::{
        deposit_under, ring_note, ring_row, wallet, AMOUNT, RING, THIRD_KEY, TREE,
    };

    const NOT_IN_FIELD: [u8; 32] = [0xff; 32];

    /// Answers each read from one list, in the position order Photon pages.
    #[derive(Default)]
    struct Rows {
        rows: Vec<ShieldedTransaction>,
        deposits: Vec<EncryptedUtxoMatch>,
    }

    impl Rows {
        fn of(rows: Vec<ShieldedTransaction>) -> Self {
            Self {
                rows,
                deposits: Vec::new(),
            }
        }

        fn page(
            &self,
            matches: impl Fn(&ShieldedTransaction) -> bool,
        ) -> GetShieldedTransactionsByTagsResponse {
            let mut rows: Vec<ShieldedTransaction> =
                self.rows.iter().filter(|tx| matches(tx)).cloned().collect();
            rows.sort_by_key(|row| {
                (
                    PaginationToken::new(row.slot, row.tx_signature),
                    row.event_index,
                )
            });
            let mut data: Vec<TransactionEvents<ShieldedTransaction, Signature>> = Vec::new();
            for row in rows {
                match data.last_mut() {
                    Some(last) if last.signature == row.tx_signature && last.slot == row.slot => {
                        last.events.push(row)
                    }
                    _ => data.push(TransactionEvents {
                        slot: row.slot,
                        signature: row.tx_signature,
                        events: vec![row],
                    }),
                }
            }
            terminal(self.tip(), data)
        }

        fn tip(&self) -> u64 {
            let rows = self.rows.iter().map(|tx| tx.slot);
            rows.chain(self.deposits.iter().map(|deposit| deposit.slot))
                .max()
                .unwrap_or_default()
        }
    }

    fn terminal<T>(slot: u64, data: Vec<T>) -> Page<T> {
        Page {
            context: Context {
                block_time: 0,
                slot,
            },
            output_tree_id: Some(TREE),
            data,
            pagination_token: None,
        }
    }

    #[async_trait]
    impl AsyncRpc for Rows {
        async fn get_shielded_transactions_by_tags(
            &self,
            tags: Vec<[u8; 32]>,
            _pagination_token: Option<PaginationToken>,
            _limit: Option<u32>,
            _filters: HistoryFilters,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Ok(self.page(|tx| {
                tx.output_slots
                    .iter()
                    .any(|slot| tags.contains(&slot.view_tag))
            }))
        }

        async fn get_shielded_transactions_by_ring(
            &self,
            options: RingHistoryOptions,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Ok(self.page(|tx| tx.ring_program_id == Some(options.ring_program_id)))
        }

        async fn get_encrypted_utxos_by_tags(
            &self,
            tags: Vec<[u8; 32]>,
            _pagination_token: Option<PaginationToken>,
            _limit: Option<u32>,
            _filters: HistoryFilters,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
            let data = self
                .deposits
                .iter()
                .filter(|deposit| tags.contains(&deposit.output_slot.view_tag))
                .map(|deposit| TransactionOutputs {
                    slot: deposit.slot,
                    signature: deposit.tx_signature,
                    outputs: vec![deposit.clone()],
                })
                .collect();
            Ok(terminal(self.tip(), data))
        }

        async fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<[u8; 32]>,
            _pagination_token: Option<PaginationToken>,
            _limit: Option<u32>,
            _filters: HistoryFilters,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Ok(self.page(|tx| tx.nullifiers.iter().any(|spent| nullifiers.contains(spent))))
        }
    }

    #[derive(PartialEq)]
    enum HolderFailure {
        /// The error a bad published value raises.
        MergeOutputKey,
        MergeSeed,
    }

    /// Answers as its keypair does, except the call it fails.
    struct FailingHolder(ShieldedKeypair, HolderFailure);

    impl ShieldedKeys for FailingHolder {
        fn address(&self) -> Result<ShieldedAddress, TransactionError> {
            self.0.address()
        }

        fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
            self.0.viewing_public_keys()
        }

        fn decrypt(
            &self,
            requests: &[DecryptRequest<'_>],
        ) -> Result<Vec<Vec<u8>>, TransactionError> {
            self.0.decrypt(requests)
        }

        fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
            if self.1 == HolderFailure::MergeOutputKey
                && requests
                    .iter()
                    .any(|request| matches!(request, DeriveRequest::MergeOutputKey { .. }))
            {
                return Err(TransactionError::Keypair(KeypairError::Poseidon(1)));
            }
            self.0.derive(requests)
        }

        fn transaction_keys(
            &self,
            requests: &[TransactionKeyRequest],
        ) -> Result<Vec<ViewingKey>, TransactionError> {
            self.0.transaction_keys(requests)
        }
    }

    impl MergeSeedHolder for FailingHolder {
        fn merge_seeds(
            &self,
            requests: &[MergeSeedRequest],
        ) -> Result<Vec<MergeSeed>, RingKeyError> {
            if self.1 == HolderFailure::MergeSeed {
                return Err(RingKeyError::UnknownViewingKey);
            }
            self.0.merge_seeds(requests)
        }
    }

    impl RingKeys for FailingHolder {
        fn ring_delivery_secrets(
            &self,
            requests: &[RingDeliveryRequest],
        ) -> Result<Vec<[u8; 32]>, RingKeyError> {
            self.0.ring_delivery_secrets(requests)
        }

        fn ring_tag_matches(
            &self,
            frames: &[RingTagFrame],
        ) -> Result<Vec<Vec<Option<SlotSecret>>>, RingKeyError> {
            self.0.ring_tag_matches(frames)
        }

        fn view_tags(&self, requests: &[ViewTagRequest]) -> Result<Vec<ViewTag>, RingKeyError> {
            self.0.view_tags(requests)
        }
    }

    fn assets() -> RingAssets {
        RingAssets::new([]).unwrap()
    }

    fn hashes(notes: &[WalletUtxo]) -> Vec<[u8; 32]> {
        notes.iter().map(|note| note.utxo_hash).collect()
    }

    fn deposit_hash(deposit: &EncryptedUtxoMatch) -> [u8; 32] {
        deposit.output_slot.output_context.hash
    }

    /// A row with no transaction key or salt, spending `first`.
    fn merge_row(slot: OutputSlot, first: [u8; 32]) -> ShieldedTransaction {
        ShieldedTransaction {
            tx_signature: Signature::from([first[0]; 64]),
            slot: 2,
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![slot],
            messages: Vec::new(),
            nullifiers: vec![first],
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }

    fn output_context(hash: [u8; 32]) -> OutputContext {
        OutputContext {
            hash,
            tree_id: TREE,
            leaf_index: 0,
        }
    }

    fn merge_payload(key: &[u8; 32], published: [u8; 32]) -> Vec<u8> {
        let salt = [8; 16];
        let ciphertext = MergeOutputPlaintext {
            amount: AMOUNT,
            mint: Mint::SOL.asset,
        }
        .encrypt(key, &salt)
        .unwrap();
        encode_merge_output_data(MergeOutputDataRef {
            salt: &salt,
            ciphertext: &ciphertext,
            prefix: &[published],
            binding: MergeCiphertextBinding::Proven,
        })
    }

    struct ProvenMerge {
        /// Enters the commitment, the proof holds the published value to it.
        committed: [u8; 32],
        published: [u8; 32],
    }

    impl ProvenMerge {
        /// The row of `merge_ring_v2` under `owner`'s nonzero key and the utxo hash it commits.
        fn row(self, owner: &ShieldedKeypair, first: [u8; 32]) -> ([u8; 32], ShieldedTransaction) {
            let address = owner.shielded_address().unwrap();
            let blinding = merge_output_blinding(&owner.nullifier_key, &first).unwrap();
            let hash = ring_note(&address, blinding)
                .hash(&address.nullifier_pubkey, &[0; 32], &self.committed, TREE)
                .unwrap();
            let key = merge_output_key(&owner.nullifier_key, &first).unwrap();
            let slot = OutputSlot {
                view_tag: first,
                output_context: output_context(hash),
                payload: merge_payload(&key, self.published),
            };
            (hash, merge_row(slot, first))
        }

        /// The utxo hash the row commits and what its owner opens from the row.
        fn opened(self) -> ([u8; 32], Vec<[u8; 32]>) {
            let owner = wallet(7);
            let (hash, row) = self.row(&owner, [0x11; 32]);
            let opened = RingMerges::among(vec![row])
                .open(&owner, &assets())
                .unwrap();
            (hash, hashes(&opened.utxos))
        }
    }

    /// A zero-key merge under `owner`'s tag, encrypted to `seed`, its commitment and row.
    fn seeded_merge(
        owner: &ShieldedAddress,
        seed: &MergeSeed,
        first: [u8; 32],
    ) -> ([u8; 32], ShieldedTransaction) {
        let hash = ring_note(owner, seed.output_blinding(&first).unwrap())
            .hash(&ZERO_NULLIFIER_PUBKEY, &[0; 32], &[0; 32], TREE)
            .unwrap();
        let slot = OutputSlot {
            view_tag: owner.signing_pubkey.owner_proof_input_hash().unwrap(),
            output_context: output_context(hash),
            payload: merge_payload(&seed.output_key(&first).unwrap(), [0; 32]),
        };
        (hash, merge_row(slot, first))
    }

    fn own_seed(keys: &ShieldedKeypair, first: [u8; 32]) -> MergeSeed {
        keys.merge_seeds(&[MergeSeedRequest {
            viewing_pubkey: keys.viewing_pubkey(),
            ring_program_id: RING,
            first_nullifier: first,
        }])
        .unwrap()
        .remove(0)
    }

    /// One delivered payment, every event shares one signature.
    fn payment_event(recipient: &ShieldedKeypair, event_index: u16) -> ShieldedTransaction {
        let address = recipient.shielded_address().unwrap();
        let tx_key = ViewingKey::new();
        let salt = [9; 16];
        let first_nullifier = [0x21; 32];
        let view = recipient.viewing_pubkey();
        let secret = DeliveredSlot {
            agreement: &tx_key.ecdh(&view).unwrap(),
            tx_viewing_pk: tx_key.pubkey().as_bytes(),
            recipient_viewing_pk: view.as_bytes(),
            salt: &salt,
            output_index: 0,
            first_nullifier: &first_nullifier,
        }
        .secret()
        .unwrap();
        let blinding = [0x20 + event_index as u8; 32];
        let hash = ring_note(&address, blinding)
            .hash(&address.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
            .unwrap();
        let body = seal_recipient_body(
            &RecipientBody {
                blinding,
                amount: AMOUNT,
                mint: Mint::SOL.asset.to_bytes(),
                ..RecipientBody::default()
            },
            &secret,
        )
        .unwrap();
        ShieldedTransaction {
            slot: 3,
            tx_signature: Signature::from([3; 64]),
            event_index: Some(event_index),
            tx_viewing_pk: Some(tx_key.pubkey()),
            salt: Some(salt),
            output_slots: vec![OutputSlot {
                view_tag: slot_tag(view.u()),
                output_context: output_context(hash),
                payload: encode_ring_body_output(&body, &[]).unwrap(),
            }],
            messages: Vec::new(),
            nullifiers: vec![first_nullifier],
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }

    /// `merge_ring_v2` under a nonzero key, the proven encoding and its first nullifier tag.
    #[test]
    fn a_proven_ring_merge_opens_under_the_nullifier_secret() {
        let (hash, opened) = ProvenMerge {
            committed: [0; 32],
            published: [0; 32],
        }
        .opened();
        assert_eq!(opened, [hash]);
    }

    /// `merge.go` leaves the value free, the commitment holds it and the owner rebuilds from the row.
    #[test]
    fn a_relay_chosen_ring_data_hash_binds_the_commitment_and_stays_the_owners_note() {
        let chosen = [3; 32];
        let (hash, opened) = ProvenMerge {
            committed: chosen,
            published: chosen,
        }
        .opened();
        assert_eq!(opened, [hash]);
        let (_, unbound) = ProvenMerge {
            committed: chosen,
            published: [4; 32],
        }
        .opened();
        assert!(unbound.is_empty());
    }

    #[tokio::test]
    async fn a_deposit_before_enrollment_reads_exposed_on_every_reader() {
        let owner = wallet(7);
        let address = owner.shielded_address().unwrap();
        let deposit = deposit_under(&address, &ZERO_NULLIFIER_PUBKEY, [0x12; 32]);
        let hash = deposit_hash(&deposit);
        let row = ring_row(deposit.clone());
        let assets = assets();
        let scan = RingConfidentialScan::new(&owner, &assets);
        let indexer = Rows {
            rows: vec![row.clone()],
            deposits: vec![deposit],
        };

        let opened = scan.open(core::slice::from_ref(&row)).unwrap();
        assert_eq!(hashes(&opened.exposed_if_spent), [hash]);
        assert!(opened.owned.utxos.is_empty());

        let fetched = scan
            .fetch(&indexer, core::slice::from_ref(&row))
            .await
            .unwrap();
        assert_eq!(hashes(&fetched.exposed_if_spent), [hash]);
        assert!(fetched.owned.utxos.is_empty());

        let full = scan.full_scan(&indexer, RING).await.unwrap();
        assert_eq!(hashes(&full.owned.exposed_if_spent), [hash]);
        assert!(full.owned.owned.utxos.is_empty());

        let history = ViewingHistory::new(owner.viewing_pubkey(), 0).with_ring(RING, None);
        let synced = AnonymousSync::new(&owner, &assets)
            .fetch(&indexer, &history)
            .await
            .unwrap();
        let owned = verify_ring_owned(&owner, synced.decrypted()).unwrap();
        assert_eq!(hashes(&owned.exposed_if_spent), [hash]);
        assert_eq!(
            owned.exposed_if_spent[0].nullifier_pubkey,
            ZERO_NULLIFIER_PUBKEY
        );
    }

    #[tokio::test]
    async fn a_deposit_under_a_third_key_opens_on_no_reader() {
        let owner = wallet(7);
        let address = owner.shielded_address().unwrap();
        let row = ring_row(deposit_under(&address, &THIRD_KEY, [0x12; 32]));
        let assets = assets();
        let scan = RingConfidentialScan::new(&owner, &assets);
        let opened = scan.open(core::slice::from_ref(&row)).unwrap();
        assert!(opened.exposed_if_spent.is_empty() && opened.owned.utxos.is_empty());
        let full = scan.full_scan(&Rows::of(vec![row]), RING).await.unwrap();
        assert!(full.owned.exposed_if_spent.is_empty() && full.owned.owned.utxos.is_empty());
    }

    #[tokio::test]
    async fn fetch_finds_a_zero_key_merge_with_no_input_history_and_reads_it_exposed() {
        let owner = wallet(7);
        let address = owner.shielded_address().unwrap();
        let first = [0x14; 32];
        let (hash, row) = seeded_merge(&address, &own_seed(&owner, first), first);
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(&Rows::of(vec![row]), &[])
            .await
            .unwrap();
        assert_eq!(hashes(&notes.exposed_if_spent), [hash]);
        assert!(notes.owned.utxos.is_empty());
    }

    #[tokio::test]
    async fn fetch_moves_the_exposure_from_a_spent_zero_key_note_to_its_merge_output() {
        let owner = wallet(7);
        let address = owner.shielded_address().unwrap();
        let blinding = [0x12; 32];
        let deposit = ring_row(deposit_under(&address, &ZERO_NULLIFIER_PUBKEY, blinding));
        let input = NullifierKey::from_secret([0; 31])
            .nullifier(&deposit.output_slots[0].output_context.hash, &blinding)
            .unwrap();
        let (hash, merge) = seeded_merge(&address, &own_seed(&owner, input), input);
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(
                &Rows::of(vec![deposit.clone(), merge]),
                core::slice::from_ref(&deposit),
            )
            .await
            .unwrap();
        assert_eq!(hashes(&notes.exposed_if_spent), [hash]);
    }

    #[tokio::test]
    async fn fetch_opens_no_zero_key_merge_under_another_wallets_seed() {
        let (owner, other) = (wallet(7), wallet(8));
        let first = [0x14; 32];
        let (_, row) = seeded_merge(
            &owner.shielded_address().unwrap(),
            &own_seed(&other, first),
            first,
        );
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(&Rows::of(vec![row]), &[])
            .await
            .unwrap();
        assert!(notes.exposed_if_spent.is_empty() && notes.owned.utxos.is_empty());
    }

    #[tokio::test]
    async fn a_poseidon_error_from_the_holder_fails_fetch_and_full_scan() {
        let holder = FailingHolder(wallet(7), HolderFailure::MergeOutputKey);
        let address = holder.address().unwrap();
        let blinding = [0x12; 32];
        let deposit = ring_row(deposit_under(&address, &address.nullifier_pubkey, blinding));
        let input = holder
            .0
            .nullifier(&deposit.output_slots[0].output_context.hash, &blinding)
            .unwrap();
        let (_, merge) = ProvenMerge {
            committed: [0; 32],
            published: [0; 32],
        }
        .row(&holder.0, input);
        let indexer = Rows::of(vec![deposit.clone(), merge]);
        let assets = assets();
        let scan = RingConfidentialScan::new(&holder, &assets);
        let refused = |error: AnonymousError| {
            matches!(
                error,
                AnonymousError::Transaction(TransactionError::Keypair(KeypairError::Poseidon(_)))
            )
        };
        assert!(refused(
            scan.fetch(&indexer, core::slice::from_ref(&deposit))
                .await
                .err()
                .unwrap()
        ));
        assert!(refused(scan.full_scan(&indexer, RING).await.err().unwrap()));
    }

    #[tokio::test]
    async fn a_merge_seed_failure_from_the_holder_fails_fetch_and_full_scan() {
        let holder = FailingHolder(wallet(7), HolderFailure::MergeSeed);
        let address = holder.address().unwrap();
        let first = [0x14; 32];
        let (_, row) = seeded_merge(&address, &own_seed(&holder.0, first), first);
        let indexer = Rows::of(vec![row]);
        let assets = assets();
        let scan = RingConfidentialScan::new(&holder, &assets);
        assert!(scan.fetch(&indexer, &[]).await.is_err());
        assert!(scan.full_scan(&indexer, RING).await.is_err());
    }

    #[test]
    fn a_published_value_outside_the_field_skips_only_its_merge() {
        let owner = wallet(7);
        let (hash, good) = ProvenMerge {
            committed: [0; 32],
            published: [0; 32],
        }
        .row(&owner, [0x11; 32]);
        let (_, bad_ring_data) = ProvenMerge {
            committed: [0; 32],
            published: NOT_IN_FIELD,
        }
        .row(&owner, [0x12; 32]);
        let (_, mut bad_first) = ProvenMerge {
            committed: [0; 32],
            published: [0; 32],
        }
        .row(&owner, [0x13; 32]);
        bad_first.nullifiers[0] = NOT_IN_FIELD;
        let opened = RingMerges::among(vec![bad_ring_data, good, bad_first])
            .open(&owner, &assets())
            .unwrap();
        assert_eq!(hashes(&opened.utxos), [hash]);
    }

    #[tokio::test]
    async fn a_seeded_merge_with_a_first_nullifier_outside_the_field_fails_no_read() {
        let owner = wallet(7);
        let address = owner.shielded_address().unwrap();
        let first = [0x14; 32];
        let (hash, good) = seeded_merge(&address, &own_seed(&owner, first), first);
        let other = [0x15; 32];
        let (_, mut bad) = seeded_merge(&address, &own_seed(&owner, other), other);
        bad.nullifiers[0] = NOT_IN_FIELD;
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(&Rows::of(vec![good, bad]), &[])
            .await
            .unwrap();
        assert_eq!(hashes(&notes.exposed_if_spent), [hash]);
    }

    #[tokio::test]
    async fn two_events_of_one_transaction_both_open_on_fetch() {
        let owner = wallet(7);
        let (first, second) = (payment_event(&owner, 0), payment_event(&owner, 1));
        let both = [
            first.output_slots[0].output_context.hash,
            second.output_slots[0].output_context.hash,
        ];
        let assets = assets();
        let notes = RingConfidentialScan::new(&owner, &assets)
            .fetch(
                &Rows::of(vec![first.clone(), second]),
                core::slice::from_ref(&first),
            )
            .await
            .unwrap();
        assert_eq!(hashes(&notes.owned.utxos), both);
    }

    #[test]
    fn an_event_read_twice_stays_one_row() {
        let owner = wallet(7);
        let (first, second) = (payment_event(&owner, 0), payment_event(&owner, 1));
        let read = union_events(
            core::slice::from_ref(&first),
            vec![first.clone(), first.clone(), second.clone()],
        );
        let events: Vec<_> = read.iter().map(|tx| tx.event_index).collect();
        assert_eq!(events, [first.event_index, second.event_index]);
    }
}
