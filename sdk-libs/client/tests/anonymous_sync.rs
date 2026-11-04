//! `AnonymousSync` against an in-memory indexer, every transfer sealed by the anonymous rail.

#[path = "common/history_page.rs"]
pub mod history_page;

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex,
};

use async_trait::async_trait;
use custom_ring_interface::stream::slot_tag;
use custom_ring_interface::{
    encode_ring_body_output, encode_ring_sender_bundle_output,
    stream::{DeliveredSlot, SlotSecret},
    RecipientBody, RingDepositAuditCapsule, SenderBundle, MIN_REPLY_LEN, RECIPIENT_BODY_LEN,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncRpc, ClientError, Context,
    EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetShieldedTransactionsByTagsResponse,
    HistoryFilters, IndexerRpcConfig, OutputContext, OutputSlot, PaginationToken,
    RingHistoryOptions, ShieldedTransaction,
};
use spr_event::{
    encode_encrypted_ring_deposit_output, encode_merge_output_data, EncryptedRingDepositData,
    EncryptedRingDepositOutput, MergeOutputDataRef, MessageData,
};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{
    random_salt, viewing_key::ViewTag, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey,
    X25519Pubkey,
};
use spr_transaction::instructions::merge::MergeSeed;
use spr_transaction::{
    instructions::{
        merge::{merge_output_blinding, merge_output_key, MergeOutputPlaintext},
        transact::ConfidentialTransaction,
    },
    owner_utxo_hash, verify_spendable, Data, DecryptRequest, DecryptionResult, DeriveRequest, Mint,
    ShieldedKeys, TransactionError, TransactionKeyRequest, Utxo, WalletUtxo,
};
use zolana_ring_client::{
    note_state, verify_ring_owned, AnonymousError, AnonymousScan, AnonymousStream, AnonymousSync,
    AnonymousWallet, NoteState, SentCheck, ViewingHistory, TAGS_PER_REQUEST, TAG_GAP,
    VIEWING_HISTORY_VERSION,
};
use zolana_ring_keys::{
    MergeSeedHolder, MergeSeedRequest, RingDeliveryRequest, RingKeyError, RingKeys, RingTagFrame,
    RotatingRingKeys, ViewTagRequest,
};
use zolana_ring_transaction::{
    seal_recipient_body, seal_reply, seal_sender_bundle, AnonymousPlan, ReplyMetadata, RingAssets,
    RingDelivery, RingDepositPlaintext, RingOutputRail,
};

use history_page::{position, EventsPage, OutputsPage};

const RING: Address = Address::new_from_array([4; 32]);
const TREE: u16 = 2;
const RESPONSE_TOO_LARGE: &str = "JSON-RPC error from ring: code=Some(-32008) message=\"large\"";

fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

#[derive(Default)]
struct Indexer {
    transactions: Mutex<Vec<ShieldedTransaction>>,
    deposits: Mutex<Vec<EncryptedUtxoMatch>>,
    next_leaf: Mutex<u64>,
    tip: Mutex<u64>,
    /// Transactions per ring page below the asked limit.
    page_cap: Mutex<Option<usize>>,
    /// Ring pages asked above the limit answer `-32008`.
    response_limit: Mutex<Option<u32>>,
    limits_asked: Mutex<Vec<u32>>,
    /// The ring page at the index fails.
    failing_page: Mutex<Option<usize>>,
    ring_pages: AtomicUsize,
    transaction_tag_reads: AtomicUsize,
}

impl Indexer {
    fn publish(&self, transaction: ShieldedTransaction) {
        let mut tip = self.tip.lock().unwrap();
        *tip = (*tip).max(transaction.slot);
        self.transactions.lock().unwrap().push(transaction);
    }

    /// A deposit reaches the tag read and the ring's history as a proofless row.
    fn publish_deposit(&self, deposit: EncryptedUtxoMatch) {
        self.deposits.lock().unwrap().push(deposit.clone());
        let row = deposit.into_proofless_transaction().unwrap();
        self.publish(ShieldedTransaction {
            ring_program_id: Some(RING),
            ..row
        });
    }

    /// Leaves in append order, every published output takes the next.
    fn leaves(&self, count: usize) -> u64 {
        let mut next = self.next_leaf.lock().unwrap();
        let first = *next;
        *next += count as u64;
        first
    }

    fn context(&self) -> Context {
        Context {
            block_time: 0,
            slot: *self.tip.lock().unwrap(),
        }
    }

    fn take_ring_pages(&self) -> usize {
        self.ring_pages.swap(0, Ordering::Relaxed)
    }

    fn page(
        &self,
        filters: HistoryFilters,
        matches: impl Fn(&ShieldedTransaction) -> bool,
    ) -> GetShieldedTransactionsByTagsResponse {
        EventsPage {
            context: self.context(),
            output_tree_id: Some(TREE),
            rows: self
                .transactions
                .lock()
                .unwrap()
                .iter()
                .filter(|tx| filters.slot.contains(tx.slot) && matches(tx))
                .cloned()
                .collect(),
            more: false,
        }
        .response()
    }
}

#[async_trait]
impl AsyncRpc for Indexer {
    async fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.transaction_tag_reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.page(filters, |_| false))
    }

    async fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        let limit = options.limit.unwrap();
        self.limits_asked.lock().unwrap().push(limit);
        if self
            .response_limit
            .lock()
            .unwrap()
            .is_some_and(|cap| limit > cap)
        {
            return Err(ClientError::Indexer(RESPONSE_TOO_LARGE.to_owned()));
        }
        let page = self.ring_pages.fetch_add(1, Ordering::Relaxed);
        if *self.failing_page.lock().unwrap() == Some(page) {
            return Err(ClientError::Indexer("a failed page".to_owned()));
        }
        let mut rows: Vec<ShieldedTransaction> = self
            .transactions
            .lock()
            .unwrap()
            .iter()
            .filter(|tx| {
                tx.ring_program_id == Some(options.ring_program_id)
                    && options.filters.slot.contains(tx.slot)
                    && options
                        .pagination_token
                        .is_none_or(|token| position(tx) > token)
            })
            .cloned()
            .collect();
        rows.sort_by_key(position);
        let cap = self
            .page_cap
            .lock()
            .unwrap()
            .map_or(limit as usize, |cap| cap.min(limit as usize));
        let more = rows.len() > cap;
        rows.truncate(cap);
        Ok(EventsPage {
            context: self.context(),
            output_tree_id: Some(TREE),
            rows,
            more,
        }
        .response())
    }

    async fn get_encrypted_utxos_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetEncryptedUtxosByTagsResponse, ClientError> {
        Ok(OutputsPage {
            context: self.context(),
            output_tree_id: Some(TREE),
            rows: self
                .deposits
                .lock()
                .unwrap()
                .iter()
                .filter(|deposit| {
                    filters.slot.contains(deposit.slot)
                        && tags.contains(&deposit.output_slot.view_tag)
                })
                .cloned()
                .collect(),
        }
        .response())
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        Ok(self.page(filters, |tx| {
            tx.nullifiers.iter().any(|n| nullifiers.contains(n))
        }))
    }
}

struct RingHistoryOnly<'a>(&'a Indexer);

#[async_trait]
impl AsyncRpc for RingHistoryOnly<'_> {
    async fn get_shielded_transactions_by_ring(
        &self,
        options: RingHistoryOptions,
        config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.0
            .get_shielded_transactions_by_ring(options, config)
            .await
    }
}

struct Wallet {
    keys: ShieldedKeypair,
    /// Holds the deposit tag counters a depositor stores before it sends.
    history: ViewingHistory,
    /// Notes it spends, never published, the sync of another wallet never reads them.
    funding: Vec<WalletUtxo>,
    replies: bool,
}

struct Pay<'a> {
    to: &'a ShieldedAddress,
    amount: u64,
}

impl Wallet {
    fn new(seed: u8) -> Self {
        let keys = keypair(seed);
        let history = ViewingHistory::new(keys.viewing_pubkey(), 0);
        let funding = (0..8)
            .map(|index| funding_utxo(&keys, seed, index))
            .collect();
        Self {
            keys,
            history,
            funding,
            replies: true,
        }
    }

    fn address(&self) -> ShieldedAddress {
        self.keys.shielded_address().unwrap()
    }

    /// Seals one anonymous transfer from the next funding note and publishes it.
    fn pay(&mut self, indexer: &Indexer, payments: &[Pay<'_>]) -> ShieldedTransaction {
        let tx = self.seal(indexer, payments);
        indexer.publish(tx.clone());
        tx
    }

    /// Seals one anonymous transfer, its leaves taken, without publishing it.
    fn seal(&mut self, indexer: &Indexer, payments: &[Pay<'_>]) -> ShieldedTransaction {
        let first_nullifier = self.funding[0].nullifier;
        let tx_key = self
            .keys
            .viewing_key
            .get_transaction_viewing_key(&first_nullifier)
            .unwrap();
        self.seal_under(indexer, payments, tx_key)
    }

    /// `tx_key` of the wallet's own derivation, or a relayer's.
    fn seal_under(
        &mut self,
        indexer: &Indexer,
        payments: &[Pay<'_>],
        tx_key: ViewingKey,
    ) -> ShieldedTransaction {
        let reply = ReplyMetadata {
            viewing_key: self.keys.viewing_pubkey(),
            owner_key: self.address().solana_address().unwrap().to_bytes(),
            nullifier_pk: self.address().nullifier_pubkey,
            data: Data::default(),
        };
        let plan = payments.iter().fold(AnonymousPlan::new(), |plan, pay| {
            let plan = plan.with_payment(pay.to.viewing_pubkey);
            match self.replies {
                true => plan.with_reply(reply.clone()),
                false => plan,
            }
        });
        let input = self.funding.remove(0);
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![input],
            self.address().solana_address().unwrap(),
            RING,
        )
        .unwrap()
        .with_output_tree_id(TREE)
        .unwrap();
        for pay in payments {
            transaction
                .transfer_with_ring(pay.to, Mint::SOL, pay.amount, Some(RING))
                .unwrap();
        }
        let rail = RingOutputRail::new(tx_key, RingDelivery::Anonymous(Box::new(plan)));
        let proof = rail.encrypt(transaction, &self.address()).unwrap();
        let external = &proof.external_data;
        let leaf = indexer.leaves(external.outputs.len());
        ShieldedTransaction {
            slot: leaf + 1,
            tx_signature: Signature::from(signature(leaf)),
            event_index: Some(0),
            tx_viewing_pk: Some(rail.tx_viewing_key().pubkey()),
            salt: Some(rail.salt()),
            output_slots: external
                .outputs
                .iter()
                .zip(&external.resolved_owner_tags)
                .zip(leaf..)
                .map(|((output, tag), leaf_index)| OutputSlot {
                    view_tag: *tag,
                    output_context: OutputContext {
                        hash: output.utxo_hash,
                        tree_id: TREE,
                        leaf_index,
                    },
                    payload: output.data.clone().unwrap_or_default(),
                })
                .collect(),
            messages: external.messages.clone(),
            nullifiers: proof
                .input_utxos
                .iter()
                .map(|input| input.nullifier())
                .collect(),
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        }
    }

    async fn sync(&self, indexer: &Indexer, history: &ViewingHistory) -> AnonymousScan {
        AnonymousSync::new(&self.keys, &assets())
            .fetch(indexer, history)
            .await
            .unwrap()
    }

    async fn recover(&self, indexer: &Indexer) -> AnonymousScan {
        AnonymousSync::new(&self.keys, &assets())
            .full_scan(&RingHistoryOnly(indexer), &fresh(self), RING)
            .await
            .unwrap()
    }
}

fn assets() -> RingAssets {
    RingAssets::new([]).unwrap()
}

fn signature(leaf: u64) -> [u8; 64] {
    let mut bytes = [0x5a; 64];
    bytes[..8].copy_from_slice(&leaf.to_be_bytes());
    bytes
}

/// A held ring note of `owner`, its nullifier canonical as every real one is.
fn funding_utxo(owner: &ShieldedKeypair, seed: u8, index: u8) -> WalletUtxo {
    let utxo = Utxo {
        owner: owner.signing_pubkey(),
        asset: Mint::SOL,
        amount: 100,
        blinding: field(seed, index),
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let nullifier_pubkey = owner.shielded_address().unwrap().nullifier_pubkey;
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    WalletUtxo {
        nullifier: owner.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id: TREE,
        leaf_index: u64::from(index),
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::from([seed; 64]),
        slot_index: 0,
    }
}

/// A canonical field value distinct per pair.
fn field(seed: u8, index: u8) -> [u8; 32] {
    let mut value = [0x11; 32];
    value[30] = seed;
    value[31] = index;
    value
}

fn stream(scan: &AnonymousScan, utxo_hash: [u8; 32]) -> AnonymousStream {
    scan.utxos
        .iter()
        .find(|utxo| utxo.utxo_hash == utxo_hash)
        .map(|utxo| utxo.stream)
        .unwrap_or_else(|| panic!("note {utxo_hash:?} not found"))
}

fn found(scan: &AnonymousScan) -> Vec<[u8; 32]> {
    scan.utxos.iter().map(|utxo| utxo.utxo_hash).collect()
}

/// The hash of the output at `position`.
fn output(tx: &ShieldedTransaction, position: usize) -> [u8; 32] {
    tx.output_slots[position].output_context.hash
}

/// A wallet that never synced, reading `RING` from its start.
fn fresh(wallet: &Wallet) -> ViewingHistory {
    ViewingHistory::new(wallet.keys.viewing_pubkey(), 0).with_ring(RING, None)
}

fn pay<'a>(to: &'a ShieldedAddress, amount: u64) -> Pay<'a> {
    Pay { to, amount }
}

fn after_slot(history: &ViewingHistory) -> Option<u64> {
    history.current().ring_positions()[&RING]
}

#[tokio::test]
async fn a_payment_is_found_under_its_proven_tag_and_the_read_stores_its_final_context() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 30)]);
    let scan = bob.sync(&indexer, &fresh(&bob)).await;
    assert_eq!(found(&scan), [output(&paid, 1)]);
    assert_eq!(stream(&scan, output(&paid, 1)), AnonymousStream::ProvenTag);
    assert_eq!(after_slot(scan.history()), Some(paid.slot));
    assert_eq!(
        indexer.transaction_tag_reads.load(Ordering::Relaxed),
        0,
        "a transfer is read from the ring's history alone"
    );
    assert_eq!(*indexer.limits_asked.lock().unwrap(), [1000]);
}

#[tokio::test]
async fn change_is_found_by_the_bundle_tag_and_the_change_slot_publishes_zero() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 30)]);
    assert_eq!(paid.output_slots[0].view_tag, [0; 32]);
    let scan = alice.sync(&indexer, &fresh(&alice)).await;
    assert_eq!(found(&scan), [output(&paid, 0)]);
    assert_eq!(stream(&scan, output(&paid, 0)), AnonymousStream::ProvenTag);
    let reader = bob.sync(&indexer, &fresh(&bob)).await;
    assert_eq!(found(&reader), [output(&paid, 1)]);
}

#[tokio::test]
async fn a_body_sealed_to_another_key_is_skipped_and_the_scan_goes_on() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let carol = Wallet::new(3);
    let to_carol = alice.pay(&indexer, &[pay(&carol.address(), 30)]);
    let to_bob = alice.pay(&indexer, &[pay(&bob.address(), 10)]);
    assert_eq!(
        found(&bob.sync(&indexer, &fresh(&bob)).await),
        [output(&to_bob, 1)]
    );
    assert_eq!(
        found(&carol.sync(&indexer, &fresh(&carol)).await),
        [output(&to_carol, 1)]
    );
}

/// The circuit refuses a wrong tag on a live slot, only a frame past it would reach here.
#[tokio::test]
async fn a_wrong_tag_hides_a_note_from_the_tag_scan_and_never_from_recovery() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let mut wrong = alice.seal(&indexer, &[pay(&bob.address(), 30)]);
    for slot in &mut wrong.output_slots {
        slot.view_tag = [0x7e; 32];
    }
    for message in &mut wrong.messages {
        message.view_tag = [0x7f; 32];
    }
    indexer.publish(wrong.clone());
    assert!(found(&bob.sync(&indexer, &fresh(&bob)).await).is_empty());
    assert!(found(&alice.sync(&indexer, &fresh(&alice)).await).is_empty());
    let recipient = bob.recover(&indexer).await;
    assert_eq!(found(&recipient), [output(&wrong, 1)]);
    assert_eq!(
        stream(&recipient, output(&wrong, 1)),
        AnonymousStream::FullScan
    );
    assert_eq!(found(&alice.recover(&indexer).await), [output(&wrong, 0)]);
}

#[tokio::test]
async fn the_tag_scan_and_recovery_find_the_same_notes_on_one_history() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let mut bob = Wallet::new(2);
    alice.pay(&indexer, &[pay(&bob.address(), 30)]);
    let bob_address = bob.address();
    bob.pay(&indexer, &[pay(&alice.address(), 11)]);
    alice.pay(&indexer, &[pay(&bob_address, 7), pay(&bob_address, 9)]);
    for wallet in [&alice, &bob] {
        let mut scanned = found(&wallet.sync(&indexer, &fresh(wallet)).await);
        let mut recovered = found(&wallet.recover(&indexer).await);
        scanned.sort_unstable();
        recovered.sort_unstable();
        assert_eq!(scanned, recovered);
        assert!(!scanned.is_empty());
    }
}

/// The production holder across a rotation and a restart, the old key stays readable.
#[tokio::test]
async fn a_rotated_wallet_finds_notes_under_both_keys_through_a_restart_and_a_recovery() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let identity = keypair(2);
    let old_address = identity.shielded_address().unwrap();
    let to_old = alice.pay(&indexer, &[pay(&old_address, 30)]);
    let keys = RotatingRingKeys::new(&identity).unwrap();
    let history = ViewingHistory::new(old_address.viewing_pubkey, 0).with_ring(RING, None);
    let mut wallet = AnonymousWallet::new(history);
    let scan = AnonymousSync::new(&keys, &assets())
        .fetch(&indexer, wallet.history())
        .await
        .unwrap();
    assert_eq!(found(&scan), [output(&to_old, 1)]);
    wallet.absorb(scan).unwrap();

    let next = ViewingKey::new();
    let keys = keys.rotate(next.clone()).unwrap();
    let new_address = keys.address().unwrap();
    assert_eq!(new_address.signing_pubkey, old_address.signing_pubkey);
    assert_ne!(new_address.viewing_pubkey, old_address.viewing_pubkey);
    let rotated = wallet
        .history()
        .clone()
        .with_rotated_key(new_address.viewing_pubkey, 1)
        .unwrap();
    wallet.update_history(rotated).unwrap();
    let to_new = alice.pay(&indexer, &[pay(&new_address, 10)]);
    let to_old_again = alice.pay(&indexer, &[pay(&old_address, 7)]);

    let stored = wallet.to_json();
    let mut current = keypair(2);
    current.viewing_key = next;
    let restarted_keys = RotatingRingKeys::new(&current)
        .unwrap()
        .with_retired(vec![identity.viewing_key.clone()])
        .unwrap();
    let mut restarted = AnonymousWallet::from_json(&stored).unwrap();
    let scan = AnonymousSync::new(&restarted_keys, &assets())
        .fetch(&indexer, restarted.history())
        .await
        .unwrap();
    restarted.absorb(scan).unwrap();
    let mut expected = [
        output(&to_old, 1),
        output(&to_new, 1),
        output(&to_old_again, 1),
    ];
    expected.sort_unstable();
    let mut held: Vec<[u8; 32]> = restarted
        .notes()
        .iter()
        .map(|note| note.utxo_hash)
        .collect();
    held.sort_unstable();
    assert_eq!(held, expected);

    let recovered = AnonymousSync::new(&restarted_keys, &assets())
        .full_scan(&indexer, restarted.history(), RING)
        .await
        .unwrap();
    let mut notes = found(&recovered);
    notes.sort_unstable();
    assert_eq!(notes, expected);
    let unspent = verify_spendable(&restarted_keys, recovered.decrypted()).unwrap();
    assert_eq!(unspent.utxos().count(), expected.len());
}

#[tokio::test]
async fn a_ring_watched_after_rotation_reads_payments_to_the_retired_key() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let identity = keypair(2);
    let old_address = identity.shielded_address().unwrap();
    let keys = RotatingRingKeys::new(&identity)
        .unwrap()
        .rotate(ViewingKey::new())
        .unwrap();
    let history = ViewingHistory::new(old_address.viewing_pubkey, 0)
        .with_rotated_key(keys.address().unwrap().viewing_pubkey, 1)
        .unwrap()
        .with_ring(RING, None);
    let payment = alice.pay(&indexer, &[pay(&old_address, 30)]);
    let scan = AnonymousSync::new(&keys, &assets())
        .fetch(&indexer, &history)
        .await
        .unwrap();
    assert_eq!(found(&scan), [output(&payment, 1)]);
    assert!(scan
        .history()
        .entries()
        .iter()
        .all(|entry| entry.ring_positions()[&RING] == Some(payment.slot)));
}

/// A key added after a sync reads the ring's whole history under its own query, the stored key reads on.
#[tokio::test]
async fn an_imported_key_finds_the_notes_below_the_wallets_position() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let identity = keypair(2);
    let imported_key = ViewingKey::new();
    let old_address = ShieldedAddress {
        viewing_pubkey: imported_key.pubkey(),
        ..identity.shielded_address().unwrap()
    };
    let old_note = alice.pay(&indexer, &[pay(&old_address, 30)]);
    let current = identity.viewing_pubkey();
    let alone = RotatingRingKeys::new(&identity).unwrap();
    let synced = AnonymousSync::new(&alone, &assets())
        .fetch(
            &indexer,
            &ViewingHistory::new(current, 5).with_ring(RING, None),
        )
        .await
        .unwrap();
    assert!(found(&synced).is_empty(), "the holder lacks the old key");
    let position = after_slot(synced.history());
    assert_eq!(position, Some(old_note.slot));
    let imported = synced
        .history()
        .clone()
        .with_imported_key(imported_key.pubkey(), 1)
        .unwrap();
    assert_eq!(
        after_slot(&imported),
        position,
        "the current key keeps its position"
    );
    indexer.take_ring_pages();
    let keys = RotatingRingKeys::new(&identity)
        .unwrap()
        .with_retired(vec![imported_key.clone()])
        .unwrap();
    let scan = AnonymousSync::new(&keys, &assets())
        .fetch(&indexer, &imported)
        .await
        .unwrap();
    assert_eq!(found(&scan), [output(&old_note, 1)]);
    assert_eq!(indexer.take_ring_pages(), 2, "one query per position");
    let retired = scan.history().entry(&imported_key.pubkey()).unwrap();
    assert_eq!(retired.ring_positions()[&RING], Some(old_note.slot));
}

/// Pages stop inside one slot, a run that fails there stores nothing and the next finds every row once.
#[tokio::test]
async fn a_restart_inside_a_split_slot_skips_nothing_and_repeats_nothing() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let split: Vec<ShieldedTransaction> = [10, 11, 12]
        .map(|amount| {
            let mut paid = alice.seal(&indexer, &[pay(&bob.address(), amount)]);
            paid.slot = 5;
            indexer.publish(paid.clone());
            paid
        })
        .into();
    *indexer.page_cap.lock().unwrap() = Some(1);
    *indexer.failing_page.lock().unwrap() = Some(1);
    let wallet = AnonymousWallet::new(fresh(&bob));
    let failed = AnonymousSync::new(&bob.keys, &assets())
        .fetch(&indexer, wallet.history())
        .await;
    assert!(failed.is_err(), "a failed page ends the read");

    *indexer.failing_page.lock().unwrap() = None;
    indexer.take_ring_pages();
    let restarted = AnonymousWallet::from_json(&wallet.to_json()).unwrap();
    let scan = bob.sync(&indexer, restarted.history()).await;
    assert_eq!(
        indexer.take_ring_pages(),
        3,
        "a token on every page ahead of more"
    );
    assert_eq!(scan.utxos.len(), split.len());
    for paid in &split {
        stream(&scan, output(paid, 1));
    }
    assert_eq!(after_slot(scan.history()), Some(5));

    let later = alice.pay(&indexer, &[pay(&bob.address(), 13)]);
    let next = bob.sync(&indexer, scan.history()).await;
    assert_eq!(found(&next), [output(&later, 1)]);
    assert_eq!(after_slot(next.history()), Some(later.slot));
}

/// A crash on either side of the one replace skips no note, a scan is stored only through `absorb`.
#[tokio::test]
async fn a_crash_on_either_side_of_the_one_write_skips_no_funds() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 30)]);
    let mut wallet = AnonymousWallet::new(fresh(&bob));
    let before = wallet.to_json();
    let scan = bob.sync(&indexer, wallet.history()).await;
    assert!(after_slot(scan.history()).is_some());

    // The position alone is refused, its notes unwritten.
    assert!(matches!(
        wallet.update_history(scan.history().clone()),
        Err(AnonymousError::ScanProgressMoved)
    ));

    // The crash before the replace.
    let restarted = AnonymousWallet::from_json(&before).unwrap();
    assert_eq!(after_slot(restarted.history()), None);
    let replay = bob.sync(&indexer, restarted.history()).await;
    assert_eq!(found(&replay), [output(&paid, 1)]);

    // The crash after it.
    wallet.absorb(scan).unwrap();
    let after = wallet.to_json();
    let mut restarted = AnonymousWallet::from_json(&after).unwrap();
    assert_eq!(restarted, wallet);
    assert_eq!(restarted.notes()[0].utxo_hash, output(&paid, 1));
    assert!(bob
        .sync(&indexer, restarted.history())
        .await
        .utxos
        .is_empty());

    let before = restarted.clone();
    assert!(matches!(
        restarted.absorb(replay),
        Err(AnonymousError::ScanHistoryChanged)
    ));
    assert_eq!(restarted, before);
    assert_eq!(restarted.notes().len(), 1);
}

#[tokio::test]
async fn a_scan_cannot_overwrite_a_later_tag_key_or_sender() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    alice.pay(&indexer, &[pay(&bob.address(), 30)]);
    let history = fresh(&bob);
    let mut confirmed = history.clone();
    confirmed
        .confirm_sender(alice.keys.viewing_pubkey())
        .unwrap();
    let updates = [
        history.request_tag(&bob.keys).unwrap().history,
        history
            .clone()
            .with_rotated_key(ViewingKey::new().pubkey(), 1)
            .unwrap(),
        confirmed,
    ];
    for updated in updates {
        let mut wallet = AnonymousWallet::new(history.clone());
        let scan = bob.sync(&indexer, wallet.history()).await;
        wallet.update_history(updated).unwrap();
        let before = wallet.clone();
        assert!(matches!(
            wallet.absorb(scan),
            Err(AnonymousError::ScanHistoryChanged)
        ));
        assert_eq!(wallet, before);
    }
}

#[tokio::test]
async fn a_tag_counter_update_keeps_the_stored_progress() {
    let bob = Wallet::new(2);
    let mut wallet = AnonymousWallet::new(fresh(&bob));
    let advanced = wallet.history().sender_tag(&bob.keys).unwrap().history;
    wallet.update_history(advanced.clone()).unwrap();
    assert_eq!(*wallet.history(), advanced);
    assert_eq!(wallet.history().current().tx_count(), 1);
}

#[tokio::test]
async fn a_page_too_large_halves_the_limit_and_loses_no_row() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = [
        alice.pay(&indexer, &[pay(&bob.address(), 10)]),
        alice.pay(&indexer, &[pay(&bob.address(), 11)]),
    ];
    *indexer.response_limit.lock().unwrap() = Some(1);
    *indexer.page_cap.lock().unwrap() = Some(1);
    let scan = bob.sync(&indexer, &fresh(&bob)).await;
    assert_eq!(found(&scan), paid.each_ref().map(|paid| output(paid, 1)));
    let asked = indexer.limits_asked.lock().unwrap().clone();
    assert_eq!(asked[..2], [1000, 500]);
    assert_eq!(asked.iter().filter(|limit| **limit == 1).count(), 2);
    assert_eq!(after_slot(scan.history()), Some(paid[1].slot));
}

#[tokio::test]
async fn a_page_too_large_at_limit_one_fails_the_read_and_moves_nothing() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    alice.pay(&indexer, &[pay(&bob.address(), 10)]);
    *indexer.response_limit.lock().unwrap() = Some(0);
    let refused = AnonymousSync::new(&bob.keys, &assets())
        .fetch(&indexer, &fresh(&bob))
        .await;
    assert!(matches!(
        refused,
        Err(AnonymousError::Client(ClientError::Indexer(_)))
    ));
    assert_eq!(indexer.limits_asked.lock().unwrap().last(), Some(&1));
}

#[tokio::test]
async fn a_repeated_row_of_one_transaction_refuses_the_page() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 10)]);
    indexer.publish(paid);
    let refused = AnonymousSync::new(&bob.keys, &assets())
        .fetch(&indexer, &fresh(&bob))
        .await;
    assert!(matches!(refused, Err(AnonymousError::InvalidHistoryPage)));
}

/// A relayer's transaction key is not the wallet's, only the bundle tag finds its change.
#[tokio::test]
async fn a_relayed_proof_under_another_transaction_key_is_not_missed_by_the_fast_path() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let relayed = alice.seal_under(&indexer, &[pay(&bob.address(), 30)], ViewingKey::new());
    indexer.publish(relayed.clone());
    let own = alice.pay(&indexer, &[pay(&bob.address(), 20)]);
    let scan = AnonymousSync::new(&alice.keys, &assets())
        .with_sender_fast_path()
        .fetch(&indexer, &fresh(&alice))
        .await
        .unwrap();
    assert_eq!(found(&scan), [output(&relayed, 0), output(&own, 0)]);
    assert_eq!(scan.sent.len(), 1, "a sent row needs the wallet's own key");
    assert_eq!(scan.sent[0].tx_signature, own.tx_signature);
}

#[tokio::test]
async fn a_sender_recovers_its_change_after_a_wipe() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 30)]);
    let scan = alice.recover(&indexer).await;
    assert_eq!(found(&scan), [output(&paid, 0)]);
    assert_eq!(stream(&scan, output(&paid, 0)), AnonymousStream::FullScan);
    assert_eq!(scan.sent.len(), 1);
    assert!(scan
        .decrypted()
        .spent_nullifiers
        .contains(&paid.nullifiers[0]));
    assert_eq!(after_slot(scan.history()), Some(paid.slot));
}

/// With no change the bundle alone names the transfer, the sender still recovers its payment.
#[tokio::test]
async fn a_sender_with_no_change_recovers_its_payment_row_after_a_wipe() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 100)]);
    let scan = alice.recover(&indexer).await;
    assert!(scan.utxos.is_empty());
    assert_eq!(scan.sent.len(), 1);
    assert_eq!(scan.sent[0].amount, 100);
    assert_eq!(scan.sent[0].utxo_hash, output(&paid, 0));
    assert!(scan
        .decrypted()
        .spent_nullifiers
        .contains(&paid.nullifiers[0]));
}

/// Past the tag gap the deposit's stream stops, the ring's history still names the row.
#[tokio::test]
async fn recovery_opens_a_deposit_past_the_tag_gap() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let owner = bob.address();
    let lost = bob.keys.get_sender_view_tag(TAG_GAP + 5).unwrap();
    let deposit = deposit_row(&owner, lost, true, field(7, 3));
    let hash = deposit.output_slot.output_context.hash;
    indexer.publish_deposit(deposit);
    assert!(bob.sync(&indexer, &fresh(&bob)).await.utxos.is_empty());
    let recovered = bob.recover(&indexer).await;
    assert_eq!(found(&recovered), [hash]);
    assert_eq!(stream(&recovered, hash), AnonymousStream::FullScan);
}

#[tokio::test]
async fn a_deposit_under_a_request_tag_is_found_by_the_tag_read() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let minted = bob.history.request_tag(&bob.keys).unwrap();
    let deposit = deposit_row(&bob.address(), minted.tag, true, field(7, 4));
    let hash = deposit.output_slot.output_context.hash;
    indexer.publish_deposit(deposit);
    let scan = bob
        .sync(&indexer, &minted.history.with_ring(RING, None))
        .await;
    assert_eq!(stream(&scan, hash), AnonymousStream::Request { index: 0 });
}

#[tokio::test]
async fn a_deposit_under_the_bootstrap_tag_is_found_by_the_tag_read() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let deposit = deposit_row(
        &bob.address(),
        bob.keys.viewing_pubkey().u(),
        true,
        field(7, 5),
    );
    let hash = deposit.output_slot.output_context.hash;
    indexer.publish_deposit(deposit);
    let scan = bob.sync(&indexer, &fresh(&bob)).await;
    assert_eq!(stream(&scan, hash), AnonymousStream::Bootstrap);
}

/// A deposit to the wallet's own note takes its next sender tag, a malformed capsule opens to nothing.
#[tokio::test]
async fn an_own_deposit_is_found_on_the_sender_tag_and_moves_tx_count() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let truncated = alice.history.sender_tag(&alice.keys).unwrap();
    alice.history = truncated.history;
    let kept = alice.history.sender_tag(&alice.keys).unwrap();
    alice.history = kept.history;
    let owner = alice.address();
    for (tag, capsule, blinding) in [
        (truncated.tag, false, field(7, 1)),
        (kept.tag, true, field(7, 2)),
    ] {
        indexer.publish_deposit(deposit_row(&owner, tag, capsule, blinding));
    }
    let scanned = alice.sync(&indexer, &fresh(&alice)).await;
    let found: Vec<AnonymousStream> = scanned.utxos.iter().map(|utxo| utxo.stream).collect();
    assert_eq!(found, [AnonymousStream::Sender { index: 1 }]);
    assert_eq!(scanned.history().current().tx_count(), 2);
}

#[tokio::test]
async fn the_change_lists_every_payment_and_a_held_address_verifies_its_row() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2).address();
    let carol = Wallet::new(3).address();
    let paid = alice.pay(&indexer, &[pay(&bob, 30), pay(&carol, 20)]);
    let forged = ShieldedAddress {
        nullifier_pubkey: Wallet::new(4).address().nullifier_pubkey,
        ..carol
    };
    let held = [bob, forged];
    let scan = AnonymousSync::new(&alice.keys, &assets())
        .with_recipient_addresses(&held)
        .fetch(&indexer, &fresh(&alice))
        .await
        .unwrap();
    let rows: Vec<_> = scan
        .sent
        .iter()
        .map(|row| {
            (
                row.position,
                row.recipient_viewing_pubkey,
                row.owner_pubkey,
                row.amount,
                row.check,
                row.utxo_hash,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                1,
                bob.viewing_pubkey,
                Some(bob.signing_pubkey),
                30,
                SentCheck::Verified { mint: Mint::SOL },
                output(&paid, 1),
            ),
            (
                2,
                carol.viewing_pubkey,
                None,
                20,
                SentCheck::Unverified,
                output(&paid, 2),
            ),
        ]
    );
    assert!(scan
        .sent
        .iter()
        .all(|row| row.tx_signature == paid.tx_signature));
    let unheld = alice.sync(&indexer, &fresh(&alice)).await;
    assert!(unheld
        .sent
        .iter()
        .all(|row| row.check == SentCheck::Unverified));
    assert_eq!(unheld.sent.len(), 2);
}

/// A listed payment whose body opens to nothing leaves no row, the sync and the change go on.
#[tokio::test]
async fn a_sent_body_that_fails_to_open_leaves_no_row() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2).address();
    let mut paid = alice.seal(&indexer, &[pay(&bob, 30)]);
    // One byte short of a scheme 11 body, behind the encoding tag, the length and the scheme.
    let short_body = RECIPIENT_BODY_LEN - 1;
    let payload = &mut paid.output_slots[1].payload;
    payload.truncate(6 + short_body);
    payload[1..5].copy_from_slice(&u32::try_from(1 + short_body).unwrap().to_le_bytes());
    indexer.publish(paid.clone());
    let scan = alice.sync(&indexer, &fresh(&alice)).await;
    assert!(scan.sent.is_empty());
    assert_eq!(stream(&scan, output(&paid, 0)), AnonymousStream::ProvenTag);
}

/// A sender can hold a correct tag over any bytes, those bodies open to nothing and the sync carries on.
#[tokio::test]
async fn sender_chosen_garbage_under_a_proven_tag_never_fails_the_sync() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let tx_key = ViewingKey::new();
    let salt = random_salt();
    let noise = [0x5c; RECIPIENT_BODY_LEN];
    let first_nullifier = field(9, 9);
    let bundle_nullifier = field(9, 8);
    let bob_view = bob.keys.viewing_pubkey();
    let secret = |first_nullifier: &[u8; 32], slot| {
        DeliveredSlot {
            agreement: &tx_key.ecdh(&bob_view).unwrap(),
            tx_viewing_pk: tx_key.pubkey().as_bytes(),
            recipient_viewing_pk: bob_view.as_bytes(),
            salt: &salt,
            output_index: slot,
            first_nullifier,
        }
        .secret()
        .unwrap()
    };
    // Its blinding outside the field fails the hash rebuild.
    let named = seal_recipient_body(
        &RecipientBody {
            blinding: [0xff; 32],
            amount: 5,
            mint: Mint::SOL.asset.to_bytes(),
            ..RecipientBody::default()
        },
        &secret(&first_nullifier, 1),
    )
    .unwrap();
    let bundle = |recipient_keys: Vec<[u8; 32]>| SenderBundle {
        mint: Mint::SOL.asset.to_bytes(),
        amount: 0,
        sol_amount: 5,
        output_seed: [0x0b; 32],
        recipient_keys,
    };
    // Rebuilds under a mint the registry does not name.
    let unregistered = Mint {
        asset: Address::new_from_array([0xee; 32]),
        asset_id: 0,
    };
    let blinding = field(9, 7);
    let unknown_mint = seal_recipient_body(
        &RecipientBody {
            blinding,
            amount: 5,
            mint: unregistered.asset.to_bytes(),
            ..RecipientBody::default()
        },
        &secret(&first_nullifier, 2),
    )
    .unwrap();
    let unknown_mint_hash = Utxo {
        owner: bob.address().signing_pubkey,
        asset: unregistered,
        amount: 5,
        blinding,
        ring_program_id: Some(RING),
        data: Data::default(),
    }
    .hash(&bob.address().nullifier_pubkey, &[0; 32], &[0; 32], TREE)
    .unwrap();
    let bodies = [
        (noise.to_vec(), [0x0c; 32]),
        (named, [0x0c; 32]),
        (unknown_mint, unknown_mint_hash),
    ];
    let leaf = indexer.leaves(bodies.len());
    indexer.publish(ShieldedTransaction {
        slot: 1,
        tx_signature: Signature::from([0x77; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(tx_key.pubkey()),
        salt: Some(salt),
        output_slots: bodies
            .iter()
            .zip(0u32..)
            .map(|((body, hash), slot)| OutputSlot {
                view_tag: slot_tag(secret(&first_nullifier, slot).recipient_tag().unwrap()),
                output_context: OutputContext {
                    hash: *hash,
                    tree_id: TREE,
                    leaf_index: leaf + u64::from(slot),
                },
                payload: encode_ring_body_output(body, &[]).unwrap(),
            })
            .collect(),
        messages: vec![MessageData {
            view_tag: secret(&first_nullifier, 3).sender_tag().unwrap(),
            data: encode_ring_sender_bundle_output(
                &seal_sender_bundle(
                    &bundle(vec![keypair(8).viewing_pubkey().u(); 3]),
                    &secret(&first_nullifier, 3),
                )
                .unwrap(),
            )
            .unwrap(),
        }],
        nullifiers: vec![first_nullifier],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    // A bundle with no output to rebuild.
    indexer.publish(ShieldedTransaction {
        slot: 1,
        tx_signature: Signature::from([0x78; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(tx_key.pubkey()),
        salt: Some(salt),
        output_slots: Vec::new(),
        messages: vec![MessageData {
            view_tag: secret(&bundle_nullifier, 0).sender_tag().unwrap(),
            data: encode_ring_sender_bundle_output(
                &seal_sender_bundle(&bundle(Vec::new()), &secret(&bundle_nullifier, 0)).unwrap(),
            )
            .unwrap(),
        }],
        nullifiers: vec![bundle_nullifier],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 30)]);
    let scanned = bob.sync(&indexer, &fresh(&bob)).await;
    assert_eq!(found(&scanned), [output(&paid, 1)]);
    assert_eq!(scanned.unmatched, [unknown_mint_hash]);
    assert_eq!(
        scanned.sender_claims().len(),
        1,
        "only the reply on a note that rebuilds its hash reads as a claim"
    );
}

/// A griefing note costs one stored row, the next open reads past it and registering spends it.
#[tokio::test]
async fn an_unknown_mint_keeps_the_position_moving_and_its_note_unspendable_until_registered() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let sender = keypair(3);
    let reply = ReplyMetadata {
        viewing_key: sender.viewing_pubkey(),
        owner_key: sender.signing_pubkey().as_ed25519().unwrap(),
        nullifier_pk: sender.nullifier_key.pubkey().unwrap(),
        data: Data::default(),
    };
    let unregistered = Mint {
        asset: Address::new_from_array([0xee; 32]),
        asset_id: 9,
    };
    let tx_key = ViewingKey::new();
    let salt = random_salt();
    let first_nullifier = field(9, 6);
    let view = bob.keys.viewing_pubkey();
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
    let blinding = field(9, 5);
    let hash = Utxo {
        owner: bob.address().signing_pubkey,
        asset: unregistered,
        amount: 5,
        blinding,
        ring_program_id: Some(RING),
        data: Data::default(),
    }
    .hash(&bob.address().nullifier_pubkey, &[0; 32], &[0; 32], TREE)
    .unwrap();
    let body = seal_recipient_body(
        &RecipientBody {
            blinding,
            amount: 5,
            mint: unregistered.asset.to_bytes(),
            ..RecipientBody::default()
        },
        &secret,
    )
    .unwrap();
    let mut transaction = ShieldedTransaction {
        slot: 3,
        tx_signature: Signature::from(signature(3)),
        event_index: Some(0),
        tx_viewing_pk: Some(tx_key.pubkey()),
        salt: Some(salt),
        output_slots: vec![OutputSlot {
            view_tag: slot_tag(secret.recipient_tag().unwrap()),
            output_context: OutputContext {
                hash,
                tree_id: TREE,
                leaf_index: 0,
            },
            payload: encode_ring_body_output(
                &body,
                &seal_reply(&reply, MIN_REPLY_LEN, &secret).unwrap(),
            )
            .unwrap(),
        }],
        messages: Vec::new(),
        nullifiers: vec![first_nullifier],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    };
    indexer.publish(transaction.clone());
    transaction.slot = 4;
    transaction.tx_signature = Signature::from(signature(4));
    transaction.output_slots[0].output_context.hash = field(8, 8);
    indexer.publish(transaction);
    let mut wallet = AnonymousWallet::new(fresh(&bob));
    let scan = bob.sync(&indexer, wallet.history()).await;
    assert_eq!(scan.unmatched, [hash]);
    assert_eq!(after_slot(scan.history()), Some(4), "the position moves");
    assert!(scan.utxos.is_empty());
    let [claim] = scan.sender_claims() else {
        panic!("one claim from the matching commitment");
    };
    assert_eq!(claim.utxo_hash, hash);
    assert_eq!(claim.claim.claimed(), &reply);
    wallet.absorb(scan).unwrap();

    let mut wallet = AnonymousWallet::from_json(&wallet.to_json()).unwrap();
    let [pending] = wallet.pending_notes() else {
        panic!("one pending note");
    };
    assert_eq!(
        (pending.mint(), pending.amount(), pending.utxo_hash()),
        (unregistered.asset, 5, hash)
    );
    let [claim] = wallet.pending_claims() else {
        panic!("one stored claim");
    };
    assert_eq!(claim.utxo_hash, hash);
    assert_eq!(claim.claimed_viewing_key, reply.viewing_key);
    assert_eq!(claim.claimed_owner_key, reply.owner_key);
    assert_eq!(claim.claimed_nullifier_pk, reply.nullifier_pk);
    assert!(wallet.notes().is_empty());
    assert_eq!(
        verify_spendable(&bob.keys, &wallet.decrypted())
            .unwrap()
            .utxos()
            .count(),
        0,
        "nothing to spend before the mint registers"
    );

    let next = bob.sync(&indexer, wallet.history()).await;
    assert!(
        next.utxos.is_empty() && next.unmatched.is_empty(),
        "no row reads again"
    );
    wallet.absorb(next).unwrap();
    assert_eq!(wallet.pending_notes().len(), 1);

    wallet.resolve_pending(&assets());
    assert_eq!(wallet.pending_notes().len(), 1, "still unregistered");

    indexer.take_ring_pages();
    wallet.resolve_pending(&RingAssets::new([unregistered]).unwrap());
    assert_eq!(indexer.take_ring_pages(), 0, "resolving reads no history");
    assert!(wallet.pending_notes().is_empty());
    let spendable = verify_spendable(&bob.keys, &wallet.decrypted()).unwrap();
    let notes: Vec<_> = spendable.utxos().collect();
    let [note] = notes.as_slice() else {
        panic!("one spendable note");
    };
    assert_eq!(note.utxo_hash, hash);
    assert_eq!(note.utxo.asset, unregistered);
    assert_ne!(note.nullifier, [0; 32]);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HolderCall {
    Decrypt,
    TagMatches,
    DeliverySecrets,
}

/// A remote holder whose first call of one kind fails.
struct FlakyHolder {
    keys: ShieldedKeypair,
    failing: HolderCall,
    failed: AtomicBool,
}

impl FlakyHolder {
    fn new(seed: u8, failing: HolderCall) -> Self {
        Self {
            keys: keypair(seed),
            failing,
            failed: AtomicBool::new(false),
        }
    }

    fn fails(&self, call: HolderCall) -> bool {
        call == self.failing && !self.failed.swap(true, Ordering::Relaxed)
    }
}

impl ShieldedKeys for FlakyHolder {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        self.keys.address()
    }

    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        self.keys.viewing_public_keys()
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        if self.fails(HolderCall::Decrypt) {
            return Err(TransactionError::IncompleteDecryption { got: 0, want: 1 });
        }
        self.keys.decrypt(requests)
    }

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.keys.derive(requests)
    }

    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        self.keys.transaction_keys(requests)
    }
}

impl MergeSeedHolder for FlakyHolder {
    fn merge_seeds(&self, requests: &[MergeSeedRequest]) -> Result<Vec<MergeSeed>, RingKeyError> {
        self.keys.merge_seeds(requests)
    }
}

impl RingKeys for FlakyHolder {
    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, RingKeyError> {
        if self.fails(HolderCall::DeliverySecrets) {
            return Err(RingKeyError::UnknownViewingKey);
        }
        self.keys.ring_delivery_secrets(requests)
    }

    fn ring_tag_matches(
        &self,
        frames: &[RingTagFrame],
    ) -> Result<Vec<Vec<Option<SlotSecret>>>, RingKeyError> {
        if self.fails(HolderCall::TagMatches) {
            return Err(RingKeyError::UnknownViewingKey);
        }
        self.keys.ring_tag_matches(frames)
    }

    fn view_tags(&self, requests: &[ViewTagRequest]) -> Result<Vec<ViewTag>, RingKeyError> {
        self.keys.view_tags(requests)
    }
}

/// `fetch` fails with the holder and stores nothing, the retry finds `note`.
async fn a_failed_holder_moves_nothing(
    indexer: &Indexer,
    holder: &FlakyHolder,
    wallet: &mut AnonymousWallet,
    note: [u8; 32],
) {
    let before = wallet.to_json();
    assert!(AnonymousSync::new(holder, &assets())
        .fetch(indexer, wallet.history())
        .await
        .is_err());
    assert_eq!(wallet.to_json(), before, "a failed read stores nothing");
    assert_eq!(after_slot(wallet.history()), None);
    let scan = AnonymousSync::new(holder, &assets())
        .fetch(indexer, wallet.history())
        .await
        .unwrap();
    assert!(after_slot(scan.history()).is_some());
    wallet.absorb(scan).unwrap();
    let held: Vec<[u8; 32]> = wallet
        .notes()
        .iter()
        .map(|held| held.utxo_hash)
        .chain(wallet.pending_notes().iter().map(|held| held.utxo_hash()))
        .collect();
    assert_eq!(held, [note]);
}

#[tokio::test]
async fn a_holder_failure_on_a_tag_test_leaves_the_position_and_the_retry_finds_the_note() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 30)]);
    let holder = FlakyHolder::new(2, HolderCall::TagMatches);
    let mut wallet = AnonymousWallet::new(fresh(&bob));
    a_failed_holder_moves_nothing(&indexer, &holder, &mut wallet, output(&paid, 1)).await;
}

#[tokio::test]
async fn a_holder_failure_on_a_deposit_leaves_the_position_and_the_retry_finds_the_note() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let deposit = deposit_row(
        &bob.address(),
        bob.keys.viewing_pubkey().u(),
        true,
        field(7, 7),
    );
    let hash = deposit.output_slot.output_context.hash;
    indexer.publish_deposit(deposit);
    let holder = FlakyHolder::new(2, HolderCall::Decrypt);
    let mut wallet = AnonymousWallet::new(fresh(&bob));
    a_failed_holder_moves_nothing(&indexer, &holder, &mut wallet, hash).await;
}

#[tokio::test]
async fn a_holder_failure_in_recovery_fails_the_read_and_the_retry_finds_the_note() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 30)]);
    let holder = FlakyHolder::new(2, HolderCall::DeliverySecrets);
    let history = fresh(&bob);
    assert!(AnonymousSync::new(&holder, &assets())
        .full_scan(&indexer, &history, RING)
        .await
        .is_err());
    let scan = AnonymousSync::new(&holder, &assets())
        .full_scan(&indexer, &history, RING)
        .await
        .unwrap();
    assert_eq!(found(&scan), [output(&paid, 1)]);
}

/// A deposit under an unregistered mint holds back its verified note the same way.
#[tokio::test]
async fn a_deposit_of_an_unknown_mint_waits_with_its_data_hashes() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let unregistered = Mint {
        asset: Address::new_from_array([0xee; 32]),
        asset_id: 9,
    };
    let deposit = deposit_row_in(
        &bob.address(),
        bob.keys.viewing_pubkey().u(),
        field(7, 6),
        unregistered,
    );
    let hash = deposit.output_slot.output_context.hash;
    indexer.publish_deposit(deposit);
    let mut wallet = AnonymousWallet::new(fresh(&bob));
    let scan = bob.sync(&indexer, wallet.history()).await;
    assert_eq!(scan.pending_notes().len(), 1);
    assert_eq!(scan.pending_notes()[0].utxo_hash(), hash);
    assert!(scan.utxos.is_empty());
    wallet.absorb(scan).unwrap();
    wallet.resolve_pending(&RingAssets::new([unregistered]).unwrap());
    assert_eq!(wallet.notes()[0].utxo_hash, hash);
    assert_eq!(wallet.notes()[0].utxo.asset, unregistered);
}

/// A merge of notes the wallet never opened names only unknown nullifiers, recovery still rebuilds it.
#[tokio::test]
async fn recovery_opens_a_merge_whose_inputs_the_wallet_never_saw() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let first = [0x11; 32];
    let owner = bob.address();
    let nullifier_key = &bob.keys.nullifier_key;
    let merged = Utxo {
        owner: owner.signing_pubkey,
        asset: Mint::SOL,
        amount: 100,
        blinding: merge_output_blinding(nullifier_key, &first).unwrap(),
        ring_program_id: Some(RING),
        data: Default::default(),
    };
    let merged_hash = merged
        .hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    let salt = [8; 16];
    let ciphertext = MergeOutputPlaintext {
        amount: 100,
        mint: Mint::SOL.asset,
    }
    .encrypt(&merge_output_key(nullifier_key, &first).unwrap(), &salt)
    .unwrap();
    indexer.publish(ShieldedTransaction {
        slot: 99,
        tx_signature: Signature::from([0x99; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: first,
            output_context: OutputContext {
                hash: merged_hash,
                tree_id: TREE,
                leaf_index: indexer.leaves(1),
            },
            payload: encode_merge_output_data(MergeOutputDataRef {
                salt: &salt,
                ciphertext: &ciphertext,
                prefix: &[[0; 32]],
                binding: spr_event::MergeCiphertextBinding::Unverified,
            }),
        }],
        messages: Vec::new(),
        nullifiers: vec![first],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    let scan = AnonymousSync::new(&bob.keys, &assets())
        .full_scan(&indexer, &fresh(&bob), RING)
        .await
        .unwrap();
    assert_eq!(found(&scan), [merged_hash]);
    assert_eq!(
        scan.utxos[0].stream,
        AnonymousStream::Merge {
            first_nullifier: first
        }
    );
    let tag_only = bob.sync(&indexer, &fresh(&bob)).await;
    assert!(tag_only.utxos.is_empty());
}

#[test]
fn a_ring_added_after_a_rotation_reaches_every_held_key() {
    let old = ViewingKey::new().pubkey();
    let new = ViewingKey::new().pubkey();
    let history = ViewingHistory::new(old, 0)
        .with_rotated_key(new, 1)
        .unwrap()
        .with_ring(RING, None);
    for key in [old, new] {
        assert!(history
            .entry(&key)
            .unwrap()
            .ring_positions()
            .contains_key(&RING));
    }
}

/// `Spent` wins over the zero key, and a spent note leaves the exposed list and the balance.
#[tokio::test]
async fn a_spent_zero_key_note_leaves_the_exposed_list() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let unkeyed = ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
        ..bob.address()
    };
    let paid = alice.pay(&indexer, &[pay(&unkeyed, 30)]);
    let scan = bob.sync(&indexer, &fresh(&bob)).await;
    assert_eq!(found(&scan), [output(&paid, 1)]);
    let mut wallet = AnonymousWallet::new(fresh(&bob));
    wallet.absorb(scan).unwrap();
    let note = wallet.notes()[0].clone();
    assert_eq!(wallet.note_state(&note), NoteState::ExposedIfSpent);
    let balance = wallet.balances()[&Mint::SOL.asset];
    assert_eq!((balance.spendable, balance.exposed_if_spent), (0, 30));
    let owned = verify_ring_owned(&bob.keys, &wallet.decrypted()).unwrap();
    assert!(owned.owned.utxos.is_empty());
    assert_eq!(owned.exposed_if_spent.len(), 1);
    assert_eq!(owned.exposed_if_spent[0].nullifier, note.nullifier);

    let spent = DecryptionResult {
        spent_nullifiers: [note.nullifier].into_iter().collect(),
        ..wallet.decrypted()
    };
    let owned = verify_ring_owned(&bob.keys, &spent).unwrap();
    assert!(owned.exposed_if_spent.is_empty());
    assert!(owned.spent_exposed.contains(&note.nullifier));
    assert_eq!(
        note_state(&note, |nullifier| spent
            .spent_nullifiers
            .contains(nullifier)),
        NoteState::Spent
    );
}

#[tokio::test]
async fn a_merge_of_the_wallets_notes_is_found_by_recovery_and_marks_them_spent() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    for amount in [70, 30] {
        alice.pay(&indexer, &[pay(&bob.address(), amount)]);
    }
    let held = bob.sync(&indexer, &fresh(&bob)).await;
    let notes = &held.decrypted().utxos;
    let nullifiers: Vec<[u8; 32]> = notes.iter().map(|utxo| utxo.nullifier).collect();
    let first = nullifiers[0];
    let owner = bob.address();
    let nullifier_key = &bob.keys.nullifier_key;
    let merged = Utxo {
        owner: owner.signing_pubkey,
        asset: Mint::SOL,
        amount: 100,
        blinding: merge_output_blinding(nullifier_key, &first).unwrap(),
        ring_program_id: Some(RING),
        data: Default::default(),
    };
    let merged_hash = merged
        .hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
        .unwrap();
    let salt = [8; 16];
    let ciphertext = MergeOutputPlaintext {
        amount: 100,
        mint: Mint::SOL.asset,
    }
    .encrypt(&merge_output_key(nullifier_key, &first).unwrap(), &salt)
    .unwrap();
    indexer.publish(ShieldedTransaction {
        slot: 99,
        tx_signature: Signature::from([0x99; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: first,
            output_context: OutputContext {
                hash: merged_hash,
                tree_id: TREE,
                leaf_index: indexer.leaves(1),
            },
            payload: encode_merge_output_data(MergeOutputDataRef {
                salt: &salt,
                ciphertext: &ciphertext,
                prefix: &[[0; 32]],
                binding: spr_event::MergeCiphertextBinding::Unverified,
            }),
        }],
        messages: Vec::new(),
        nullifiers,
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    let next = AnonymousSync::new(&bob.keys, &assets())
        .with_held_notes(&held.decrypted().utxos)
        .fetch(&indexer, held.history())
        .await
        .unwrap();
    assert_eq!(
        stream(&next, merged_hash),
        AnonymousStream::Merge {
            first_nullifier: first
        }
    );
    let recovered = bob.recover(&indexer).await;
    assert_eq!(
        stream(&recovered, merged_hash),
        AnonymousStream::Merge {
            first_nullifier: first
        }
    );
    let unspent: Vec<[u8; 32]> = verify_spendable(&bob.keys, recovered.decrypted())
        .unwrap()
        .utxos()
        .map(|utxo| utxo.utxo_hash)
        .collect();
    assert_eq!(unspent, [merged_hash]);
}

/// A claim stays one until the wallet confirms it, confirming marks the contact and reads nothing else.
#[tokio::test]
async fn a_reply_stays_an_unverified_claim_until_the_wallet_confirms_it() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    let bob = Wallet::new(2);
    let first = alice.pay(&indexer, &[pay(&bob.address(), 10)]);
    let sender = alice.keys.viewing_pubkey();
    let unconfirmed = bob.sync(&indexer, &fresh(&bob)).await;
    let [claim] = unconfirmed.sender_claims() else {
        panic!("one claim on the note found");
    };
    assert_eq!(claim.utxo_hash, output(&first, 1));
    assert_eq!(claim.claim.claimed().viewing_key, sender);
    assert!(!unconfirmed
        .history()
        .current()
        .known_senders()
        .contains(&sender));
    let mut wallet = AnonymousWallet::new(fresh(&bob));
    assert!(matches!(
        wallet.confirm_claim(sender),
        Err(AnonymousError::UnknownSenderClaim)
    ));
    wallet.absorb(unconfirmed).unwrap();
    let restarted = AnonymousWallet::from_json(&wallet.to_json()).unwrap();
    assert_eq!(restarted.pending_claims().len(), 1);
    assert_eq!(restarted.pending_claims()[0].claimed_viewing_key, sender);
    assert!(!restarted
        .history()
        .current()
        .known_senders()
        .contains(&sender));
    let mut confirmed = restarted;
    confirmed.confirm_claim(sender).unwrap();
    assert!(confirmed.pending_claims().is_empty());
    assert!(confirmed
        .history()
        .current()
        .known_senders()
        .contains(&sender));
}

/// A send carries no reply unless it opts in, the recipient learns no sender.
#[tokio::test]
async fn a_payment_without_a_reply_names_no_sender() {
    let indexer = Indexer::default();
    let mut alice = Wallet::new(1);
    alice.replies = false;
    let bob = Wallet::new(2);
    let paid = alice.pay(&indexer, &[pay(&bob.address(), 10)]);
    assert_eq!(
        paid.output_slots[1].payload.len(),
        8 + RECIPIENT_BODY_LEN,
        "no reply bytes follow the body"
    );
    let scan = bob.sync(&indexer, &fresh(&bob)).await;
    assert_eq!(scan.utxos.len(), 1);
    assert!(scan.sender_claims().is_empty());
    assert!(scan.history().current().known_senders().is_empty());
}

#[test]
fn a_wallet_document_round_trips_and_refuses_another_version() {
    let bob = Wallet::new(2);
    let mut confirmed = fresh(&bob);
    confirmed
        .confirm_sender(keypair(3).viewing_pubkey())
        .unwrap();
    let rotated = confirmed
        .with_rotated_key(keypair(4).viewing_pubkey(), 5)
        .unwrap();
    let wallet = AnonymousWallet::new(rotated);
    let json = wallet.to_json();
    assert_eq!(AnonymousWallet::from_json(&json).unwrap(), wallet);
    assert!(json.contains(&format!("\"version\":{VIEWING_HISTORY_VERSION}")));
    let other = json.replacen(
        &format!("\"version\":{VIEWING_HISTORY_VERSION}"),
        "\"version\":6",
        1,
    );
    let bare = r#"{"version":6,"viewingHistory":[]}"#;
    for refused in [other.as_str(), bare] {
        assert!(matches!(
            AnonymousWallet::from_json(refused),
            Err(AnonymousError::ViewingHistoryVersion { version: 6 })
        ));
    }
}

#[test]
fn a_bare_history_of_the_current_version_is_refused() {
    let bob = Wallet::new(2);
    let wallet = AnonymousWallet::new(fresh(&bob));
    let document: serde_json::Value = serde_json::from_str(&wallet.to_json()).unwrap();
    assert!(matches!(
        AnonymousWallet::from_json(&document["history"].to_string()),
        Err(AnonymousError::WalletDocument(_))
    ));
}

#[tokio::test]
async fn a_held_key_with_no_history_entry_refuses_the_scan() {
    let indexer = Indexer::default();
    let identity = keypair(2);
    let keys = RotatingRingKeys::new(&identity)
        .unwrap()
        .with_retired(vec![ViewingKey::new()])
        .unwrap();
    let history = ViewingHistory::new(identity.viewing_pubkey(), 0).with_ring(RING, None);
    assert!(matches!(
        AnonymousSync::new(&keys, &assets())
            .fetch(&indexer, &history)
            .await,
        Err(AnonymousError::HeldKeyNotInHistory)
    ));
}

#[test]
fn a_history_prints_no_contact() {
    let bob = Wallet::new(2);
    let sender = keypair(3).viewing_pubkey();
    let mut history = fresh(&bob);
    history.confirm_sender(sender).unwrap();
    let printed = format!("{history:?}");
    assert!(!printed.contains(&format!("{:?}", sender.as_bytes())));
    assert!(!printed.contains(&format!("{:?}", sender.u())));
}

#[test]
fn a_tag_round_reads_at_most_one_request() {
    assert!(usize::try_from(TAG_GAP).unwrap() <= TAGS_PER_REQUEST);
}

fn deposit_row_in(
    owner: &ShieldedAddress,
    tag: ViewTag,
    blinding: [u8; 32],
    asset: Mint,
) -> EncryptedUtxoMatch {
    deposit_of(owner, tag, true, blinding, asset)
}

fn deposit_row(
    owner: &ShieldedAddress,
    tag: ViewTag,
    capsule: bool,
    blinding: [u8; 32],
) -> EncryptedUtxoMatch {
    deposit_of(owner, tag, capsule, blinding, Mint::SOL)
}

fn deposit_of(
    owner: &ShieldedAddress,
    tag: ViewTag,
    capsule: bool,
    blinding: [u8; 32],
    deposited: Mint,
) -> EncryptedUtxoMatch {
    let encrypted = RingDepositPlaintext {
        blinding,
        utxo_data: None,
        memo: None,
        ring_data: Vec::new(),
    }
    .encrypt(&owner.viewing_pubkey)
    .unwrap();
    let ciphertext = match capsule {
        true => RingDepositAuditCapsule {
            slot_index: 0,
            eph_pk: &[2; 33],
            ciphertext: &[0; custom_ring_interface::RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
            recipient_ciphertext: &encrypted.ciphertext,
        }
        .encode(),
        false => b"CRDEP002".to_vec(),
    };
    let payload = encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
        owner_utxo_hash: owner_utxo_hash(&owner.owner_hash().unwrap(), &blinding).unwrap(),
        asset: deposited.asset.to_bytes(),
        amount: 25,
        data_hash: None,
        ring_program_id: RING.to_bytes(),
        ring_data_hash: [0; 32],
        encrypted: EncryptedRingDepositData {
            ciphertext,
            ..encrypted
        },
    });
    let hash = Utxo {
        owner: owner.signing_pubkey,
        asset: deposited,
        amount: 25,
        blinding,
        ring_program_id: Some(RING),
        data: Default::default(),
    }
    .hash(&owner.nullifier_pubkey, &[0; 32], &[0; 32], TREE)
    .unwrap();
    EncryptedUtxoMatch {
        slot: 1,
        tx_signature: Signature::from([blinding[31]; 64]),
        output_slot: OutputSlot {
            view_tag: tag,
            output_context: OutputContext {
                hash,
                tree_id: TREE,
                leaf_index: 500 + u64::from(blinding[31]),
            },
            payload,
        },
        tx_viewing_pk: None,
        salt: None,
    }
}

fn publish_owner_merge(
    indexer: &Indexer,
    owner: &ShieldedAddress,
    seed: &MergeSeed,
    first: [u8; 32],
) -> [u8; 32] {
    let merged = Utxo {
        owner: owner.signing_pubkey,
        asset: Mint::SOL,
        amount: 100,
        blinding: seed.output_blinding(&first).unwrap(),
        ring_program_id: Some(RING),
        data: Default::default(),
    };
    let hash = merged
        .hash(&ZERO_NULLIFIER_PUBKEY, &[0; 32], &[0; 32], TREE)
        .unwrap();
    let salt = [8; 16];
    let ciphertext = MergeOutputPlaintext {
        amount: 100,
        mint: Mint::SOL.asset,
    }
    .encrypt(&seed.output_key(&first).unwrap(), &salt)
    .unwrap();
    indexer.publish(ShieldedTransaction {
        slot: 1,
        tx_signature: Signature::from([first[0]; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: owner.signing_pubkey.owner_proof_input_hash().unwrap(),
            output_context: OutputContext {
                hash,
                tree_id: TREE,
                leaf_index: indexer.leaves(1),
            },
            payload: encode_merge_output_data(MergeOutputDataRef {
                salt: &salt,
                ciphertext: &ciphertext,
                prefix: &[[0; 32]],
                binding: spr_event::MergeCiphertextBinding::Proven,
            }),
        }],
        messages: Vec::new(),
        nullifiers: vec![first],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    hash
}

fn own_seed(wallet: &Wallet, viewing_pubkey: X25519Pubkey, first: [u8; 32]) -> MergeSeed {
    wallet
        .keys
        .merge_seeds(&[MergeSeedRequest {
            viewing_pubkey,
            ring_program_id: RING,
            first_nullifier: first,
        }])
        .unwrap()
        .remove(0)
}

#[tokio::test]
async fn a_zero_key_merge_opens_with_its_input_history_deleted_and_reads_exposed() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let first = [0x11; 32];
    let seed = own_seed(&bob, bob.keys.viewing_key.pubkey(), first);
    let hash = publish_owner_merge(&indexer, &bob.address(), &seed, first);
    let scan = AnonymousSync::new(&bob.keys, &assets())
        .full_scan(&indexer, &fresh(&bob), RING)
        .await
        .unwrap();
    assert_eq!(found(&scan), [hash]);
    assert_eq!(
        scan.utxos[0].stream,
        AnonymousStream::Merge {
            first_nullifier: first
        }
    );
    let note = &scan.decrypted().utxos[0];
    assert_eq!(note.nullifier_pubkey, ZERO_NULLIFIER_PUBKEY);
    assert_eq!(note.utxo.amount, 100);
    assert_eq!(
        note_state(note, |_| false),
        NoteState::ExposedIfSpent,
        "a zero-key merge output spends only by naming its owner"
    );
    assert_eq!(note_state(note, |_| true), NoteState::Spent);
}

#[tokio::test]
async fn another_wallets_owner_tag_opens_nothing_and_a_seed_of_another_key_opens_nothing() {
    let indexer = Indexer::default();
    let (bob, carol) = (Wallet::new(2), Wallet::new(3));
    let first = [0x12; 32];
    let carols = own_seed(&carol, carol.keys.viewing_key.pubkey(), first);
    publish_owner_merge(&indexer, &carol.address(), &carols, first);
    let scan = AnonymousSync::new(&bob.keys, &assets())
        .full_scan(&indexer, &fresh(&bob), RING)
        .await
        .unwrap();
    assert!(found(&scan).is_empty());

    // A keeper-chosen seed reads the same.
    let second = [0x13; 32];
    let foreign = own_seed(&carol, carol.keys.viewing_key.pubkey(), second);
    publish_owner_merge(&indexer, &bob.address(), &foreign, second);
    let scan = AnonymousSync::new(&bob.keys, &assets())
        .full_scan(&indexer, &fresh(&bob), RING)
        .await
        .unwrap();
    assert!(found(&scan).is_empty());
}

#[tokio::test]
async fn a_rotated_wallet_opens_a_zero_key_merge_under_its_retired_key() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let retired = bob.keys.viewing_key.pubkey();
    let first = [0x14; 32];
    let seed = own_seed(&bob, retired, first);
    let hash = publish_owner_merge(&indexer, &bob.address(), &seed, first);
    let next = ViewingKey::new();
    let next_key = next.pubkey();
    let rotated = RotatingRingKeys::new(&bob.keys)
        .unwrap()
        .rotate(next)
        .unwrap();
    let history = fresh(&bob).with_rotated_key(next_key, 1).unwrap();
    let scan = AnonymousSync::new(&rotated, &assets())
        .full_scan(&indexer, &history, RING)
        .await
        .unwrap();
    assert_eq!(found(&scan), [hash]);
}

#[tokio::test]
async fn an_extended_recipient_body_rebuilds_its_commitment_with_its_data() {
    let indexer = Indexer::default();
    let bob = Wallet::new(2);
    let tx_key = ViewingKey::new();
    let salt = random_salt();
    let first_nullifier = field(9, 9);
    let bob_view = bob.keys.viewing_pubkey();
    let secret = DeliveredSlot {
        agreement: &tx_key.ecdh(&bob_view).unwrap(),
        tx_viewing_pk: tx_key.pubkey().as_bytes(),
        recipient_viewing_pk: bob_view.as_bytes(),
        salt: &salt,
        output_index: 0,
        first_nullifier: &first_nullifier,
    }
    .secret()
    .unwrap();
    let (blinding, data_hash, ring_data_hash) = (field(9, 7), field(9, 6), field(9, 5));
    let note = Utxo {
        owner: bob.address().signing_pubkey,
        asset: Mint::SOL,
        amount: 5,
        blinding,
        ring_program_id: Some(RING),
        data: Data::default(),
    };
    let hash = note
        .hash(
            &bob.address().nullifier_pubkey,
            &data_hash,
            &ring_data_hash,
            TREE,
        )
        .unwrap();
    let body = seal_recipient_body(
        &RecipientBody {
            blinding,
            amount: 5,
            mint: Mint::SOL.asset.to_bytes(),
            ring_data_hash: Some(ring_data_hash),
            data: [&data_hash[..], b"memo"].concat(),
        },
        &secret,
    )
    .unwrap();
    assert!(body.len() > RECIPIENT_BODY_LEN);
    indexer.publish(ShieldedTransaction {
        slot: 1,
        tx_signature: Signature::from([0x78; 64]),
        event_index: Some(0),
        tx_viewing_pk: Some(tx_key.pubkey()),
        salt: Some(salt),
        output_slots: vec![OutputSlot {
            view_tag: slot_tag(secret.recipient_tag().unwrap()),
            output_context: OutputContext {
                hash,
                tree_id: TREE,
                leaf_index: indexer.leaves(1),
            },
            payload: encode_ring_body_output(&body, &[]).unwrap(),
        }],
        messages: Vec::new(),
        nullifiers: vec![first_nullifier],
        proofless: false,
        ring_config: None,
        ring_program_id: Some(RING),
    });
    let scan = AnonymousSync::new(&bob.keys, &assets())
        .full_scan(&indexer, &fresh(&bob), RING)
        .await
        .unwrap();
    assert_eq!(found(&scan), [hash]);
    let opened = &scan.decrypted().utxos[0];
    assert_eq!(opened.data_hash, Some(data_hash));
    assert_eq!(opened.ring_data_hash, Some(ring_data_hash));
    assert_eq!(
        opened.utxo.data.utxo_data().map(<[u8]>::to_vec),
        Some(b"memo".to_vec())
    );
}
