//! Anonymous ring sync, spec First Time Sync Wallet, every stream resumed from its scan watermark.

use std::collections::{BTreeSet, HashMap, HashSet};

use custom_ring_interface::{anonymous_recipient_output_body, anonymous_sender_output_body};
use solana_address::Address;
use solana_signature::Signature;
use zeroize::Zeroizing;
use zolana_client::{AsyncRpc, IndexerRpcConfig};
use zolana_event_parser::decode_encrypted_ring_deposit_output_data;
use zolana_keypair::{
    viewing_key::ViewTag, KeypairError, PublicKey, ShieldedAddress, ViewingKey, X25519Pubkey,
};
use zolana_ring_keys::{
    RingKeys, SharedTagPair, SharedTagsRequest, SharedViewTags, ViewTagRequest, ViewTagStream,
};
use zolana_ring_transaction::{
    is_contributory, listed_recipients, AnonymousOutput, RingAssets, DUMMY_RECIPIENT_VIEWING_PK,
};
use zolana_transaction::{
    serialization::anonymous::{
        AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext,
    },
    verify_owned, DecryptLabel, DecryptRequest, DecryptionResult, DepositPayload, DeriveRequest,
    Mint, OutputSlot, ShieldedKeys, ShieldedTransaction, TransactionError, TransactionKeyRequest,
    Utxo, WalletUtxo,
};

use crate::{
    delivered::RingDeliveryContext,
    deposit_payload, exactly_one, exactly_one_each,
    tags::{IndexerReads, TagWindow, TAG_WINDOW},
    viewing_history::{Learned, StreamCounter, ViewingHistory, ViewingKeyEntry},
    AnonymousError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousStream {
    /// A change output or a deposit under `get_sender_view_tag(index)`.
    Sender {
        index: u64,
    },
    Request {
        index: u64,
    },
    Bootstrap,
    /// Under `get_recipient_shared_view_tag(sender, index)`.
    Shared {
        sender: X25519Pubkey,
        index: u64,
    },
    Merge {
        first_nullifier: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousRingUtxo {
    pub utxo_hash: [u8; 32],
    pub viewing_pubkey: X25519Pubkey,
    pub stream: AnonymousStream,
}

/// A counterparty a full map left out, its stream unread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkippedCounterparty {
    pub viewing_pubkey: X25519Pubkey,
    pub pair: SharedTagPair,
}

/// One payment the wallet's sender bundle lists, its body opened with the transaction key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentPayment {
    pub tx_signature: Signature,
    pub utxo_hash: [u8; 32],
    pub position: u32,
    pub recipient_viewing_pubkey: X25519Pubkey,
    pub owner_pubkey: PublicKey,
    pub amount: u64,
    pub check: SentCheck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentCheck {
    /// A held recipient address rebuilt the published hash under `mint`.
    Verified { mint: Mint },
    /// No held address names the owner and viewing key, or the body rebuilds no hash.
    Unverified,
}

#[derive(Clone, Debug)]
pub struct AnonymousScan {
    /// Counters, watermarks and counterparties raised to what the indexer holds, never lowered.
    pub history: ViewingHistory,
    /// The notes found past each watermark, their spends read from every fetched nullifier.
    pub decrypted: DecryptionResult,
    pub utxos: Vec<AnonymousRingUtxo>,
    pub skipped_counterparties: Vec<SkippedCounterparty>,
    /// Bodies that decoded as the wallet's but rebuilt under no mint of `assets`.
    pub unmatched: Vec<[u8; 32]>,
    /// The wallet's payments in the transfers whose change it found, a body that fails to open left out.
    pub sent: Vec<SentPayment>,
}

/// Reads every anonymous stream of each held viewing key, each tag derived by `keys`.
#[must_use]
pub struct AnonymousSync<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a RingAssets,
    config: Option<IndexerRpcConfig>,
    deposit_payload: DepositPayload,
    from: ScanFrom,
    held: &'a [WalletUtxo],
    recipients: &'a [ShieldedAddress],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanFrom {
    Watermark,
    Start,
}

impl<'a, K: ShieldedKeys + RingKeys + ?Sized> AnonymousSync<'a, K> {
    pub fn new(keys: &'a K, assets: &'a RingAssets) -> Self {
        Self {
            keys,
            assets,
            config: None,
            deposit_payload,
            from: ScanFrom::Watermark,
            held: &[],
            recipients: &[],
        }
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// A framing of the deposit ciphertexts other than the audit capsule.
    pub fn with_deposit_payload(mut self, deposit_payload: DepositPayload) -> Self {
        self.deposit_payload = deposit_payload;
        self
    }

    /// Every stream from index 0, for a wallet that keeps no notes between syncs.
    pub fn with_full_rescan(mut self) -> Self {
        self.from = ScanFrom::Start;
        self
    }

    /// Notes found by earlier syncs, a merge spending them is found from their nullifiers.
    pub fn with_held_notes(mut self, held: &'a [WalletUtxo]) -> Self {
        self.held = held;
        self
    }

    /// The recipients' addresses the wallet holds, a sent payment verifies only against one.
    pub fn with_recipient_addresses(mut self, recipients: &'a [ShieldedAddress]) -> Self {
        self.recipients = recipients;
        self
    }

    /// An entry whose key the holder lacks stays as stored.
    pub async fn fetch<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        history: &ViewingHistory,
    ) -> Result<AnonymousScan, AnonymousError> {
        let held = self.keys.viewing_public_keys();
        let mut scan = Scan {
            sync: self,
            address: self.keys.address()?,
            reads: IndexerReads::configured(indexer, self.config),
            history: history.clone(),
            found: Vec::new(),
            utxos: Vec::new(),
            decrypted: DecryptionResult::default(),
            opened: HashSet::new(),
            spends: HashSet::new(),
            skipped: Vec::new(),
            unmatched: Vec::new(),
            sent: Vec::new(),
        };
        for index in 0..scan.history.entries().len() {
            let viewing_pubkey = scan.history.entries()[index].viewing_pubkey();
            if held.contains(&viewing_pubkey) {
                scan.entry(index).await?;
            }
        }
        scan.merges().await?;
        let Scan {
            history,
            found,
            utxos,
            mut decrypted,
            skipped,
            unmatched,
            sent,
            ..
        } = scan;
        assign_nullifiers(self.keys, &mut decrypted, found)?;
        Ok(AnonymousScan {
            history,
            decrypted,
            utxos,
            skipped_counterparties: skipped,
            unmatched,
            sent,
        })
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Sender,
    Request,
    /// `ToRecipient` streams are the wallet's own payments, observed and never opened.
    Pair(SharedTagPair),
}

/// Derives a stream's tags window by window, a pair's ECDH once per sync.
enum TagSource {
    Own(fn(u64) -> ViewTagStream),
    Shared(SharedViewTags),
}

impl Stream {
    fn found(self, index: u64) -> Option<AnonymousStream> {
        match self {
            Self::Sender => Some(AnonymousStream::Sender { index }),
            Self::Request => Some(AnonymousStream::Request { index }),
            Self::Pair(SharedTagPair::FromSender(sender)) => {
                Some(AnonymousStream::Shared { sender, index })
            }
            Self::Pair(SharedTagPair::ToRecipient(_)) => None,
        }
    }
}

struct Scan<'s, 'a, 'r, I: ?Sized, K: ?Sized> {
    sync: &'s AnonymousSync<'a, K>,
    address: ShieldedAddress,
    reads: IndexerReads<'r, I>,
    history: ViewingHistory,
    /// Notes whose rebuilt hash matched, before their nullifiers.
    found: Vec<WalletUtxo>,
    utxos: Vec<AnonymousRingUtxo>,
    decrypted: DecryptionResult,
    /// Sites already read, a body under two tags opens once.
    opened: HashSet<(Signature, Option<u16>, Site)>,
    spends: HashSet<(Signature, Option<u16>)>,
    skipped: Vec<SkippedCounterparty>,
    unmatched: Vec<[u8; 32]>,
    sent: Vec<SentPayment>,
}

/// A recipient body at an output, a sender bundle in a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Site {
    Output(usize),
    Message(usize),
}

struct Hit<'t> {
    tx: &'t ShieldedTransaction,
    site: Site,
    found: Option<AnonymousStream>,
}

/// A scheme 1 or 2 body the entry's key may open.
struct Body<'t> {
    tx: &'t ShieldedTransaction,
    site: Site,
    ciphertext: Vec<u8>,
    context: RingDeliveryContext,
    found: AnonymousStream,
}

impl Body<'_> {
    /// Messages follow the outputs.
    fn slot_index(&self) -> Result<u32, TransactionError> {
        let index = match self.site {
            Site::Output(position) => position,
            Site::Message(message) => self.tx.output_slots.len() + message,
        };
        u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)
    }
}

impl<I: AsyncRpc + ?Sized, K: ShieldedKeys + RingKeys + ?Sized> Scan<'_, '_, '_, I, K> {
    /// Phase 1 reads the sender, request and bootstrap tags, Phase 2 repeats while it adds a counterparty.
    async fn entry(&mut self, index: usize) -> Result<(), AnonymousError> {
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        self.stream(index, Stream::Sender).await?;
        self.stream(index, Stream::Request).await?;
        let bootstrap = TagWindow::new(0, [viewing_pubkey.u()]);
        let _ = self
            .window(index, &bootstrap, |_| Some(AnonymousStream::Bootstrap))
            .await?;
        let mut scanned: HashSet<SharedTagPair> = HashSet::new();
        loop {
            let entry = &self.history.entries()[index];
            let pending: Vec<SharedTagPair> = entry
                .known_senders()
                .keys()
                .map(|sender| SharedTagPair::FromSender(*sender))
                .chain(
                    entry
                        .known_recipients()
                        .keys()
                        .map(|recipient| SharedTagPair::ToRecipient(*recipient)),
                )
                .filter(|pair| scanned.insert(*pair))
                .collect();
            if pending.is_empty() {
                return Ok(());
            }
            for pair in pending {
                self.stream(index, Stream::Pair(pair)).await?;
            }
        }
    }

    /// Windows of [`TAG_WINDOW`] from the watermark until one holds no tag, the pending indices read with the first.
    async fn stream(&mut self, index: usize, stream: Stream) -> Result<(), AnonymousError> {
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        let Some(counter) = self.counter_mut(index, stream) else {
            return Ok(());
        };
        let (scanned, mut late) = (counter.scanned(), counter.pending().collect::<Vec<_>>());
        let from = match self.sync.from {
            ScanFrom::Watermark => scanned,
            ScanFrom::Start => 0,
        };
        let source = match stream {
            Stream::Sender => TagSource::Own(|tx_count| ViewTagStream::Sender { tx_count }),
            Stream::Request => {
                TagSource::Own(|request_count| ViewTagStream::Request { request_count })
            }
            Stream::Pair(pair) => {
                TagSource::Shared(exactly_one(self.sync.keys.shared_view_tags(&[
                    SharedTagsRequest {
                        viewing_pubkey,
                        pair,
                    },
                ])?)?)
            }
        };
        let mut observed = BTreeSet::new();
        let mut start = from;
        loop {
            let counters: Vec<u64> = std::mem::take(&mut late)
                .into_iter()
                .chain((0..TAG_WINDOW).map_while(|offset| start.checked_add(offset)))
                .collect();
            let tags = self.tags(viewing_pubkey, &source, &counters)?;
            let window = TagWindow::indexed(counters.into_iter().zip(tags));
            let seen = self
                .window(index, &window, |counter| stream.found(counter))
                .await?;
            let advanced = seen.range(start..).next().is_some();
            observed.extend(seen);
            match start.checked_add(TAG_WINDOW) {
                Some(later) if advanced => start = later,
                _ => break,
            }
        }
        if let Some(counter) = self.counter_mut(index, stream) {
            counter.observe(from, &observed);
        }
        Ok(())
    }

    fn tags(
        &self,
        viewing_pubkey: X25519Pubkey,
        source: &TagSource,
        counters: &[u64],
    ) -> Result<Vec<ViewTag>, AnonymousError> {
        match source {
            TagSource::Own(stream) => {
                let requests: Vec<ViewTagRequest> = counters
                    .iter()
                    .map(|counter| ViewTagRequest {
                        viewing_pubkey,
                        stream: stream(*counter),
                    })
                    .collect();
                Ok(exactly_one_each(
                    self.sync.keys.view_tags(&requests)?,
                    requests.len(),
                )?)
            }
            TagSource::Shared(shared) => Ok(counters
                .iter()
                .map(|counter| shared.tag(*counter))
                .collect::<Result<_, KeypairError>>()?),
        }
    }

    /// Opens every output under a tag of `window`, the indices any output holds.
    async fn window(
        &mut self,
        index: usize,
        window: &TagWindow,
        found: impl Fn(u64) -> Option<AnonymousStream>,
    ) -> Result<BTreeSet<u64>, AnonymousError> {
        let tags = window.tags();
        let transactions = self.reads.transactions(&tags).await?;
        let deposits = self.reads.deposits(&tags).await?;
        let mut observed = BTreeSet::new();
        let mut hits = Vec::new();
        for tx in &transactions {
            let outputs = tx.output_slots.iter().map(|slot| &slot.view_tag);
            let messages = tx.messages.iter().map(|message| &message.view_tag);
            let sites = (0..).map(Site::Output).zip(outputs);
            let sites = sites.chain((0..).map(Site::Message).zip(messages));
            for (site, tag) in sites {
                let Some(counter) = window.index_of(tag) else {
                    continue;
                };
                observed.insert(counter);
                hits.push(Hit {
                    tx,
                    site,
                    found: found(counter),
                });
            }
        }
        self.note_spends(&transactions);
        self.open(index, &hits)?;
        for deposit in &deposits {
            let counters = deposit
                .output_slots
                .iter()
                .filter_map(|slot| window.index_of(&slot.view_tag));
            for counter in counters {
                observed.insert(counter);
                if let Some(found) = found(counter) {
                    self.open_deposit(index, deposit, found)?;
                }
            }
        }
        Ok(observed)
    }

    /// Decrypts every scheme 1 and 2 body of `hits` under its slot index in one request.
    fn open(&mut self, index: usize, hits: &[Hit<'_>]) -> Result<(), AnonymousError> {
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        let mut bodies = Vec::new();
        for hit in hits {
            let Some(found) = hit.found else {
                continue;
            };
            let tx = hit.tx;
            if !self
                .opened
                .insert((tx.tx_signature, tx.event_index, hit.site))
            {
                continue;
            }
            let Some(context) = RingDeliveryContext::of(tx) else {
                continue;
            };
            let ciphertext = match hit.site {
                Site::Output(position) => {
                    anonymous_recipient_output_body(&tx.output_slots[position].payload)
                }
                Site::Message(message) => anonymous_sender_output_body(&tx.messages[message].data),
            };
            let Some(ciphertext) = ciphertext else {
                continue;
            };
            bodies.push(Body {
                tx,
                site: hit.site,
                ciphertext: ciphertext.to_vec(),
                context,
                found,
            });
        }
        if bodies.is_empty() {
            return Ok(());
        }
        let requests = bodies
            .iter()
            .map(|body| {
                Ok(DecryptRequest {
                    ciphertext: &body.ciphertext,
                    viewing_pubkey,
                    tx_viewing_pubkey: body.context.tx_viewing_pk,
                    salt: body.context.salt,
                    slot_index: body.slot_index()?,
                    label: DecryptLabel::Utxo,
                })
            })
            .collect::<Result<Vec<_>, AnonymousError>>()?;
        let plaintexts = exactly_one_each(self.sync.keys.decrypt(&requests)?, requests.len())?;
        let own = self.own_transactions(viewing_pubkey, &bodies)?;
        for (body, plaintext) in bodies.iter().zip(plaintexts) {
            match body.site {
                Site::Output(position) => self.open_recipient(index, body, position, &plaintext)?,
                Site::Message(_) => {
                    let own = own.get(&body.context.first_nullifier);
                    self.open_bundle(index, body, &plaintext, own)?
                }
            }
        }
        Ok(())
    }

    /// The transaction key of each transaction the entry's key sent, keyed by its first nullifier.
    fn own_transactions(
        &self,
        viewing_pubkey: X25519Pubkey,
        bodies: &[Body<'_>],
    ) -> Result<HashMap<[u8; 32], ViewingKey>, AnonymousError> {
        let mut contexts: Vec<RingDeliveryContext> = Vec::new();
        for body in bodies {
            if matches!(body.site, Site::Message(_))
                && contexts
                    .iter()
                    .all(|held| held.first_nullifier != body.context.first_nullifier)
            {
                contexts.push(body.context);
            }
        }
        if contexts.is_empty() {
            return Ok(HashMap::new());
        }
        let requests: Vec<TransactionKeyRequest> = contexts
            .iter()
            .map(|context| TransactionKeyRequest {
                viewing_pubkey,
                first_nullifier: context.first_nullifier,
            })
            .collect();
        let keys = exactly_one_each(self.sync.keys.transaction_keys(&requests)?, requests.len())?;
        Ok(contexts
            .iter()
            .zip(keys)
            // Another viewing key sent the transaction.
            .filter(|(context, tx_viewing_key)| tx_viewing_key.pubkey() == context.tx_viewing_pk)
            .map(|(context, tx_viewing_key)| (context.first_nullifier, tx_viewing_key))
            .collect())
    }

    /// A body that rebuilds no hash is unmatched, one that fails to decode or names another owner skipped.
    fn open_recipient(
        &mut self,
        index: usize,
        body: &Body<'_>,
        position: usize,
        plaintext: &[u8],
    ) -> Result<(), AnonymousError> {
        let Ok(note) = AnonymousTransferRecipientPlaintext::deserialize(plaintext) else {
            return Ok(());
        };
        if note.verified.owner_pubkey != self.address.signing_pubkey {
            return Ok(());
        }
        let sender = note.unverified.sender_pubkey;
        match self
            .output_at(body, &self.address, position)
            .open_recipient(note)
        {
            Ok(Some(utxo)) => {
                self.accept(index, body, position, utxo)?;
                self.learn(index, SharedTagPair::FromSender(sender));
            }
            Ok(None) | Err(_) => self.unmatched.push(output_hash(body, position)),
        }
        Ok(())
    }

    /// Each change output the bundle rebuilds, the change leading at output 0.
    fn open_bundle(
        &mut self,
        index: usize,
        body: &Body<'_>,
        plaintext: &[u8],
        own: Option<&ViewingKey>,
    ) -> Result<(), AnonymousError> {
        let Ok(bundle) = AnonymousTransferSenderPlaintext::deserialize(plaintext) else {
            return Ok(());
        };
        if bundle.verified.owner_pubkey != self.address.signing_pubkey {
            return Ok(());
        }
        let listed = bundle.verified.recipient_viewing_pks.clone();
        let recipients: Vec<X25519Pubkey> = listed_recipients(&bundle).copied().collect();
        let outputs = body.tx.output_slots.len();
        if outputs == 0 {
            return Ok(());
        }
        let first_nullifier = body.context.first_nullifier;
        let change = match self
            .output_at(body, &self.address, 0)
            .sender_change(bundle, &first_nullifier)
        {
            Ok(change) => change,
            Err(_) => {
                self.unmatched.push(output_hash(body, 0));
                return Ok(());
            }
        };
        for (position, utxo) in change.into_iter().enumerate().take(outputs) {
            match self
                .output_at(body, &self.address, position)
                .rebuilds(&utxo)
            {
                true => self.accept(index, body, position, utxo)?,
                false => self.unmatched.push(output_hash(body, position)),
            }
        }
        // Only the wallet's own transaction key proves the listed payments its own.
        let Some(tx_viewing_key) = own else {
            return Ok(());
        };
        self.record_sent(body, &listed, tx_viewing_key);
        for recipient in recipients {
            self.learn(index, SharedTagPair::ToRecipient(recipient));
        }
        Ok(())
    }

    /// The bundle lists one key per output after the change, in output order.
    fn record_sent(
        &mut self,
        body: &Body<'_>,
        listed: &[X25519Pubkey],
        tx_viewing_key: &ViewingKey,
    ) {
        let Some(first) = body.tx.output_slots.len().checked_sub(listed.len()) else {
            return;
        };
        for (position, recipient) in (first..).zip(listed) {
            if *recipient.as_bytes() == DUMMY_RECIPIENT_VIEWING_PK || !is_contributory(recipient) {
                continue;
            }
            if let Some(sent) = self.sent_payment(body, position, recipient, tx_viewing_key) {
                self.sent.push(sent);
            }
        }
    }

    /// `None` when the body at `position` fails to open under the recipient's key.
    fn sent_payment(
        &self,
        body: &Body<'_>,
        position: usize,
        recipient: &X25519Pubkey,
        tx_viewing_key: &ViewingKey,
    ) -> Option<SentPayment> {
        let slot = &body.tx.output_slots[position];
        let ciphertext = anonymous_recipient_output_body(&slot.payload)?;
        let slot_index = u32::try_from(position).ok()?;
        let plaintext = Zeroizing::new(
            tx_viewing_key
                .decrypt_slot_ephemeral(recipient, ciphertext, body.context.salt, slot_index)
                .ok()?,
        );
        let note = AnonymousTransferRecipientPlaintext::deserialize(&plaintext).ok()?;
        let (owner_pubkey, amount) = (note.verified.owner_pubkey, note.verified.amount);
        let check = self
            .sync
            .recipients
            .iter()
            .filter(|address| {
                address.viewing_pubkey == *recipient && address.signing_pubkey == owner_pubkey
            })
            .find_map(|address| {
                self.output_at(body, address, position)
                    .open_recipient(note.clone())
                    .ok()
                    .flatten()
            })
            .map_or(SentCheck::Unverified, |utxo| SentCheck::Verified {
                mint: utxo.asset,
            });
        Some(SentPayment {
            tx_signature: body.tx.tx_signature,
            utxo_hash: slot.output_context.hash,
            position: slot_index,
            recipient_viewing_pubkey: *recipient,
            owner_pubkey,
            amount,
            check,
        })
    }

    fn output_at<'b>(
        &'b self,
        body: &'b Body<'_>,
        owner: &'b ShieldedAddress,
        position: usize,
    ) -> AnonymousOutput<'b> {
        let context = &body.tx.output_slots[position].output_context;
        AnonymousOutput {
            owner,
            assets: self.sync.assets,
            ring: body.context.ring,
            tree_id: context.tree_id,
            utxo_hash: &context.hash,
        }
    }

    /// A key no ECDH accepts never enters the map, a full map reports the pair.
    fn learn(&mut self, index: usize, pair: SharedTagPair) {
        let (SharedTagPair::FromSender(key) | SharedTagPair::ToRecipient(key)) = pair;
        if !is_contributory(&key) {
            return;
        }
        let entry = self.entry_mut(index);
        let viewing_pubkey = entry.viewing_pubkey();
        if entry.learn(pair) == Learned::Full {
            let skipped = SkippedCounterparty {
                viewing_pubkey,
                pair,
            };
            if !self.skipped.contains(&skipped) {
                self.skipped.push(skipped);
            }
        }
    }

    /// Keeps a rebuilt note once, under the stream that found it.
    fn accept(
        &mut self,
        index: usize,
        body: &Body<'_>,
        position: usize,
        utxo: Utxo,
    ) -> Result<(), AnonymousError> {
        let context = &body.tx.output_slots[position].output_context;
        if self.found.iter().any(|held| held.utxo_hash == context.hash) {
            return Ok(());
        }
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        self.found.push(WalletUtxo {
            utxo,
            nullifier_pubkey: self.address.nullifier_pubkey,
            utxo_hash: context.hash,
            nullifier: [0; 32],
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: None,
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
            latest_tree_id: None,
            slot: body.tx.slot,
            tx_signature: body.tx.tx_signature,
            slot_index: u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?,
        });
        self.utxos.push(AnonymousRingUtxo {
            utxo_hash: context.hash,
            viewing_pubkey,
            stream: body.found,
        });
        Ok(())
    }

    /// A deposit's owner hash, not its decryption, proves it the wallet's.
    fn open_deposit(
        &mut self,
        index: usize,
        deposit: &ShieldedTransaction,
        found: AnonymousStream,
    ) -> Result<(), AnonymousError> {
        let mut tx = deposit.clone();
        let Some(ring) = tx.output_slots.first().and_then(deposit_ring) else {
            return Ok(());
        };
        let framing = tx
            .output_slots
            .iter_mut()
            .try_for_each(|slot| slot.unwrap_ring_deposit(&ring, self.sync.deposit_payload));
        match framing {
            Ok(()) => {}
            Err(TransactionError::Deserialize(_)) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let mut opened = DecryptionResult::default();
        match opened.extend(
            self.sync.keys,
            core::slice::from_ref(&tx),
            self.sync.assets.registry(),
        ) {
            Ok(()) => {}
            // The pinned decryption fails on a blinding outside the field, the deposit opens to nothing.
            Err(TransactionError::Keypair(KeypairError::Poseidon(_))) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        self.decrypted
            .unknown_mints
            .extend(opened.unknown_mints.iter().copied());
        self.decrypted
            .unknown_asset_ids
            .extend(opened.unknown_asset_ids.iter().copied());
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        for utxo in verify_owned(self.sync.keys, &opened)?.utxos {
            if self
                .found
                .iter()
                .any(|held| held.utxo_hash == utxo.utxo_hash)
            {
                continue;
            }
            self.utxos.push(AnonymousRingUtxo {
                utxo_hash: utxo.utxo_hash,
                viewing_pubkey,
                stream: found,
            });
            self.found.push(utxo);
        }
        Ok(())
    }

    /// The spends of every found or held ring note, round after round, open the ring merges among them.
    async fn merges(&mut self) -> Result<(), AnonymousError> {
        let mut queried: HashSet<[u8; 32]> = HashSet::new();
        let held: Vec<[u8; 32]> = self
            .sync
            .held
            .iter()
            .filter(|utxo| utxo.utxo.ring_program_id.is_some())
            .map(|utxo| utxo.nullifier)
            .collect();
        loop {
            assign_nullifiers(
                self.sync.keys,
                &mut self.decrypted,
                std::mem::take(&mut self.found),
            )?;
            let frontier: Vec<[u8; 32]> = self
                .decrypted
                .utxos
                .iter()
                .filter(|utxo| utxo.utxo.ring_program_id.is_some())
                .map(|utxo| utxo.nullifier)
                .chain(held.iter().copied())
                .filter(|nullifier| queried.insert(*nullifier))
                .collect();
            if frontier.is_empty() {
                return Ok(());
            }
            let spends = self.reads.spends(&frontier).await?;
            self.note_spends(&spends);
            let merges: Vec<ShieldedTransaction> = spends
                .into_iter()
                .filter(|tx| tx.ring_program_id.is_some() && tx.may_be_merge())
                .collect();
            let mut opened = DecryptionResult::default();
            opened.extend(self.sync.keys, &merges, self.sync.assets.registry())?;
            let viewing_pubkey = self.address.viewing_pubkey;
            let known = |hash: &[u8; 32], decrypted: &DecryptionResult| {
                decrypted.utxos.iter().any(|held| held.utxo_hash == *hash)
                    || self.sync.held.iter().any(|held| held.utxo_hash == *hash)
            };
            for merge in &merges {
                let Some(&first_nullifier) = merge.nullifiers.first() else {
                    continue;
                };
                for slot in &merge.output_slots {
                    let hash = slot.output_context.hash;
                    let Some(utxo) = opened.utxos.iter().find(|utxo| utxo.utxo_hash == hash) else {
                        continue;
                    };
                    if known(&hash, &self.decrypted) {
                        continue;
                    }
                    self.found.push(utxo.clone());
                    self.utxos.push(AnonymousRingUtxo {
                        utxo_hash: hash,
                        viewing_pubkey,
                        stream: AnonymousStream::Merge { first_nullifier },
                    });
                }
            }
            self.decrypted
                .unknown_mints
                .extend(opened.unknown_mints.iter().copied());
        }
    }

    fn note_spends(&mut self, transactions: &[ShieldedTransaction]) {
        for tx in transactions {
            if self.spends.insert((tx.tx_signature, tx.event_index)) {
                self.decrypted
                    .spent_nullifiers
                    .extend(tx.nullifiers.iter().copied());
            }
        }
    }

    fn counter_mut(&mut self, index: usize, stream: Stream) -> Option<&mut StreamCounter> {
        let entry = self.entry_mut(index);
        match stream {
            Stream::Sender => Some(entry.tx_stream_mut()),
            Stream::Request => Some(entry.request_stream_mut()),
            Stream::Pair(pair) => entry.pair_mut(&pair),
        }
    }

    fn entry_mut(&mut self, index: usize) -> &mut ViewingKeyEntry {
        &mut self.history.entries_mut()[index]
    }
}

fn output_hash(body: &Body<'_>, position: usize) -> [u8; 32] {
    body.tx.output_slots[position].output_context.hash
}

/// The ring a deposit output names, `None` for any other output.
fn deposit_ring(slot: &OutputSlot) -> Option<Address> {
    decode_encrypted_ring_deposit_output_data(&slot.payload)
        .ok()
        .map(|output| Address::new_from_array(output.ring_program_id))
}

/// Derives the nullifiers of `found` and adds them to `decrypted` in publication order.
fn assign_nullifiers<K: ShieldedKeys + ?Sized>(
    keys: &K,
    decrypted: &mut DecryptionResult,
    mut found: Vec<WalletUtxo>,
) -> Result<(), AnonymousError> {
    if found.is_empty() {
        return Ok(());
    }
    let requests: Vec<DeriveRequest> = found
        .iter()
        .map(|utxo| DeriveRequest::Nullifier {
            utxo_hash: utxo.utxo_hash,
            blinding: utxo.utxo.blinding,
        })
        .collect();
    let nullifiers = exactly_one_each(keys.derive(&requests)?, requests.len())?;
    for (utxo, nullifier) in found.iter_mut().zip(nullifiers) {
        utxo.nullifier = nullifier;
    }
    decrypted.utxos.extend(found);
    decrypted.utxos.sort_by_key(|utxo| {
        (
            utxo.slot,
            utxo.tx_signature.as_ref().to_vec(),
            utxo.slot_index,
        )
    });
    Ok(())
}
