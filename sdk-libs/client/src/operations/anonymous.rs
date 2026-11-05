//! Anonymous ring sync, each ring's history read from its stored position under the tag hints.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use custom_ring_interface::{
    ring_body_output, ring_sender_bundle_output_body, stream::SlotSecret, SENDER_BUNDLE_HEAD_LEN,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{AsyncRpc, IndexerRpcConfig};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{viewing_key::ViewTag, PublicKey, ShieldedAddress, ViewingKey, X25519Pubkey};
use spr_transaction::{
    instructions::merge::{MergeOutputPlaintext, MergeSeed},
    DecryptionResult, DepositPayload, Mint, ShieldedKeys, ShieldedTransaction, TransactionError,
    TransactionKeyRequest, WalletUtxo,
};
use zolana_ring_keys::{
    MergeSeedHolder, MergeSeedRequest, RingDeliveryRequest, RingKeys, RingTagFrame, RingTagKind,
    RingTagProbe, ViewTagRequest, ViewTagStream,
};
use zolana_ring_transaction::{
    is_contributory, open_recipient_body, open_reply, open_sender_bundle, AnonymousOutput,
    OpenedBody, OpenedNote, ReplyClaim, RingAssets,
};

use crate::history::{HistoryPosition, PageEnd};
use crate::{
    anonymous_wallet::PendingNote,
    confidential::{is_ring_merge, RingMerges},
    delivered::{self, RingDeliveryContext},
    deposit::{DepositOpener, DepositSlot, OpenedDeposit},
    deposit_payload, exactly_one, exactly_one_each,
    merge_audit::RingMergeBody,
    tags::{IndexerReads, TagWindow},
    viewing_history::{GapScan, StreamCounter, ViewingHistory, ViewingKeyEntry},
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
    /// A transfer's slot or bundle whose tag hint matched.
    TagHint,
    Merge {
        first_nullifier: [u8; 32],
    },
    /// Found by trying the slot with no use of its tag.
    FullScan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousRingUtxo {
    pub utxo_hash: [u8; 32],
    pub viewing_pubkey: X25519Pubkey,
    pub stream: AnonymousStream,
}

/// One payment the wallet's sender bundle lists, its body opened with the transaction key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentPayment {
    pub tx_signature: Signature,
    pub utxo_hash: [u8; 32],
    pub position: u32,
    pub recipient_viewing_pubkey: X25519Pubkey,
    /// The held address that rebuilt the hash, `None` under `SentCheck::Unverified`.
    pub owner_pubkey: Option<PublicKey>,
    pub amount: u64,
    pub check: SentCheck,
}

/// A decrypted reply, an unauthenticated claim about who paid, never a verified sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderClaim {
    pub utxo_hash: [u8; 32],
    pub viewing_pubkey: X25519Pubkey,
    pub claim: ReplyClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentCheck {
    /// A held recipient address rebuilt the published hash under `mint`.
    Verified { mint: Mint },
    /// No held address names the owner and viewing key, or the body rebuilds no hash.
    Unverified,
}

/// Bodies no held key rebuilt, an owner's note under a bad body opens only through an auditor read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditorRecovery {
    /// Commitments, foreign notes and dummies among them.
    pub unopened: Vec<[u8; 32]>,
}

/// Only [`crate::AnonymousWallet::absorb`] stores what it covers.
pub struct AnonymousScan {
    starting_history: ViewingHistory,
    history: ViewingHistory,
    decrypted: DecryptionResult,
    pending: Vec<PendingNote>,
    sender_claims: Vec<SenderClaim>,
    pub utxos: Vec<AnonymousRingUtxo>,
    /// Bodies that rebuilt under no mint of `assets`, each among the pending notes.
    pub unmatched: Vec<[u8; 32]>,
    /// The wallet's payments in the transfers whose bundle it opened, a body that fails to open left out.
    pub sent: Vec<SentPayment>,
    /// Filled by a full scan alone.
    pub auditor_recovery: AuditorRecovery,
}

impl AnonymousScan {
    pub fn history(&self) -> &ViewingHistory {
        &self.history
    }

    pub fn decrypted(&self) -> &DecryptionResult {
        &self.decrypted
    }

    /// Notes verified under a mint `assets` does not name, none spendable.
    pub fn pending_notes(&self) -> &[PendingNote] {
        &self.pending
    }

    /// Replies on the wallet's notes, unauthenticated, [`ViewingHistory::confirm_sender`] is the only trust path.
    pub fn sender_claims(&self) -> &[SenderClaim] {
        &self.sender_claims
    }

    pub(crate) fn starts_from(&self, history: &ViewingHistory) -> bool {
        self.starting_history == *history
    }

    pub(crate) fn into_stored(
        self,
    ) -> (
        ViewingHistory,
        DecryptionResult,
        Vec<PendingNote>,
        Vec<SenderClaim>,
    ) {
        (
            self.history,
            self.decrypted,
            self.pending,
            self.sender_claims,
        )
    }
}

/// Reads every ring and deposit stream of each held viewing key, each tag answered by `keys`.
#[must_use]
pub struct AnonymousSync<'a, K: ?Sized> {
    keys: &'a K,
    assets: &'a RingAssets,
    config: Option<IndexerRpcConfig>,
    deposit_payload: DepositPayload,
    from: ScanFrom,
    held: &'a [WalletUtxo],
    recipients: &'a [ShieldedAddress],
    sender_fast_path: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanFrom {
    Watermark,
    Start,
}

impl<'a, K: ShieldedKeys + RingKeys + MergeSeedHolder + ?Sized> AnonymousSync<'a, K> {
    pub fn new(keys: &'a K, assets: &'a RingAssets) -> Self {
        Self {
            keys,
            assets,
            config: None,
            deposit_payload,
            from: ScanFrom::Watermark,
            held: &[],
            recipients: &[],
            sender_fast_path: false,
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

    /// A bundle under the wallet's own transaction key skips its tag test, every other candidate keeps it.
    pub fn with_sender_fast_path(mut self) -> Self {
        self.sender_fast_path = true;
        self
    }

    /// Every stream and ring from its start, for a wallet that keeps no notes between syncs.
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

    /// An entry whose key the holder lacks stays as stored, a failed page moves nothing.
    pub async fn fetch<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        history: &ViewingHistory,
    ) -> Result<AnonymousScan, AnonymousError> {
        let mut scan = self.scan(indexer, history)?;
        let held = scan.held_entries();
        for index in &held {
            scan.entry(*index).await?;
        }
        for read in scan.ring_reads(&held) {
            scan.read_ring(read, Trial::TagHints).await?;
        }
        scan.merges(MergeSource::Indexer).await?;
        scan.finish(self.keys)
    }

    /// Reads `ring` from its first row without tag or nullifier queries.
    pub async fn full_scan<I: AsyncRpc + ?Sized>(
        &self,
        indexer: &I,
        history: &ViewingHistory,
        ring: Address,
    ) -> Result<AnonymousScan, AnonymousError> {
        let mut scan = self.scan(indexer, history)?;
        let held = scan.held_entries();
        let merges = scan
            .read_ring(
                RingRead {
                    ring,
                    position: HistoryPosition::default(),
                    entries: held,
                },
                Trial::EverySite,
            )
            .await?;
        scan.merges(MergeSource::History(merges)).await?;
        scan.finish(self.keys)
    }

    fn scan<'s, 'r, I: AsyncRpc + ?Sized>(
        &'s self,
        indexer: &'r I,
        history: &ViewingHistory,
    ) -> Result<Scan<'s, 'a, 'r, I, K>, AnonymousError> {
        // A held key with no entry would read nothing and report nothing missed.
        if self
            .keys
            .viewing_public_keys()
            .iter()
            .any(|key| history.entry(key).is_none())
        {
            return Err(AnonymousError::HeldKeyNotInHistory);
        }
        Ok(Scan {
            sync: self,
            address: self.keys.address()?,
            reads: IndexerReads::configured(indexer, self.config),
            starting_history: history.clone(),
            history: history.clone(),
            found: Vec::new(),
            held_back: Vec::new(),
            utxos: Vec::new(),
            decrypted: DecryptionResult::default(),
            spends: HashSet::new(),
            unmatched: Vec::new(),
            sent: Vec::new(),
            sender_claims: Vec::new(),
            unopened: BTreeSet::new(),
        })
    }
}

fn sites_of(tx: &ShieldedTransaction) -> impl Iterator<Item = Site> {
    let outputs = (0..tx.output_slots.len()).map(Site::Output);
    outputs.chain((0..tx.messages.len()).map(Site::Message))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Trial {
    TagHints,
    EverySite,
}

enum MergeSource {
    Indexer,
    History(RingMerges),
}

/// One history query, every entry listed shares its position and pays one read.
struct RingRead {
    ring: Address,
    position: HistoryPosition,
    entries: Vec<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Stream {
    Sender,
    Request,
}

struct ActiveStream {
    stream: Stream,
    scan: GapScan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RoundTag {
    Bootstrap,
    Stream { slot: usize, index: u64 },
}

impl Stream {
    fn found(self, index: u64) -> AnonymousStream {
        match self {
            Self::Sender => AnonymousStream::Sender { index },
            Self::Request => AnonymousStream::Request { index },
        }
    }

    fn view_tag(self, index: u64) -> ViewTagStream {
        match self {
            Self::Sender => ViewTagStream::Sender { tx_count: index },
            Self::Request => ViewTagStream::Request {
                request_count: index,
            },
        }
    }
}

struct Scan<'s, 'a, 'r, I: ?Sized, K: ?Sized> {
    sync: &'s AnonymousSync<'a, K>,
    address: ShieldedAddress,
    reads: IndexerReads<'r, I>,
    starting_history: ViewingHistory,
    history: ViewingHistory,
    /// Notes whose rebuilt hash matched, before their nullifiers.
    found: Vec<WalletUtxo>,
    /// The same under a mint `assets` does not name.
    held_back: Vec<WalletUtxo>,
    utxos: Vec<AnonymousRingUtxo>,
    decrypted: DecryptionResult,
    spends: HashSet<(Signature, Option<u16>)>,
    unmatched: Vec<[u8; 32]>,
    sent: Vec<SentPayment>,
    sender_claims: Vec<SenderClaim>,
    unopened: BTreeSet<[u8; 32]>,
}

/// A recipient body at an output, a sender bundle in a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Site {
    Output(usize),
    Message(usize),
}

/// A ring body or sender bundle payload the entry's key may open.
struct Body<'t> {
    tx: &'t ShieldedTransaction,
    site: Site,
    /// The frame's `m` on a bundle, a recipient body's own index otherwise.
    slot_index: u32,
    context: RingDeliveryContext,
    found: AnonymousStream,
}

impl<'t> Body<'t> {
    fn probe(&self) -> RingTagProbe {
        let (kind, tag) = match self.site {
            Site::Output(position) => (
                RingTagKind::Recipient,
                self.tx.output_slots[position].view_tag,
            ),
            Site::Message(message) => (
                RingTagKind::SenderBundle,
                self.tx.messages[message].view_tag,
            ),
        };
        RingTagProbe {
            kind,
            output_index: self.slot_index,
            tag,
        }
    }

    /// `None` on a site of another scheme, a bundle's length names `m` and must fit the row.
    fn of(tx: &'t ShieldedTransaction, site: Site, found: AnonymousStream) -> Option<Self> {
        let slot_index = match site {
            Site::Output(position) => {
                ring_body_output(&tx.output_slots[position].payload)?;
                position
            }
            Site::Message(message) => {
                let bundle = ring_sender_bundle_output_body(&tx.messages[message].data)?;
                let keys = bundle.len().checked_sub(SENDER_BUNDLE_HEAD_LEN)?;
                (keys % 32 == 0 && keys / 32 == tx.output_slots.len()).then_some(keys / 32)?
            }
        };
        Some(Self {
            tx,
            site,
            slot_index: u32::try_from(slot_index).ok()?,
            context: RingDeliveryContext::of(tx)?,
            found,
        })
    }
}

impl<I: AsyncRpc + ?Sized, K: ShieldedKeys + RingKeys + MergeSeedHolder + ?Sized>
    Scan<'_, '_, '_, I, K>
{
    fn held_entries(&self) -> Vec<usize> {
        let held = self.sync.keys.viewing_public_keys();
        self.history
            .entries()
            .iter()
            .enumerate()
            .filter(|(_, entry)| held.contains(&entry.viewing_pubkey()))
            .map(|(index, _)| index)
            .collect()
    }

    /// Entries at one position of one ring share a read, a key added later is its own query.
    fn ring_reads(&self, held: &[usize]) -> Vec<RingRead> {
        let rescan = self.sync.from == ScanFrom::Start;
        let mut reads: BTreeMap<(Address, Option<u64>), Vec<usize>> = BTreeMap::new();
        for index in held {
            let entry = &self.history.entries()[*index];
            for (ring, after_slot) in entry.ring_positions() {
                let after_slot = after_slot.filter(|_| !rescan);
                reads.entry((*ring, after_slot)).or_default().push(*index);
            }
        }
        reads
            .into_iter()
            .map(|((ring, after_slot), entries)| RingRead {
                ring,
                position: after_slot
                    .map_or_else(HistoryPosition::default, HistoryPosition::after_slot),
                entries,
            })
            .collect()
    }

    /// Reads to a terminal page, only its `context.slot` becomes a position.
    async fn read_ring(
        &mut self,
        read: RingRead,
        trial: Trial,
    ) -> Result<RingMerges, AnonymousError> {
        let RingRead {
            ring,
            mut position,
            entries,
        } = read;
        let mut merges = Vec::new();
        loop {
            let (page, limit) = self.reads.ring_page(ring, &position).await?;
            let end = position
                .advance(&page, limit)
                .map_err(|_| AnonymousError::InvalidHistoryPage)?;
            // A custom indexer client answers here unchecked, a repeated row would count twice.
            if page.data.iter().any(|transaction| {
                transaction
                    .validate_events(|row| (row.slot, row.tx_signature, row.event_index))
                    .is_err()
            }) {
                return Err(AnonymousError::InvalidHistoryPage);
            }
            let rows: Vec<ShieldedTransaction> =
                page.data.into_iter().flat_map(|item| item.events).collect();
            self.note_spends(&rows);
            for index in &entries {
                match trial {
                    Trial::TagHints => self.test_tags(*index, &rows)?,
                    Trial::EverySite => self.try_every_site(*index, &rows)?,
                }
                self.open_owner_merges(*index, &rows)?;
            }
            if trial == Trial::EverySite {
                merges.extend(RingMerges::among(rows).0);
            }
            if let PageEnd::Terminal(context) = end {
                for index in &entries {
                    self.entry_mut(*index).set_ring_position(ring, context.slot);
                }
                return Ok(RingMerges(merges));
            }
        }
    }

    /// One agreement per candidate per key inside the holder, only a matching tag opens a body.
    fn test_tags(
        &mut self,
        index: usize,
        rows: &[ShieldedTransaction],
    ) -> Result<(), AnonymousError> {
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        let mut candidates: Vec<Vec<Body<'_>>> = Vec::new();
        for tx in rows {
            let bodies: Vec<Body<'_>> = sites_of(tx)
                .filter_map(|site| Body::of(tx, site, AnonymousStream::TagHint))
                .collect();
            if !bodies.is_empty() {
                candidates.push(bodies);
            }
        }
        if candidates.is_empty() {
            return Ok(());
        }
        let own = match self.sync.sender_fast_path {
            true => {
                let bundles: Vec<&Body<'_>> = candidates.iter().flatten().collect();
                self.own_transactions(viewing_pubkey, &bundles)?
            }
            false => HashMap::new(),
        };
        let mut recognized = Vec::new();
        let mut frames = Vec::with_capacity(candidates.len());
        let mut tested: Vec<Vec<Body<'_>>> = Vec::with_capacity(candidates.len());
        for bodies in candidates {
            let (skip, test): (Vec<Body<'_>>, Vec<Body<'_>>) =
                bodies.into_iter().partition(|body| {
                    matches!(body.site, Site::Message(_))
                        && own.contains_key(&body.context.first_nullifier)
                });
            recognized.extend(skip);
            if let Some(first) = test.first() {
                frames.push(RingTagFrame {
                    viewing_pubkey,
                    tx_viewing_pk: first.context.tx_viewing_pk,
                    salt: first.context.salt,
                    first_nullifier: first.context.first_nullifier,
                    probes: test.iter().map(Body::probe).collect(),
                });
                tested.push(test);
            }
        }
        let answers = exactly_one_each(self.sync.keys.ring_tag_matches(&frames)?, frames.len())?;
        let mut matched: Vec<(Body<'_>, SlotSecret)> = Vec::new();
        for (bodies, answers) in tested.into_iter().zip(answers) {
            let answers = exactly_one_each(answers, bodies.len())?;
            matched.extend(
                bodies
                    .into_iter()
                    .zip(answers)
                    .filter_map(|(body, answer)| answer.map(|secret| (body, secret))),
            );
        }
        matched.extend(self.body_secrets(viewing_pubkey, recognized)?);
        self.read_bodies(index, &matched)
    }

    /// The one recovery path of every rail, tags are unproved hints and no tag is read here.
    fn try_every_site(
        &mut self,
        index: usize,
        rows: &[ShieldedTransaction],
    ) -> Result<(), AnonymousError> {
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        self.unopened.extend(
            rows.iter()
                .flat_map(|tx| &tx.output_slots)
                .filter(|slot| ring_body_output(&slot.payload).is_some())
                .map(|slot| slot.output_context.hash),
        );
        let bodies: Vec<Body<'_>> = rows
            .iter()
            .flat_map(|tx| {
                sites_of(tx).filter_map(move |site| Body::of(tx, site, AnonymousStream::FullScan))
            })
            .collect();
        let opened = self.body_secrets(viewing_pubkey, bodies)?;
        self.read_bodies(index, &opened)?;
        for deposit in rows.iter().filter(|tx| tx.proofless) {
            for position in 0..deposit.output_slots.len() {
                self.open_deposit(index, deposit, position, AnonymousStream::FullScan)?;
            }
        }
        Ok(())
    }

    /// Each body's slot secret, one agreement per transaction inside the holder.
    fn body_secrets<'t>(
        &self,
        viewing_pubkey: X25519Pubkey,
        bodies: Vec<Body<'t>>,
    ) -> Result<Vec<(Body<'t>, SlotSecret)>, AnonymousError> {
        if bodies.is_empty() {
            return Ok(Vec::new());
        }
        let requests: Vec<RingDeliveryRequest> = bodies
            .iter()
            .map(|body| RingDeliveryRequest {
                viewing_pubkey,
                tx_viewing_pk: body.context.tx_viewing_pk,
                salt: body.context.salt,
                output_index: body.slot_index,
                first_nullifier: body.context.first_nullifier,
            })
            .collect();
        let secrets = exactly_one_each(
            self.sync.keys.ring_delivery_secrets(&requests)?,
            requests.len(),
        )?;
        bodies
            .into_iter()
            .zip(secrets)
            .map(|(body, secret)| Ok((body, SlotSecret::new(secret)?)))
            .collect()
    }

    fn read_bodies(
        &mut self,
        index: usize,
        opened: &[(Body<'_>, SlotSecret)],
    ) -> Result<(), AnonymousError> {
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        let bodies: Vec<&Body<'_>> = opened.iter().map(|(body, _)| body).collect();
        let own = self.own_transactions(viewing_pubkey, &bodies)?;
        for (body, secret) in opened {
            match body.site {
                Site::Output(position) => self.open_recipient(index, body, position, secret)?,
                Site::Message(message) => {
                    let own = own.get(&body.context.first_nullifier);
                    self.open_bundle(index, body, message, secret, own)?
                }
            }
        }
        Ok(())
    }

    /// Only the seed a held key derives opens a zero-key merge.
    fn open_owner_merges(
        &mut self,
        index: usize,
        rows: &[ShieldedTransaction],
    ) -> Result<(), AnonymousError> {
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        let sync = self.sync;
        let opener = OwnerMergeOpener::new(sync.keys, self.address.signing_pubkey, sync.assets)?;
        for tx in rows {
            let Some(merge) = opener.candidate(tx) else {
                continue;
            };
            if self.is_found(merge.commitment()) {
                continue;
            }
            let found = AnonymousStream::Merge {
                first_nullifier: merge.first_nullifier,
            };
            match opener.open(&merge, viewing_pubkey)? {
                Some(OpenedBody::Note(note)) => self.accept(index, tx, found, 0, note)?,
                Some(OpenedBody::UnknownMint(note)) => self.hold_back(tx, 0, note)?,
                None => {}
            }
        }
        Ok(())
    }

    /// The deposit streams, their rounds sharing each read.
    async fn entry(&mut self, index: usize) -> Result<(), AnonymousError> {
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        let rescan = self.sync.from == ScanFrom::Start;
        let mut active: Vec<ActiveStream> = [Stream::Sender, Stream::Request]
            .into_iter()
            .map(|stream| {
                let counter = self.counter_mut(index, stream);
                let from = if rescan { 0 } else { counter.scanned() };
                ActiveStream {
                    stream,
                    scan: GapScan::new(from, counter),
                }
            })
            .collect();
        let mut bootstrap = Some([
            viewing_pubkey.u(),
            custom_ring_interface::stream::confidential_slot_tag(viewing_pubkey.u()),
        ]);
        while !active.is_empty() {
            let mut tagged: Vec<(RoundTag, ViewTag)> = bootstrap
                .take()
                .into_iter()
                .flatten()
                .map(|tag| (RoundTag::Bootstrap, tag))
                .collect();
            for (slot, stream) in active.iter_mut().enumerate() {
                let indices = stream.scan.round();
                let tags = self.tags(viewing_pubkey, stream.stream, &indices)?;
                tagged.extend(
                    indices
                        .into_iter()
                        .map(|index| RoundTag::Stream { slot, index })
                        .zip(tags),
                );
            }
            let window = TagWindow::indexed(tagged);
            let seen = self
                .window(index, &window, |tag| match tag {
                    RoundTag::Bootstrap => Some(AnonymousStream::Bootstrap),
                    RoundTag::Stream { slot, index } => {
                        active.get(slot).map(|active| active.stream.found(index))
                    }
                })
                .await?;
            let mut continuing = Vec::with_capacity(active.len());
            for (slot, mut stream) in active.into_iter().enumerate() {
                let found = seen.iter().filter_map(|tag| match *tag {
                    RoundTag::Stream { slot: at, index } if at == slot => Some(index),
                    _ => None,
                });
                if stream.scan.advance(found) {
                    continuing.push(stream);
                } else {
                    stream.scan.finish(self.counter_mut(index, stream.stream));
                }
            }
            active = continuing;
        }
        Ok(())
    }

    fn tags(
        &self,
        viewing_pubkey: X25519Pubkey,
        stream: Stream,
        counters: &[u64],
    ) -> Result<Vec<ViewTag>, AnonymousError> {
        let requests: Vec<ViewTagRequest> = counters
            .iter()
            .map(|counter| ViewTagRequest {
                viewing_pubkey,
                stream: stream.view_tag(*counter),
            })
            .collect();
        Ok(exactly_one_each(
            self.sync.keys.view_tags(&requests)?,
            requests.len(),
        )?)
    }

    /// Opens every deposit under a tag of `window`, the tags any deposit holds.
    async fn window<T: Copy + Ord>(
        &mut self,
        index: usize,
        window: &TagWindow<T>,
        found: impl Fn(T) -> Option<AnonymousStream>,
    ) -> Result<BTreeSet<T>, AnonymousError> {
        let deposits = self.reads.deposits(&window.tags()).await?;
        let mut observed = BTreeSet::new();
        for deposit in &deposits {
            for (position, slot) in deposit.output_slots.iter().enumerate() {
                let Some(counter) = window.index_of(&slot.view_tag) else {
                    continue;
                };
                observed.insert(counter);
                if let Some(found) = found(counter) {
                    self.open_deposit(index, deposit, position, found)?;
                }
            }
        }
        Ok(observed)
    }

    /// The transaction key of each transaction the entry's key sent, keyed by its first nullifier.
    fn own_transactions(
        &self,
        viewing_pubkey: X25519Pubkey,
        bodies: &[&Body<'_>],
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

    /// Only a rebuilt commitment proves the note the wallet's, every other body stays silent.
    fn open_recipient(
        &mut self,
        index: usize,
        body: &Body<'_>,
        position: usize,
        secret: &SlotSecret,
    ) -> Result<(), AnonymousError> {
        let slot = &body.tx.output_slots[position];
        let Some((ciphertext, reply)) = ring_body_output(&slot.payload) else {
            return Ok(());
        };
        let Ok(plain) = open_recipient_body(ciphertext, secret) else {
            return Ok(());
        };
        let opened = self
            .output_at(body, &self.address, position)
            .open_body(&plain);
        match opened {
            Ok(Some(OpenedBody::Note(note))) => {
                self.accept(index, body.tx, body.found, position, note)?;
            }
            Ok(Some(OpenedBody::UnknownMint(note))) => {
                self.hold_back(body.tx, position, note)?;
            }
            Ok(None) | Err(_) => return Ok(()),
        }
        if let Ok(Some(claim)) = open_reply(reply, secret) {
            let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
            self.sender_claims.push(SenderClaim {
                utxo_hash: slot.output_context.hash,
                viewing_pubkey,
                claim,
            });
        }
        Ok(())
    }

    /// Each change slot its cells rebuild under the wallet's own address and `TXOB(i)`, from the seed and retained chain history with no auditor read.
    fn open_bundle(
        &mut self,
        index: usize,
        body: &Body<'_>,
        message: usize,
        secret: &SlotSecret,
        own: Option<&ViewingKey>,
    ) -> Result<(), AnonymousError> {
        let Some(ciphertext) = ring_sender_bundle_output_body(&body.tx.messages[message].data)
        else {
            return Ok(());
        };
        let Ok(bundle) = open_sender_bundle(ciphertext, secret, body.slot_index as usize) else {
            return Ok(());
        };
        let first_nullifier = body.context.first_nullifier;
        for position in (0u32..2).take(body.tx.output_slots.len()) {
            match self
                .output_at(body, &self.address, position as usize)
                .open_change(&bundle, &first_nullifier, position)
            {
                Ok(Some(OpenedBody::Note(note))) => {
                    self.accept(index, body.tx, body.found, position as usize, note)?
                }
                Ok(Some(OpenedBody::UnknownMint(note))) => {
                    self.hold_back(body.tx, position as usize, note)?;
                }
                Ok(None) | Err(_) => {}
            }
        }
        // Only the wallet's own transaction key proves the listed payments its own.
        let Some(tx_viewing_key) = own else {
            return Ok(());
        };
        self.record_sent(body, &bundle.recipient_keys, tx_viewing_key);
        Ok(())
    }

    /// Each cell names one slot, a zero cell reads change, exit or dummy.
    fn record_sent(
        &mut self,
        body: &Body<'_>,
        recipient_keys: &[[u8; 32]],
        tx_viewing_key: &ViewingKey,
    ) {
        for (position, key) in recipient_keys.iter().enumerate() {
            let Ok(recipient) = X25519Pubkey::from_u(*key) else {
                continue;
            };
            if *key == [0; 32] || !is_contributory(&recipient) {
                continue;
            }
            if let Some(sent) = self.sent_payment(body, position, &recipient, tx_viewing_key) {
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
        let (ciphertext, _) = ring_body_output(&slot.payload)?;
        let slot_index = u32::try_from(position).ok()?;
        let agreement = zeroize::Zeroizing::new(tx_viewing_key.ecdh(recipient).ok()?);
        let secret = custom_ring_interface::stream::DeliveredSlot {
            agreement: &agreement,
            tx_viewing_pk: body.context.tx_viewing_pk.as_bytes(),
            recipient_viewing_pk: recipient.as_bytes(),
            salt: &body.context.salt,
            output_index: slot_index,
            first_nullifier: &body.context.first_nullifier,
        }
        .secret()
        .ok()?;
        let plain = open_recipient_body(ciphertext, &secret).ok()?;
        let verified = self
            .sync
            .recipients
            .iter()
            .filter(|address| address.viewing_pubkey == *recipient)
            .find_map(|address| {
                match self
                    .output_at(body, address, position)
                    .open_body(&plain)
                    .ok()
                    .flatten()?
                {
                    OpenedBody::Note(note) => Some((address.signing_pubkey, note.utxo.asset)),
                    OpenedBody::UnknownMint(_) => None,
                }
            });
        let (owner_pubkey, check) = match verified {
            Some((owner, mint)) => (Some(owner), SentCheck::Verified { mint }),
            None => (None, SentCheck::Unverified),
        };
        Some(SentPayment {
            tx_signature: body.tx.tx_signature,
            utxo_hash: slot.output_context.hash,
            position: slot_index,
            recipient_viewing_pubkey: *recipient,
            owner_pubkey,
            amount: plain.amount,
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

    /// Keeps a rebuilt note once, under the stream that found it.
    fn accept(
        &mut self,
        index: usize,
        tx: &ShieldedTransaction,
        stream: AnonymousStream,
        position: usize,
        note: OpenedNote,
    ) -> Result<(), AnonymousError> {
        if self.is_found(&tx.output_slots[position].output_context.hash) {
            return Ok(());
        }
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        let utxo = published_note(tx, position, note)?;
        self.keep(utxo, viewing_pubkey, stream);
        Ok(())
    }

    /// Verified under a mint `assets` does not name, it waits among the pending notes.
    fn hold_back(
        &mut self,
        tx: &ShieldedTransaction,
        position: usize,
        note: OpenedNote,
    ) -> Result<(), AnonymousError> {
        let utxo = published_note(tx, position, note)?;
        self.hold_back_note(utxo);
        Ok(())
    }

    fn hold_back_note(&mut self, utxo: WalletUtxo) {
        if !self.unmatched.contains(&utxo.utxo_hash) {
            self.unmatched.push(utxo.utxo_hash);
            self.held_back.push(utxo);
        }
    }

    fn is_found(&self, utxo_hash: &[u8; 32]) -> bool {
        self.found.iter().any(|held| held.utxo_hash == *utxo_hash)
    }

    fn keep(&mut self, utxo: WalletUtxo, viewing_pubkey: X25519Pubkey, stream: AnonymousStream) {
        self.utxos.push(AnonymousRingUtxo {
            utxo_hash: utxo.utxo_hash,
            viewing_pubkey,
            stream,
        });
        self.found.push(utxo);
    }

    fn open_deposit(
        &mut self,
        index: usize,
        deposit: &ShieldedTransaction,
        position: usize,
        found: AnonymousStream,
    ) -> Result<(), AnonymousError> {
        if self.is_found(&deposit.output_slots[position].output_context.hash) {
            return Ok(());
        }
        let viewing_pubkey = self.history.entries()[index].viewing_pubkey();
        let opener = DepositOpener {
            keys: self.sync.keys,
            address: &self.address,
            assets: self.sync.assets.registry(),
            deposit_payload: self.sync.deposit_payload,
        };
        let opened = opener.open(DepositSlot {
            deposit,
            position,
            viewing_pubkey,
        })?;
        match opened {
            Some(OpenedDeposit::Note(utxo)) => self.keep(*utxo, viewing_pubkey, found),
            Some(OpenedDeposit::UnknownMint(utxo)) => self.hold_back_note(*utxo),
            None => {}
        }
        Ok(())
    }

    /// The spends of every found or held ring note, round after round, open the ring merges among them.
    async fn merges(&mut self, source: MergeSource) -> Result<(), AnonymousError> {
        let mut queried: HashSet<[u8; 32]> = HashSet::new();
        let mut first_round = true;
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
            let history_unread = first_round && matches!(source, MergeSource::History(_));
            if frontier.is_empty() && !history_unread {
                return Ok(());
            }
            let spends = match &source {
                MergeSource::Indexer => self.reads.spends(&frontier).await?,
                // Every merge was read, a note outside the frontier opens it as well.
                MergeSource::History(merges) if first_round => merges.0.clone(),
                MergeSource::History(_) => Vec::new(),
            };
            first_round = false;
            self.note_spends(&spends);
            let merges = RingMerges::among(spends);
            let opened = merges.open(self.sync.keys, self.sync.assets)?;
            let viewing_pubkey = self.address.viewing_pubkey;
            let known = |hash: &[u8; 32], decrypted: &DecryptionResult| {
                decrypted.utxos.iter().any(|held| held.utxo_hash == *hash)
                    || self.sync.held.iter().any(|held| held.utxo_hash == *hash)
            };
            for merge in &merges.0 {
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
                    self.keep(
                        utxo.clone(),
                        viewing_pubkey,
                        AnonymousStream::Merge { first_nullifier },
                    );
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

    /// A held back note carries its nullifier, an absorb stores it with the position past its row.
    fn finish<S: ShieldedKeys + ?Sized>(self, keys: &S) -> Result<AnonymousScan, AnonymousError> {
        let Scan {
            starting_history,
            history,
            found,
            held_back,
            utxos,
            mut decrypted,
            unmatched,
            sent,
            sender_claims,
            mut unopened,
            ..
        } = self;
        assign_nullifiers(keys, &mut decrypted, found)?;
        let mut held = DecryptionResult::default();
        assign_nullifiers(keys, &mut held, held_back)?;
        for note in decrypted.utxos.iter().chain(&held.utxos) {
            unopened.remove(&note.utxo_hash);
        }
        Ok(AnonymousScan {
            starting_history,
            history,
            decrypted,
            pending: held.utxos.into_iter().map(PendingNote::new).collect(),
            sender_claims,
            utxos,
            unmatched,
            sent,
            auditor_recovery: AuditorRecovery {
                unopened: unopened.into_iter().collect(),
            },
        })
    }

    fn counter_mut(&mut self, index: usize, stream: Stream) -> &mut StreamCounter {
        let entry = self.entry_mut(index);
        match stream {
            Stream::Sender => entry.tx_stream_mut(),
            Stream::Request => entry.request_stream_mut(),
        }
    }

    fn entry_mut(&mut self, index: usize) -> &mut ViewingKeyEntry {
        &mut self.history.entries_mut()[index]
    }
}

/// Opens one owner's zero-key merges, the shared reader of normal fetch and full scan.
pub(crate) struct OwnerMergeOpener<'a, K: ?Sized> {
    keys: &'a K,
    owner: PublicKey,
    owner_tag: [u8; 32],
    assets: &'a RingAssets,
}

impl<'a, K: MergeSeedHolder + ?Sized> OwnerMergeOpener<'a, K> {
    pub(crate) fn new(
        keys: &'a K,
        owner: PublicKey,
        assets: &'a RingAssets,
    ) -> Result<Self, AnonymousError> {
        Ok(Self {
            keys,
            owner,
            owner_tag: owner.owner_proof_input_hash()?,
            assets,
        })
    }

    pub(crate) fn candidate<'t>(&self, tx: &'t ShieldedTransaction) -> Option<OwnerMerge<'t>> {
        OwnerMerge::of(tx, &self.owner_tag)
    }

    /// `None` under another wallet's seed, a holder failure fails the read.
    pub(crate) fn open(
        &self,
        merge: &OwnerMerge<'_>,
        viewing_pubkey: X25519Pubkey,
    ) -> Result<Option<OpenedBody>, AnonymousError> {
        let seed = exactly_one(self.keys.merge_seeds(&[MergeSeedRequest {
            viewing_pubkey,
            ring_program_id: merge.ring,
            first_nullifier: merge.first_nullifier,
        }])?)?;
        let Some(note) = merge.rebuild(&seed, self.owner)? else {
            return Ok(None);
        };
        Ok(Some(
            match self.assets.registry().mint(&note.utxo.asset.asset) {
                Ok(registered) => OpenedBody::Note(OpenedNote {
                    utxo: spr_transaction::Utxo {
                        asset: registered,
                        ..note.utxo
                    },
                    ..note
                }),
                Err(TransactionError::UnknownMint(_)) => OpenedBody::UnknownMint(note),
                Err(error) => return Err(error.into()),
            },
        ))
    }
}

/// Nothing of it is authentic until its commitment rebuilds.
pub(crate) struct OwnerMerge<'t> {
    pub(crate) tx: &'t ShieldedTransaction,
    ring: Address,
    first_nullifier: [u8; 32],
    body: RingMergeBody,
}

impl<'t> OwnerMerge<'t> {
    fn of(tx: &'t ShieldedTransaction, owner_tag: &[u8; 32]) -> Option<Self> {
        let [slot] = tx.output_slots.as_slice() else {
            return None;
        };
        if slot.view_tag != *owner_tag || !is_ring_merge(tx) {
            return None;
        }
        Some(Self {
            tx,
            ring: tx.ring_program_id?,
            first_nullifier: *tx.nullifiers.first()?,
            body: RingMergeBody::of(slot)?,
        })
    }

    fn commitment(&self) -> &'t [u8; 32] {
        &self.tx.output_slots[0].output_context.hash
    }

    /// `None` under another wallet's seed.
    fn rebuild(
        &self,
        seed: &MergeSeed,
        owner: PublicKey,
    ) -> Result<Option<OpenedNote>, AnonymousError> {
        let key = seed.output_key(&self.first_nullifier)?;
        let Ok(plaintext) = MergeOutputPlaintext::decrypt(&self.body.encrypted, &key) else {
            return Ok(None);
        };
        let utxo = plaintext.into_utxo(
            owner,
            Mint::new(plaintext.mint, 0),
            seed.output_blinding(&self.first_nullifier)?,
            Some(self.ring),
        );
        let hash = utxo.hash(
            &ZERO_NULLIFIER_PUBKEY,
            &[0; 32],
            &self.body.ring_data_hash,
            self.tx.output_slots[0].output_context.tree_id,
        )?;
        Ok((hash == *self.commitment()).then_some(OpenedNote {
            utxo,
            nullifier_pk: ZERO_NULLIFIER_PUBKEY,
            data_hash: None,
            ring_data_hash: Some(self.body.ring_data_hash),
        }))
    }
}

pub(crate) fn published_note(
    tx: &ShieldedTransaction,
    position: usize,
    note: OpenedNote,
) -> Result<WalletUtxo, AnonymousError> {
    let context = &tx.output_slots[position].output_context;
    Ok(WalletUtxo {
        utxo: note.utxo,
        nullifier_pubkey: note.nullifier_pk,
        utxo_hash: context.hash,
        nullifier: [0; 32],
        tx_viewing_key: None,
        data_hash: note.data_hash,
        ring_data_hash: note.ring_data_hash,
        tree_id: context.tree_id,
        leaf_index: context.leaf_index,
        latest_tree_id: None,
        slot: tx.slot,
        tx_signature: tx.tx_signature,
        slot_index: u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?,
    })
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
    delivered::assign_nullifiers(keys, &mut found)?;
    decrypted.utxos.extend(found);
    delivered::sort_by_publication(&mut decrypted.utxos);
    Ok(())
}
