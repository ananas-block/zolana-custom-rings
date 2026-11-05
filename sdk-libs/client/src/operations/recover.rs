//! Rebuilds a source member's unspent ring notes from what the auditor sees.

use std::{
    collections::{BTreeSet, HashSet},
    num::{NonZeroU32, NonZeroUsize},
};

use custom_ring_interface::RingMode;
use solana_address::Address;
use spr_client::{AsyncRpc, IndexerRpcConfig};
use spr_event::EncryptedRingDepositOutput;
use spr_event_parser::decode_encrypted_ring_deposit_output_data;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{hash::owner_hash, NullifierKey, ShieldedAddress, X25519Keypair};
use spr_transaction::{
    instructions::merge::{
        merge_circuit_width, merge_output_blinding, merge_output_key, MergeOutputPlaintext,
    },
    Data, OutputContext, OutputSlot, ShieldedTransaction, TransactionError, Utxo, WalletUtxo,
};
use zolana_ring_transaction::RingAssets;

use crate::{
    confirmed_merge,
    created::{CreatedUtxos, DepositSlot},
    decrypt::TransactionAudit,
    known::KnownUtxoIndex,
    merge_audit::RingMergeBody,
    origin::{ConfirmedEventKind, RingOrigin, TransactionOrigin},
    scan::{RingHistory, ScanPage, SkippedRow, RING_HISTORY_MAX_PAGES, RING_HISTORY_PAGE_SIZE},
    types::{InputOpening, OutputOpening},
    AuditError, KnownUtxo, UtxoOwner,
};

#[must_use = "run the recovery explicitly"]
pub struct RingRecovery<'a> {
    ring_program_id: Address,
    auditor: &'a X25519Keypair,
    mode: RingMode,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

pub struct SourceMember<'a> {
    pub address: &'a ShieldedAddress,
    pub nullifier_key: &'a NullifierKey,
}

#[must_use = "run the recovery explicitly"]
pub struct MemberRecovery<'a> {
    recovery: RingRecovery<'a>,
    source: SourceMember<'a>,
}

/// Application commitments supplied by the note's protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct UtxoDataHashes {
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
}

/// Verified unspent notes with the coverage left unresolved.
pub struct RecoveredNotes {
    pub utxos: Vec<WalletUtxo>,
    /// Commitments that cannot yet become spendable notes, including unknown mints.
    pub unopened: Vec<[u8; 32]>,
    /// Tagged deposits whose ownership and spentness are unknown.
    pub unsupported_deposits: Vec<[u8; 32]>,
    /// Verified merge mints the asset registry lacks, their notes stay unresolved.
    pub unknown_mints: BTreeSet<Address>,
    /// Nullifiers of real inputs no note the member opened matches.
    pub unseen_inputs: Vec<[u8; 32]>,
}

impl<'a> RingRecovery<'a> {
    pub fn new(ring_program_id: Address, auditor: &'a X25519Keypair) -> Self {
        Self {
            ring_program_id,
            auditor,
            mode: RingMode::Confidential,
            page_size: RING_HISTORY_PAGE_SIZE,
            max_pages: RING_HISTORY_MAX_PAGES,
            indexer_config: None,
        }
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    /// The rail a ring `Transact` frame parses under.
    pub fn with_mode(mut self, mode: RingMode) -> Self {
        self.mode = mode;
        self
    }

    /// Bounds each history scan and all spentness queries together.
    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    /// An indexer behind `config.require_slot` would report a spent note as unspent.
    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub fn for_member(self, source: SourceMember<'a>) -> MemberRecovery<'a> {
        MemberRecovery {
            recovery: self,
            source,
        }
    }
}

impl SourceMember<'_> {
    /// The key a note of `owner` sits under, `None` for another owner.
    fn nullifier_pk_of(&self, owner: [u8; 32]) -> Result<Option<[u8; 32]>, AuditError> {
        // A zero-key note of the member's signing key is still the member's note.
        for nullifier_pk in [self.address.nullifier_pubkey, ZERO_NULLIFIER_PUBKEY] {
            if owner_hash(&self.address.signing_pubkey, &nullifier_pk)? == owner {
                return Ok(Some(nullifier_pk));
            }
        }
        Ok(None)
    }

    /// A zero-key note's nullifier needs no secret, anyone with the opening derives it.
    fn nullifier(
        &self,
        nullifier_pk: &[u8; 32],
        commitment: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], AuditError> {
        let zero_key;
        let key = if *nullifier_pk == ZERO_NULLIFIER_PUBKEY {
            zero_key = NullifierKey::from_secret([0; 31]);
            &zero_key
        } else {
            self.nullifier_key
        };
        Ok(key.nullifier(commitment, blinding)?)
    }

    /// The UTXO at `context` under `nullifier_pk` and whether it reproduces the leaf there.
    fn wallet_utxo(
        &self,
        utxo: Utxo,
        nullifier_pk: [u8; 32],
        context: &OutputContext,
        hashes: UtxoDataHashes,
        tx: &ShieldedTransaction,
        slot_index: u32,
    ) -> Result<(WalletUtxo, bool), AuditError> {
        let commitment = utxo.hash(
            &nullifier_pk,
            &hashes.data_hash.unwrap_or_default(),
            &hashes.ring_data_hash.unwrap_or_default(),
            context.tree_id,
        )?;
        let held = WalletUtxo {
            nullifier: self.nullifier(&nullifier_pk, &context.hash, &utxo.blinding)?,
            utxo,
            nullifier_pubkey: nullifier_pk,
            utxo_hash: context.hash,
            tx_viewing_key: None,
            data_hash: hashes.data_hash,
            ring_data_hash: hashes.ring_data_hash,
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
            latest_tree_id: None,
            slot: tx.slot,
            tx_signature: tx.tx_signature,
            slot_index,
        };
        Ok((held, commitment == context.hash))
    }

    fn utxo(&self, asset: spr_transaction::Mint, amount: u64, blinding: [u8; 32]) -> Utxo {
        Utxo {
            owner: self.address.signing_pubkey,
            asset,
            amount,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        }
    }
}

/// Notes found so far, by the commitments already claimed.
#[derive(Default)]
struct Found {
    candidates: Vec<WalletUtxo>,
    /// Commitments without a verified opening, with their nullifiers.
    unresolved: Vec<([u8; 32], [u8; 32])>,
    seen: HashSet<[u8; 32]>,
    unknown_mints: BTreeSet<Address>,
    /// Openings a merge output resolves from, in history order.
    known: KnownUtxoIndex,
    /// In history order.
    real_inputs: Vec<[u8; 32]>,
}

impl Found {
    fn nullifiers(&self) -> HashSet<[u8; 32]> {
        self.candidates
            .iter()
            .map(|note| note.nullifier)
            .chain(self.unresolved.iter().map(|(_, nullifier)| *nullifier))
            .collect()
    }
}

impl<'a> MemberRecovery<'a> {
    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
        assets: &RingAssets,
    ) -> Result<RecoveredNotes, AuditError> {
        // The nullifier key must derive the requested address.
        if self.source.nullifier_key.pubkey()? != self.source.address.nullifier_pubkey {
            return Err(AuditError::NullifierKeyMismatch);
        }
        let recovery = &self.recovery;
        let history = self.ring_history(indexer, origin).await?;
        let mut found = Found::default();
        for (transaction, confirmed) in &history {
            if recovery.mode == RingMode::Anonymous {
                let created = CreatedUtxos {
                    transaction,
                    origin: confirmed,
                    ring: recovery.ring_program_id,
                }
                .open(recovery.auditor)?;
                found.known.extend(
                    created
                        .into_iter()
                        .map(|created| (created.commitment, created.utxo)),
                );
            }
            if confirmed.event.kind() == ConfirmedEventKind::Merge {
                let event_index = transaction
                    .event_index
                    .ok_or(AuditError::MissingEventIndex)?;
                if let Some(merge) =
                    confirmed_merge(transaction, event_index, confirmed, recovery.auditor)?
                {
                    found.known.apply_merge(merge);
                }
            }
        }
        let unsupported_deposits = self.deposited_utxos(&history, assets, &mut found)?;
        for confirmed in &history {
            if confirmed.1.requires_audit() {
                self.audited_utxos(confirmed, assets, &mut found)?;
            }
        }
        let spent = history
            .iter()
            .flat_map(|(transaction, _)| transaction.nullifiers.iter().copied())
            .collect::<HashSet<_>>();
        let merges = MergeRecovery {
            ring: recovery.ring_program_id,
            history: &history,
            assets,
            found: &mut found,
        }
        .recover(&self.source)?;
        let opened_nullifiers = found.nullifiers();
        let unseen_inputs = found
            .real_inputs
            .iter()
            .filter(|nullifier| !opened_nullifiers.contains(*nullifier))
            .copied()
            .collect();
        let mut unopened: Vec<_> = found
            .unresolved
            .into_iter()
            .filter(|(_, nullifier)| !spent.contains(nullifier))
            .map(|(commitment, _)| commitment)
            .collect();
        unopened.extend(
            merges
                .iter()
                .map(|merge| merge.output_slots[0].output_context.hash)
                .filter(|commitment| !found.seen.contains(commitment)),
        );
        Ok(RecoveredNotes {
            utxos: found
                .candidates
                .into_iter()
                .filter(|candidate| !spent.contains(&candidate.nullifier))
                .collect(),
            unopened,
            unsupported_deposits,
            unknown_mints: found.unknown_mints,
            unseen_inputs,
        })
    }

    /// The source's ring outputs in one audited transaction, every opening already proof-bound.
    fn audited_utxos(
        &self,
        (transaction, origin): &(ShieldedTransaction, RingOrigin),
        assets: &RingAssets,
        found: &mut Found,
    ) -> Result<(), AuditError> {
        let frame = origin.audit_frame(self.recovery.mode)?;
        let audited = TransactionAudit::new(transaction, frame).run(self.recovery.auditor)?;
        found.known.extend(
            audited
                .utxos()
                .map(|created| (created.commitment, created.utxo)),
        );
        found.real_inputs.extend(
            audited
                .inputs
                .iter()
                .filter(|input| input.opening == InputOpening::Real)
                .map(|input| input.nullifier),
        );
        if let Some(error) = audited.payload_errors.first() {
            return Err(AuditError::UnopenedOutput {
                slot: error.slot_index,
                kind: error.kind,
            });
        }
        for output in &audited.outputs {
            let OutputOpening::Ring { utxo: opened, .. } = &output.opening else {
                continue;
            };
            let context = &output.context;
            let Some(nullifier_pk) = self.source.nullifier_pk_of(opened.owner_hash()?)? else {
                continue;
            };
            if !found.seen.insert(context.hash) {
                continue;
            }
            let mint = match opened
                .mint
                .map(|mint| assets.registry().mint(&mint))
                .transpose()
            {
                Ok(mint) => mint,
                Err(TransactionError::UnknownMint(mint)) => {
                    found.unknown_mints.insert(mint);
                    None
                }
                Err(error) => return Err(error.into()),
            };
            let Some(mint) = mint else {
                // Ownership and spentness remain known even without the asset preimage.
                found.unresolved.push((
                    context.hash,
                    self.source
                        .nullifier(&nullifier_pk, &context.hash, &opened.blinding)?,
                ));
                continue;
            };
            let hashes = UtxoDataHashes {
                data_hash: Some(opened.data_hash).filter(|hash| *hash != [0; 32]),
                ring_data_hash: Some(opened.ring_data_hash).filter(|hash| *hash != [0; 32]),
            };
            let utxo = Utxo {
                ring_program_id: Some(self.recovery.ring_program_id),
                ..self.source.utxo(mint, opened.amount, opened.blinding)
            };
            match self.source.wallet_utxo(
                utxo,
                nullifier_pk,
                context,
                hashes,
                transaction,
                output.slot_index,
            )? {
                (held, true) => found.candidates.push(held),
                (held, false) => found.unresolved.push((context.hash, held.nullifier)),
            }
        }
        Ok(())
    }

    async fn ring_history<I: AsyncRpc, O: TransactionOrigin>(
        &self,
        indexer: &I,
        origin: &O,
    ) -> Result<Vec<(ShieldedTransaction, RingOrigin)>, AuditError> {
        let RingRecovery {
            ring_program_id,
            page_size,
            max_pages,
            indexer_config,
            ..
        } = self.recovery;
        let kinds = &[
            ConfirmedEventKind::Deposit,
            ConfirmedEventKind::Merge,
            ConfirmedEventKind::Transfer,
        ];
        let page = RingHistory {
            ring: ring_program_id,
            kinds,
            cursor: None,
            page_size,
            max_pages,
            indexer_config,
        }
        .bound(indexer, origin)
        .await?;
        complete(page)
    }

    /// Disclosed deposits are found without trusting their recipient view tags.
    fn deposited_utxos(
        &self,
        history: &[(ShieldedTransaction, RingOrigin)],
        assets: &RingAssets,
        found: &mut Found,
    ) -> Result<Vec<[u8; 32]>, AuditError> {
        let ring = self.recovery.ring_program_id;
        let mut processed = HashSet::new();
        let mut unsupported = Vec::new();
        let deposits = history
            .iter()
            .filter(|(_, confirmed)| confirmed.event.kind() == ConfirmedEventKind::Deposit);
        for (transaction, confirmed) in deposits {
            for (slot_index, slot) in (0u32..).zip(&transaction.output_slots) {
                let Some(output) = deposit_output(slot, ring) else {
                    continue;
                };
                let context = &slot.output_context;
                if !processed.insert(context.hash) || found.seen.contains(&context.hash) {
                    continue;
                }
                let opened = DepositSlot {
                    output: &output,
                    bindings: &confirmed.deposits,
                    slot_index,
                }
                .open(self.recovery.auditor);
                let Ok(Some(opening)) = opened else {
                    unsupported.push(context.hash);
                    continue;
                };
                let Some(nullifier_pk) = self.source.nullifier_pk_of(opening.owner_hash)? else {
                    continue;
                };
                let asset = Address::new_from_array(output.asset);
                // The deposit proof binds the raw mint, the commitment needs no registry id.
                let mint = match assets.registry().mint(&asset) {
                    Ok(mint) => Some(mint),
                    Err(TransactionError::UnknownMint(_)) => None,
                    Err(error) => return Err(error.into()),
                };
                let utxo = Utxo {
                    ring_program_id: Some(ring),
                    ..self.source.utxo(
                        mint.unwrap_or_else(|| spr_transaction::Mint::new(asset, 0)),
                        output.amount,
                        *opening.blinding,
                    )
                };
                let hashes = UtxoDataHashes {
                    data_hash: output.data_hash,
                    ring_data_hash: Some(output.ring_data_hash),
                };
                let (held, opens) = self.source.wallet_utxo(
                    utxo,
                    nullifier_pk,
                    context,
                    hashes,
                    transaction,
                    slot_index,
                )?;
                if !opens {
                    return Err(AuditError::DepositOpeningMismatch);
                }
                found.known.insert(
                    context.hash,
                    KnownUtxo {
                        owner_key: opening.owner_key,
                        owner: UtxoOwner::Keyed { nullifier_pk },
                        asset: spr_hasher::primitives::hash_bytes(asset.as_array())?,
                        mint: Some(asset),
                        amount: output.amount,
                        blinding: *opening.blinding,
                        data_hash: hashes.data_hash.unwrap_or_default(),
                        ring_data_hash: hashes.ring_data_hash.unwrap_or_default(),
                        tree_id: context.tree_id,
                    },
                );
                found.seen.insert(context.hash);
                if mint.is_some() {
                    found.candidates.push(held);
                } else {
                    found.unknown_mints.insert(asset);
                    found.unresolved.push((context.hash, held.nullifier));
                }
            }
        }
        Ok(unsupported)
    }
}

struct RecoveredMerge {
    note: WalletUtxo,
    opening: KnownUtxo,
}

impl RecoveredMerge {
    fn from_note(note: WalletUtxo) -> Result<Self, AuditError> {
        let opening = KnownUtxo {
            owner_key: note.utxo.owner.confidential_view_tag()?,
            owner: UtxoOwner::Keyed {
                nullifier_pk: note.nullifier_pubkey,
            },
            asset: spr_hasher::primitives::hash_bytes(note.utxo.asset.asset.as_array())?,
            mint: Some(note.utxo.asset.asset),
            amount: note.utxo.amount,
            blinding: note.utxo.blinding,
            data_hash: [0; 32],
            ring_data_hash: note.ring_data_hash.unwrap_or_default(),
            tree_id: note.tree_id,
        };
        Ok(Self { note, opening })
    }
}

struct MergeRecovery<'a, 'h> {
    ring: Address,
    history: &'h [(ShieldedTransaction, RingOrigin)],
    assets: &'a RingAssets,
    found: &'a mut Found,
}

impl<'h> MergeRecovery<'_, 'h> {
    fn recover(
        self,
        source: &SourceMember<'_>,
    ) -> Result<Vec<&'h ShieldedTransaction>, AuditError> {
        let Self {
            ring,
            history,
            assets,
            found,
        } = self;
        let merges: Vec<_> = history
            .iter()
            .filter(|(transaction, origin)| {
                origin.event.kind() == ConfirmedEventKind::Merge
                    && transaction.output_slots.len() == 1
                    && merge_circuit_width(transaction.nullifiers.len()).is_some()
            })
            .map(|(transaction, _)| transaction)
            .collect();
        loop {
            let previous = found.seen.len();
            let source_nullifiers = found.nullifiers();
            for transaction in &merges {
                let output = &transaction.output_slots[0].output_context;
                if found.seen.contains(&output.hash) {
                    continue;
                }
                let successor = match found.known.merge_output(&output.hash).cloned() {
                    // 1. A sealed record opens its output without input history, the only path to a zero-key merge.
                    Some(merged) => {
                        let owner =
                            source.nullifier_pk_of(merged.owner.hash(&merged.owner_key)?)?;
                        match owner {
                            Some(nullifier_pk) => {
                                let opening = merged.opening()?;
                                // Rebuild checked this commitment, the leaf check adds nothing.
                                let (note, _) = source.wallet_utxo(
                                    Utxo {
                                        ring_program_id: Some(ring),
                                        ..source.utxo(
                                            spr_transaction::Mint::new(merged.mint, 0),
                                            opening.amount,
                                            opening.blinding,
                                        )
                                    },
                                    nullifier_pk,
                                    output,
                                    UtxoDataHashes {
                                        data_hash: None,
                                        ring_data_hash: Some(opening.ring_data_hash),
                                    },
                                    transaction,
                                    0,
                                )?;
                                Some(RecoveredMerge { note, opening })
                            }
                            // 2. Another owner's record, the member's spends alone never claim its output.
                            None => None,
                        }
                    }
                    // 3. With no record, only a merge spending a source note opens under the nullifier key.
                    None if transaction
                        .nullifiers
                        .iter()
                        .any(|nullifier| source_nullifiers.contains(nullifier)) =>
                    {
                        merge_successor(source, transaction, ring)?
                            .map(RecoveredMerge::from_note)
                            .transpose()?
                    }
                    None => None,
                };
                let Some(RecoveredMerge { mut note, opening }) = successor else {
                    continue;
                };
                found.seen.insert(output.hash);
                found.known.insert(output.hash, opening);
                match assets.registry().mint(&note.utxo.asset.asset) {
                    Ok(mint) => {
                        note.utxo.asset = mint;
                        found.candidates.push(note);
                    }
                    Err(TransactionError::UnknownMint(mint)) => {
                        found.unknown_mints.insert(mint);
                        found.unresolved.push((note.utxo_hash, note.nullifier));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if found.seen.len() == previous {
                break;
            }
        }
        let source_nullifiers = found.nullifiers();
        Ok(merges
            .into_iter()
            .filter(|transaction| {
                found
                    .seen
                    .contains(&transaction.output_slots[0].output_context.hash)
                    || transaction
                        .nullifiers
                        .iter()
                        .any(|nullifier| source_nullifiers.contains(nullifier))
            })
            .collect())
    }
}

fn complete<T>(page: ScanPage<T>) -> Result<Vec<T>, AuditError> {
    if page.next_cursor.is_some() {
        return Err(AuditError::IncompleteScan);
    }
    refuse_skipped(page.skipped)?;
    Ok(page.transactions)
}

/// A row left unread can hold a source note or its spend, the result would not be complete.
fn refuse_skipped(skipped: Vec<SkippedRow>) -> Result<(), AuditError> {
    match skipped.into_iter().next() {
        Some(row) => Err(row.error),
        None => Ok(()),
    }
}

pub(crate) fn deposit_output(
    slot: &OutputSlot,
    ring: Address,
) -> Option<EncryptedRingDepositOutput> {
    decode_encrypted_ring_deposit_output_data(&slot.payload)
        .ok()
        .filter(|output| output.ring_program_id == ring.to_bytes())
}

/// A temporary asset id verifies the commitment before the registry lookup.
fn merge_successor(
    source: &SourceMember<'_>,
    transaction: &ShieldedTransaction,
    ring: Address,
) -> Result<Option<WalletUtxo>, AuditError> {
    let Some(first_nullifier) = transaction.nullifiers.first() else {
        return Ok(None);
    };
    let Some(slot) = transaction.output_slots.first() else {
        return Ok(None);
    };
    let Some(RingMergeBody {
        ring_data_hash,
        encrypted,
    }) = RingMergeBody::of(slot)
    else {
        return Ok(None);
    };
    let key = merge_output_key(source.nullifier_key, first_nullifier)?;
    let Ok(plaintext) = MergeOutputPlaintext::decrypt(&encrypted, &key) else {
        return Ok(None);
    };
    let utxo = plaintext.into_utxo(
        source.address.signing_pubkey,
        spr_transaction::Mint::new(plaintext.mint, 0),
        merge_output_blinding(source.nullifier_key, first_nullifier)?,
        Some(ring),
    );
    let hashes = UtxoDataHashes {
        data_hash: None,
        ring_data_hash: Some(ring_data_hash),
    };
    let (successor, opens) = source.wallet_utxo(
        utxo,
        source.address.nullifier_pubkey,
        &slot.output_context,
        hashes,
        transaction,
        0,
    )?;
    Ok(opens.then_some(successor))
}
