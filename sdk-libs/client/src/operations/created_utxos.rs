//! Ring notes of deposits, a spend names them by hash.

use std::{
    collections::HashMap,
    num::{NonZeroU32, NonZeroUsize},
};

use solana_address::Address;
use spr_client::{AsyncRpc, IndexerRpcConfig, ProofInputUtxo, ShieldedTransaction};
use spr_event::EncryptedRingDepositOutput;
use spr_hasher::primitives::hash_bytes;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::X25519Keypair;

use crate::history::HistoryCursor;
use crate::{
    confirmed_merge,
    encryption::{open_deposit, DepositCapsule, DepositOpening},
    origin::{ConfirmedDeposit, ConfirmedEventKind, RingOrigin, TransactionOrigin},
    recover::deposit_output,
    scan::{RingHistory, SkippedRow, RING_HISTORY_MAX_PAGES, RING_HISTORY_PAGE_SIZE},
    types::{CreatedUtxo, KnownUtxo, UtxoOwner},
    AuditError, ConfirmedMerge,
};

/// `transaction` is bound to `origin` through [`RingOrigin::bind_transaction`].
#[must_use = "open the notes explicitly"]
pub struct CreatedUtxos<'a> {
    pub transaction: &'a ShieldedTransaction,
    pub origin: &'a RingOrigin,
    pub ring: Address,
}

#[must_use = "run or discard the scan explicitly"]
pub struct CreatedUtxoScan<'a> {
    ring: Address,
    auditor: &'a X25519Keypair,
    cursor: Option<HistoryCursor>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositOwner {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
}

/// Answers only an owner whose `Poseidon(solana_owner_identity(owner_key), nullifier_pk)` is `owner_hash`.
pub trait DepositOwners {
    fn deposit_owner(&self, owner_hash: &[u8; 32]) -> Option<DepositOwner>;
}

/// A deposit note its capsule opened, the commitment checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositNote {
    pub commitment: [u8; 32],
    pub slot_index: u32,
    pub leaf_index: u64,
    pub owner_hash: [u8; 32],
    pub owner_key: [u8; 32],
    pub asset: [u8; 32],
    pub mint: Address,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
    pub tree_id: u16,
}

#[derive(Debug, Default)]
pub struct CreatedNotes {
    pub utxos: Vec<CreatedUtxo>,
    pub unowned: Vec<DepositNote>,
}

/// `next_cursor` is live only when the page cap stopped the read.
pub struct CreatedUtxoPage {
    pub utxos: Vec<CreatedUtxo>,
    pub merges: Vec<ConfirmedMerge>,
    pub next_cursor: Option<HistoryCursor>,
    pub skipped: Vec<SkippedRow>,
}

/// A deposit output beside the confirmed bindings of its transaction.
pub(crate) struct DepositSlot<'a> {
    pub output: &'a EncryptedRingDepositOutput,
    pub bindings: &'a [ConfirmedDeposit],
    pub slot_index: u32,
}

impl<'a> CreatedUtxoScan<'a> {
    pub fn new(ring: Address, auditor: &'a X25519Keypair) -> Self {
        Self {
            ring,
            auditor,
            cursor: None,
            page_size: RING_HISTORY_PAGE_SIZE,
            max_pages: RING_HISTORY_MAX_PAGES,
            indexer_config: None,
        }
    }

    pub fn with_cursor(mut self, cursor: HistoryCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    pub fn with_max_pages(mut self, max_pages: NonZeroUsize) -> Self {
        self.max_pages = max_pages;
        self
    }

    pub fn with_indexer_config(mut self, config: IndexerRpcConfig) -> Self {
        self.indexer_config = Some(config);
        self
    }

    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<CreatedUtxoPage, AuditError> {
        let Self {
            ring,
            auditor,
            cursor,
            page_size,
            max_pages,
            indexer_config,
        } = self;
        let page = RingHistory {
            ring,
            kinds: &[ConfirmedEventKind::Deposit, ConfirmedEventKind::Merge],
            cursor,
            page_size,
            max_pages,
            indexer_config,
        }
        .bound(indexer, origin)
        .await?;
        let mut utxos = Vec::new();
        let mut merges = Vec::new();
        let mut skipped = page.skipped;
        for (transaction, confirmed) in &page.transactions {
            if confirmed.event.kind() == ConfirmedEventKind::Merge {
                let event_index = transaction
                    .event_index
                    .ok_or(AuditError::MissingEventIndex)?;
                match confirmed_merge(transaction, event_index, confirmed, auditor) {
                    Ok(Some(merge)) => merges.push(merge),
                    Ok(None) => {}
                    Err(error) => skipped.push(SkippedRow::of(transaction, error)?),
                }
                continue;
            }
            let opened = CreatedUtxos {
                transaction,
                origin: confirmed,
                ring,
            }
            .open(auditor);
            match opened {
                Ok(created) => utxos.extend(created),
                Err(error) => skipped.push(SkippedRow::of(transaction, error)?),
            }
        }
        Ok(CreatedUtxoPage {
            utxos,
            merges,
            next_cursor: page.next_cursor,
            skipped,
        })
    }
}

impl CreatedUtxos<'_> {
    /// Empty for a transfer.
    pub fn open(self, auditor: &X25519Keypair) -> Result<Vec<CreatedUtxo>, AuditError> {
        let mut notes = self.open_for(auditor, &HashMap::new())?;
        notes
            .utxos
            .extend(notes.unowned.iter().map(DepositNote::deposited));
        Ok(notes.utxos)
    }

    /// A deposit `owners` does not name stays in `unowned`.
    pub fn open_for(
        self,
        auditor: &X25519Keypair,
        owners: &dyn DepositOwners,
    ) -> Result<CreatedNotes, AuditError> {
        match self.origin.event.kind() {
            ConfirmedEventKind::Deposit => {
                let mut notes = CreatedNotes::default();
                for note in self.deposits(auditor)? {
                    match note.created(owners) {
                        Some(utxo) => notes.utxos.push(utxo),
                        None => notes.unowned.push(note),
                    }
                }
                Ok(notes)
            }
            ConfirmedEventKind::Merge | ConfirmedEventKind::Transfer => Ok(CreatedNotes::default()),
        }
    }

    fn deposits(&self, auditor: &X25519Keypair) -> Result<Vec<DepositNote>, AuditError> {
        let mut notes = Vec::new();
        for (slot_index, slot) in (0u32..).zip(&self.transaction.output_slots) {
            let Some(output) = deposit_output(slot, self.ring) else {
                continue;
            };
            let Some(opening) = (DepositSlot {
                output: &output,
                bindings: &self.origin.deposits,
                slot_index,
            })
            .open(auditor)?
            else {
                continue;
            };
            let owner_hash = opening.owner_hash;
            let mint = Address::new_from_array(output.asset);
            let data_hash = output.data_hash.unwrap_or_default();
            let context = &slot.output_context;
            let commitment = ProofInputUtxo::new(
                owner_hash,
                &mint,
                output.amount,
                &opening.blinding,
                context.tree_id,
            )?
            .with_data_hash(data_hash)
            .with_ring(output.ring_data_hash, &Some(self.ring))?
            .hash()?;
            if commitment != context.hash {
                return Err(AuditError::DepositOpeningMismatch);
            }
            notes.push(DepositNote {
                commitment,
                slot_index,
                leaf_index: context.leaf_index,
                owner_hash,
                owner_key: opening.owner_key,
                asset: hash_bytes(mint.as_array())?,
                mint,
                amount: output.amount,
                blinding: *opening.blinding,
                data_hash,
                ring_data_hash: output.ring_data_hash,
                tree_id: context.tree_id,
            });
        }
        Ok(notes)
    }
}

impl DepositNote {
    /// `None` until `owners` names the owner's nullifier key, a zero secret owner registers none.
    pub fn created(&self, owners: &dyn DepositOwners) -> Option<CreatedUtxo> {
        let nullifier_pk = match owners.deposit_owner(&self.owner_hash) {
            Some(escrowed) => escrowed.nullifier_pk,
            None => self.zero_secret_owner()?,
        };
        Some(self.owned_by(UtxoOwner::Keyed { nullifier_pk }))
    }

    fn zero_secret_owner(&self) -> Option<[u8; 32]> {
        let zero_owner = UtxoOwner::Keyed {
            nullifier_pk: ZERO_NULLIFIER_PUBKEY,
        };
        let rebuilt = KnownUtxo {
            owner: zero_owner,
            ..self.deposited().utxo
        };
        (rebuilt.owner_hash().ok()? == self.owner_hash).then_some(ZERO_NULLIFIER_PUBKEY)
    }

    pub fn deposited(&self) -> CreatedUtxo {
        self.owned_by(UtxoOwner::Deposited {
            owner_hash: self.owner_hash,
        })
    }

    fn owned_by(&self, owner: UtxoOwner) -> CreatedUtxo {
        CreatedUtxo {
            commitment: self.commitment,
            slot_index: self.slot_index,
            leaf_index: self.leaf_index,
            ring_note: true,
            utxo: KnownUtxo {
                owner_key: self.owner_key,
                owner,
                asset: self.asset,
                mint: Some(self.mint),
                amount: self.amount,
                blinding: self.blinding,
                data_hash: self.data_hash,
                ring_data_hash: self.ring_data_hash,
                tree_id: self.tree_id,
            },
        }
    }
}

impl DepositOwners for HashMap<[u8; 32], DepositOwner> {
    fn deposit_owner(&self, owner_hash: &[u8; 32]) -> Option<DepositOwner> {
        self.get(owner_hash).copied()
    }
}

impl DepositSlot<'_> {
    /// `None` without a binding, the capsule proof covers a bound slot alone.
    pub(crate) fn open(
        self,
        auditor: &X25519Keypair,
    ) -> Result<Option<DepositOpening>, AuditError> {
        let Some(binding) = self
            .bindings
            .iter()
            .find(|binding| u32::from(binding.slot_index()) == self.slot_index)
        else {
            return Ok(None);
        };
        let capsule = DepositCapsule::parse(&self.output.encrypted.ciphertext)
            .ok()
            .flatten()
            .ok_or(AuditError::DepositOpeningMismatch)?;
        let opening = open_deposit(&capsule, auditor, &self.output.owner_utxo_hash, binding)?;
        match opening.agrees_with(&self.output.asset, self.output.amount) {
            true => Ok(Some(opening)),
            false => Err(AuditError::DepositOpeningMismatch),
        }
    }
}
