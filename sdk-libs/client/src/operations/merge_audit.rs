//! Reads every confirmed ring merge into the ledger's input list, keys the disclosure alone opens.

use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroUsize},
};

use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    AsyncRpc, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, RingHistoryOptions,
    ShieldedTransaction,
};
use spr_event::{
    merge_output::MERGE_OUTPUT_SALT_LEN, split_merge_output_body, OutputDataEncoding,
    MERGE_OUTPUT_BODY_LEN, MERGE_OUTPUT_SCHEME,
};
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_indexer_api::Context;
use spr_interface::instruction::instruction_data::merge_transact::merge_circuit_width;
use spr_keypair::{X25519Keypair, X25519Pubkey};

use crate::{
    encryption::open_merge_disclosure,
    history::{HistoryCursor, HistoryPosition, HistoryQuery, HistoryStream, PageEnd},
    merge_ledger::ConfirmedMerge,
    origin::{ConfirmedEventKind, ConfirmedMergeDisclosure, RingOrigin, TransactionOrigin},
    scan::{RING_HISTORY_MAX_PAGES, RING_HISTORY_PAGE_SIZE},
    AuditError,
};

/// The cursor names the last Solana transaction the page examined.
pub struct MergeAuditPage {
    pub context: Context,
    pub merges: Vec<ConfirmedMerge>,
    /// Merge rows whose disclosure no v3 frame carries, the historical reader owns them.
    pub historical: Vec<(u64, Signature, u16)>,
    pub next_cursor: Option<HistoryCursor>,
}

/// An incomplete scan aborts.
#[must_use = "run or discard the merge audit explicitly"]
pub struct MergeAudit<'a> {
    ring: Address,
    auditor: &'a X25519Keypair,
    cursor: Option<HistoryCursor>,
    page_size: NonZeroU32,
    max_pages: NonZeroUsize,
    indexer_config: Option<IndexerRpcConfig>,
}

/// One confirmed merge output, its body length and fields checked.
pub(crate) struct MergeOutput {
    pub(crate) commitment: [u8; 32],
    pub(crate) tree_id: u16,
    pub(crate) leaf_index: u64,
    pub(crate) first_nullifier: [u8; 32],
    pub(crate) width: usize,
    pub(crate) salt: [u8; MERGE_OUTPUT_SALT_LEN],
}

#[derive(Default)]
struct OpenedPage {
    merges: Vec<ConfirmedMerge>,
    historical: Vec<(u64, Signature, u16)>,
}

impl<'a> MergeAudit<'a> {
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

    pub fn with_page_size(mut self, page_size: NonZeroU32) -> Self {
        self.page_size = page_size;
        self
    }

    pub fn with_cursor(mut self, cursor: Option<HistoryCursor>) -> Self {
        self.cursor = cursor;
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

    /// Every confirmed merge from the cursor on, in history order.
    pub async fn run<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<Vec<ConfirmedMerge>, AuditError> {
        let mut position = self.query().position(self.cursor)?;
        let mut merges = Vec::new();
        let mut seen = HashSet::new();
        for _ in 0..self.max_pages.get() {
            let (response, end) = self.read_history_page(indexer, &mut position).await?;
            let page = self
                .open_transactions(rows(response), origin, &mut seen)
                .await?;
            merges.extend(page.merges);
            if let PageEnd::Terminal(_) = end {
                return Ok(merges);
            }
        }
        Err(AuditError::IncompleteScan)
    }

    /// Open one ring-history page for an authenticated RPC reader.
    pub async fn page<I: AsyncRpc, O: TransactionOrigin>(
        self,
        indexer: &I,
        origin: &O,
    ) -> Result<MergeAuditPage, AuditError> {
        let query = self.query();
        let mut position = query.position(self.cursor)?;
        let (response, _) = self.read_history_page(indexer, &mut position).await?;
        let context = response.context;
        let mut seen = HashSet::new();
        let page = self
            .open_transactions(rows(response), origin, &mut seen)
            .await?;
        Ok(MergeAuditPage {
            context,
            merges: page.merges,
            historical: page.historical,
            next_cursor: query.next_cursor(&position),
        })
    }

    const fn query(&self) -> HistoryQuery {
        HistoryQuery {
            ring: self.ring,
            stream: HistoryStream::Ring,
        }
    }

    async fn read_history_page<I: AsyncRpc>(
        &self,
        indexer: &I,
        position: &mut HistoryPosition,
    ) -> Result<(GetShieldedTransactionsByTagsResponse, PageEnd), AuditError> {
        let response = indexer
            .get_shielded_transactions_by_ring(
                RingHistoryOptions {
                    ring_program_id: self.ring,
                    pagination_token: position.token(),
                    limit: Some(self.page_size.get()),
                    filters: position.filters(),
                },
                self.indexer_config,
            )
            .await?;
        let end = position
            .advance(&response, self.page_size.get())
            .map_err(|_| AuditError::InvalidHistoryPage)?;
        Ok((response, end))
    }

    async fn open_transactions<O: TransactionOrigin>(
        &self,
        transactions: Vec<ShieldedTransaction>,
        origin: &O,
        seen: &mut HashSet<(Signature, u16)>,
    ) -> Result<OpenedPage, AuditError> {
        let mut page = OpenedPage::default();
        for mut tx in transactions {
            if tx.ring_program_id != Some(self.ring) {
                continue;
            }
            let event_index = tx.event_index.ok_or(AuditError::MissingEventIndex)?;
            let confirmed = origin
                .origin(tx.tx_signature, event_index, self.ring)
                .await?;
            if !confirmed.ring_invoked || confirmed.event.kind() != ConfirmedEventKind::Merge {
                continue;
            }
            confirmed.bind_transaction(&mut tx, self.ring)?;
            remember_merge(seen, tx.tx_signature, event_index)?;
            match confirmed_merge(&tx, event_index, &confirmed, self.auditor)? {
                Some(merge) => page.merges.push(merge),
                None => page
                    .historical
                    .push((tx.slot, tx.tx_signature, event_index)),
            }
        }
        Ok(page)
    }
}

fn rows(response: GetShieldedTransactionsByTagsResponse) -> Vec<ShieldedTransaction> {
    response
        .data
        .into_iter()
        .flat_map(|item| item.events)
        .collect()
}

/// The merge a bound row settled, `None` on a frame with no v3 disclosure.
pub fn confirmed_merge(
    transaction: &ShieldedTransaction,
    event_index: u16,
    origin: &RingOrigin,
    auditor: &X25519Keypair,
) -> Result<Option<ConfirmedMerge>, AuditError> {
    let Some(disclosure) = &origin.merge_disclosure else {
        return Ok(None);
    };
    let output = MergeOutput::of(transaction)?;
    let list = output.disclose(auditor, disclosure)?;
    Ok(Some(ConfirmedMerge {
        slot: transaction.slot,
        tx_signature: transaction.tx_signature,
        event_index,
        output_commitment: output.commitment,
        tree_id: output.tree_id,
        leaf_index: output.leaf_index,
        first_nullifier: output.first_nullifier,
        inputs: ConfirmedMerge::real_inputs(&list),
    }))
}

impl MergeOutput {
    /// A malformed confirmed field is an audit error.
    pub(crate) fn of(tx: &ShieldedTransaction) -> Result<Self, AuditError> {
        let [slot] = tx.output_slots.as_slice() else {
            return Err(invalid_merge());
        };
        let first_nullifier = *tx.nullifiers.first().ok_or_else(invalid_merge)?;
        let width = merge_circuit_width(tx.nullifiers.len()).ok_or_else(invalid_merge)?;
        let Some(OutputDataEncoding::Encrypted(blob)) = slot.output_data() else {
            return Err(invalid_merge());
        };
        let Some((&MERGE_OUTPUT_SCHEME, body)) = blob.split_first() else {
            return Err(invalid_merge());
        };
        let Some((Some(ring_data_hash), encrypted)) = split_merge_output_body(body) else {
            return Err(invalid_merge());
        };
        let commitment = slot.output_context.hash;
        let (salt, fields) = encrypted
            .split_first_chunk::<MERGE_OUTPUT_SALT_LEN>()
            .filter(|_| encrypted.len() == MERGE_OUTPUT_BODY_LEN)
            .ok_or_else(invalid_merge)?;
        if ![first_nullifier, commitment, *ring_data_hash]
            .iter()
            .chain(fields.as_chunks::<32>().0)
            .all(is_canonical_bn254_scalar_be)
        {
            return Err(invalid_merge());
        }
        Ok(Self {
            commitment,
            tree_id: slot.output_context.tree_id,
            leaf_index: slot.output_context.leaf_index,
            first_nullifier,
            width,
            salt: *salt,
        })
    }

    /// The list in circuit slot order, its proof binds length, order and dummies.
    pub(crate) fn disclose(
        &self,
        auditor: &X25519Keypair,
        disclosure: &ConfirmedMergeDisclosure,
    ) -> Result<Vec<[u8; 32]>, AuditError> {
        let opening = open_merge_disclosure(
            auditor,
            &X25519Pubkey::from_bytes(disclosure.eph_pk)?,
            &disclosure.ciphertext,
            self.salt,
            &disclosure.fields,
        )?;
        if opening.input_commitments.len() != self.width {
            return Err(AuditError::MergeDisclosureMismatch);
        }
        Ok(opening.input_commitments)
    }
}

fn invalid_merge() -> AuditError {
    AuditError::InvalidConfirmedEvent("ring merge output is malformed".to_owned())
}

fn remember_merge(
    seen: &mut HashSet<(Signature, u16)>,
    signature: Signature,
    event_index: u16,
) -> Result<(), AuditError> {
    if !seen.insert((signature, event_index)) {
        return Err(AuditError::InvalidConfirmedEvent(
            "duplicate confirmed ring merge".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use spr_client::rpc::PaginationToken;

    use super::*;
    use crate::origin::RingOrigin;

    struct History {
        pagination_token: Option<PaginationToken>,
    }

    #[async_trait::async_trait]
    impl AsyncRpc for History {
        async fn get_shielded_transactions_by_ring(
            &self,
            _options: RingHistoryOptions,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
            Ok(GetShieldedTransactionsByTagsResponse {
                context: spr_client::Context {
                    slot: 1,
                    block_time: 0,
                },
                output_tree_id: None,
                data: Vec::new(),
                pagination_token: self.pagination_token,
            })
        }
    }

    #[tokio::test]
    async fn a_terminal_history_page_ends_the_merge_scan() {
        let auditor = X25519Keypair::new();
        let audit = MergeAudit::new(Address::new_from_array([9; 32]), &auditor);
        let indexer = History {
            pagination_token: None,
        };
        let mut position = HistoryPosition::default();
        let (response, end) = audit
            .read_history_page(&indexer, &mut position)
            .await
            .unwrap();
        assert_eq!(end, PageEnd::Terminal(response.context));
    }

    #[tokio::test]
    async fn a_token_with_no_row_behind_it_fails_the_merge_scan() {
        let auditor = X25519Keypair::new();
        let audit = MergeAudit::new(Address::new_from_array([9; 32]), &auditor);
        let indexer = History {
            pagination_token: Some(PaginationToken::new(1, Signature::default())),
        };
        let mut position = HistoryPosition::default();
        assert!(matches!(
            audit.read_history_page(&indexer, &mut position).await,
            Err(AuditError::InvalidHistoryPage)
        ));
        assert_eq!(position, HistoryPosition::default());
    }

    #[tokio::test]
    async fn a_cursor_of_another_stream_is_refused_before_any_read() {
        let auditor = X25519Keypair::new();
        let ring = Address::new_from_array([9; 32]);
        let cursor = HistoryCursor {
            query: HistoryQuery {
                ring,
                stream: HistoryStream::Tags,
            },
            token: PaginationToken::new(1, Signature::default()),
        };
        let indexer = History {
            pagination_token: None,
        };
        assert!(matches!(
            MergeAudit::new(ring, &auditor)
                .with_cursor(Some(cursor))
                .page(&indexer, &UnreadOrigin)
                .await,
            Err(AuditError::HistoryCursor(_))
        ));
    }

    #[test]
    fn a_confirmed_merge_cannot_be_counted_twice_across_history_pages() {
        let mut seen = HashSet::new();
        let signature = Signature::default();
        remember_merge(&mut seen, signature, 1).unwrap();
        remember_merge(&mut seen, signature, 2).unwrap();
        assert!(matches!(
            remember_merge(&mut seen, signature, 1),
            Err(AuditError::InvalidConfirmedEvent(_))
        ));
    }

    struct UnreadOrigin;

    impl TransactionOrigin for UnreadOrigin {
        async fn origin(
            &self,
            signature: Signature,
            _event_index: u16,
            _ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            Err(AuditError::Unavailable {
                signature,
                message: "no origin read".to_owned(),
            })
        }
    }

    #[tokio::test]
    async fn a_row_of_another_ring_never_reaches_the_origin_read() {
        let ring = Address::new_from_array([9; 32]);
        let auditor = X25519Keypair::new();
        let outsider = ShieldedTransaction {
            slot: 0,
            tx_signature: Signature::default(),
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: Vec::new(),
            messages: Vec::new(),
            nullifiers: Vec::new(),
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        };
        let page = MergeAudit::new(ring, &auditor)
            .open_transactions(vec![outsider], &UnreadOrigin, &mut HashSet::new())
            .await
            .unwrap();
        assert!(page.merges.is_empty());
    }
}
