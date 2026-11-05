//! Exact-tag reads of the indexer, an output nobody can decrypt still occupies its tag.

use std::{collections::HashMap, future::Future};

use solana_address::Address;
use spr_keypair::viewing_key::ViewTag;

use spr_client::{
    rpc::{EncryptedUtxoMatch, HistoryFilters, Page, PaginationToken},
    AsyncRpc, ClientError, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig,
    RingHistoryOptions, ShieldedTransaction,
};
use spr_indexer_api::Positioned;

use crate::history::{HistoryPosition, PageEnd};

const PAGE_LIMIT: u32 = spr_indexer_api::PAGE_LIMIT as u32;

/// Photon's refusal of a response above its size limit, as `ClientError::Indexer` prints it.
const RESPONSE_TOO_LARGE: &str = "code=Some(-32008)";

/// The indexer's cap on the tags or nullifiers one request names.
pub const TAGS_PER_REQUEST: usize = spr_indexer_api::PAGE_LIMIT as usize;

/// Rows of one history read and where the next read of the same query resumes.
#[derive(Clone, Debug)]
pub struct HistoryRows<T> {
    pub rows: Vec<T>,
    /// After the lowest chunk's terminal slot, a row above it may come back again.
    pub next: HistoryPosition,
}

#[derive(Clone, Debug)]
pub struct TagWindow<K = u64> {
    by_tag: HashMap<ViewTag, K>,
}

impl TagWindow {
    /// `tags` in index order from `start`.
    pub fn new(start: u64, tags: impl IntoIterator<Item = ViewTag>) -> Self {
        Self::indexed((start..).zip(tags))
    }
}

impl<K: Copy> TagWindow<K> {
    pub fn indexed(tags: impl IntoIterator<Item = (K, ViewTag)>) -> Self {
        Self {
            by_tag: tags.into_iter().map(|(index, tag)| (tag, index)).collect(),
        }
    }

    pub fn tags(&self) -> Vec<ViewTag> {
        self.by_tag.keys().copied().collect()
    }

    pub fn index_of(&self, tag: &ViewTag) -> Option<K> {
        self.by_tag.get(tag).copied()
    }
}

/// Exact-tag and spend reads.
#[must_use]
pub struct IndexerReads<'a, I: ?Sized> {
    indexer: &'a I,
    config: Option<IndexerRpcConfig>,
    /// Halved in place while a ring page is too large, the rest of the read asks for less.
    ring_page_limit: u32,
}

impl<'a, I: AsyncRpc + ?Sized> IndexerReads<'a, I> {
    pub fn new(indexer: &'a I) -> Self {
        Self::configured(indexer, None)
    }

    pub fn with_indexer_config(self, config: IndexerRpcConfig) -> Self {
        Self {
            config: Some(config),
            ..self
        }
    }

    pub(crate) fn configured(indexer: &'a I, config: Option<IndexerRpcConfig>) -> Self {
        Self {
            indexer,
            config,
            ring_page_limit: PAGE_LIMIT,
        }
    }

    /// The next page of `ring` and the limit it was asked at, a refused limit loses no row.
    pub(crate) async fn ring_page(
        &mut self,
        ring: Address,
        position: &HistoryPosition,
    ) -> Result<(GetShieldedTransactionsByTagsResponse, u32), ClientError> {
        loop {
            let limit = self.ring_page_limit;
            match self
                .indexer
                .get_shielded_transactions_by_ring(
                    RingHistoryOptions {
                        ring_program_id: ring,
                        pagination_token: position.token(),
                        limit: Some(limit),
                        filters: position.filters(),
                    },
                    self.config,
                )
                .await
            {
                Ok(page) => {
                    return Ok((page, limit));
                }
                Err(ClientError::Indexer(message))
                    if limit > 1 && message.contains(RESPONSE_TOO_LARGE) =>
                {
                    self.ring_page_limit = limit / 2;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// The deposits published under one of `tags`, one transaction per deposited output.
    pub async fn deposits(
        &mut self,
        tags: &[ViewTag],
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        let (indexer, config) = (self.indexer, self.config);
        let matches = self
            .paged(
                tags,
                HistoryPosition::default(),
                |tags, token, filters| async move {
                    indexer
                        .get_encrypted_utxos_by_tags(tags, token, Some(PAGE_LIMIT), filters, config)
                        .await
                },
            )
            .await?;
        Ok(matches
            .rows
            .into_iter()
            .flat_map(|item| item.outputs)
            .filter_map(EncryptedUtxoMatch::into_proofless_transaction)
            .collect())
    }

    /// The transfers above `from` publishing a slot under one of `tags`.
    pub async fn tagged(
        &mut self,
        tags: &[ViewTag],
        from: HistoryPosition,
    ) -> Result<HistoryRows<ShieldedTransaction>, ClientError> {
        let (indexer, config) = (self.indexer, self.config);
        let transactions = self
            .paged(tags, from, |tags, token, filters| async move {
                indexer
                    .get_shielded_transactions_by_tags(
                        tags,
                        token,
                        Some(PAGE_LIMIT),
                        filters,
                        config,
                    )
                    .await
            })
            .await?;
        Ok(HistoryRows {
            rows: transactions
                .rows
                .into_iter()
                .flat_map(|item| item.events)
                .collect(),
            next: transactions.next,
        })
    }

    pub async fn spends(
        &mut self,
        nullifiers: &[[u8; 32]],
    ) -> Result<Vec<ShieldedTransaction>, ClientError> {
        let (indexer, config) = (self.indexer, self.config);
        let transactions = self
            .paged(
                nullifiers,
                HistoryPosition::default(),
                |nullifiers, token, filters| async move {
                    indexer
                        .get_shielded_transactions_by_nullifiers(
                            nullifiers,
                            token,
                            Some(PAGE_LIMIT),
                            filters,
                            config,
                        )
                        .await
                },
            )
            .await?;
        Ok(transactions
            .rows
            .into_iter()
            .flat_map(|item| item.events)
            .collect())
    }

    /// Each chunk reads from `from` to a terminal page, `from` comes back unchanged with no chunk.
    async fn paged<T, F, Fut>(
        &mut self,
        queried: &[[u8; 32]],
        from: HistoryPosition,
        fetch: F,
    ) -> Result<HistoryRows<T>, ClientError>
    where
        T: Positioned,
        F: Fn(Vec<[u8; 32]>, Option<PaginationToken>, HistoryFilters) -> Fut,
        Fut: Future<Output = Result<Page<T>, ClientError>>,
    {
        let mut rows = Vec::new();
        let mut covered: Option<u64> = None;
        for chunk in queried.chunks(TAGS_PER_REQUEST) {
            let mut position = from;
            loop {
                let page = fetch(chunk.to_vec(), position.token(), position.filters()).await?;
                let end = position
                    .advance(&page, PAGE_LIMIT)
                    .map_err(|_| ClientError::IndexerCursorNotAdvanced)?;
                rows.extend(page.data);
                if let PageEnd::Terminal(context) = end {
                    covered = Some(covered.map_or(context.slot, |slot| slot.min(context.slot)));
                    break;
                }
            }
        }
        Ok(HistoryRows {
            rows,
            next: covered.map_or(from, HistoryPosition::after_slot),
        })
    }
}
