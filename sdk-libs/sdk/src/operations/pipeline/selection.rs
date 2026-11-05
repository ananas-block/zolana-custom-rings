//! The fewest UTXOs over the fewest input trees whose framed transfer fits one transaction.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
};

use solana_address::Address;
use spr_client::{AsyncRpc, Shape, SPP_SUPPORTED_SHAPES};
use spr_interface::{MAX_INPUT_TREES, ZERO_NULLIFIER_PUBKEY};
use spr_transaction::{TransactionError, WalletUtxo};

use super::{Rail, RingTransfer};
use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    projection::retry_projection_lag,
    select::{candidates, select_exact_where, select_spend_where, SpendableKeys},
    RingError,
};

pub(super) struct Funding<'u> {
    pub utxos: &'u [WalletUtxo],
    pub asset: Address,
    pub amount: u64,
    pub max_inputs: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Candidate {
    pub utxos: Vec<WalletUtxo>,
    pub change: bool,
}

/// The payments' total, refused when zero or past a u64.
pub(super) fn payment_total(amounts: impl IntoIterator<Item = u64>) -> Result<u64, RingError> {
    match amounts
        .into_iter()
        .try_fold(0u64, u64::checked_add)
        .ok_or(RingError::PaymentOverflow)?
    {
        0 => Err(TransactionError::ZeroSpendAmount.into()),
        total => Ok(total),
    }
}

/// The most inputs a keyed shape takes beside `payments` outputs.
pub(super) fn widest(payments: usize, keyed: impl Fn(Shape) -> bool) -> Option<usize> {
    SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| shape.n_outputs() >= payments && keyed(*shape))
        .map(|shape| shape.n_inputs())
        .max()
}

/// The trees `utxos` span, a selection over a wider set that spans fewer repeats a narrower one.
pub(super) fn spanned_trees<'u>(utxos: impl IntoIterator<Item = &'u WalletUtxo>) -> usize {
    utxos
        .into_iter()
        .map(|utxo| utxo.tree_id)
        .collect::<BTreeSet<_>>()
        .len()
}

/// The most trees a pair search draws from, the best by reach.
pub(super) const PAIR_POOL_TREES: usize = 8;

// The staged search tries singles then pairs, a third input tree would need a third stage.
const _: () = assert!(MAX_INPUT_TREES == 2);

/// Each tree alone, then only when none funds, each pair within `pool`.
pub(super) fn staged_tree_search<T>(
    trees: &[u16],
    pool: &[u16],
    mut fund: impl FnMut(&[u16]) -> Option<T>,
) -> Vec<T> {
    let singles: Vec<T> = trees.iter().filter_map(|tree| fund(&[*tree])).collect();
    if !singles.is_empty() {
        return singles;
    }
    pool.iter()
        .enumerate()
        .flat_map(|(at, first)| pool[at + 1..].iter().map(move |second| [*first, *second]))
        .filter_map(|mut pair| {
            pair.sort_unstable();
            fund(&pair)
        })
        .collect()
}

impl<'u> Funding<'u> {
    /// The fewest UTXOs on one tree, two trees only when no tree alone funds, then the least change.
    pub fn candidates(&self, keep: impl Fn(&WalletUtxo) -> bool) -> Vec<Candidate> {
        self.covers(&self.by_tree(keep))
    }

    /// Exact funding per tree ahead of [`Self::candidates`], the change of a default-ring spend enters the ring.
    pub fn exact_first(&self, keep: impl Fn(&WalletUtxo) -> bool) -> Vec<Candidate> {
        let by_tree = self.by_tree(keep);
        let mut ranked: Vec<Candidate> = by_tree
            .values()
            .filter_map(|notes| {
                select_exact_where(
                    notes.iter().copied(),
                    self.asset,
                    self.amount,
                    self.max_inputs,
                    |_| true,
                )
            })
            .map(|utxos| Candidate {
                utxos,
                change: false,
            })
            .collect();
        ranked.sort_by_key(|candidate| candidate.utxos.len());
        let covers: Vec<Candidate> = self
            .covers(&by_tree)
            .into_iter()
            .filter(|cover| !ranked.contains(cover))
            .collect();
        ranked.extend(covers);
        ranked
    }

    /// Only a size or key refusal moves on to the next attempt.
    pub async fn first_fit<R: Rail, P: AsyncRpc, I: RingIndexerBackend>(
        &self,
        attempts: Vec<Result<RingTransfer<R>, RingError>>,
        client: &RingClient<P, I>,
    ) -> Result<RingTransfer<R>, RingError> {
        let mut first_refusal = None;
        for attempt in attempts {
            let refusal = match attempt {
                Ok(transfer) => match retry_projection_lag(|| transfer.measure(client)).await {
                    Ok(()) => return Ok(transfer),
                    Err(error) => error,
                },
                Err(error) => error,
            };
            match refusal {
                RingError::TransferTooWide { .. }
                | RingError::TooManyAddresses { .. }
                | RingError::ShapeUnkeyed { .. }
                | RingError::DefaultRingSpendTooWide { .. } => {
                    first_refusal.get_or_insert(refusal);
                }
                error => return Err(error),
            }
        }
        Err(first_refusal.unwrap_or_else(|| self.unfunded()))
    }

    /// The keyed notes of the asset `keep` admits, by tree.
    fn by_tree(&self, keep: impl Fn(&WalletUtxo) -> bool) -> BTreeMap<u16, Vec<&'u WalletUtxo>> {
        let mut by_tree: BTreeMap<u16, Vec<&'u WalletUtxo>> = BTreeMap::new();
        for utxo in candidates(self.utxos, self.asset, SpendableKeys::Keyed, keep) {
            by_tree.entry(utxo.tree_id).or_default().push(utxo);
        }
        by_tree
    }

    /// One per funding tree set from [`staged_tree_search`], ranked by UTXO count, total, then tree ids.
    fn covers(&self, by_tree: &BTreeMap<u16, Vec<&'u WalletUtxo>>) -> Vec<Candidate> {
        // 1. Rank trees by the value their largest notes hold within the input budget.
        //    The sort is stable, an equal reach keeps the lower tree id first.
        let mut ranked: Vec<_> = by_tree.iter().collect();
        ranked.sort_by_cached_key(|(_, notes)| {
            let mut amounts: Vec<u64> = notes.iter().map(|utxo| utxo.utxo.amount).collect();
            amounts.sort_unstable_by_key(|amount| Reverse(*amount));
            Reverse(
                amounts
                    .into_iter()
                    .take(self.max_inputs)
                    .map(u128::from)
                    .sum::<u128>(),
            )
        });
        let trees: Vec<u16> = ranked.into_iter().map(|(tree, _)| *tree).collect();
        let pool = &trees[..trees.len().min(PAIR_POOL_TREES)];
        // 2. A pair runs only when no tree alone funds, its picks always span both trees.
        let mut funded = staged_tree_search(&trees, pool, |set| {
            let utxos = select_spend_where(
                set.iter()
                    .filter_map(|tree| by_tree.get(tree))
                    .flatten()
                    .copied(),
                self.asset,
                self.amount,
                self.max_inputs,
                |_| true,
            )
            .ok()?;
            let total: u128 = utxos.iter().map(|utxo| u128::from(utxo.utxo.amount)).sum();
            let change = total > u128::from(self.amount);
            Some((
                (utxos.len(), total, set.to_vec()),
                Candidate { utxos, change },
            ))
        });
        funded.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        funded.into_iter().map(|(_, candidate)| candidate).collect()
    }

    /// Names the zero-key funds only a public spend reaches.
    fn unfunded(&self) -> RingError {
        let exposed_if_spent = self
            .utxos
            .iter()
            .filter(|utxo| {
                utxo.utxo.asset.asset == self.asset
                    && utxo.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY
            })
            .fold(0u64, |sum, utxo| sum.saturating_add(utxo.utxo.amount));
        match exposed_if_spent {
            0 => RingError::Unfunded {
                mint: self.asset,
                amount: self.amount,
                max_inputs: self.max_inputs,
            },
            exposed_if_spent => RingError::UnfundedPastExposure {
                mint: self.asset,
                amount: self.amount,
                exposed_if_spent,
            },
        }
    }
}

impl Candidate {
    /// The cheapest keyed shape holding the inputs, `payments` and any change.
    pub fn shape(&self, payments: usize, keyed: impl Fn(Shape) -> bool) -> Option<Shape> {
        let outputs = payments + usize::from(self.change);
        SPP_SUPPORTED_SHAPES.into_iter().find(|shape| {
            shape.n_inputs() >= self.utxos.len() && shape.n_outputs() >= outputs && keyed(*shape)
        })
    }
}

#[cfg(test)]
#[path = "../../tests/operations/selection.rs"]
mod tests;
