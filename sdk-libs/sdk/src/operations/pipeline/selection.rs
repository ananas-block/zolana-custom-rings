//! The fewest UTXOs over the fewest input trees whose framed transfer fits one transaction.

use std::collections::BTreeSet;

use solana_address::Address;
use spr_client::{AsyncRpc, Shape, SPP_SUPPORTED_SHAPES};
use spr_interface::{MAX_INPUT_TREES, ZERO_NULLIFIER_PUBKEY};
use spr_transaction::{TransactionError, WalletUtxo};

use super::{Rail, RingTransfer};
use crate::client::{RingClient, RingIndexerBackend};
use crate::{projection::retry_projection_lag, select::select_spend_where, RingError};

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

/// Every set of up to [`MAX_INPUT_TREES`] trees the UTXOs sit on, ascending within a set.
pub(super) fn tree_sets(utxos: &[WalletUtxo]) -> Vec<Vec<u16>> {
    let trees: Vec<u16> = utxos
        .iter()
        .map(|utxo| utxo.tree_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut sets = Vec::new();
    let mut frontier: Vec<Vec<u16>> = vec![Vec::new()];
    for _ in 0..MAX_INPUT_TREES {
        // A set grows only by a later tree, no set repeats in another order.
        frontier = frontier
            .iter()
            .flat_map(|set| {
                trees
                    .iter()
                    .filter(|tree| set.last().is_none_or(|last| *tree > last))
                    .map(|tree| [set.as_slice(), &[*tree]].concat())
            })
            .collect();
        sets.extend(frontier.iter().cloned());
    }
    sets
}

/// The trees `utxos` span, a selection over a wider set that spans fewer repeats a narrower one.
pub(super) fn spanned_trees<'u>(utxos: impl IntoIterator<Item = &'u WalletUtxo>) -> usize {
    utxos
        .into_iter()
        .map(|utxo| utxo.tree_id)
        .collect::<BTreeSet<_>>()
        .len()
}

impl Funding<'_> {
    /// One per tree set, one tree before two, then the fewest UTXOs, then the least change.
    pub fn candidates(&self, keep: impl Fn(&WalletUtxo) -> bool) -> Vec<Candidate> {
        let mut ranked: Vec<_> = tree_sets(self.utxos)
            .into_iter()
            .filter_map(|trees| {
                let utxos = select_spend_where(
                    self.utxos,
                    self.asset,
                    self.amount,
                    self.max_inputs,
                    |utxo| trees.contains(&utxo.tree_id) && keep(utxo),
                )
                .ok()
                .filter(|utxos| spanned_trees(utxos) == trees.len())?;
                let total: u128 = utxos.iter().map(|utxo| u128::from(utxo.utxo.amount)).sum();
                let change = total > u128::from(self.amount);
                Some((
                    (trees.len(), utxos.len(), total, trees),
                    Candidate { utxos, change },
                ))
            })
            .collect();
        ranked.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        ranked.into_iter().map(|(_, candidate)| candidate).collect()
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
