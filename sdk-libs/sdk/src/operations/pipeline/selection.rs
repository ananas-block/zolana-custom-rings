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

/// Preferred trees per mint, their pairs run ahead of the complete pair search.
pub(super) const PAIR_POOL_TREES: usize = 8;

// The search tries singles then pairs, a third input tree would need a third stage.
const _: () = assert!(MAX_INPUT_TREES == 2);

/// Per tree, the sum of its largest notes at each count up to the input budget.
pub(super) struct Reach {
    budget: usize,
    prefixes: BTreeMap<u16, Vec<u128>>,
}

impl Reach {
    pub fn new<'u>(notes: impl IntoIterator<Item = &'u WalletUtxo>, budget: usize) -> Self {
        let mut amounts: BTreeMap<u16, Vec<u64>> = BTreeMap::new();
        for note in notes {
            amounts
                .entry(note.tree_id)
                .or_default()
                .push(note.utxo.amount);
        }
        let prefixes = amounts
            .into_iter()
            .map(|(tree, mut amounts)| {
                amounts.sort_unstable_by_key(|amount| Reverse(*amount));
                let sums = amounts.into_iter().take(budget).scan(0u128, |sum, amount| {
                    *sum += u128::from(amount);
                    Some(*sum)
                });
                (tree, std::iter::once(0).chain(sums).collect())
            })
            .collect();
        Self { budget, prefixes }
    }

    /// The most a largest first pick of at most `budget` notes takes from `set`.
    pub fn of(&self, set: &[u16]) -> u128 {
        let largest = |tree: &u16, count: usize| {
            self.prefixes
                .get(tree)
                .and_then(|sums| sums.get(count.min(sums.len() - 1)))
                .copied()
                .unwrap_or_default()
        };
        match set {
            [tree] => largest(tree, self.budget),
            // The union's largest notes split between the trees at one count.
            [left, right] => (0..=self.budget)
                .map(|count| largest(left, count) + largest(right, self.budget - count))
                .max()
                .unwrap_or_default(),
            _ => 0,
        }
    }

    /// Whether any tree or pair reaches `amount`.
    pub fn reaches_anywhere(&self, amount: u64) -> bool {
        let trees: Vec<u16> = self.prefixes.keys().copied().collect();
        let reaches = |set: &[u16]| self.of(set) >= u128::from(amount);
        trees.iter().any(|tree| reaches(&[*tree])) || pairs(&trees).any(|pair| reaches(&pair))
    }

    /// The trees holding the mint, the greatest reach first, an equal reach by lower tree id.
    fn ranked(&self) -> Vec<u16> {
        let mut trees: Vec<u16> = self.prefixes.keys().copied().collect();
        trees.sort_by_cached_key(|tree| Reverse(self.of(&[*tree])));
        trees
    }
}

/// Trees holding a spend's mints, each mint's [`PAIR_POOL_TREES`] best leading as the pool.
pub(super) struct RankedTrees {
    trees: Vec<u16>,
    pool: usize,
}

impl RankedTrees {
    pub fn new(reaches: &[Reach]) -> Self {
        let ranked: Vec<Vec<u16>> = reaches.iter().map(Reach::ranked).collect();
        let preferred = || {
            ranked
                .iter()
                .flat_map(|trees| trees.iter().take(PAIR_POOL_TREES))
        };
        let pool = distinct(preferred()).len();
        let trees = distinct(preferred().chain(ranked.iter().flatten()));
        Self { trees, pool }
    }
}

/// A funding tree set, infeasible when no keyed shape holds its inputs and outputs.
pub(super) enum Trial<T> {
    Feasible(T),
    Infeasible(T),
}

/// Singles, pool pairs, then the other pairs, a stage with a feasible set ends the search.
#[must_use = "run the search"]
pub(super) struct TreeSearch<'t, R, F> {
    pub trees: &'t RankedTrees,
    pub reaches: R,
    pub fund: F,
}

impl<R: Fn(&[u16]) -> bool, F> TreeSearch<'_, R, F> {
    pub fn run<T>(mut self) -> Vec<T>
    where
        F: FnMut(&[u16]) -> Option<Trial<T>>,
    {
        let trees = &self.trees.trees;
        let pool = &trees[..self.trees.pool];
        let mut infeasible = Vec::new();
        let singles = self.stage(trees.iter().map(|tree| [*tree]), &mut infeasible);
        if !singles.is_empty() {
            return singles;
        }
        let preferred = self.stage(pairs(pool), &mut infeasible);
        if !preferred.is_empty() {
            return preferred;
        }
        // Complete over every pair of T trees, a reach check prunes each pair before any selection.
        let rest = self.stage(
            pairs(trees).filter(|pair| !pair.iter().all(|tree| pool.contains(tree))),
            &mut infeasible,
        );
        if !rest.is_empty() {
            return rest;
        }
        infeasible
    }

    fn stage<T, S: AsRef<[u16]>>(
        &mut self,
        sets: impl IntoIterator<Item = S>,
        infeasible: &mut Vec<T>,
    ) -> Vec<T>
    where
        F: FnMut(&[u16]) -> Option<Trial<T>>,
    {
        let mut feasible = Vec::new();
        for set in sets {
            let set = set.as_ref();
            if !(self.reaches)(set) {
                continue;
            }
            match (self.fund)(set) {
                Some(Trial::Feasible(found)) => feasible.push(found),
                Some(Trial::Infeasible(found)) => infeasible.push(found),
                None => {}
            }
        }
        feasible
    }
}

fn distinct<'t>(trees: impl IntoIterator<Item = &'t u16>) -> Vec<u16> {
    let mut distinct = Vec::new();
    for tree in trees {
        if !distinct.contains(tree) {
            distinct.push(*tree);
        }
    }
    distinct
}

/// Every pair of `trees`, ascending within a pair.
fn pairs(trees: &[u16]) -> impl Iterator<Item = [u16; 2]> + '_ {
    trees.iter().enumerate().flat_map(move |(at, first)| {
        trees[at + 1..].iter().map(move |second| {
            let mut pair = [*first, *second];
            pair.sort_unstable();
            pair
        })
    })
}

impl<'u> Funding<'u> {
    /// The fewest UTXOs on one tree, two trees only when no tree alone fits, then the least change.
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

    /// One per funding tree set from [`TreeSearch`], ranked by UTXO count, total, then tree ids.
    fn covers(&self, by_tree: &BTreeMap<u16, Vec<&'u WalletUtxo>>) -> Vec<Candidate> {
        let reach = Reach::new(by_tree.values().flatten().copied(), self.max_inputs);
        let mut funded = TreeSearch {
            trees: &RankedTrees::new(std::slice::from_ref(&reach)),
            reaches: |set: &[u16]| reach.of(set) >= u128::from(self.amount),
            fund: |set: &[u16]| {
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
                .ok()
                // Picks on one tree repeat that tree's own trial.
                .filter(|utxos| spanned_trees(utxos) == set.len())?;
                let total: u128 = utxos.iter().map(|utxo| u128::from(utxo.utxo.amount)).sum();
                let candidate = Candidate {
                    utxos,
                    change: total > u128::from(self.amount),
                };
                // `max_inputs` is a keyed width, every funded set has its shape.
                Some(Trial::Feasible((
                    (candidate.utxos.len(), total, set.to_vec()),
                    candidate,
                )))
            },
        }
        .run();
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
