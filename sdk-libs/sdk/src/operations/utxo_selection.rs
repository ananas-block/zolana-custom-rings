//! UTXO selection over the UTXOs a caller's predicate admits.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashSet},
};

use solana_address::Address;
use spr_interface::{MAX_INPUT_TREES, ZERO_NULLIFIER_PUBKEY};
use spr_transaction::{instructions::merge::MAX_MERGE_INPUTS, TransactionError, WalletUtxo};

/// The nullifier key classes a selection may spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpendableKeys {
    /// A wallet's own spend, a zero-key note publishes its owner so only a named public spend takes one.
    Keyed,
    /// A delegate moves both classes under one authority, the proof takes each note's secret by its nullifier.
    Any,
}

impl SpendableKeys {
    fn admits(self, utxo: &WalletUtxo) -> bool {
        self == Self::Any || utxo.nullifier_pubkey != ZERO_NULLIFIER_PUBKEY
    }
}

/// The largest UTXOs of an asset until they cover `amount`, at most `max_inputs`.
#[must_use = "select the UTXOs"]
pub(crate) struct SpendSelection<'a> {
    pub utxos: &'a [WalletUtxo],
    pub asset: Address,
    pub amount: u64,
    pub max_inputs: usize,
    pub keys: SpendableKeys,
}

impl SpendSelection<'_> {
    pub fn select_where(
        self,
        keep: impl Fn(&WalletUtxo) -> bool,
    ) -> Result<Vec<WalletUtxo>, TransactionError> {
        let admitted = candidates(self.utxos, self.asset, self.keys, keep);
        select(admitted, self.asset, self.amount, self.max_inputs)
    }
}

/// The largest keyed UTXOs `keep` admits until they cover `amount`, at most `max_inputs`.
pub fn select_spend_where<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    amount: u64,
    max_inputs: usize,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let admitted = candidates(utxos, asset, SpendableKeys::Keyed, keep);
    select(admitted, asset, amount, max_inputs)
}

/// One largest first pass over the keyed UTXOs no larger than the remainder, a full subset sum search is out of scope.
pub(crate) fn select_exact_where<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    amount: u64,
    max_inputs: usize,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Option<Vec<WalletUtxo>> {
    let mut admitted = candidates(utxos, asset, SpendableKeys::Keyed, keep);
    admitted.sort_by_key(|utxo| Reverse(utxo.utxo.amount));
    let mut remainder = amount;
    let mut selected = Vec::new();
    for utxo in admitted {
        if remainder == 0 || selected.len() == max_inputs {
            break;
        }
        if let Some(rest) = remainder.checked_sub(utxo.utxo.amount) {
            remainder = rest;
            selected.push(utxo.clone());
        }
    }
    (amount > 0 && remainder == 0).then_some(selected)
}

/// The smallest keyed UTXOs `keep` admits on the tree holding most of them, at most `max_inputs` up to [`MAX_MERGE_INPUTS`].
pub fn select_merge_where<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    max_inputs: usize,
    excluded: &HashSet<[u8; 32]>,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    let mut trees: BTreeMap<u16, Vec<&WalletUtxo>> = BTreeMap::new();
    let admitted = candidates(utxos, asset, SpendableKeys::Keyed, keep);
    for utxo in admitted
        .into_iter()
        .filter(|utxo| !excluded.contains(&utxo.nullifier))
    {
        trees.entry(utxo.tree_id()).or_default().push(utxo);
    }
    // The lowest tree id wins a tie, so the choice does not depend on order.
    let mut selected = trees
        .into_values()
        .rev()
        .max_by_key(Vec::len)
        .unwrap_or_default();
    selected.sort_by_key(|utxo| utxo.utxo.amount);
    selected.truncate(max_inputs.min(MAX_MERGE_INPUTS));
    if selected.len() < 2 {
        return Err(TransactionError::NothingToMerge { asset });
    }
    Ok(selected.into_iter().cloned().collect())
}

/// The nonzero UTXOs of `asset` the key class and `keep` admit.
pub(crate) fn candidates<'a>(
    utxos: impl IntoIterator<Item = &'a WalletUtxo>,
    asset: Address,
    keys: SpendableKeys,
    keep: impl Fn(&WalletUtxo) -> bool,
) -> Vec<&'a WalletUtxo> {
    utxos
        .into_iter()
        .filter(|utxo| {
            utxo.utxo.asset.asset == asset
                && utxo.utxo.amount > 0
                && keys.admits(utxo)
                && keep(utxo)
        })
        .collect()
}

fn select(
    mut utxos: Vec<&WalletUtxo>,
    asset: Address,
    amount: u64,
    max_inputs: usize,
) -> Result<Vec<WalletUtxo>, TransactionError> {
    if amount == 0 {
        return Err(TransactionError::ZeroSpendAmount);
    }
    if utxos.is_empty() {
        return Err(TransactionError::NoSpendableBalance { asset });
    }
    let available = utxos
        .iter()
        .try_fold(0u64, |total, utxo| total.checked_add(utxo.utxo.amount))
        .ok_or(TransactionError::SelectedBalanceOverflow)?;
    if available < amount {
        return Err(TransactionError::InsufficientBalance {
            requested: amount,
            available,
        });
    }
    utxos.sort_by_key(|utxo| Reverse(utxo.utxo.amount));
    let mut selected = Vec::new();
    let mut covered = 0u64;
    for utxo in utxos.into_iter().take(max_inputs) {
        // At most `available`, which did not overflow.
        covered += utxo.utxo.amount;
        selected.push(utxo.clone());
        if covered >= amount {
            let mut trees: Vec<u16> = selected.iter().map(WalletUtxo::tree_id).collect();
            trees.sort_unstable();
            trees.dedup();
            if trees.len() > MAX_INPUT_TREES {
                return Err(TransactionError::TooManyInputTrees {
                    got: trees.len(),
                    max: MAX_INPUT_TREES,
                });
            }
            return Ok(selected);
        }
    }
    Err(TransactionError::SpendNeedsMerge { amount, max_inputs })
}
