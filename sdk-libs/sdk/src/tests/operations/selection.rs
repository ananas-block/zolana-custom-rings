use std::cell::RefCell;

use serde::Deserialize;
use solana_address::Address;
use spr_transaction::{Mint, WalletUtxo};

use super::{staged_tree_search, Funding, PAIR_POOL_TREES};
use crate::tests::support::{keypair, ring_utxo, wallet};

fn notes(held: impl IntoIterator<Item = (u16, u64)>) -> Vec<WalletUtxo> {
    let owner = keypair(7);
    held.into_iter()
        .zip(0..)
        .map(|((tree, amount), leaf)| {
            wallet(
                ring_utxo(&owner, Mint::SOL, amount, leaf).utxo,
                &owner.nullifier_key,
                tree,
                leaf,
            )
        })
        .collect()
}

fn funding(utxos: &[WalletUtxo], amount: u64, max_inputs: usize) -> Funding<'_> {
    Funding {
        utxos,
        asset: Mint::SOL.asset,
        amount,
        max_inputs,
    }
}

fn picked(utxos: &[WalletUtxo]) -> Vec<(u16, u64)> {
    let mut picked: Vec<_> = utxos
        .iter()
        .map(|utxo| (utxo.tree_id, utxo.utxo.amount))
        .collect();
    picked.sort_unstable();
    picked
}

#[test]
fn one_tree_funding_tries_no_pair() {
    let tried = RefCell::new(Vec::new());
    let funded = staged_tree_search(&[1, 2, 3], &[1, 2, 3], |set| {
        tried.borrow_mut().push(set.to_vec());
        (set == [2]).then_some(())
    });
    assert_eq!(funded.len(), 1);
    assert_eq!(tried.into_inner(), [vec![1], vec![2], vec![3]]);
}

#[test]
fn pays_ten_from_six_on_each_of_two_trees() {
    let utxos = notes([(0, 6), (1, 6), (2, 1)]);
    let candidates = funding(&utxos, 10, 5).candidates(|_| true);
    assert_eq!(picked(&candidates[0].utxos), [(0, 6), (1, 6)]);
}

#[test]
fn a_tree_of_another_asset_stays_out_of_the_search() {
    let mut utxos = notes([(0, 6), (1, 6)]);
    utxos[1].utxo.asset = Mint::new(Address::new_from_array([9; 32]), 2);
    assert!(funding(&utxos, 10, 5).candidates(|_| true).is_empty());
}

#[test]
fn a_many_tree_wallet_falls_back_after_the_preferred_pool() {
    let trees = 20;
    let tried = RefCell::new(0usize);
    let ids: Vec<u16> = (0..trees).collect();
    let funded = staged_tree_search(&ids, &ids[..PAIR_POOL_TREES], |_| {
        *tried.borrow_mut() += 1;
        None::<()>
    });
    assert!(funded.is_empty());
    let pairs = PAIR_POOL_TREES * (PAIR_POOL_TREES - 1) / 2;
    assert_eq!(
        tried.into_inner(),
        usize::from(trees) + usize::from(trees * (trees - 1) / 2)
    );

    // Equal reach ranks by tree id, every pair sits within the first pool trees.
    let utxos = notes(ids.iter().map(|tree| (*tree, 1)));
    let candidates = funding(&utxos, 2, 5).candidates(|_| true);
    assert_eq!(candidates.len(), pairs);
    assert!(candidates
        .iter()
        .flat_map(|candidate| &candidate.utxos)
        .all(|utxo| usize::from(utxo.tree_id) < PAIR_POOL_TREES));
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    amount: u64,
    max_inputs: usize,
    notes: Vec<Note>,
    selected: Vec<Note>,
}

#[derive(Deserialize)]
struct Note {
    tree: u16,
    amount: u64,
}

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

/// TS `selectAcrossTrees` pins the same file.
#[test]
fn matches_the_shared_tree_selection_vector() {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../../../../test-vectors/wallet/tree-selection.json"
    ))
    .unwrap();
    for case in vectors.cases {
        let utxos = notes(case.notes.iter().map(|note| (note.tree, note.amount)));
        let candidates = funding(&utxos, case.amount, case.max_inputs).candidates(|_| true);
        let expected: Vec<_> = case
            .selected
            .iter()
            .map(|note| (note.tree, note.amount))
            .collect();
        assert_eq!(picked(&candidates[0].utxos), expected, "{}", case.name);
    }
}

#[test]
fn pair_selection_respects_the_shared_input_budget() {
    let utxos = notes(
        (0..8)
            .flat_map(|tree| [(tree, 40), (tree, 40)])
            .chain([(8, 60)]),
    );
    let candidates = funding(&utxos, 100, 2).candidates(|_| true);
    assert_eq!(candidates[0].utxos.len(), 2);
    assert_eq!(
        candidates[0]
            .utxos
            .iter()
            .map(|note| note.utxo.amount)
            .sum::<u64>(),
        100
    );
    assert!(candidates[0].utxos.iter().any(|note| note.tree_id == 8));
}
