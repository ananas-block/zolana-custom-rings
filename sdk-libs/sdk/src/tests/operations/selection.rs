use std::cell::RefCell;

use serde::Deserialize;
use solana_address::Address;
use spr_transaction::{Mint, WalletUtxo};

use super::{Funding, RankedTrees, Reach, TreeSearch, Trial, PAIR_POOL_TREES};
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

fn first_choice(utxos: &[WalletUtxo], amount: u64, max_inputs: usize) -> Vec<(u16, u64)> {
    let candidates = funding(utxos, amount, max_inputs).candidates(|_| true);
    let mut picked: Vec<_> = candidates
        .first()
        .map(|candidate| &candidate.utxos[..])
        .unwrap_or_default()
        .iter()
        .map(|utxo| (utxo.tree_id, utxo.utxo.amount))
        .collect();
    picked.sort_unstable();
    picked
}

/// Every set the search funds, `funds` deciding feasibility and none pruned by reach.
fn tried_sets(trees: &[u16], pool: usize, funds: impl Fn(&[u16]) -> bool) -> Vec<Vec<u16>> {
    let tried = RefCell::new(Vec::new());
    let _: Vec<()> = TreeSearch {
        trees: &RankedTrees {
            trees: trees.to_vec(),
            pool,
        },
        reaches: |_: &[u16]| true,
        fund: |set: &[u16]| {
            tried.borrow_mut().push(set.to_vec());
            funds(set).then_some(Trial::Feasible(()))
        },
    }
    .run();
    tried.into_inner()
}

#[test]
fn one_tree_funding_tries_no_pair() {
    let tried = tried_sets(&[1, 2, 3], 3, |set| set == [2]);
    assert_eq!(tried, [vec![1], vec![2], vec![3]]);
}

#[test]
fn a_many_tree_wallet_tries_every_pair_only_when_the_pool_fails() {
    let trees: Vec<u16> = (0..20).collect();
    let pool_pairs = PAIR_POOL_TREES * (PAIR_POOL_TREES - 1) / 2;
    let in_pool = tried_sets(&trees, PAIR_POOL_TREES, |set| set == [0, 1]);
    assert_eq!(in_pool.len(), trees.len() + pool_pairs);
    let complete = tried_sets(&trees, PAIR_POOL_TREES, |_| false);
    assert_eq!(
        complete.len(),
        trees.len() + trees.len() * (trees.len() - 1) / 2
    );
}

#[test]
fn a_pair_no_reach_covers_runs_no_selection() {
    let utxos = notes((0..20).map(|tree| (tree, 1)));
    let reach = Reach::new(&utxos, 5);
    let selections = RefCell::new(0usize);
    let found: Vec<()> = TreeSearch {
        trees: &RankedTrees::new(std::slice::from_ref(&reach)),
        reaches: |set: &[u16]| reach.of(set) >= 3,
        fund: |_: &[u16]| {
            *selections.borrow_mut() += 1;
            None
        },
    }
    .run();
    assert!(found.is_empty());
    assert_eq!(selections.into_inner(), 0);
}

#[test]
fn pays_ten_from_six_on_each_of_two_trees() {
    let utxos = notes([(0, 6), (1, 6), (2, 1)]);
    assert_eq!(first_choice(&utxos, 10, 5), [(0, 6), (1, 6)]);
}

#[test]
fn a_tree_of_another_asset_stays_out_of_the_search() {
    let mut utxos = notes([(0, 6), (1, 6)]);
    utxos[1].utxo.asset = Mint::new(Address::new_from_array([9; 32]), 2);
    assert!(funding(&utxos, 10, 5).candidates(|_| true).is_empty());
}

#[test]
fn pair_selection_respects_the_shared_input_budget() {
    let utxos = notes(
        (0..8)
            .flat_map(|tree| [(tree, 40), (tree, 40)])
            .chain([(8, 60)]),
    );
    let picked = first_choice(&utxos, 100, 2);
    assert_eq!(picked.len(), 2);
    assert_eq!(picked.iter().map(|(_, amount)| amount).sum::<u64>(), 100);
    assert!(picked.iter().any(|(tree, _)| *tree == 8));
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
        let expected: Vec<_> = case
            .selected
            .iter()
            .map(|note| (note.tree, note.amount))
            .collect();
        assert_eq!(
            first_choice(&utxos, case.amount, case.max_inputs),
            expected,
            "{}",
            case.name
        );
    }
}
