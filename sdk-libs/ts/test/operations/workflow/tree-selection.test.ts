import { ShieldedKeypair, SigningKey } from "@heliuslabs/zolana/keypair";
import { treeAddress } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";
import { AssetRegistry, Data, SOL_MINT, Utxo, Wallet } from "@heliuslabs/zolana/transaction";
import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vectors from "../../../../../test-vectors/wallet/tree-selection.json" with { type: "json" };
import { selectAuthorityNotes } from "../../../src/operations/management/delegate.js";
import { anonymousInputCap, selectRingInputs } from "../../../src/operations/payments/transfer.js";
import {
  PAIR_POOL_TREES,
  ringSelectionErrors,
  selectAcrossTrees,
  TreeReach,
  rankedTrees,
  treeSearch,
} from "../../../src/operations/workflow/selection.js";

const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

type Note = readonly [tree: number, amount: bigint, asset?: Address];

const MINT = address("Mint111111111111111111111111111111111111111");

function walletOf(notes: readonly Note[], ringProgramId?: Address): Wallet {
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry([[2n, MINT]]),
  });
  wallet._replace({
    utxos: notes.map(([tree, amount, asset = SOL_MINT], index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset,
        amount,
        blinding: filled((index % 250) + 1),
        data: new Data(),
        ...(ringProgramId === undefined ? {} : { ringProgramId }),
      }),
      outputContext: {
        hash: new Uint8Array(32)
          .fill(index % 250)
          .map((byte, at) => (at === 0 ? index >> 8 : byte)) as Bytes32,
        tree: treeAddress(tree),
        leafIndex: BigInt(index),
      },
      nullifier: new Uint8Array(32)
        .fill(index % 250)
        .map((byte, at) => (at === 1 ? 7 : byte)) as Bytes32,
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function sortedByTree(
  entries: readonly { outputContext: { tree: Address }; utxo: { amount: bigint } }[],
) {
  return entries
    .map((entry) => [entry.outputContext.tree, entry.utxo.amount] as const)
    .sort(([left, leftAmount], [right, rightAmount]) =>
      left === right ? Number(rightAmount - leftAmount) : left.localeCompare(right),
    );
}

/** Each picked note as its tree and amount, sorted by tree address. */
function picked(notes: readonly Note[], amount: bigint, maxInputs: number) {
  return sortedByTree(
    selectAcrossTrees({
      wallet: walletOf(notes),
      covers: [{ asset: SOL_MINT, amount }],
      policy: {
        eligible: () => true,
        ordering: "largestFirst",
        maxInputs,
        errors: ringSelectionErrors,
      },
    }),
  );
}

function expected(notes: readonly Note[]) {
  return sortedByTree(
    notes.map(([tree, amount]) => ({
      outputContext: { tree: treeAddress(tree) },
      utxo: { amount },
    })),
  );
}

/** Every set the search funds, `funds` deciding feasibility and none pruned by reach. */
function triedSets(
  trees: readonly Address[],
  pool: readonly Address[],
  funds: (set: readonly Address[]) => boolean,
) {
  const tried: (readonly Address[])[] = [];
  treeSearch({
    trees,
    pool,
    maxTrees: 2,
    reaches: () => true,
    fund: (set) => {
      tried.push(set);
      return funds(set) ? { found: set, feasible: true } : undefined;
    },
  });
  return tried;
}

describe("selectAcrossTrees", () => {
  it("tries no pair when one tree funds", () => {
    const trees = [treeAddress(1), treeAddress(2), treeAddress(3)];
    const tried = triedSets(trees, trees, (set) => set.length === 1 && set[0] === trees[1]);
    expect(tried).toEqual(trees.map((tree) => [tree]));
  });

  it("tries every pair of a many-tree wallet only when the pool fails", () => {
    const trees = Array.from({ length: 20 }, (_, id) => treeAddress(id));
    const pool = trees.slice(0, PAIR_POOL_TREES);
    const poolPairs = (PAIR_POOL_TREES * (PAIR_POOL_TREES - 1)) / 2;
    const first = [trees[0], trees[1]];
    const inPool = triedSets(
      trees,
      pool,
      (set) => set.length === 2 && set.every((tree, at) => tree === first[at]),
    );
    expect(inPool).toHaveLength(trees.length + poolPairs);
    expect(triedSets(trees, pool, () => false)).toHaveLength(
      trees.length + (trees.length * (trees.length - 1)) / 2,
    );
  });

  it("runs no selection on a pair no reach covers", () => {
    const wallet = walletOf(Array.from({ length: 20 }, (_, tree) => [tree, 1n] as const));
    const reach = new TreeReach(wallet.utxos(), 5);
    let selections = 0;
    const found = treeSearch({
      ...rankedTrees([reach]),
      maxTrees: 2,
      reaches: (set) => reach.of(set) >= 3n,
      fund: () => {
        selections += 1;
        return undefined;
      },
    });
    expect(found).toEqual([]);
    expect(selections).toBe(0);
  });

  it("pays ten from six on each of two trees", () => {
    expect(
      picked(
        [
          [0, 6n],
          [1, 6n],
          [2, 1n],
        ],
        10n,
        5,
      ),
    ).toEqual(
      expected([
        [0, 6n],
        [1, 6n],
      ]),
    );
  });

  /** Rust `a_delegate_move_funds_from_a_pair_past_the_preferred_trees`, on the transfer path. */
  it("funds from a pair past the preferred trees", () => {
    const small = Array.from({ length: 8 }, (_, tree) =>
      [20n, 20n, 20n, 5n].map((amount) => [tree + 1, amount] as const),
    ).flat();
    expect(picked([...small, [9, 60n], [10, 60n]], 120n, 4)).toEqual(
      expected([
        [9, 60n],
        [10, 60n],
      ]),
    );
  });

  /** Rust `a_delegate_move_skips_a_tree_whose_change_no_shape_holds`, on one tree as the core authority builder takes. */
  it("skips a delegate selection whose change no authority shape holds", () => {
    const notes: readonly Note[] = [
      [0, 101n],
      [1, 50n],
      [1, 50n],
    ];
    const selected = selectAuthorityNotes({
      wallet: walletOf(notes),
      covers: [{ asset: SOL_MINT, amount: 100n }],
      outputs: 4,
      eligible: () => true,
    });
    expect(sortedByTree(selected)).toEqual(
      expected([
        [1, 50n],
        [1, 50n],
      ]),
    );
  });

  /** Rust `an_anonymous_move_counts_the_sender_change_before_selection`. */
  it("counts the anonymous sender change before selection", () => {
    expect(anonymousInputCap("ring", 2)).toBe(24);
    const ones: readonly Note[] = Array.from({ length: 25 }, () => [1, 1n] as const);
    const select = (notes: readonly Note[]) =>
      selectRingInputs({
        wallet: walletOf(notes, RING),
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 25n,
        inputs: "ring",
        maxInputs: anonymousInputCap("ring", 2),
      });
    expect(() => select(ones)).toThrow("RING_TOO_MANY_INPUTS");
    const selected = select([...ones, [2, 5n]]);
    expect(selected).toHaveLength(21);
    expect(new Set(selected.map((entry) => entry.outputContext.tree))).toEqual(
      new Set([treeAddress(1), treeAddress(2)]),
    );
  });

  it("names the mint no tree set reaches", () => {
    const select = () =>
      selectAcrossTrees({
        wallet: walletOf([
          [1, 10n],
          [2, 5n, MINT],
        ]),
        covers: [
          { asset: SOL_MINT, amount: 10n },
          { asset: MINT, amount: 100n },
        ],
        policy: {
          eligible: () => true,
          ordering: "largestFirst",
          maxInputs: 4,
          errors: ringSelectionErrors,
        },
      });
    expect(select).toThrow(
      expect.objectContaining({
        code: "RING_INSUFFICIENT_BALANCE",
        details: expect.objectContaining({ asset: MINT }),
      }),
    );
  });

  /** Rust `Funding::candidates` pins the same file. */
  it.each(vectors.cases)("matches the shared vector: $name", (vector) => {
    expect(
      picked(
        vector.notes.map((note) => [note.tree, BigInt(note.amount)] as const),
        BigInt(vector.amount),
        vector.maxInputs,
      ),
    ).toEqual(expected(vector.selected.map((note) => [note.tree, BigInt(note.amount)] as const)));
  });
});
