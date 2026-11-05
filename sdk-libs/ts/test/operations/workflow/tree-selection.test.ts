import { ShieldedKeypair, SigningKey } from "@heliuslabs/zolana/keypair";
import { treeAddress } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";
import { AssetRegistry, Data, SOL_MINT, Utxo, Wallet } from "@heliuslabs/zolana/transaction";
import { describe, expect, it } from "vitest";

import vectors from "../../../../../test-vectors/wallet/tree-selection.json" with { type: "json" };
import {
  PAIR_POOL_TREES,
  ringSelectionErrors,
  selectAcrossTrees,
  stagedTreeSearch,
} from "../../../src/operations/workflow/selection.js";

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function walletOf(notes: readonly Note[]): Wallet {
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry([]),
  });
  wallet._replace({
    utxos: notes.map(([tree, amount], index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: filled(index + 1),
        data: new Data(),
      }),
      outputContext: { hash: filled(index + 1), tree: treeAddress(tree), leafIndex: BigInt(index) },
      nullifier: filled(index + 100),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

type Note = readonly [tree: number, amount: bigint];

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
    }).map((entry) => [entry.outputContext.tree, entry.utxo.amount] as const),
  );
}

function sortedByTree(notes: readonly (readonly [Address, bigint])[]) {
  return [...notes].sort(([left], [right]) => left.localeCompare(right));
}

describe("selectAcrossTrees", () => {
  it("tries no pair when one tree funds", () => {
    const trees = [treeAddress(1), treeAddress(2), treeAddress(3)];
    const tried: (readonly Address[])[] = [];
    const funded = stagedTreeSearch(trees, trees, (set) => {
      tried.push(set);
      return set.length === 1 && set[0] === trees[1] ? set : undefined;
    });
    expect(funded).toHaveLength(1);
    expect(tried).toEqual(trees.map((tree) => [tree]));
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
      sortedByTree([
        [treeAddress(0), 6n],
        [treeAddress(1), 6n],
      ]),
    );
  });

  it("pairs only within the pool on a many-tree wallet", () => {
    const trees = Array.from({ length: 20 }, (_, id) => treeAddress(id));
    let tried = 0;
    const funded = stagedTreeSearch(trees, trees.slice(0, PAIR_POOL_TREES), () => {
      tried += 1;
      return undefined;
    });
    expect(funded).toEqual([]);
    expect(tried).toBe(trees.length + (PAIR_POOL_TREES * (PAIR_POOL_TREES - 1)) / 2);

    const pool = new Set(trees.slice(0, PAIR_POOL_TREES));
    const spent = picked(
      trees.map((_, id) => [id, 1n] as const),
      2n,
      5,
    );
    expect(spent).toHaveLength(2);
    expect(spent.every(([tree]) => pool.has(tree))).toBe(true);
  });

  /** Rust `Funding::candidates` pins the same file. */
  it.each(vectors.cases)("matches the shared vector: $name", (vector) => {
    const expected = sortedByTree(
      vector.selected.map((note) => [treeAddress(note.tree), BigInt(note.amount)] as const),
    );
    expect(
      picked(
        vector.notes.map((note) => [note.tree, BigInt(note.amount)] as const),
        BigInt(vector.amount),
        vector.maxInputs,
      ),
    ).toEqual(expected);
  });
});
