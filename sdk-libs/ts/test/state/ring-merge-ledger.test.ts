import { getBase58Decoder, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { BN254_SCALAR_ORDER, bigIntToBytes } from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes32, Signature } from "@heliuslabs/zolana/interface";
import { SOL_MINT } from "@heliuslabs/zolana/transaction";

import { knownUtxoOwnerHash } from "../../src/operations/audit/audit.js";
import {
  MergeLedger,
  type ConfirmedMerge,
  type KnownMergeInput,
  type MergeInput,
} from "../../src/state/merge-ledger.js";

await initializePoseidon();

const OWNER_KEY = filled(1);
const NULLIFIER_PK = filled(2);
const ASSET = filled(7);
const MINT: Address = SOL_MINT;
const ZERO = filled(0);
const NOTHING: KnownMergeInput = () => undefined;

function filled(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

function signatureOf(byte: number): Signature {
  return getBase58Decoder().decode(new Uint8Array(64).fill(byte)) as Signature;
}

function note(amount: bigint): MergeInput {
  return {
    ownerKey: OWNER_KEY,
    owner: { kind: "keyed", nullifierPk: NULLIFIER_PK },
    asset: ASSET,
    mint: MINT,
    amount,
  };
}

function merge(id: number, inputs: readonly number[], output: number): ConfirmedMerge {
  return {
    slot: BigInt(id),
    signature: signatureOf(id),
    eventIndex: 0,
    outputCommitment: filled(output),
    treeId: 1,
    leafIndex: BigInt(id),
    firstNullifier: filled(id),
    ringDataHash: new Uint8Array(32) as Bytes32,
    inputs: inputs.map(filled),
  };
}

function knownOnly(openings: Readonly<Record<number, bigint>>): KnownMergeInput {
  return (commitment) => {
    const amount = openings[commitment[0] ?? 0];
    return amount === undefined ? undefined : note(amount);
  };
}

describe("MergeLedger", () => {
  it("records the sum under the inherited owner and asset, with no wallet opening", () => {
    const ledger = new MergeLedger();
    const transition = ledger.apply(merge(1, [10, 11], 20), knownOnly({ 10: 10n, 11: 11n }));
    expect(transition.spent).toEqual([filled(10), filled(11)]);
    expect(transition.resolved).toEqual([
      {
        commitment: filled(20),
        slot: 1n,
        signature: signatureOf(1),
        eventIndex: 0,
        treeId: 1,
        leafIndex: 1n,
        firstNullifier: filled(1),
        ringDataHash: ZERO,
        ownerKey: OWNER_KEY,
        owner: { kind: "keyed", nullifierPk: NULLIFIER_PK },
        asset: ASSET,
        mint: MINT,
        amount: 21n,
        inputs: [filled(10), filled(11)],
      },
    ]);
    expect(ledger.output(filled(20))).toEqual(transition.resolved[0]);
    expect(ledger.outputs()).toEqual(transition.resolved);
  });

  it("applies each signature and event index once", () => {
    const ledger = new MergeLedger();
    const known = knownOnly({ 10: 5n });
    expect(ledger.apply(merge(1, [10], 20), known).spent).toEqual([filled(10)]);
    const first = ledger.outputs();
    expect(ledger.apply(merge(1, [10], 20), known)).toEqual({
      spent: [],
      resolved: [],
    });
    expect(ledger.outputs()).toEqual(first);
    const sameTransaction = { ...merge(1, [12], 21), eventIndex: 1 };
    expect(ledger.apply(sameTransaction, NOTHING).spent).toEqual([filled(12)]);
  });

  it("marks an unknown input spent and holds the merge and its descendant until it opens", () => {
    const ledger = new MergeLedger();
    ledger.apply(merge(2, [20, 12], 30), NOTHING);
    const parent = ledger.apply(merge(1, [10], 20), NOTHING);
    expect(parent.spent).toEqual([filled(10)]);
    expect(parent.resolved).toEqual([]);
    expect(ledger.unresolved().map(({ slot }) => slot)).toEqual([1n, 2n]);

    expect(ledger.resolve(knownOnly({ 10: 5n })).map(({ amount }) => amount)).toEqual([5n]);
    expect(ledger.unresolved().map(({ slot }) => slot)).toEqual([2n]);

    expect(ledger.resolve(knownOnly({ 10: 5n, 12: 6n })).map(({ amount }) => amount)).toEqual([
      11n,
    ]);
    expect(ledger.unresolved()).toEqual([]);
  });

  it("runs resolution through a chain of descendants to a fixed point", () => {
    const ledger = new MergeLedger();
    ledger.apply(merge(1, [10], 20), NOTHING);
    ledger.apply(merge(2, [20], 30), NOTHING);
    ledger.apply(merge(3, [30], 40), NOTHING);
    const resolved = ledger.resolve(knownOnly({ 10: 9n }));
    expect(resolved.map(({ commitment }) => commitment)).toEqual([
      filled(20),
      filled(30),
      filled(40),
    ]);
    expect(ledger.output(filled(40))?.amount).toBe(9n);
  });

  it.each([
    [10, 11],
    [11, 10],
  ])("resolves equal deposited and keyed owners through descendants in order %j", (...inputs) => {
    const keyed = note(5n);
    const deposited: MergeInput = {
      ...keyed,
      owner: { kind: "deposited", ownerHash: knownUtxoOwnerHash(keyed) },
    };
    const ledger = new MergeLedger();
    ledger.apply(merge(2, [20, 12], 30), NOTHING);
    ledger.apply(merge(1, inputs, 20), NOTHING);
    const known: KnownMergeInput = (commitment) => {
      switch (commitment[0]) {
        case 10:
          return deposited;
        case 11:
          return keyed;
        case 12:
          return note(7n);
        default:
          return undefined;
      }
    };
    expect(ledger.resolve(known)).toHaveLength(2);
    expect(ledger.output(filled(20))).toMatchObject({ owner: keyed.owner, amount: 10n });
    expect(ledger.output(filled(30))).toMatchObject({ owner: keyed.owner, amount: 17n });
    expect(ledger.unresolved()).toEqual([]);
  });

  it.each(["apply", "resolve"] as const)(
    "keeps the ledger unchanged when %s fails in a descendant owner check",
    (operation) => {
      const ledger = new MergeLedger();
      const parent = merge(1, [10], 20);
      const descendant = merge(2, [20, 11], 30);
      ledger.apply(parent, NOTHING);
      if (operation === "resolve") ledger.apply(descendant, NOTHING);
      const before = ledger.unresolved();
      const invalid: MergeInput = {
        ...note(5n),
        owner: {
          kind: "keyed",
          nullifierPk: bigIntToBytes(BN254_SCALAR_ORDER) as Bytes32,
        },
      };
      const known: KnownMergeInput = (commitment) => {
        if (commitment[0] === 10) return note(5n);
        if (commitment[0] === 11) return invalid;
        return undefined;
      };
      const resolve = (openings: KnownMergeInput) =>
        operation === "apply"
          ? ledger.apply(descendant, openings).resolved
          : ledger.resolve(openings);
      expect(() => resolve(known)).toThrow();
      expect(ledger.outputs()).toEqual([]);
      expect(ledger.unresolved()).toEqual(before);
      expect(resolve(knownOnly({ 10: 5n, 11: 7n }))).toHaveLength(2);
      expect(ledger.output(filled(30))?.amount).toBe(12n);
      expect(ledger.unresolved()).toEqual([]);
    },
  );

  it.each<readonly [string, MergeInput]>([
    ["two owner keys", { ...note(1n), ownerKey: filled(9) }],
    ["two nullifier keys", { ...note(1n), owner: { kind: "keyed", nullifierPk: filled(9) } }],
    [
      "a keyed and a deposited owner",
      { ...note(1n), owner: { kind: "deposited", ownerHash: filled(2) } },
    ],
    ["two assets", { ...note(1n), asset: filled(9) }],
    ["an amount past u64", { ...note(2n ** 64n - 1n) }],
  ])("never resolves inputs of %s", (_name, second) => {
    const ledger = new MergeLedger();
    const known: KnownMergeInput = (commitment) => (commitment[0] === 10 ? note(1n) : second);
    expect(ledger.apply(merge(1, [10, 11], 20), known).resolved).toEqual([]);
    expect(ledger.unresolved()).toHaveLength(1);
  });

  it("names the mint any input knows", () => {
    const ledger = new MergeLedger();
    const { mint: _mint, ...unnamed } = note(1n);
    const known: KnownMergeInput = (commitment) => (commitment[0] === 10 ? unnamed : note(1n));
    expect(ledger.apply(merge(1, [10, 11], 20), known).resolved[0]?.mint).toBe(MINT);
  });
});
