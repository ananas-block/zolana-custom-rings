import { getBase58Decoder } from "@solana/kit";
import { expect, it } from "vitest";

import type { Bytes32, Signature } from "@heliuslabs/zolana/interface";
import { isPoseidonInitialized } from "@heliuslabs/zolana/keypair";

import { MergeLedger, type ConfirmedMerge, type MergeInput } from "../../src/state/merge-ledger.js";

const hash = new Uint8Array(32).fill(1) as Bytes32;
const owner: MergeInput = {
  ownerKey: hash,
  owner: { kind: "keyed", nullifierPk: hash },
  asset: hash,
  amount: 5n,
};
const merge: ConfirmedMerge = {
  slot: 1n,
  signature: getBase58Decoder().decode(new Uint8Array(64).fill(1)) as Signature,
  eventIndex: 0,
  outputCommitment: new Uint8Array(32).fill(2) as Bytes32,
  treeId: 1,
  leafIndex: 0n,
  firstNullifier: hash,
  inputs: [hash],
};
const initializedBeforeHooks = isPoseidonInitialized();
const applying = new MergeLedger();
const resolving = new MergeLedger();
resolving.apply(merge, () => undefined);
const failures = [
  () => applying.apply(merge, () => owner),
  () => resolving.resolve(() => owner),
].map((operation) => {
  try {
    operation();
    return undefined;
  } catch (error) {
    return error;
  }
});

it("retries unchanged ledgers after Poseidon initialization", () => {
  expect(initializedBeforeHooks).toBe(false);
  expect(failures).toMatchObject([{ code: "NotInitialized" }, { code: "NotInitialized" }]);
  expect(applying.outputs()).toEqual([]);
  expect(applying.unresolved()).toEqual([]);
  expect(resolving.outputs()).toEqual([]);
  expect(resolving.unresolved()).toEqual([merge]);
  expect(isPoseidonInitialized()).toBe(true);
  expect(applying.apply(merge, () => owner)).toMatchObject({
    spent: [hash],
    resolved: [{ amount: 5n }],
  });
  expect(resolving.resolve(() => owner)).toMatchObject([{ amount: 5n }]);
  expect(applying.unresolved()).toEqual([]);
  expect(resolving.unresolved()).toEqual([]);
});
