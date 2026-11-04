import type { Address, Bytes32, Instruction } from "@heliuslabs/zolana/interface";
import { encodeBase58 } from "@heliuslabs/zolana/internal";
import { ShieldedKeypair } from "@heliuslabs/zolana/keypair";
import { SOL_MINT } from "@heliuslabs/zolana/transaction";
import { describe, expect, it } from "vitest";

import {
  decideAddressCeiling,
  MAX_TRANSACTION_ADDRESSES as LIMIT,
  type CeilingDecision,
  type MergeCapacity,
  type SpentInput,
} from "../../../src/operations/workflow/address-ceiling.js";

function address(seed: number): Address {
  const bytes = new Uint8Array(32).fill(0xaa);
  new DataView(bytes.buffer).setUint32(0, seed);
  return encodeBase58(bytes);
}

const owners = new Map<number, ShieldedKeypair>();
const ownerOf = (owner: number): ShieldedKeypair => {
  const held = owners.get(owner) ?? ShieldedKeypair.generate();
  owners.set(owner, held);
  return held;
};

const note = (owner: number, seed: number): SpentInput => ({
  owner: ownerOf(owner).signingPublicKey(),
  asset: SOL_MINT,
  nullifierPublicKey: new Uint8Array(32).fill(owner) as Bytes32,
  ringProgramId: address(0),
  treeId: 1,
  nullifierPda: address(1000 + seed),
});

function decide(
  inputs: readonly SpentInput[],
  other: number,
  mergeCapacity: MergeCapacity = { keyed: 45, zeroKey: 45 },
): CeilingDecision {
  const accounts = [
    ...inputs.map((input) => input.nullifierPda),
    ...Array.from({ length: other }, (_, seed) => address(5000 + seed)),
  ].map((account) => ({ address: account, role: 1 }));
  const instruction = { programAddress: address(2), accounts } as unknown as Instruction;
  return decideAddressCeiling({ payer: address(1), instruction, inputs, mergeCapacity });
}

const notes = (owner: number, count: number): readonly SpentInput[] =>
  Array.from({ length: count }, (_, seed) => note(owner, seed));

const refused = (inputs: readonly SpentInput[], other: number) => {
  try {
    decide(inputs, other);
  } catch (error) {
    return (error as { code?: string; details?: unknown }).details;
  }
  throw new Error("under the ceiling");
};

describe("decideAddressCeiling, the cases of Rust `validation::address_ceiling`", () => {
  it("keeps a transaction at the ceiling one transaction", () => {
    expect(decide(notes(1, 10), LIMIT - 2 - 10)).toEqual({
      kind: "underCeiling",
      addresses: LIMIT,
    });
  });

  it("names only the groups the ceiling needs", () => {
    const inputs = [...notes(1, 4), note(2, 4), note(2, 5)];
    const decision = decide(inputs, LIMIT - 2 - 6 + 2);
    if (decision.kind !== "mergeFirst") throw new Error("merge first");
    expect(decision.addresses).toBe(LIMIT - 1);
    expect(decision.groups.map((group) => group.inputs)).toEqual([[0, 1, 2, 3]]);
    expect(decision.groups[0]?.owner.equals(inputs[0]?.owner as never)).toBe(true);
  });

  it("forms no group of mixed owners and reports the compiled count", () => {
    const inputs = [0, 1, 2, 3].map((seed) => note(seed + 1, seed));
    expect(refused(inputs, LIMIT - 2 - 4 + 1)).toEqual({
      compiled: LIMIT + 1,
      limit: LIMIT,
      afterMerging: LIMIT + 1,
      dataNotes: 0,
    });
  });

  it("keeps a data note out of every group", () => {
    const inputs = notes(1, 4).map((input) => ({
      ...input,
      dataHash: new Uint8Array(32).fill(9) as Bytes32,
    }));
    expect(refused(inputs, LIMIT - 2 - 4 + 1)).toMatchObject({
      afterMerging: LIMIT + 1,
      dataNotes: 4,
    });
  });

  it("merges no notes of another asset, key or tree", () => {
    const inputs = [
      note(1, 0),
      { ...note(1, 1), asset: address(7) },
      { ...note(1, 2), nullifierPublicKey: new Uint8Array(32).fill(9) as Bytes32 },
      { ...note(1, 3), treeId: 2 },
    ];
    expect(refused(inputs, LIMIT - 2 - 4 + 1)).toMatchObject({ afterMerging: LIMIT + 1 });
  });

  it("refuses consolidation short of the ceiling with how far it reached", () => {
    expect(refused(notes(1, 4), LIMIT - 2 - 4 + 5)).toMatchObject({
      compiled: LIMIT + 5,
      afterMerging: LIMIT + 2,
    });
  });

  it("names no merge for a lone note past the capacity", () => {
    const decision = decide(notes(1, 4), LIMIT - 2 - 4 + 1, { keyed: 3, zeroKey: 3 });
    if (decision.kind !== "mergeFirst") throw new Error("merge first");
    expect(decision.groups.map((group) => group.inputs)).toEqual([[0, 1, 2]]);
    expect(decision.addresses).toBe(LIMIT - 1);
  });
});
