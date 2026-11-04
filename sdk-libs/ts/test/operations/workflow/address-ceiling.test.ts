import type { Address, Bytes32, Instruction } from "@heliuslabs/zolana/interface";
import { encodeBase58 } from "@heliuslabs/zolana/internal";
import { ShieldedKeypair } from "@heliuslabs/zolana/keypair";
import { SOL_MINT } from "@heliuslabs/zolana/transaction";
import { describe, expect, it } from "vitest";

import { MAX_FRAME_LEN } from "../../../src/protocol/transaction/frame-buffer.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { MAX_TRANSACTION_ADDRESSES as LIMIT } from "../../../src/operations/workflow/compile.js";
import {
  decideAddressCeiling,
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
): Promise<CeilingDecision> {
  const accounts = [
    ...inputs.map((input) => input.nullifierPda),
    ...Array.from({ length: other }, (_, seed) => address(5000 + seed)),
  ].map((account) => ({ address: account, role: 1 }));
  const instruction = { programAddress: address(2), accounts } as unknown as Instruction;
  return decideAddressCeiling({
    payer: address(1),
    instruction,
    computeUnitLimit: 1_000_000,
    inputs,
    mergeCapacity,
  });
}

const notes = (owner: number, count: number): readonly SpentInput[] =>
  Array.from({ length: count }, (_, seed) => note(owner, seed));

const refused = async (inputs: readonly SpentInput[], other: number) => {
  try {
    await decide(inputs, other);
  } catch (error) {
    return (error as { code?: string; details?: unknown }).details;
  }
  throw new Error("under the ceiling");
};

function decideFrame(length: number): Promise<CeilingDecision> {
  const data = new Uint8Array(length);
  data[0] = RingInstructionTag.transfer;
  return decideAddressCeiling({
    payer: address(1),
    instruction: { programAddress: address(2), accounts: [], data } as unknown as Instruction,
    computeUnitLimit: 1_000_000,
    inputs: [],
    mergeCapacity: { keyed: 45, zeroKey: 45 },
  });
}

describe("decideAddressCeiling, the cases of Rust `validation::address_ceiling`", () => {
  it("keeps a transaction at the ceiling one transaction", async () => {
    expect(await decide(notes(1, 10), LIMIT - 2 - 10)).toMatchObject({
      kind: "inline",
      size: { addresses: LIMIT },
    });
  });

  it("names only the groups the ceiling needs", async () => {
    const inputs = [...notes(1, 4), note(2, 4), note(2, 5)];
    const decision = await decide(inputs, LIMIT - 2 - 6 + 2);
    if (decision.kind !== "mergeFirst") throw new Error("merge first");
    expect(decision.addresses).toBe(LIMIT - 1);
    expect(decision.groups.map((group) => group.inputs)).toEqual([[0, 1, 2, 3]]);
    expect(decision.groups[0]?.owner.equals(inputs[0]?.owner as never)).toBe(true);
  });

  it("forms no group of mixed owners and reports the compiled count", async () => {
    const inputs = [0, 1, 2, 3].map((seed) => note(seed + 1, seed));
    expect(await refused(inputs, LIMIT - 2 - 4 + 1)).toEqual({
      compiled: LIMIT + 1,
      limit: LIMIT,
      afterMerging: LIMIT + 1,
      dataNotes: 0,
    });
  });

  it("keeps a data note out of every group", async () => {
    const inputs = notes(1, 4).map((input) => ({
      ...input,
      dataHash: new Uint8Array(32).fill(9) as Bytes32,
    }));
    expect(await refused(inputs, LIMIT - 2 - 4 + 1)).toMatchObject({
      afterMerging: LIMIT + 1,
      dataNotes: 4,
    });
  });

  it("merges no notes of another asset, key or tree", async () => {
    const inputs = [
      note(1, 0),
      { ...note(1, 1), asset: address(7) },
      { ...note(1, 2), nullifierPublicKey: new Uint8Array(32).fill(9) as Bytes32 },
      { ...note(1, 3), treeId: 2 },
    ];
    expect(await refused(inputs, LIMIT - 2 - 4 + 1)).toMatchObject({ afterMerging: LIMIT + 1 });
  });

  it("refuses consolidation short of the ceiling with how far it reached", async () => {
    expect(await refused(notes(1, 4), LIMIT - 2 - 4 + 5)).toMatchObject({
      compiled: LIMIT + 5,
      afterMerging: LIMIT + 2,
    });
  });

  it("names no merge for a lone note past the capacity", async () => {
    const decision = await decide(notes(1, 4), LIMIT - 2 - 4 + 1, { keyed: 3, zeroKey: 3 });
    if (decision.kind !== "mergeFirst") throw new Error("merge first");
    expect(decision.groups.map((group) => group.inputs)).toEqual([[0, 1, 2]]);
    expect(decision.addresses).toBe(LIMIT - 1);
  });

  it("takes a frame past the byte ceiling to a buffer and refuses it past the CPI limit", async () => {
    expect(await decideFrame(1000)).toMatchObject({ kind: "inline" });
    const past = await decideFrame(4096);
    expect(past.kind).toBe("buffered");
    if (past.kind === "buffered") expect(past.size.bytes).toBeLessThan(4096);
    expect(await decideFrame(MAX_FRAME_LEN)).toMatchObject({ kind: "buffered" });
    await expect(decideFrame(MAX_FRAME_LEN + 1)).rejects.toMatchObject({
      code: "RING_FRAME_TOO_LARGE",
      details: { bytes: MAX_FRAME_LEN + 1, limit: MAX_FRAME_LEN },
    });
  });
});
