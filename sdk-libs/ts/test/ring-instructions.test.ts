import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";
import {
  NO_CACHE_WRITES,
  type CircuitId,
  type TransactInstructionData,
} from "@heliuslabs/zolana/interface";
import type { Bytes16, Bytes32, Bytes33, Bytes128 } from "@heliuslabs/zolana";
import { ringTransactInstruction } from "../src/ring/instructions.js";

const PAYER = address("k7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn");
const TREE = address("2RJD1KnDRGEkvuFfAGrJ7PD28LRE9LRDjZznDywagzmr");
const OUTPUT_TREE = address("2VDW9dFE1ZXz4zWAbaBDQFynNVdRpQ73HyfSHMzBSL6Z");
const RING_AUTH = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");

function filled(value: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function field(seed: number): Bytes32 {
  const value = filled(seed, 32);
  value[0] = 0;
  return value as Bytes32;
}

function transactData(circuit: CircuitId): TransactInstructionData {
  return {
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    privateTxHash: field(41),
    circuit,
    txViewingPk: filled(3, 33) as Bytes33,
    salt: filled(42, 16) as Bytes16,
    proof: {
      a: filled(43, 32) as Bytes32,
      b: filled(44, 128) as Bytes128,
      c: filled(45, 32) as Bytes32,
    },
    inputs: Array.from({ length: circuit.inputs }, (_, index) => ({
      nullifierHash: field(0x10 + index),
      treeIndex: 0,
    })),
    treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    interfaceTransfers: [],
    outputs: [],
    messages: [],
  };
}

describe("ring transact cache accounts", () => {
  it("refuses a cached circuit on the custom-ring transact, which the ring program rejects", async () => {
    await expect(
      ringTransactInstruction({
        ringProgramId: RING_AUTH,
        payer: PAYER,
        inputTrees: [TREE],
        outputTree: OUTPUT_TREE,
        proof: new Uint8Array(),
        data: transactData({
          kind: "confidentialRingEddsaCached",
          inputs: 2,
          outputs: 2,
          publicAssetSlots: 3,
          cacheAccess: { readBitmap: 1n, writeSlots: NO_CACHE_WRITES },
        }),
      }),
    ).rejects.toMatchObject({
      code: "RING_CACHE_UNSUPPORTED",
      details: { kind: "confidentialRingEddsaCached" },
    });
  });
});
