import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { RingError } from "../../../src/protocol/error.js";
import type { TransferKeyCircuit } from "../../../src/protocol/proof/transfer-shapes.js";
import { ringStreamLayout, type RingRail } from "../../../src/protocol/transaction/transact.js";
import {
  NO_RECORD_POOLS,
  planTransfer,
  planTransferAt,
  rekeyedPlan,
  type PlanFrame,
} from "../../../src/operations/workflow/transfer-plan.js";

interface RustCircuit {
  readonly outputs: number;
  readonly inputs: number;
  readonly withdrawals: number;
  readonly owners: number;
  readonly entry: boolean;
  readonly wide: boolean;
}

/** One case of Rust `a_read_keeps_a_seal_of_one_stream_and_refuses_another`. */
interface RekeyCase {
  readonly name: string;
  readonly rail: RingRail;
  readonly inputs: number;
  readonly outputs: number;
  readonly spendsDefaultRing: boolean;
  readonly hasData: boolean;
  readonly approval: boolean;
  readonly readPools: Readonly<{ own: number; curator: number; tracking: number }>;
  readonly sealed: RustCircuit;
  readonly read: RustCircuit;
  readonly outcome: "reuse" | "reseal";
}

const CASES = JSON.parse(
  readFileSync(
    new URL("../../../../sdk/tests/fixtures/transfer-plan-rekey.json", import.meta.url),
    "utf8",
  ),
) as readonly RekeyCase[];

function frameOf(rekey: RekeyCase): PlanFrame {
  return {
    subjects: {
      rail: rekey.rail,
      inputs: rekey.inputs,
      outputs: rekey.outputs,
      spendsDefaultRing: rekey.spendsDefaultRing,
      legs: 0,
      owners: 1,
      pools: NO_RECORD_POOLS,
      wide: false,
    },
    layoutUnder: (wideOwners) =>
      ringStreamLayout({
        rail: rekey.rail,
        nIn: rekey.inputs,
        nOut: rekey.outputs,
        inputs: rekey.inputs,
        outputs: rekey.outputs,
        entry: rekey.spendsDefaultRing,
        hasData: rekey.hasData,
        wideOwners,
      }),
    settlement: "inline",
    spansCapacity: rekey.hasData || rekey.approval,
  };
}

function rustCircuit(circuit: TransferKeyCircuit): RustCircuit {
  const { outputs, withdrawals, owners, entry, wide } = circuit;
  return { outputs, inputs: circuit.class, withdrawals, owners, entry, wide };
}

describe("a planned transfer under a later read", () => {
  it("covers every Rust case", () => {
    expect(CASES.map((rekey) => rekey.outcome)).toEqual([
      "reuse",
      "reseal",
      "reuse",
      "reseal",
      "reseal",
    ]);
  });

  for (const rekey of CASES)
    it(`${rekey.outcome === "reuse" ? "keeps" : "refuses until resealed"} ${rekey.name}`, () => {
      const frame = frameOf(rekey);
      const sealed = planTransfer(frame, NO_RECORD_POOLS);
      const read = planTransfer(frame, rekey.readPools);
      expect(rustCircuit(sealed.circuit)).toEqual(rekey.sealed);
      expect(rustCircuit(read.circuit)).toEqual(rekey.read);
      if (rekey.outcome === "reuse") {
        // The relay proves the key a direct transfer takes from the same read.
        expect(rekeyedPlan(sealed, read)).toBe(read);
        return;
      }
      let refusal: unknown;
      try {
        rekeyedPlan(sealed, read);
      } catch (cause) {
        refusal = cause;
      }
      expect(refusal).toBeInstanceOf(RingError);
      expect(refusal).toMatchObject({ code: "RING_RESEAL_REQUIRED", details: { row: "wide" } });
      expect(rekeyedPlan(planTransferAt(frame, "wide"), read)).toBe(read);
    });
});
