import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  RING_KEYS,
  ringCredentialCapacity,
  type RingKeyCircuit,
} from "../../src/protocol/proof/proving-keys.js";
import {
  fittedSpend,
  ringTransferCircuit,
  TRANSFER_SHAPES,
  transferPoolCapacity,
  transferKeys,
  type TransferShape,
  type TransferSpend,
} from "../../src/protocol/proof/transfer-shapes.js";

const NO_POOLS = { own: 0, curator: 0, credentials: 0 };

function loaded(entry: TransferShape, pools = NO_POOLS): TransferSpend {
  return {
    rail: "confidential",
    inputs: entry.inputs,
    outputs: entry.outputs,
    spendsDefaultRing: entry.entry,
    legs: entry.withdrawals,
    owners: entry.owners,
    pools,
    wide: false,
  };
}

function row(outputs: number, inputs: number, entry: boolean): TransferShape {
  const rows = TRANSFER_SHAPES.filter(
    (shape) => shape.outputs === outputs && shape.inputs === inputs && shape.entry === entry,
  );
  const [first] = rows;
  if (first === undefined) throw new Error(`no ${inputs}x${outputs} row`);
  return first;
}

describe("the sibling keys", () => {
  it("serves eight inputs at sixteen outputs and four at an eight output entry", () => {
    const sixteen = ringTransferCircuit(fittedSpend(loaded(row(16, 8, false))));
    expect(sixteen).toMatchObject({ outputs: 16, class: 8, withdrawals: 8, owners: 8, wide: true });
    expect(transferPoolCapacity(sixteen!)).toEqual({ own: 83, curator: 83, credentials: 32 });
    const entry = ringTransferCircuit(fittedSpend(loaded(row(8, 4, true))));
    expect(entry).toMatchObject({ outputs: 8, class: 4, withdrawals: 4, owners: 4, entry: true });
    expect(transferPoolCapacity(entry!)).toEqual({ own: 43, curator: 43, credentials: 16 });
    expect(transferKeys()).toHaveLength(12);
  });

  it("refuses a spend past the sibling", () => {
    const past = { ...loaded(row(16, 8, false)), inputs: 9 };
    expect(ringTransferCircuit(fittedSpend(past))).toBeUndefined();
  });
});

/** Rust `RING_KEYS` as TS circuits, a transfer's `inputs` is the TS `class`. */
function rustRingKeys(): readonly Readonly<{ circuit: RingKeyCircuit; name: string }>[] {
  const source = readFileSync(
    new URL("../../../../program-libs/interface/src/proof/ring_keys.rs", import.meta.url),
    "utf8",
  );
  return [
    ...source.matchAll(/circuit: RingCircuit::(\w+)(?: \{([^}]*)\})?,\s*name: "([a-z0-9-]+)"/gu),
  ].map(([, variant = "", body = "", name = ""]) => {
    const fields = [...body.matchAll(/(\w+): (\w+)/gu)].map(([, field = "", value = ""]) => [
      field === "inputs" ? "class" : field,
      value === "true" || value === "false" ? value === "true" : Number(value),
    ]);
    const family = `${variant.slice(0, 1).toLowerCase()}${variant.slice(1)}`;
    return { circuit: { family, ...Object.fromEntries(fields) } as RingKeyCircuit, name };
  });
}

describe("the ring key catalog", () => {
  it("lists every key of ring_keys.rs in its order and no other", () => {
    const rust = rustRingKeys();
    expect(rust.map((key) => key.circuit.family)).not.toContain("applyEnrollments");
    expect(RING_KEYS).toEqual(rust);
  });

  it("bounds each key's credential read like Rust `credential_capacity`", () => {
    const transfer = transferKeys()[0]!;
    expect(ringCredentialCapacity(transfer)).toBe(transferPoolCapacity(transfer).credentials);
    expect(ringCredentialCapacity({ family: "deposit", capacity: 8 })).toBe(8);
    expect(ringCredentialCapacity({ family: "merge" })).toBe(1);
    expect(ringCredentialCapacity({ family: "applyRecords", writes: 16 })).toBe(16);
  });

  it("gives no credential capacity to RegisterKey or a shape off the catalog", () => {
    expect(ringCredentialCapacity({ family: "registerKey" })).toBeUndefined();
    expect(ringCredentialCapacity({ family: "applyRecords", writes: 3 })).toBeUndefined();
    expect(ringCredentialCapacity({ family: "deposit", capacity: 16 })).toBeUndefined();
  });
});
