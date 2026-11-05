import { describe, expect, it } from "vitest";

import {
  fittedSpend,
  ringTransferCircuit,
  TRANSFER_SHAPES,
  transferPoolCapacity,
  transferKeys,
  type TransferShape,
  type TransferSpend,
} from "../../src/protocol/proof/transfer-shapes.js";

const NO_POOLS = { own: 0, curator: 0, tracking: 0 };

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
    expect(transferPoolCapacity(sixteen!)).toEqual({ own: 83, curator: 83, tracking: 32 });
    const entry = ringTransferCircuit(fittedSpend(loaded(row(8, 4, true))));
    expect(entry).toMatchObject({ outputs: 8, class: 4, withdrawals: 4, owners: 4, entry: true });
    expect(transferPoolCapacity(entry!)).toEqual({ own: 43, curator: 43, tracking: 16 });
    expect(transferKeys()).toHaveLength(12);
  });

  it("refuses a spend past the sibling", () => {
    const past = { ...loaded(row(16, 8, false)), inputs: 9 };
    expect(ringTransferCircuit(fittedSpend(past))).toBeUndefined();
  });
});
