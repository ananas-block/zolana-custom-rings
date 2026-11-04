/** The totals a transfer proof binds for a co-signer, Rust `zolana_ring_policy::ApprovalTotals`. */
import { bigIntBytes, equalBytes, hashChain4, ZERO_32 } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import { assetFlows, orderedOwners, type DebitTransfer, type PublicGross } from "./owner-debits.js";

/** "CRAO". */
export const APPROVAL_TOTALS_DOMAIN = 0x4352_414fn;

/** `peak` is one owner's largest outflow of the asset, the value `cosignAbove` compares. */
export interface OutputTotals {
  /** Zero on a dummy slot. */
  readonly asset: Bytes32;
  readonly peak: bigint;
  readonly outflow: bigint;
}

/** `peak` and `outflow` read debits alone, a charged asset reads whole under its live output. */
export interface PublicTotals extends OutputTotals {
  readonly gross: bigint;
}

/** The layout every key commits, a slot past the live ones reads zeros. */
export class ApprovalTotals {
  readonly outputs: readonly OutputTotals[];
  readonly publicSlots: readonly PublicTotals[];

  /** `slotAssets` holds `undefined` on a dummy slot, `publicSlots` follows the statement's order. */
  constructor(
    input: Readonly<{
      transfer: DebitTransfer;
      slotAssets: readonly (Bytes32 | undefined)[];
      publicSlots: readonly PublicGross[];
    }>,
  ) {
    const { transfer } = input;
    const owners = orderedOwners(transfer);
    this.outputs = Object.freeze(
      input.slotAssets.map((asset) =>
        asset === undefined
          ? Object.freeze({ asset: ZERO_32, peak: 0n, outflow: 0n })
          : Object.freeze({
              asset,
              ...peakAndSum(assetFlows(transfer, owners, asset).map((row) => row.outflow)),
            }),
      ),
    );
    this.publicSlots = Object.freeze(
      input.publicSlots.map(({ asset, gross }) =>
        Object.freeze({
          asset,
          ...peakAndSum(assetFlows(transfer, owners, asset).map((row) => row.debit)),
          gross,
        }),
      ),
    );
    Object.freeze(this);
  }

  /** Zero when no slot names `asset`. */
  peakOf(asset: Bytes32): bigint {
    return this.#largest(asset, (slot) => slot.peak);
  }

  /** Zero when no slot names `asset`. */
  outflowOf(asset: Bytes32): bigint {
    return this.#largest(asset, (slot) => slot.outflow);
  }

  /** The frame's `approvalTotals` extension, the blinder fresh per transaction. */
  commitment(blinder: Bytes32): Bytes32 {
    return hashChain4([
      amountField(APPROVAL_TOTALS_DOMAIN),
      blinder,
      ...this.outputs.flatMap((slot) => [
        slot.asset,
        amountField(slot.peak),
        amountField(slot.outflow),
      ]),
      ...this.publicSlots.flatMap((slot) => [
        slot.asset,
        amountField(slot.peak),
        amountField(slot.outflow),
        amountField(slot.gross),
      ]),
    ]) as Bytes32;
  }

  #largest(asset: Bytes32, read: (slot: OutputTotals) => bigint): bigint {
    return [...this.outputs, ...this.publicSlots]
      .filter((slot) => equalBytes(slot.asset, asset))
      .map(read)
      .reduce((largest, value) => (value > largest ? value : largest), 0n);
  }
}

function peakAndSum(values: readonly bigint[]): Readonly<{ peak: bigint; outflow: bigint }> {
  return values.reduce(
    ({ peak, outflow }, value) => ({
      peak: value > peak ? value : peak,
      outflow: outflow + value,
    }),
    { peak: 0n, outflow: 0n },
  );
}

function amountField(value: bigint): Bytes32 {
  return bigIntBytes(value) as Bytes32;
}
