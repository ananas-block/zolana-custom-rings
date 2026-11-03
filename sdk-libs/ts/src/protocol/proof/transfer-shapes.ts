/** The transfer key catalog, Rust `key_catalog.rs` and the shape lists in `prover/circuits/transfer`. */
import type { RingRail } from "../transaction/transact.js";
import { N_PUBLIC_SLOTS } from "../transaction/spp.js";

/** One transfer family at one output count, Rust `TransferShape`. */
export interface TransferShape {
  readonly outputs: number;
  /** The input slots the key opens, the widest published input count it serves. */
  readonly inputs: number;
  /** The withdrawal leg capacities keyed at the output count, ascending. */
  readonly withdrawals: readonly number[];
}

const shape = (outputs: number, inputs: number, withdrawals: readonly number[]): TransferShape =>
  Object.freeze({ outputs, inputs, withdrawals: Object.freeze(withdrawals) });

/** The signer, in-proof and authority rails. */
export const CONFIDENTIAL_TRANSFER_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(2, 24, [4, 32]),
  shape(4, 24, [4, 32]),
  shape(8, 16, [4, 32]),
  shape(16, 5, [8]),
]);
/** The anonymous rail over ring notes. */
export const ANONYMOUS_TRANSFER_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(2, 24, [4, 32]),
  shape(4, 16, [4, 32]),
  shape(8, 5, [24]),
]);
/** The anonymous rail spending a default-ring note, every input opened. */
export const ENTRY_TRANSFER_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(2, 8, [4]),
  shape(4, 8, [4]),
  shape(8, 2, [4]),
]);

/** A transfer key, Rust `RingCircuit::Transfer*`. */
export type TransferKeyCircuit =
  | Readonly<{
      family: "transferConfidential";
      outputs: number;
      inputs: number;
      withdrawals: number;
    }>
  | Readonly<{ family: "transferAnonymous"; outputs: number; class: number; withdrawals: number }>
  | Readonly<{
      family: "transferAnonymousEntry";
      outputs: number;
      class: number;
      withdrawals: number;
    }>;

/** What selects a transfer key, every count the frame fixes, Rust `TransferSpend`. */
export interface TransferSpend {
  readonly rail: RingRail;
  /** Published inputs, the spent notes. */
  readonly inputs: number;
  readonly outputs: number;
  /** A spent note of the default ring, the anonymous entry layout. */
  readonly spendsDefaultRing: boolean;
  /** Public withdrawal legs. */
  readonly legs: number;
}

/** The one transfer key serving the spend, `undefined` when the catalog keys none, Rust `RingCircuit::transfer`. */
export function ringTransferCircuit(spend: TransferSpend): TransferKeyCircuit | undefined {
  const family = transferFamily(spend.rail, spend.spendsDefaultRing);
  const keyed = family === undefined ? undefined : familyShapes(family);
  const found = keyed?.find((entry) => entry.outputs === spend.outputs);
  if (family === undefined || found === undefined) return undefined;
  if (!Number.isInteger(spend.inputs) || spend.inputs < 1 || spend.inputs > found.inputs)
    return undefined;
  if (!Number.isInteger(spend.legs) || spend.legs < 0) return undefined;
  const withdrawals = found.withdrawals.find((capacity) => capacity >= spend.legs);
  if (withdrawals === undefined) return undefined;
  return family === "transferConfidential"
    ? Object.freeze({ family, outputs: found.outputs, inputs: found.inputs, withdrawals })
    : Object.freeze({ family, outputs: found.outputs, class: found.inputs, withdrawals });
}

export function familyShapes(family: TransferKeyCircuit["family"]): readonly TransferShape[] {
  switch (family) {
    case "transferConfidential":
      return CONFIDENTIAL_TRANSFER_SHAPES;
    case "transferAnonymous":
      return ANONYMOUS_TRANSFER_SHAPES;
    case "transferAnonymousEntry":
      return ENTRY_TRANSFER_SHAPES;
  }
}

export function transferInputClass(circuit: TransferKeyCircuit): number {
  return circuit.family === "transferConfidential" ? circuit.inputs : circuit.class;
}

/** Record pool widths, each subject pool as wide. */
export interface PolicyPoolCapacity {
  readonly own: number;
  readonly curator: number;
}

/** `Q`, the owners one transfer key screens, entry keys spend for one owner. */
export function screenedOwners(circuit: TransferKeyCircuit): number {
  return circuit.family === "transferAnonymousEntry" ? 1 : 4;
}

/** `S`, the SPP owner signers one transfer key binds, entry keys refuse a nonempty run. */
export function signerSlots(circuit: TransferKeyCircuit): number {
  return circuit.family === "transferAnonymousEntry" ? 0 : transferInputClass(circuit);
}

/** Go `PolicyInputs.recordCapacity`, Rust `RingCircuit::record_pools`. */
export function transferPoolCapacity(circuit: TransferKeyCircuit): PolicyPoolCapacity {
  // Withdrawals settle through the public slots, their assets are at most N_PUBLIC_SLOTS.
  const withdrawalAssets = Math.min(circuit.withdrawals, N_PUBLIC_SLOTS);
  const distinct = screenedOwners(circuit) + 2 * circuit.outputs + circuit.withdrawals;
  return Object.freeze({
    own: distinct + Math.max(withdrawalAssets, N_PUBLIC_SLOTS),
    curator: distinct + withdrawalAssets,
  });
}

/** The circuit type the prover serves the key under, Go `Key.Circuit`. */
export function transferCircuitType(circuit: TransferKeyCircuit): string {
  const family =
    circuit.family === "transferConfidential"
      ? "confidential"
      : circuit.family === "transferAnonymous"
        ? "anonymous"
        : "anonymous-entry";
  return `custom-ring-transfer-${family}-${circuit.outputs}-in${transferInputClass(circuit)}-w${circuit.withdrawals}`;
}

/** Every transfer key in the catalog's order, each family's shapes then their capacities ascending. */
export function transferKeys(): readonly TransferKeyCircuit[] {
  const families: readonly TransferKeyCircuit["family"][] = [
    "transferConfidential",
    "transferAnonymous",
    "transferAnonymousEntry",
  ];
  return families.flatMap((family) =>
    familyShapes(family).flatMap((entry) =>
      entry.withdrawals.map((withdrawals): TransferKeyCircuit =>
        family === "transferConfidential"
          ? Object.freeze({ family, outputs: entry.outputs, inputs: entry.inputs, withdrawals })
          : Object.freeze({ family, outputs: entry.outputs, class: entry.inputs, withdrawals }),
      ),
    ),
  );
}

function transferFamily(
  rail: RingRail,
  spendsDefaultRing: boolean,
): TransferKeyCircuit["family"] | undefined {
  if (rail === "anonymous")
    return spendsDefaultRing ? "transferAnonymousEntry" : "transferAnonymous";
  return spendsDefaultRing ? undefined : "transferConfidential";
}
