/** The transfer key catalog, Rust `key_catalog.rs` and the shape lists in `prover/circuits/transfer`. */
import type { RingRail } from "../transaction/transact.js";
import { N_PUBLIC_SLOTS } from "../transaction/spp.js";

/** One transfer family at one output count, Rust `TransferShape`. */
export interface TransferShape {
  readonly outputs: number;
  /** The widest published input count the key serves. */
  readonly inputs: number;
  /** Keyed leg capacities, ascending. */
  readonly withdrawals: readonly number[];
  /** Keyed owner rows, ascending, `[small, wide]` or `[small]` where the shape has one. */
  readonly owners: readonly number[];
}

const shape = (
  outputs: number,
  inputs: number,
  withdrawals: readonly number[],
  owners: readonly number[],
): TransferShape =>
  Object.freeze({
    outputs,
    inputs,
    withdrawals: Object.freeze(withdrawals),
    owners: Object.freeze(owners),
  });

/** The signer, in-proof and authority rails. */
export const CONFIDENTIAL_TRANSFER_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(2, 24, [4, 32], [4, 24]),
  shape(4, 24, [4, 32], [4, 24]),
  shape(8, 16, [4, 32], [4, 16]),
  shape(16, 5, [8], [4, 5]),
]);
/** The hidden sender, public owner and authority rails over ring notes. */
export const ANONYMOUS_TRANSFER_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(2, 24, [4, 32], [4, 24]),
  shape(4, 16, [4, 32], [4, 16]),
  shape(8, 5, [24], [4, 5]),
]);
/** Spending a default-ring note, on the owner rails. */
export const ENTRY_TRANSFER_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(2, 8, [4], [4, 8]),
  shape(4, 8, [4], [4, 8]),
  shape(8, 2, [4], [2]),
]);

export type TransferFamilyName =
  | "transferConfidential"
  | "transferConfidentialEntry"
  | "transferAnonymous"
  | "transferAnonymousEntry";

/** A transfer key, Rust `RingCircuit::Transfer*`. */
export interface TransferKeyCircuit {
  readonly family: TransferFamilyName;
  readonly outputs: number;
  /** The input class, the widest published input count. */
  readonly class: number;
  readonly withdrawals: number;
  /** Owner rows the key opens. */
  readonly owners: number;
  /** One tail per published slot. */
  readonly data: boolean;
}

/** What selects a transfer key, Rust `TransferSpend`. */
export interface TransferSpend {
  readonly rail: RingRail;
  /** Published inputs, the spent notes. */
  readonly inputs: number;
  readonly outputs: number;
  readonly spendsDefaultRing: boolean;
  /** Public withdrawal legs. */
  readonly legs: number;
  /** Distinct live input owners. */
  readonly owners: number;
  /** The frame carries data tails. */
  readonly hasData: boolean;
}

/** `undefined` on the delegate rails spending a default-ring note, Rust `TransferShape::family`. */
export function transferShapes(
  rail: RingRail,
  entry: boolean,
): readonly TransferShape[] | undefined {
  const family = transferFamily(rail, entry);
  return family === undefined ? undefined : familyShapes(family);
}

/** The one transfer key serving the spend, `undefined` when the catalog keys none, Rust `RingCircuit::transfer`. */
export function ringTransferCircuit(spend: TransferSpend): TransferKeyCircuit | undefined {
  const family = transferFamily(spend.rail, spend.spendsDefaultRing);
  const found =
    family === undefined
      ? undefined
      : familyShapes(family).find((entry) => entry.outputs === spend.outputs);
  if (family === undefined || found === undefined) return undefined;
  if (!Number.isInteger(spend.inputs) || spend.inputs < 1 || spend.inputs > found.inputs)
    return undefined;
  if (!Number.isInteger(spend.legs) || spend.legs < 0) return undefined;
  if (!Number.isInteger(spend.owners) || spend.owners < 0) return undefined;
  const withdrawals = found.withdrawals.find((capacity) => capacity >= spend.legs);
  const owners = found.owners.find((capacity) => capacity >= spend.owners);
  if (withdrawals === undefined || owners === undefined) return undefined;
  return Object.freeze({
    family,
    outputs: found.outputs,
    class: found.inputs,
    withdrawals,
    owners,
    data: spend.hasData,
  });
}

export function familyShapes(family: TransferFamilyName): readonly TransferShape[] {
  switch (family) {
    case "transferConfidential":
      return CONFIDENTIAL_TRANSFER_SHAPES;
    case "transferAnonymous":
      return ANONYMOUS_TRANSFER_SHAPES;
    case "transferConfidentialEntry":
    case "transferAnonymousEntry":
      return ENTRY_TRANSFER_SHAPES;
  }
}

export function transferInputClass(circuit: TransferKeyCircuit): number {
  return circuit.class;
}

/** Rust `RecordPools`, each subject pool as wide as its record pool. */
export interface PolicyPoolCapacity {
  readonly own: number;
  readonly curator: number;
  readonly tracking: number;
}

/** `S`, the owner signer slots of a key's statement chain, Go `Sections.Signers`. */
export function signerSlots(circuit: TransferKeyCircuit): number {
  return circuit.class;
}

/** Rust `RingCircuit::record_pools`. */
export function transferPoolCapacity(circuit: TransferKeyCircuit): PolicyPoolCapacity {
  // Withdrawals settle through the public slots, their assets are at most N_PUBLIC_SLOTS.
  const withdrawalAssets = Math.min(circuit.withdrawals, N_PUBLIC_SLOTS);
  const distinct = circuit.owners + 2 * circuit.outputs + circuit.withdrawals;
  return Object.freeze({
    own: distinct + Math.max(withdrawalAssets, N_PUBLIC_SLOTS),
    curator: distinct + withdrawalAssets,
    tracking: circuit.owners + circuit.outputs,
  });
}

/** The circuit type the prover serves the key under, Go `Key.circuitType`. */
export function transferCircuitType(circuit: TransferKeyCircuit): string {
  const family = {
    transferConfidential: "confidential",
    transferConfidentialEntry: "confidential-entry",
    transferAnonymous: "anonymous",
    transferAnonymousEntry: "anonymous-entry",
  }[circuit.family];
  const suffix = circuit.data ? "-data" : "";
  return `custom-ring-transfer-${family}-${circuit.outputs}-in${circuit.class}-w${circuit.withdrawals}-s${circuit.owners}${suffix}`;
}

/** Every transfer key in the catalog's order, Go `keys`. */
export function transferKeys(): readonly TransferKeyCircuit[] {
  const families: readonly TransferFamilyName[] = [
    "transferConfidential",
    "transferConfidentialEntry",
    "transferAnonymous",
    "transferAnonymousEntry",
  ];
  return families.flatMap((family) =>
    familyShapes(family).flatMap((entry) =>
      entry.withdrawals.flatMap((withdrawals) =>
        entry.owners.flatMap((owners) =>
          [false, true].map((data): TransferKeyCircuit =>
            Object.freeze({
              family,
              outputs: entry.outputs,
              class: entry.inputs,
              withdrawals,
              owners,
              data,
            }),
          ),
        ),
      ),
    ),
  );
}

/** Addresses SPP takes beside its nullifier PDAs. */
const SPP_ADDRESSES = 4;
/** Ring program, ring, ring config, own, curator, tracking. */
const RING_ADDRESSES = 6;
/** Rust `MAX_TRANSACTION_ADDRESSES`, the v1 ceiling. */
const MAX_TRANSACTION_ADDRESSES = 64;

/** What takes a v1 transaction's addresses beside its owner signers, Rust `TransferAddresses`. */
export interface TransferAddresses {
  /** The shape's nullifier PDAs. */
  readonly nInputs: number;
  readonly coSigners: number;
  readonly legs: number;
}

/** Contract Output 5, the owner signers that fit, a co-signer takes its record too. */
export function ownerSignerCapacity(addresses: TransferAddresses): number {
  const taken =
    SPP_ADDRESSES + RING_ADDRESSES + addresses.nInputs + 2 * addresses.coSigners + addresses.legs;
  return Math.max(0, MAX_TRANSACTION_ADDRESSES - taken);
}

function transferFamily(rail: RingRail, entry: boolean): TransferFamilyName | undefined {
  switch (rail) {
    case "anonymous":
      return entry ? "transferAnonymousEntry" : "transferAnonymous";
    case "confidential":
      return entry ? "transferConfidentialEntry" : "transferConfidential";
    case "delegate":
      return entry ? undefined : "transferConfidential";
    case "anonymousDelegate":
      return entry ? undefined : "transferAnonymous";
  }
}
