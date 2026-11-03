import { type ExpectedProvingKey } from "@heliuslabs/zolana/internal";
import { InterfaceError } from "@heliuslabs/zolana/interface";

import { RING_PROVING_KEY_SHA256S } from "./ring-proving-keys.js";
import { APPLY_BATCH } from "../membership/member-registry.js";
import { MERGE_WIDTHS } from "../codec/ring-disclosure-layout.js";
import {
  transferCircuitType,
  transferKeys,
  transferPoolCapacity,
  type PolicyPoolCapacity,
  type TransferKeyCircuit,
} from "./transfer-shapes.js";

export { RING_PROVING_KEY_SHA256S };
export { transferPoolCapacity as policyPoolCapacity, type PolicyPoolCapacity };

/** A ring circuit by the shape its key serves, Rust `RingCircuit`. */
export type RingKeyCircuit =
  | TransferKeyCircuit
  | Readonly<{ family: "applyRecords"; writes: number }>
  | Readonly<{ family: "registerKey" }>
  | Readonly<{ family: "deposit"; capacity: number }>
  | Readonly<{ family: "merge"; width: number }>;

/** Rust `RING_KEYS`, every ring key in its order, `name` the circuit type the prover serves. */
export const RING_KEYS: readonly Readonly<{
  circuit: RingKeyCircuit;
  name: string;
}>[] = Object.freeze(
  (
    [
      ...transferKeys().map((circuit) => [circuit, transferCircuitType(circuit)] as const),
      ...[1, 2, 4, 8, APPLY_BATCH].map(
        (writes) =>
          [{ family: "applyRecords", writes }, `custom-ring-apply-records-${writes}`] as const,
      ),
      [{ family: "registerKey" }, "custom-ring-register-key"],
      ...[1, 2, 4, 8].map(
        (capacity) => [{ family: "deposit", capacity }, `custom-ring-deposit-${capacity}`] as const,
      ),
      ...MERGE_WIDTHS.map(
        (width) => [{ family: "merge", width }, `custom-ring-merge-v3-${width}`] as const,
      ),
    ] as const
  ).map(([circuit, name]) =>
    Object.freeze({ circuit: Object.freeze<RingKeyCircuit>(circuit), name }),
  ),
);

/** The circuit type the prover serves `circuit` under, refused for a shape no ring key serves. */
export function ringCircuitType(circuit: RingKeyCircuit): string {
  const key = RING_KEYS.find((entry) => sameRingCircuit(entry.circuit, circuit));
  if (key === undefined)
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", {
      circuit: circuit.family,
    });
  return key.name;
}

/** The ring key a proof must come from, the file name Go `RingKeyFile` derives from the circuit type. */
export function ringProvingKey(circuit: RingKeyCircuit): ExpectedProvingKey {
  return pinnedProvingKey(`${ringCircuitType(circuit).replaceAll("-", "_")}.key`, circuit.family);
}

/** A key without a pin has no committed verifying key, the program refuses its proofs. */
function pinnedProvingKey(name: string, circuit: string): ExpectedProvingKey {
  const sha256 = Object.hasOwn(RING_PROVING_KEY_SHA256S, name)
    ? RING_PROVING_KEY_SHA256S[name]
    : undefined;
  if (sha256 === undefined) throw new InterfaceError("INTERFACE_INVALID_SHAPE", { circuit });
  return Object.freeze({ name, sha256 });
}

function sameRingCircuit(left: RingKeyCircuit, right: RingKeyCircuit): boolean {
  switch (left.family) {
    case "transferConfidential":
      return (
        right.family === left.family &&
        right.outputs === left.outputs &&
        right.inputs === left.inputs &&
        right.withdrawals === left.withdrawals
      );
    case "transferAnonymous":
    case "transferAnonymousEntry":
      return (
        right.family === left.family &&
        right.outputs === left.outputs &&
        right.class === left.class &&
        right.withdrawals === left.withdrawals
      );
    case "applyRecords":
      return right.family === left.family && right.writes === left.writes;
    case "merge":
      return right.family === left.family && right.width === left.width;
    case "registerKey":
      return right.family === left.family;
    case "deposit":
      return right.family === left.family && right.capacity === left.capacity;
  }
}
