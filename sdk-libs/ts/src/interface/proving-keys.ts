import { type ExpectedProvingKey } from "@heliuslabs/zolana/internal";
import { InterfaceError } from "@heliuslabs/zolana/interface";

import { RING_PROVING_KEY_SHA256S } from "./ring-proving-keys.js";
import {
  ANONYMOUS_AUDIT_CLASSES,
  ANONYMOUS_ENTRY_CLASS,
  ANONYMOUS_ENTRY_OUTPUTS,
  DELIVERED_AUDIT_CAPACITIES,
  PACKED_AUDIT_CAPACITIES,
} from "./ring-disclosure-layout.js";
import { RING_AUTHORITY_SHAPES } from "./spp.js";

export { RING_PROVING_KEY_SHA256S };

/** A ring circuit by the shape its key serves, Rust `RingCircuit`. */
export type RingKeyCircuit =
  | Readonly<{ family: "packedAudit"; outputs: number }>
  | Readonly<{ family: "deliveredAudit"; outputs: number }>
  | Readonly<{ family: "anonymousAudit"; inputClass: number; outputs: number }>
  /** Opens every spent UTXO, the key of a transfer spending a default-ring note. */
  | Readonly<{ family: "anonymousEntryAudit"; inputClass: number; outputs: number }>
  | Readonly<{ family: "memberPolicy"; outputs: number }>
  | Readonly<{ family: "delegatePolicy"; inputs: number; outputs: number }>
  | Readonly<{ family: "applyRecords"; writes: number }>
  | Readonly<{ family: "registerKey" }>
  | Readonly<{ family: "deposit" }>
  | Readonly<{ family: "anonymousMerge"; width: number }>;

/** Rust `RING_KEYS`, every ring key in its order, `name` the circuit type the prover serves. */
export const RING_KEYS: readonly Readonly<{
  circuit: RingKeyCircuit;
  name: string;
}>[] = Object.freeze(
  (
    [
      ...PACKED_AUDIT_CAPACITIES.map(
        (outputs) =>
          [{ family: "packedAudit", outputs }, `custom-ring-audit-packed-${outputs}`] as const,
      ),
      ...DELIVERED_AUDIT_CAPACITIES.map(
        (outputs) =>
          [
            { family: "deliveredAudit", outputs },
            `custom-ring-audit-delivered-${outputs}`,
          ] as const,
      ),
      ...ANONYMOUS_AUDIT_CLASSES.flatMap(({ outputs, classes }) =>
        classes.map(
          (inputClass) =>
            [
              { family: "anonymousAudit", inputClass, outputs },
              `custom-ring-audit-anonymous-${inputClass}-${outputs}`,
            ] as const,
        ),
      ),
      ...ANONYMOUS_ENTRY_OUTPUTS.map(
        (outputs) =>
          [
            { family: "anonymousEntryAudit", inputClass: ANONYMOUS_ENTRY_CLASS, outputs },
            `custom-ring-audit-anonymous-entry-${ANONYMOUS_ENTRY_CLASS}-${outputs}`,
          ] as const,
      ),
      [{ family: "memberPolicy", outputs: 2 }, "custom-ring-policy-member-2"],
      [{ family: "memberPolicy", outputs: 4 }, "custom-ring-policy-member-4"],
      [{ family: "memberPolicy", outputs: 8 }, "custom-ring-policy-member-8"],
      [{ family: "memberPolicy", outputs: 16 }, "custom-ring-policy-member-16"],
      // Go `ringKeys` sizes the delegate keys by the SPP ring authority rule.
      ...RING_AUTHORITY_SHAPES.map(
        ({ inputs, outputs }) =>
          [
            { family: "delegatePolicy", inputs, outputs },
            `custom-ring-policy-delegate-${inputs}x${outputs}`,
          ] as const,
      ),
      [{ family: "applyRecords", writes: 1 }, "custom-ring-apply-records-1"],
      [{ family: "applyRecords", writes: 16 }, "custom-ring-apply-records-16"],
      [{ family: "registerKey" }, "custom-ring-register-key"],
      [{ family: "deposit" }, "custom-ring-deposit"],
      [{ family: "anonymousMerge", width: 8 }, "custom-ring-merge-anonymous-8"],
      [{ family: "anonymousMerge", width: 24 }, "custom-ring-merge-anonymous-24"],
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
    case "packedAudit":
    case "deliveredAudit":
    case "memberPolicy":
      return right.family === left.family && right.outputs === left.outputs;
    case "anonymousAudit":
    case "anonymousEntryAudit":
      return (
        right.family === left.family &&
        right.inputClass === left.inputClass &&
        right.outputs === left.outputs
      );
    case "delegatePolicy":
      return (
        right.family === left.family &&
        right.inputs === left.inputs &&
        right.outputs === left.outputs
      );
    case "applyRecords":
      return right.family === left.family && right.writes === left.writes;
    case "anonymousMerge":
      return right.family === left.family && right.width === left.width;
    case "registerKey":
    case "deposit":
      return right.family === left.family;
  }
}
