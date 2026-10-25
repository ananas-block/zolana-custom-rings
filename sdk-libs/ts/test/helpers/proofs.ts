import { RING_PROVING_KEY_SHA256S } from "../../src/protocol/proving-keys.js";
import { proofFor as sppProofFor } from "../../../../zolana/sdk-libs/ts/test/helpers/proofs.js";

const ZERO_POINT = ["0x0", "0x0"];

/** `sppProofFor` that also answers the ring circuits, `custom-ring-<x>` proves with `custom_ring_<x>.key`. */
export function proofFor(body: unknown): Record<string, unknown> {
  const request = (typeof body === "string" ? JSON.parse(body) : body) as Record<string, unknown>;
  const name = `${String(request["circuitType"]).replaceAll("-", "_")}.key`;
  const sha256 = Object.entries(RING_PROVING_KEY_SHA256S).find(([key]) => key === name)?.[1];
  if (sha256 === undefined) return sppProofFor(request);
  return {
    ar: ZERO_POINT,
    bs: [ZERO_POINT, ZERO_POINT],
    krs: ZERO_POINT,
    provingKeySha256: sha256,
  };
}
