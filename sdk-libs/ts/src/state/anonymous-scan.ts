/** The scan's candidate step over plain bytes, a `Worker` runs it as the key's holder. */
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes16, Bytes32 } from "@heliuslabs/zolana/interface";
import { ViewingKey, X25519PublicKey } from "@heliuslabs/zolana/keypair";

import {
  ViewingKeyHolder,
  type RingKeys,
  type RingTagFrame,
  type RingTagProbe,
} from "./ring-keys.js";

/** A tag frame that survives a structured clone, the worker's one key implied. */
export interface PlainTagFrame {
  readonly txViewingKey: Uint8Array;
  readonly salt: Bytes16;
  readonly firstNullifier: Bytes32;
  readonly probes: readonly RingTagProbe[];
}

export interface ScanWorkerRequest {
  readonly viewingSecret: Bytes32;
  readonly frames: readonly PlainTagFrame[];
}

/** Per frame one answer per probe, the slot secret on a match. */
export type ScanWorkerReply = readonly (readonly (Bytes32 | undefined)[])[];

export function plainTagFrame(frame: RingTagFrame): PlainTagFrame {
  return {
    txViewingKey: frame.txViewingPublicKey.toBytes(),
    salt: frame.salt,
    firstNullifier: frame.firstNullifier,
    probes: frame.probes,
  };
}

/** A worker entry runs it on each message, the request's secret wiped once answered. */
export async function answerScanRequest(request: ScanWorkerRequest): Promise<ScanWorkerReply> {
  await initializePoseidon();
  const key = ViewingKey.fromBytes(request.viewingSecret);
  const viewingPublicKey = key.publicKey();
  const holder = new ViewingKeyHolder([key]);
  try {
    return await holder.ringTagMatches(
      request.frames.map((frame) => ({
        viewingPublicKey,
        txViewingPublicKey: X25519PublicKey.fromBytes(frame.txViewingKey),
        salt: frame.salt,
        firstNullifier: frame.firstNullifier,
        probes: frame.probes,
      })),
    );
  } finally {
    holder.destroy();
    request.viewingSecret.fill(0);
  }
}

/** Sends a sync's tag test to `ask`, a sync names one viewing key per call. */
export function scanWorkerMatcher(
  ask: (
    viewingPublicKey: X25519PublicKey,
    frames: readonly PlainTagFrame[],
  ) => Promise<ScanWorkerReply>,
): Pick<RingKeys, "ringTagMatches"> {
  return {
    ringTagMatches: async (frames) => {
      const [first] = frames;
      return first === undefined ? [] : ask(first.viewingPublicKey, frames.map(plainTagFrame));
    },
  };
}
