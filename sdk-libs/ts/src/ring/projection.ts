import type { RingErrorCode } from "./error.js";

export const KEY_REGISTRY_PROJECTION_ERRORS: ReadonlySet<string> = new Set<RingErrorCode>([
  "RING_KEY_REGISTRY_OUT_OF_SYNC",
  "RING_KEY_REGISTRY_ROOT_CHANGED",
]);

export const SPEND_RECORD_PROJECTION_ERRORS: ReadonlySet<string> = new Set<RingErrorCode>([
  "RING_SPEND_RECORD_OUT_OF_SYNC",
]);
