import { InstructionTag } from "@heliuslabs/zolana/interface";

/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  transfer: 45,
  legacyTransact: 3,
  legacyDelegateTransact: 25,
  // Tags 4 and 5 are retired, never reuse them.
  updateAuthority: 6,
  setPaused: 11,
  clearCoSigner: 21,
  merge: 47,
  setDelegate: 24,
  authorityTransfer: 46,
  /** Decoding only, the program refuses it. */
  historicalTransfer: 43,
  /** Decoding only, the program refuses it. */
  historicalAuthorityTransfer: 44,
  /** Decoding only, the program refuses it. */
  historicalMerge: InstructionTag.ringMergeTransact,
  setCoSigner: 27,
  // Tags 28 and 29 are retired, never reuse them.
  deposit: 31,
  // Tags 39 to 42 are retired, never reuse them.
  // Tag 48 is retired, never reuse it.
  initialize: 53,
  updatePolicy: 54,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];
