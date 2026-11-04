import { InstructionTag } from "@heliuslabs/zolana/interface";

/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  // Tags 1 and 2 are retired, never reuse them.
  legacyTransact: 3,
  /** Decoding only, the program refuses it. */
  historicalTransfer: 43,
  /** Decoding only, the program refuses it. */
  historicalTransferV3: 45,
  transfer: 55,
  // Tag 18 is retired, never reuse it.
  /** Decoding only, the program refuses it. */
  historicalMerge: InstructionTag.ringMergeTransact,
  /** Decoding only, the program refuses it. */
  historicalMergeV3: 47,
  merge: 57,
  // Tags 4 and 5 are retired, never reuse them.
  updateAuthority: 6,
  // Tags 7 to 10 and 12 are retired, never reuse them.
  setPaused: 11,
  setCoSigner: 27,
  clearCoSigner: 21,
  // Tags 22, 23 and 26 are retired, never reuse them.
  setDelegate: 24,
  legacyDelegateTransact: 25,
  /** Decoding only, the program refuses it. */
  historicalAuthorityTransfer: 44,
  /** Decoding only, the program refuses it. */
  historicalAuthorityTransferV3: 46,
  authorityTransfer: 56,
  // Tags 28 to 30 are retired, never reuse them.
  /** Decoding only, the program refuses it. */
  historicalDeposit: 31,
  deposit: 58,
  // Tags 32 to 42 and 48 are retired, never reuse them.
  initialize: 53,
  updatePolicy: 54,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];
