/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  // Tags 1 to 3 are retired, never reuse them.
  transfer: 55,
  // Tags 18, 20 and 43 to 47 are retired, never reuse them.
  merge: 57,
  // Tags 4 and 5 are retired, never reuse them.
  updateAuthority: 6,
  // Tags 7 to 10 and 12 are retired, never reuse them.
  setPaused: 11,
  setCoSigner: 27,
  clearCoSigner: 21,
  // Tags 22, 23 and 26 are retired, never reuse them.
  setDelegate: 24,
  // Tag 25 is retired, never reuse it.
  authorityTransfer: 56,
  // Tags 28 to 31 are retired, never reuse them.
  deposit: 58,
  // Tags 32 to 42 and 48 are retired, never reuse them.
  initialize: 53,
  updatePolicy: 54,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];
