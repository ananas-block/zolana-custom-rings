/** Rust `tag`, the first byte of the ring program's instruction data. */
export const RingInstructionTag = Object.freeze({
  transfer: 55,
  merge: 57,
  updateAuthority: 6,
  setPaused: 11,
  setCoSigner: 27,
  clearCoSigner: 21,
  setDelegate: 24,
  authorityTransfer: 56,
  deposit: 58,
  initialize: 53,
  updatePolicy: 54,
  writeFrame: 59,
  closeFrameBuffer: 60,
  settleBuffered: 61,
  /** Readers accept it only inside `settleBuffered`. */
  frameEvent: 63,
} as const);
export type RingInstructionTag = (typeof RingInstructionTag)[keyof typeof RingInstructionTag];
