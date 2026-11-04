/** Rust `custom_ring_interface::accounts::frame_buffer`. */
import { equalBytes, sha256 } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";

import { RingError } from "../error.js";
import { RingInstructionTag } from "./instruction-tag.js";

export const FRAME_BUFFER_PDA_SEED = new TextEncoder().encode("frame_buffer");
export const FRAME_BUFFER_HEADER_LEN = 34;
/** The runtime's ceiling on an inner create and on CPI instruction data. */
export const MAX_CPI_DATA_LEN = 10 * 1024;
export const MAX_FRAME_LEN = MAX_CPI_DATA_LEN - FRAME_BUFFER_HEADER_LEN;

const FRAME_BUFFER_DISCRIMINATOR = 16;

export function bufferedFrame(account: Uint8Array): Uint8Array | undefined {
  return account.length < FRAME_BUFFER_HEADER_LEN || account[0] !== FRAME_BUFFER_DISCRIMINATOR
    ? undefined
    : account.subarray(FRAME_BUFFER_HEADER_LEN);
}

/** The account's writer, `undefined` on any other account of the program. */
export function frameBufferWriter(account: Uint8Array): Uint8Array | undefined {
  return bufferedFrame(account) === undefined ? undefined : account.subarray(1, 33);
}

/** The first write creates the buffer at `[seed, writer, nonce]`. */
export interface WriteFrame {
  readonly nonce: bigint;
  /** Read when the write creates the buffer. */
  readonly frameLen: number;
  readonly offset: number;
  readonly bytes: Uint8Array;
}

export function frameDigest(frame: Uint8Array): Bytes32 {
  return sha256(frame) as Bytes32;
}

export function writeFrameData(write: WriteFrame): Uint8Array {
  const data = new Uint8Array(1 + 8 + 2 + 2 + write.bytes.length);
  const view = new DataView(data.buffer);
  data[0] = RingInstructionTag.writeFrame;
  view.setBigUint64(1, write.nonce, true);
  view.setUint16(9, write.frameLen, true);
  view.setUint16(11, write.offset, true);
  data.set(write.bytes, 13);
  return data;
}

export function closeFrameBufferData(): Uint8Array {
  return Uint8Array.of(RingInstructionTag.closeFrameBuffer);
}

/** Every signer of the message signs the digest. */
export function settleBufferedData(digest: Bytes32): Uint8Array {
  return Uint8Array.of(RingInstructionTag.settleBuffered, ...digest);
}

/** The caller takes `event` from the inner instructions of `settle`. */
export function settledFrame(
  input: Readonly<{
    ringProgram: Address;
    settleProgram: Address;
    eventProgram: Address;
    succeeded: boolean;
    settle: Uint8Array;
    event: Uint8Array;
  }>,
): Uint8Array {
  const { settle, event } = input;
  if (
    !input.succeeded ||
    input.settleProgram !== input.ringProgram ||
    input.eventProgram !== input.ringProgram ||
    settle[0] !== RingInstructionTag.settleBuffered ||
    event[0] !== RingInstructionTag.frameEvent
  )
    throw new RingError("RING_FRAME_EVENT_INVALID");
  const frame = event.subarray(1);
  if (!equalBytes(frameDigest(frame), settle.subarray(1)))
    throw new RingError("RING_FRAME_EVENT_INVALID", { details: { reason: "digest" } });
  return frame;
}
