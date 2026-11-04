import { describe, expect, it } from "vitest";

import vector from "../../../../../test-vectors/settlement/frame_buffer.json" with { type: "json" };
import type { Address } from "@heliuslabs/zolana/interface";

import {
  closeFrameBufferData,
  FRAME_BUFFER_HEADER_LEN,
  FRAME_BUFFER_PDA_SEED,
  frameDigest,
  MAX_FRAME_LEN,
  settleBufferedData,
  settledFrame,
  writeFrameData,
} from "../../../src/protocol/transaction/frame-buffer.js";

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const bytes = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));
const frame = bytes(vector.frame);
const RING = "ring" as Address;
const honest = {
  ringProgram: RING,
  settleProgram: RING,
  eventProgram: RING,
  succeeded: true,
  settle: bytes(vector.settle),
  event: bytes(vector.event),
};

describe("frame_buffer.json", () => {
  it("builds the wire Rust pins", () => {
    expect(hex(FRAME_BUFFER_PDA_SEED)).toBe(vector.seed);
    expect(FRAME_BUFFER_HEADER_LEN).toBe(vector.header_len);
    expect(MAX_FRAME_LEN).toBe(vector.max_frame_len);
    expect(
      hex(writeFrameData({ nonce: 7n, frameLen: 6, offset: 2, bytes: frame.subarray(2) })),
    ).toBe(vector.write);
    expect(hex(closeFrameBufferData())).toBe(vector.close);
    expect(hex(settleBufferedData(frameDigest(frame)))).toBe(vector.settle);
  });

  it("takes the frame from a successful ring settlement that signed it", () => {
    expect(hex(settledFrame(honest))).toBe(vector.frame);
  });

  it("refuses a forged frame, another tag, another program and a failed settlement", () => {
    const flipped = (value: Uint8Array, at: number) => {
      const copy = value.slice();
      copy[at] = (copy[at] ?? 0) ^ 1;
      return copy;
    };
    for (const refused of [
      { event: flipped(honest.event, 3) },
      { event: flipped(honest.event, 0) },
      { settle: flipped(honest.settle, 0) },
      { settle: Uint8Array.of(...honest.settle, 0) },
      { settleProgram: "other" as Address },
      { eventProgram: "other" as Address },
      { succeeded: false },
    ])
      expect(() => settledFrame({ ...honest, ...refused })).toThrow(
        expect.objectContaining({ code: "RING_FRAME_EVENT_INVALID" }),
      );
  });
});
