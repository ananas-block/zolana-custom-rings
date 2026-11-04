import { describe, expect, it } from "vitest";

import vector from "../../../../../test-vectors/settlement/frame_buffer.json" with { type: "json" };
import { AccountRole } from "@solana/kit";
import type { Address, Instruction } from "@heliuslabs/zolana/interface";
import { encodeBase58 } from "@heliuslabs/zolana/internal";

import { ringComputeUnitLimit } from "../../../src/operations/management/admin.js";
import { BufferedFrame } from "../../../src/operations/payments/buffered-frame.js";
import { transactionSize } from "../../../src/operations/workflow/compile.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";

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

describe("BufferedFrame", () => {
  const WRITER = encodeBase58(new Uint8Array(32).fill(7)) as Address;
  const PROGRAM = encodeBase58(new Uint8Array(32).fill(9)) as Address;
  const inline = (length: number, tag: number = RingInstructionTag.transfer): Instruction => {
    const data = Uint8Array.from({ length }, (_, index) => index % 251);
    data[0] = tag;
    return {
      programAddress: PROGRAM,
      accounts: [{ address: WRITER, role: AccountRole.WRITABLE_SIGNER }],
      data,
    };
  };

  it("writes rebuild the frame and each fits one transaction", async () => {
    const frame = inline(MAX_FRAME_LEN);
    const writes = (await BufferedFrame.of(frame, WRITER, 3n)).writes();
    expect(writes.length).toBeGreaterThan(1);
    const rebuilt = new Uint8Array(MAX_FRAME_LEN);
    for (const write of writes) {
      const size = transactionSize({
        feePayer: WRITER,
        instructions: [write],
        computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.writeFrame),
      });
      expect(size.bytes).toBeLessThanOrEqual(4096);
      const data = write.data as Uint8Array;
      const view = new DataView(data.buffer, data.byteOffset);
      expect(data[0]).toBe(RingInstructionTag.writeFrame);
      expect(view.getBigUint64(1, true)).toBe(3n);
      expect(view.getUint16(9, true)).toBe(MAX_FRAME_LEN);
      rebuilt.set(data.subarray(13), view.getUint16(11, true));
    }
    expect(rebuilt).toEqual(frame.data);
  });

  it("settles on the digest ahead of the transfer accounts and closes to the writer", async () => {
    const frame = inline(5000);
    const buffered = await BufferedFrame.of(frame, WRITER, 0n);
    const settle = buffered.settle();
    expect(settle.data).toEqual(settleBufferedData(frameDigest(frame.data as Uint8Array)));
    expect(settle.accounts?.[0]?.address).toBe(buffered.buffer);
    expect(settle.accounts?.[1]?.address).toBe(PROGRAM);
    expect(settle.accounts?.slice(2)).toEqual(frame.accounts);
    const close = buffered.close();
    expect(close.data).toEqual(closeFrameBufferData());
    expect(close.accounts?.[0]).toMatchObject({
      address: WRITER,
      role: AccountRole.WRITABLE_SIGNER,
    });
  });

  it("admits a delegate frame", async () => {
    const buffered = await BufferedFrame.of(
      inline(5000, RingInstructionTag.authorityTransfer),
      WRITER,
      0n,
    );
    expect(buffered.settle().data?.[0]).toBe(RingInstructionTag.settleBuffered);
  });

  it("has no buffer past the CPI limit or for another tag", async () => {
    await expect(BufferedFrame.of(inline(MAX_FRAME_LEN + 1), WRITER, 0n)).rejects.toMatchObject({
      code: "RING_FRAME_TOO_LARGE",
    });
    await expect(
      BufferedFrame.of(inline(10, RingInstructionTag.merge), WRITER, 0n),
    ).rejects.toMatchObject({ code: "RING_BUFFERED_TAG" });
    await expect(BufferedFrame.of(inline(10), WRITER, 1n << 64n)).rejects.toMatchObject({
      code: "RING_BUFFERED_NONCE",
    });
  });
});
