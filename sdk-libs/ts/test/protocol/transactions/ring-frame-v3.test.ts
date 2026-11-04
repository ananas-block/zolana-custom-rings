import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import type { Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";

import { ringFrame, ringInstructionData } from "../../helpers/ring-frame-v3.js";
import { RingError } from "../../../src/protocol/error.js";
import {
  ringTransferStatement,
  signerBinding,
  transferStatementElements,
  type TransferBinding,
} from "../../../src/protocol/historical/v3/statement.js";
import { RingTransactData, type RingOutput } from "../../../src/protocol/historical/v3/frame.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { RECIPIENT_BODY_LEN } from "../../../src/protocol/codec/anonymous-delivery.js";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { hashChain4, Reader, Writer } from "@heliuslabs/zolana/internal";
import {
  mergeDisclosureFieldCount,
  readRingMergeDisclosure,
  writeRingMergeDisclosure,
} from "../../../src/protocol/historical/v3/merge-disclosure.js";

const ZERO = new Uint8Array(32) as Bytes32;
const VECTORS = new URL("../../../../../test-vectors/", import.meta.url);
const AUDITOR = Uint8Array.of(4, ...new Uint8Array(31), 9) as Bytes33;

function binding(signers: readonly Bytes32[] = []): TransferBinding {
  return {
    ringId: ZERO,
    auditorPubkey: AUDITOR,
    keyEscrow: false,
    sender: ZERO,
    partyIdentities: [ZERO, ZERO, ZERO],
    signers,
    roots: { policyHash: ZERO, ownRoot: ZERO, curatorRoot: ZERO },
    publicAssets: [ZERO, ZERO, ZERO],
    publicAmounts: [ZERO, ZERO, ZERO],
    publicGross: [ZERO, ZERO, ZERO],
    withdrawalHash: ZERO,
  };
}

function refusal(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof RingError) return String((error.details as { reason?: string }).reason);
    throw error;
  }
  throw new Error("expected a refusal");
}

const encoded = (frame: RingTransactData): Uint8Array => RingTransactData.encode(frame);

describe("transfer frame", () => {
  it("uses the new tags and carries the published count after the input byte", () => {
    expect(RingInstructionTag.historicalTransferV3).toBe(45);
    expect(RingInstructionTag.historicalAuthorityTransferV3).toBe(46);
    expect(RingInstructionTag.historicalMergeV3).toBe(47);
    const frame = ringFrame({ rail: "confidential", inputs: 2, outputs: 4 });
    expect(ringInstructionData(frame)[0]).toBe(45);
    expect(encoded(frame)[3]).toBe(4);
  });

  it("reads an anonymous frame back with its change prefix and fixed bundle", () => {
    const frame = ringFrame({ rail: "anonymous", inputs: 2, outputs: 2 });
    const parsed = RingTransactData.parse(encoded(frame), "anonymous");
    expect(parsed.outputs.map((output) => output.kind)).toEqual(["change", "anonymous"]);
    expect(parsed.sender?.body.length).toBe(80 + 32 * 2);
    expect(parsed.ownRevision).toBe(1n);
  });

  it("refuses a published count out of range and any other length", () => {
    const bytes = encoded(ringFrame({ rail: "confidential", inputs: 2, outputs: 2 }));
    const zeroSlots = bytes.slice();
    zeroSlots[3] = 0;
    expect(refusal(() => RingTransactData.parse(zeroSlots, "confidential"))).toBe(
      "OutputCountOutOfRange",
    );
    const overCapacity = bytes.slice();
    overCapacity[3] = 3;
    expect(refusal(() => RingTransactData.parse(overCapacity, "confidential"))).toBe(
      "OutputCountOutOfRange",
    );
    expect(refusal(() => RingTransactData.parse(Uint8Array.of(...bytes, 0), "confidential"))).toBe(
      "RingTransactLength",
    );
  });

  it("refuses bit 7 of the flags and reply metadata off the anonymous rail", () => {
    const bytes = encoded(ringFrame({ rail: "confidential", inputs: 2, outputs: 2 }));
    const high = bytes.slice();
    high[0] = 1 << 7;
    expect(refusal(() => RingTransactData.parse(high, "confidential"))).toBe("FlagNotAllowed");
    const reply = bytes.slice();
    reply[0] = 1 << 6;
    expect(refusal(() => RingTransactData.parse(reply, "confidential"))).toBe("FlagNotAllowed");
  });

  it("refuses change past the prefix, overlap with an exit and three change bits", () => {
    const frame = ringFrame({ rail: "anonymous", inputs: 2, outputs: 2 });
    const later: RingOutput[] = [
      { kind: "anonymous", hash: ZERO, tag: ZERO, body: new Uint8Array(RECIPIENT_BODY_LEN) },
      { kind: "change", hash: ZERO, tag: ZERO },
    ];
    expect(refusal(() => encoded({ ...frame, outputs: later }))).toBe("InvalidChangeBits");
    const wide = ringFrame({ rail: "anonymous", inputs: 2, outputs: 4 });
    const three = wide.outputs.map((_, index): RingOutput =>
      index < 3
        ? { kind: "change", hash: ZERO, tag: ZERO }
        : { kind: "anonymous", hash: ZERO, tag: ZERO, body: new Uint8Array(RECIPIENT_BODY_LEN) },
    );
    expect(refusal(() => encoded({ ...wide, outputs: three }))).toBe("InvalidChangeBits");
  });

  it("omits a compact suffix from the frame and from every list", () => {
    const full = ringFrame({ rail: "confidential", inputs: 2, outputs: 4 });
    const compact = ringFrame({ rail: "confidential", inputs: 2, outputs: 4 });
    const short: RingTransactData = { ...compact, outputs: compact.outputs.slice(0, 3) };
    const parsed = RingTransactData.parse(encoded(short), "confidential");
    expect(parsed.nOut).toBe(4);
    expect(parsed.outputs.length).toBe(3);
    expect(encoded(full).length - encoded(short).length).toBe(32 + 32 + 104);
  });

  it("refuses a nonzero tag on change and a tag at or above q on a recipient, a dummy and the bundle", () => {
    const frame = ringFrame({ rail: "anonymous", inputs: 2, outputs: 4 });
    const [change, payment, ...rest] = frame.outputs;
    if (change?.kind !== "change" || payment?.kind !== "anonymous") throw new Error("no slots");
    const aboveField = new Uint8Array(32).fill(0xff) as Bytes32;
    const nonzero = new Uint8Array(32).fill(1) as Bytes32;
    expect(
      refusal(() =>
        encoded({ ...frame, outputs: [{ ...change, tag: nonzero }, payment, ...rest] }),
      ),
    ).toBe("ChangeTagNotZero");
    expect(
      refusal(() =>
        encoded({ ...frame, outputs: [change, { ...payment, tag: aboveField }, ...rest] }),
      ),
    ).toBe("ViewTagNotCanonical");
    const { sender } = frame;
    if (sender === undefined) throw new Error("no bundle");
    expect(refusal(() => encoded({ ...frame, sender: { ...sender, tag: aboveField } }))).toBe(
      "ViewTagNotCanonical",
    );
    const payload = new Uint8Array(32).fill(7) as Bytes32;
    const bundle = new Uint8Array(32).fill(8) as Bytes32;
    const bytes = encoded({
      ...frame,
      outputs: [change, { ...payment, tag: payload }, ...rest],
      sender: { ...sender, tag: bundle },
    });
    const refusedWith = (tag: Bytes32): string => {
      const copy = Uint8Array.from(bytes);
      copy.set(aboveField, Buffer.from(bytes).indexOf(Buffer.from(tag)));
      return refusal(() => RingTransactData.parse(copy, "anonymous"));
    };
    expect(refusedWith(payload)).toBe("ViewTagNotCanonical");
    expect(refusedWith(bundle)).toBe("ViewTagNotCanonical");
  });

  it("refuses replies of two lengths and a reply shorter than its minimum", () => {
    const frame = ringFrame({ rail: "anonymous", inputs: 2, outputs: 4 });
    expect(
      refusal(() =>
        encoded({
          ...frame,
          replies: [new Uint8Array(97), new Uint8Array(98), new Uint8Array(97)],
        }),
      ),
    ).toBe("ReplyLength");
    expect(
      refusal(() =>
        encoded({
          ...frame,
          replies: [new Uint8Array(96), new Uint8Array(96), new Uint8Array(96)],
        }),
      ),
    ).toBe("ReplyLength");
  });
});

describe("statement version 3", () => {
  it("holds 41 + N confidential elements and 45 anonymous elements", () => {
    const confidential = ringFrame({ rail: "confidential", inputs: 2, outputs: 4 });
    expect(transferStatementElements(ringTransferStatement(confidential, binding())).length).toBe(
      41 + 4,
    );
    const anonymous = ringFrame({ rail: "anonymous", inputs: 2, outputs: 4 });
    expect(transferStatementElements(ringTransferStatement(anonymous, binding())).length).toBe(45);
  });

  it("chains each tag at element 18, zero on change and past m, the bundle tag last", () => {
    const full = ringFrame({ rail: "anonymous", inputs: 2, outputs: 4 });
    const frame: RingTransactData = { ...full, outputs: full.outputs.slice(0, 3) };
    const elements = transferStatementElements(ringTransferStatement(frame, binding()));
    expect(elements).toHaveLength(45);
    const tags = frame.outputs.map((output) =>
      output.kind === "anonymous" ? output.tag : (new Uint8Array(32) as Bytes32),
    );
    const zero = new Uint8Array(32) as Bytes32;
    const bundle = frame.sender?.tag ?? zero;
    const expected = hashChain4([
      ...tags,
      ...Array.from({ length: frame.nOut - tags.length }, () => zero),
      bundle,
    ]);
    expect(elements[18]).toEqual(expected);
    const swapped: RingTransactData = {
      ...frame,
      sender: { body: frame.sender?.body ?? new Uint8Array(), tag: zero },
    };
    expect(transferStatementElements(ringTransferStatement(swapped, binding()))[18]).not.toEqual(
      expected,
    );
  });

  it("zero fills past the published count and keeps the count apart", () => {
    const full = ringFrame({ rail: "confidential", inputs: 2, outputs: 4 });
    const short: RingTransactData = { ...full, outputs: full.outputs.slice(0, 3) };
    const elements = transferStatementElements(ringTransferStatement(short, binding()));
    const fullElements = transferStatementElements(ringTransferStatement(full, binding()));
    expect(elements.length).toBe(fullElements.length);
    expect(elements[16]?.at(-1)).toBe(3);
    expect(fullElements[16]?.at(-1)).toBe(4);
  });

  it("binds no signer run on the in-proof, authority and entry keys", () => {
    const delegate = ringFrame({ rail: "delegate", inputs: 2, outputs: 2 });
    const statement = ringTransferStatement(delegate, { ...binding([ZERO]), keyEscrow: true });
    expect(statement.signers.count).toBe(0);
    expect(statement.signers.chain).toEqual(ZERO);
  });

  it("hashes a reordered or extra signer apart", () => {
    const first = new Uint8Array(32).fill(1) as Bytes32;
    const second = new Uint8Array(32).fill(2) as Bytes32;
    const ordered = signerBinding([first, second], 4);
    expect(signerBinding([second, first], 4).chain).not.toEqual(ordered.chain);
    expect(signerBinding([first, second, first], 4).chain).not.toEqual(ordered.chain);
    expect(ordered.count).toBe(2);
  });
});

describe("frame_v3 vector", () => {
  const frames = readFileSync(new URL("settlement/frame_v3.hex", VECTORS), "utf8")
    .trim()
    .split("\n");

  it("parses under one rail and encodes back to the same bytes", () => {
    expect(frames.length).toBeGreaterThan(0);
    for (const [index, line] of frames.entries()) {
      const bytes = hexToBytes(line);
      const parsed = (["confidential", "anonymous", "delegate"] as const).flatMap((rail) => {
        try {
          return [RingTransactData.parse(bytes, rail)];
        } catch {
          return [];
        }
      });
      expect(parsed.length, `frame ${String(index)}`).toBeGreaterThan(0);
      for (const frame of parsed) expect(bytesToHex(RingTransactData.encode(frame))).toBe(line);
    }
  });
});

describe("merge_frame_v2 vector", () => {
  it("holds its revision, its ring data hash and an input list disclosure", () => {
    const lines = readFileSync(new URL("merge/merge_frame_v2.hex", VECTORS), "utf8")
      .trim()
      .split("\n");
    for (const line of lines) {
      const bytes = hexToBytes(line);
      const reader = new Reader(bytes.subarray(8 + 32));
      const disclosure = readRingMergeDisclosure(reader);
      expect([8, 24].map(mergeDisclosureFieldCount)).toContain(disclosure.fields.length);
      const written = writeRingMergeDisclosure(new Writer(), disclosure).finish();
      expect(bytesToHex(written)).toBe(bytesToHex(bytes.subarray(8 + 32, 8 + 32 + written.length)));
    }
  });
});
