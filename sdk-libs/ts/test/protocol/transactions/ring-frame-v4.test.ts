import { describe, expect, it } from "vitest";

import { MAX_CACHE_WRITES } from "@heliuslabs/zolana/interface";
import type { Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { hashChain4 } from "@heliuslabs/zolana/internal";

import { CUSTOM_RING_PROOF_LENGTH } from "../../../src/protocol/proof/custom-ring-proof.js";
import { field, ringFrame, ringInstructionData } from "../../helpers/ring-frame.js";
import { TRANSFER_STATEMENT_VERSION } from "../../../src/crypto/derivation/ring-domain.js";
import { RingError } from "../../../src/protocol/error.js";
import {
  ringTransferStatement,
  signerBinding,
  transferStatementElements,
  transferStatementHash,
  type TransferBinding,
} from "../../../src/protocol/proof/statement.js";
import { RECIPIENT_BODY_LEN } from "../../../src/protocol/codec/anonymous-delivery.js";
import {
  CONFIDENTIAL_DATA_FREE_BODY_LEN,
  encodeRingBodyOutput,
  ringBodyOutput,
  RingScheme,
  readRingOutput,
} from "../../../src/protocol/transaction/output.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import {
  ANONYMOUS_PARTIES,
  ApprovalMask,
  landedRingRail,
  RingTransactData,
  ringRailOf,
  ringTransactOutput,
  type RingTransactData as Frame,
} from "../../../src/protocol/transaction/transact.js";

const ZERO = new Uint8Array(32) as Bytes32;
const AUDITOR = Uint8Array.of(4, ...new Uint8Array(31), 9) as Bytes33;

function binding(signers: readonly Bytes32[] = [], slots = 24): TransferBinding {
  return {
    ringId: field(21),
    auditorPubkey: AUDITOR,
    sender: field(22),
    partyIdentities: Array.from({ length: ANONYMOUS_PARTIES }, () => ZERO),
    signers: signerBinding(signers, slots),
    roots: {
      policyHash: field(23),
      ownRoot: field(24),
      curatorRoot: field(25),
      trackingRoot: field(26),
    },
    publicAssets: [ZERO, ZERO, ZERO],
    publicAmounts: [ZERO, ZERO, ZERO],
    publicGross: [ZERO, ZERO, ZERO],
    withdrawalHash: ZERO,
  };
}

function reason(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    if (error instanceof RingError) return error.details?.["reason"];
    throw error;
  }
  throw new Error("expected a refusal");
}

const roundTrips: readonly Readonly<{ name: string; frame: Frame }>[] = [
  { name: "confidential", frame: ringFrame({ rail: "confidential", inputs: 2, outputs: 4 }) },
  { name: "anonymous", frame: ringFrame({ rail: "anonymous", inputs: 2, outputs: 4 }) },
  { name: "delegate", frame: ringFrame({ rail: "delegate", inputs: 2, outputs: 2 }) },
  {
    name: "anonymous delegate",
    frame: ringFrame({ rail: "anonymousDelegate", inputs: 2, outputs: 2 }),
  },
  {
    name: "public owners",
    frame: ringFrame({ rail: "anonymous", inputs: 2, outputs: 2, publicOwners: true }),
  },
  {
    name: "entry with data and wide owners",
    frame: ringFrame({
      rail: "confidential",
      inputs: 2,
      outputs: 2,
      entry: true,
      hasData: true,
      wideOwners: true,
    }),
  },
];

describe("the v4 ring frame", () => {
  it.each(roundTrips)("$name round trips", ({ frame }) => {
    const bytes = RingTransactData.encode(frame);
    expect(RingTransactData.parse(bytes, frame.rail)).toEqual(frame);
  });

  it("puts the wide owner flag at bit 7 of the output count and the approval mask past the header", () => {
    const frame: Frame = {
      ...ringFrame({ rail: "confidential", inputs: 1, outputs: 2, wideOwners: true }),
      approval: ApprovalMask.outflow | ApprovalMask.withdrawal,
    };
    const bytes = RingTransactData.encode(frame);
    expect(bytes[3]).toBe(2 | (1 << 7));
    expect(bytes[4]).toBe(3);
    expect(RingTransactData.parse(bytes, "confidential").approval).toBe(frame.approval);
  });

  it("refuses an approval mask past its two bits", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    for (const approval of [4, -1, 1.5])
      expect(reason(() => RingTransactData.encode({ ...frame, approval }))).toBe("FlagNotAllowed");
    const bytes = RingTransactData.encode(frame);
    for (const mask of [1 << 2, 6 << 2, 1 << 5, 1 << 7]) {
      bytes[4] = mask;
      expect(reason(() => RingTransactData.parse(bytes, "confidential"))).toBe("FlagNotAllowed");
    }
  });

  it("publishes a live slot's tag in eight bytes, an exit's whole, and refuses leading tag bytes", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const whole = new Uint8Array(32).fill(7) as Bytes32;
    const tagged = (output: Frame["outputs"][number]) => ({ ...output, ownerTag: whole });
    expect(
      reason(() => RingTransactData.encode({ ...frame, outputs: frame.outputs.map(tagged) })),
    ).toBe("RingTransactLength");
    const exit: Frame = {
      ...frame,
      outputs: frame.outputs.map((output, slot) =>
        slot === 1
          ? {
              ...tagged(output),
              body: {
                kind: "exit" as const,
                payload: new Uint8Array(CONFIDENTIAL_DATA_FREE_BODY_LEN),
              },
            }
          : output,
      ),
    };
    const bytes = RingTransactData.encode(exit);
    expect(RingTransactData.parse(bytes, "confidential")).toEqual(exit);
    expect(bytes.length).toBe(
      RingTransactData.encode(frame).length +
        32 -
        8 +
        CONFIDENTIAL_DATA_FREE_BODY_LEN -
        RECIPIENT_BODY_LEN,
    );
  });

  it("refuses an appended byte and a truncation", () => {
    const bytes = RingTransactData.encode(
      ringFrame({ rail: "confidential", inputs: 1, outputs: 2 }),
    );
    for (const refused of [Uint8Array.of(...bytes, 0), bytes.subarray(0, bytes.length - 1)])
      expect(reason(() => RingTransactData.parse(refused, "confidential"))).toBe(
        "RingTransactLength",
      );
  });

  it("refuses a slot without its tail under has_data and a tail without it", () => {
    const plain = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    expect(reason(() => RingTransactData.encode({ ...plain, hasData: true }))).toBe(
      "RingTransactLength",
    );
    const data = ringFrame({ rail: "confidential", inputs: 1, outputs: 2, hasData: true });
    expect(reason(() => RingTransactData.encode({ ...data, hasData: false }))).toBe(
      "RingTransactLength",
    );
  });

  it("refuses a body past its plain length without has_data and keeps it with the length prefix", () => {
    const plain = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const extended = new Uint8Array(105);
    const outputs = plain.outputs.map((output) => ({
      ...output,
      body: { kind: "recipient" as const, body: extended },
    }));
    expect(reason(() => RingTransactData.encode({ ...plain, outputs }))).toBe("RingTransactLength");
    const data = ringFrame({ rail: "confidential", inputs: 1, outputs: 2, hasData: true });
    const carried = {
      ...data,
      outputs: data.outputs.map((output) => ({
        ...output,
        body: { kind: "recipient" as const, body: extended },
      })),
    };
    expect(RingTransactData.parse(RingTransactData.encode(carried), "confidential")).toEqual(
      carried,
    );
  });

  it("refuses flags the rail forbids", () => {
    const anonymous = ringFrame({ rail: "anonymous", inputs: 1, outputs: 2 });
    expect(reason(() => RingTransactData.encode({ ...anonymous, rail: "confidential" }))).toBe(
      "RingTransactLength",
    );
    const delegate = ringFrame({ rail: "delegate", inputs: 2, outputs: 2 });
    expect(reason(() => RingTransactData.encode({ ...delegate, entry: true }))).toBe(
      "FlagNotAllowed",
    );
    expect(reason(() => RingTransactData.encode({ ...delegate, ownRevision: 1n }))).toBe(
      "FlagNotAllowed",
    );
    expect(reason(() => RingTransactData.encode({ ...delegate, publicOwners: true }))).toBe(
      "FlagNotAllowed",
    );
    expect(
      reason(() =>
        RingTransactData.encode({
          ...delegate,
          extensions: {
            cache: {
              readBitmap: 0n,
              writeSlots: Array.from({ length: 16 }, () => ({ output: 0xff, slot: 0xff })),
            },
          },
        }),
      ),
    ).toBe("FlagNotAllowed");
  });

  it("carries the extensions and forwards the application message ahead of the auditor's", () => {
    const frame: Frame = {
      ...ringFrame({ rail: "confidential", inputs: 1, outputs: 2 }),
      extensions: {
        dataHash: field(81),
        ringDataHash: field(82),
        messages: [{ viewTag: field(83), data: Uint8Array.of(1, 2, 3) }],
        cache: {
          readBitmap: 0n,
          writeSlots: Array.from({ length: MAX_CACHE_WRITES }, () => ({
            output: 0xff,
            slot: 0xff,
          })),
        },
      },
    };
    const bytes = RingTransactData.encode(frame);
    expect(RingTransactData.parse(bytes, "confidential")).toEqual(frame);
    // The extension byte follows the salt.
    const extensions = 4 + 1 + CUSTOM_RING_PROOF_LENGTH + 8 + 8 + 4 + 32 + 16;
    expect(bytes[extensions]).toBe(1 | 2 | 4 | 8);
    bytes[extensions] = 1 | 2 | 4 | 8 | 16;
    expect(reason(() => RingTransactData.parse(bytes, "confidential"))).toBe("FlagNotAllowed");
    const { messages } = RingTransactData.expand(frame, { auditorPubkey: AUDITOR });
    expect(messages.map((message) => message.viewTag)).toEqual([field(83), AUDITOR.slice(1)]);
  });

  it("keeps a bodiless slot out of SPP's data and frames a recipient under scheme 13", () => {
    const frame = ringFrame({ rail: "anonymous", inputs: 1, outputs: 2 });
    const reply = new Uint8Array(97).fill(9);
    const withReply: Frame = { ...frame, replies: { length: 97, region: reply } };
    expect(RingTransactData.slotReplies(withReply).map((bytes) => bytes.length)).toEqual([0, 97]);
    expect(RingTransactData.parse(RingTransactData.encode(withReply), "anonymous")).toEqual(
      withReply,
    );
  });

  it("selects SPP's confidential rail for public owners and the exit circuit for a delegate exit", () => {
    const owners = ringFrame({ rail: "anonymous", inputs: 2, outputs: 2, publicOwners: true });
    expect(RingTransactData.circuit(owners).kind).toBe("confidentialRingEddsa");
    const delegate = ringFrame({ rail: "delegate", inputs: 2, outputs: 2 });
    expect(RingTransactData.circuit(delegate).kind).toBe("ringAuthority");
    const exit: Frame = {
      ...delegate,
      outputs: delegate.outputs.map((output, slot) =>
        slot === 1
          ? { ...output, body: { kind: "exit" as const, payload: new Uint8Array(83) } }
          : output,
      ),
    };
    expect(RingTransactData.circuit(exit).kind).toBe("ringAuthorityExit");
  });

  it("names the rail from the tag and refuses a historical tag", () => {
    expect(RingInstructionTag.transfer).toBe(55);
    expect(RingInstructionTag.authorityTransfer).toBe(56);
    expect(RingInstructionTag.merge).toBe(57);
    expect(RingInstructionTag.deposit).toBe(58);
    expect(RingInstructionTag.historicalTransferV3).toBe(45);
    expect(RingInstructionTag.historicalAuthorityTransferV3).toBe(46);
    expect(RingInstructionTag.historicalMergeV3).toBe(47);
    expect(RingInstructionTag.historicalDeposit).toBe(31);
    expect(ringRailOf(55, "anonymous")).toBe("anonymous");
    expect(ringRailOf(56, "anonymous")).toBe("anonymousDelegate");
    expect(ringRailOf(56, "confidential")).toBe("delegate");
    expect(reason(() => ringRailOf(45, "confidential"))).toBe("InvalidInstructionData");
  });

  it.each(roundTrips)("reads the $name rail back from the landed instruction", ({ frame }) => {
    const instruction = ringInstructionData(frame);
    const sppAnonymous = frame.rail === "anonymous" && !frame.publicOwners;
    expect(landedRingRail(instruction, sppAnonymous)).toBe(frame.rail);
  });
});

describe("the v4 transfer statement", () => {
  const STATEMENT_LENGTH = 49;

  it("orders the confidential elements and closes on the length and version", () => {
    const frame: Frame = {
      ...ringFrame({ rail: "confidential", inputs: 2, outputs: 2 }),
      approval: ApprovalMask.outflow | ApprovalMask.withdrawal,
      noSpend: true,
    };
    const elements = transferStatementElements(ringTransferStatement(frame, binding([field(31)])));
    expect(elements).toHaveLength(STATEMENT_LENGTH);
    const bigint = (bytes: Bytes32 | undefined): bigint =>
      bytes === undefined ? -1n : BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
    expect(bigint(elements[15])).toBe(3n);
    expect(bigint(elements[16])).toBe(1n);
    expect(bigint(elements[17])).toBe(2n);
    expect(bigint(elements[21])).toBe(2n);
    expect(bigint(elements[31])).toBe(1n);
    expect(bigint(elements.at(-2))).toBe(BigInt(elements.length));
    expect(bigint(elements.at(-1))).toBe(TRANSFER_STATEMENT_VERSION);
    expect(TRANSFER_STATEMENT_VERSION).toBe(4n);
  });

  it("zero fills the output chains to the capacity and leaves the tail chain zero off has_data", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const elements = transferStatementElements(ringTransferStatement(frame, binding()));
    expect(elements[20]).toEqual(ZERO);
    const withData = ringFrame({ rail: "confidential", inputs: 1, outputs: 2, hasData: true });
    const data = transferStatementElements(ringTransferStatement(withData, binding()));
    expect(data[20]).not.toEqual(ZERO);
    expect(elements[18]).toEqual(hashChain4(frame.outputs.map((output) => output.hash)) as Bytes32);
  });

  it("carries the seven parties and both rail bits on the anonymous frame", () => {
    const frame = ringFrame({ rail: "anonymous", inputs: 1, outputs: 2, publicOwners: true });
    const statement = ringTransferStatement(frame, binding());
    expect(statement.family).toMatchObject({
      kind: "anonymous",
      publicOwners: true,
      delegate: false,
    });
    expect(transferStatementElements(statement)).toHaveLength(STATEMENT_LENGTH);
    expect(ANONYMOUS_PARTIES).toBe(7);
    const delegate = ringFrame({ rail: "anonymousDelegate", inputs: 2, outputs: 2 });
    expect(ringTransferStatement(delegate, binding()).family).toMatchObject({ delegate: true });
  });

  it("hashes apart on any bound field", () => {
    const frame = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const base = transferStatementHash(ringTransferStatement(frame, binding()));
    const moved = {
      ...binding(),
      roots: { ...binding().roots, trackingRoot: field(99) },
    };
    expect(transferStatementHash(ringTransferStatement(frame, moved))).not.toEqual(base);
    expect(
      transferStatementHash(
        ringTransferStatement({ ...frame, approval: ApprovalMask.outflow }, binding()),
      ),
    ).not.toEqual(base);
  });

  it("dedups the signer run by first occurrence and refuses one past the slots", () => {
    expect(signerBinding([field(1), field(1), field(2)], 4).count).toBe(2);
    expect(signerBinding([], 4).chain).toEqual(ZERO);
    expect(() => signerBinding([field(1), field(2)], 1)).toThrow(RingError);
  });
});

describe("scheme 13", () => {
  const slot = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 }).outputs[1];

  it("frames body then reply and reads them back", () => {
    if (slot === undefined) throw new Error("a slot");
    const body = new Uint8Array(72).fill(5);
    const reply = new Uint8Array(97).fill(9);
    const { data } = ringTransactOutput({ ...slot, body: { kind: "recipient", body } }, reply);
    if (data === undefined) throw new Error("a framed body");
    expect(readRingOutput(data).scheme).toBe(RingScheme.ringBody);
    expect(ringBodyOutput(data)).toEqual({ body, reply });
  });

  it("refuses a length past the payload and below the plain body", () => {
    if (slot === undefined) throw new Error("a slot");
    expect(ringBodyOutput(new Uint8Array())).toBeUndefined();
    const short = encodeRingBodyOutput(new Uint8Array(71), new Uint8Array());
    expect(ringBodyOutput(short)).toBeUndefined();
    const framed = encodeRingBodyOutput(new Uint8Array(72), new Uint8Array());
    const past = framed.slice();
    past[6] = 73;
    expect(ringBodyOutput(past)).toBeUndefined();
  });

  it("keeps an exit under scheme 3 and a bodiless slot out of SPP's data", () => {
    if (slot === undefined) throw new Error("a slot");
    const exit = ringTransactOutput({
      ...slot,
      body: { kind: "exit", payload: new Uint8Array(83) },
    }).data;
    if (exit === undefined) throw new Error("a framed exit");
    expect(readRingOutput(exit).scheme).toBe(RingScheme.confidential);
    expect(ringTransactOutput({ ...slot, body: { kind: "none" } }).data).toBeUndefined();
  });
});
