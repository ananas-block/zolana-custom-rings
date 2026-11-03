import { Reader } from "@heliuslabs/zolana/internal";
import { InterfaceError, SPP_SUPPORTED_SHAPES } from "@heliuslabs/zolana/interface";
import type {
  Bytes16,
  Bytes32,
  InterfaceTransfer,
  Shape,
  TreeContext,
} from "@heliuslabs/zolana/interface";

import { readInterfaceTransfer, readTreeContext } from "../codec/codecs.js";
import { RingError } from "../error.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../proof/custom-ring-proof.js";
import { RingInstructionTag } from "../transaction/instruction-tag.js";
import { CONFIDENTIAL_DATA_FREE_BODY_LEN } from "../transaction/output.js";
import { RING_AUTHORITY_SHAPES } from "../transaction/spp.js";
import {
  anonymousAuditKey,
  checkedStreamLayout,
  confidentialAuditKey,
  deliveredBodyLen,
  DELIVERED_BODY_LEN,
  envelopeRegion,
  ESCROWED_DELIVERED_BODY_LEN,
  isExitSlot,
  recordLen,
  recordSlots,
  type AuditLayout,
  type AuditStreamLayout,
} from "./layout.js";

export type HistoricalRail = "confidential" | "anonymous" | "delegate";

export interface HistoricalPolicy {
  readonly splWithdrawalOwners: readonly Bytes32[];
  readonly curatorRevision?: bigint;
  readonly recipients: HistoricalRecipients;
}

export type HistoricalRecipients =
  | Readonly<{ kind: "hidden" }>
  /** One owner identity per output slot. */
  | Readonly<{ kind: "framed"; recipients: readonly Bytes32[] }>;

export interface HistoricalInProofOwner {
  readonly owner: Bytes32;
  readonly commitment: Bytes32;
  readonly commitmentPok: Bytes32;
}

export interface HistoricalAnonymousProof {
  readonly commitment: Bytes32;
  readonly commitmentPok: Bytes32;
  readonly defaultOwnerTag?: Bytes32;
}

export type HistoricalInputTrees =
  | Readonly<{ kind: "one"; context: TreeContext }>
  | Readonly<{
      kind: "two";
      first: TreeContext;
      second: TreeContext;
      /** Bit `i` spends input `i` from `second`. */
      secondInputs: bigint;
    }>;

export type HistoricalOutput =
  | Readonly<{ kind: "delivered"; hash: Bytes32; u: Bytes32; body: Uint8Array }>
  /** Its scheme 1 body unproven and absent on a change output. */
  | Readonly<{ kind: "anonymous"; hash: Bytes32; tag: Bytes32; body?: Uint8Array }>
  | Readonly<{ kind: "exit"; hash: Bytes32; ownerTag: Bytes32; payload: Uint8Array }>;

/** Scheme 2 under its tag, a `u16` length prefix ahead of the body. */
export interface HistoricalSenderBundle {
  readonly tag: Bytes32;
  readonly body: Uint8Array;
}

export interface HistoricalTransactData {
  readonly rail: HistoricalRail;
  readonly nIn: number;
  readonly nOut: number;
  readonly proof: Uint8Array;
  readonly ownRevision?: bigint;
  readonly policy?: HistoricalPolicy;
  readonly exempt: boolean;
  readonly approvalRequired: boolean;
  readonly expiryUnixTs: number;
  readonly txViewingU: Bytes32;
  readonly salt: Bytes16;
  readonly interfaceTransfers: readonly InterfaceTransfer[];
  readonly keyEscrow: boolean;
  readonly fullOpenings: boolean;
  readonly outputs: readonly HistoricalOutput[];
  readonly sender?: HistoricalSenderBundle;
  readonly ephU: Bytes32;
  /** `tx_viewing_sk ‖ evidence` under the auditor stream. */
  readonly envelope: Uint8Array;
  readonly records: readonly Uint8Array[];
  readonly privateTxHash: Bytes32;
  readonly anonymous?: HistoricalAnonymousProof;
  readonly inProofOwner?: HistoricalInProofOwner;
  /** `a ‖ b ‖ c` with `b` compressed. */
  readonly sppProof: Uint8Array;
  readonly nullifiers: readonly Bytes32[];
  readonly inputTrees: HistoricalInputTrees;
}

/** An in-proof owner runs the confidential rail through SPP's anonymous circuit. */
export function landedHistoricalRail(
  instruction: Uint8Array,
  sppAnonymous: boolean,
): HistoricalRail {
  const anonymous = sppAnonymous && !has(instruction[1] ?? 0, Flag.ownerInProof);
  switch (instruction[0]) {
    case RingInstructionTag.historicalTransfer:
      return anonymous ? "anonymous" : "confidential";
    case RingInstructionTag.historicalAuthorityTransfer:
      if (anonymous) throw invalid("AnonymousRingRefused");
      return "delegate";
    default:
      throw invalid("InvalidInstructionData");
  }
}

export const HistoricalTransactData = Object.freeze({
  /** `data` without the tag, every length fixed by the flags, the shape and the counts. */
  parse(data: Uint8Array, rail: HistoricalRail): HistoricalTransactData {
    try {
      return readFrame(new Reader(data), rail);
    } catch (error) {
      throw shortRead(error, "RingTransactLength");
    }
  },

  auditLayout(data: HistoricalTransactData): AuditLayout {
    return Object.freeze({
      keyEscrow: data.keyEscrow,
      fullOpenings: data.fullOpenings,
    });
  },

  streamLayout(data: HistoricalTransactData): AuditStreamLayout {
    return auditShape(data.rail, {
      nIn: data.nIn,
      nOut: data.nOut,
      inputCount: data.nullifiers.length,
      flags: {
        defaultOwnerTag: data.anonymous?.defaultOwnerTag !== undefined,
        keyEscrow: data.keyEscrow,
        fullOpenings: data.fullOpenings,
      },
      ownerInProof: data.inProofOwner !== undefined,
    }).layout(exitsBitmap(data.outputs));
  },

  /** One ciphertext per slot in output order, its delivered body or its record. */
  outputCiphertexts(data: HistoricalTransactData): readonly Uint8Array[] {
    const records = data.records[Symbol.iterator]();
    return data.outputs.map((output) => {
      if (output.kind === "delivered") return checkedBody(output.body);
      const record = records.next();
      if (record.done === true) throw invalid("RingTransactLength");
      return record.value;
    });
  },

  /** One per output slot, zero off a policy and on the anonymous rail. */
  recipients(data: HistoricalTransactData): readonly Bytes32[] {
    const recipients = data.policy?.recipients;
    return recipients?.kind === "framed" ? recipients.recipients : data.outputs.map(() => ZERO);
  },

  firstNullifier(data: HistoricalTransactData): Bytes32 {
    const first = data.nullifiers[0];
    if (first === undefined) throw invalid("RingTransactLength");
    return first;
  },
});

/** Bit `i` set when slot `i` exits. */
export function exitsBitmap(outputs: readonly HistoricalOutput[]): bigint {
  return outputs.reduce(
    (bits, output, slot) => (output.kind === "exit" ? bits | (1n << BigInt(slot)) : bits),
    0n,
  );
}

const Flag = Object.freeze({
  policy: 1 << 0,
  curator: 1 << 1,
  approvalRequired: 1 << 2,
  ownerInProof: 1 << 3,
  exempt: 1 << 4,
  secondTree: 1 << 5,
});
const KNOWN_FLAGS =
  Flag.policy |
  Flag.curator |
  Flag.approvalRequired |
  Flag.ownerInProof |
  Flag.exempt |
  Flag.secondTree;

const FrameByte = Object.freeze({
  low: 0b0011_1111,
  bit6: 1 << 6,
  bit7: 1 << 7,
});

const PLAIN_GROTH16_PROOF_LENGTH = 128;
const ZERO = new Uint8Array(32) as Bytes32;

interface FrameFlags {
  readonly defaultOwnerTag: boolean;
  readonly keyEscrow: boolean;
  readonly fullOpenings: boolean;
}

interface FrameHeader {
  readonly nIn: number;
  readonly nOut: number;
  readonly inputCount: number;
  readonly flags: FrameFlags;
  readonly ownerInProof: boolean;
}

type AuditShape = Readonly<{
  outputs: number;
  layout(exits: bigint): AuditStreamLayout;
}>;

function railShapes(rail: HistoricalRail): readonly Shape[] {
  return rail === "delegate" ? RING_AUTHORITY_SHAPES : SPP_SUPPORTED_SHAPES;
}

function auditShape(rail: HistoricalRail, header: FrameHeader): AuditShape {
  const { nIn, nOut, inputCount: inputs, flags } = header;
  const supported = railShapes(rail).some(
    (shape) => shape.inputs === nIn && shape.outputs === nOut,
  );
  const key =
    rail === "anonymous"
      ? anonymousAuditKey({ inputs, outputs: nOut, spendsDefaultRing: flags.fullOpenings })
      : confidentialAuditKey(nOut, rail === "delegate" || header.ownerInProof);
  if (key === undefined || inputs > key.class || !supported) throw invalid("RingShapeUnkeyed");
  if (inputs === 0 || inputs > nIn) throw invalid("RingTransactLength");
  return {
    outputs: nOut,
    layout: (exits) =>
      Object.freeze(
        checkedStreamLayout({ key, keyEscrow: flags.keyEscrow, inputs, outputs: nOut, exits }),
      ),
  };
}

function readFrame(bytes: Reader, rail: HistoricalRail): HistoricalTransactData {
  const flags = bytes.u8("flags");
  checkFlags(flags, rail);
  const header = readHeader(bytes, rail, flags);
  const { nIn, nOut, inputCount } = header;
  const shape = auditShape(rail, header);
  const proof = bytes.bytes(CUSTOM_RING_PROOF_LENGTH, "proof");
  const ownRevision = readsOwnRoot(flags) ? bytes.u64("ownRevision") : undefined;
  const policySection = has(flags, Flag.policy)
    ? readPolicy(bytes, {
        curator: has(flags, Flag.curator),
        recipients: rail === "anonymous" ? "hidden" : "framed",
        outputs: shape.outputs,
      })
    : undefined;
  const expiryUnixTs = bytes.u32("expiryUnixTs");
  const txViewingU = field32(bytes, "txViewingU");
  const salt = bytes.bytes(16, "salt") as Bytes16;
  const interfaceTransfers = within("InvalidInstructionData", () =>
    Array.from({ length: bytes.u8("interfaceTransfers.length") }, () =>
      readInterfaceTransfer(bytes),
    ),
  );
  if (has(flags, Flag.exempt) && !withdraws(interfaceTransfers))
    throw invalid("ExemptionWithoutWithdrawal");
  const policy =
    policySection === undefined
      ? undefined
      : Object.freeze({
          ...policySection,
          splWithdrawalOwners: Object.freeze(
            interfaceTransfers
              .filter((transfer) => transfer.kind === "splWithdrawal")
              .map(() => field32(bytes, "splWithdrawalOwner")),
          ),
        });
  const exits = readBitmap(bytes, shape.outputs);
  if (rail === "delegate" && exits !== 0n) throw invalid("FlagNotAllowed");
  const layout = shape.layout(exits);
  const outputs = Array.from({ length: shape.outputs }, (_, slot) =>
    readOutput(bytes, layout, slot),
  );
  const sender = rail === "anonymous" ? readSender(bytes) : undefined;
  const ephU = field32(bytes, "ephU");
  const envelope = bytes.bytes(envelopeRegion(layout).length, "envelope");
  const records = recordSlots(layout).map((slot) => bytes.bytes(recordLen(layout, slot), "record"));
  const privateTxHash = field32(bytes, "privateTxHash");
  const anonymous =
    rail === "anonymous" ? readAnonymous(bytes, header.flags.defaultOwnerTag) : undefined;
  const inProofOwner = header.ownerInProof
    ? Object.freeze({
        owner: field32(bytes, "inProofOwner.owner"),
        commitment: field32(bytes, "inProofOwner.commitment"),
        commitmentPok: field32(bytes, "inProofOwner.commitmentPok"),
      })
    : undefined;
  const sppProof = bytes.bytes(PLAIN_GROTH16_PROOF_LENGTH, "sppProof");
  const nullifiers = Array.from({ length: inputCount }, () => field32(bytes, "nullifier"));
  const inputTrees = readInputTrees(bytes, flags, inputCount);
  bytes.done();
  return Object.freeze({
    rail,
    nIn,
    nOut,
    proof,
    ...(ownRevision === undefined ? {} : { ownRevision }),
    ...(policy === undefined ? {} : { policy }),
    exempt: has(flags, Flag.exempt),
    approvalRequired: has(flags, Flag.approvalRequired),
    expiryUnixTs,
    txViewingU,
    salt,
    interfaceTransfers: Object.freeze(interfaceTransfers),
    keyEscrow: header.flags.keyEscrow,
    fullOpenings: header.flags.fullOpenings,
    outputs: Object.freeze(outputs),
    ...(sender === undefined ? {} : { sender }),
    ephU,
    envelope,
    records: Object.freeze(records),
    privateTxHash,
    ...(anonymous === undefined ? {} : { anonymous }),
    ...(inProofOwner === undefined ? {} : { inProofOwner }),
    sppProof,
    nullifiers: Object.freeze(nullifiers),
    inputTrees,
  });
}

function readInputTrees(bytes: Reader, flags: number, inputCount: number): HistoricalInputTrees {
  if (!has(flags, Flag.secondTree))
    return Object.freeze({ kind: "one", context: readTreeContext(bytes) });
  const secondInputs = readBitmap(bytes, inputCount);
  return Object.freeze({
    kind: "two",
    first: readTreeContext(bytes),
    second: readTreeContext(bytes),
    secondInputs,
  });
}

function readPolicy(
  bytes: Reader,
  section: Readonly<{
    curator: boolean;
    recipients: HistoricalRecipients["kind"];
    outputs: number;
  }>,
): HistoricalPolicy {
  const curatorRevision = section.curator ? bytes.u64("policy.curatorRevision") : undefined;
  const recipients: HistoricalRecipients =
    section.recipients === "framed"
      ? {
          kind: "framed",
          recipients: Object.freeze(
            Array.from({ length: section.outputs }, () => field32(bytes, "policy.recipient")),
          ),
        }
      : { kind: "hidden" };
  return Object.freeze({
    splWithdrawalOwners: Object.freeze([]),
    recipients: Object.freeze(recipients),
    ...(curatorRevision === undefined ? {} : { curatorRevision }),
  });
}

function readSender(bytes: Reader): HistoricalSenderBundle {
  const tag = field32(bytes, "sender.tag");
  const body = readAnonymousBody(bytes, "sender");
  if (body.length === 0) throw invalid("AnonymousBodyLength");
  return Object.freeze({ tag, body });
}

function readAnonymous(bytes: Reader, tagged: boolean): HistoricalAnonymousProof {
  const commitment = field32(bytes, "anonymous.commitment");
  const commitmentPok = field32(bytes, "anonymous.commitmentPok");
  const defaultOwnerTag = tagged ? field32(bytes, "anonymous.defaultOwnerTag") : undefined;
  return Object.freeze({
    commitment,
    commitmentPok,
    ...(defaultOwnerTag === undefined ? {} : { defaultOwnerTag }),
  });
}

function readOutput(bytes: Reader, layout: AuditStreamLayout, slot: number): HistoricalOutput {
  const hash = field32(bytes, "output.hash");
  if (isExitSlot(layout, slot)) {
    const ownerTag = field32(bytes, "output.ownerTag");
    return Object.freeze({
      kind: "exit",
      hash,
      ownerTag,
      payload: bytes.bytes(CONFIDENTIAL_DATA_FREE_BODY_LEN, "output.payload"),
    });
  }
  if (layout.key.kind === "confidential") {
    const u = field32(bytes, "output.u");
    return Object.freeze({
      kind: "delivered",
      hash,
      u,
      body: bytes.bytes(deliveredBodyLen(layout.keyEscrow), "output.body"),
    });
  }
  const tag = field32(bytes, "output.tag");
  const body = readAnonymousBody(bytes, "output");
  return Object.freeze({
    kind: "anonymous",
    hash,
    tag,
    ...(body.length === 0 ? {} : { body }),
  });
}

function readAnonymousBody(bytes: Reader, name: string): Uint8Array {
  return bytes.bytes(bytes.u16(`${name}.length`), `${name}.body`);
}

/** `ceil(len / 8)` bytes, bit `i` at byte `i / 8` bit `i % 8`, no bit set past `len`. */
function readBitmap(bytes: Reader, length: number): bigint {
  const raw = bytes.bytes(Math.ceil(length / 8), "bitmap");
  const bits = raw.reduce((value, byte, index) => value | (BigInt(byte) << BigInt(8 * index)), 0n);
  if (bits >> BigInt(length) !== 0n) throw invalid("InvalidInstructionData");
  return bits;
}

function checkFlags(flags: number, rail: HistoricalRail): void {
  const foreignOwner = has(flags, Flag.ownerInProof) && rail !== "confidential";
  const delegateExempt = has(flags, Flag.exempt) && rail === "delegate";
  if ((flags & ~KNOWN_FLAGS) !== 0 || foreignOwner || delegateExempt)
    throw invalid("FlagNotAllowed");
  const needsPolicy = has(flags, Flag.curator) || has(flags, Flag.approvalRequired);
  if (needsPolicy && !has(flags, Flag.policy)) throw invalid("FlagNotAllowed");
}

function has(flags: number, bit: number): boolean {
  return (flags & bit) !== 0;
}

function readsOwnRoot(flags: number): boolean {
  return has(flags, Flag.policy) || has(flags, Flag.exempt);
}

function withdraws(transfers: readonly InterfaceTransfer[]): boolean {
  return transfers.some(
    (transfer) => transfer.kind === "solWithdrawal" || transfer.kind === "splWithdrawal",
  );
}

function readHeader(bytes: Reader, rail: HistoricalRail, transact: number): FrameHeader {
  const shapeByte = bytes.u8("shapeByte");
  const inputByte = bytes.u8("inputByte");
  if (has(shapeByte, FrameByte.bit7)) throw invalid("FlagNotAllowed");
  const shape = SPP_SUPPORTED_SHAPES[shapeByte & FrameByte.low];
  if (shape === undefined) throw invalid("RingShapeUnkeyed");
  const flags: FrameFlags = {
    defaultOwnerTag: has(shapeByte, FrameByte.bit6),
    keyEscrow: has(inputByte, FrameByte.bit6),
    fullOpenings: has(inputByte, FrameByte.bit7),
  };
  checkFrameFlags(flags, rail);
  return {
    nIn: shape.inputs,
    nOut: shape.outputs,
    inputCount: inputByte & FrameByte.low,
    flags,
    ownerInProof: has(transact, Flag.ownerInProof),
  };
}

function checkFrameFlags(flags: FrameFlags, rail: HistoricalRail): void {
  const anonymousOnly = flags.defaultOwnerTag || flags.fullOpenings;
  const refused =
    rail === "anonymous"
      ? flags.keyEscrow
      : rail === "confidential"
        ? anonymousOnly
        : anonymousOnly || !flags.keyEscrow;
  if (refused) throw invalid("FlagNotAllowed");
}

function field32(bytes: Reader, name: string): Bytes32 {
  return bytes.bytes(32, name) as Bytes32;
}

function checkedBody(body: Uint8Array): Uint8Array {
  if (body.length !== DELIVERED_BODY_LEN && body.length !== ESCROWED_DELIVERED_BODY_LEN)
    throw invalid("RingTransactLength");
  return body;
}

function within<T>(reason: string, run: () => T): T {
  try {
    return run();
  } catch (error) {
    throw shortRead(error, reason);
  }
}

/** A ring refusal passes through. */
function shortRead(error: unknown, reason: string): unknown {
  return error instanceof InterfaceError
    ? new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason }, cause: error })
    : error;
}

function invalid(reason: string): RingError {
  return new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason } });
}
