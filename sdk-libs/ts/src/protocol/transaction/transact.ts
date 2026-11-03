import { writeTreeContext, Reader, Writer } from "@heliuslabs/zolana/internal";
import {
  encodeRingTransactInstructionData,
  type RingCircuitId,
  type RingTransactInstructionData,
} from "../proof/circuit.js";
import {
  InterfaceError,
  externalDataHash,
  type SettlementAccounts,
  InstructionTag,
  SPP_SUPPORTED_SHAPES,
} from "@heliuslabs/zolana/interface";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  Bytes128,
  InterfaceTransfer,
  TransactInstructionData,
  TransactOutput,
  TreeContext,
  Shape,
} from "@heliuslabs/zolana/interface";
import { packBytesBe } from "../../crypto/derivation/hasher.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../proof/custom-ring-proof.js";
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
} from "../codec/ring-disclosure-layout.js";
import { ringTransferCircuit, type TransferKeyCircuit } from "../proof/transfer-shapes.js";

import { RingInstructionTag } from "../../operations/management/admin.js";
import type { RingMode } from "../codec/ring-codecs.js";
import { RingError } from "../error.js";
import { N_PUBLIC_SLOTS, RING_AUTHORITY_SHAPES } from "./spp.js";
import {
  decompressG2,
  readInterfaceTransfer,
  readTreeContext,
  writeInterfaceTransfer,
} from "../codec/codecs.js";
import { CONFIDENTIAL_DATA_FREE_BODY_LEN, encodeRingOutput, RingScheme } from "./output.js";

/** The program rail the data serves, fixed by the instruction and the ring mode. */
export type RingRail = "confidential" | "anonymous" | "delegate";

/** The policy section of the frame, Rust `PolicyProof`. */
export interface PolicyProof {
  readonly splWithdrawalOwners: readonly Bytes32[];
  /** Set exactly when a source names the curator registry. */
  readonly curatorRevision?: bigint;
  readonly recipients: PolicyRecipients;
}

/** Fixed by the rail, Rust `PolicyRecipients`. */
export type PolicyRecipients =
  /** The anonymous rail, every recipient zero. */
  | Readonly<{ kind: "hidden" }>
  /** One owner identity per output slot. */
  | Readonly<{ kind: "framed"; recipients: readonly Bytes32[] }>;

/** The owner SPP's anonymous rail verifies and hides, the delivered audit publishes it. */
export interface InProofOwner {
  readonly owner: Bytes32;
  readonly commitment: Bytes32;
  readonly commitmentPok: Bytes32;
}

export function publishesRecipients(rail: RingRail): boolean {
  return rail !== "anonymous";
}

/** The anonymous SPP rail's BSB22 commitment and its hidden owner's default-ring key. */
export interface AnonymousProofData {
  readonly commitment: Bytes32;
  readonly commitmentPok: Bytes32;
  readonly defaultOwnerTag?: Bytes32;
}

export type InputTrees =
  | Readonly<{ kind: "one"; context: TreeContext }>
  | Readonly<{
      kind: "two";
      first: TreeContext;
      second: TreeContext;
      /** Bit `i` spends input `i` from `second`. */
      secondInputs: bigint;
    }>;

/** One published output slot without its SPP framing, Rust `RingOutput`. */
export type RingOutput =
  | Readonly<{ kind: "delivered"; hash: Bytes32; u: Bytes32; body: Uint8Array }>
  /** Under a view tag, its scheme 1 body unproven and absent on a change output. */
  | Readonly<{ kind: "anonymous"; hash: Bytes32; tag: Bytes32; body?: Uint8Array }>
  | Readonly<{ kind: "exit"; hash: Bytes32; ownerTag: Bytes32; payload: Uint8Array }>;

/** Scheme 2, forwarded under its tag as the first SPP message, Rust `SenderBundle`. */
export interface SenderBundle {
  readonly tag: Bytes32;
  readonly body: Uint8Array;
}

/** The data of `Transfer` and `AuthorityTransfer`, Rust `RingTransactData`. */
export interface RingTransactData {
  readonly rail: RingRail;
  /** SPP shape inputs. */
  readonly nIn: number;
  /** SPP shape outputs. */
  readonly nOut: number;
  readonly proof: Uint8Array;
  /** Present under a policy or the exempt flag, the own registry revision the roots read. */
  readonly ownRevision?: bigint;
  /** Present exactly on a policy ring. */
  readonly policy?: PolicyProof;
  /** Every public withdrawal stays within its record's threshold, the proof binds the claim. */
  readonly exempt: boolean;
  readonly approvalRequired: boolean;
  readonly expiryUnixTs: number;
  readonly txViewingU: Bytes32;
  /** Random per attempt, a resend under the same first nullifier reuses no pad or keystream. */
  readonly salt: Bytes16;
  readonly interfaceTransfers: readonly InterfaceTransfer[];
  /** The policy proof escrows every output nullifier key, the ring mode's. */
  readonly keyEscrow: boolean;
  /** The anonymous entry key, every spent UTXO opens in full. */
  readonly fullOpenings: boolean;
  /** Published order. */
  readonly outputs: readonly RingOutput[];
  /** Present exactly on the anonymous rail. */
  readonly sender?: SenderBundle;
  readonly ephU: Bytes32;
  /** `tx_viewing_sk ‖ evidence` under the auditor stream. */
  readonly envelope: Uint8Array;
  /** The auditor records of the slots that have one, in slot order. */
  readonly records: readonly Uint8Array[];
  readonly privateTxHash: Bytes32;
  /** Present exactly on the anonymous rail. */
  readonly anonymous?: AnonymousProofData;
  /** Set exactly on the in-proof owner rail. */
  readonly inProofOwner?: InProofOwner;
  /** `a ‖ b ‖ c` with `b` compressed. */
  readonly sppProof: Uint8Array;
  /** One per spent input slot SPP publishes. */
  readonly nullifiers: readonly Bytes32[];
  readonly inputTrees: InputTrees;
}

/** The ring config values the program expands the data with. */
export interface RingTransactConfig {
  /** `0x04 ‖ u`. */
  readonly auditorPubkey: Bytes33;
}

/** The rail of the ring instruction `tag` under `mode`, Rust `RingRail::of`. */
export function ringRailOf(tag: number, mode: RingMode): RingRail {
  if (tag === RingInstructionTag.transfer || tag === RingInstructionTag.legacyTransact)
    return mode === "anonymous" ? "anonymous" : "confidential";
  if (
    tag !== RingInstructionTag.authorityTransfer &&
    tag !== RingInstructionTag.legacyDelegateTransact
  )
    throw invalid("InvalidInstructionData");
  if (mode === "anonymous") throw invalid("AnonymousRingRefused");
  return "delegate";
}

/** The rail of a landed ring instruction, an in-proof owner runs the confidential rail through SPP's anonymous circuit. */
export function landedRingRail(instruction: Uint8Array, sppAnonymous: boolean): RingRail {
  const tag = instruction[0];
  if (tag === undefined) throw invalid("InvalidInstructionData");
  const ownerInProof = has(instruction[1] ?? 0, Flag.ownerInProof);
  return ringRailOf(tag, sppAnonymous && !ownerInProof ? "anonymous" : "confidential");
}

/** Rust `RingRail::new`, the delegate rail needs the delegate only `SetDelegate` writes. */
export function ringRail(
  tag: number,
  config: Readonly<{ mode: RingMode; delegate?: Address }>,
): RingRail {
  const rail = ringRailOf(tag, config.mode);
  if (rail === "delegate" && config.delegate === undefined) throw invalid("DelegateDisabled");
  return rail;
}

export function railSppTag(rail: RingRail): number {
  return rail === "delegate" ? InstructionTag.ringAuthorityTransact : InstructionTag.ringTransact;
}

/** `pack_be(u)` of a delivered slot, zeros for any other. */
export function outputRecipientKeyFields(output: RingOutput): readonly Bytes32[] {
  return output.kind === "delivered"
    ? (packBytesBe(checkedField(output.u, "u")) as Bytes32[])
    : [ZERO, ZERO];
}

/** SPP's input slots and tree contexts, the nullifier accounts the instruction names follow them. */
export function ringSppInputs(
  data: Pick<RingTransactData, "nullifiers" | "inputTrees">,
): Pick<TransactInstructionData, "inputs" | "treeContexts"> {
  return Object.freeze({
    inputs: data.nullifiers.map((nullifierHash, input) =>
      Object.freeze({ nullifierHash, treeIndex: treeIndex(data.inputTrees, input) }),
    ),
    treeContexts:
      data.inputTrees.kind === "one"
        ? [data.inputTrees.context]
        : [data.inputTrees.first, data.inputTrees.second],
  });
}

/** The stream layout the audit key of a shape fixes, `inputs` the published count. */
export function ringStreamLayout(
  shape: Readonly<{
    rail: RingRail;
    nIn: number;
    nOut: number;
    inputs: number;
    outputs: number;
    keyEscrow: boolean;
    fullOpenings: boolean;
    exits: bigint;
    /** The in-proof owner signs inside SPP's anonymous rail proof. */
    ownerInProof?: boolean;
  }>,
): AuditStreamLayout {
  const flags: FrameFlags = {
    defaultOwnerTag: false,
    keyEscrow: shape.keyEscrow,
    fullOpenings: shape.fullOpenings,
  };
  checkFrameFlags(flags, shape.rail);
  if (shape.outputs !== shape.nOut) throw invalid("RingTransactLength");
  return auditShape(shape.rail, {
    nIn: shape.nIn,
    nOut: shape.nOut,
    inputCount: shape.inputs,
    flags,
    ownerInProof: shape.ownerInProof ?? false,
  }).layout(shape.exits);
}

/** `0x04 ‖ u`, the tagged key the statements pack and SPP carries. */
export function taggedX25519(u: Bytes32): Bytes33 {
  const key = new Uint8Array(33);
  key[0] = VIEWING_PUBKEY_TAG;
  key.set(checkedField(u, "u"), 1);
  return key as Bytes33;
}

export const RingTransactData = Object.freeze({
  /** Every length fixed by the flags, the shape and the counts, trailing bytes refused. */
  parse(data: Uint8Array, rail: RingRail): RingTransactData {
    try {
      return readCompact(new Reader(data), rail);
    } catch (error) {
      throw shortRead(error, "RingTransactLength");
    }
  },

  /** The bytes `parse` reads back, refusing what it refuses. */
  encode(data: RingTransactData): Uint8Array {
    try {
      return writeCompact(data);
    } catch (error) {
      throw shortRead(error, "InvalidInstructionData");
    }
  },

  auditLayout(data: RingTransactData): AuditLayout {
    return Object.freeze({
      keyEscrow: data.keyEscrow,
      fullOpenings: data.fullOpenings,
    });
  },

  streamLayout(data: RingTransactData): AuditStreamLayout {
    return ringStreamLayout({
      rail: data.rail,
      nIn: data.nIn,
      nOut: data.nOut,
      inputs: data.nullifiers.length,
      outputs: data.outputs.length,
      keyEscrow: data.keyEscrow,
      fullOpenings: data.fullOpenings,
      exits: exitsBitmap(data.outputs),
      ownerInProof: data.inProofOwner !== undefined,
    });
  },

  /** One ring disclosure ciphertext per slot in output order, its delivered body or its record. */
  outputCiphertexts(data: RingTransactData): readonly Uint8Array[] {
    const records = data.records[Symbol.iterator]();
    return data.outputs.map((output) => {
      if (output.kind === "delivered") return checkedBody(output.body);
      const record = records.next();
      if (record.done === true) throw invalid("RingTransactLength");
      return record.value;
    });
  },

  /** The SPP selector of the data's shape and rail. */
  circuit(data: RingTransactData): RingCircuitId {
    return circuitId(data);
  },

  /** One per output slot, zero off a policy and on the anonymous rail, Rust `recipients`. */
  recipients(data: RingTransactData): readonly Bytes32[] {
    const recipients = data.policy?.recipients;
    return recipients?.kind === "framed" ? recipients.recipients : data.outputs.map(() => ZERO);
  },

  /** The transfer key serving the frame with `legs` public withdrawals, Rust `transfer_circuit`. */
  transferCircuit(data: RingTransactData, legs: number): TransferKeyCircuit {
    const circuit = ringTransferCircuit({
      rail: data.rail,
      inputs: data.nullifiers.length,
      outputs: data.nOut,
      spendsDefaultRing: data.fullOpenings,
      legs,
    });
    if (circuit === undefined) throw invalid("RingShapeUnkeyed");
    return circuit;
  },

  firstNullifier(data: RingTransactData): Bytes32 {
    const first = data.nullifiers[0];
    if (first === undefined) throw invalid("RingTransactLength");
    return first;
  },

  /** The SPP data the program forwards, `b` decompressed for SPP's verifier. */
  expand(data: RingTransactData, config: RingTransactConfig): RingTransactInstructionData {
    let b: Bytes128;
    try {
      b = decompressG2(data.sppProof.slice(32, 96) as Bytes64);
    } catch (cause) {
      throw new RingError("RING_TRANSACT_DATA_INVALID", {
        details: { reason: "InvalidSppProofPoint" },
        cause,
      });
    }
    return transactIxData(data, config, {
      a: data.sppProof.slice(0, 32) as Bytes32,
      b,
      c: data.sppProof.slice(96, 128) as Bytes32,
    });
  },

  sppInstructionData(data: RingTransactData, config: RingTransactConfig): Uint8Array {
    const expanded = encodeRingTransactInstructionData(RingTransactData.expand(data, config));
    const out = new Uint8Array(1 + expanded.length);
    out[0] = railSppTag(data.rail);
    out.set(expanded, 1);
    return out;
  },

  /** The external data hash the SPP proof binds, computable before either proof exists. */
  externalDataHash(
    data: RingTransactData,
    config: RingTransactConfig,
    settlements: readonly SettlementAccounts[],
  ): Bytes32 {
    const expanded = transactIxData(data, config, ZERO_PROOF);
    return externalDataHash({
      ...expanded,
      instructionDiscriminator: railSppTag(data.rail),
      settlementAccounts: settlements,
      resolvedOwnerTags: expanded.outputs.map((output) =>
        output.ownerTag.kind === "inline" ? output.ownerTag.value : ZERO,
      ),
    });
  },
});

/** Byte 0 of the compact data. */
const Flag = Object.freeze({
  policy: 1 << 0,
  curator: 1 << 1,
  approvalRequired: 1 << 2,
  /** The confidential rail's owner signs inside SPP's anonymous rail proof. */
  ownerInProof: 1 << 3,
  exempt: 1 << 4,
  secondTree: 1 << 5,
});
/** Bits 6 and 7 are refused. */
const KNOWN_FLAGS =
  Flag.policy |
  Flag.curator |
  Flag.approvalRequired |
  Flag.ownerInProof |
  Flag.exempt |
  Flag.secondTree;

/** Bytes 1 and 2 of the compact data, the SPP shape's index and the input count below their flags. */
const FrameByte = Object.freeze({
  low: 0b0011_1111,
  bit6: 1 << 6,
  bit7: 1 << 7,
});

/** The flags of frame bytes 1 and 2, Rust `FrameFlags`. */
interface FrameFlags {
  /** Shape byte bit 6, the anonymous rail's default owner tag follows the commitment pok. */
  readonly defaultOwnerTag: boolean;
  /** Input byte bit 6. */
  readonly keyEscrow: boolean;
  /** Input byte bit 7, the anonymous entry key. */
  readonly fullOpenings: boolean;
}

interface FrameHeader {
  readonly nIn: number;
  readonly nOut: number;
  readonly inputCount: number;
  readonly flags: FrameFlags;
  /** Byte 0's `ownerInProof`, the audit takes the sender key. */
  readonly ownerInProof: boolean;
}

/** A storage revision, little endian u64. */
export const REVISION_LENGTH = 8;
/** `a ‖ b ‖ c` with `b` compressed, Rust `PlainGroth16Proof::SIZE`. */
export const PLAIN_GROTH16_PROOF_LENGTH = 128;
const VIEWING_PUBKEY_TAG = 4;
const ZERO = new Uint8Array(32) as Bytes32;
const ZERO_PROOF = Object.freeze({
  a: new Uint8Array(32) as Bytes32,
  b: new Uint8Array(128) as Bytes128,
  c: new Uint8Array(32) as Bytes32,
});

type AuditShape = Readonly<{
  /** Every slot of the shape is published. */
  outputs: number;
  layout(exits: bigint): AuditStreamLayout;
}>;

/** Rust `RingRail::supports`, the authority rail admits SPP's ring-authority widths alone. */
export function railShapes(rail: RingRail): readonly Shape[] {
  return rail === "delegate" ? RING_AUTHORITY_SHAPES : SPP_SUPPORTED_SHAPES;
}

/** The audit key the header names, before the outputs are read, Rust `RingRail::audit_shape`. */
function auditShape(rail: RingRail, header: FrameHeader): AuditShape {
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

function readCompact(bytes: Reader, rail: RingRail): RingTransactData {
  const flags = bytes.u8("flags");
  checkFlags(flags, rail);
  const header = readHeader(bytes, rail, flags);
  const { nIn, nOut, inputCount } = header;
  const shape = auditShape(rail, header);
  const proof = bytes.bytes(CUSTOM_RING_PROOF_LENGTH, "proof");
  const ownRevision = readsOwnRoot(flags) ? bytes.u64("ownRevision") : undefined;
  let policy = has(flags, Flag.policy)
    ? readPolicy(bytes, {
        curator: has(flags, Flag.curator),
        recipients: publishesRecipients(rail) ? "framed" : "hidden",
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
  if (policy !== undefined)
    policy = Object.freeze({
      ...policy,
      splWithdrawalOwners: Object.freeze(
        interfaceTransfers
          .filter((t) => t.kind === "splWithdrawal")
          .map(() => field32(bytes, "splWithdrawalOwner")),
      ),
    });
  const outputCount = shape.outputs;
  const exits = readBitmap(bytes, outputCount);
  if (rail === "delegate" && exits !== 0n) throw invalid("FlagNotAllowed");
  const layout = shape.layout(exits);
  const outputs = Array.from({ length: outputCount }, (_, slot) => readOutput(bytes, layout, slot));
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
  const inputTrees: InputTrees = has(flags, Flag.secondTree)
    ? (() => {
        const secondInputs = readBitmap(bytes, inputCount);
        return Object.freeze({
          kind: "two" as const,
          first: readTreeContext(bytes),
          second: readTreeContext(bytes),
          secondInputs,
        });
      })()
    : Object.freeze({ kind: "one" as const, context: readTreeContext(bytes) });
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

function readPolicy(
  bytes: Reader,
  section: Readonly<{
    curator: boolean;
    recipients: PolicyRecipients["kind"];
    outputs: number;
  }>,
): PolicyProof {
  const curatorRevision = section.curator ? bytes.u64("policy.curatorRevision") : undefined;
  const recipients: PolicyRecipients =
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

function readSender(bytes: Reader): SenderBundle {
  const tag = field32(bytes, "sender.tag");
  const body = readAnonymousBody(bytes, "sender");
  if (body.length === 0) throw invalid("AnonymousBodyLength");
  return Object.freeze({ tag, body });
}

function readAnonymous(bytes: Reader, tagged: boolean): AnonymousProofData {
  const commitment = field32(bytes, "anonymous.commitment");
  const commitmentPok = field32(bytes, "anonymous.commitmentPok");
  const defaultOwnerTag = tagged ? field32(bytes, "anonymous.defaultOwnerTag") : undefined;
  return Object.freeze({
    commitment,
    commitmentPok,
    ...(defaultOwnerTag === undefined ? {} : { defaultOwnerTag }),
  });
}

/** No output carries data, every exit payload is a data-free scheme 3 body. */
function readOutput(bytes: Reader, layout: AuditStreamLayout, slot: number): RingOutput {
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

function writeCompact(data: RingTransactData): Uint8Array {
  const flags = compactFlags(data);
  checkFlags(flags, data.rail);
  if ([data.keyEscrow, data.fullOpenings, data.exempt].some((flag) => typeof flag !== "boolean"))
    throw invalid("InvalidInstructionData");
  const header = headerOf(data);
  const shape = auditShape(data.rail, header);
  if (data.outputs.length !== shape.outputs) throw invalid("RingTransactLength");
  const layout = shape.layout(exitsBitmap(data.outputs));
  const slots = recordSlots(layout);
  const anonymousRail = data.rail === "anonymous";
  const policyFits = data.policy === undefined || recipientsFit(data.policy.recipients, data);
  if (data.exempt && !withdraws(data.interfaceTransfers))
    throw invalid("ExemptionWithoutWithdrawal");
  if (
    !policyFits ||
    (data.ownRevision !== undefined) !== readsOwnRoot(flags) ||
    (data.anonymous !== undefined) !== anonymousRail ||
    (data.sender !== undefined) !== anonymousRail ||
    data.envelope.length !== envelopeRegion(layout).length ||
    data.records.length !== slots.length ||
    slots.some((slot, index) => data.records[index]?.length !== recordLen(layout, slot)) ||
    !data.outputs.every((output) => fits(output, layout))
  )
    throw invalid("RingTransactLength");
  if (data.rail === "delegate" && data.outputs.some((output) => output.kind === "exit"))
    throw invalid("FlagNotAllowed");
  const [shapeByte, inputByte] = headerBytes(header);
  const out = new Writer()
    .u8(flags, "flags")
    .u8(shapeByte, "shapeByte")
    .u8(inputByte, "inputByte")
    .bytes(data.proof, CUSTOM_RING_PROOF_LENGTH, "proof");
  if (data.ownRevision !== undefined) out.u64(data.ownRevision, "ownRevision");
  if (data.policy !== undefined) {
    if (data.policy.curatorRevision !== undefined)
      out.u64(data.policy.curatorRevision, "policy.curatorRevision");
    const { recipients } = data.policy;
    if (recipients.kind === "framed")
      for (const recipient of recipients.recipients) out.bytes(recipient, 32, "policy.recipient");
  }
  out
    .u32(data.expiryUnixTs, "expiryUnixTs")
    .bytes(data.txViewingU, 32, "txViewingU")
    .bytes(data.salt, 16, "salt")
    .u8(data.interfaceTransfers.length, "interfaceTransfers.length");
  for (const transfer of data.interfaceTransfers) writeInterfaceTransfer(out, transfer);
  if (data.policy !== undefined) {
    if (
      data.policy.splWithdrawalOwners.length !==
      data.interfaceTransfers.filter((t) => t.kind === "splWithdrawal").length
    )
      throw invalid("RingTransactLength");
    for (const owner of data.policy.splWithdrawalOwners) out.bytes(owner, 32, "splWithdrawalOwner");
  }
  writeBitmap(
    out,
    data.outputs.map((output) => output.kind === "exit"),
  );
  for (const output of data.outputs) writeOutput(out, output);
  if (data.sender !== undefined) {
    out.bytes(data.sender.tag, 32, "sender.tag");
    writeAnonymousBody(out, data.sender.body, "sender");
  }
  out.bytes(data.ephU, 32, "ephU").bytes(data.envelope);
  for (const record of data.records) out.bytes(record);
  out.bytes(data.privateTxHash, 32, "privateTxHash");
  if (data.anonymous !== undefined) {
    out
      .bytes(data.anonymous.commitment, 32, "anonymous.commitment")
      .bytes(data.anonymous.commitmentPok, 32, "anonymous.commitmentPok");
    if (data.anonymous.defaultOwnerTag !== undefined)
      out.bytes(data.anonymous.defaultOwnerTag, 32, "anonymous.defaultOwnerTag");
  }
  if (data.inProofOwner !== undefined)
    out
      .bytes(data.inProofOwner.owner, 32, "inProofOwner.owner")
      .bytes(data.inProofOwner.commitment, 32, "inProofOwner.commitment")
      .bytes(data.inProofOwner.commitmentPok, 32, "inProofOwner.commitmentPok");
  out.bytes(data.sppProof, PLAIN_GROTH16_PROOF_LENGTH, "sppProof");
  for (const nullifier of data.nullifiers) out.bytes(nullifier, 32, "nullifier");
  if (data.inputTrees.kind === "one") {
    writeTreeContext(out, data.inputTrees.context);
  } else {
    const { secondInputs } = data.inputTrees;
    if (
      typeof secondInputs !== "bigint" ||
      secondInputs < 0n ||
      secondInputs >> BigInt(header.inputCount) !== 0n
    )
      throw invalid("InvalidInstructionData");
    writeBitmap(
      out,
      data.nullifiers.map((_, input) => ((secondInputs >> BigInt(input)) & 1n) === 1n),
    );
    writeTreeContext(out, data.inputTrees.first);
    writeTreeContext(out, data.inputTrees.second);
  }
  return out.finish();
}

function writeOutput(out: Writer, output: RingOutput): void {
  out.bytes(output.hash, 32, "output.hash");
  switch (output.kind) {
    case "delivered":
      out.bytes(output.u, 32, "output.u").bytes(output.body);
      return;
    case "anonymous":
      out.bytes(output.tag, 32, "output.tag");
      if (output.body === undefined) out.u16(0, "output.length");
      else writeAnonymousBody(out, output.body, "output");
      return;
    case "exit":
      if (output.payload.length !== CONFIDENTIAL_DATA_FREE_BODY_LEN)
        throw invalid("DataFreeBodyLength");
      out.bytes(output.ownerTag, 32, "output.ownerTag").bytes(output.payload);
      return;
  }
}

function writeAnonymousBody(out: Writer, body: Uint8Array, name: string): void {
  out.u16(checkedAnonymousBody(body).length, `${name}.length`).bytes(body);
}

function writeBitmap(out: Writer, bits: readonly boolean[]): void {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  bits.forEach((set, index) => {
    if (set) bytes[index >> 3] = (bytes[index >> 3] ?? 0) | (1 << (index & 7));
  });
  out.bytes(bytes);
}

function fits(output: RingOutput, layout: AuditStreamLayout): boolean {
  switch (output.kind) {
    case "exit":
      return true;
    case "delivered":
      return (
        layout.key.kind === "confidential" &&
        output.body.length === deliveredBodyLen(layout.keyEscrow)
      );
    case "anonymous":
      return layout.key.kind !== "confidential";
  }
}

function recipientsFit(recipients: PolicyRecipients, data: RingTransactData): boolean {
  switch (recipients.kind) {
    case "hidden":
      return data.rail === "anonymous";
    case "framed":
      return data.rail !== "anonymous" && recipients.recipients.length === data.outputs.length;
  }
}

function compactFlags(data: RingTransactData): number {
  const bits: readonly (readonly [boolean, number])[] = [
    [data.policy !== undefined, Flag.policy],
    [data.policy?.curatorRevision !== undefined, Flag.curator],
    [data.approvalRequired, Flag.approvalRequired],
    [data.inProofOwner !== undefined, Flag.ownerInProof],
    [data.exempt, Flag.exempt],
    [data.inputTrees.kind === "two", Flag.secondTree],
  ];
  return bits.reduce((flags, [set, bit]) => (set ? flags | bit : flags), 0);
}

/** The curator and approval flags need a policy, the in-proof owner flag the confidential rail, the exempt flag never a delegate frame. */
function checkFlags(flags: number, rail: RingRail): void {
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

/** A policy or an exemption opens own registry records, the frame then carries the revision. */
function readsOwnRoot(flags: number): boolean {
  return has(flags, Flag.policy) || has(flags, Flag.exempt);
}

function withdraws(transfers: readonly InterfaceTransfer[]): boolean {
  return transfers.some(
    (transfer) => transfer.kind === "solWithdrawal" || transfer.kind === "splWithdrawal",
  );
}

function readHeader(bytes: Reader, rail: RingRail, transact: number): FrameHeader {
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

function headerOf(data: RingTransactData): FrameHeader {
  const flags: FrameFlags = {
    defaultOwnerTag: data.anonymous?.defaultOwnerTag !== undefined,
    keyEscrow: data.keyEscrow,
    fullOpenings: data.fullOpenings,
  };
  checkFrameFlags(flags, data.rail);
  return {
    nIn: data.nIn,
    nOut: data.nOut,
    inputCount: data.nullifiers.length,
    flags,
    ownerInProof: data.inProofOwner !== undefined,
  };
}

function headerBytes(header: FrameHeader): readonly [number, number] {
  const index = SPP_SUPPORTED_SHAPES.findIndex(
    (shape) => shape.inputs === header.nIn && shape.outputs === header.nOut,
  );
  if (index < 0) throw invalid("RingShapeUnkeyed");
  if (header.inputCount > FrameByte.low) throw invalid("RingTransactLength");
  const { flags } = header;
  const bit = (set: boolean, value: number) => (set ? value : 0);
  return [
    index | bit(flags.defaultOwnerTag, FrameByte.bit6),
    header.inputCount |
      bit(flags.keyEscrow, FrameByte.bit6) |
      bit(flags.fullOpenings, FrameByte.bit7),
  ];
}

/** The anonymous rail alone takes a default owner tag and the entry key and never escrows, the delegate rail always escrows. */
function checkFrameFlags(flags: FrameFlags, rail: RingRail): void {
  const anonymousOnly = flags.defaultOwnerTag || flags.fullOpenings;
  const refused =
    rail === "anonymous"
      ? flags.keyEscrow
      : rail === "confidential"
        ? anonymousOnly
        : anonymousOnly || !flags.keyEscrow;
  if (refused) throw invalid("FlagNotAllowed");
}

function circuitId(data: RingTransactData): RingCircuitId {
  const { anonymous, inProofOwner } = data;
  const shape = { inputs: data.nIn, outputs: data.nOut, publicAssetSlots: N_PUBLIC_SLOTS };
  switch (data.rail) {
    case "confidential":
      // Ring notes only, a default owner tag would publish the owner SPP hides.
      if (inProofOwner !== undefined)
        return Object.freeze({
          kind: "anonymousRingEddsa",
          ...shape,
          proofData: Object.freeze({
            bsb22Commitment: Object.freeze({
              commitment: inProofOwner.commitment,
              commitmentPok: inProofOwner.commitmentPok,
            }),
          }),
        });
      return Object.freeze({ kind: "confidentialRingEddsa", ...shape });
    case "delegate":
      return Object.freeze({ kind: "ringAuthority", ...shape });
    case "anonymous":
      if (anonymous === undefined) throw invalid("RingTransactLength");
      return Object.freeze({
        kind: "anonymousRingEddsa",
        ...shape,
        proofData: Object.freeze({
          bsb22Commitment: Object.freeze({
            commitment: anonymous.commitment,
            commitmentPok: anonymous.commitmentPok,
          }),
          ...(anonymous.defaultOwnerTag === undefined
            ? {}
            : { defaultOwnerTag: anonymous.defaultOwnerTag }),
        }),
      });
  }
}

function transactIxData(
  data: RingTransactData,
  config: RingTransactConfig,
  proof: TransactInstructionData["proof"],
): RingTransactInstructionData {
  const auditor = config.auditorPubkey;
  if (!(auditor instanceof Uint8Array) || auditor.length !== 33)
    throw invalid("InvalidAuditorPubkey");
  return Object.freeze({
    expiryUnixTs: BigInt(data.expiryUnixTs),
    txViewingPk: taggedX25519(data.txViewingU),
    salt: data.salt,
    interfaceTransfers: data.interfaceTransfers,
    outputs: data.outputs.map(ringTransactOutput),
    // The auditor message stays last.
    messages: [
      ...(data.sender === undefined
        ? []
        : [
            Object.freeze({
              viewTag: checkedField(data.sender.tag, "sender.tag"),
              data: encodeRingOutput(
                RingScheme.anonymousSender,
                checkedAnonymousBody(data.sender.body),
              ),
            }),
          ]),
      Object.freeze({
        viewTag: auditor.slice(1) as Bytes32,
        data: concat([taggedX25519(data.ephU), data.envelope, ...data.records]),
      }),
    ],
    privateTxHash: data.privateTxHash,
    circuit: RingTransactData.circuit(data),
    proof,
    ...ringSppInputs(data),
  });
}

/** The SPP output, the owner tag and the scheme framing rebuilt from the slot, Rust `RingOutput::transact_output`. */
export function ringTransactOutput(output: RingOutput): TransactOutput {
  const [ownerTag, data] = ((): readonly [Bytes32, Uint8Array | undefined] => {
    switch (output.kind) {
      case "delivered":
        return [
          output.u,
          encodeRingOutput(RingScheme.ringConfidentialDelivered, checkedBody(output.body)),
        ];
      case "anonymous":
        return [
          output.tag,
          output.body === undefined
            ? undefined
            : encodeRingOutput(RingScheme.anonymousRecipient, checkedAnonymousBody(output.body)),
        ];
      case "exit":
        return [output.ownerTag, encodeRingOutput(RingScheme.confidential, output.payload)];
    }
  })();
  return Object.freeze({
    utxoHash: output.hash,
    ownerTag: Object.freeze({ kind: "inline", value: checkedField(ownerTag, "ownerTag") }),
    ...(data === undefined ? {} : { data }),
  });
}

/** The inline tag SPP reads the slot's owner identity from, Rust `RingOutput::owner_tag`. */
export function outputOwnerTag(output: RingOutput): Bytes32 {
  switch (output.kind) {
    case "delivered":
      return output.u;
    case "anonymous":
      return output.tag;
    case "exit":
      return output.ownerTag;
  }
}

function treeIndex(trees: InputTrees, input: number): number {
  return trees.kind === "one" ? 0 : Number((trees.secondInputs >> BigInt(input)) & 1n);
}

function field32(bytes: Reader, name: string): Bytes32 {
  return bytes.bytes(32, name) as Bytes32;
}

function checkedField(value: Uint8Array, name: string): Bytes32 {
  if (!(value instanceof Uint8Array) || value.length !== 32)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "InvalidInstructionData", name },
    });
  return value as Bytes32;
}

function checkedAnonymousBody(body: Uint8Array): Uint8Array {
  if (!(body instanceof Uint8Array) || body.length === 0 || body.length > 0xffff)
    throw invalid("AnonymousBodyLength");
  return body;
}

/** The ring's key escrow flag picks one of the lengths, `writeCompact` holds a frame to it. */
function checkedBody(body: Uint8Array): Uint8Array {
  if (
    !(body instanceof Uint8Array) ||
    (body.length !== DELIVERED_BODY_LEN && body.length !== ESCROWED_DELIVERED_BODY_LEN)
  )
    throw invalid("RingTransactLength");
  return body;
}

/** Bit `i` set when slot `i` exits. */
export function exitsBitmap(outputs: readonly RingOutput[]): bigint {
  return outputs.reduce(
    (bits, output, slot) => (output.kind === "exit" ? bits | (1n << BigInt(slot)) : bits),
    0n,
  );
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** An interface codec failure inside `run` reads as `reason`. */
function within<T>(reason: string, run: () => T): T {
  try {
    return run();
  } catch (error) {
    throw shortRead(error, reason);
  }
}

/** A short read or a codec refusal is the program's `reason`, a ring refusal passes through. */
function shortRead(error: unknown, reason: string): unknown {
  return error instanceof InterfaceError
    ? new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason }, cause: error })
    : error;
}

/** `reason` names the `CustomRingError` the program raises. */
function invalid(reason: string): RingError {
  return new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason } });
}
