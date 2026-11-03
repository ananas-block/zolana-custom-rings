import {
  EMPTY_MINT_POLICY,
  assetLimitsFields,
  mintPolicyField,
  mintPolicyWriteField,
  type AssetLimits,
} from "../../protocol/membership/mint-policy.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { InterfaceError } from "@heliuslabs/zolana/interface";
import { bigIntBytes, bytesField, type ExpectedProvingKey } from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32 } from "@heliuslabs/zolana/interface";
import { type PresentRecordOpening } from "./types.js";
import { ClientError } from "@heliuslabs/zolana/client";
import {
  APPLY_BATCH,
  MEMBER_REGISTRY_CAPACITY,
  QUAD_ARITY,
  QUAD_HEIGHT,
  canopyLevels,
  type ApplyProofInputs,
  type MemberRecord,
  type QuadPath,
  type QueueEntry,
  type RecordOpening,
  type RecordPool,
  type RecordWriteProofInput,
} from "../../protocol/membership/member-registry.js";
import {
  ringCircuitType,
  ringProvingKey,
  type RingKeyCircuit,
} from "../../protocol/proof/proving-keys.js";
import {
  screenedOwners,
  transferPoolCapacity,
  type PolicyPoolCapacity,
  type TransferKeyCircuit,
} from "../../protocol/proof/transfer-shapes.js";
import { RING_DEPOSIT_AUDIT_SLOTS } from "../../protocol/codec/ring-deposit-capsule.js";
import { RECIPIENT_BODY_LEN } from "../../protocol/codec/anonymous-delivery.js";
import {
  auditLayoutValue,
  deliveredBodyLen,
  type AuditLayout,
} from "../../protocol/codec/ring-disclosure-layout.js";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "./types.js";
import { N_PUBLIC_SLOTS } from "../../protocol/transaction/spp.js";

/** Go `Opening`, one transaction slot as the ring circuits open it. */
export interface RingSlotOpening {
  readonly domain: Bytes32;
  readonly treeId: Bytes32;
  readonly ownerPkHash: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly asset: Bytes32;
  readonly amount: Bytes32;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly ringProgramId: Bytes32;
}

/** Go `AuditParams`, the envelope inputs every transfer proof opens with. */
export interface AuditEnvelopeProofInputs {
  readonly firstNullifier: Bytes32;
  /** The clamped secret the envelope seals. */
  readonly txViewingSk: Bytes32;
  readonly ephSk: Bytes32;
  /** The auditor's X25519 u without the tag byte. */
  readonly auditorPk: Bytes32;
  readonly salt: Bytes16;
  /** The statement's layout element, its flags fix the ciphertext lengths. */
  readonly layout: AuditLayout;
}

/** Go `DeliveredOutput`, a delivered slot and the body its recipient decrypts. */
export interface DeliveredSlotProofInputs {
  readonly output: RingSlotOpening;
  readonly recipientKey: Bytes32;
  readonly ownerKey: Bytes32;
  readonly body: Uint8Array;
}

/** The owner key zero on a dummy, the key and revision zero off a live ring slot, a change slot holds the sender's. */
export interface AnonymousSlotProofInputs {
  readonly output: RingSlotOpening;
  readonly ownerKey: Bytes32;
  readonly recipientKey: Bytes32;
  readonly addressRevision: bigint;
  readonly mintChunks: readonly Bytes32[];
  readonly body: Uint8Array;
  /** Zero on change, an exit and an omitted slot. */
  readonly tag: Bytes32;
  /** Read only on a published dummy, zero elsewhere. */
  readonly tagPreimage: Bytes32;
}

/** Go `Source`, a zero `registry` names the ring's own registry. */
export interface PolicySourceProofInput {
  readonly listId: number;
  readonly registry: Bytes32;
}

/** Go `OutflowLimit`. */
export interface OutflowLimitProofInput {
  readonly asset: Bytes32;
  readonly cap: Bytes32;
  readonly cosignAbove: Bytes32;
}

/** Go `PolicyTable`, every row past its count zero. */
export interface PolicyTableProofInputs {
  readonly sources: readonly PolicySourceProofInput[];
  readonly policyLen: number;
  readonly rules: readonly Bytes32[];
}

/** Go `PooledEntry`, the curator index 0 without a curator registry. */
export interface PolicySubjectEntry {
  readonly own: number;
  readonly curator: number;
}

/** Go `PolicyParams`, one owner and one asset entry per output and withdrawal slot, both pools at the key's widths. */
export interface PolicyProofInputs extends PolicyTableProofInputs {
  readonly withdrawalCount: number;
  readonly withdrawalHash: Bytes32;
  readonly withdrawals: readonly Readonly<{ owner: Bytes32; asset: Bytes32; amount: bigint }>[];
  readonly policyHash: Bytes32;
  readonly ringId: Bytes32;
  readonly ownRoot: Bytes32;
  readonly curatorRoot: Bytes32;
  readonly publicAssets: readonly Bytes32[];
  readonly publicAmounts: readonly Bytes32[];
  /** Gross withdrawals per slot as right aligned u128. */
  readonly publicGross: readonly Bytes32[];
  /** One per output slot, zero without key escrow. */
  readonly ctHashes: readonly Bytes32[];
  readonly recipients: readonly Bytes32[];
  readonly ownPool: RecordPool;
  readonly curatorPool: RecordPool;
  /** The pool rows of the key's `Q` screened owners, the proof derives the owners. */
  readonly senderEntries: readonly PolicySubjectEntry[];
  readonly ownerEntries: readonly PolicySubjectEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
  readonly publicAssetEntries: readonly number[];
}

/** Go `MergeInput`, one SPP merge slot. */
export interface MergeInputOpening {
  readonly domain: Bytes32;
  readonly treeId: Bytes32;
  readonly amount: Bytes32;
  readonly blinding: Bytes32;
  readonly ringDataHash: Bytes32;
}

/** Go `TransferParams`, what every transfer key reads. */
export interface TransferProofInputs extends AuditEnvelopeProofInputs, PolicyProofInputs {
  readonly publicInputHash: Bytes32;
  readonly exempt: boolean;
  readonly approvalRequired: boolean;
  /** The published nullifier count, the input slots past it carry no UTXO. */
  readonly inputCount: number;
  /** `m`, the slots past it leave the frame. */
  readonly outputCount: number;
  /** SPP's owner signer run by owner identity, zero filled to the key's `S`. */
  readonly signers: readonly Bytes32[];
  readonly signerCount: number;
  readonly privateTxHash: Bytes32;
  /** SPP's blinding of the hash, the proof reopens it with no address input. */
  readonly privateTxBlinding: Bytes32;
}

/** Go `ConfidentialTransferParams`, `inputs` fill the input class. */
export interface ConfidentialTransferProofRequest extends TransferProofInputs {
  readonly kind: "transferConfidential";
  readonly inProof: boolean;
  readonly delegate: boolean;
  readonly outputs: readonly DeliveredSlotProofInputs[];
  /** Every slot a dummy on the signer rail and past the spent notes. */
  readonly inputs: readonly RingSlotOpening[];
  /** The statement's sender, zero on the authority rail where `senderPkHash` names the member. */
  readonly sender: Bytes32;
  readonly senderPkHash: Bytes32;
}

/** Go `AnonymousTransferParams`, `inputs` fill the input class. */
export interface AnonymousTransferProofRequest extends TransferProofInputs {
  readonly kind: "transferAnonymous";
  readonly outputs: readonly AnonymousSlotProofInputs[];
  /** Present on the entry key alone. */
  readonly senderKey?: Bytes32;
  readonly inputs: readonly RingSlotOpening[];
  readonly partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
  /** `sender`'s address, its record binds it and change follows it. */
  readonly senderNullifierPk: Bytes32;
  readonly senderViewingKey: Bytes32;
  readonly senderAddressRevision: bigint;
  readonly senderBundleTag: Bytes32;
  /** `ciphertext_digest(reply region)`, zero without replies. */
  readonly replyDigest: Bytes32;
}

/** Go `ApplyRecordsParams`, one write takes the 1-write key, more the batch key. */
export interface ApplyRecordsProofRequest extends ApplyProofInputs {
  readonly kind: "applyRecords";
  readonly publicInputHash: Bytes32;
}

/** Go `KeyRegisterParams`. */
export interface RegisterKeyProofRequest {
  readonly kind: "registerKey";
  readonly publicInputHash: Bytes32;
  /** The owner identity of the signing member. */
  readonly member: Bytes32;
  /** A zero lead byte then the 31 secret bytes. */
  readonly nullifierSecret: Bytes32;
  readonly ephSk: Bytes32;
  readonly auditorPk: Bytes32;
}

/** Go `DepositParams`, every slot list at the deposit capacity. */
export interface DepositProofRequest {
  readonly kind: "deposit";
  readonly publicInputHash: Bytes32;
  readonly contextHash: Bytes32;
  readonly count: number;
  readonly anonymous: boolean;
  readonly ownerPkHashes: readonly Bytes32[];
  readonly ownerKeys: readonly Bytes32[];
  readonly nullifierPks: readonly Bytes32[];
  readonly blindingSecrets: readonly Bytes32[];
  readonly ctHashes: readonly Bytes32[];
  readonly members: readonly (PresentRecordOpening | undefined)[];
  readonly ephSk: Bytes32;
  readonly auditorPk: Bytes32;
  readonly keyEscrow: boolean;
  readonly memberRegistryRoot: Bytes32;
  readonly curatorRoot: Bytes32;
  readonly policyHash: Bytes32;
  /** SPP's asset field of each deposit's group. */
  readonly assets: readonly Bytes32[];
  readonly amounts: readonly Bytes32[];
  /** Absent without a written policy, `assetRecords` then opens nothing. */
  readonly table?: PolicyTableProofInputs;
  readonly assetRecords: readonly (RecordOpening | undefined)[];
  /** Undefined entries without a curator source. */
  readonly curatorAssetRecords: readonly (RecordOpening | undefined)[];
}

/** Go `MergeParams`. */
export interface MergeProofRequest {
  readonly partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
  readonly kind: "merge";
  readonly publicInputHash: Bytes32;
  readonly privateTxHash: Bytes32;
  readonly outputUtxoHash: Bytes32;
  readonly firstNullifier: Bytes32;
  readonly ringProgramId: Bytes32;
  readonly auditorPk: Bytes32;
  /** The SPP output ciphertext salt as one field. */
  readonly salt: Bytes32;
  readonly ephSk: Bytes32;
  readonly disclosureKey: Bytes32;
  readonly ownerKey: Bytes32;
  readonly nullifierSecret: Bytes32;
  /** `HashChain(mint[0..31], mint[31..32])`. */
  readonly asset: Bytes32;
  /** The published nullifiers, `1 <= inputCount <= width`, a hidden dummy counts. */
  readonly inputCount: number;
  readonly inputs: readonly MergeInputOpening[];
  readonly outputTreeId: Bytes32;
  readonly outputRingDataHash: Bytes32;
  readonly keyEscrow: boolean;
  readonly memberRegistryRoot: Bytes32;
  /** `hashBytes` of the RegisterKey ciphertext the record escrows beside the nullifier key. */
  readonly ctHash: Bytes32;
  /** Present exactly when `keyEscrow` is set. */
  readonly member?: PresentRecordOpening;
}

export type RingProofRequest =
  | ConfidentialTransferProofRequest
  | AnonymousTransferProofRequest
  | ApplyRecordsProofRequest
  | RegisterKeyProofRequest
  | DepositProofRequest
  | MergeProofRequest;

/** The key a request proves under, its list widths pick the shape. */
export function ringProofCircuit(request: RingProofRequest): RingKeyCircuit {
  switch (request.kind) {
    case "transferConfidential":
    case "transferAnonymous":
      return transferCircuit(request);
    case "applyRecords":
      return { family: "applyRecords", writes: applyCapacity(listLength(request.writes)) };
    case "registerKey":
      return { family: "registerKey" };
    case "deposit":
      return { family: "deposit", capacity: depositCapacity(request.count) };
    case "merge":
      return { family: "merge", width: listLength(request.inputs) };
    default:
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
}

/** The transfer key the request's list widths name, Rust `RingCircuit::Transfer*`. */
function transferCircuit(
  request: ConfidentialTransferProofRequest | AnonymousTransferProofRequest,
): TransferKeyCircuit {
  const outputs = listLength(request.outputs);
  const withdrawals = listLength(request.withdrawals);
  if (request.kind === "transferConfidential")
    return {
      family: "transferConfidential",
      outputs,
      inputs: listLength(request.inputs),
      withdrawals,
    };
  return {
    family: flag(request.layout.fullOpenings) ? "transferAnonymousEntry" : "transferAnonymous",
    outputs,
    class: listLength(request.inputs),
    withdrawals,
  };
}

export function ringRequestKey(request: RingProofRequest): ExpectedProvingKey {
  return proofInput(() => ringProvingKey(ringProofCircuit(request)));
}

/** The body the prover's strict decoder accepts, keys in Go declaration order. */
export function ringProofRequestBody(request: RingProofRequest): Readonly<Record<string, unknown>> {
  const head = {
    circuitType: keyedCircuitType(request),
    publicInputHash: field(request.publicInputHash, "publicInputHash"),
  };
  switch (request.kind) {
    case "transferConfidential":
      return {
        ...head,
        ...transferJson(request),
        inProof: flag(request.inProof),
        delegate: flag(request.delegate),
        outputs: request.outputs.map((output, i) =>
          deliveredJson(output, deliveredBodyLen(flag(request.layout.keyEscrow)), `outputs[${i}]`),
        ),
        inputs: request.inputs.map((input, i) => openingJson(input, `inputs[${i}]`)),
        sender: field(request.sender, "sender"),
        senderPkHash: field(request.senderPkHash, "senderPkHash"),
        signers: fields(request.signers, request.signers.length, "signers"),
      };
    case "transferAnonymous":
      return {
        ...head,
        ...transferJson(request),
        outputs: request.outputs.map((output, i) => anonymousSlotJson(output, `outputs[${i}]`)),
        ...entrySenderKey(request),
        inputs: request.inputs.map((input, i) => openingJson(input, `inputs[${i}]`)),
        partyIdentities: fields(request.partyIdentities, 3, "partyIdentities"),
        signers: fields(request.signers, request.signers.length, "signers"),
        senderNullifierPk: field(request.senderNullifierPk, "senderNullifierPk"),
        senderViewingKey: hexBytes(request.senderViewingKey, 32, "senderViewingKey"),
        senderAddressRevision: u64(request.senderAddressRevision, "senderAddressRevision"),
        senderBundleTag: field(request.senderBundleTag, "senderBundleTag"),
        replyDigest: field(request.replyDigest, "replyDigest"),
      };
    case "applyRecords": {
      const capacity = applyCapacity(request.writes.length);
      return {
        ...head,
        oldRoot: field(request.oldRoot, "oldRoot"),
        newRoot: field(request.newRoot, "newRoot"),
        oldNextIndex: integer(request.oldNextIndex, "oldNextIndex", 0, U32_MAX),
        newNextIndex: integer(request.newNextIndex, "newNextIndex", 0, U32_MAX),
        chainStart: field(request.chainStart, "chainStart"),
        chainEnd: field(request.chainEnd, "chainEnd"),
        count: request.writes.length,
        // A slot past the count assigns zeros.
        writes: Array.from({ length: capacity }, (_, i) => {
          const write = request.writes[i];
          return write === undefined ? null : writeJson(write, `writes[${i}]`);
        }),
      };
    }
    case "registerKey":
      return {
        ...head,
        member: field(request.member, "member"),
        nullifierSecret: hexBytes(request.nullifierSecret, 32, "nullifierSecret"),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
      };
    case "deposit":
      return {
        ...head,
        contextHash: field(request.contextHash, "contextHash"),
        count: integer(request.count, "count", 1, RING_DEPOSIT_AUDIT_SLOTS),
        ...(flag(request.anonymous) ? { anonymous: true } : {}),
        ownerPkHashes: fields(
          request.ownerPkHashes,
          depositCapacity(request.count),
          "ownerPkHashes",
        ),
        ownerKeys: sized(request.ownerKeys, depositCapacity(request.count), "ownerKeys").map(
          (key, i) => hexBytes(key, 32, `ownerKeys[${i}]`),
        ),
        nullifierPks: fields(request.nullifierPks, depositCapacity(request.count), "nullifierPks"),
        blindingSecrets: fields(
          request.blindingSecrets,
          depositCapacity(request.count),
          "blindingSecrets",
        ),
        ctHashes: fields(request.ctHashes, depositCapacity(request.count), "ctHashes"),
        members: sized(request.members, depositCapacity(request.count), "members").map(
          (member, i) => (member === undefined ? null : recordJson(member, `members[${i}]`)),
        ),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
        keyEscrow: flag(request.keyEscrow),
        memberRegistryRoot: field(request.memberRegistryRoot, "memberRegistryRoot"),
        curatorRoot: field(request.curatorRoot, "curatorRoot"),
        policyHash: field(request.policyHash, "policyHash"),
        assets: fields(request.assets, depositCapacity(request.count), "assets"),
        amounts: fields(request.amounts, depositCapacity(request.count), "amounts"),
        ...(request.table === undefined ? {} : { table: tableJson(request.table) }),
        assetRecords: sized(
          request.assetRecords,
          depositCapacity(request.count),
          "assetRecords",
        ).map((opening, i) => memberOpeningJson(opening, `assetRecords[${i}]`)),
        curatorAssetRecords: sized(
          request.curatorAssetRecords,
          depositCapacity(request.count),
          "curatorAssetRecords",
        ).map((opening, i) => memberOpeningJson(opening, `curatorAssetRecords[${i}]`)),
      };
    case "merge":
      return {
        ...head,
        partyIdentities: fields(request.partyIdentities, 3, "partyIdentities"),
        privateTxHash: field(request.privateTxHash, "privateTxHash"),
        outputUtxoHash: field(request.outputUtxoHash, "outputUtxoHash"),
        firstNullifier: field(request.firstNullifier, "firstNullifier"),
        ringProgramId: field(request.ringProgramId, "ringProgramId"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
        salt: field(request.salt, "salt"),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        disclosureKey: hexBytes(request.disclosureKey, 32, "disclosureKey"),
        ownerKey: hexBytes(request.ownerKey, 32, "ownerKey"),
        nullifierSecret: field(request.nullifierSecret, "nullifierSecret"),
        asset: field(request.asset, "asset"),
        inputCount: integer(request.inputCount, "inputCount", 1, request.inputs.length),
        inputs: request.inputs.map((input, i) => mergeInputJson(input, `inputs[${i}]`)),
        outputTreeId: field(request.outputTreeId, "outputTreeId"),
        outputRingDataHash: field(request.outputRingDataHash, "outputRingDataHash"),
        keyEscrow: flag(request.keyEscrow),
        memberRegistryRoot: field(request.memberRegistryRoot, "memberRegistryRoot"),
        ctHash: field(request.ctHash, "ctHash"),
        member: request.member === undefined ? null : recordJson(request.member, "member"),
      };
  }
}

type Json = Readonly<Record<string, unknown>>;

const U8_MAX = 0xff;
const U32_MAX = 0xffff_ffff;
/** Go `[2]Field`, the two `hash_bytes_32` halves of a mint. */
const MINT_CHUNKS = 2;
const ZERO = new Uint8Array(32) as Bytes32;
const MAX_LEAF_INDEX = Number(MEMBER_REGISTRY_CAPACITY) - 1;

/** One write takes the 1-write key, 2 to `APPLY_BATCH` the batch key, any other count none. */
function applyCapacity(count: number): number {
  return [1, 2, 4, 8, APPLY_BATCH].find((n) => count <= n) ?? count;
}

/** A list width no key serves fails here, before any encoding. */
function keyedCircuitType(request: RingProofRequest): string {
  return proofInput(() => ringCircuitType(ringProofCircuit(request)));
}

/** An interface refusal of a request value is an invalid proof input. */
function proofInput<T>(read: () => T): T {
  try {
    return read();
  } catch (cause) {
    if (cause instanceof InterfaceError) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    throw cause;
  }
}

function transferJson(
  request: ConfidentialTransferProofRequest | AnonymousTransferProofRequest,
): Json {
  return {
    ...envelopeJson(request),
    exempt: flag(request.exempt),
    approvalRequired: flag(request.approvalRequired),
    outputCount: integer(request.outputCount, "outputCount", 1, request.outputs.length),
    inputCount: integer(request.inputCount, "inputCount", 1, request.inputs.length),
    signerCount: integer(request.signerCount, "signerCount", 0, request.signers.length),
    privateTxHash: field(request.privateTxHash, "privateTxHash"),
    privateTxBlinding: field(request.privateTxBlinding, "privateTxBlinding"),
    ...policyJson(request, transferCircuit(request)),
  };
}

function envelopeJson(envelope: AuditEnvelopeProofInputs): Json {
  return {
    firstNullifier: field(envelope.firstNullifier, "firstNullifier"),
    txViewingSk: hexBytes(envelope.txViewingSk, 32, "txViewingSk"),
    ephSk: hexBytes(envelope.ephSk, 32, "ephSk"),
    auditorPk: hexBytes(envelope.auditorPk, 32, "auditorPk"),
    salt: hexBytes(envelope.salt, 16, "salt"),
    layout: proofInput(() => auditLayoutValue(envelope.layout)),
  };
}

function openingJson(opening: RingSlotOpening, name: string): Json {
  return {
    domain: field(opening.domain, `${name}.domain`),
    treeId: field(opening.treeId, `${name}.treeId`),
    ownerPkHash: field(opening.ownerPkHash, `${name}.ownerPkHash`),
    nullifierPk: field(opening.nullifierPk, `${name}.nullifierPk`),
    asset: field(opening.asset, `${name}.asset`),
    amount: field(opening.amount, `${name}.amount`),
    blinding: field(opening.blinding, `${name}.blinding`),
    dataHash: field(opening.dataHash, `${name}.dataHash`),
    ringDataHash: field(opening.ringDataHash, `${name}.ringDataHash`),
    ringProgramId: field(opening.ringProgramId, `${name}.ringProgramId`),
  };
}

function deliveredJson(slot: DeliveredSlotProofInputs, bodyLength: number, name: string): Json {
  return {
    output: openingJson(slot.output, `${name}.output`),
    recipientKey: hexBytes(slot.recipientKey, 32, `${name}.recipientKey`),
    ownerKey: hexBytes(slot.ownerKey, 32, `${name}.ownerKey`),
    body: hexBytes(slot.body, bodyLength, `${name}.body`),
  };
}

function anonymousSlotJson(slot: AnonymousSlotProofInputs, name: string): Json {
  return {
    output: openingJson(slot.output, `${name}.output`),
    ownerKey: hexBytes(slot.ownerKey, 32, `${name}.ownerKey`),
    recipientKey: hexBytes(slot.recipientKey, 32, `${name}.recipientKey`),
    addressRevision: u64(slot.addressRevision, `${name}.addressRevision`),
    mintChunks: fields(slot.mintChunks, MINT_CHUNKS, `${name}.mintChunks`),
    body: hexBytes(slot.body, RECIPIENT_BODY_LEN, `${name}.body`),
    tag: field(slot.tag, `${name}.tag`),
    tagPreimage: field(slot.tagPreimage, `${name}.tagPreimage`),
  };
}

function policyJson(policy: PolicyProofInputs, circuit: TransferKeyCircuit): Json {
  const outputs = policy.recipients.length;
  const slots = outputs + policy.withdrawals.length;
  const capacity = transferPoolCapacity(circuit);
  const own = poolJson(policy.ownPool, capacity.own, "ownPool");
  const curator = poolJson(policy.curatorPool, capacity.curator, "curatorPool");
  return {
    withdrawalCount: integer(
      policy.withdrawalCount,
      "withdrawalCount",
      0,
      policy.withdrawals.length,
    ),
    withdrawalHash: field(policy.withdrawalHash, "withdrawalHash"),
    withdrawals: policy.withdrawals.map((w) => ({
      owner: field(w.owner, "withdrawal.owner"),
      asset: field(w.asset, "withdrawal.asset"),
      amount: withdrawalAmount(w.amount),
    })),
    policyHash: field(policy.policyHash, "policyHash"),
    ringId: field(policy.ringId, "ringId"),
    ownRoot: field(policy.ownRoot, "ownRoot"),
    curatorRoot: field(policy.curatorRoot, "curatorRoot"),
    publicAssets: fields(policy.publicAssets, N_PUBLIC_SLOTS, "publicAssets"),
    publicAmounts: fields(policy.publicAmounts, N_PUBLIC_SLOTS, "publicAmounts"),
    publicGross: fields(policy.publicGross, N_PUBLIC_SLOTS, "publicGross"),
    ...tableJson(policy),
    ctHashes: fields(policy.ctHashes, outputs, "ctHashes"),
    recipients: fields(policy.recipients, outputs, "recipients"),
    ownRecords: own.records,
    curatorRecords: curator.records,
    ownProof: own.proof,
    curatorProof: curator.proof,
    ownSubjects: own.subjects,
    curatorSubjects: curator.subjects,
    senderEntries: sized(policy.senderEntries, screenedOwners(circuit), "senderEntries").map(
      (entry, i) => entryJson(entry, capacity, `senderEntries[${i}]`),
    ),
    ownerEntries: sized(policy.ownerEntries, slots, "ownerEntries").map((entry, i) =>
      entryJson(entry, capacity, `ownerEntries[${i}]`),
    ),
    assetEntries: sized(policy.assetEntries, slots, "assetEntries").map((entry, i) =>
      entryJson(entry, capacity, `assetEntries[${i}]`),
    ),
    publicAssetEntries: sized(policy.publicAssetEntries, N_PUBLIC_SLOTS, "publicAssetEntries").map(
      (index, i) => integer(index, `publicAssetEntries[${i}]`, 0, capacity.own - 1),
    ),
  };
}

function tableJson(table: PolicyTableProofInputs): Json {
  return {
    sources: sized(table.sources, RING_SOURCE_SLOTS, "sources").map((source, i) => ({
      listId: integer(source.listId, `sources[${i}].listId`, 0, U8_MAX),
      registry: field(source.registry, `sources[${i}].registry`),
    })),
    policyLen: integer(table.policyLen, "policyLen", 0, RING_RULE_SLOTS),
    rules: fields(table.rules, RING_RULE_SLOTS, "rules"),
  };
}

type PoolJson = Readonly<{
  records: readonly Json[];
  proof: Readonly<{ canopy: readonly string[]; paths: readonly Json[] }>;
  subjects: readonly Json[];
}>;

/** Go `PooledRecord`, `SharedRegistryProof` and `PooledSubject` rows at the key's capacity. */
function poolJson(pool: RecordPool, capacity: number, name: string): PoolJson {
  const levels = canopyLevels(capacity);
  return {
    records: sized(pool.records, capacity, `${name}.records`).map((record, i) => ({
      member: field(record.member, `${name}.records[${i}].member`),
      ...recordFieldsJson(record, `${name}.records[${i}]`),
    })),
    proof: {
      canopy: fields(pool.canopy, QUAD_ARITY ** levels, `${name}.canopy`),
      paths: sized(pool.paths, capacity, `${name}.paths`).map((path, i) => ({
        index: integer(path.index, `${name}.paths[${i}].index`, 0, MAX_LEAF_INDEX),
        siblings: sized(path.siblings, QUAD_HEIGHT - levels, `${name}.paths[${i}].siblings`).map(
          (level, l) => fields(level, QUAD_ARITY - 1, `${name}.paths[${i}].siblings[${l}]`),
        ),
      })),
    },
    subjects: sized(pool.subjects, capacity, `${name}.subjects`).map((subject, i) => ({
      member: field(subject.member, `${name}.subjects[${i}].member`),
      recordIndex: integer(
        subject.recordIndex,
        `${name}.subjects[${i}].recordIndex`,
        0,
        capacity - 1,
      ),
    })),
  };
}

function entryJson(entry: PolicySubjectEntry, capacity: PolicyPoolCapacity, name: string): Json {
  return {
    own: integer(entry.own, `${name}.own`, 0, capacity.own - 1),
    curator: [integer(entry.curator, `${name}.curator`, 0, capacity.curator - 1)],
  };
}

/** Go `MemberOpening`, the side the opening does not use is zero. */
function memberOpeningJson(opening: RecordOpening | undefined, name: string): Json | null {
  if (opening === undefined) return null;
  if (opening.kind !== "present" && opening.kind !== "absent")
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  const present = opening.kind === "present";
  const record = present ? opening.record : undefined;
  const low = present ? undefined : opening.low;
  return {
    present,
    next: field(record?.next ?? ZERO, `${name}.next`),
    lists: u64(record?.lists ?? 0n, `${name}.lists`),
    escrowKey: field(record?.escrowKey ?? ZERO, `${name}.escrowKey`),
    mintPolicy: field(
      mintPolicyField(record?.mintPolicy ?? EMPTY_MINT_POLICY),
      `${name}.mintPolicy`,
    ),
    withdrawalThreshold: field(
      bigIntBytes(record?.mintPolicy.withdrawalThreshold ?? 0n, 32) as Bytes32,
      `${name}.withdrawalThreshold`,
    ),
    assetLimits: limitsJson(
      (record?.mintPolicy ?? EMPTY_MINT_POLICY).limits,
      `${name}.assetLimits`,
    ),
    addressHash: field(record?.addressHash ?? ZERO, `${name}.addressHash`),
    ...quadPathJson(opening.path, name, "index", "path"),
    lowMember: field(low?.member ?? ZERO, `${name}.lowMember`),
    lowNext: field(low?.next ?? ZERO, `${name}.lowNext`),
    lowLists: u64(low?.lists ?? 0n, `${name}.lowLists`),
    lowEscrow: field(low?.escrowKey ?? ZERO, `${name}.lowEscrow`),
    lowMintPolicy: field(
      mintPolicyField(low?.mintPolicy ?? EMPTY_MINT_POLICY),
      `${name}.lowMintPolicy`,
    ),
    lowWithdrawalThreshold: field(
      bigIntBytes(low?.mintPolicy.withdrawalThreshold ?? 0n, 32) as Bytes32,
      `${name}.lowWithdrawalThreshold`,
    ),
    lowAssetLimits: limitsJson(
      (low?.mintPolicy ?? EMPTY_MINT_POLICY).limits,
      `${name}.lowAssetLimits`,
    ),
    lowAddressHash: field(low?.addressHash ?? ZERO, `${name}.lowAddressHash`),
  };
}

/** Go `RecordOpening`, the present record a deposit and a ring merge prove. */
export function recordJson(opening: PresentRecordOpening, name: string): Json {
  if (opening.kind !== "present") throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return {
    ...recordFieldsJson(opening.record, name),
    ...quadPathJson(opening.path, name, "index", "path"),
  };
}

function recordFieldsJson(record: MemberRecord, name: string): Json {
  return {
    next: field(record.next, `${name}.next`),
    lists: u64(record.lists, `${name}.lists`),
    escrowKey: field(record.escrowKey, `${name}.escrowKey`),
    mintPolicy: field(mintPolicyField(record.mintPolicy), `${name}.mintPolicy`),
    withdrawalThreshold: field(
      bigIntBytes(record.mintPolicy.withdrawalThreshold, 32) as Bytes32,
      `${name}.withdrawalThreshold`,
    ),
    assetLimits: limitsJson(record.mintPolicy.limits, `${name}.assetLimits`),
    addressHash: field(record.addressHash, `${name}.addressHash`),
  };
}

function writeJson(write: RecordWriteProofInput, name: string): Json {
  return {
    entry: queueEntryJson(write.entry, `${name}.entry`),
    exists: flag(write.exists),
    oldNext: field(write.oldNext, `${name}.oldNext`),
    oldLists: u64(write.oldLists, `${name}.oldLists`),
    oldEscrow: field(write.oldEscrow, `${name}.oldEscrow`),
    oldMintPolicy: field(mintPolicyField(write.oldMintPolicy), `${name}.oldMintPolicy`),
    oldWithdrawalThreshold: field(
      bigIntBytes(write.oldMintPolicy.withdrawalThreshold, 32) as Bytes32,
      `${name}.oldWithdrawalThreshold`,
    ),
    oldAssetLimits: limitsJson(write.oldMintPolicy.limits, `${name}.oldAssetLimits`),
    oldAddressHash: field(write.oldAddressHash, `${name}.oldAddressHash`),
    ...quadPathJson(write.slot, name, "index", "path"),
    lowMember: field(write.low.member, `${name}.lowMember`),
    lowNext: field(write.low.next, `${name}.lowNext`),
    lowLists: u64(write.low.lists, `${name}.lowLists`),
    lowEscrow: field(write.low.escrowKey, `${name}.lowEscrow`),
    lowMintPolicy: field(mintPolicyField(write.low.mintPolicy), `${name}.lowMintPolicy`),
    lowWithdrawalThreshold: field(
      bigIntBytes(write.low.mintPolicy.withdrawalThreshold, 32) as Bytes32,
      `${name}.lowWithdrawalThreshold`,
    ),
    lowAssetLimits: limitsJson(write.low.mintPolicy.limits, `${name}.lowAssetLimits`),
    lowAddressHash: field(write.low.addressHash, `${name}.lowAddressHash`),
    ...quadPathJson(write.lowPath, name, "lowIndex", "lowPath"),
    nullifierPk: field(write.pair?.nullifierPk ?? ZERO, `${name}.nullifierPk`),
    addressRing: field(write.pair?.addressRing ?? ZERO, `${name}.addressRing`),
    view0: field(write.pair?.view0 ?? ZERO, `${name}.view0`),
    view1: field(write.pair?.view1 ?? ZERO, `${name}.view1`),
    addressRevision: u64(write.pair?.addressRevision ?? 0n, `${name}.addressRevision`),
    escrowCtHash: field(write.pair?.escrowCiphertextHash ?? ZERO, `${name}.escrowCtHash`),
  };
}

function queueEntryJson(entry: QueueEntry, name: string): Json {
  return {
    member: field(entry.member, `${name}.member`),
    mask: u64(entry.mask, `${name}.mask`),
    value: u64(entry.value, `${name}.value`),
    escrowKey: field(entry.escrowKey, `${name}.escrowKey`),
    mintPolicy: field(mintPolicyWriteField(entry.mintPolicy), `${name}.mintPolicy`),
    withdrawalThreshold: field(
      bigIntBytes(entry.mintPolicy?.withdrawalThreshold ?? 0n, 32) as Bytes32,
      `${name}.withdrawalThreshold`,
    ),
    assetLimits: limitsJson((entry.mintPolicy ?? EMPTY_MINT_POLICY).limits, `${name}.assetLimits`),
    addressHash: field(entry.addressHash ?? ZERO, `${name}.addressHash`),
  };
}

function limitsJson(limits: AssetLimits, name: string): string[] {
  return assetLimitsFields(limits).map((limit, index) => field(limit, `${name}[${String(index)}]`));
}

function mergeInputJson(input: MergeInputOpening, name: string): Json {
  return {
    domain: field(input.domain, `${name}.domain`),
    treeId: field(input.treeId, `${name}.treeId`),
    amount: field(input.amount, `${name}.amount`),
    blinding: field(input.blinding, `${name}.blinding`),
    ringDataHash: field(input.ringDataHash, `${name}.ringDataHash`),
  };
}

/** Go keeps the index and the flat siblings, leaf level first, three per level in child order. */
function quadPathJson(path: QuadPath, name: string, index: string, siblings: string): Json {
  const levels = sized(path.siblings, QUAD_HEIGHT, `${name}.${siblings}`);
  return {
    [index]: integer(path.index, `${name}.${index}`, 0, Number.MAX_SAFE_INTEGER),
    [siblings]: levels.flatMap((level, l) =>
      fields(level, QUAD_ARITY - 1, `${name}.${siblings}[${l}]`),
    ),
  };
}

/** Go `Field`, `0x` and 64 lowercase hex digits below the modulus. */
function field(value: Bytes32, name: string): string {
  const bytes = checkedLength(value, 32, name);
  bytesField(bytes, name);
  return `0x${bytesToHex(bytes)}`;
}

function fields(values: readonly Bytes32[], length: number, name: string): readonly string[] {
  return sized(values, length, name).map((value, i) => field(value, `${name}[${i}]`));
}

/** Go `Bytes`, the circuit array it fills fixes its length. */
function hexBytes(value: Uint8Array, length: number, name: string): string {
  return `0x${bytesToHex(checkedLength(value, length, name))}`;
}

function checkedLength(value: Uint8Array, length: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length)
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: {
        field: name,
        expected: length,
        actual: value instanceof Uint8Array ? value.length : -1,
      },
    });
  return value;
}

function entrySenderKey(request: AnonymousTransferProofRequest): Readonly<{ senderKey?: string }> {
  const { senderKey } = request;
  if ((senderKey !== undefined) !== flag(request.layout.fullOpenings))
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return senderKey === undefined ? {} : { senderKey: hexBytes(senderKey, 32, "senderKey") };
}

function listLength(values: readonly unknown[]): number {
  if (!Array.isArray(values)) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return values.length;
}

function sized<T>(values: readonly T[], length: number, name: string): readonly T[] {
  if (!Array.isArray(values) || values.length !== length)
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: {
        field: name,
        expected: length,
        actual: Array.isArray(values) ? values.length : -1,
      },
    });
  return values;
}

function integer(value: number, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: name, length: byteWidth(maximum) },
    });
  return value;
}

/** Go `uint64`, sent as a JSON number, so above the safe range no JSON number is exact. */
function u64(value: bigint, name: string): number {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: name, length: 8 } });
  return Number(value);
}

function flag(value: boolean): boolean {
  if (typeof value !== "boolean") throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return value;
}

function byteWidth(maximum: number): number {
  return maximum <= U8_MAX ? 1 : maximum <= U32_MAX ? 4 : 8;
}

function depositCapacity(count: number): number {
  return [1, 2, 4, RING_DEPOSIT_AUDIT_SLOTS].find((n) => count <= n) ?? count;
}

/** The circuit bounds this canonical field to u64; JSON numbers cannot carry that full range. */
function withdrawalAmount(amount: bigint): string {
  if (typeof amount !== "bigint" || amount < 0n || amount > 0xffff_ffff_ffff_ffffn)
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: "withdrawal.amount", length: 8 },
    });
  return field(bigIntBytes(amount) as Bytes32, "withdrawal.amount");
}
