import {
  EMPTY_MINT_POLICY,
  assetLimitsFields,
  mintPolicyField,
  mintPolicyWriteField,
  type AssetLimits,
  type MintPolicy,
} from "../../protocol/membership/mint-policy.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { InterfaceError } from "@heliuslabs/zolana/interface";
import {
  bigIntBytes,
  bytesField,
  ZERO_32,
  type ExpectedProvingKey,
} from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32 } from "@heliuslabs/zolana/interface";
import { ClientError } from "@heliuslabs/zolana/client";
import { packBytesBe } from "../../crypto/derivation/hasher.js";
import {
  APPLY_BATCH,
  MEMBER_REGISTRY_CAPACITY,
  QUAD_ARITY,
  QUAD_HEIGHT,
  canopyLevels,
  type ApplyProofInputs,
  type MemberRecord,
  type PoolSubject,
  type QuadPath,
  type QueueEntry,
  type RecordOpening,
  type RecordPool,
  type RecordWriteProofInput,
} from "../../protocol/membership/member-registry.js";
import {
  TRACKING_CAPACITY,
  TRACKING_QUAD_HEIGHT,
  type TrackingEntry,
  type TrackingOpening,
  type TrackingRecord,
} from "../../protocol/membership/tracking.js";
import {
  ringCircuitType,
  ringProvingKey,
  type RingKeyCircuit,
} from "../../protocol/proof/proving-keys.js";
import {
  transferPoolCapacity,
  type PolicyPoolCapacity,
  type TransferKeyCircuit,
} from "../../protocol/proof/transfer-shapes.js";
import { RING_DEPOSIT_AUDIT_SLOTS } from "../../protocol/codec/ring-deposit-capsule.js";
import { auditLayoutValue, type AuditLayout } from "../../protocol/codec/ring-disclosure-layout.js";
import { ANONYMOUS_PARTIES } from "../../protocol/transaction/transact.js";
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
  /** The statement's layout element. */
  readonly layout: AuditLayout;
}

/** Go `OutputOpening`, one output slot and the preimages its record names. */
export interface OutputOpeningProofInput {
  readonly output: RingSlotOpening;
  readonly ownerKey: Bytes32;
  readonly mintChunks: readonly Bytes32[];
}

/** Go `EntryOpening`, zero off a default-ring input. */
export interface EntryOpeningProofInput {
  readonly ownerKey: Bytes32;
  readonly mintChunks: readonly Bytes32[];
}

/** Go `Source`, a zero `registry` names the ring's own registry. */
export interface PolicySourceProofInput {
  readonly listId: number;
  readonly registry: Bytes32;
}

/** Circuit `privatelist.Source`, zero without a private source. */
export interface PrivateSourceProofInput {
  readonly ownerLists: number;
  readonly registry: Bytes32;
}

/** Go `PolicyTable`, every row past its count zero, `source` the wire circuit `Table.Source` reads. */
export interface PolicyTableProofInputs {
  readonly sources: readonly PolicySourceProofInput[];
  readonly source: PrivateSourceProofInput;
  readonly policyLen: number;
  readonly rules: readonly Bytes32[];
}

/** Go `PooledEntry`, the curator index 0 without a curator registry. */
export interface PolicySubjectEntry {
  readonly own: number;
  readonly curator: number;
  /** Set on an owner row of a key with private rows. */
  readonly private?: number;
}

/** Go `PrivateOpening`, one position of a private row. */
export interface PrivateOpeningProofInput {
  readonly written: boolean;
  readonly lists: bigint;
  readonly leafSalt: Bytes32;
  readonly siblings: readonly Bytes32[];
}

/** Go `PrivateRow`, a clear `live` pads. */
export interface PrivateRowProofInput {
  readonly live: boolean;
  readonly listSalt: Bytes32;
  readonly salted: PrivateOpeningProofInput;
  readonly zero: PrivateOpeningProofInput;
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
  readonly privateRoot: Bytes32;
  readonly publicAssets: readonly Bytes32[];
  readonly publicAmounts: readonly Bytes32[];
  /** Gross withdrawals per slot as right aligned u128. */
  readonly publicGross: readonly Bytes32[];
  readonly ownPool: RecordPool;
  readonly curatorPool: RecordPool;
  /** The pool rows of the key's owner rows. */
  readonly senderEntries: readonly PolicySubjectEntry[];
  readonly ownerEntries: readonly PolicySubjectEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
  readonly publicAssetEntries: readonly number[];
  /** One per subject on a key with private rows, absent otherwise. */
  readonly privateRows?: readonly PrivateRowProofInput[];
  readonly privateOwners?: readonly Bytes32[];
  readonly privateTracking?: readonly number[];
}

/** Go `TrackingRecordParams` rows, their shared proof and the subjects they open. */
export interface TrackingPoolProofInput {
  readonly records: readonly TrackingRecord[];
  readonly canopy: readonly Bytes32[];
  /** `paths[i]` opens `records[i]` up to the canopy, leaf level first. */
  readonly paths: readonly QuadPath[];
  readonly subjects: readonly PoolSubject[];
}

/** Go `TrackingParams`, every owner row and live ring output under the frame's tracking root. */
export interface TrackingProofInputs {
  readonly trackingRoot: Bytes32;
  readonly trackingPool: TrackingPoolProofInput;
  /** Index `trackingPool.subjects`, 0 on a zero row. */
  readonly rowEntries: readonly number[];
  /** Index `trackingPool.subjects`, 0 off a live ring output. */
  readonly outputEntries: readonly number[];
}

/** Go `TransferParams`, what every transfer key reads. */
export interface TransferProofInputs
  extends AuditEnvelopeProofInputs, PolicyProofInputs, TrackingProofInputs {
  readonly publicInputHash: Bytes32;
  /** The statement's proven bits. */
  readonly approvalMask: number;
  /** `m`, the slots past it leave the frame. */
  readonly outputCount: number;
  readonly outputs: readonly OutputOpeningProofInput[];
  /** The published nullifier count, the input slots past it carry no UTXO. */
  readonly inputCount: number;
  /** At the key's input class. */
  readonly inputs: readonly RingSlotOpening[];
  /** One per input class slot on an entry key, empty otherwise. */
  readonly entries: readonly EntryOpeningProofInput[];
  readonly signerCount: number;
  /** SPP's owner signer run, zero filled to the input class. */
  readonly signers: readonly Bytes32[];
  /** The distinct live input owners ascending, zero rows last, at the key's owner rows. */
  readonly rows: readonly Bytes32[];
  readonly privateTxHash: Bytes32;
  /** SPP's blinding of the hash, the proof reopens it with no address input. */
  readonly privateTxBlinding: Bytes32;
  /** SPP's chain of address slot nullifiers, zero without one. */
  readonly addressChain: Bytes32;
}

/** Go `ConfidentialTransferParams`. */
export interface ConfidentialTransferProofRequest extends TransferProofInputs {
  readonly kind: "transferConfidential";
  readonly inProof: boolean;
  readonly delegate: boolean;
  /** The in-proof owner, zero on the signer and authority rails. */
  readonly sender: Bytes32;
}

/** Go `AnonymousTransferParams`. */
export interface AnonymousTransferProofRequest extends TransferProofInputs {
  readonly kind: "transferAnonymous";
  readonly publicOwners: boolean;
  readonly delegate: boolean;
  /** Payer, five co-signers and exit destination, zero when absent. */
  readonly partyIdentities: readonly Bytes32[];
}

/** Go `ApplyRecordsParams`, one write takes the 1-write key, more the batch key. */
export interface ApplyRecordsProofRequest extends ApplyProofInputs {
  readonly kind: "applyRecords";
  readonly publicInputHash: Bytes32;
}

/** Go `TrackingWrite`, the witness of one applied entry. */
export interface TrackingWriteProofInput {
  readonly entry: TrackingEntry;
  readonly exists: boolean;
  readonly oldRecord: TrackingRecord;
  readonly slot: QuadPath;
  readonly lowRecord: TrackingRecord;
  readonly lowPath: QuadPath;
}

/** Go `ApplyEnrollmentsParams`. */
export interface ApplyEnrollmentsProofRequest {
  readonly kind: "applyEnrollments";
  readonly publicInputHash: Bytes32;
  readonly oldRoot: Bytes32;
  readonly newRoot: Bytes32;
  readonly oldNextIndex: number;
  readonly newNextIndex: number;
  readonly chainStart: Bytes32;
  readonly chainEnd: Bytes32;
  readonly writes: readonly TrackingWriteProofInput[];
}

/** Go `RegisterKeyParams`. */
export interface RegisterKeyProofRequest {
  readonly kind: "registerKey";
  readonly publicInputHash: Bytes32;
  /** The tracking registry's. */
  readonly ringId: Bytes32;
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
  readonly ephSk: Bytes32;
  readonly auditorPk: Bytes32;
  readonly trackingRoot: Bytes32;
  /** Undefined at a padding slot. */
  readonly tracking: readonly (TrackingOpening | undefined)[];
  readonly ownRoot: Bytes32;
  readonly curatorRoot: Bytes32;
  readonly policyHash: Bytes32;
  /** SPP's asset field of each deposit's group. */
  readonly assets: readonly Bytes32[];
  readonly amounts: readonly Bytes32[];
  /** Two chunks per slot, zero at a padding slot. */
  readonly mintChunks: readonly (readonly Bytes32[])[];
  /** Absent without a written policy, the records then open nothing. */
  readonly table?: PolicyTableProofInputs;
  readonly assetRecords: readonly (RecordOpening | undefined)[];
  readonly ownerRecords: readonly (RecordOpening | undefined)[];
  /** Undefined entries without a curator source. */
  readonly curatorAssetRecords: readonly (RecordOpening | undefined)[];
  readonly curatorOwnerRecords: readonly (RecordOpening | undefined)[];
}

/** Go `MergeParams`, seals a ring's SPP merge output to its auditor. */
export interface MergeProofRequest {
  readonly kind: "merge";
  readonly publicInputHash: Bytes32;
  readonly outputUtxoHash: Bytes32;
  readonly firstNullifier: Bytes32;
  readonly ringProgramId: Bytes32;
  readonly auditorPk: Bytes32;
  readonly payer: Bytes32;
  readonly trackingRoot: Bytes32;
  readonly ephSk: Bytes32;
  readonly ownerKey: Bytes32;
  readonly ownerPkHash: Bytes32;
  readonly mintChunks: readonly Bytes32[];
  readonly asset: Bytes32;
  readonly amount: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly seed: Bytes32;
  readonly outputTreeId: Bytes32;
  readonly outputRingDataHash: Bytes32;
  /** Undefined under a zero key. */
  readonly tracking?: TrackingOpening;
}

export type RingProofRequest =
  | ConfidentialTransferProofRequest
  | AnonymousTransferProofRequest
  | ApplyRecordsProofRequest
  | ApplyEnrollmentsProofRequest
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
    case "applyEnrollments":
      return { family: "applyEnrollments", writes: applyCapacity(listLength(request.writes)) };
    case "registerKey":
      return { family: "registerKey" };
    case "deposit":
      return { family: "deposit", capacity: depositCapacity(request.count) };
    case "merge":
      return { family: "merge" };
    default:
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
}

/** The transfer key the request's list widths name, Rust `RingCircuit::Transfer*`. */
function transferCircuit(
  request: ConfidentialTransferProofRequest | AnonymousTransferProofRequest,
): TransferKeyCircuit {
  const entry = flag(request.layout.entry);
  const family =
    request.kind === "transferConfidential"
      ? entry
        ? "transferConfidentialEntry"
        : "transferConfidential"
      : entry
        ? "transferAnonymousEntry"
        : "transferAnonymous";
  return {
    family,
    outputs: listLength(request.outputs),
    class: listLength(request.inputs),
    withdrawals: listLength(request.withdrawals),
    owners: listLength(request.rows),
    data: flag(request.layout.hasData),
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
        sender: field(request.sender, "sender"),
      };
    case "transferAnonymous":
      return {
        ...head,
        ...transferJson(request),
        publicOwners: flag(request.publicOwners),
        delegate: flag(request.delegate),
        partyIdentities: fields(request.partyIdentities, ANONYMOUS_PARTIES, "partyIdentities"),
      };
    case "applyRecords": {
      const capacity = applyCapacity(request.writes.length);
      return {
        ...head,
        ...applyHeadJson(request),
        oldNextIndex: integer(request.oldNextIndex, "oldNextIndex", 0, U32_MAX),
        newNextIndex: integer(request.newNextIndex, "newNextIndex", 0, U32_MAX),
        count: request.writes.length,
        writes: paddedWrites(request.writes, capacity, writeJson),
      };
    }
    case "applyEnrollments": {
      const capacity = applyCapacity(request.writes.length);
      return {
        ...head,
        ...applyHeadJson(request),
        oldNextIndex: integer(request.oldNextIndex, "oldNextIndex", 0, U32_MAX),
        newNextIndex: integer(request.newNextIndex, "newNextIndex", 0, U32_MAX),
        count: request.writes.length,
        writes: paddedWrites(request.writes, capacity, trackingWriteJson),
      };
    }
    case "registerKey":
      return {
        ...head,
        ringId: field(request.ringId, "ringId"),
        member: field(request.member, "member"),
        nullifierSecret: hexBytes(request.nullifierSecret, 32, "nullifierSecret"),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
      };
    case "deposit": {
      const capacity = depositCapacity(request.count);
      const records = (
        openings: readonly (RecordOpening | undefined)[],
        name: string,
      ): readonly (Json | null)[] =>
        sized(openings, capacity, name).map((opening, i) =>
          memberOpeningJson(opening, `${name}[${i}]`),
        );
      return {
        ...head,
        contextHash: field(request.contextHash, "contextHash"),
        count: integer(request.count, "count", 1, RING_DEPOSIT_AUDIT_SLOTS),
        ...(flag(request.anonymous) ? { anonymous: true } : {}),
        ownerPkHashes: fields(request.ownerPkHashes, capacity, "ownerPkHashes"),
        ownerKeys: sized(request.ownerKeys, capacity, "ownerKeys").map((key, i) =>
          hexBytes(key, 32, `ownerKeys[${i}]`),
        ),
        nullifierPks: fields(request.nullifierPks, capacity, "nullifierPks"),
        blindingSecrets: fields(request.blindingSecrets, capacity, "blindingSecrets"),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
        trackingRoot: field(request.trackingRoot, "trackingRoot"),
        tracking: sized(request.tracking, capacity, "tracking").map((opening, i) =>
          trackingOpeningJson(opening, `tracking[${i}]`),
        ),
        ownRoot: field(request.ownRoot, "ownRoot"),
        curatorRoot: field(request.curatorRoot, "curatorRoot"),
        policyHash: field(request.policyHash, "policyHash"),
        assets: fields(request.assets, capacity, "assets"),
        amounts: fields(request.amounts, capacity, "amounts"),
        mintChunks: sized(request.mintChunks, capacity, "mintChunks").map((chunks, i) =>
          fields(chunks, MINT_CHUNKS, `mintChunks[${i}]`),
        ),
        ...(request.table === undefined ? {} : { table: tableJson(request.table) }),
        assetRecords: records(request.assetRecords, "assetRecords"),
        ownerRecords: records(request.ownerRecords, "ownerRecords"),
        curatorAssetRecords: records(request.curatorAssetRecords, "curatorAssetRecords"),
        curatorOwnerRecords: records(request.curatorOwnerRecords, "curatorOwnerRecords"),
      };
    }
    case "merge":
      return {
        ...head,
        outputUtxoHash: field(request.outputUtxoHash, "outputUtxoHash"),
        firstNullifier: field(request.firstNullifier, "firstNullifier"),
        ringProgramId: field(request.ringProgramId, "ringProgramId"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
        payer: field(request.payer, "payer"),
        trackingRoot: field(request.trackingRoot, "trackingRoot"),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        ownerKey: hexBytes(request.ownerKey, 32, "ownerKey"),
        ownerPkHash: field(request.ownerPkHash, "ownerPkHash"),
        mintChunks: fields(request.mintChunks, MINT_CHUNKS, "mintChunks"),
        asset: field(request.asset, "asset"),
        amount: field(request.amount, "amount"),
        nullifierPk: field(request.nullifierPk, "nullifierPk"),
        seed: field(request.seed, "seed"),
        outputTreeId: field(request.outputTreeId, "outputTreeId"),
        outputRingDataHash: field(request.outputRingDataHash, "outputRingDataHash"),
        tracking: trackingOpeningJson(request.tracking, "tracking"),
      };
  }
}

type Json = Readonly<Record<string, unknown>>;

const U8_MAX = 0xff;
const U32_MAX = 0xffff_ffff;
/** Go `[2]Field`, the two `hash_bytes_32` halves of a mint. */
const MINT_CHUNKS = 2;
const MAX_LEAF_INDEX = Number(MEMBER_REGISTRY_CAPACITY) - 1;
const MAX_TRACKING_INDEX = Number(TRACKING_CAPACITY) - 1;

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
  const circuit = transferCircuit(request);
  const slots = request.inputs.length;
  return {
    ...envelopeJson(request),
    approvalMask: integer(request.approvalMask, "approvalMask", 0, APPROVAL_MASK_MAX),
    outputCount: integer(request.outputCount, "outputCount", 1, request.outputs.length),
    outputs: request.outputs.map((output, i) => outputJson(output, `outputs[${i}]`)),
    inputCount: integer(request.inputCount, "inputCount", 1, slots),
    inputs: request.inputs.map((input, i) => openingJson(input, `inputs[${i}]`)),
    ...(flag(request.layout.entry)
      ? {
          entries: sized(request.entries, slots, "entries").map((entry, i) =>
            entryOpeningJson(entry, `entries[${i}]`),
          ),
        }
      : {}),
    signerCount: integer(request.signerCount, "signerCount", 0, slots),
    signers: fields(request.signers, slots, "signers"),
    rows: fields(request.rows, circuit.owners, "rows"),
    privateTxHash: field(request.privateTxHash, "privateTxHash"),
    privateTxBlinding: field(request.privateTxBlinding, "privateTxBlinding"),
    addressChain: field(request.addressChain, "addressChain"),
    ...trackingJson(request, circuit),
    ...policyJson(request, circuit),
  };
}

const APPROVAL_MASK_MAX = 3;

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

function outputJson(slot: OutputOpeningProofInput, name: string): Json {
  return {
    output: openingJson(slot.output, `${name}.output`),
    ...entryOpeningJson(slot, name),
  };
}

function entryOpeningJson(entry: EntryOpeningProofInput, name: string): Json {
  return {
    ownerKey: hexBytes(entry.ownerKey, 32, `${name}.ownerKey`),
    mintChunks: fields(entry.mintChunks, MINT_CHUNKS, `${name}.mintChunks`),
  };
}

function trackingJson(tracking: TrackingProofInputs, circuit: TransferKeyCircuit): Json {
  const capacity = transferPoolCapacity(circuit).tracking;
  const { trackingPool: pool } = tracking;
  const levels = canopyLevels(capacity);
  const entry = (index: number, name: string): number => integer(index, name, 0, capacity - 1);
  return {
    trackingRoot: field(tracking.trackingRoot, "trackingRoot"),
    trackingRecords: sized(pool.records, capacity, "trackingRecords").map((record, i) =>
      trackingRecordJson(record, `trackingRecords[${i}]`),
    ),
    trackingProof: {
      canopy: fields(pool.canopy, QUAD_ARITY ** levels, "trackingProof.canopy"),
      paths: sized(pool.paths, capacity, "trackingProof.paths").map((path, i) =>
        sharedPathJson(
          path,
          TRACKING_QUAD_HEIGHT - levels,
          MAX_TRACKING_INDEX,
          `trackingProof.paths[${i}]`,
        ),
      ),
    },
    trackingSubjects: subjectsJson(pool.subjects, capacity, "trackingSubjects"),
    rowEntries: sized(tracking.rowEntries, circuit.owners, "rowEntries").map((index, i) =>
      entry(index, `rowEntries[${i}]`),
    ),
    outputEntries: sized(tracking.outputEntries, circuit.outputs, "outputEntries").map((index, i) =>
      entry(index, `outputEntries[${i}]`),
    ),
  };
}

/** Go `TrackingRecordParams` and `TrackingLeaf`, one wire shape. */
function trackingRecordJson(record: TrackingRecord, name: string): Json {
  return {
    member: field(record.member, `${name}.member`),
    next: field(record.next, `${name}.next`),
    ...trackingFieldsJson(record, name),
  };
}

function trackingFieldsJson(entry: TrackingEntry, name: string): Json {
  const [view0, view1] = packBytesBe(checkedLength(entry.viewingU, 32, `${name}.viewingU`));
  return {
    nullifierPk: field(entry.nullifierPk, `${name}.nullifierPk`),
    ctHash: field(entry.ctHash, `${name}.ctHash`),
    view0: field(view0 as Bytes32, `${name}.view0`),
    view1: field(view1 as Bytes32, `${name}.view1`),
    revision: field(bigIntBytes(entry.revision, 32) as Bytes32, `${name}.revision`),
    listTag: field(entry.listTag, `${name}.listTag`),
  };
}

/** Go `TrackingOpening`, a padding slot and a zero key send null. */
function trackingOpeningJson(opening: TrackingOpening | undefined, name: string): Json | null {
  if (opening === undefined) return null;
  const present = opening.kind === "present";
  return {
    present,
    record: trackingRecordJson(present ? opening.record : opening.low, `${name}.record`),
    path: sharedPathJson(opening.path, TRACKING_QUAD_HEIGHT, MAX_TRACKING_INDEX, `${name}.path`),
  };
}

/** Go `SharedRegistryPath`. */
function sharedPathJson(path: QuadPath, height: number, maxIndex: number, name: string): Json {
  return {
    index: integer(path.index, `${name}.index`, 0, maxIndex),
    siblings: sized(path.siblings, height, `${name}.siblings`).map((level, l) =>
      fields(level, QUAD_ARITY - 1, `${name}.siblings[${l}]`),
    ),
  };
}

function subjectsJson(
  subjects: readonly PoolSubject[],
  capacity: number,
  name: string,
): readonly Json[] {
  return sized(subjects, capacity, name).map((subject, i) => ({
    member: field(subject.member, `${name}[${i}].member`),
    recordIndex: integer(subject.recordIndex, `${name}[${i}].recordIndex`, 0, capacity - 1),
  }));
}

function policyJson(policy: PolicyProofInputs, circuit: TransferKeyCircuit): Json {
  const slots = circuit.outputs + circuit.withdrawals;
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
    withdrawals: sized(policy.withdrawals, circuit.withdrawals, "withdrawals").map((w) => ({
      owner: field(w.owner, "withdrawal.owner"),
      asset: field(w.asset, "withdrawal.asset"),
      amount: withdrawalAmount(w.amount),
    })),
    policyHash: field(policy.policyHash, "policyHash"),
    ringId: field(policy.ringId, "ringId"),
    ownRoot: field(policy.ownRoot, "ownRoot"),
    curatorRoot: field(policy.curatorRoot, "curatorRoot"),
    privateRoot: field(policy.privateRoot, "privateRoot"),
    publicAssets: fields(policy.publicAssets, N_PUBLIC_SLOTS, "publicAssets"),
    publicAmounts: fields(policy.publicAmounts, N_PUBLIC_SLOTS, "publicAmounts"),
    publicGross: fields(policy.publicGross, N_PUBLIC_SLOTS, "publicGross"),
    ...tableJson(policy),
    ownRecords: own.records,
    curatorRecords: curator.records,
    ownProof: own.proof,
    curatorProof: curator.proof,
    ownSubjects: own.subjects,
    curatorSubjects: curator.subjects,
    senderEntries: sized(policy.senderEntries, circuit.owners, "senderEntries").map((entry, i) =>
      entryJson(entry, capacity, `senderEntries[${i}]`),
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
    ...privateRowsJson(policy),
  };
}

/** Omitted on a key with no private rows, the decoder takes them as empty. */
function privateRowsJson(policy: PolicyProofInputs): Json {
  const { privateRows, privateOwners, privateTracking } = policy;
  if (privateRows === undefined || privateOwners === undefined || privateTracking === undefined)
    return {};
  const count = privateRows.length;
  const opening = (open: PrivateOpeningProofInput, name: string): Json => ({
    written: flag(open.written),
    lists: u64(open.lists, `${name}.lists`),
    leafSalt: field(open.leafSalt, `${name}.leafSalt`),
    siblings: fields(open.siblings, open.siblings.length, `${name}.siblings`),
  });
  return {
    privateRows: privateRows.map((row, i) => ({
      live: flag(row.live),
      listSalt: field(row.listSalt, `privateRows[${i}].listSalt`),
      salted: opening(row.salted, `privateRows[${i}].salted`),
      zero: opening(row.zero, `privateRows[${i}].zero`),
    })),
    privateOwners: fields(privateOwners, count, "privateOwners"),
    privateTracking: sized(privateTracking, count, "privateTracking").map((index, i) =>
      integer(index, `privateTracking[${i}]`, 0, U32_MAX),
    ),
  };
}

function tableJson(table: PolicyTableProofInputs): Json {
  return {
    sources: sized(table.sources, RING_SOURCE_SLOTS, "sources").map((source, i) => ({
      listId: integer(source.listId, `sources[${i}].listId`, 0, U8_MAX),
      registry: field(source.registry, `sources[${i}].registry`),
    })),
    source: {
      ownerLists: field(
        bigIntBytes(
          BigInt(integer(table.source.ownerLists, "source.ownerLists", 0, U8_MAX)),
        ) as Bytes32,
        "source.ownerLists",
      ),
      registry: field(table.source.registry, "source.registry"),
    },
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
      paths: sized(pool.paths, capacity, `${name}.paths`).map((path, i) =>
        sharedPathJson(path, QUAD_HEIGHT - levels, MAX_LEAF_INDEX, `${name}.paths[${i}]`),
      ),
    },
    subjects: subjectsJson(pool.subjects, capacity, `${name}.subjects`),
  };
}

function entryJson(entry: PolicySubjectEntry, capacity: PolicyPoolCapacity, name: string): Json {
  return {
    own: integer(entry.own, `${name}.own`, 0, capacity.own - 1),
    curator: [integer(entry.curator, `${name}.curator`, 0, capacity.curator - 1)],
    ...(entry.private === undefined
      ? {}
      : { private: [integer(entry.private, `${name}.private`, 0, U32_MAX)] }),
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
    next: field(record?.next ?? ZERO_32, `${name}.next`),
    lists: u64(record?.lists ?? 0n, `${name}.lists`),
    ...mintPolicyJson(record?.mintPolicy ?? EMPTY_MINT_POLICY, name, ""),
    ...quadPathJson(opening.path, name, "index", "path"),
    lowMember: field(low?.member ?? ZERO_32, `${name}.lowMember`),
    lowNext: field(low?.next ?? ZERO_32, `${name}.lowNext`),
    lowLists: u64(low?.lists ?? 0n, `${name}.lowLists`),
    ...mintPolicyJson(low?.mintPolicy ?? EMPTY_MINT_POLICY, name, "low"),
  };
}

function recordFieldsJson(record: MemberRecord, name: string): Json {
  return {
    next: field(record.next, `${name}.next`),
    lists: u64(record.lists, `${name}.lists`),
    ...mintPolicyJson(record.mintPolicy, name, ""),
  };
}

/** The mint policy columns of one record, `prefix` names its side in the Go struct. */
function mintPolicyJson(policy: MintPolicy, name: string, prefix: "" | "low" | "old"): Json {
  const key = (column: string): string =>
    prefix === "" ? column : `${prefix}${column.charAt(0).toUpperCase()}${column.slice(1)}`;
  return {
    [key("mintPolicy")]: field(mintPolicyField(policy), `${name}.${key("mintPolicy")}`),
    [key("withdrawalThreshold")]: field(
      bigIntBytes(policy.withdrawalThreshold, 32) as Bytes32,
      `${name}.${key("withdrawalThreshold")}`,
    ),
    [key("assetLimits")]: limitsJson(policy.limits, `${name}.${key("assetLimits")}`),
  };
}

function applyHeadJson(
  request: Readonly<{
    oldRoot: Bytes32;
    newRoot: Bytes32;
    chainStart: Bytes32;
    chainEnd: Bytes32;
  }>,
): Json {
  return {
    oldRoot: field(request.oldRoot, "oldRoot"),
    newRoot: field(request.newRoot, "newRoot"),
    chainStart: field(request.chainStart, "chainStart"),
    chainEnd: field(request.chainEnd, "chainEnd"),
  };
}

/** A slot past the count assigns zeros. */
function paddedWrites<T>(
  writes: readonly T[],
  capacity: number,
  encode: (write: T, name: string) => Json,
): readonly (Json | null)[] {
  return Array.from({ length: capacity }, (_, i) => {
    const write = writes[i];
    return write === undefined ? null : encode(write, `writes[${i}]`);
  });
}

function writeJson(write: RecordWriteProofInput, name: string): Json {
  return {
    entry: queueEntryJson(write.entry, `${name}.entry`),
    exists: flag(write.exists),
    oldNext: field(write.oldNext, `${name}.oldNext`),
    oldLists: u64(write.oldLists, `${name}.oldLists`),
    ...mintPolicyJson(write.oldMintPolicy, name, "old"),
    ...quadPathJson(write.slot, name, "index", "path"),
    lowMember: field(write.low.member, `${name}.lowMember`),
    lowNext: field(write.low.next, `${name}.lowNext`),
    lowLists: u64(write.low.lists, `${name}.lowLists`),
    ...mintPolicyJson(write.low.mintPolicy, name, "low"),
    ...quadPathJson(write.lowPath, name, "lowIndex", "lowPath"),
  };
}

function trackingWriteJson(write: TrackingWriteProofInput, name: string): Json {
  return {
    member: field(write.entry.member, `${name}.member`),
    ...trackingFieldsJson(write.entry, name),
    exists: flag(write.exists),
    oldRecord: trackingRecordJson(write.oldRecord, `${name}.oldRecord`),
    ...trackingPathJson(write.slot, name, "index", "path"),
    lowRecord: trackingRecordJson(write.lowRecord, `${name}.lowRecord`),
    ...trackingPathJson(write.lowPath, name, "lowIndex", "lowPath"),
  };
}

/** The flat siblings `newQuadPath` chunks, leaf level first. */
function trackingPathJson(path: QuadPath, name: string, index: string, siblings: string): Json {
  const levels = sized(path.siblings, TRACKING_QUAD_HEIGHT, `${name}.${siblings}`);
  return {
    [index]: integer(path.index, `${name}.${index}`, 0, MAX_TRACKING_INDEX),
    [siblings]: levels.flatMap((level, l) =>
      fields(level, QUAD_ARITY - 1, `${name}.${siblings}[${l}]`),
    ),
  };
}

function queueEntryJson(entry: QueueEntry, name: string): Json {
  return {
    member: field(entry.member, `${name}.member`),
    mask: u64(entry.mask, `${name}.mask`),
    value: u64(entry.value, `${name}.value`),
    mintPolicy: field(mintPolicyWriteField(entry.mintPolicy), `${name}.mintPolicy`),
    withdrawalThreshold: field(
      bigIntBytes(entry.mintPolicy?.withdrawalThreshold ?? 0n, 32) as Bytes32,
      `${name}.withdrawalThreshold`,
    ),
    assetLimits: limitsJson((entry.mintPolicy ?? EMPTY_MINT_POLICY).limits, `${name}.assetLimits`),
  };
}

function limitsJson(limits: AssetLimits, name: string): string[] {
  return assetLimitsFields(limits).map((limit, index) => field(limit, `${name}[${String(index)}]`));
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
