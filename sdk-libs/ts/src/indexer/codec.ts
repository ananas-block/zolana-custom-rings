import { indexerCodec, indexerScalars } from "@heliuslabs/zolana/internal";

import { KEY_REGISTRY_CAPACITY, KEY_REGISTRY_HEIGHT } from "../interface/key-registry.js";
import type {
  GetRingSpendRecordResponse,
  RingMemberProofRequest,
  RingMemberRequest,
  RingKeyRegistryEntry,
  RingKeyRegistryRegisterProof,
} from "./types.js";

const { array, context, indexedTransaction, object, toWireInteger, u16, wireInteger } =
  indexerCodec;
const { checkedAddress, checkedBase64, checkedHash, schemaFailure } = indexerScalars;

type WireObject = Record<string, unknown>;

export function encodeRingMemberRequest(
  value: RingMemberRequest,
): Readonly<Record<string, unknown>> {
  return {
    ringProgramId: checkedAddress(value.ringProgramId, "ringProgramId"),
    member: checkedHash(value.member, "member"),
  };
}

export function encodeRingMemberProofRequest(
  value: RingMemberProofRequest,
): Readonly<Record<string, unknown>> {
  return {
    ...encodeRingMemberRequest(value),
    expectedRoot: checkedHash(value.expectedRoot, "expectedRoot"),
    expectedNextIndex: toWireInteger(
      value.expectedNextIndex,
      "expectedNextIndex",
      1n,
      KEY_REGISTRY_CAPACITY,
    ),
  };
}

function indexedPath(value: unknown, path: string) {
  const proof = array(value, path, checkedHash);
  if (proof.length !== KEY_REGISTRY_HEIGHT) {
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      path,
      `${String(KEY_REGISTRY_HEIGHT)} siblings`,
      value,
    );
  }
  return proof;
}

function memberContext(record: WireObject) {
  return {
    context: context(record["context"], "context"),
    root: checkedHash(record["root"], "root"),
    member: checkedHash(record["member"], "member"),
    nextIndex: wireInteger(record["nextIndex"], "nextIndex", 1n, KEY_REGISTRY_CAPACITY),
  };
}

export function decodeRingKeyRegistryRegisterProof(value: unknown): RingKeyRegistryRegisterProof {
  const row = object(value, "$", [
    "context",
    "root",
    "member",
    "nextIndex",
    "lowMember",
    "lowNext",
    "lowKeyHash",
    "lowIndex",
    "lowProof",
    "newProof",
  ]);
  const common = memberContext(row);
  return {
    ...common,
    lowMember: checkedHash(row["lowMember"], "lowMember"),
    lowNext: checkedHash(row["lowNext"], "lowNext"),
    lowKeyHash: checkedHash(row["lowKeyHash"], "lowKeyHash"),
    lowIndex: wireInteger(row["lowIndex"], "lowIndex", 0n, common.nextIndex - 1n),
    lowProof: indexedPath(row["lowProof"], "lowProof"),
    newProof: indexedPath(row["newProof"], "newProof"),
  };
}

export function decodeRingKeyRegistryEntry(value: unknown): RingKeyRegistryEntry {
  const row = object(value, "$", [
    "context",
    "root",
    "member",
    "nextIndex",
    "next",
    "index",
    "ephPk",
    "ciphertext",
    "proof",
  ]);
  const common = memberContext(row);
  return {
    ...common,
    next: checkedHash(row["next"], "next"),
    index: wireInteger(row["index"], "index", 1n, common.nextIndex - 1n),
    ephPk: checkedBase64(row["ephPk"], "ephPk"),
    ciphertext: checkedBase64(row["ciphertext"], "ciphertext"),
    proof: indexedPath(row["proof"], "proof"),
  };
}

export function decodeRingSpendRecordResponse(value: unknown): GetRingSpendRecordResponse {
  const row = object(value, "$", ["context", "record"]);
  const indexed = context(row["context"], "context");
  if (row["record"] === null) return { context: indexed, record: null };
  const record = object(row["record"], "record", ["transaction", "outputIndex"]);
  const transaction = indexedTransaction(record["transaction"], "record.transaction");
  const outputIndex = u16(record["outputIndex"], "record.outputIndex");
  if (outputIndex >= transaction.outputSlots.length)
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "record.outputIndex",
      "an existing output",
      outputIndex,
    );
  return { context: indexed, record: { transaction, outputIndex } };
}
