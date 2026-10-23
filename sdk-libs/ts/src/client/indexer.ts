import { ClientError, type Bytes32, type RequestContext } from "@heliuslabs/zolana";
import {
  ApiError,
  convertShieldedTransaction,
  decodeBase64,
  decodeX25519,
  indexerScalars,
  invalidResponse,
  wrapIndexer,
  type ZolanaApi,
} from "@heliuslabs/zolana/internal";

import {
  getRingKeyRegistryEntryMethod,
  getRingKeyRegistryRegisterProofMethod,
  getRingSpendRecordMethod,
} from "../indexer/methods.js";
import { RingError, type RingErrorCode } from "../ring/error.js";
import type {
  RingKeyRegistryEntry,
  RingKeyRegistryReader,
  RingKeyRegistryRegisterProof,
  RingMemberProofRequest,
  RingMemberRequest,
  RingSpendRecordLookup,
  RingSpendRecordReader,
} from "./ports.js";

const { hash, hashBytes } = indexerScalars;

/** Photon's ring projection codes, `zolana_indexer_api::error_code`. */
const RING_PROJECTION_CODES: ReadonlyMap<number, RingErrorCode> = new Map([
  [-32070, "RING_KEY_REGISTRY_OUT_OF_SYNC"],
  [-32071, "RING_KEY_REGISTRY_ROOT_CHANGED"],
  [-32072, "RING_KEY_REGISTRY_MEMBER_UNREGISTERED"],
  [-32073, "RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED"],
  [-32074, "RING_SPEND_RECORD_OUT_OF_SYNC"],
]);

export class RingIndexer implements RingSpendRecordReader, RingKeyRegistryReader {
  readonly #api: ZolanaApi;

  constructor(api: ZolanaApi) {
    this.#api = api;
  }

  async getRingSpendRecord(
    request: RingMemberRequest,
    context?: RequestContext,
  ): Promise<RingSpendRecordLookup> {
    const method = "getRingSpendRecord";
    try {
      const response = await this.#api.call(
        getRingSpendRecordMethod,
        { ringProgramId: request.ringProgramId, member: hash(request.member) },
        context,
      );
      const record = response.record;
      return Object.freeze({
        context: response.context,
        record:
          record === null
            ? null
            : Object.freeze({
                transaction: convertShieldedTransaction(
                  record.transaction,
                  method,
                  "record.transaction",
                ),
                outputIndex: record.outputIndex,
              }),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getRingKeyRegistryEntry(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryEntry> {
    const method = "getRingKeyRegistryEntry";
    try {
      const wire = memberRequest(request);
      const response = await this.#api.call(getRingKeyRegistryEntryMethod, wire, context);
      checkMemberResponse(wire, response);
      return Object.freeze({
        context: response.context,
        root: hashBytes(response.root),
        member: hashBytes(response.member),
        nextIndex: response.nextIndex,
        next: hashBytes(response.next),
        index: response.index,
        ephemeralPublicKey: decodeX25519(response.ephPk, method, "$.ephPk"),
        ciphertext: decodeCiphertext(response.ciphertext, method, "$.ciphertext"),
        proof: Object.freeze(response.proof.map(hashBytes)),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }

  async getRingKeyRegistryRegisterProof(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryRegisterProof> {
    const method = "getRingKeyRegistryRegisterProof";
    try {
      const wire = memberRequest(request);
      const response = await this.#api.call(getRingKeyRegistryRegisterProofMethod, wire, context);
      checkMemberResponse(wire, response);
      return Object.freeze({
        context: response.context,
        root: hashBytes(response.root),
        member: hashBytes(response.member),
        nextIndex: response.nextIndex,
        lowMember: hashBytes(response.lowMember),
        lowNext: hashBytes(response.lowNext),
        lowKeyHash: hashBytes(response.lowKeyHash),
        lowIndex: response.lowIndex,
        lowProof: Object.freeze(response.lowProof.map(hashBytes)),
        newProof: Object.freeze(response.newProof.map(hashBytes)),
      });
    } catch (cause) {
      throw ringIndexerError(cause, method);
    }
  }
}

function ringIndexerError(cause: unknown, method: string): RingError | ClientError {
  if (cause instanceof ApiError && cause.code === "API_JSON_RPC") {
    const rpcCode = cause.details?.["rpcCode"];
    const code = typeof rpcCode === "number" ? RING_PROJECTION_CODES.get(rpcCode) : undefined;
    if (code !== undefined) return new RingError(code, { details: { method } });
  }
  return wrapIndexer(cause, method);
}

function memberRequest(request: RingMemberProofRequest) {
  return Object.freeze({
    ringProgramId: request.ringProgramId,
    member: hash(request.member),
    expectedRoot: hash(request.expectedRoot),
    expectedNextIndex: request.expectedNextIndex,
  });
}

function checkMemberResponse(
  request: ReturnType<typeof memberRequest>,
  response: Readonly<{ root: string; member: string; nextIndex: bigint }>,
): void {
  if (
    response.root !== request.expectedRoot ||
    response.member !== request.member ||
    response.nextIndex !== request.expectedNextIndex
  ) {
    throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
      details: { method: "ringMemberProof", path: "$.result" },
    });
  }
}

function decodeCiphertext(value: string, method: string, path: string): Bytes32 {
  const bytes = decodeBase64(value, path);
  if (bytes.length !== 32) throw invalidResponse(method, path, 32, bytes.length);
  return bytes as Bytes32;
}
