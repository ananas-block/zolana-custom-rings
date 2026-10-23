import { X25519PublicKey, X25519Keypair, poseidon } from "@heliuslabs/zolana/keypair";
import {
  isCanonicalField,
  wireDecoder,
  bytesToBigInt,
  checkedClientBytes as checkedBytes,
  type ProverClient,
  parseIndexedResponse,
  parseCheckedProof,
} from "@heliuslabs/zolana/internal";
import {
  INPUT_TREES,
  treeIdField,
  type TreeSlot,
  DUMMY_DOMAIN,
} from "@heliuslabs/zolana/interface";
import { type Bytes32, type RequestContext, ClientError } from "@heliuslabs/zolana";
import type { IndexedProofResult, ProvingKeyReport, Proof } from "@heliuslabs/zolana/client";
import { KEY_REGISTRY_CAPACITY, KEY_REGISTRY_HEIGHT } from "../../interface/key-registry.js";
import {
  ringProvingKey,
  RING_PROVING_KEY_SHA256S,
  type RingCircuit,
} from "../../interface/proving-keys.js";
import { RING_DEPOSIT_AUDIT_SLOTS } from "../../interface/ring-deposit-capsule.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { RingError } from "../../ring/error.js";
import type { IndexedDepositInputs, IndexedPolicyInputs } from "../ports.js";
import {
  checkDepositResolution,
  checkPolicyResolution,
  indexedDepositEnvelope,
  indexedPolicyEnvelope,
  snapshotPolicyInputs,
} from "./policy.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_INPUT_SLOTS,
  RING_NULLIFIER_PATH_LENGTH,
  RING_OUTPUT_SLOTS,
  RING_ANSWER_SLOTS,
  RING_RULE_SLOTS,
  RING_SOURCE_SLOTS,
  RING_STATE_PATH_LENGTH,
  RING_VELOCITY_SLOTS,
} from "./types.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingDepositProofRequest,
  CustomRingOpening,
  CustomRingSourceOwner,
  CustomRingRuleAnswer,
  CustomRingPolicyProofRequest,
  CustomRingCompressedPolicyProofRequest,
  CustomRingRegistryInsertion,
  CustomRingRegisterKeyProofRequest,
  CustomRingRegistryKey,
  CustomRingSpendRecordProofInput,
  CustomRingVelocityRow,
} from "./types.js";

const invalidProverJson = (): ClientError => new ClientError("CLIENT_PROVER_JSON");
const proverJsonDecoder = wireDecoder(invalidProverJson);

export class CustomRingProver {
  readonly #prover: ProverClient;

  constructor(prover: ProverClient) {
    this.#prover = prover;
  }

  async proveIndexedPolicy(
    request: IndexedPolicyInputs,
    context?: RequestContext,
  ): Promise<IndexedProofResult> {
    const inputs = snapshotPolicyInputs(request);
    const body = indexedPolicyEnvelope(inputs, customRingPolicyProofRequest(inputs.policy));
    const result = await this.#indexed(body, inputs.circuit, context);
    checkPolicyResolution(inputs, result.resolution);
    return result;
  }

  async proveIndexedDeposit(
    inputs: IndexedDepositInputs,
    context?: RequestContext,
  ): Promise<Proof> {
    const publicInputHash = checkedBytes(inputs.deposit.publicInputHash, 32, "public input hash");
    const body = indexedDepositEnvelope(inputs, customRingDepositProofRequest(inputs.deposit));
    const result = await this.#indexed(body, "custom-ring-deposit", context);
    checkDepositResolution(publicInputHash, result.resolution);
    return result.proof;
  }

  async proveCustomRingPolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    return this.#queued(customRingPolicyProofRequest(inputs), "custom-ring-policy", context);
  }

  async proveCustomRingCompressedPolicy(
    inputs: CustomRingCompressedPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    return this.#queued(
      customRingCompressedPolicyProofRequest(inputs),
      "custom-ring-compressed-policy",
      context,
    );
  }

  async proveCustomRingRegisterKey(
    inputs: CustomRingRegisterKeyProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    return this.#queued(
      customRingRegisterKeyProofRequest(inputs),
      "custom-ring-register-key",
      context,
    );
  }

  async proveCustomRingDeposit(
    inputs: CustomRingDepositProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    return this.#queued(customRingDepositProofRequest(inputs), "custom-ring-deposit", context);
  }

  async proveCustomRingDelegatePolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    if (inputs.velocity.windowIndex !== 0n || inputs.velocity.approvalRequired)
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    return this.#queued(
      { circuitType: "custom-ring-delegate-policy", policy: customRingPolicyProofRequest(inputs) },
      "custom-ring-delegate-policy",
      context,
    );
  }

  async proveCustomRingBase(
    inputs: CustomRingBaseProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    return this.#queued(customRingBaseProofRequest(inputs), "custom-ring-base", context);
  }

  checkProvingKeys(context?: RequestContext): Promise<ProvingKeyReport> {
    return this.#prover.checkProvingKeys(context, RING_PROVING_KEY_SHA256S);
  }

  async #queued(
    body: Readonly<Record<string, unknown>>,
    circuit: RingCircuit,
    context: RequestContext | undefined,
  ): Promise<Proof> {
    const key = ringProvingKey(circuit);
    return parseCheckedProof(
      await this.#prover.send(JSON.stringify(body), "queued", key, context),
      key,
    );
  }

  async #indexed(
    body: Readonly<Record<string, unknown>>,
    circuit: RingCircuit,
    context: RequestContext | undefined,
  ): Promise<IndexedProofResult> {
    const key = ringProvingKey(circuit);
    return parseIndexedResponse(
      await this.#prover.send(JSON.stringify(body), "indexed", key, context, registryRefusal),
      key,
    );
  }
}

/** The prover's `registry_member_missing`, any other refusal stays the prover's own error. */
function registryRefusal(body: Readonly<Record<string, unknown>>): RingError | undefined {
  if (body["code"] !== "registry_member_missing") return undefined;
  return new RingError("RING_KEY_REGISTRY_MEMBER_UNREGISTERED", {
    details: { method: "prove", member: registryMember(body["member"]) },
  });
}

/** Base58 on the wire, hex in details like `RING_UNREGISTERED_OUTPUT_KEY.owner`. */
function registryMember(value: unknown): string {
  const member = proverJsonDecoder.base58(value, "$.member");
  if (member.length !== 32) throw invalidProverJson();
  return bytesToHex(member);
}

/** Mirrors Rust `CustomRingBaseProofRequest::body`, key order included. */
export function customRingBaseProofRequest(
  inputs: CustomRingBaseProofRequest,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    circuitType: "custom-ring-base",
    publicInputHash: hex32(inputs.publicInputHash, "publicInputHash"),
    privateTxHash: hex32(inputs.privateTxHash, "privateTxHash"),
    txViewingSk: hex32(inputs.txViewingSecret, "txViewingSecret"),
    ephSk: hex32(inputs.ephemeralSecret, "ephemeralSecret"),
    auditorPk: auditorPkHex(inputs.auditorPublicKey),
    salt: bytesHex(inputs.salt),
    nOut: u8(inputs.nOut, "nOut"),
    outputs: sized(inputs.outputs, RING_OUTPUT_SLOTS, "outputs").map(auditOpeningJson),
  });
}

/** Mirrors Rust `CustomRingPolicyProofRequest::body`, key order included. */
export function customRingPolicyProofRequest(
  inputs: CustomRingPolicyProofRequest,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    circuitType: "custom-ring-policy",
    publicInputHash: hex32(inputs.publicInputHash, "publicInputHash"),
    privateTxHash: hex32(inputs.privateTxHash, "privateTxHash"),
    txViewingSk: hex32(inputs.txViewingSecret, "txViewingSecret"),
    ephSk: hex32(inputs.ephemeralSecret, "ephemeralSecret"),
    auditorPk: auditorPkHex(inputs.auditorPublicKey),
    salt: bytesHex(inputs.salt),
    nIn: u8(inputs.nIn, "nIn"),
    nOut: u8(inputs.nOut, "nOut"),
    inputs: sized(inputs.inputs, RING_INPUT_SLOTS, "inputs").map((opening) => {
      if (opening.key !== undefined) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
      return openingJson(opening);
    }),
    outputs: sized(inputs.outputs, RING_OUTPUT_SLOTS, "outputs").map(openingJson),
    addressChain: hex32(inputs.addressChain, "addressChain"),
    privateTxBlinding: hex32(inputs.privateTxBlinding, "privateTxBlinding"),
    sources: sized(inputs.sources, RING_SOURCE_SLOTS, "sources").map(sourceJson),
    policyLen: u8(inputs.policyLen, "policyLen"),
    ruleEnc: sized(inputs.rules, RING_RULE_SLOTS, "rules").map((rule) => hex32(rule, "rules")),
    inlineAssets: sized(inputs.inlineAssets, RING_INLINE_ASSET_SLOTS, "inlineAssets").map((asset) =>
      hex32(asset, "inlineAssets"),
    ),
    inlineLimits: sized(inputs.inlineLimits, RING_INLINE_ASSET_SLOTS, "inlineLimits").map((limit) =>
      u64FieldHex(limit, "inlineLimits"),
    ),
    inlineCount: u8(inputs.inlineCount, "inlineCount"),
    treeSlots: policyTreeSlots(inputs.treeSlots).map(policyTreeSlotJson),
    addressTreeId: hex32(treeIdField(inputs.addressTreeId), "addressTreeId"),
    windowSlots: u64Json(inputs.velocity.windowSlots, "windowSlots"),
    velocity: paddedVelocityRows(inputs.velocity.rows).map(velocityRowJson),
    velocityCount: u8(inputs.velocity.rows.length, "velocityCount"),
    ringId: hex32(inputs.velocity.ringId, "ringId"),
    namespaceOwnerHash: hex32(inputs.velocity.namespaceOwnerHash, "namespaceOwnerHash"),
    windowIndex: u64Json(inputs.velocity.windowIndex, "windowIndex"),
    approvalRequired: inputs.velocity.approvalRequired,
    ...keyEscrowJson(inputs.keyRegistryRoot),
    record: spendRecordJson(inputs.velocity.record),
    answers: sized(inputs.answers, RING_ANSWER_SLOTS, "answers").map(answersJson),
  });
}

/** Mirrors Go `readTreeSlots`, the populated prefix of one to `INPUT_TREES` slots. */
function policyTreeSlots(slots: readonly TreeSlot[]): readonly TreeSlot[] {
  if (!Array.isArray(slots) || slots.length < 1 || slots.length > INPUT_TREES) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: {
        field: "treeSlots",
        expected: INPUT_TREES,
        actual: Array.isArray(slots) ? slots.length : 0,
      },
    });
  }
  return slots;
}

function policyTreeSlotJson(slot: TreeSlot): Readonly<Record<string, unknown>> {
  return Object.freeze({
    id: hex32(treeIdField(slot.id), "treeSlots id"),
    utxoRoot: hex32(slot.utxoRoot, "treeSlots utxoRoot"),
    nullifierRoot: hex32(slot.nullifierRoot, "treeSlots nullifierRoot"),
  });
}

/** Mirrors Go `readKeyEscrow`, the root is zero exactly when escrow is off. */
function keyEscrowJson(root: Bytes32 | undefined): Readonly<Record<string, unknown>> {
  return Object.freeze({
    keyEscrow: root !== undefined,
    keyRegistryRoot: hex32(root ?? new Uint8Array(32), "keyRegistryRoot"),
  });
}

/** Mirrors Go `writeRegistryKey`, `null` for an absent key. */
function registryKeyJson(
  key: CustomRingRegistryKey | undefined,
): Readonly<Record<string, unknown>> | null {
  if (key === undefined) return null;
  if (typeof key.index !== "bigint" || key.index < 0n || key.index >= KEY_REGISTRY_CAPACITY)
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: "key index" } });
  return Object.freeze({
    next: hex32(key.next, "key next"),
    ctHash: hex32(key.ctHash, "key ctHash"),
    index: u64Json(key.index, "key index"),
    path: sized(key.path, KEY_REGISTRY_HEIGHT, "key path").map((node) => hex32(node, "key path")),
  });
}

function registryIndexHex(index: bigint, field: string): string {
  if (typeof index !== "bigint" || index < 0n || index >= KEY_REGISTRY_CAPACITY)
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field } });
  return `0x${index.toString(16).padStart(64, "0")}`;
}

export function customRingCompressedPolicyProofRequest(
  input: CustomRingCompressedPolicyProofRequest,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    circuitType: "custom-ring-compressed-policy",
    transactionSalt: bytesHex(checkedBytes(input.transactionSalt, 16, "transactionSalt")),
    policy: customRingPolicyProofRequest(input.policy),
  });
}

function registryInsertionJson(
  input: CustomRingRegistryInsertion,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    registryOldRoot: hex32(input.registryOldRoot, "registryOldRoot"),
    registryNewRoot: hex32(input.registryNewRoot, "registryNewRoot"),
    member: hex32(input.member, "member"),
    newIndex: registryIndexHex(input.newIndex, "newIndex"),
    lowIndex: registryIndexHex(input.lowIndex, "lowIndex"),
    lowMember: hex32(input.lowMember, "lowMember"),
    lowNext: hex32(input.lowNext, "lowNext"),
    lowKey: hex32(input.lowKey, "lowKey"),
    lowProof: sized(input.lowProof, KEY_REGISTRY_HEIGHT, "lowProof").map((node) =>
      hex32(node, "lowProof"),
    ),
    newProof: sized(input.newProof, KEY_REGISTRY_HEIGHT, "newProof").map((node) =>
      hex32(node, "newProof"),
    ),
  });
}

/** Mirrors Rust `RegisterKeyProofRequest::body`, the zero high byte keeps the secret below the field order. */
export function customRingRegisterKeyProofRequest(
  input: CustomRingRegisterKeyProofRequest,
): Readonly<Record<string, unknown>> {
  const nullifierSecret = checkedBytes(input.nullifierSecret, 32, "nullifierSecret");
  if (nullifierSecret[0] !== 0) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return Object.freeze({
    circuitType: "custom-ring-register-key",
    publicInputHash: hex32(input.publicInputHash, "publicInputHash"),
    ...registryInsertionJson(input),
    nullifierSecret: bytesHex(nullifierSecret),
    ephSk: hex32(input.ephemeralSecret, "ephSk"),
    auditorPk: auditorPkHex(input.auditorPublicKey),
  });
}

export function customRingDepositProofRequest(
  input: CustomRingDepositProofRequest,
): Readonly<Record<string, unknown>> {
  const columns = [input.ownerPkHashes, input.nullifierPks, input.blindings];
  if (
    !Number.isInteger(input.count) ||
    input.count < 1 ||
    input.count > RING_DEPOSIT_AUDIT_SLOTS ||
    !Array.isArray(input.keys) ||
    input.keys.length !== RING_DEPOSIT_AUDIT_SLOTS ||
    columns.some((column) => !Array.isArray(column) || column.length !== RING_DEPOSIT_AUDIT_SLOTS)
  )
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  try {
    auditorPkHex(input.auditorPublicKey);
    X25519Keypair.fromBytes(input.ephemeralSecret).destroy();
  } catch {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  for (const field of [input.publicInputHash, input.contextHash, ...columns.flat()]) {
    if (!isCanonicalField(field)) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  for (let index = input.count; index < RING_DEPOSIT_AUDIT_SLOTS; index++) {
    if (
      columns.some((column) => column[index]?.some((byte) => byte !== 0)) ||
      input.keys[index] !== undefined
    )
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  return Object.freeze({
    circuitType: "custom-ring-deposit",
    publicInputHash: hex32(input.publicInputHash, "publicInputHash"),
    contextHash: hex32(input.contextHash, "contextHash"),
    count: input.count,
    ownerPkHashes: input.ownerPkHashes.map((field) => hex32(field, "ownerPkHash")),
    nullifierPks: input.nullifierPks.map((field) => hex32(field, "nullifierPk")),
    blindings: input.blindings.map((field) => hex32(field, "blinding")),
    keys: input.keys.map(registryKeyJson),
    ephSk: hex32(input.ephemeralSecret, "ephSk"),
    auditorPk: auditorPkHex(input.auditorPublicKey),
    ...keyEscrowJson(input.keyRegistryRoot),
  });
}

/** Rows past the count are zero, the server refuses other padding. */
function paddedVelocityRows(
  rows: readonly CustomRingVelocityRow[],
): readonly CustomRingVelocityRow[] {
  if (rows.length > RING_VELOCITY_SLOTS) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: { field: "velocity", expected: RING_VELOCITY_SLOTS, actual: rows.length },
    });
  }
  return Object.freeze(
    Array.from(
      { length: RING_VELOCITY_SLOTS },
      (_, index) =>
        rows[index] ?? { asset: new Uint8Array(32) as Bytes32, cap: 0n, cosignAbove: 0n },
    ),
  );
}

function velocityRowJson(row: CustomRingVelocityRow): Readonly<Record<string, unknown>> {
  return Object.freeze({
    asset: hex32(row.asset, "velocity asset"),
    cap: u64FieldHex(row.cap, "velocity cap"),
    cosignAbove: u64FieldHex(row.cosignAbove, "velocity cosignAbove"),
  });
}

function spendRecordJson(
  record: CustomRingSpendRecordProofInput,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    version: u64Json(record.version, "record version"),
    window: u64Json(record.window, "record window"),
    commitment: hex32(record.commitment, "record commitment"),
    salt: hex32(record.salt, "record salt"),
    assets: sized(record.assets, RING_VELOCITY_SLOTS, "record assets").map((asset) =>
      hex32(asset, "record assets"),
    ),
    spent: sized(record.spent, RING_VELOCITY_SLOTS, "record spent").map((spent) =>
      u64FieldHex(spent, "record spent"),
    ),
    nextSalt: hex32(record.nextSalt, "record nextSalt"),
  });
}

function openingJson(opening: CustomRingOpening): Readonly<Record<string, unknown>> {
  return Object.freeze({
    domain: hex32(opening.domain, "domain"),
    treeId: hex32(opening.treeId, "treeId"),
    ownerPkHash: hex32(opening.ownerPkHash, "ownerPkHash"),
    nullifierPk: hex32(opening.nullifierPk, "nullifierPk"),
    asset: hex32(opening.asset, "asset"),
    amount: hex32(opening.amount, "amount"),
    blinding: hex32(opening.blinding, "blinding"),
    dataHash: hex32(opening.dataHash, "dataHash"),
    ringDataHash: hex32(opening.ringDataHash, "ringDataHash"),
    ringProgramId: hex32(opening.ringProgramId, "ringProgramId"),
    ...(opening.key === undefined ? {} : { key: registryKeyJson(opening.key) }),
  });
}

/** The base circuit needs the already-combined owner hash used by the SPP commitment. */
function auditOpeningJson(opening: CustomRingOpening): Readonly<Record<string, unknown>> {
  const domain = bytesToBigInt(opening.domain);
  const ownerHash =
    domain === 0n || domain === BigInt(DUMMY_DOMAIN)
      ? new Uint8Array(32)
      : poseidon([opening.ownerPkHash, opening.nullifierPk]);
  return Object.freeze({
    domain: hex32(opening.domain, "domain"),
    treeId: hex32(opening.treeId, "treeId"),
    ownerHash: hex32(ownerHash, "ownerHash"),
    asset: hex32(opening.asset, "asset"),
    amount: hex32(opening.amount, "amount"),
    blinding: hex32(opening.blinding, "blinding"),
    dataHash: hex32(opening.dataHash, "dataHash"),
    ringDataHash: hex32(opening.ringDataHash, "ringDataHash"),
    ringProgramId: hex32(opening.ringProgramId, "ringProgramId"),
  });
}

function sourceJson(source: CustomRingSourceOwner): Readonly<Record<string, unknown>> {
  return Object.freeze({
    listId: u8(source.listId, "listId"),
    ownerHash: hex32(source.ownerHash, "ownerHash"),
  });
}

function answersJson(entry: CustomRingRuleAnswer): Readonly<Record<string, unknown>> {
  return Object.freeze({
    enabled: entry.enabled,
    treeSlot: u8(entry.treeSlot, "treeSlot"),
    mode: u8(entry.mode, "mode"),
    listId: u8(entry.listId, "listId"),
    state: u8(entry.state, "state"),
    absentBranch: u8(entry.absentBranch, "absentBranch"),
    member: hex32(entry.member, "member"),
    contentHash: hex32(entry.contentHash, "contentHash"),
    version: u64Json(entry.version, "version"),
    blinding: hex32(entry.blinding, "blinding"),
    low: hex32(entry.low, "low"),
    next: hex32(entry.next, "next"),
    nfPathElements: sized(entry.nullifierPath, RING_NULLIFIER_PATH_LENGTH, "nullifierPath").map(
      (element) => hex32(element, "nullifierPath"),
    ),
    nfPathIndex: u64Json(entry.nullifierPathIndex, "nullifierPathIndex"),
    statePathElements: sized(entry.statePath, RING_STATE_PATH_LENGTH, "statePath").map((element) =>
      hex32(element, "statePath"),
    ),
    statePathIndex: u64Json(entry.statePathIndex, "statePathIndex"),
  });
}

/** Rust `field_hex`, the fixed-width hex the prover requires. */
function hex32(bytes: Uint8Array, field: string): string {
  return bytesHex(checkedBytes(bytes, 32, field));
}

/** Canonical little-endian X25519 auditor coordinate witnessed by the circuit. */
function auditorPkHex(auditorPublicKey: Uint8Array): string {
  if (!(auditorPublicKey instanceof Uint8Array) || auditorPublicKey.length !== 32)
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  try {
    X25519PublicKey.fromBytes(Uint8Array.of(4, ...auditorPublicKey));
  } catch {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  return bytesHex(auditorPublicKey);
}

function u8(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xff) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field } });
  }
  return value;
}

/** Rust emits `u64` as a JSON number, the value must stay a safe integer. */
function u64Json(value: bigint, field: string): number {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field } });
  }
  return Number(value);
}

function u64FieldHex(value: bigint, field: string): string {
  if (typeof value !== "bigint" || value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field } });
  }
  return `0x${value.toString(16).padStart(64, "0")}`;
}

function sized<T>(values: readonly T[], expected: number, field: string): readonly T[] {
  if (!Array.isArray(values) || values.length !== expected) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: { field, expected, actual: Array.isArray(values) ? values.length : 0 },
    });
  }
  return values;
}

function bytesHex(bytes: Uint8Array): string {
  return `0x${bytesToHex(bytes)}`;
}
