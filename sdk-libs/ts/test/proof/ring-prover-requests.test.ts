import { policyWithdrawalHash } from "../../src/proof/withdrawals.js";
import { initializePoseidon } from "@heliuslabs/zolana";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename } from "node:path";

import { describe, expect, it } from "vitest";

import {
  ringProofCircuit,
  ringProofRequestBody,
  ringRequestKey,
  type AnonymousSlotProofInputs,
  type AnonymousTransferProofRequest,
  type AuditEnvelopeProofInputs,
  type ConfidentialTransferProofRequest,
  type DeliveredSlotProofInputs,
  type PolicyProofInputs,
  type PolicySubjectEntry,
  type PolicyTableProofInputs,
  type RingProofRequest,
  type RingSlotOpening,
} from "../../src/rpc/prover/ring.js";
import { type PresentRecordOpening } from "../../src/rpc/prover/types.js";
import { encodeBase58, isZero, solanaOwnerIdentity } from "@heliuslabs/zolana/internal";
import { UTXO_DOMAIN } from "@heliuslabs/zolana/interface";
import type { Bytes16, Bytes31, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import {
  NullifierKey,
  poseidon,
  ShieldedKeypair,
  SigningKey,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  privateTxHash,
  SOL_MINT,
} from "@heliuslabs/zolana/transaction";
import type {
  MemberRecord,
  QuadPath,
  RecordOpening,
  RecordPool,
  RecordWriteProofInput,
} from "../../src/protocol/membership/member-registry.js";
import {
  RING_KEYS,
  RING_PROVING_KEY_SHA256S,
  ringCircuitType,
  ringProvingKey,
} from "../../src/protocol/proof/proving-keys.js";
import {
  AUDIT_ENC_INFO,
  auditSharedSecret,
  symmetricAuditApply,
} from "../../src/crypto/audit/audit.js";
import { RECIPIENT_BODY_LEN } from "../../src/protocol/codec/anonymous-delivery.js";
import {
  deliveredBodyLen,
  recordRegion,
  recordSlots,
  STREAM_FIRST_COUNTER,
  type AuditLayout,
  type AuditStreamLayout,
} from "../../src/protocol/codec/ring-disclosure-layout.js";
import {
  disclosurePlaintext,
  type AnonymousOutputOpening,
  type DeliveredOutputOpening,
  type RingDisclosure,
} from "../../src/crypto/audit/ring-disclosure.js";
import { sealSenderBundle } from "../../src/protocol/codec/anonymous-delivery.js";
import { sealDeliveredBody } from "../../src/protocol/transaction/output.js";
import { deliveredSlotSecret } from "../../src/crypto/derivation/ring-stream.js";
import {
  addressRecordHash,
  applyRecordsStatement,
  replayRecordWrites,
  verifyRecordPool,
  type MemberOpeningRead,
} from "../../src/protocol/membership/member-opening.js";
import {
  buildRuleTable,
  decodeRule,
  policyTableHash,
} from "../../src/protocol/membership/policy.js";
import { sealNullifierKeyWith } from "../../src/operations/management/register-key.js";
import {
  applyRecordsStatementHash,
  registerKeyStatementHash,
  signerBinding,
  transferStatementHash,
  type AuditHead,
} from "../../src/protocol/proof/statement.js";
import type { RingOutput } from "../../src/protocol/transaction/transact.js";
import {
  OutputBlindings,
  ringBlindingSeed,
  ringOutputBlinding,
} from "../../src/crypto/derivation/blinding.js";
import { signingKeySpendSigner } from "../../src/operations/payments/anonymous.js";
import { CustomRingTransfer } from "../../src/operations/payments/transfer-rails.js";
import { RingAddress } from "../../src/crypto/keys/ring-address.js";
import { noteInput, ringFixture, walletKeys, type Fixture } from "../helpers/ring-pipeline.js";

await initializePoseidon();

const GOLDENS = new URL("../../../../prover/ring/testdata/", import.meta.url);
const HAS_GOLDENS = existsSync(GOLDENS);
const GOLDEN_FILES = HAS_GOLDENS
  ? readdirSync(GOLDENS, { recursive: true }).filter(
      (name): name is string => typeof name === "string" && name.endsWith(".json"),
    )
  : [];
const GOLDEN_BY_CIRCUIT = new Map(
  GOLDEN_FILES.map((file) => [basename(file, ".json"), file] as const),
);
const RUST_FIXTURES = new URL("../../../sdk/tests/fixtures/", import.meta.url);
const RUST_TRANSFER_FIXTURES = readdirSync(RUST_FIXTURES).filter(
  (name) => name.startsWith("custom-ring-transfer-") && name.endsWith(".json"),
);
const ZERO = new Uint8Array(32) as Bytes32;

type Json = Readonly<Record<string, unknown>>;

function golden(circuitType: string): Json {
  const file = GOLDEN_BY_CIRCUIT.get(circuitType);
  if (file === undefined) throw new Error(`missing golden for ${circuitType}`);
  return record(JSON.parse(readFileSync(new URL(file, GOLDENS), "utf8")));
}

function record(value: unknown): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("golden object");
  return value as Json;
}

function list(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error("golden list");
  return value;
}

function text(value: unknown): string {
  if (typeof value !== "string") throw new Error("golden string");
  return value;
}

function count(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error("golden integer");
  return value;
}

function flag(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("golden boolean");
  return value;
}

function bytes<T extends Uint8Array>(value: unknown, length: number): T {
  const hex = text(value);
  if (!hex.startsWith("0x") || hex.length !== 2 + 2 * length) throw new Error("golden hex");
  return Uint8Array.from(Buffer.from(hex.slice(2), "hex")) as T;
}

function field(value: unknown): Bytes32 {
  return bytes<Bytes32>(value, 32);
}

function fields(value: unknown): readonly Bytes32[] {
  return list(value).map(field);
}

function hex(value: Uint8Array): string {
  return `0x${Buffer.from(value).toString("hex")}`;
}

function amountOf(value: Bytes32): bigint {
  return BigInt(hex(value));
}

function opening(value: unknown): RingSlotOpening {
  const item = record(value);
  return {
    domain: field(item["domain"]),
    treeId: field(item["treeId"]),
    ownerPkHash: field(item["ownerPkHash"]),
    nullifierPk: field(item["nullifierPk"]),
    asset: field(item["asset"]),
    amount: field(item["amount"]),
    blinding: field(item["blinding"]),
    dataHash: field(item["dataHash"]),
    ringDataHash: field(item["ringDataHash"]),
    ringProgramId: field(item["ringProgramId"]),
  };
}

function quadPath(index: unknown, flat: unknown): QuadPath {
  const siblings = fields(flat);
  return {
    index: count(index),
    siblings: Array.from({ length: siblings.length / 3 }, (_, level) =>
      siblings.slice(3 * level, 3 * level + 3),
    ),
  };
}

/** Go `RecordOpening` carries no member, the test names the subject it opens. */
function presentRecord(value: unknown, member: Bytes32): PresentRecordOpening {
  const item = record(value);
  return {
    kind: "present",
    record: {
      mintPolicy: mintSettings(
        item["mintPolicy"],
        item["withdrawalThreshold"],
        item["assetLimits"],
      ),
      member,
      next: field(item["next"]),
      lists: BigInt(count(item["lists"])),
      escrowKey: field(item["escrowKey"]),
      addressHash: field(item["addressHash"]),
    },
    path: quadPath(item["index"], item["path"]),
  };
}

function memberOpening(value: unknown, member: Bytes32): RecordOpening | undefined {
  if (value === null) return undefined;
  const item = record(value);
  if (flag(item["present"])) return presentRecord(item, member);
  return {
    kind: "absent",
    low: {
      mintPolicy: mintSettings(
        item["lowMintPolicy"],
        item["lowWithdrawalThreshold"],
        item["lowAssetLimits"],
      ),
      member: field(item["lowMember"]),
      next: field(item["lowNext"]),
      lists: BigInt(count(item["lowLists"])),
      escrowKey: field(item["lowEscrow"]),
      addressHash: field(item["lowAddressHash"]),
    },
    path: quadPath(item["index"], item["path"]),
  };
}

function table(item: Json): PolicyTableProofInputs {
  return {
    sources: list(item["sources"]).map((value) => {
      const source = record(value);
      return {
        listId: count(source["listId"]),
        registry: field(source["registry"]),
      };
    }),
    policyLen: count(item["policyLen"]),
    rules: fields(item["rules"]),
  };
}

function entry(value: unknown): PolicySubjectEntry {
  const item = record(value);
  const [curator, ...rest] = list(item["curator"]);
  if (curator === undefined || rest.length !== 0) throw new Error("golden curator entry");
  return { own: count(item["own"]), curator: count(curator) };
}

function memberRecord(value: unknown): MemberRecord {
  const item = record(value);
  return {
    mintPolicy: mintSettings(item["mintPolicy"], item["withdrawalThreshold"], item["assetLimits"]),
    member: field(item["member"]),
    next: field(item["next"]),
    lists: BigInt(count(item["lists"])),
    escrowKey: field(item["escrowKey"]),
    addressHash: field(item["addressHash"]),
  };
}

/** Go `PooledRecord`, `SharedRegistryProof` and `PooledSubject` rows. */
function recordPool(records: unknown, proof: unknown, subjects: unknown): RecordPool {
  const rows = list(records);
  const shared = record(proof);
  return {
    records: rows.map(memberRecord),
    canopy: fields(shared["canopy"]),
    paths: list(shared["paths"]).map((value) => {
      const path = record(value);
      return {
        index: count(path["index"]),
        siblings: list(path["siblings"]).map(fields),
      };
    }),
    subjects: list(subjects).map((value) => {
      const subject = record(value);
      return {
        member: field(subject["member"]),
        recordIndex: count(subject["recordIndex"]),
      };
    }),
  };
}

/** `key_escrow << 1 | full_openings << 3`. */
function layout(value: unknown): AuditLayout {
  const flags = count(value);
  return {
    keyEscrow: (flags & 2) !== 0,
    fullOpenings: (flags & 8) !== 0,
  };
}

function envelope(item: Json): AuditEnvelopeProofInputs {
  return {
    firstNullifier: field(item["firstNullifier"]),
    txViewingSk: bytes<Bytes32>(item["txViewingSk"], 32),
    ephSk: bytes<Bytes32>(item["ephSk"], 32),
    auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
    salt: bytes<Bytes16>(item["salt"], 16),
    layout: layout(item["layout"]),
  };
}

function delivered(value: unknown, keyEscrow: boolean): DeliveredSlotProofInputs {
  const item = record(value);
  return {
    output: opening(item["output"]),
    recipientKey: bytes<Bytes32>(item["recipientKey"], 32),
    ownerKey: bytes<Bytes32>(item["ownerKey"], 32),
    body: bytes(item["body"], deliveredBodyLen(keyEscrow)),
  };
}

function anonymousSlot(value: unknown): AnonymousSlotProofInputs {
  const item = record(value);
  return {
    output: opening(item["output"]),
    ownerKey: bytes<Bytes32>(item["ownerKey"], 32),
    recipientKey: bytes<Bytes32>(item["recipientKey"], 32),
    addressRevision: BigInt(count(item["addressRevision"])),
    mintChunks: fields(item["mintChunks"]),
    body: bytes(item["body"], RECIPIENT_BODY_LEN),
    tag: field(item["tag"]),
    tagPreimage: field(item["tagPreimage"]),
  };
}

function policy(item: Json): PolicyProofInputs {
  const withdrawals = list(item["withdrawals"]).map((value) => {
    const leg = record(value);
    return {
      owner: field(leg["owner"]),
      asset: field(leg["asset"]),
      amount: BigInt(String(leg["amount"])),
    };
  });
  return {
    withdrawalCount: count(item["withdrawalCount"]),
    withdrawalHash: field(item["withdrawalHash"]),
    withdrawals,
    policyHash: field(item["policyHash"]),
    ringId: field(item["ringId"]),
    ownRoot: field(item["ownRoot"]),
    curatorRoot: field(item["curatorRoot"]),
    publicAssets: fields(item["publicAssets"]),
    publicAmounts: fields(item["publicAmounts"]),
    publicGross: fields(item["publicGross"]),
    ...table(item),
    ctHashes: fields(item["ctHashes"]),
    recipients: fields(item["recipients"]),
    ownPool: recordPool(item["ownRecords"], item["ownProof"], item["ownSubjects"]),
    curatorPool: recordPool(item["curatorRecords"], item["curatorProof"], item["curatorSubjects"]),
    senderEntries: list(item["senderEntries"]).map(entry),
    ownerEntries: list(item["ownerEntries"]).map(entry),
    assetEntries: list(item["assetEntries"]).map(entry),
    publicAssetEntries: list(item["publicAssetEntries"]).map(count),
  };
}

function write(value: unknown): RecordWriteProofInput {
  const item = record(value);
  const queued = record(item["entry"]);
  return {
    oldMintPolicy: mintSettings(
      item["oldMintPolicy"],
      item["oldWithdrawalThreshold"],
      item["oldAssetLimits"],
    ),
    entry: {
      member: field(queued["member"]),
      mask: BigInt(count(queued["mask"])),
      value: BigInt(count(queued["value"])),
      escrowKey: field(queued["escrowKey"]),
      addressHash: field(queued["addressHash"]),
    },
    exists: flag(item["exists"]),
    oldNext: field(item["oldNext"]),
    oldLists: BigInt(count(item["oldLists"])),
    oldEscrow: field(item["oldEscrow"]),
    oldAddressHash: field(item["oldAddressHash"]),
    pair: {
      nullifierPk: field(item["nullifierPk"]),
      addressRing: field(item["addressRing"]),
      view0: field(item["view0"]),
      view1: field(item["view1"]),
      addressRevision: BigInt(count(item["addressRevision"])),
      escrowCiphertextHash: field(item["escrowCtHash"]),
    },
    slot: quadPath(item["index"], item["path"]),
    low: {
      mintPolicy: mintSettings(
        item["lowMintPolicy"],
        item["lowWithdrawalThreshold"],
        item["lowAssetLimits"],
      ),
      member: field(item["lowMember"]),
      next: field(item["lowNext"]),
      lists: BigInt(count(item["lowLists"])),
      escrowKey: field(item["lowEscrow"]),
      addressHash: field(item["lowAddressHash"]),
    },
    lowPath: quadPath(item["lowIndex"], item["lowPath"]),
  };
}

/** The typed request a golden file holds, built field by field. */
function request(item: Json): RingProofRequest {
  const circuitType = text(item["circuitType"]);
  const publicInputHash = field(item["publicInputHash"]);
  const transfer = () => ({
    publicInputHash,
    ...envelope(item),
    exempt: flag(item["exempt"]),
    approvalRequired: flag(item["approvalRequired"]),
    outputCount: count(item["outputCount"]),
    inputCount: count(item["inputCount"]),
    signerCount: count(item["signerCount"]),
    signers: fields(item["signers"]),
    privateTxHash: field(item["privateTxHash"]),
    privateTxBlinding: field(item["privateTxBlinding"]),
    ...policy(item),
  });
  if (circuitType.startsWith("custom-ring-transfer-confidential-"))
    return {
      kind: "transferConfidential",
      ...transfer(),
      inProof: flag(item["inProof"]),
      delegate: flag(item["delegate"]),
      outputs: list(item["outputs"]).map((output) =>
        delivered(output, layout(item["layout"]).keyEscrow),
      ),
      inputs: list(item["inputs"]).map(opening),
      sender: field(item["sender"]),
      senderPkHash: field(item["senderPkHash"]),
    };
  if (circuitType.startsWith("custom-ring-transfer-anonymous-"))
    return {
      kind: "transferAnonymous",
      ...transfer(),
      outputs: list(item["outputs"]).map(anonymousSlot),
      ...(item["senderKey"] === undefined
        ? {}
        : { senderKey: bytes<Bytes32>(item["senderKey"], 32) }),
      inputs: list(item["inputs"]).map(opening),
      partyIdentities: fields(item["partyIdentities"]) as [Bytes32, Bytes32, Bytes32],
      senderNullifierPk: field(item["senderNullifierPk"]),
      senderViewingKey: bytes<Bytes32>(item["senderViewingKey"], 32),
      senderAddressRevision: BigInt(count(item["senderAddressRevision"])),
      senderBundleTag: field(item["senderBundleTag"]),
      replyDigest: field(item["replyDigest"]),
    };
  if (circuitType.startsWith("custom-ring-apply-records-"))
    return {
      kind: "applyRecords",
      publicInputHash,
      oldRoot: field(item["oldRoot"]),
      newRoot: field(item["newRoot"]),
      oldNextIndex: count(item["oldNextIndex"]),
      newNextIndex: count(item["newNextIndex"]),
      chainStart: field(item["chainStart"]),
      chainEnd: field(item["chainEnd"]),
      writes: list(item["writes"]).slice(0, count(item["count"])).map(write),
    };
  if (circuitType === "custom-ring-register-key")
    return {
      kind: "registerKey",
      publicInputHash,
      ringId: field(item["ringId"]),
      member: field(item["member"]),
      nullifierSecret: bytes<Bytes32>(item["nullifierSecret"], 32),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
    };
  if (circuitType.startsWith("custom-ring-deposit-")) {
    const ownerPkHashes = fields(item["ownerPkHashes"]);
    return {
      kind: "deposit",
      publicInputHash,
      contextHash: field(item["contextHash"]),
      count: count(item["count"]),
      anonymous: item["anonymous"] === undefined ? false : flag(item["anonymous"]),
      ownerPkHashes,
      ownerKeys: list(item["ownerKeys"]).map((key) => bytes<Bytes32>(key, 32)),
      nullifierPks: fields(item["nullifierPks"]),
      blindingSecrets: fields(item["blindingSecrets"]),
      ctHashes: fields(item["ctHashes"]),
      members: list(item["members"]).map((member, i) =>
        member === null ? undefined : presentRecord(member, ownerPkHashes[i] ?? ZERO),
      ),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
      keyEscrow: flag(item["keyEscrow"]),
      memberRegistryRoot: field(item["memberRegistryRoot"]),
      curatorRoot: field(item["curatorRoot"]),
      policyHash: field(item["policyHash"]),
      assets: fields(item["assets"]),
      amounts: fields(item["amounts"]),
      ...(item["table"] === undefined ? {} : { table: table(record(item["table"])) }),
      assetRecords: list(item["assetRecords"]).map((opening, i) =>
        memberOpening(opening, fields(item["assets"])[i] ?? ZERO),
      ),
      curatorAssetRecords: list(item["curatorAssetRecords"]).map((opening, i) =>
        memberOpening(opening, fields(item["assets"])[i] ?? ZERO),
      ),
      ownerRecords: list(item["ownerRecords"]).map((opening, i) =>
        memberOpening(opening, fields(item["ownerPkHashes"])[i] ?? ZERO),
      ),
      curatorOwnerRecords: list(item["curatorOwnerRecords"]).map((opening, i) =>
        memberOpening(opening, fields(item["ownerPkHashes"])[i] ?? ZERO),
      ),
    };
  }
  if (circuitType.startsWith("custom-ring-merge-v3-")) {
    const ownerKey = bytes<Bytes32>(item["ownerKey"], 32);
    return {
      kind: "merge",
      partyIdentities: fields(item["partyIdentities"]) as [Bytes32, Bytes32, Bytes32],
      publicInputHash,
      privateTxHash: field(item["privateTxHash"]),
      outputUtxoHash: field(item["outputUtxoHash"]),
      firstNullifier: field(item["firstNullifier"]),
      ringProgramId: field(item["ringProgramId"]),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
      salt: field(item["salt"]),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      disclosureKey: bytes<Bytes32>(item["disclosureKey"], 32),
      ownerKey,
      nullifierSecret: field(item["nullifierSecret"]),
      asset: field(item["asset"]),
      inputCount: count(item["inputCount"]),
      inputs: list(item["inputs"]).map((value) => {
        const input = record(value);
        return {
          domain: field(input["domain"]),
          treeId: field(input["treeId"]),
          amount: field(input["amount"]),
          blinding: field(input["blinding"]),
          ringDataHash: field(input["ringDataHash"]),
        };
      }),
      outputTreeId: field(item["outputTreeId"]),
      outputRingDataHash: field(item["outputRingDataHash"]),
      keyEscrow: flag(item["keyEscrow"]),
      memberRegistryRoot: field(item["memberRegistryRoot"]),
      ctHash: field(item["ctHash"]),
      ...(item["member"] === null
        ? {}
        : {
            member: presentRecord(item["member"], solanaOwnerIdentity(ownerKey) as Bytes32),
          }),
    };
  }
  throw new Error(`no request for ${circuitType}`);
}

function tagged(u: Uint8Array): Bytes33 {
  return Uint8Array.from([4, ...u]) as Bytes33;
}

function publicKeyOf(secret: Uint8Array): X25519PublicKey {
  const keypair = X25519Keypair.fromBytes(secret);
  try {
    return keypair.publicKey();
  } finally {
    keypair.destroy();
  }
}

function agreement(secret: Uint8Array, peer: X25519PublicKey): Bytes32 {
  const keypair = X25519Keypair.fromBytes(secret);
  try {
    return keypair.ecdh(peer);
  } finally {
    keypair.destroy();
  }
}

/** The auditor stream the circuit seals, rebuilt from the request's secrets. */
function requestStream(
  envelope: AuditEnvelopeProofInputs,
  disclosure: RingDisclosure,
): Readonly<{ envelope: Uint8Array; records: readonly Uint8Array[] }> {
  const auditor = X25519PublicKey.fromBytes(tagged(envelope.auditorPk));
  const eph = publicKeyOf(envelope.ephSk);
  const shared = auditSharedSecret(agreement(envelope.ephSk, auditor), eph, auditor);
  const plaintext = disclosurePlaintext(disclosure);
  const seal = (counter: number, data: Uint8Array) =>
    symmetricAuditApply(shared, { label: AUDIT_ENC_INFO, counter }, data);
  return {
    envelope: seal(
      STREAM_FIRST_COUNTER,
      Uint8Array.of(...envelope.txViewingSk, ...plaintext.evidence),
    ),
    records: recordSlots(disclosure.layout).map((slot, index) =>
      seal(recordRegion(disclosure.layout, slot).startCounter, plaintext.records[index]!),
    ),
  };
}

function auditHead(
  envelope: AuditEnvelopeProofInputs & Readonly<{ ringId: Bytes32 }>,
  stream: Readonly<{ envelope: Uint8Array }>,
): AuditHead {
  return {
    firstNullifier: envelope.firstNullifier,
    ringId: envelope.ringId,
    txViewingU: publicKeyOf(envelope.txViewingSk).u(),
    auditorPubkey: tagged(envelope.auditorPk),
    ephU: publicKeyOf(envelope.ephSk).u(),
    envelope: stream.envelope,
    salt: envelope.salt,
    layout: envelope.layout,
  };
}

/** Bit `i` set when slot `i` opens a UTXO outside the ring. */
function exitsOf(outputs: readonly Readonly<{ output: RingSlotOpening }>[]): bigint {
  return outputs.reduce(
    (bits, { output }, slot) =>
      isUtxo(output) && !isRingOutput(output) ? bits | (1n << BigInt(slot)) : bits,
    0n,
  );
}

/** One ring disclosure ciphertext per slot, `record` the stream's record of `slot`. */
function slotCiphertexts(
  layout: AuditStreamLayout,
  records: readonly Uint8Array[],
  bodyOf: (slot: number) => Uint8Array | undefined,
): readonly Uint8Array[] {
  const slots = recordSlots(layout);
  return Array.from({ length: layout.outputs }, (_, slot) => {
    const index = slots.indexOf(slot);
    return index < 0 ? bodyOf(slot)! : records[index]!;
  });
}

/** Go `UtxoHashCircuit`, a dummy's owner is zero. */
function openingHash(slot: RingSlotOpening): Bytes32 {
  const owner = isUtxo(slot) ? poseidon([slot.ownerPkHash, slot.nullifierPk]) : ZERO;
  return poseidon([
    slot.domain,
    slot.treeId,
    slot.asset,
    slot.amount,
    slot.dataHash,
    poseidon([slot.ringDataHash, slot.ringProgramId]),
    poseidon([owner, slot.blinding]),
  ]) as Bytes32;
}

function isUtxo(slot: RingSlotOpening): boolean {
  return amountOf(slot.domain) === BigInt(UTXO_DOMAIN);
}

function isRingOutput(slot: RingSlotOpening): boolean {
  return isUtxo(slot) && amountOf(slot.ringProgramId) !== 0n;
}

/** SPP's TXOB blinding of slot `outputIndex` under the seed the envelope's `tx_viewing_sk` fixes. */
function blindingOf(envelope: AuditEnvelopeProofInputs, outputIndex: number): Bytes32 {
  return ringOutputBlinding({
    firstNullifier: envelope.firstNullifier,
    blindingSeed: ringBlindingSeed(envelope.txViewingSk, envelope.salt),
    outputIndex,
  });
}

function exitOutput(hash: Bytes32): RingOutput {
  return { kind: "exit", hash, ownerTag: ZERO, payload: new Uint8Array(0) };
}

// The Go ring prover goldens live outside the repository.
const CIRCUIT_TYPES = [...GOLDEN_BY_CIRCUIT.keys()].sort();

describe.runIf(HAS_GOLDENS)("ring prover request encoding against the Go goldens", () => {
  it("lists every ring key of ring_keys.rs and names one for each golden", () => {
    const rust = readFileSync(
      new URL("../../../../program-libs/interface/src/proof/ring_keys.rs", import.meta.url),
      "utf8",
    );
    const names = [...rust.matchAll(/name: "([a-z0-9-]+)"/gu)].map((match) => match[1]);
    expect(RING_KEYS.map((key) => key.name)).toEqual(names);
    for (const circuitType of CIRCUIT_TYPES) expect(names).toContain(circuitType);
    for (const key of RING_KEYS) expect(ringCircuitType(key.circuit)).toBe(key.name);
  });

  it.each(CIRCUIT_TYPES)("encodes %s byte for byte", (circuitType) => {
    expectReencoded(golden(circuitType));
  });

  it("names the deposit key the prover loads and refuses a shape no ring key serves", () => {
    expect(ringProvingKey({ family: "deposit", capacity: 8 })).toEqual({
      name: "custom_ring_deposit_8.key",
      sha256: RING_PROVING_KEY_SHA256S["custom_ring_deposit_8.key"],
    });
    expect(() =>
      ringProvingKey({
        family: "transferConfidential",
        outputs: 3,
        inputs: 40,
        withdrawals: 4,
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }));
  });
});

function recorded<K extends "transferConfidential" | "transferAnonymous">(
  fixture: Fixture,
  kind: K,
): Extract<RingProofRequest, { kind: K }> {
  const found = fixture.ringRequests.find((item) => item.kind === kind);
  if (found === undefined) throw new Error(`no ${kind} request`);
  return found as Extract<RingProofRequest, { kind: K }>;
}

const assets = new AssetRegistry();

async function confidentialRequest(
  options: Readonly<{ policy?: boolean; inProof?: boolean }> = {},
): Promise<ConfidentialTransferProofRequest> {
  const signing = SigningKey.generate();
  const sender = ShieldedKeypair.fromKeypair(signing);
  const fixture = await ringFixture(
    options.policy === true ? { table: buildRuleTable({ rules: [] }), records: [] } : {},
  );
  const transfer = new ConfidentialTransfer(
    sender.shieldedAddress(),
    [noteInput(sender, 1_000n, fixture.ringProgramId)],
    fixture.authority,
  );
  transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 400n);
  const rail = CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: walletKeys(sender),
    transfer,
    assets,
  });
  await (
    options.inProof === true ? rail.withInProofOwner(signingKeySpendSigner(signing)) : rail
  ).prove(fixture.client);
  return recorded(fixture, "transferConfidential");
}

async function anonymousRequest(
  options: Readonly<{ entry?: boolean; policy?: boolean }> = {},
): Promise<AnonymousTransferProofRequest> {
  const signing = SigningKey.generate();
  const sender = ShieldedKeypair.fromKeypair(signing);
  const bob = ShieldedKeypair.generate();
  const fixture = await ringFixture({
    mode: "anonymous",
    ...(options.policy === true ? { table: buildRuleTable({ rules: [] }), records: [] } : {}),
  });
  fixture.enroll(sender.shieldedAddress());
  fixture.enroll(bob.shieldedAddress());
  const transfer = new ConfidentialTransfer(
    sender.shieldedAddress(),
    [noteInput(sender, 1_000n, options.entry === true ? undefined : fixture.ringProgramId)],
    fixture.authority,
  );
  await CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: walletKeys(sender),
    transfer,
    assets,
  })
    .withAnonymousSigner(signingKeySpendSigner(signing))
    .withPayment({
      to: new RingAddress({
        recipient: bob.shieldedAddress(),
        ringProgramId: fixture.ringProgramId,
        listSalt: new Uint8Array(32).fill(1) as Bytes32,
      }),
      asset: SOL_MINT,
      amount: 400n,
      reply: null,
    })
    .prove(fixture.client);
  return recorded(fixture, "transferAnonymous");
}

const GO_PARAMS = readFileSync(
  new URL("../../../../prover/ring/params.go", import.meta.url),
  "utf8",
);

/** The JSON keys of a Go struct in declaration order, embedded structs promoted. */
function goKeys(name: string): readonly string[] {
  const body = new RegExp(`type ${name} struct \\{([\\s\\S]*?)\\n\\}`, "u").exec(GO_PARAMS)?.[1];
  if (body === undefined) throw new Error(`no Go struct ${name}`);
  return body.split("\n").flatMap((line) => {
    if (line.trim().startsWith("//")) return [];
    const tag = /json:"([A-Za-z0-9]+)/u.exec(line)?.[1];
    if (tag !== undefined) return [tag];
    const embedded = /^\s*([A-Z]\w+)\s*$/u.exec(line)?.[1];
    return embedded === undefined ? [] : goKeys(embedded);
  });
}

const CONFIDENTIAL = await confidentialRequest();
const ANONYMOUS = await anonymousRequest();
const ENTRY = await anonymousRequest({ entry: true });

describe("ring prover requests of the rails", () => {
  it("sends the keys of the Go params in declaration order", () => {
    expect(Object.keys(ringProofRequestBody(CONFIDENTIAL))).toEqual(
      goKeys("ConfidentialTransferParams"),
    );
    const anonymous = goKeys("AnonymousTransferParams");
    expect(Object.keys(ringProofRequestBody(ENTRY))).toEqual(anonymous);
    expect(Object.keys(ringProofRequestBody(ANONYMOUS))).toEqual(
      anonymous.filter((key) => key !== "senderKey"),
    );
    const keysOfSlot = (request: RingProofRequest) =>
      Object.keys(record(list(ringProofRequestBody(request)["outputs"])[0]));
    expect(keysOfSlot(CONFIDENTIAL)).toEqual(goKeys("DeliveredOutput"));
    expect(keysOfSlot(ANONYMOUS)).toEqual(goKeys("AnonymousOutput"));
  });

  it("encodes the full u64 withdrawal range exactly and rejects overflow", () => {
    const [leg, ...rest] = CONFIDENTIAL.withdrawals;
    if (leg === undefined) throw new Error("request without a withdrawal slot");
    const body = ringProofRequestBody({
      ...CONFIDENTIAL,
      withdrawals: [{ ...leg, amount: 0xffff_ffff_ffff_ffffn }, ...rest],
    });
    expect((body["withdrawals"] as { amount: string }[])[0]?.amount).toBe(
      "0x" + "00".repeat(24) + "ff".repeat(8),
    );
    for (const amount of [-1n, 1n << 64n])
      expect(() =>
        ringProofRequestBody({
          ...CONFIDENTIAL,
          withdrawals: [{ ...leg, amount }, ...rest],
        }),
      ).toThrow();
  });

  it("refuses a request no key serves or the strict decoder would refuse", () => {
    const base = CONFIDENTIAL;
    const [first, ...rest] = base.outputs;
    if (first === undefined) throw new Error("no delivered output");
    expect(() => ringProofRequestBody({ ...base, outputs: [...base.outputs, first] })).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
    );
    const modulus = Uint8Array.from(
      Buffer.from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "hex"),
    ) as Bytes32;
    expect(() => ringProofRequestBody({ ...base, firstNullifier: modulus })).toThrow(
      expect.objectContaining({
        code: "CLIENT_INVALID_FIELD",
        details: { field: "firstNullifier" },
      }),
    );
    expect(() =>
      ringProofRequestBody({
        ...base,
        outputs: [{ ...first, body: first.body.slice(1) }, ...rest],
      }),
    ).toThrow(
      expect.objectContaining({
        code: "CLIENT_INVALID_LENGTH",
        details: {
          field: "outputs[0].body",
          expected: first.body.length,
          actual: first.body.length - 1,
        },
      }),
    );
    const unknown = { ...base };
    Reflect.set(unknown, "kind", "transferConfidentialV2");
    const loose = { ...base };
    Reflect.set(loose, "outputs", { length: base.outputs.length });
    for (const malformed of [unknown, loose]) {
      expect(() => ringProofRequestBody(malformed)).toThrow(
        expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
      );
      expect(() => ringRequestKey(malformed)).toThrow(
        expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
      );
    }
  });

  it("sends the sender key on the entry key alone", () => {
    expect(ringProofRequestBody(ANONYMOUS)).not.toHaveProperty("senderKey");
    expect(ringProofRequestBody(ENTRY)).toHaveProperty("senderKey");
    const { senderKey, ...keyless } = ENTRY;
    if (senderKey === undefined) throw new Error("entry request without its sender key");
    for (const refused of [{ ...ANONYMOUS, senderKey }, keyless])
      expect(() => ringProofRequestBody(refused)).toThrow(
        expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }),
      );
  });

  it("reads every body field back and rebuilds each rail's statement from the request", async () => {
    for (const typed of [
      CONFIDENTIAL,
      await confidentialRequest({ policy: true }),
      await confidentialRequest({ inProof: true }),
    ]) {
      expectReencoded(JSON.parse(JSON.stringify(ringProofRequestBody(typed))));
      checkConfidentialStatement(typed);
    }
    for (const typed of [ANONYMOUS, ENTRY, await anonymousRequest({ policy: true })]) {
      expectReencoded(JSON.parse(JSON.stringify(ringProofRequestBody(typed))));
      checkAnonymousStatement(typed);
    }
  });
});

// Go solves every Rust fixture, a TS body equal to it assigns the same witness.
describe("ring prover request encoding against the Rust fixtures", () => {
  it("finds a Rust transfer fixture", () => {
    expect(RUST_TRANSFER_FIXTURES.length).toBeGreaterThan(0);
  });

  it.each(RUST_TRANSFER_FIXTURES)("encodes %s byte for byte", (name) => {
    expectReencoded(record(JSON.parse(readFileSync(new URL(name, RUST_FIXTURES), "utf8"))));
  });
});

describe.runIf(HAS_GOLDENS)("ring statements rebuilt from the Go goldens", () => {
  it("rebuilds the register key statement and its sealed key", () => {
    const typed = request(golden("custom-ring-register-key"));
    if (typed.kind !== "registerKey") throw new Error("register key golden");
    expect(typed.nullifierSecret[0]).toBe(0);
    const key = NullifierKey.fromSecret(typed.nullifierSecret.slice(1) as Bytes31);
    const ephemeral = X25519Keypair.fromBytes(typed.ephSk);
    try {
      const envelope = sealNullifierKeyWith(
        ephemeral,
        key,
        X25519PublicKey.fromBytes(tagged(typed.auditorPk)),
      );
      const statement = {
        ringId: typed.ringId,
        member: typed.member,
        nullifierPk: envelope.nullifierPublicKey,
        listTag: field(golden("custom-ring-register-key")["listTag"]),
        auditorPubkey: tagged(typed.auditorPk),
        ephU: envelope.sealed.ephemeralPublicKey.u(),
        ciphertext: envelope.sealed.ciphertext,
      };
      expect(hex(registerKeyStatementHash(statement))).toBe(hex(typed.publicInputHash));
    } finally {
      ephemeral.destroy();
      key.destroy();
    }
  });

  it.each(["custom-ring-apply-records-1", "custom-ring-apply-records-16"])(
    "replays %s to the golden root, index, chain and statement",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "applyRecords") throw new Error("apply golden");
      const replayed = replayRecordWrites({
        oldRoot: typed.oldRoot,
        oldNextIndex: typed.oldNextIndex,
        chainStart: typed.chainStart,
        writes: typed.writes,
      });
      expect(hex(replayed.newRoot)).toBe(hex(typed.newRoot));
      expect(replayed.newNextIndex).toBe(typed.newNextIndex);
      expect(hex(replayed.chainEnd)).toBe(hex(typed.chainEnd));
      expect(hex(applyRecordsStatementHash(applyRecordsStatement(replayed)))).toBe(
        hex(typed.publicInputHash),
      );
    },
  );

  it.each(CIRCUIT_TYPES.filter((name) => name.startsWith("custom-ring-transfer-confidential-")))(
    "rebuilds %s from tx_sk, every recipient key and its registry openings",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "transferConfidential") throw new Error("confidential golden");
      checkConfidentialStatement(typed);
    },
  );

  it.each(CIRCUIT_TYPES.filter((name) => name.startsWith("custom-ring-transfer-anonymous-")))(
    "rebuilds %s with its owner keys, its spent inputs and its registry openings",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "transferAnonymous") throw new Error("anonymous golden");
      checkAnonymousStatement(typed);
    },
  );
});

function checkConfidentialStatement(typed: ConfidentialTransferProofRequest): void {
  const { keyEscrow } = typed.layout;
  const slots = typed.outputs.slice(0, typed.outputCount);
  const layout: AuditStreamLayout = {
    key: { kind: "confidential", class: typed.inputs.length },
    keyEscrow,
    inputs: typed.inputCount,
    capacity: typed.outputs.length,
    outputs: typed.outputCount,
    exits: exitsOf(slots),
    change: 0n,
  };
  const outputs = slots.map((slot, i): DeliveredOutputOpening => {
    const opened = slot.output;
    if (!isUtxo(opened)) return { kind: "body" };
    const nullifierPk = keyEscrow ? undefined : opened.nullifierPk;
    expect(hex(blindingOf(typed, i))).toBe(hex(opened.blinding));
    if (!isRingOutput(opened)) {
      return {
        kind: "exit",
        nullifierPk,
        asset: opened.asset,
        amount: amountOf(opened.amount),
      };
    }
    const secret = slotSecret(typed, slot.recipientKey, i);
    expect(
      hex(
        sealDeliveredBody(secret, {
          blinding: opened.blinding,
          amount: amountOf(opened.amount),
          ownerKey: slot.ownerKey,
          nullifierPk,
        }),
      ),
    ).toBe(hex(slot.body));
    expect(hex(opened.ringDataHash)).toBe(hex(ZERO));
    return { kind: "body" };
  });
  const firstSigner = typed.signerCount > 0 ? typed.signers[0] : undefined;
  checkPolicySection(typed, firstSigner ?? typed.senderPkHash);
  const stream = requestStream(typed, {
    kind: "delivered",
    layout,
    inputs: inputCommitmentsOf(typed.inputs.slice(0, typed.inputCount)),
    outputs,
  });
  const hash = transferStatementHash({
    ...statementTail(typed),
    head: auditHead(typed, stream),
    family: {
      kind: "confidential",
      inProof: typed.inProof,
      delegate: typed.delegate,
      sender: typed.sender,
      recipients: typed.recipients,
    },
    outputs: slots.map((slot) =>
      isUtxo(slot.output) && !isRingOutput(slot.output)
        ? exitOutput(openingHash(slot.output))
        : {
            kind: "delivered",
            hash: openingHash(slot.output),
            u: slot.recipientKey,
            body: slot.body,
          },
    ),
    outputCiphertexts: slotCiphertexts(layout, stream.records, (slot) => typed.outputs[slot]?.body),
  });
  expect(hex(hash)).toBe(hex(typed.publicInputHash));
}

function checkAnonymousStatement(typed: AnonymousTransferProofRequest): void {
  const spent = typed.inputs.slice(0, typed.inputCount);
  const [first] = spent;
  if (first === undefined) throw new Error("anonymous request without an input");
  const senderPkHash = first.ownerPkHash;
  expect(typed.senderKey === undefined).toBe(!typed.layout.fullOpenings);
  if (typed.senderKey !== undefined)
    expect(hex(solanaOwnerIdentity(typed.senderKey))).toBe(hex(senderPkHash));
  const slots = typed.outputs.slice(0, typed.outputCount);
  const changes = slots.map(
    (slot) =>
      isRingOutput(slot.output) &&
      hex(slot.output.ownerPkHash) === hex(senderPkHash) &&
      hex(slot.output.nullifierPk) === hex(typed.senderNullifierPk) &&
      hex(slot.recipientKey) === hex(typed.senderViewingKey),
  );
  const outputs = slots.map((slot, i): AnonymousOutputOpening => {
    const opened = slot.output;
    if (!isUtxo(opened)) return { kind: "dummy" };
    expect(hex(blindingOf(typed, i))).toBe(hex(opened.blinding));
    if (!isRingOutput(opened)) {
      return {
        kind: "exit",
        nullifierPk: opened.nullifierPk,
        asset: opened.asset,
        amount: amountOf(opened.amount),
      };
    }
    // A ring output commits to no ring data, its owner the identity of its disclosed key.
    expect(hex(opened.ringDataHash)).toBe(hex(ZERO));
    expect(hex(solanaOwnerIdentity(slot.ownerKey))).toBe(hex(opened.ownerPkHash));
    return {
      kind: "ring",
      nullifierPk: opened.nullifierPk,
      ownerKey: slot.ownerKey,
      asset: opened.asset,
      amount: amountOf(opened.amount),
    };
  });
  expect(
    hex(
      privateTxHash({
        inputHashes: typed.inputs.map((slot) => (isUtxo(slot) ? openingHash(slot) : ZERO)),
        outputHashes: typed.outputs.map((slot) =>
          isUtxo(slot.output) ? openingHash(slot.output) : ZERO,
        ),
        blinding: typed.privateTxBlinding,
      }),
    ),
  ).toBe(hex(typed.privateTxHash));
  checkPolicySection(typed, senderPkHash);
  checkSenderAddress(typed, senderPkHash);
  const { fullOpenings } = typed.layout;
  const layout: AuditStreamLayout = {
    key: {
      kind: fullOpenings ? "entry" : "commitment",
      class: typed.inputs.length,
    },
    keyEscrow: false,
    inputs: typed.inputCount,
    capacity: typed.outputs.length,
    outputs: typed.outputCount,
    exits: exitsOf(slots),
    change: changes.reduce(
      (bits, change, slot) => (change ? bits | (1n << BigInt(slot)) : bits),
      0n,
    ),
  };
  const stream = requestStream(typed, {
    kind: "anonymous",
    layout,
    outputs,
    inputs:
      typed.senderKey === undefined
        ? inputCommitmentsOf(spent)
        : {
            kind: "openings",
            senderKey: typed.senderKey,
            senderNullifierPk: first.nullifierPk,
            inputs: spent.map((slot) =>
              isUtxo(slot)
                ? {
                    hash: openingHash(slot),
                    asset: slot.asset,
                    amount: amountOf(slot.amount),
                    blinding: slot.blinding,
                  }
                : undefined,
            ),
          },
  });
  // A digest alone cannot rebuild a reply region, every request here names no reply.
  expect(hex(typed.replyDigest)).toBe(hex(ZERO));
  const hash = transferStatementHash({
    ...statementTail(typed),
    head: auditHead(typed, stream),
    family: {
      kind: "anonymous",
      partyIdentities: typed.partyIdentities,
      senderBundle: rebuiltBundle(typed, slots, changes),
      senderBundleTag: typed.senderBundleTag,
    },
    outputs: slots.map((slot, i): RingOutput => {
      const hash = openingHash(slot.output);
      if (isUtxo(slot.output) && !isRingOutput(slot.output)) return exitOutput(hash);
      return changes[i] === true
        ? { kind: "change", hash, tag: ZERO }
        : { kind: "anonymous", hash, tag: slot.tag, body: slot.body };
    }),
    outputCiphertexts: stream.records,
  });
  expect(hex(hash)).toBe(hex(typed.publicInputHash));
}

/** One list feeds the evidence and the transaction binding, a dummy reads zero. */
function inputCommitmentsOf(spent: readonly RingSlotOpening[]) {
  return {
    kind: "commitments" as const,
    hashes: spent.map((slot) => (isUtxo(slot) ? openingHash(slot) : undefined)),
  };
}

/** The scheme 12 ciphertext the circuit seals from the request's slots at index `m`. */
function rebuiltBundle(
  typed: AnonymousTransferProofRequest,
  slots: readonly AnonymousSlotProofInputs[],
  changes: readonly boolean[],
): Uint8Array {
  const blindings = new OutputBlindings(
    typed.firstNullifier,
    ringBlindingSeed(typed.txViewingSk, typed.salt),
  );
  const [first, second] = slots;
  return sealSenderBundle(slotSecret(typed, typed.senderViewingKey, slots.length), {
    mint:
      changes[0] === true && first !== undefined ? mintOf(first) : encodeBase58(new Uint8Array(32)),
    amount: changes[0] === true && first !== undefined ? amountOf(first.output.amount) : 0n,
    solAmount: changes[1] === true && second !== undefined ? amountOf(second.output.amount) : 0n,
    outputSeed: blindings.outputSeed(),
    recipientKeys: slots.map((slot, i) => (changes[i] === true ? ZERO : slot.recipientKey)),
  });
}

/** `mint[0..31]` right aligned then `mint[31]`, the `hash_bytes_32` halves. */
function mintOf(slot: AnonymousSlotProofInputs) {
  const [head, tail] = slot.mintChunks;
  if (head === undefined || tail === undefined) throw new Error("slot without mint chunks");
  return encodeBase58(Uint8Array.of(...head.subarray(1), tail[31] ?? 0));
}

/** The sender's own row binds the address the proof encrypts change and the bundle to. */
function checkSenderAddress(typed: AnonymousTransferProofRequest, sender: Bytes32): void {
  const row = typed.senderEntries[0]?.own ?? -1;
  expect(typed.ownPool.subjects[row]?.member).toEqual(sender);
  const reads = poolReads(typed.ownPool, typed.ownRoot);
  expect(hex(reads[row]?.record()?.addressHash ?? ZERO)).toBe(
    hex(
      addressRecordHash({
        member: sender,
        ringId: typed.ringId,
        nullifierPk: typed.senderNullifierPk,
        viewingU: typed.senderViewingKey,
        addressRevision: typed.senderAddressRevision,
      }),
    ),
  );
}

/** The statement values the request binds beside the head, the family and the slots. */
function statementTail(
  typed: ConfidentialTransferProofRequest | AnonymousTransferProofRequest,
): Omit<
  Parameters<typeof transferStatementHash>[0],
  "head" | "family" | "outputs" | "outputCiphertexts"
> {
  return {
    exempt: typed.exempt,
    approvalRequired: typed.approvalRequired,
    capacity: typed.recipients.length,
    signers: signerBinding(typed.signers.slice(0, typed.signerCount), typed.inputs.length),
    inputCount: typed.inputCount,
    privateTxHash: typed.privateTxHash,
    roots: {
      policyHash: typed.policyHash,
      ownRoot: typed.ownRoot,
      curatorRoot: typed.curatorRoot,
    },
    publicAssets: typed.publicAssets,
    publicAmounts: typed.publicAmounts,
    publicGross: typed.publicGross,
    withdrawalHash: typed.withdrawalHash,
  };
}

/** A screened request opens the sender and every live slot in pools under the bound roots, an unscreened one binds no root. */
function checkPolicySection(typed: RingProofRequest & PolicyProofInputs, sender: Bytes32): void {
  if (typed.kind !== "transferConfidential" && typed.kind !== "transferAnonymous")
    throw new Error("transfer golden");
  expect(typed.withdrawalHash).toEqual(
    policyWithdrawalHash(typed.withdrawals.slice(0, typed.withdrawalCount)),
  );
  if (isZero(typed.policyHash)) return;
  const table = buildRuleTable({
    rules: typed.rules.slice(0, typed.policyLen).map(decodeRule),
  });
  expect(hex(policyTableHash(table, typed.sources))).toBe(hex(typed.policyHash));
  const ownReads = poolReads(typed.ownPool, typed.ownRoot);
  if (!isZero(typed.curatorRoot)) poolReads(typed.curatorPool, typed.curatorRoot);
  const own = (entry: PolicySubjectEntry | undefined, member: Bytes32) => {
    const index = entry?.own ?? -1;
    expect(typed.ownPool.subjects[index]?.member).toEqual(member);
    return ownReads[index]?.record();
  };
  own(typed.senderEntries[0], sender);
  typed.outputs.forEach((slot, i) => {
    const output = slot.output;
    if (!isUtxo(output)) return;
    const owner = own(typed.ownerEntries[i], output.ownerPkHash);
    own(typed.assetEntries[i], output.asset);
    const ctHash = typed.ctHashes[i];
    // The escrow key binds the ciphertext hash under key escrow alone, the gate off leaves it unread.
    if (typed.layout.keyEscrow && ctHash !== undefined && owner !== undefined)
      expect(hex(owner.escrowKey)).toBe(hex(poseidon([output.nullifierPk, ctHash])));
  });
}

function expectReencoded(item: Json): void {
  const typed = request(item);
  const body = ringProofRequestBody(typed);
  expect(body).toEqual(item);
  expect(JSON.stringify(body)).toBe(JSON.stringify(item));
  expect(ringCircuitType(ringProofCircuit(typed))).toBe(text(item["circuitType"]));
}

/** Every subject's read, the padded pool verified as the indexer would serve it. */
function poolReads(pool: RecordPool, root: Bytes32): readonly MemberOpeningRead[] {
  return verifyRecordPool(
    {
      records: pool.records.map((record, i) => ({
        record,
        path: pool.paths[i] as QuadPath,
      })),
      canopy: pool.canopy,
      subjects: pool.subjects.map((subject) => subject.recordIndex),
    },
    root,
    pool.subjects.map((subject) => subject.member),
    pool.records.length,
  );
}

/** CRDS under `X25519(tx_sk, u)`, the secret the recipient rebuilds from its own key. */
function slotSecret(
  envelope: AuditEnvelopeProofInputs,
  recipientKey: Bytes32,
  outputIndex: number,
): Bytes32 {
  const recipient = X25519PublicKey.fromBytes(tagged(recipientKey));
  return deliveredSlotSecret({
    agreement: agreement(envelope.txViewingSk, recipient),
    txViewingKey: publicKeyOf(envelope.txViewingSk),
    recipientViewingKey: recipient,
    salt: envelope.salt,
    outputIndex,
    firstNullifier: envelope.firstNullifier,
  });
}

function mintSettings(packed: unknown, withdrawal: unknown, limits: unknown) {
  const mask = (1n << 64n) - 1n;
  const amounts = (fieldValue: unknown) => {
    const value = amountOf(field(fieldValue));
    return [(value >> 128n) & mask, (value >> 64n) & mask, value & mask] as const;
  };
  const [threshold, cap, cosignAbove] = amounts(packed);
  // The last field holds two amounts below an unused top one.
  const [
    senderCap,
    senderWindowSlots,
    volumeCap,
    volumeWindowSlots,
    depositCap,
    depositWindowSlots,
    ,
    withdrawalCap,
    withdrawalWindowSlots,
  ] = list(limits).flatMap(amounts);
  return {
    threshold,
    cap,
    cosignAbove,
    withdrawalThreshold: amountOf(field(withdrawal)),
    limits: {
      senderCap: senderCap!,
      senderWindowSlots: senderWindowSlots!,
      volumeCap: volumeCap!,
      volumeWindowSlots: volumeWindowSlots!,
      depositCap: depositCap!,
      depositWindowSlots: depositWindowSlots!,
      withdrawalCap: withdrawalCap!,
      withdrawalWindowSlots: withdrawalWindowSlots!,
    },
  };
}
