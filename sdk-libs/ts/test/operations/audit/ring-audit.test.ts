import { getAddressEncoder, type Address, type Signature } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import anonymous from "../../../../../test-vectors/audit/audit-disclosure-anonymous.json" with { type: "json" };
import delivered from "../../../../../test-vectors/audit/audit-disclosure-delivered.json" with { type: "json" };
import {
  ZERO_32,
  ZERO_NULLIFIER_PK,
  encodeBase58,
  treeAddress,
  mergeOutputBlinding,
  mergeOutputKey,
  equalBytes,
  solanaOwnerIdentity,
  hashBytes,
  addressBytes,
  poseidon,
  encodeMergeOutputData,
  encryptMergeOutput,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import { SHIELDED_POOL_PROGRAM_ID, StateDiscriminator } from "@heliuslabs/zolana/interface";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import {
  ShieldedKeypair,
  ViewingKey,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import { AssetRegistry, SOL_MINT, Utxo, ownerUtxoHash } from "@heliuslabs/zolana/transaction";
import {
  encodeRingOutput,
  readRingOutput,
  RingScheme,
  sealDeliveredBody,
} from "../../../src/protocol/transaction/output.js";
import type { IndexedShieldedTransaction, OutputSlot } from "@heliuslabs/zolana/transaction";
import { CUSTOM_RING_PROOF_LENGTH } from "../../../src/protocol/proof/custom-ring-proof.js";
import {
  deliveredBodyLen,
  firstRecordCounter,
  maxEvidenceBlocks,
  recordBlocks,
  recordRegion,
  recordSlots,
  STREAM_FIRST_COUNTER,
  transferAuditKey,
  type AuditStreamLayout,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";
import {
  AUDIT_ENC_INFO,
  AuditSchedule,
  auditSharedSecret,
  auditorMessageData,
  openTransactionViewingSecret,
  parseAuditorMessage,
  sealAuditorStream,
  symmetricAuditApply,
} from "../../../src/crypto/audit/audit.js";
import { ciphertextDigest } from "../../../src/protocol/proof/statement.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../../src/crypto/derivation/blinding.js";
import { dummyUtxoHash } from "../../../src/protocol/membership/utxo-hash.js";
import { txKeySlotSecret } from "../../../src/crypto/derivation/ring-stream.js";
import {
  disclosurePlaintext,
  openAuditEnvelope,
  openRingDisclosure,
  sealRingDisclosure,
  type RingDisclosure,
} from "../../../src/crypto/audit/ring-disclosure.js";
import {
  KnownUtxoIndex,
  auditRing,
  auditRingTransaction,
  auditedUtxos,
  hasUnknownAssets,
  knownUtxoHash,
  openRingTransfer,
  type AuditedInput,
  type AuditedUtxo,
  type EscrowedKeys,
  type KnownUtxo,
  type KnownUtxos,
  type OutputOpening,
} from "../../../src/operations/audit/audit.js";
import { sealRingDepositOpenings } from "../../../src/proof/deposit-audit.js";
import { sealRingMergeDisclosure } from "../../../src/crypto/audit/merge-disclosure.js";
import {
  ConfirmedDeposit,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../../../src/protocol/transaction/origin.js";
import { RingError } from "../../../src/protocol/error.js";
import { recoverRingMemberNotes } from "../../../src/operations/workflow/recover.js";
import { ringAuditReader } from "../../helpers/clients.js";
import { transactionsPage } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import {
  confirmedDepositTransaction,
  ringDepositPayload,
} from "../../helpers/confirmed-deposits.js";
import { CONFIDENTIAL_DATA_FREE_BODY_LEN } from "../../../src/protocol/transaction/output.js";
import { RECIPIENT_BODY_LEN } from "../../../src/protocol/codec/anonymous-delivery.js";
import { x25519FromU } from "../../../src/crypto/keys/x25519.js";
import { transactionItems } from "../../../../../zolana/sdk-libs/ts/test/helpers/pages.js";
import { historyCursor } from "../../../src/rpc/history.js";

await initializePoseidon();

function hex<T extends Uint8Array>(value: string, length?: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (length !== undefined && decoded.length !== length)
    throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function field(value: string): Bytes32 {
  return hex<Bytes32>(value, 32);
}

type Layout = "delivered" | "anonymous";
type Vector = (typeof delivered.cases)[number] | (typeof anonymous.cases)[number];
type VectorSlot = Vector["slots"][number];
type VectorEntry = Readonly<{
  layout: Layout;
  bound: AuditStreamLayout;
  vector: Vector;
}>;

/** Change moves no stream region, the auditor reads every anonymous record alike. */
function bound(layout: Layout, vector: Vector): AuditStreamLayout {
  const outputs = vector.slots.length;
  const exits = vector.slots.reduce(
    (bits, slot, index) => (slot.kind === "exit" ? bits | (1n << BigInt(index)) : bits),
    0n,
  );
  const inputs = vector.input_count;
  const key = transferAuditKey({
    rail: layout === "delivered" ? "confidential" : "anonymous",
    inputs,
    capacity: outputs,
    spendsDefaultRing: "key" in vector && vector.key === "entry",
  });
  if (key === undefined) throw new Error("no key at the vector's capacity");
  return {
    key,
    keyEscrow: (vector.layout & 2) !== 0,
    inputs,
    capacity: outputs,
    outputs,
    exits,
    change: 0n,
  };
}

const VECTORS: readonly VectorEntry[] = [
  ...delivered.cases.map((vector) => ({
    layout: "delivered" as const,
    vector,
  })),
  ...anonymous.cases.map((vector) => ({
    layout: "anonymous" as const,
    vector,
  })),
].map((entry) => ({ ...entry, bound: bound(entry.layout, entry.vector) }));

const SIGNATURE = "1".repeat(64) as Signature;
/** A mint no default registry names, the exit of the pair vector settles it. */
const FOREIGN_MINT = encodeBase58(new Uint8Array(32).fill(0x0a));
const OTHER_RING = encodeBase58(new Uint8Array(32).fill(0x0b));

function vectorOf(layout: Layout, name: string): VectorEntry {
  const found = VECTORS.find((entry) => entry.layout === layout && entry.vector.name === name);
  if (found === undefined) throw new Error(`no ${layout} ${name} vector`);
  return found;
}

/** The capacity 2 delivered case with an exit and no escrow, every key published. */
const PAIR = vectorOf("delivered", "pair_exits");
const PAIR_LAYOUT = PAIR.bound;
const PAIR_VECTOR = PAIR.vector;

/** The slot's payload under the scheme its rail expands to, exits under scheme 3. */
function payload(entry: VectorEntryOf, slot: VectorSlot): Uint8Array {
  if (slot.kind === "exit")
    return encodeRingOutput(
      RingScheme.confidential,
      new Uint8Array(CONFIDENTIAL_DATA_FREE_BODY_LEN),
    );
  if (entry.layout === "anonymous")
    return "stream" in slot && slot.stream === "change"
      ? new Uint8Array()
      : encodeRingOutput(
          RingScheme.ringRecipientBody,
          new Uint8Array(RECIPIENT_BODY_LEN).fill(0x5d),
        );
  const { keyEscrow } = bound(entry.layout, entry.vector);
  // A hidden dummy publishes bytes no key opens.
  if (slot.kind === "dummy")
    return encodeRingOutput(
      RingScheme.ringConfidentialDelivered,
      new Uint8Array(deliveredBodyLen(keyEscrow)).fill(0xd0),
    );
  return encodeRingOutput(
    RingScheme.ringConfidentialDelivered,
    sealDeliveredBody(
      field(need("slot_secret" in slot ? slot.slot_secret : undefined, "slot_secret")),
      {
        blinding: field(slot.blinding),
        amount: BigInt(need(slot.amount, "amount")),
        ownerKey: field(need(slot.owner_key, "owner_key")),
        nullifierPk: keyEscrow ? undefined : field(need(slot.nullifier_pk, "nullifier_pk")),
      },
    ),
  );
}

type VectorEntryOf = Readonly<{ layout: Layout; vector: Vector }>;

/** The notes a delivered vector names without listing them, a zero entry reads as a dummy. */
function deliveredEvidence(vector: Vector, count: number): readonly (Bytes32 | undefined)[] {
  return Array.from({ length: count }, (_, index) => {
    const hash = field(
      vector.envelope_plaintext.slice(64 * (index + 1), 64 * (index + 2)).padEnd(64, "0"),
    );
    return hash.some((byte) => byte !== 0) ? hash : undefined;
  });
}

/** The evidence and records of the vector's openings. */
function vectorDisclosure(entry: VectorEntryOf): RingDisclosure {
  const { vector } = entry;
  const layout = bound(entry.layout, vector);
  const exit = (slot: VectorSlot) => ({
    kind: "exit" as const,
    asset: field(need(slot.asset, "asset")),
    amount: BigInt(need(slot.amount, "amount")),
  });
  if (entry.layout === "delivered")
    return {
      kind: "delivered",
      layout,
      inputs: {
        kind: "commitments",
        hashes: deliveredEvidence(vector, layout.inputs),
      },
      outputs: vector.slots.map((slot) =>
        slot.kind === "exit"
          ? {
              ...exit(slot),
              nullifierPk: layout.keyEscrow
                ? undefined
                : field(need(slot.nullifier_pk, "nullifier_pk")),
            }
          : { kind: "body" },
      ),
    };
  if (!("inputs" in vector)) throw new Error("anonymous vector without inputs");
  return {
    kind: "anonymous",
    layout,
    outputs: vector.slots.map((slot) => {
      if (slot.kind === "dummy") return { kind: "dummy" };
      const nullifierPk = field(need(slot.nullifier_pk, "nullifier_pk"));
      return slot.kind === "exit"
        ? { ...exit(slot), nullifierPk }
        : {
            ...exit(slot),
            kind: "ring",
            nullifierPk,
            ownerKey: field(need(slot.owner_key, "owner_key")),
          };
    }),
    inputs:
      vector.key === "entry"
        ? {
            kind: "openings",
            senderKey: field(vector.sender_key),
            senderNullifierPk: field(vector.sender_nullifier_pk),
            inputs: vector.inputs.map((input) => ({
              hash: field(input.commitment),
              asset: field(input.asset),
              amount: BigInt(input.amount),
              blinding: field(input.blinding),
            })),
          }
        : {
            kind: "commitments",
            hashes: vector.inputs.map((input) => field(input.commitment)),
          },
  };
}

/** The nullifier key each owner's escrow record holds, read from the vector's openings. */
function escrowRecords(vector: Vector): EscrowedKeys {
  const keys = new Map(
    vector.slots.flatMap((slot) =>
      slot.kind === "dummy"
        ? []
        : [[need(slot.owner_key, "owner_key"), field(need(slot.nullifier_pk, "nullifier_pk"))]],
    ),
  );
  return {
    nullifierPk: (ownerKey) => keys.get(Buffer.from(ownerKey).toString("hex")),
  };
}

/** The sender's earlier UTXOs an anonymous vector spends. */
function spentUtxos(vector: Vector, assets: AssetRegistry): KnownUtxoIndex {
  const inputs = "inputs" in vector ? vector.inputs : [];
  const sender = "sender_key" in vector ? vector.sender_key : undefined;
  return new KnownUtxoIndex(
    inputs.map((input) => {
      const asset = field(input.asset);
      const mint = assets.addressForField(asset);
      const utxo: KnownUtxo = {
        ownerKey: field(need(sender, "sender_key")),
        owner: {
          kind: "keyed",
          nullifierPk: field(
            need(
              "sender_nullifier_pk" in vector ? vector.sender_nullifier_pk : undefined,
              "sender_nullifier_pk",
            ),
          ),
        },
        asset,
        ...(mint === undefined ? {} : { mint }),
        amount: BigInt(input.amount),
        blinding: field(input.blinding),
        dataHash: new Uint8Array(32) as Bytes32,
        ringDataHash: new Uint8Array(32) as Bytes32,
        treeId: input.input_tree_id,
      };
      return { commitment: field(input.commitment), utxo };
    }),
  );
}

/** The confirmed transfer the vector describes, its tx secret sealed to `auditor`. */
function vectorTransaction(
  entry: Readonly<{ layout: Layout; vector: Vector }>,
  auditor: X25519PublicKey,
): IndexedShieldedTransaction {
  const { vector } = entry;
  const message = auditorMessageData(
    sealRingDisclosure({
      txViewingSecret: field(vector.tx_viewing_sk),
      auditorPublicKey: auditor,
      disclosure: vectorDisclosure(entry),
    }),
    auditor,
  );
  const outputSlots: OutputSlot[] = vector.slots.map((slot, index) => ({
    viewTag: field(slot.owner_tag),
    outputContext: {
      hash: field(slot.output_hash),
      tree: treeAddress(vector.output_tree_id),
      treeId: vector.output_tree_id,
      leafIndex: BigInt(index),
    },
    payload: payload(entry, slot),
  }));
  const nullifiers =
    "inputs" in vector
      ? vector.inputs.map((input) => field(input.nullifier))
      : [field(vector.first_nullifier)];
  return {
    slot: 7n,
    txSignature: SIGNATURE,
    eventIndex: 0,
    txViewingPublicKey: x25519FromU(field(vector.tx_viewing_u)),
    salt: hex<Bytes16>(vector.salt, 16),
    outputSlots,
    messages: [message],
    nullifiers,
    proofless: false,
    ringProgramId: encodeBase58(field(vector.ring_program_id)),
  };
}

/** A vector field every opened slot carries. */
function need<T>(value: T | undefined, name: string): T {
  if (value === undefined) throw new Error(`vector slot without ${name}`);
  return value;
}

/** Every mint the vector's slots hold, the registry a delivered body's asset is matched against. */
function vectorAssets(vector: Vector): AssetRegistry {
  const mints = new Set<string>();
  for (const slot of vector.slots)
    if ("asset_address" in slot && typeof slot.asset_address === "string")
      mints.add(slot.asset_address);
  mints.delete("00".repeat(32));
  return new AssetRegistry(
    [...mints].map((mint, index) => [BigInt(index + 2), encodeBase58(hex(mint, 32))] as const),
  );
}

/** What the auditor must rebuild for `slot`, Rust `OutputOpening`. */
function expectedOpening(layout: Layout, slot: VectorSlot, assets: AssetRegistry): OutputOpening {
  if (slot.kind === "dummy") return { kind: "dummy" };
  const asset = field(need(slot.asset, "asset"));
  const mint = assets.addressForField(asset);
  const utxo: AuditedUtxo = {
    ownerKey: field(need(slot.owner_key, "owner_key")),
    nullifierPk: field(need(slot.nullifier_pk, "nullifier_pk")),
    asset,
    ...(mint === undefined ? {} : { mint }),
    amount: BigInt(need(slot.amount, "amount")),
    blinding: field(slot.blinding),
    dataHash: field(need(slot.data_hash, "data_hash")),
    ringDataHash: field(need(slot.ring_data_hash, "ring_data_hash")),
  };
  if (slot.kind === "exit") return { kind: "exit", utxo };
  if (layout === "anonymous")
    return {
      kind: "ring",
      utxo,
      ownerTag: { kind: "view", tag: field(slot.owner_tag) },
    };
  const recipientU = "recipient_u" in slot ? slot.recipient_u : undefined;
  return {
    kind: "ring",
    utxo,
    ownerTag: { kind: "recipient", u: field(need(recipientU, "recipient_u")) },
  };
}

function audit(
  entry: VectorEntry,
  options: Readonly<{
    auditor?: X25519Keypair;
    assets?: AssetRegistry;
    transaction?: (transaction: IndexedShieldedTransaction) => IndexedShieldedTransaction;
    inputTreeIds?: readonly (number | undefined)[];
    layout?: AuditStreamLayout;
    escrowedKeys?: EscrowedKeys;
    knownUtxos?: KnownUtxos;
  }> = {},
) {
  const auditor = options.auditor ?? X25519Keypair.generate();
  const transaction = vectorTransaction(entry, auditor.publicKey());
  return auditRingTransaction({
    auditor,
    transaction: options.transaction?.(transaction) ?? transaction,
    assets: options.assets ?? vectorAssets(entry.vector),
    layout: options.layout ?? entry.bound,
    ...(options.inputTreeIds === undefined ? {} : { inputTreeIds: options.inputTreeIds }),
    ...(options.escrowedKeys === undefined ? {} : { escrowedKeys: options.escrowedKeys }),
    ...(options.knownUtxos === undefined ? {} : { knownUtxos: options.knownUtxos }),
  });
}

function withSlot(
  index: number,
  change: (slot: OutputSlot) => OutputSlot,
): (transaction: IndexedShieldedTransaction) => IndexedShieldedTransaction {
  return (transaction) => ({
    ...transaction,
    outputSlots: transaction.outputSlots.map((slot, at) => (at === index ? change(slot) : slot)),
  });
}

function ringError(code: string, details?: Readonly<Record<string, unknown>>): unknown {
  return expect.objectContaining({
    code,
    ...(details === undefined ? {} : { details: expect.objectContaining(details) }),
  });
}

describe("auditor envelope", () => {
  // Pinned by prover/ringtest/ringaudit/kdf_test.go and sdk-libs/client/src/crypto/encryption/mod.rs.
  const auditor = X25519Keypair.fromBytes(
    hex("01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c", 32),
  );
  const ephemeralPublicKey = X25519PublicKey.fromBytes(
    hex<Bytes33>("048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966", 33),
  );

  it("matches the circuit vector", () => {
    expect(auditor.publicKey().toBytes()).toEqual(
      hex("04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a", 33),
    );
    const dh = auditor.ecdh(ephemeralPublicKey);
    expect(dh).toEqual(field("464b33b122dc1346a6012199742d7e14b2ee6436589c454a579fdda24feec92c"));
    expect(auditSharedSecret(dh, ephemeralPublicKey, auditor.publicKey())).toEqual(
      field("2590b2b949a2f87b9201e4d065167ea9282c4bd06a32e888e24e33c5bddae54f"),
    );
    const envelope = field("da94f616e95702bdea89178dd9c4547393ebce9d47e67d0cac1533f13b678b90");
    expect(openTransactionViewingSecret(auditor, { ephemeralPublicKey, envelope })).toEqual(
      field("001013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f4e"),
    );
  });
});

describe("openAuditEnvelope", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each(VECTORS)("returns the key and disclosure of $layout $vector.name", (entry) => {
    const auditor = X25519Keypair.generate();
    const transaction = vectorTransaction(entry, auditor.publicKey());
    const layout = entry.bound;
    const message = parseAuditorMessage(transaction.messages.at(-1)!.data, layout);
    const opened = openAuditEnvelope(auditor, { layout, message });
    expect(opened.txViewingKey.secretBytes()).toEqual(field(entry.vector.tx_viewing_sk));
    expect(opened.disclosure()).toEqual(openRingDisclosure(auditor, { layout, message }));
    opened.destroy();
    expect(() => opened.txViewingKey.secretBytes()).toThrow();
  });

  it.each(VECTORS)("audits $layout $vector.name under one agreement and schedule", (entry) => {
    const auditor = X25519Keypair.generate();
    const transaction = vectorTransaction(entry, auditor.publicKey());
    const ecdh = vi.spyOn(auditor, "ecdh");
    const derive = vi.spyOn(AuditSchedule, "derive");
    auditRingTransaction({
      auditor,
      transaction,
      assets: vectorAssets(entry.vector),
      layout: entry.bound,
    });
    expect(ecdh).toHaveBeenCalledTimes(1);
    expect(derive.mock.calls.filter(([, label]) => label === AUDIT_ENC_INFO)).toHaveLength(1);
  });

  it("refuses a forged published key before the evidence decodes", () => {
    const auditor = X25519Keypair.generate();
    const entry = vectorOf("anonymous", "commitment");
    const plaintext = disclosurePlaintext(vectorDisclosure(entry));
    const sealed = sealAuditorStream({
      auditorPublicKey: auditor.publicKey(),
      envelope: Uint8Array.of(
        ...field(entry.vector.tx_viewing_sk),
        ...new Uint8Array(plaintext.evidence.length).fill(0xff),
      ),
      records: recordSlots(entry.bound).map((slot, index) => ({
        counter: recordRegion(entry.bound, slot).startCounter,
        bytes: plaintext.records[index]!,
      })),
    });
    const forged = (transaction: IndexedShieldedTransaction) => ({
      ...transaction,
      messages: [auditorMessageData(sealed, auditor.publicKey())],
    });
    expect(() => audit(entry, { auditor, transaction: forged })).toThrow(
      expect.objectContaining({ code: "KEYPAIR_DISCLOSURE_FIELD" }),
    );
    expect(() =>
      audit(entry, {
        auditor,
        transaction: (transaction) => ({
          ...forged(transaction),
          txViewingPublicKey: X25519Keypair.generate().publicKey(),
        }),
      }),
    ).toThrow(ringError("RING_AUDIT_KEY_MISMATCH"));
    sealed.ephemeralSecret.fill(0);
  });
});

describe("OpenedRingTransfer.withAssets", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function withInputMints(vector: Vector): AssetRegistry {
    const assets = vectorAssets(vector);
    const spent = "inputs" in vector ? vector.inputs : [];
    spent.forEach((input, index) => {
      if (assets.addressForField(field(input.asset)) === undefined)
        assets.register(BigInt(index + 100), encodeBase58(field(input.asset_address)));
    });
    return assets;
  }

  it("names the mint of a known note stored without one", () => {
    const auditor = X25519Keypair.generate();
    const entry = vectorOf("anonymous", "commitment");
    const known = spentUtxos(entry.vector, new AssetRegistry());
    const opened = openRingTransfer({
      auditor,
      transaction: vectorTransaction(entry, auditor.publicKey()),
      assets: new AssetRegistry(),
      layout: entry.bound,
      knownUtxos: known,
    });
    const assets = withInputMints(entry.vector);
    const named = (inputs: readonly AuditedInput[]) =>
      inputs.flatMap(({ opening }) =>
        opening.kind === "opened" && opening.mint !== undefined ? [opening.mint] : [],
      );
    expect(named(opened.withAssets(assets).inputs).length).toBeGreaterThan(
      named(opened.audited.inputs).length,
    );
    expect(hasUnknownAssets(opened.withAssets(assets))).toBe(false);
  });

  describe.each([
    ["without", (): EscrowedKeys | undefined => undefined],
    ["with", (vector: Vector) => escrowRecords(vector)],
  ] as const)("%s escrow records", (_, escrow) => {
    it.each(VECTORS)("matches a new audit of $layout $vector.name", (entry) => {
      const auditor = X25519Keypair.generate();
      const escrowedKeys = escrow(entry.vector);
      const fields = {
        auditor,
        transaction: vectorTransaction(entry, auditor.publicKey()),
        layout: entry.bound,
        knownUtxos: spentUtxos(entry.vector, withInputMints(entry.vector)),
        ...(escrowedKeys === undefined ? {} : { escrowedKeys }),
      };
      const opened = openRingTransfer({
        ...fields,
        assets: new AssetRegistry(),
      });
      const assets = withInputMints(entry.vector);
      const ecdh = vi.spyOn(auditor, "ecdh");
      const resolved = opened.withAssets(assets);
      expect(ecdh).not.toHaveBeenCalled();
      expect(resolved).toEqual(auditRingTransaction({ ...fields, assets }));
    });
  });

  it("opens a delivered slot a registered mint rebuilds and keeps published order", () => {
    const auditor = X25519Keypair.generate();
    const entry = vectorOf("delivered", "dense");
    const opened = openRingTransfer({
      auditor,
      transaction: vectorTransaction(entry, auditor.publicKey()),
      assets: new AssetRegistry(),
      layout: entry.bound,
    });
    const closed = opened.audited.payloadErrors.map(({ slotIndex }) => slotIndex);
    expect(closed.length).toBeGreaterThan(0);
    const resolved = opened.withAssets(vectorAssets(entry.vector));
    expect(resolved.payloadErrors).toEqual([]);
    expect(resolved.outputs.map(({ slotIndex }) => slotIndex)).toEqual(
      entry.vector.slots.map((_, index) => index),
    );
    expect(opened.withAssets(new AssetRegistry())).toEqual(opened.audited);
  });
});

describe("the shared auditor stream vectors", () => {
  it.each(VECTORS)("rebuilds the stream of the $layout case $vector.name", (entry) => {
    const { vector, bound: layout } = entry;
    expect(layout.exits).toBe(BigInt(vector.exits_bitmap));
    expect(maxEvidenceBlocks(layout.key)).toBe(vector.max_evidence_blocks);
    expect(recordBlocks(layout.key)).toBe(vector.record_blocks);
    expect(firstRecordCounter(layout.key)).toBe(vector.first_record_counter);
    const eph = X25519Keypair.fromBytes(field(vector.eph_sk));
    expect(eph.publicKey().u()).toEqual(field(vector.eph_u));
    const auditor = x25519FromU(field(vector.auditor_u));
    const secret = auditSharedSecret(eph.ecdh(auditor), eph.publicKey(), auditor);
    const seal = (counter: number, bytes: Uint8Array) =>
      symmetricAuditApply(secret, { label: AUDIT_ENC_INFO, counter }, bytes);
    const plaintext = disclosurePlaintext(vectorDisclosure(entry));
    const envelopePlaintext = Uint8Array.of(...field(vector.tx_viewing_sk), ...plaintext.evidence);
    expect(envelopePlaintext).toEqual(hex(vector.envelope_plaintext));
    const envelope = seal(STREAM_FIRST_COUNTER, envelopePlaintext);
    expect(envelope).toEqual(hex(vector.envelope));
    expect(ciphertextDigest(envelope)).toEqual(field(vector.envelope_digest));
    const slots = recordSlots(layout);
    expect(vector.records.map((record) => record.slot)).toEqual(slots);
    const records = vector.records.map((record, index) => {
      expect(record.record_counter).toBe(recordRegion(layout, record.slot).startCounter);
      expect(plaintext.records[index]).toEqual(hex(record.record_plaintext));
      const sealed = seal(record.record_counter, hex(record.record_plaintext));
      expect(sealed).toEqual(hex(record.record));
      return sealed;
    });
    expect(
      auditorMessageData({ ephemeralPublicKey: eph.publicKey(), envelope, records }, auditor).data,
    ).toEqual(hex(vector.message));
    for (const slot of vector.slots)
      if (slot.kind === "ring" && "body" in slot) {
        const payloadBody = readRingOutput(payload(entry, slot)).body;
        expect(payloadBody).toEqual(hex(need(slot.body, "body")));
      }
  });
});

describe("auditRingTransaction over the shared disclosure vectors", () => {
  it.each(VECTORS)(
    "opens every slot of the $layout case to the Rust opening, an exit as a default-ring note",
    (entry) => {
      const assets = vectorAssets(entry.vector);
      const audited = audit(entry, {
        assets,
        escrowedKeys: escrowRecords(entry.vector),
        knownUtxos: spentUtxos(entry.vector, assets),
      });
      expect(audited.payloadErrors).toEqual([]);
      expect(audited.outputs.map((output) => output.slotIndex)).toEqual(
        entry.vector.slots.map((_, index) => index),
      );
      audited.outputs.forEach((output, index) => {
        const slot = entry.vector.slots[index]!;
        expect(output.outputContext.hash).toEqual(field(slot.output_hash));
        expect(output.opening).toEqual(expectedOpening(entry.layout, slot, assets));
      });
    },
  );

  it.each(VECTORS.filter((entry) => entry.bound.keyEscrow))(
    "returns the proven fields of every slot of the $layout escrow case until its records arrive",
    (entry) => {
      const pending = audit(entry);
      expect(pending.payloadErrors).toEqual([]);
      expect(auditedUtxos(pending)).toEqual([]);
      expect(pending.outputs.map((output) => output.opening.kind)).toEqual(
        entry.vector.slots.map((slot) => (slot.kind === "dummy" ? "dummy" : "escrowPending")),
      );
      pending.outputs.forEach((output, index) => {
        const slot = entry.vector.slots[index]!;
        if (output.opening.kind !== "escrowPending") return;
        expect(output.opening.amount).toBe(BigInt(need(slot.amount, "amount")));
        expect(output.opening.slot.kind).toBe(slot.kind === "exit" ? "exit" : "ring");
      });
      const assets = vectorAssets(entry.vector);
      expect(
        audit(entry, { assets, escrowedKeys: escrowRecords(entry.vector) }).payloadErrors,
      ).toEqual([]);
    },
  );

  it("names each input of a delivered rail by its full hash, opened or unseen", () => {
    const auditor = X25519Keypair.generate();
    const assets = vectorAssets(PAIR.vector);
    const spentHash = field(PAIR.vector.slots[0]!.output_hash);
    const layout: AuditStreamLayout = { ...PAIR_LAYOUT, inputs: 2 };
    const transaction = {
      ...vectorTransaction(PAIR, auditor.publicKey()),
      nullifiers: [field(PAIR.vector.first_nullifier), new Uint8Array(32).fill(1) as Bytes32],
      messages: [
        auditorMessageData(
          sealRingDisclosure({
            txViewingSecret: field(PAIR.vector.tx_viewing_sk),
            auditorPublicKey: auditor.publicKey(),
            disclosure: {
              ...vectorDisclosure(PAIR),
              layout,
              inputs: { kind: "commitments", hashes: [spentHash, undefined] },
            } as RingDisclosure,
          }),
          auditor.publicKey(),
        ),
      ],
    };
    const audited = auditRingTransaction({
      auditor,
      transaction,
      assets,
      layout,
    });
    expect(audited.payloadErrors).toEqual([]);
    expect(audited.sender).toBeUndefined();
    expect(audited.inputs.map((input) => input.opening)).toEqual([
      { kind: "unseenHash", hash: spentHash },
      { kind: "dummy" },
    ]);
    const known = new KnownUtxoIndex(
      auditedUtxos(audited).filter(({ commitment }) => equalBytes(commitment, spentHash)),
    );
    expect(
      auditRingTransaction({
        auditor,
        transaction,
        assets,
        layout,
        knownUtxos: known,
      }).inputs[0]?.opening,
    ).toMatchObject({
      kind: "opened",
      ring: { kind: "ring", commitment: spentHash },
    });
  });

  it.each([
    ["signer and in-proof", "delivered", "pair_exits"],
    ["authority", "delivered", "quad_escrow"],
    ["anonymous commitment", "anonymous", "commitment"],
  ] as const)("keeps every output open past an unseen hash on the %s rail", (_, layout, name) => {
    const entry = vectorOf(layout, name);
    const hash = new Uint8Array(32).fill(0x11) as Bytes32;
    const assets = vectorAssets(entry.vector);
    const auditor = X25519Keypair.generate();
    const unseen = Array.from({ length: entry.bound.inputs }, () => hash);
    const message = auditorMessageData(
      sealRingDisclosure({
        txViewingSecret: field(entry.vector.tx_viewing_sk),
        auditorPublicKey: auditor.publicKey(),
        disclosure: {
          ...vectorDisclosure(entry),
          inputs: { kind: "commitments", hashes: unseen },
        } as RingDisclosure,
      }),
      auditor.publicKey(),
    );
    const audited = audit(entry, {
      auditor,
      assets,
      escrowedKeys: escrowRecords(entry.vector),
      transaction: (transaction) => ({ ...transaction, messages: [message] }),
    });
    expect(audited.inputs.map((input) => input.opening)).toEqual(
      unseen.map(() => ({ kind: "unseenHash", hash })),
    );
    expect(audited.payloadErrors).toEqual([]);
    expect(audited.outputs.map(({ opening }) => opening)).toEqual(
      entry.vector.slots.map((slot) => expectedOpening(layout, slot, assets)),
    );
    expect(audited.sender).toBeUndefined();
  });

  it("opens the entry rail from its evidence with no note known", () => {
    const entry = vectorOf("anonymous", "entry");
    const audited = audit(entry);
    expect(audited.payloadErrors).toEqual([]);
    expect(audited.inputs.every(({ opening }) => opening.kind === "opened")).toBe(true);
  });

  describe("a zero nullifier key output", () => {
    const entry = vectorOf("delivered", "exits_escrow");
    const zeroKeyed = (slot: VectorSlot): VectorSlot => {
      const exit = slot.kind === "exit";
      const utxo: KnownUtxo = {
        ownerKey: field(exit ? slot.owner_tag : need(slot.owner_key, "owner_key")),
        owner: { kind: "keyed", nullifierPk: ZERO_NULLIFIER_PK },
        asset: field(need(slot.asset, "asset")),
        amount: BigInt(need(slot.amount, "amount")),
        blinding: field(slot.blinding),
        dataHash: ZERO_32,
        ringDataHash: ZERO_32,
        treeId: entry.vector.output_tree_id,
      };
      const ring = exit ? ZERO_32 : field(entry.vector.ring_id);
      return {
        ...slot,
        output_hash: Buffer.from(knownUtxoHash(utxo, ring)).toString("hex"),
      } as VectorSlot;
    };
    const exitIndex = entry.vector.slots.findIndex((slot) => slot.kind === "exit");
    const zeroEntry: VectorEntry = {
      ...entry,
      vector: {
        ...entry.vector,
        slots: entry.vector.slots.map((slot, index) =>
          index === 0 || index === exitIndex ? zeroKeyed(slot) : slot,
        ),
      } as Vector,
    };
    const zeroKeyOf = (opening: OutputOpening | undefined) =>
      opening?.kind === "ring" || opening?.kind === "exit" ? opening.utxo.nullifierPk : undefined;

    it("resolves when no escrow key is known", () => {
      const audited = audit(zeroEntry);
      expect(audited.payloadErrors).toEqual([]);
      expect(audited.outputs[0]?.opening.kind).toBe("ring");
      expect(zeroKeyOf(audited.outputs[0]?.opening)).toEqual(ZERO_NULLIFIER_PK);
      expect(audited.outputs[exitIndex]?.opening.kind).toBe("exit");
      expect(zeroKeyOf(audited.outputs[exitIndex]?.opening)).toEqual(ZERO_NULLIFIER_PK);
      expect(audited.outputs[1]?.opening.kind).toBe("escrowPending");
    });

    it("resolves past a registered key the commitment does not take", () => {
      const other = new Uint8Array(32).fill(0x07) as Bytes32;
      const audited = audit(zeroEntry, {
        escrowedKeys: {
          nullifierPk: (ownerKey) => escrowRecords(entry.vector).nullifierPk(ownerKey) ?? other,
        },
      });
      expect(audited.payloadErrors).toEqual([]);
      expect(zeroKeyOf(audited.outputs[0]?.opening)).toEqual(ZERO_NULLIFIER_PK);
      expect(zeroKeyOf(audited.outputs[exitIndex]?.opening)).toEqual(ZERO_NULLIFIER_PK);
    });
  });

  it("records a body whose blinding is off the slot's as a commitment error", () => {
    const entry = vectorOf("delivered", "exits");
    const slot = entry.vector.slots[0]!;
    const audited = audit(entry, {
      escrowedKeys: escrowRecords(entry.vector),
      transaction: withSlot(0, (published) => ({
        ...published,
        payload: encodeRingOutput(
          RingScheme.ringConfidentialDelivered,
          sealDeliveredBody(
            field(need("slot_secret" in slot ? slot.slot_secret : undefined, "slot_secret")),
            {
              blinding: new Uint8Array(32).fill(0) as Bytes32,
              amount: BigInt(need(slot.amount, "amount")),
              ownerKey: field(need(slot.owner_key, "owner_key")),
              nullifierPk: field(need(slot.nullifier_pk, "nullifier_pk")),
            },
          ),
        ),
      })),
    });
    expect(audited.payloadErrors).toEqual([{ slotIndex: 0, kind: "commitment" }]);
  });

  it("reports a zero amount delivered output no registered asset rebuilds", () => {
    const entry = vectorOf("delivered", "exits");
    const slot = entry.vector.slots[0]!;
    const audited = audit(entry, {
      escrowedKeys: escrowRecords(entry.vector),
      transaction: withSlot(0, (published) => ({
        ...published,
        payload: encodeRingOutput(
          RingScheme.ringConfidentialDelivered,
          sealDeliveredBody(
            field(need("slot_secret" in slot ? slot.slot_secret : undefined, "slot_secret")),
            {
              blinding: field(slot.blinding),
              amount: 0n,
              ownerKey: field(need(slot.owner_key, "owner_key")),
              nullifierPk: field(need(slot.nullifier_pk, "nullifier_pk")),
            },
          ),
        ),
      })),
    });
    expect(audited.payloadErrors).toEqual([{ slotIndex: 0, kind: "unknownAsset" }]);
  });

  it("keeps a delivered slot closed until its mint is registered", () => {
    const entry = vectorOf("delivered", "dense");
    const audited = audit(entry, { assets: new AssetRegistry() });
    const closed = audited.payloadErrors.map(({ slotIndex }) => slotIndex);
    expect(closed).toContain(1);
    expect(audited.outputs.map(({ slotIndex }) => slotIndex)).not.toContain(1);
    expect(hasUnknownAssets(audited)).toBe(true);
    expect(audited.outputCommitments[1]).toEqual(field(entry.vector.slots[1]!.output_hash));
  });

  it("names a registered mint and leaves an unregistered one to a refresh", () => {
    const exit = (assets: AssetRegistry) =>
      audit(PAIR, { assets }).outputs.find((output) => output.opening.kind === "exit");
    const unknown = exit(new AssetRegistry())?.opening;
    expect(unknown?.kind === "exit" && unknown.utxo.mint).toBeUndefined();
    const known = exit(new AssetRegistry([[2n, FOREIGN_MINT]]))?.opening;
    expect(known?.kind === "exit" && known.utxo.mint).toBe(FOREIGN_MINT);
  });

  it("reads a merge output's record as a merged input and names its owner as the sender", () => {
    const entry = vectorOf("anonymous", "commitment");
    const vector = entry.vector as Extract<typeof entry.vector, { sender_key: string }>;
    const ownerKey = field(vector.sender_key);
    const first = field(need(vector.inputs[0], "input").commitment);
    const audited = audit(entry, {
      knownUtxos: {
        utxo: () => undefined,
        merged: (commitment) =>
          equalBytes(commitment, first)
            ? {
                ownerKey,
                owner: {
                  kind: "deposited",
                  ownerHash: field(vector.sender_nullifier_pk),
                },
                asset: first,
                amount: 7n,
              }
            : undefined,
      },
    });
    expect(audited.sender).toEqual({ ownerKey });
    expect(audited.inputs[0]?.opening).toEqual({
      kind: "merged",
      ownerKey,
      asset: first,
      amount: 7n,
    });
    expect(audited.inputs[1]?.opening.kind).toBe("unseenHash");
  });

  it("takes the sender from spent note 0 and opens the later note by its hash", () => {
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const assets = new AssetRegistry();
    const known = spentUtxos(vector, assets);
    const audited = audit(entry, { assets, knownUtxos: known });
    expect(audited.sender).toEqual({
      ownerKey: field(vector.sender_key),
      nullifierPk: field(vector.sender_nullifier_pk),
    });
    expect(audited.inputs).toEqual(
      vector.inputs.map((input) => ({
        nullifier: field(input.nullifier),
        hash: field(input.commitment),
        opening: {
          kind: "opened",
          asset: field(input.asset),
          ...openedMint(assets, input.asset),
          amount: BigInt(input.amount),
          blinding: field(input.blinding),
          ring: { kind: "ring", commitment: field(input.commitment) },
        },
      })),
    );
  });

  it("withholds no slot for an unseen spent note and resolves once the note is known", () => {
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const assets = new AssetRegistry();
    const known = spentUtxos(vector, assets);
    const [first, later] = vector.inputs.map((input) => field(input.commitment));
    const only = (commitments: readonly Bytes32[]) =>
      new KnownUtxoIndex(
        commitments.map((commitment) => ({
          commitment,
          utxo: known.utxo(commitment)!,
        })),
      );
    const resolved = audit(entry, {
      assets,
      knownUtxos: only([first!, later!]),
    });
    expect(resolved.outputs).toHaveLength(entry.vector.slots.length);
    const sender = {
      ownerKey: field(vector.sender_key),
      nullifierPk: field(vector.sender_nullifier_pk),
    };
    const unseenFirst = { kind: "unseenHash", hash: first };
    const unseenLater = { kind: "unseenHash", hash: later };
    const opened = (commitment: Bytes32 | undefined) => ({
      kind: "opened",
      ring: { kind: "ring", commitment },
    });
    for (const [notes, expectedSender, firstInput, laterInput] of [
      [[], undefined, unseenFirst, unseenLater],
      [[first!], sender, opened(first), unseenLater],
      [[later!], undefined, unseenFirst, opened(later)],
      [[first!, later!], sender, opened(first), opened(later)],
    ] as const) {
      const audited = audit(entry, { assets, knownUtxos: only(notes) });
      expect(audited.payloadErrors).toEqual([]);
      expect(audited.outputs).toEqual(resolved.outputs);
      expect(audited.sender).toEqual(expectedSender);
      expect(audited.inputs.map((input) => input.opening)).toMatchObject([firstInput, laterInput]);
      expect(audited.inputs.map((input) => input.nullifier)).toEqual(
        vector.inputs.map((input) => field(input.nullifier)),
      );
    }
    const noIndex = audit(entry, { assets });
    expect(noIndex.sender).toBeUndefined();
    expect(noIndex.outputs).toEqual(resolved.outputs);
  });

  it("keeps a note's first opening unless a later one names its mint", () => {
    const vector = anonymousCase("commitment");
    const commitment = field(vector.inputs[0]!.commitment);
    const opened = spentUtxos(vector, new AssetRegistry()).utxo(commitment)!;
    const { mint: _, ...unminted } = opened;
    const index = new KnownUtxoIndex([{ commitment, utxo: unminted }]);
    index.insert(commitment, { ...unminted, amount: 1n });
    expect(index.utxo(commitment)).toEqual(unminted);
    const minted = { ...unminted, mint: FOREIGN_MINT };
    index.insert(commitment, minted);
    expect(index.utxo(commitment)).toEqual(minted);
  });

  it("names no sender nullifier key when spent note 0 is a deposit", () => {
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const assets = new AssetRegistry();
    const utxos = spentUtxos(vector, assets);
    const deposited = field(vector.inputs[0]!.commitment);
    const audited = audit(entry, {
      assets,
      knownUtxos: {
        utxo: (commitment) => {
          const utxo = utxos.utxo(commitment);
          if (utxo === undefined || !equalBytes(commitment, deposited)) return utxo;
          return {
            ...utxo,
            owner: {
              kind: "deposited",
              ownerHash: new Uint8Array(32).fill(9) as Bytes32,
            },
          };
        },
      },
    });
    expect(audited.sender).toEqual({ ownerKey: field(vector.sender_key) });
    expect(audited.inputs[0]?.opening).toMatchObject({
      kind: "opened",
      amount: BigInt(vector.inputs[0]!.amount),
    });
  });

  it("opens every spent note of the entry key and resolves its ring from the evidence hash", () => {
    const entry = vectorOf("anonymous", "entry");
    const vector = anonymousCase("entry");
    const assets = new AssetRegistry();
    const trees = vector.inputs.map((input) => input.input_tree_id);
    const resolved = audit(entry, { assets, inputTreeIds: trees });
    expect(resolved.sender).toEqual({
      ownerKey: field(vector.sender_key),
      nullifierPk: field(vector.sender_nullifier_pk),
    });
    expect(resolved.inputs).toEqual(
      vector.inputs.map((input) => ({
        nullifier: field(input.nullifier),
        hash: field(input.commitment),
        opening: {
          kind: "opened",
          asset: field(input.asset),
          ...openedMint(assets, input.asset),
          amount: BigInt(input.amount),
          blinding: field(input.blinding),
          ring: { kind: input.ring, commitment: field(input.commitment) },
        },
      })),
    );
    const ringOf = ({ opening }: AuditedInput) =>
      opening.kind === "opened" ? opening.ring : undefined;
    const unresolved = audit(entry, {
      inputTreeIds: trees.map((tree) => tree + 1),
    });
    for (const input of unresolved.inputs) expect(ringOf(input)?.kind).toBe("unresolved");
    expect(audit(entry).inputs.every((input) => ringOf(input) === undefined)).toBe(true);
  });

  it("records a record byte moved off its opening as that slot's commitment error", () => {
    const audited = audit(PAIR, {
      transaction: (transaction) => {
        const message = transaction.messages[0]!;
        const data = message.data.slice();
        // The exit's nullifier key ends the message, its low bit keeps the key canonical.
        const last = data.length - 1;
        data[last] = (data[last] ?? 0) ^ 1;
        return {
          ...transaction,
          messages: [{ viewTag: message.viewTag, data }],
        };
      },
    });
    expect(audited.payloadErrors).toEqual([{ slotIndex: 1, kind: "commitment" }]);
    expect(audited.outputs.map((output) => output.slotIndex)).toEqual([0]);
  });

  it("opens a delivered ring output from its body and a hidden dummy from its commitment alone", () => {
    const entry = vectorOf("delivered", "exits");
    const assets = vectorAssets(entry.vector);
    const audited = audit(entry, { assets });
    entry.vector.slots.forEach((slot, index) => {
      const opening = audited.outputs[index]?.opening;
      expect(opening?.kind).toBe(slot.kind);
    });
  });

  it("refuses a delivered body under an anonymous scheme or of another length as a frame error", () => {
    const entry = vectorOf("delivered", "exits");
    const framed = (scheme: RingScheme, length: number) =>
      audit(entry, {
        transaction: withSlot(0, (published) => ({
          ...published,
          payload: encodeRingOutput(scheme, new Uint8Array(length)),
        })),
      }).payloadErrors;
    expect(framed(RingScheme.ringRecipientBody, 104)).toEqual([{ slotIndex: 0, kind: "frame" }]);
    expect(framed(RingScheme.ringConfidentialDelivered, 72)).toEqual([
      { slotIndex: 0, kind: "frame" },
    ]);
  });

  it("opens an anonymous output from its disclosure whatever body it publishes", () => {
    const entry = vectorOf("anonymous", "commitment");
    const assets = vectorAssets(entry.vector);
    const audited = audit(entry, {
      assets,
      knownUtxos: spentUtxos(entry.vector, assets),
      transaction: withSlot(0, (published) => ({
        ...published,
        payload: encodeRingOutput(RingScheme.ringRecipientBody, Uint8Array.of(1)),
      })),
    });
    expect(audited.payloadErrors).toEqual([]);
    expect(audited.outputs[0]?.opening).toEqual(
      expectedOpening("anonymous", entry.vector.slots[0]!, assets),
    );
  });

  it("refuses a recipient key without an X25519 agreement", () => {
    const audited = audit(vectorOf("delivered", "exits"), {
      transaction: withSlot(5, (slot) => ({
        ...slot,
        viewTag: new Uint8Array(32) as Bytes32,
      })),
    });
    expect(audited.payloadErrors).toEqual([{ slotIndex: 5, kind: "recipientKey" }]);
  });

  it("opens an anonymous ring output under any view tag and reports the tag it took", () => {
    const entry = vectorOf("anonymous", "commitment");
    const assets = vectorAssets(entry.vector);
    const viewTag = new Uint8Array(32).fill(0xe1) as Bytes32;
    const audited = audit(entry, {
      assets,
      knownUtxos: spentUtxos(entry.vector, assets),
      transaction: withSlot(0, (slot) => ({ ...slot, viewTag })),
    });
    expect(audited.payloadErrors).toEqual([]);
    const opening = audited.outputs[0]?.opening;
    expect(opening?.kind === "ring" && opening.ownerTag).toEqual({
      kind: "view",
      tag: viewTag,
    });
  });

  it("reads the last message alone and refuses one sealed to another auditor or not last", () => {
    const entry = vectorOf("delivered", "exits");
    const auditor = X25519Keypair.generate();
    const sealed = vectorTransaction(entry, auditor.publicKey());
    const message = sealed.messages[0]!;
    const other = {
      viewTag: new Uint8Array(32).fill(3) as Bytes32,
      data: Uint8Array.of(1),
    };
    const bundle = { viewTag: message.viewTag, data: Uint8Array.of(1) };
    const refused = (messages: IndexedShieldedTransaction["messages"]) => () =>
      auditRingTransaction({
        auditor,
        transaction: { ...sealed, messages },
        assets: new AssetRegistry(),
        layout: entry.bound,
      });
    expect(() =>
      auditRingTransaction({
        auditor: X25519Keypair.generate(),
        transaction: sealed,
        assets: new AssetRegistry(),
        layout: entry.bound,
      }),
    ).toThrow(ringError("RING_AUDIT_MESSAGE", { reason: "missing" }));
    expect(refused([bundle, message])()).toEqual(refused([message])());
    expect(refused([message, bundle])).toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "malformed" }),
    );
    expect(refused([message, other])).toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "missing" }),
    );
  });

  it("refuses a published key the envelope does not seal", () => {
    expect(() =>
      audit(PAIR, {
        transaction: (transaction) => ({
          ...transaction,
          txViewingPublicKey: X25519Keypair.generate().publicKey(),
        }),
      }),
    ).toThrow(ringError("RING_AUDIT_KEY_MISMATCH"));
  });

  it("refuses an unclamped alias of the sealed transaction secret", () => {
    const auditor = X25519Keypair.generate();
    const transaction = vectorTransaction(PAIR, auditor.publicKey());
    const alias = field(PAIR_VECTOR.tx_viewing_sk);
    alias[0] = (alias[0] ?? 0) | 1;
    const message = auditorMessageData(
      sealRingDisclosure({
        txViewingSecret: alias,
        auditorPublicKey: auditor.publicKey(),
        disclosure: vectorDisclosure(PAIR),
      }),
      auditor.publicKey(),
    );
    expect(() =>
      auditRingTransaction({
        auditor,
        transaction: { ...transaction, messages: [message] },
        assets: new AssetRegistry(),
        layout: PAIR_LAYOUT,
      }),
    ).toThrow(ringError("RING_AUDIT_NONCANONICAL_KEY"));
  });

  it("audits under the layout the frame bound and refuses one off the published counts", () => {
    // The escrow layout leaves out every key, the record length no longer matches the message.
    expect(() =>
      audit(PAIR, {
        layout: { ...PAIR_LAYOUT, keyEscrow: true },
      }),
    ).toThrow(ringError("RING_AUDIT_MESSAGE", { reason: "malformed" }));
    expect(() =>
      audit(PAIR, {
        layout: { ...PAIR_LAYOUT, outputs: 4 },
      }),
    ).toThrow(ringError("RING_AUDIT_MESSAGE", { reason: "layout" }));
    // The program sets each exits bit exactly when its published slot exits.
    expect(() => audit(PAIR, { layout: { ...PAIR_LAYOUT, exits: 0n } })).toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "layout" }),
    );
  });

  it("refuses a transfer without its salt and input trees of another count", () => {
    const auditor = X25519Keypair.generate();
    const transaction = vectorTransaction(PAIR, auditor.publicKey());
    const unsalted: IndexedShieldedTransaction = {
      slot: transaction.slot,
      txSignature: transaction.txSignature,
      outputSlots: transaction.outputSlots,
      messages: transaction.messages,
      nullifiers: transaction.nullifiers,
      proofless: false,
      ...(transaction.txViewingPublicKey === undefined
        ? {}
        : { txViewingPublicKey: transaction.txViewingPublicKey }),
      ...(transaction.ringProgramId === undefined
        ? {}
        : { ringProgramId: transaction.ringProgramId }),
    };
    expect(() =>
      auditRingTransaction({
        auditor,
        transaction: unsalted,
        assets: new AssetRegistry(),
        layout: PAIR_LAYOUT,
      }),
    ).toThrow(ringError("RING_AUDIT_UNSEALED", { reason: "salt" }));
    expect(() => audit(PAIR, { inputTreeIds: [9, 9] })).toThrow(
      ringError("RING_INVALID_LENGTH", { name: "inputTreeIds" }),
    );
  });
});

function anonymousCase(name: string): (typeof anonymous.cases)[number] {
  const found = anonymous.cases.find((vector) => vector.name === name);
  if (found === undefined) throw new Error(`no anonymous ${name} vector`);
  return found;
}

function openedMint(assets: AssetRegistry, asset: string): Readonly<{ mint?: Address }> {
  const mint = assets.addressForField(field(asset));
  return mint === undefined ? {} : { mint };
}

const RING = encodeBase58(field(PAIR_VECTOR.ring_program_id));

const TRANSFERS: TransactionOrigin = {
  confirmedTransaction: async (transaction) => ({
    kind: "transfer",
    transaction,
    inputTreeIds: transaction.nullifiers.map(() => undefined),
    layout: PAIR_LAYOUT,
  }),
};

describe("auditRing", () => {
  const ring = RING;
  const transfers = TRANSFERS;

  function scan(
    transactions: readonly IndexedShieldedTransaction[],
    origin: TransactionOrigin,
    extra: Readonly<{
      solanaRpc?: object;
      assets?: AssetRegistry;
      auditor: X25519Keypair;
      knownUtxos?: KnownUtxos;
    }>,
  ) {
    return auditRing({
      client: ringAuditReader({
        getShieldedTransactionsByTags: async () =>
          transactionsPage({
            data: transactionItems([...transactions]),
          }),
        ...(extra.solanaRpc === undefined ? {} : { solanaRpc: extra.solanaRpc }),
      }),
      auditor: extra.auditor,
      ringProgramId: ring,
      assets: extra.assets ?? new AssetRegistry(),
      origin,
      ...(extra.knownUtxos === undefined ? {} : { knownUtxos: extra.knownUtxos }),
    });
  }

  it("opens a spend of a note an earlier call opened through the caller's known notes", async () => {
    const auditor = X25519Keypair.generate();
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const transfer = vectorTransaction(entry, auditor.publicKey());
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction) => ({
        kind: "transfer",
        transaction,
        inputTreeIds: transaction.nullifiers.map(() => undefined),
        layout: entry.bound,
      }),
    };
    const assets = new AssetRegistry();
    const unseen = await scan([transfer], origin, {
      auditor,
      assets,
      solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) },
    });
    expect(unseen.transactions[0]?.sender).toBeUndefined();
    expect(unseen.transactions[0]?.inputs[0]?.opening).toEqual({
      kind: "unseenHash",
      hash: field(vector.inputs[0]!.commitment),
    });
    expect(unseen.transactions[0]?.outputs).toHaveLength(entry.vector.slots.length);
    const page = await scan([transfer], origin, {
      auditor,
      assets,
      knownUtxos: spentUtxos(vector, assets),
      solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) },
    });
    expect(page.transactions[0]?.sender).toEqual({
      ownerKey: field(vector.sender_key),
      nullifierPk: field(vector.sender_nullifier_pk),
    });
  });

  it("resolves a merged input before tracing its later transfer in either history order", async () => {
    const auditor = X25519Keypair.generate();
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const assets = vectorAssets(vector);
    const target = field(vector.inputs[0]!.commitment);
    const original = spentUtxos(vector, assets).utxo(target)!;
    const predecessor = { ...original, blinding: field("01".repeat(32)) };
    const commitment = knownUtxoHash(predecessor, field(vector.ring_id));
    const known = new KnownUtxoIndex([{ commitment, utxo: predecessor }]);
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const firstNullifier = field("02".repeat(32));
    const { disclosure, ephemeralSecret, disclosureKey } = sealRingMergeDisclosure(
      [commitment, ...Array.from({ length: 7 }, () => ZERO_32)],
      salt,
      auditor.publicKey(),
    );
    const merge: IndexedShieldedTransaction = {
      slot: 6n,
      txSignature: "6".repeat(87) as Signature,
      eventIndex: 0,
      proofless: false,
      ringProgramId: RING,
      nullifiers: [firstNullifier, field("03".repeat(32))],
      messages: [],
      outputSlots: [
        {
          viewTag: firstNullifier,
          payload: encodeMergeOutputData({
            salt,
            ciphertext: [ZERO_32, ZERO_32, ZERO_32],
            ringDataHash: ZERO_32,
          }),
          outputContext: {
            hash: target,
            tree: treeAddress(original.treeId),
            treeId: original.treeId,
            leafIndex: 9n,
          },
        },
      ],
    };
    const transfer = vectorTransaction(entry, auditor.publicKey());
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction) =>
        transaction.txSignature === merge.txSignature
          ? {
              kind: "merge",
              transaction,
              disclosure: { ...disclosure, proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH) },
            }
          : {
              kind: "transfer",
              transaction,
              layout: entry.bound,
              inputTreeIds: transaction.nullifiers.map(() => undefined),
            },
    };
    try {
      for (const history of [
        [merge, transfer],
        [transfer, merge],
      ]) {
        const page = await scan(history, origin, { auditor, assets, knownUtxos: known });
        expect(page.skipped).toEqual([]);
        expect(page.transactions[0]?.sender).toEqual({
          ownerKey: field(vector.sender_key),
          nullifierPk: field(vector.sender_nullifier_pk),
        });
        expect(page.transactions[0]?.inputs[0]?.opening).toMatchObject({
          kind: "merged",
          ownerKey: original.ownerKey,
          asset: original.asset,
          amount: original.amount,
        });
      }
    } finally {
      ephemeralSecret.fill(0);
      disclosureKey.fill(0);
      auditor.destroy();
    }
  });

  it("audits the ring's confirmed transfers and skips every other event", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PAIR, auditor.publicKey());
    const deposit = { ...transfer, txSignature: "2".repeat(64) as Signature };
    const foreign = { ...transfer, txSignature: "3".repeat(64) as Signature };
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction): Promise<ConfirmedRingTransaction | undefined> => {
        if (transaction.txSignature === foreign.txSignature) return undefined;
        if (transaction.txSignature === deposit.txSignature)
          return { kind: "deposit", transaction, deposits: [] };
        return transfers.confirmedTransaction(transaction, ring);
      },
    };
    const assets = new AssetRegistry([[2n, FOREIGN_MINT]]);
    const page = await scan([transfer, deposit, foreign], origin, {
      auditor,
      assets,
    });
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(page.nextCursor).toBeUndefined();
  });

  it("skips a historical transfer and a historical merge without opening them", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PAIR, auditor.publicKey());
    const historical = {
      ...transfer,
      txSignature: "2".repeat(64) as Signature,
      messages: [],
    };
    const oldMerge = {
      ...transfer,
      txSignature: "3".repeat(64) as Signature,
      messages: [],
    };
    const origin: TransactionOrigin = {
      confirmedTransaction: async (row, read) => {
        if (row.txSignature === historical.txSignature)
          return {
            kind: "historicalTransfer",
            transaction: row,
            inputTreeIds: [undefined],
            instruction: Uint8Array.of(43),
            sppAnonymous: false,
          };
        if (row.txSignature === oldMerge.txSignature)
          return {
            kind: "historicalMerge",
            transaction: row,
            instruction: Uint8Array.of(20),
          };
        return transfers.confirmedTransaction(row, read);
      },
    };
    const assets = new AssetRegistry([[2n, FOREIGN_MINT]]);
    const page = await scan([historical, oldMerge, transfer], origin, {
      auditor,
      assets,
    });
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(page.skipped).toEqual([]);
  });

  it("skips a row that does not decode, reports it and stops on a transport failure", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PAIR, auditor.publicKey());
    const assets = new AssetRegistry([[2n, FOREIGN_MINT]]);
    for (const code of ["RING_ORIGIN_DECODE", "RING_TRANSACT_DATA_INVALID"] as const) {
      const bad = {
        ...transfer,
        slot: 9n,
        txSignature: "2".repeat(64) as Signature,
      };
      const origin: TransactionOrigin = {
        confirmedTransaction: async (transaction) => {
          if (transaction.txSignature === bad.txSignature) throw new RingError(code);
          return transfers.confirmedTransaction(transaction, ring);
        },
      };
      const page = await scan([bad, transfer], origin, { auditor, assets });
      expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
      expect(page.skipped).toEqual([
        {
          slot: 9n,
          signature: bad.txSignature,
          eventIndex: bad.eventIndex,
          reason: "invalidAuditData",
        },
      ]);
    }
    for (const code of ["RING_ORIGIN_UNAVAILABLE", "RING_ORIGIN_STACK"] as const) {
      const origin: TransactionOrigin = {
        confirmedTransaction: async () => {
          throw new RingError(code);
        },
      };
      await expect(scan([transfer], origin, { auditor, assets })).rejects.toThrow(ringError(code));
    }
  });

  it("lists a row that fails its audit, opens the rest and keeps its stops", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PAIR, auditor.publicKey());
    const assets = new AssetRegistry([[2n, FOREIGN_MINT]]);
    const sealed = transfer.messages.at(-1)!;
    const malformed = {
      ...transfer,
      slot: 9n,
      txSignature: "2".repeat(64) as Signature,
      messages: [{ viewTag: sealed.viewTag, data: Uint8Array.of(1) }],
    };
    const page = await scan([malformed, transfer], transfers, {
      auditor,
      assets,
    });
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(page.skipped).toEqual([
      {
        slot: 9n,
        signature: malformed.txSignature,
        eventIndex: malformed.eventIndex,
        reason: "invalidAuditData",
      },
    ]);
    await expect(
      scan([{ ...transfer, messages: [] }], transfers, { auditor, assets }),
    ).rejects.toThrow(ringError("RING_AUDIT_MESSAGE", { reason: "missing" }));
    const down = new Error("registry down");
    await expect(
      scan([transfer], transfers, {
        auditor,
        assets: new AssetRegistry(),
        solanaRpc: {
          getProgramAccounts: () => ({ send: () => Promise.reject(down) }),
        },
      }),
    ).rejects.toThrow();
  });

  it("never reads the origin of a row another ring or the default ring indexed", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PAIR, auditor.publicKey());
    const { ringProgramId: _ring, ...defaultRing } = {
      ...transfer,
      txSignature: "7".repeat(64) as Signature,
    };
    const otherRing = {
      ...transfer,
      txSignature: "8".repeat(64) as Signature,
      ringProgramId: OTHER_RING,
    };
    const read = vi.fn(async (transaction: IndexedShieldedTransaction) => {
      if (transaction.txSignature !== SIGNATURE) throw new Error("origin read of a foreign row");
      return transfers.confirmedTransaction(transaction, ring);
    });
    const assets = new AssetRegistry([[2n, FOREIGN_MINT]]);
    const page = await scan(
      [defaultRing, otherRing, transfer],
      { confirmedTransaction: read },
      {
        auditor,
        assets,
      },
    );
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("refuses a confirmed transfer without its auditor message", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PAIR, auditor.publicKey());
    await expect(scan([{ ...transfer, messages: [] }], transfers, { auditor })).rejects.toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "missing" }),
    );
  });

  it("refreshes the asset registry once for a mint the chain registers", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PAIR, auditor.publicKey());
    const registry = new Uint8Array(48);
    registry[0] = StateDiscriminator.splAssetRegistry;
    registry.set(new Uint8Array(getAddressEncoder().encode(FOREIGN_MINT as Address)), 8);
    new DataView(registry.buffer).setBigUint64(40, 2n, true);
    const getProgramAccounts = vi.fn(() => ({
      send: async () => [
        {
          account: {
            owner: SHIELDED_POOL_PROGRAM_ID,
            data: [Buffer.from(registry).toString("base64"), "base64"],
          },
        },
      ],
    }));
    const assets = new AssetRegistry();
    const page = await scan([transfer, transfer], transfers, {
      auditor,
      assets,
      solanaRpc: { getProgramAccounts },
    });
    expect(getProgramAccounts).toHaveBeenCalledTimes(1);
    for (const audited of page.transactions) {
      const exit = audited.outputs.find((output) => output.opening.kind === "exit")?.opening;
      expect(exit?.kind === "exit" && exit.utxo.mint).toBe(FOREIGN_MINT);
    }
  });

  it("repeats no agreement or schedule across the refresh", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PAIR, auditor.publicKey());
    const ecdh = vi.spyOn(auditor, "ecdh");
    const derive = vi.spyOn(AuditSchedule, "derive");
    const getProgramAccounts = vi.fn(() => ({ send: async () => [] }));
    try {
      const page = await scan([transfer], transfers, {
        auditor,
        assets: new AssetRegistry(),
        solanaRpc: { getProgramAccounts },
      });
      expect(page.transactions).toHaveLength(1);
      expect(getProgramAccounts).toHaveBeenCalledTimes(1);
      expect(ecdh).toHaveBeenCalledTimes(1);
      expect(derive.mock.calls.filter(([, label]) => label === AUDIT_ENC_INFO)).toHaveLength(1);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("opens a row on a retry once the RPC serves its auditor message", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PAIR, auditor.publicKey());
    const assets = new AssetRegistry([[2n, FOREIGN_MINT]]);
    let served = false;
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction, ring) =>
        transfers.confirmedTransaction(
          served ? transaction : { ...transaction, messages: [] },
          ring,
        ),
    };
    await expect(scan([transfer], origin, { auditor, assets })).rejects.toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "missing" }),
    );
    served = true;
    const page = await scan([transfer], origin, { auditor, assets });
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(page.skipped).toEqual([]);
  });

  it("follows the cursor to the page that states its frontier and stops at the page cap", async () => {
    const auditor = X25519Keypair.generate();
    const first = vectorTransaction(PAIR, auditor.publicKey());
    const second = { ...first, txSignature: "4".repeat(64) as Signature };
    const pages = [
      transactionsPage({
        data: transactionItems([first]),
        paginationToken: "t1",
      }),
      transactionsPage({ data: transactionItems([second]) }),
    ];
    const read = vi.fn(
      async (request: { paginationToken?: string }) =>
        pages[request.paginationToken === undefined ? 0 : 1]!,
    );
    const audit = (maxPages?: number) =>
      auditRing({
        client: ringAuditReader({ getShieldedTransactionsByTags: read }),
        auditor,
        ringProgramId: ring,
        assets: new AssetRegistry([[2n, FOREIGN_MINT]]),
        origin: transfers,
        ...(maxPages === undefined ? {} : { maxPages }),
      });
    const capped = await audit(1);
    expect(capped.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(capped.nextCursor).toEqual(historyCursor(ring, "ring", "t1"));
    const complete = await audit();
    expect(complete.transactions.map((audited) => audited.signature)).toEqual([
      SIGNATURE,
      second.txSignature,
    ]);
    expect(complete.nextCursor).toBeUndefined();
    expect(read.mock.calls.map(([request]) => request.paginationToken)).toEqual([
      undefined,
      undefined,
      "t1",
    ]);
  });

  it("refuses a token that does not advance, a cursor of another query and a zero limit", async () => {
    const auditor = X25519Keypair.generate();
    const audit = (
      pages: readonly ReturnType<typeof transactionsPage>[],
      limits: Readonly<{ pageSize?: number; maxPages?: number }> = {},
    ) => {
      const read = vi.fn(
        async (request: { paginationToken?: string }) =>
          pages[request.paginationToken === undefined ? 0 : 1]!,
      );
      return {
        read,
        result: auditRing({
          client: ringAuditReader({ getShieldedTransactionsByTags: read }),
          auditor,
          ringProgramId: ring,
          assets: new AssetRegistry(),
          origin: transfers,
          ...limits,
        }),
      };
    };
    const stuck = [
      transactionsPage({ paginationToken: "t1" }),
      transactionsPage({ paginationToken: "t1" }),
    ];
    await expect(audit(stuck).result).rejects.toThrow(ringError("RING_HISTORY_PAGE_INVALID"));
    for (const cursor of [
      historyCursor(ring, "tags", "t1"),
      historyCursor("11111111111111111111111111111111" as Address, "ring", "t1"),
      "t1",
      Uint8Array.of(2, 1) as unknown as string,
    ]) {
      const read = vi.fn(async () => transactionsPage());
      await expect(
        auditRing({
          client: ringAuditReader({ getShieldedTransactionsByTags: read }),
          auditor,
          ringProgramId: ring,
          assets: new AssetRegistry(),
          origin: transfers,
          cursor,
        }),
      ).rejects.toThrow(ringError("RING_HISTORY_CURSOR_INVALID"));
      expect(read).not.toHaveBeenCalled();
    }
    for (const limits of [{ pageSize: 0 }, { maxPages: 0 }, { pageSize: 1.5 }]) {
      const { read, result } = audit([transactionsPage()], limits);
      await expect(result).rejects.toThrow(ringError("RING_RPC", { reason: "invalid scan limit" }));
      expect(read).not.toHaveBeenCalled();
    }
  });
});

describe("recoverRingMemberNotes", () => {
  const toHex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

  /** The delivered `entry` with its first ring output paid to `owner`, its stream sealed again. */
  function ownedTransfer(owner: ShieldedKeypair, auditor: X25519PublicKey, entry = PAIR) {
    const address = owner.shieldedAddress();
    const slot = entry.vector.slots[0]!;
    const commitment = new Utxo({
      owner: address.signingPublicKey,
      asset: SOL_MINT,
      amount: BigInt(need(slot.amount, "amount")),
      blinding: field(slot.blinding),
      ringProgramId: RING,
    }).hash(address.nullifierPublicKey, entry.vector.output_tree_id);
    const vector = {
      ...entry.vector,
      slots: entry.vector.slots.map((vectorSlot: VectorSlot, index) =>
        index === 0
          ? {
              ...vectorSlot,
              owner_key: toHex(address.signingPublicKey.ed25519()),
              nullifier_pk: toHex(address.nullifierPublicKey),
              output_hash: toHex(commitment),
            }
          : vectorSlot,
      ),
    } as Vector;
    return {
      transaction: vectorTransaction({ layout: "delivered", vector }, auditor),
      commitment,
      amount: BigInt(need(slot.amount, "amount")),
    };
  }

  function anonymousTransfer(
    input: Readonly<{
      owner: ShieldedKeypair;
      auditor: X25519PublicKey;
      mint: Address;
      firstInput?: Readonly<{ hash: Bytes32; nullifier: Bytes32 }>;
    }>,
  ) {
    const base = anonymousCase("commitment");
    const firstNullifier = input.firstInput?.nullifier ?? field(base.first_nullifier);
    const blindingSeed = ringBlindingSeed(field(base.tx_viewing_sk), hex<Bytes16>(base.salt, 16));
    const address = input.owner.shieldedAddress();
    const slots = base.slots.map((slot, outputIndex) => {
      const blinding = ringOutputBlinding({ firstNullifier, blindingSeed, outputIndex });
      if (slot.kind === "dummy")
        return {
          ...slot,
          blinding: toHex(blinding),
          output_hash: toHex(dummyUtxoHash(base.output_tree_id, blinding)),
        };
      const opened =
        outputIndex === 0
          ? {
              ...slot,
              owner_key: toHex(address.confidentialViewTag()),
              nullifier_pk: toHex(address.nullifierPublicKey),
              asset_address: toHex(addressBytes(input.mint)),
              asset: toHex(hashBytes(addressBytes(input.mint))),
            }
          : slot;
      const output = ownerUtxoHash({
        owner: poseidon([
          solanaOwnerIdentity(field(need(opened.owner_key, "owner"))),
          field(need(opened.nullifier_pk, "nullifier")),
        ]),
        asset: encodeBase58(field(need(opened.asset_address, "asset"))),
        amount: BigInt(need(opened.amount, "amount")),
        blinding,
        treeId: base.output_tree_id,
        ringProgramId: RING,
      });
      return { ...opened, blinding: toHex(blinding), output_hash: toHex(output) };
    });
    const vector = {
      ...base,
      first_nullifier: toHex(firstNullifier),
      inputs: base.inputs.map((entry, index) => ({
        ...entry,
        nullifier: index === 0 ? toHex(firstNullifier) : entry.nullifier,
        commitment:
          index === 0 ? toHex(input.firstInput?.hash ?? field(entry.commitment)) : toHex(ZERO_32),
      })),
      slots,
    } as Vector;
    const first = slots[0]!;
    return {
      transaction: vectorTransaction({ layout: "anonymous", vector }, input.auditor),
      layout: bound("anonymous", vector),
      commitment: field(first.output_hash),
      blinding: field(first.blinding),
      amount: BigInt(need(first.amount, "amount")),
    };
  }

  function recover(
    input: Readonly<{
      owner: ShieldedKeypair;
      auditor: X25519Keypair;
      transaction: IndexedShieldedTransaction;
      spends?: readonly IndexedShieldedTransaction[];
      nullifierKey?: ShieldedKeypair;
      assets?: AssetRegistry;
      tags?: () => ReturnType<typeof transactionsPage>;
      /** The ring's history, else the audited page. */
      history?: readonly IndexedShieldedTransaction[];
      origin?: TransactionOrigin;
    }>,
  ) {
    const page = () =>
      transactionsPage({
        data: transactionItems([input.transaction]),
      });
    const { history } = input;
    return recoverRingMemberNotes({
      client: {
        ...ringAuditReader({
          getShieldedTransactionsByTags: async (request) =>
            request.tags.length === 0 && (history !== undefined || input.spends !== undefined)
              ? transactionsPage({
                  data: transactionItems([
                    ...(history ?? []),
                    input.transaction,
                    ...(input.spends ?? []),
                  ]),
                })
              : (input.tags ?? page)(),
          solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) },
        }),
      },
      ringProgramId: RING,
      auditor: input.auditor,
      source: input.owner.shieldedAddress(),
      nullifierKey: (input.nullifierKey ?? input.owner).nullifierKey(),
      assets: input.assets ?? new AssetRegistry([[2n, FOREIGN_MINT]]),
      origin: input.origin ?? TRANSFERS,
    });
  }

  /** A ring merge spending `nullifier` first, its output encrypted for `owner`. */
  function mergeOf(
    owner: ShieldedKeypair,
    nullifier: Bytes32,
    amount = 1000n,
    mint: Address = SOL_MINT,
  ) {
    const key = owner.nullifierKey();
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const ringDataHash = new Uint8Array(32).fill(5) as Bytes32;
    const blinding = mergeOutputBlinding(key, nullifier);
    const commitment = ownerUtxoHash({
      owner: poseidon([
        owner.shieldedAddress().signingPublicKey.ownerProofInputHash(),
        key.publicKey(),
      ]),
      asset: mint,
      amount,
      blinding,
      treeId: PAIR_VECTOR.output_tree_id,
      ringDataHash,
      ringProgramId: RING,
    });
    const ciphertext = encryptMergeOutput({ amount, mint }, mergeOutputKey(key, nullifier), salt);
    const transaction: IndexedShieldedTransaction = {
      slot: 8n,
      txSignature: "6".repeat(64) as Signature,
      eventIndex: 0,
      proofless: false,
      ringProgramId: RING,
      nullifiers: [nullifier, new Uint8Array(32).fill(7) as Bytes32],
      messages: [],
      outputSlots: [
        {
          viewTag: nullifier,
          payload: encodeMergeOutputData({ salt, ciphertext, ringDataHash }),
          outputContext: {
            hash: commitment,
            tree: treeAddress(PAIR_VECTOR.output_tree_id),
            treeId: PAIR_VECTOR.output_tree_id,
            leafIndex: 9n,
          },
        },
      ],
    };
    return { transaction, commitment };
  }

  it("recovers the source's unspent ring note and drops it once a confirmed spend names its nullifier", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction, commitment, amount } = ownedTransfer(owner, auditor.publicKey());
    const recovered = await recover({ owner, auditor, transaction });
    expect(recovered.notes.map((note) => [note.outputContext.hash, note.utxo.amount])).toEqual([
      [commitment, amount],
    ]);
    expect(recovered.unopened).toEqual([]);
    const nullifier = recovered.notes[0]!.nullifier;
    const txKey = ViewingKey.fromBytes(field(PAIR_VECTOR.tx_viewing_sk));
    const salt = hex<Bytes16>(PAIR_VECTOR.salt, 16);
    const blindingSeed = ringBlindingSeed(field(PAIR_VECTOR.tx_viewing_sk), salt);
    const spendVector = {
      ...PAIR_VECTOR,
      first_nullifier: toHex(nullifier),
      slots: PAIR_VECTOR.slots.map((slot, outputIndex) => {
        const blinding = ringOutputBlinding({
          firstNullifier: nullifier,
          blindingSeed,
          outputIndex,
        });
        const output = ownerUtxoHash({
          owner: poseidon([
            solanaOwnerIdentity(field(need(slot.owner_key, "owner"))),
            field(need(slot.nullifier_pk, "nullifier")),
          ]),
          asset: encodeBase58(field(need(slot.asset_address, "asset"))),
          amount: BigInt(need(slot.amount, "amount")),
          blinding,
          treeId: PAIR_VECTOR.output_tree_id,
          ...(slot.kind === "exit" ? {} : { ringProgramId: RING }),
        });
        const secret =
          slot.kind === "exit"
            ? undefined
            : txKeySlotSecret({
                txViewingKey: txKey,
                recipientViewingKey: x25519FromU(
                  field(need("recipient_u" in slot ? slot.recipient_u : undefined, "recipient")),
                ),
                salt,
                outputIndex,
                firstNullifier: nullifier,
              });
        return {
          ...slot,
          blinding: toHex(blinding),
          output_hash: toHex(output),
          ...(secret === undefined ? {} : { slot_secret: toHex(secret) }),
        };
      }),
    } as Vector;
    const spend = {
      ...vectorTransaction({ layout: "delivered", vector: spendVector }, auditor.publicKey()),
      txSignature: "5".repeat(64) as Signature,
    };
    txKey.destroy();
    const spent = await recover({
      owner,
      auditor,
      transaction,
      spends: [spend],
    });
    expect(spent.notes).toEqual([]);
  });

  it("records a slot no registered asset rebuilds as unopened and goes on", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction } = ownedTransfer(owner, auditor.publicKey());
    const moved = new Uint8Array(32).fill(4) as Bytes32;
    const recovered = await recover({
      owner,
      auditor,
      transaction: withSlot(0, (slot) => ({
        ...slot,
        outputContext: { ...slot.outputContext, hash: moved },
      }))(transaction),
    });
    expect(recovered.notes).toEqual([]);
    expect(recovered.unopened).toEqual([moved]);
  });

  it("refuses a result past a row it could not read and stops at a failed read", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction } = ownedTransfer(owner, auditor.publicKey());
    const sealed = transaction.messages.at(-1)!;
    await expect(
      recover({
        owner,
        auditor,
        transaction: {
          ...transaction,
          messages: [{ viewTag: sealed.viewTag, data: Uint8Array.of(1) }],
        },
      }),
    ).rejects.toThrow(ringError("RING_RECOVERY_INCOMPLETE", { reason: "skipped row" }));
    const nullifier = (await recover({ owner, auditor, transaction })).notes[0]!.nullifier;
    const spend = {
      ...transaction,
      txSignature: "5".repeat(64) as Signature,
      nullifiers: [nullifier],
    };
    const spending = (code: "RING_ORIGIN_DECODE" | "RING_ORIGIN_UNAVAILABLE") =>
      recover({
        owner,
        auditor,
        transaction,
        spends: [spend],
        origin: {
          confirmedTransaction: async (row, ring) => {
            if (row.txSignature === spend.txSignature) throw new RingError(code);
            return TRANSFERS.confirmedTransaction(row, ring);
          },
        },
      });
    await expect(spending("RING_ORIGIN_DECODE")).rejects.toThrow(
      ringError("RING_RECOVERY_INCOMPLETE", {
        reason: "skipped row",
        transactionId: spend.txSignature,
      }),
    );
    await expect(spending("RING_ORIGIN_UNAVAILABLE")).rejects.toThrow(
      ringError("RING_ORIGIN_UNAVAILABLE"),
    );
  });

  it("never reads the origin of a spend another ring indexed", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction, commitment } = ownedTransfer(owner, auditor.publicKey());
    const unspent = await recover({ owner, auditor, transaction });
    const foreign = {
      ...transaction,
      txSignature: "5".repeat(64) as Signature,
      nullifiers: [unspent.notes[0]!.nullifier],
      ringProgramId: OTHER_RING,
    };
    const recovered = await recover({
      owner,
      auditor,
      transaction,
      spends: [foreign],
      origin: {
        confirmedTransaction: async (indexed, ring) => {
          if (indexed.ringProgramId !== ring) throw new Error("origin read of a foreign row");
          return TRANSFERS.confirmedTransaction(indexed, ring);
        },
      },
    });
    expect(recovered.notes.map((note) => note.outputContext.hash)).toEqual([commitment]);
  });

  it("opens the source's escrowed note and passes over another owner's", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const escrow = vectorOf("delivered", "quad_escrow");
    const { transaction, commitment } = ownedTransfer(owner, auditor.publicKey(), escrow);
    const recovered = await recover({
      owner,
      auditor,
      transaction,
      origin: {
        confirmedTransaction: async (indexed) => ({
          kind: "transfer",
          transaction: indexed,
          inputTreeIds: indexed.nullifiers.map(() => undefined),
          layout: escrow.bound,
        }),
      },
    });
    expect(recovered.notes.map((note) => note.outputContext.hash)).toEqual([commitment]);
    expect(recovered.unopened).toEqual([]);
  });

  it("opens the deposit an anonymous transfer spends and lists a merge output it cannot name", async () => {
    const auditor = X25519Keypair.generate();
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const [deposited, merged] = vector.inputs;
    if (deposited === undefined || merged === undefined) throw new Error("two spent notes");
    const depositSignature = "2".repeat(87) as Signature;
    const mergeSignature = "3".repeat(87) as Signature;
    const leaf = (input: typeof deposited, leafIndex: bigint) => ({
      hash: field(input.commitment),
      tree: treeAddress(input.input_tree_id),
      treeId: input.input_tree_id,
      leafIndex,
    });
    const sealed = sealRingDepositOpenings(
      [
        {
          ownerHash: field(deposited.owner_hash),
          blinding: field(deposited.blinding),
          ownerKey: field(vector.sender_key),
          recipientCiphertext: Uint8Array.of(1),
        },
      ],
      auditor.publicKey(),
    );
    const salt = new Uint8Array(16).fill(4) as Bytes16;
    const disclosed = sealRingMergeDisclosure(
      Array.from(
        { length: 8 },
        (_, index) => new Uint8Array(32).fill(index === 0 ? 1 : 0) as Bytes32,
      ),
      salt,
      auditor.publicKey(),
    );
    try {
      const owner = ownerUtxoHash(field(deposited.owner_hash), field(deposited.blinding));
      const deposits = ConfirmedDeposit.fromTransaction(
        confirmedDepositTransaction(RING, depositSignature, sealed.capsules, [owner]),
        depositSignature,
        0,
        RING,
      );
      const deposit: IndexedShieldedTransaction = {
        slot: 5n,
        txSignature: depositSignature,
        eventIndex: 0,
        proofless: true,
        ringProgramId: RING,
        nullifiers: [],
        messages: [],
        outputSlots: [
          {
            viewTag: new Uint8Array(32) as Bytes32,
            outputContext: leaf(deposited, 0n),
            payload: ringDepositPayload({
              ring: RING,
              ownerCommitment: owner,
              asset: encodeBase58(field(deposited.asset_address)),
              amount: BigInt(deposited.amount),
              capsule: sealed.capsules[0]!,
            }),
          },
        ],
      };
      const firstNullifier = new Uint8Array(32).fill(0x21) as Bytes32;
      const merge: IndexedShieldedTransaction = {
        slot: 6n,
        txSignature: mergeSignature,
        eventIndex: 0,
        proofless: false,
        ringProgramId: RING,
        nullifiers: [firstNullifier, new Uint8Array(32).fill(0x22) as Bytes32],
        messages: [],
        outputSlots: [
          {
            viewTag: firstNullifier,
            outputContext: leaf(merged, 1n),
            payload: encodeMergeOutputData({
              salt,
              ciphertext: encryptMergeOutput(
                {
                  amount: BigInt(merged.amount),
                  mint: encodeBase58(field(merged.asset_address)),
                },
                mergeOutputKey(ShieldedKeypair.generate().nullifierKey(), firstNullifier),
                salt,
              ),
              ringDataHash: new Uint8Array(32) as Bytes32,
            }),
          },
        ],
      };
      const disclosure = {
        ...disclosed.disclosure,
        proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
      };
      const recovered = await recover({
        owner: ShieldedKeypair.generate(),
        auditor,
        transaction: vectorTransaction(entry, auditor.publicKey()),
        history: [deposit, merge],
        origin: {
          confirmedTransaction: async (indexed) => {
            if (indexed.txSignature === depositSignature)
              return { kind: "deposit", transaction: indexed, deposits };
            if (indexed.txSignature === mergeSignature)
              return { kind: "merge", transaction: indexed, disclosure };
            return {
              kind: "transfer",
              transaction: indexed,
              inputTreeIds: indexed.nullifiers.map(() => undefined),
              layout: entry.bound,
            };
          },
        },
      });
      expect(recovered).toEqual({
        notes: [],
        unopened: [],
        unsupportedDeposits: [],
        unknownMints: [],
        unseenInputs: [field(merged.nullifier)],
      });
    } finally {
      sealed.ephemeralSecret.fill(0);
      disclosed.ephemeralSecret.fill(0);
      disclosed.disclosureKey.fill(0);
      auditor.destroy();
    }
  });

  it("reports a deposit that does not open and stops at an error no row explains", async () => {
    const auditor = X25519Keypair.generate();
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const deposited = vector.inputs[0]!;
    const signature = "2".repeat(87) as Signature;
    const sealed = sealRingDepositOpenings(
      [
        {
          ownerHash: field(deposited.owner_hash),
          blinding: field(deposited.blinding),
          ownerKey: field(vector.sender_key),
          recipientCiphertext: Uint8Array.of(1),
        },
      ],
      auditor.publicKey(),
    );
    const owner = ownerUtxoHash(field(deposited.owner_hash), field(deposited.blinding));
    const deposits = ConfirmedDeposit.fromTransaction(
      confirmedDepositTransaction(RING, signature, sealed.capsules, [owner]),
      signature,
      0,
      RING,
    );
    const deposit: IndexedShieldedTransaction = {
      slot: 5n,
      txSignature: signature,
      eventIndex: 0,
      proofless: true,
      ringProgramId: RING,
      nullifiers: [],
      messages: [],
      outputSlots: [
        {
          viewTag: new Uint8Array(32) as Bytes32,
          outputContext: {
            hash: field(deposited.commitment),
            tree: treeAddress(deposited.input_tree_id),
            treeId: deposited.input_tree_id,
            leafIndex: 0n,
          },
          payload: ringDepositPayload({
            ring: RING,
            ownerCommitment: owner,
            asset: encodeBase58(field(deposited.asset_address)),
            amount: BigInt(deposited.amount),
            capsule: sealed.capsules[0]!,
          }),
        },
      ],
    };
    const recovered = () =>
      recover({
        owner: ShieldedKeypair.generate(),
        auditor,
        transaction: vectorTransaction(entry, auditor.publicKey()),
        history: [deposit],
        origin: {
          confirmedTransaction: async (indexed) =>
            indexed.txSignature === signature
              ? { kind: "deposit", transaction: indexed, deposits }
              : {
                  kind: "transfer",
                  transaction: indexed,
                  inputTreeIds: indexed.nullifiers.map(() => undefined),
                  layout: entry.bound,
                },
        },
      });
    const authenticate = vi.spyOn(ConfirmedDeposit.prototype, "authenticate");
    try {
      authenticate.mockImplementation(() => {
        throw new RingError("RING_AUDIT_MESSAGE");
      });
      await expect(recovered()).resolves.toMatchObject({
        unsupportedDeposits: [field(deposited.commitment)],
      });
      const bug = new TypeError("no row explains it");
      authenticate.mockImplementation(() => {
        throw bug;
      });
      await expect(recovered()).rejects.toBe(bug);
    } finally {
      vi.restoreAllMocks();
      sealed.ephemeralSecret.fill(0);
    }
  });

  it("follows a spend into the merge that folded the note and recovers the merged output", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction } = ownedTransfer(owner, auditor.publicKey());
    const unspent = await recover({ owner, auditor, transaction });
    const merge = mergeOf(owner, unspent.notes[0]!.nullifier);
    const origin: TransactionOrigin = {
      confirmedTransaction: async (indexed, ring) =>
        indexed.txSignature === merge.transaction.txSignature
          ? { kind: "merge", transaction: indexed }
          : TRANSFERS.confirmedTransaction(indexed, ring),
    };
    const merged = await recover({
      owner,
      auditor,
      transaction,
      spends: [merge.transaction],
      origin,
    });
    expect(merged.notes.map((note) => [note.outputContext.hash, note.utxo.amount])).toEqual([
      [merge.commitment, 1000n],
    ]);
    expect(merged.unopened).toEqual([]);
  });

  it("recovers a complete merge from its inputs when the native ciphertext is invalid", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction, commitment, amount } = ownedTransfer(owner, auditor.publicKey());
    const unspent = await recover({ owner, auditor, transaction });
    const merge = mergeOf(owner, unspent.notes[0]!.nullifier, amount);
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const { disclosure, ephemeralSecret, disclosureKey } = sealRingMergeDisclosure(
      [commitment, ...Array.from({ length: 7 }, () => ZERO_32)],
      salt,
      auditor.publicKey(),
    );
    const invalid = {
      ...merge.transaction,
      outputSlots: merge.transaction.outputSlots.map((slot) => ({
        ...slot,
        payload: encodeMergeOutputData({
          salt,
          ciphertext: [new Uint8Array(32).fill(255) as Bytes32, ZERO_32, ZERO_32],
          ringDataHash: new Uint8Array(32).fill(5) as Bytes32,
        }),
      })),
    };
    const origin: TransactionOrigin = {
      confirmedTransaction: async (indexed, ring) =>
        indexed.txSignature === invalid.txSignature
          ? {
              kind: "merge",
              transaction: indexed,
              disclosure: { ...disclosure, proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH) },
            }
          : TRANSFERS.confirmedTransaction(indexed, ring),
    };
    try {
      const result = await recover({ owner, auditor, transaction, history: [invalid], origin });
      expect(result.notes.map((note) => [note.outputContext.hash, note.utxo.amount])).toEqual([
        [merge.commitment, amount],
      ]);
      expect(result.unopened).toEqual([]);
      const wrong = {
        ...invalid,
        outputSlots: invalid.outputSlots.map((slot) => ({
          ...slot,
          outputContext: { ...slot.outputContext, hash: field("01".repeat(32)) },
        })),
      };
      const refused = await recover({ owner, auditor, transaction, history: [wrong], origin });
      expect(refused.notes).toEqual([]);
      expect(refused.unopened).toEqual([wrong.outputSlots[0]!.outputContext.hash]);
    } finally {
      ephemeralSecret.fill(0);
      disclosureKey.fill(0);
      auditor.destroy();
    }
  });

  it("reads an unknown merge mint from valid native bytes and retains a bad-body opening", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const source = anonymousTransfer({ owner, auditor: auditor.publicKey(), mint: FOREIGN_MINT });
    const nullifier = owner.nullifierKey().nullifier(source.commitment, source.blinding);
    const merge = mergeOf(owner, nullifier, source.amount, FOREIGN_MINT);
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const sealed = sealRingMergeDisclosure(
      [source.commitment, ...Array.from({ length: 7 }, () => ZERO_32)],
      salt,
      auditor.publicKey(),
    );
    try {
      for (const validBody of [true, false]) {
        const transaction = validBody
          ? merge.transaction
          : {
              ...merge.transaction,
              outputSlots: merge.transaction.outputSlots.map((slot) => ({
                ...slot,
                payload: encodeMergeOutputData({
                  salt,
                  ciphertext: [new Uint8Array(32).fill(255) as Bytes32, ZERO_32, ZERO_32],
                  ringDataHash: new Uint8Array(32).fill(5) as Bytes32,
                }),
              })),
            };
        const result = await recover({
          owner,
          auditor,
          transaction: source.transaction,
          history: [transaction],
          assets: new AssetRegistry(),
          origin: {
            confirmedTransaction: async (row) =>
              row.txSignature === transaction.txSignature
                ? {
                    kind: "merge",
                    transaction: row,
                    disclosure: {
                      ...sealed.disclosure,
                      proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
                    },
                  }
                : {
                    kind: "transfer",
                    transaction: row,
                    layout: source.layout,
                    inputTreeIds: row.nullifiers.map(() => undefined),
                  },
          },
        });
        expect(result.notes).toEqual([]);
        expect(result.unopened).toEqual([merge.commitment]);
        expect(result.unknownMints).toEqual(validBody ? [FOREIGN_MINT] : []);
      }
    } finally {
      sealed.ephemeralSecret.fill(0);
      sealed.disclosureKey.fill(0);
      auditor.destroy();
    }
  });

  it("refreshes unseen inputs after recovering a native merge from complete deposit history", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const source = ownedTransfer(owner, auditor.publicKey());
    const blinding = field(PAIR_VECTOR.slots[0]!.blinding);
    const sealed = sealRingDepositOpenings(
      [
        {
          ownerHash: owner.ownerHash(),
          blinding,
          ownerKey: owner.shieldedAddress().confidentialViewTag(),
          recipientCiphertext: Uint8Array.of(1),
        },
      ],
      auditor.publicKey(),
    );
    const signature = "2".repeat(87) as Signature;
    const ownerCommitment = ownerUtxoHash(owner.ownerHash(), blinding);
    const deposits = ConfirmedDeposit.fromTransaction(
      confirmedDepositTransaction(RING, signature, sealed.capsules, [ownerCommitment]),
      signature,
      0,
      RING,
    );
    const deposit: IndexedShieldedTransaction = {
      slot: 5n,
      txSignature: signature,
      eventIndex: 0,
      proofless: true,
      ringProgramId: RING,
      nullifiers: [],
      messages: [],
      outputSlots: [
        {
          viewTag: ZERO_32,
          outputContext: source.transaction.outputSlots[0]!.outputContext,
          payload: ringDepositPayload({
            ring: RING,
            ownerCommitment,
            asset: SOL_MINT,
            amount: source.amount,
            capsule: sealed.capsules[0]!,
          }),
        },
      ],
    };
    const merge = mergeOf(
      owner,
      owner.nullifierKey().nullifier(source.commitment, blinding),
      source.amount,
    );
    const mergedBlinding = mergeOutputBlinding(
      owner.nullifierKey(),
      merge.transaction.nullifiers[0]!,
    );
    const spend = anonymousTransfer({
      owner: ShieldedKeypair.generate(),
      auditor: auditor.publicKey(),
      mint: SOL_MINT,
      firstInput: {
        hash: merge.commitment,
        nullifier: owner.nullifierKey().nullifier(merge.commitment, mergedBlinding),
      },
    });
    try {
      const result = await recover({
        owner,
        auditor,
        transaction: spend.transaction,
        history: [deposit, merge.transaction],
        origin: {
          confirmedTransaction: async (transaction) =>
            transaction.txSignature === signature
              ? { kind: "deposit", transaction, deposits }
              : transaction.txSignature === merge.transaction.txSignature
                ? { kind: "merge", transaction }
                : {
                    kind: "transfer",
                    transaction,
                    layout: spend.layout,
                    inputTreeIds: transaction.nullifiers.map(() => undefined),
                  },
        },
      });
      expect(result.notes).toEqual([]);
      expect(result.unopened).toEqual([]);
      expect(result.unseenInputs).toEqual([]);
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("refuses another nullifier key, an output the auditor cannot open and a scan the page cap cuts", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction } = ownedTransfer(owner, auditor.publicKey());
    await expect(
      recover({
        owner,
        auditor,
        transaction,
        nullifierKey: ShieldedKeypair.generate(),
      }),
    ).rejects.toThrow(ringError("RING_NULLIFIER_KEY_MISMATCH"));
    const moved = withSlot(1, (slot) => ({
      ...slot,
      outputContext: {
        ...slot.outputContext,
        hash: field(PAIR_VECTOR.slots[0]!.output_hash),
      },
    }))(transaction);
    await expect(recover({ owner, auditor, transaction: moved })).rejects.toThrow(
      ringError("RING_AUDIT_OUTPUT_MISMATCH", {
        reason: "unopened",
        slotIndex: 1,
      }),
    );
    let page = 0;
    const endless = () => transactionsPage({ paginationToken: `t${++page}` });
    await expect(recover({ owner, auditor, transaction, tags: endless })).rejects.toThrow(
      ringError("RING_RECOVERY_INCOMPLETE"),
    );
  });
});
