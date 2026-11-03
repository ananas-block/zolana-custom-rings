import { describe, expect, it } from "vitest";

import prefixAssignment from "../../../../../test-vectors/audit/prefix-assignment.json" with { type: "json" };
import { initializePoseidon, SOL_MINT } from "@heliuslabs/zolana";
import {
  BN254_SCALAR_ORDER,
  Writer,
  addressBytes,
  bigIntToBytes,
  clampViewingSecret,
  concatBytes,
  encodeBase58,
  hashBytes,
  hashChain4,
  treeAddress,
  u64be,
  writeTreeContext,
} from "@heliuslabs/zolana/internal";
import {
  SPP_SUPPORTED_SHAPES,
  type Bytes16,
  type Bytes32,
  type Bytes33,
} from "@heliuslabs/zolana/interface";
import { ViewingKey, X25519Keypair, symmetricApply } from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  type IndexedShieldedTransaction,
  type OutputSlot,
} from "@heliuslabs/zolana/transaction";

import {
  auditSharedSecret,
  auditorMessageData,
  sealAuditorStream,
  sealMergeDisclosureFields,
} from "../../../src/crypto/audit/audit.js";
import { writeRingMergeDisclosure } from "../../../src/crypto/audit/merge-disclosure.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../../src/crypto/derivation/blinding.js";
import { TRANSFER_STATEMENT_VERSION } from "../../../src/crypto/derivation/ring-domain.js";
import { ringIdField } from "../../../src/crypto/derivation/ring-stream.js";
import {
  knownUtxoHash,
  openedUtxo,
  type AuditedUtxo,
  type KnownUtxo,
} from "../../../src/operations/audit/audit.js";
import { dummyUtxoHash } from "../../../src/protocol/membership/utxo-hash.js";
import {
  HISTORICAL_TRANSFER_STATEMENT_VERSION,
  HistoricalTransactData,
  PrefixedUtxoIndex,
  assignPrefixedInputs,
  anonymousAuditKey,
  confidentialAuditKey,
  decodeDisclosure,
  historicalCoverageRow,
  historicalMergeFieldCount,
  historicalStatementElements,
  historicalStatementHash,
  historicalTransferStatement,
  inputPrefix,
  landedHistoricalRail,
  openHistoricalMerge,
  openHistoricalRingTransfer,
  type AuditStreamLayout,
} from "../../../src/protocol/historical/index.js";
import { recordRegion } from "../../../src/protocol/historical/layout.js";

const RING = encodeBase58(new Uint8Array(32).fill(0x0b));
const TREE_ID = 3;
const TX_SECRET = clampViewingSecret(new Uint8Array(32).fill(0x48) as Bytes32);
const SALT = new Uint8Array(16).fill(0x50) as Bytes16;
const FIRST_NULLIFIER = field(0x70);
const TREE_CONTEXT = Object.freeze({ utxoTreeRootIndex: 1, nullifierTreeRootIndex: 2 });

function field(byte: number): Bytes32 {
  const out = new Uint8Array(32).fill(byte);
  out[0] = 0;
  return out as Bytes32;
}

function hashOf(byte: number): Bytes32 {
  const out = new Uint8Array(32).fill(byte);
  out[0] = 1;
  return out as Bytes32;
}

function hex(value: string): Bytes32 {
  return Uint8Array.from(Buffer.from(value, "hex")) as Bytes32;
}

function prefixOf(hash: Bytes32) {
  const prefix = inputPrefix(hash);
  if (prefix === undefined) throw new Error("hash without a prefix");
  return prefix;
}

/** The anonymous rail's historical frame without its tag, a slot body under a `u16` length. */
function anonymousFrame(
  input: Readonly<{
    txViewingU: Bytes32;
    slots: readonly Readonly<{ hash: Bytes32; tag: Bytes32; body?: Uint8Array }>[];
    sender: Uint8Array;
    ephU: Bytes32;
    envelope: Uint8Array;
    records: readonly Uint8Array[];
    nullifiers: readonly Bytes32[];
    fullOpenings?: boolean;
  }>,
): Uint8Array {
  const shape = SPP_SUPPORTED_SHAPES.findIndex(
    (candidate) => candidate.inputs === 2 && candidate.outputs === input.slots.length,
  );
  const out = new Writer()
    .u8(0, "flags")
    .u8(shape, "shape")
    .u8(input.nullifiers.length | (input.fullOpenings === true ? 1 << 7 : 0), "inputs")
    .bytes(new Uint8Array(192))
    .u32(1_000, "expiry")
    .bytes(input.txViewingU)
    .bytes(SALT)
    .u8(0, "transfers")
    .u8(0, "exits");
  for (const slot of input.slots) {
    out
      .bytes(slot.hash)
      .bytes(slot.tag)
      .u16(slot.body?.length ?? 0, "body");
    if (slot.body !== undefined) out.bytes(slot.body);
  }
  out.bytes(field(0x31)).u16(input.sender.length, "sender").bytes(input.sender);
  out.bytes(input.ephU).bytes(input.envelope);
  for (const record of input.records) out.bytes(record);
  out.bytes(field(0x32)).bytes(field(0x33)).bytes(field(0x34)).bytes(new Uint8Array(128));
  for (const nullifier of input.nullifiers) out.bytes(nullifier);
  writeTreeContext(out, TREE_CONTEXT);
  return out.finish();
}

function plainFrame(): Uint8Array {
  return anonymousFrame({
    txViewingU: field(0x20),
    slots: [
      { hash: field(0x21), tag: field(0x22) },
      { hash: field(0x23), tag: field(0x24), body: new Uint8Array(40).fill(9) },
    ],
    sender: new Uint8Array(80).fill(7),
    ephU: field(0x25),
    envelope: new Uint8Array(80).fill(3),
    records: [new Uint8Array(104).fill(1), new Uint8Array(104).fill(2)],
    nullifiers: [FIRST_NULLIFIER, field(0x71)],
  });
}

await initializePoseidon();

describe("historical key catalog", () => {
  it("keeps the frozen input class per output count", () => {
    const classes = (key: (outputs: number) => { class: number } | undefined) =>
      [2, 4, 8, 16].map((outputs) => key(outputs)?.class);
    expect(classes((outputs) => confidentialAuditKey(outputs, false))).toEqual([32, 24, 16, 5]);
    const anonymous = (spendsDefaultRing: boolean) =>
      classes((outputs) => anonymousAuditKey({ inputs: 1, outputs, spendsDefaultRing }));
    expect(anonymous(false)).toEqual([24, 16, 5, undefined]);
    expect(anonymous(true)).toEqual([8, 8, 2, undefined]);
    expect(anonymousAuditKey({ inputs: 3, outputs: 8, spendsDefaultRing: true })).toBeUndefined();
  });
});

describe("historical frame", () => {
  it("parses the old anonymous slots, its optional body and its sender bundle", () => {
    const data = HistoricalTransactData.parse(plainFrame(), "anonymous");
    expect(
      data.outputs.map((output) => output.kind === "anonymous" && output.body?.length),
    ).toEqual([undefined, 40]);
    expect(data.sender?.body).toEqual(new Uint8Array(80).fill(7));
    expect(HistoricalTransactData.streamLayout(data)).toEqual({
      key: { kind: "commitment", class: 24 },
      keyEscrow: false,
      inputs: 2,
      outputs: 2,
      exits: 0n,
    });
    expect(HistoricalTransactData.recipients(data)).toEqual([
      new Uint8Array(32),
      new Uint8Array(32),
    ]);
    expect(HistoricalTransactData.outputCiphertexts(data).map((record) => record[0])).toEqual([
      1, 2,
    ]);
  });

  it("refuses trailing bytes", () => {
    expect(() =>
      HistoricalTransactData.parse(Uint8Array.of(...plainFrame(), 0), "anonymous"),
    ).toThrow("RING_TRANSACT_DATA_INVALID");
  });

  it("names the two old tags alone", () => {
    expect(landedHistoricalRail(Uint8Array.of(43, 0), true)).toBe("anonymous");
    expect(landedHistoricalRail(Uint8Array.of(43, 1 << 3), true)).toBe("confidential");
    expect(landedHistoricalRail(Uint8Array.of(44, 0), false)).toBe("delegate");
    expect(() => landedHistoricalRail(Uint8Array.of(45, 0), false)).toThrow(
      "RING_TRANSACT_DATA_INVALID",
    );
  });
});

describe("historical prefixes", () => {
  it("assigns the prefix vector", () => {
    const utxo = {} as KnownUtxo;
    for (const vector of prefixAssignment.cases) {
      const notes = vector.notes.map((commitment) => ({ commitment: hex(commitment), utxo }));
      const prefix = prefixOf(notes[0]!.commitment);
      const candidates = notes.map(({ commitment }) => commitment);
      const expected = {
        opened: [{ kind: "opened", ring: { kind: "ring", commitment: notes[0]!.commitment } }],
        ambiguous: Array(vector.inputs).fill({ kind: "ambiguous", candidates }),
        unseen: Array(vector.inputs).fill({ kind: "unseen", prefix }),
      }[vector.expected];
      expect(
        assignPrefixedInputs(Array(vector.inputs).fill(prefix), () => notes),
        vector.name,
      ).toMatchObject(expected ?? []);
    }
  });

  const commitmentLayout: AuditStreamLayout = {
    key: { kind: "commitment", class: 16 },
    keyEscrow: false,
    inputs: 3,
    outputs: 4,
    exits: 0n,
  };
  const records = [0, 1, 2, 3].map(() => new Uint8Array(104));
  const evidence = (first: Uint8Array, second: Uint8Array, third: Uint8Array): Uint8Array =>
    concatBytes(first, second, third);

  it("reads spent UTXO 0 by its hash and every later one by its prefix", () => {
    const opened = decodeDisclosure(commitmentLayout, {
      evidence: evidence(hashOf(0x60), hashOf(0x61).subarray(0, 16), new Uint8Array(16)),
      records,
    });
    expect(opened.inputs).toEqual({
      kind: "commitments",
      first: hashOf(0x60),
      prefixes: [prefixOf(hashOf(0x61)), undefined],
    });
  });

  it("refuses spent UTXO 0 as a dummy and a prefix no canonical hash has", () => {
    const zeros = new Uint8Array(16);
    expect(() =>
      decodeDisclosure(commitmentLayout, {
        evidence: evidence(new Uint8Array(32), zeros, zeros),
        records,
      }),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(() =>
      decodeDisclosure(commitmentLayout, {
        evidence: evidence(hashOf(0x60), new Uint8Array(16).fill(0xff), zeros),
        records,
      }),
    ).toThrow("KEYPAIR_DISCLOSURE_FIELD");
  });

  it("reads a prefix at the modulus prefix and no zero prefix", () => {
    expect(inputPrefix(bigIntToBytes(BN254_SCALAR_ORDER - 1n) as Bytes32)).toBe(
      BN254_SCALAR_ORDER >> 128n,
    );
    expect(inputPrefix(bigIntToBytes(BN254_SCALAR_ORDER) as Bytes32)).toBeUndefined();
    const short = new Uint8Array(32) as Bytes32;
    short[16] = 1;
    expect(inputPrefix(short)).toBeUndefined();
  });
});

describe("historical statement", () => {
  it("closes with version 2 and hashes apart from version 3", () => {
    const zero = new Uint8Array(32) as Bytes32;
    const statement = historicalTransferStatement(
      HistoricalTransactData.parse(plainFrame(), "anonymous"),
      {
        ringId: field(0x41),
        auditorPubkey: new Uint8Array(33).fill(4) as Bytes33,
        keyEscrow: false,
        sender: zero,
        partyIdentities: [zero, zero, zero],
        roots: { policyHash: zero, ownRoot: zero, curatorRoot: zero },
        publicAssets: [zero, zero, zero],
        publicAmounts: [zero, zero, zero],
        publicGross: [zero, zero, zero],
        withdrawalHash: zero,
      },
    );
    const elements = historicalStatementElements(statement);
    const version = (value: bigint) => bigIntToBytes(value) as Bytes32;
    expect(HISTORICAL_TRANSFER_STATEMENT_VERSION).not.toBe(TRANSFER_STATEMENT_VERSION);
    expect(elements.at(-1)).toEqual(version(2n));
    expect(hashChain4([...elements.slice(0, -1), version(TRANSFER_STATEMENT_VERSION)])).not.toEqual(
      historicalStatementHash(statement),
    );
  });
});

describe("historical merge", () => {
  it("opens the old header and its commitments from the old frame", () => {
    const auditor = X25519Keypair.generate();
    const ephemeral = X25519Keypair.generate();
    const disclosureKey = field(0x11);
    const inputCommitments = Array.from({ length: 8 }, (_, index) => field(0x80 + index));
    const nullifierPublicKey = field(0x12);
    const outputBlinding = field(0x13);
    const owner = encodeBase58(new Uint8Array(32).fill(0xa1));
    const plaintext = new Uint8Array(historicalMergeFieldCount(8) * 31);
    plaintext.set(addressBytes(owner), 0);
    plaintext.set(nullifierPublicKey, 32);
    plaintext.set(addressBytes(SOL_MINT), 64);
    plaintext.set(u64be(55n), 96);
    plaintext.set(outputBlinding, 104);
    inputCommitments.forEach((commitment, index) => plaintext.set(commitment, 136 + 32 * index));
    const shared = auditSharedSecret(
      ephemeral.ecdh(auditor.publicKey()),
      ephemeral.publicKey(),
      auditor.publicKey(),
    );
    const out = new Writer().u8(20, "tag").bytes(new Uint8Array(8)).bytes(field(0x14));
    writeRingMergeDisclosure(out, {
      proof: new Uint8Array(192),
      ephemeralPublicKey: ephemeral.publicKey().toBytes(),
      ciphertext: symmetricApply(
        shared,
        new TextEncoder().encode("CRING/mrg1"),
        disclosureKey,
      ) as Bytes32,
      fields: sealMergeDisclosureFields(disclosureKey, SALT, plaintext),
    });
    out.bytes(new Uint8Array(64).fill(0xee));
    expect(openHistoricalMerge(auditor, out.finish(), SALT)).toEqual({
      ownerKey: owner,
      nullifierPublicKey,
      mint: SOL_MINT,
      amount: 55n,
      outputBlinding,
      inputCommitments,
    });
  });
});

describe("historical transfer audit", () => {
  const assets = new AssetRegistry();
  const ownerKey = new Uint8Array(32).fill(0xb5) as Bytes32;
  const nullifierPk = field(0x25);
  const asset = hashBytes(addressBytes(SOL_MINT)) as Bytes32;
  const ringId = (): Bytes32 => ringIdField(RING);
  const utxoOf = (amount: bigint, blinding: Bytes32): AuditedUtxo => ({
    ownerKey,
    nullifierPk,
    asset,
    mint: SOL_MINT,
    amount,
    blinding,
    dataHash: new Uint8Array(32) as Bytes32,
    ringDataHash: new Uint8Array(32) as Bytes32,
  });
  const noteOf = (amount: bigint, byte: number) => {
    const utxo = openedUtxo(utxoOf(amount, field(byte)), TREE_ID);
    return { commitment: knownUtxoHash(utxo, ringId()), utxo };
  };

  const commitmentEvidence = (first: Bytes32, later: Bytes32): Uint8Array =>
    concatBytes(first, later.subarray(0, 16));

  function transfer(auditor: X25519Keypair, evidence: Uint8Array, fullOpenings = false) {
    const txKey = ViewingKey.fromBytes(new Uint8Array(TX_SECRET) as Bytes32);
    const blindingSeed = ringBlindingSeed(TX_SECRET, SALT);
    const blinding = (outputIndex: number): Bytes32 =>
      ringOutputBlinding({ firstNullifier: FIRST_NULLIFIER, blindingSeed, outputIndex });
    const hashes = [
      knownUtxoHash(openedUtxo(utxoOf(70n, blinding(0)), TREE_ID), ringId()),
      dummyUtxoHash(TREE_ID, blinding(1)),
    ];
    const layout: AuditStreamLayout = {
      key: fullOpenings ? { kind: "entry", class: 8 } : { kind: "commitment", class: 24 },
      keyEscrow: false,
      inputs: 2,
      outputs: 2,
      exits: 0n,
    };
    const sealed = sealAuditorStream({
      auditorPublicKey: auditor.publicKey(),
      envelope: concatBytes(TX_SECRET, evidence),
      records: [concatBytes(ownerKey, asset, u64be(70n), nullifierPk), new Uint8Array(104)].map(
        (bytes, slot) => ({ counter: recordRegion(layout, slot).startCounter, bytes }),
      ),
    });
    const message = auditorMessageData(sealed, auditor.publicKey());
    const slots = hashes.map((hash, index) => ({ hash, tag: field(0x90 + index) }));
    const nullifiers = [FIRST_NULLIFIER, field(0x71)];
    const instruction = Uint8Array.of(
      43,
      ...anonymousFrame({
        txViewingU: txKey.publicKey().u(),
        slots,
        sender: new Uint8Array(80).fill(7),
        ephU: sealed.ephemeralPublicKey.u(),
        envelope: sealed.envelope,
        records: sealed.records,
        nullifiers,
        fullOpenings,
      }),
    );
    const outputSlots: OutputSlot[] = slots.map((slot, index) => ({
      viewTag: slot.tag,
      outputContext: {
        hash: slot.hash,
        tree: treeAddress(TREE_ID),
        treeId: TREE_ID,
        leafIndex: BigInt(index),
      },
      payload: Uint8Array.of(9),
    }));
    const transaction: IndexedShieldedTransaction = {
      slot: 7n,
      txSignature: "1".repeat(64) as IndexedShieldedTransaction["txSignature"],
      eventIndex: 2,
      txViewingPublicKey: txKey.publicKey(),
      salt: SALT,
      outputSlots,
      messages: [message],
      nullifiers,
      proofless: false,
      ringProgramId: RING,
    };
    return { transaction, instruction };
  }

  it("opens old slots and assigns an old prefix, nothing left for coverage", () => {
    const auditor = X25519Keypair.generate();
    const first = noteOf(30n, 0x51);
    const later = noteOf(40n, 0x52);
    const { transaction, instruction } = transfer(
      auditor,
      commitmentEvidence(first.commitment, later.commitment),
    );
    const opened = openHistoricalRingTransfer({
      auditor,
      transaction,
      assets,
      instruction,
      sppAnonymous: true,
      known: new PrefixedUtxoIndex([first, later]),
    });
    expect(opened.payloadErrors).toEqual([]);
    expect(opened.outputs.map(({ opening }) => opening.kind)).toEqual(["ring", "dummy"]);
    expect(opened.sender).toEqual({ ownerKey, nullifierPk });
    expect(opened.inputs.map(({ opening }) => opening)).toMatchObject([
      { kind: "opened", ring: { commitment: first.commitment } },
      { kind: "opened", ring: { commitment: later.commitment } },
    ]);
    expect(historicalCoverageRow(transaction, opened)).toBeUndefined();
  });

  it("opens entry evidence and tells its ring by a known commitment", () => {
    const auditor = X25519Keypair.generate();
    const blinding = field(0x51);
    const spent = noteOf(30n, 0x51);
    const { transaction, instruction } = transfer(
      auditor,
      concatBytes(ownerKey, nullifierPk, u64be(30n), asset, blinding, new Uint8Array(72)),
      true,
    );
    const opened = openHistoricalRingTransfer({
      auditor,
      transaction,
      assets,
      instruction,
      sppAnonymous: true,
      inputTreeIds: [TREE_ID, TREE_ID],
      known: new PrefixedUtxoIndex([spent]),
    });
    expect(opened.sender).toEqual({ ownerKey, nullifierPk });
    expect(opened.inputs.map(({ opening }) => opening)).toEqual([
      {
        kind: "opened",
        asset,
        mint: SOL_MINT,
        amount: 30n,
        blinding,
        ring: { kind: "ring", commitment: spent.commitment },
      },
      { kind: "dummy" },
    ]);
    expect(historicalCoverageRow(transaction, opened)).toBeUndefined();
  });

  it("reports a prefix without a note as a historical coverage row", () => {
    const auditor = X25519Keypair.generate();
    const first = noteOf(30n, 0x51);
    const later = noteOf(40n, 0x52);
    const { transaction, instruction } = transfer(
      auditor,
      commitmentEvidence(first.commitment, later.commitment),
    );
    const opened = openHistoricalRingTransfer({
      auditor,
      transaction,
      assets,
      instruction,
      sppAnonymous: true,
      known: new PrefixedUtxoIndex([first]),
    });
    expect(opened.inputs[1]?.opening).toEqual({
      kind: "unseen",
      prefix: prefixOf(later.commitment),
    });
    expect(historicalCoverageRow(transaction, opened)).toEqual({
      slot: 7n,
      txSignature: transaction.txSignature,
      eventIndex: 2,
      reason: "historicalPrefix",
      inputs: [],
    });
  });
});
