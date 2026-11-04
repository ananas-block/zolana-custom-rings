import { readFileSync } from "node:fs";
import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it, vi } from "vitest";

import mergeVector from "../../../../../test-vectors/merge/merge_v4.json" with { type: "json" };
import {
  wireDecoder,
  treeAddress,
  mergeOutputBlinding,
  mergeOutputKey,
  poseidon,
  encodeMergeOutputData,
  encryptMergeOutput,
  encodeBase58,
  seededMergeDummyNullifier,
  seededMergeOutputBlinding,
  addressBytes,
  equalBytes,
  hashBytes,
  BN254_SCALAR_ORDER,
  bigIntToBytes,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes16, Bytes31, Bytes32, Bytes33, Signature } from "@heliuslabs/zolana/interface";
import { NullifierKey, X25519Keypair } from "@heliuslabs/zolana/keypair";
import { SOL_MINT, ownerUtxoHash } from "@heliuslabs/zolana/transaction";
import type { IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";
import {
  auditRingMerges,
  classifyMergeNullifier,
  openRingMerge,
  recoverMergeOpening,
} from "../../../src/operations/audit/audit-merge.js";
import { knownUtxoHash, type KnownUtxos } from "../../../src/operations/audit/audit.js";
import {
  MergeRingAuthority,
  sealMergeRecord,
  type SealedMergeRecord,
} from "../../../src/crypto/audit/merge-disclosure.js";
import { ringIdField } from "../../../src/crypto/derivation/ring-stream.js";
import { RecordKind, type AuditRecord } from "../../../src/protocol/codec/audit-stream.js";
import { auditRingMergesV3 } from "../../../src/protocol/historical/v3/audit.js";
import { sealRingMergeDisclosure } from "../../../src/protocol/historical/v3/merge-disclosure.js";
import { RingError } from "../../../src/protocol/error.js";
import type { TransactionOrigin } from "../../../src/protocol/transaction/origin.js";
import {
  kitReads,
  solanaRpcReads,
  transactionsPage,
} from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { transactionItems } from "../../../../../zolana/sdk-libs/ts/test/helpers/pages.js";

await initializePoseidon();

const decode = wireDecoder((path) => new Error(`merge fixture ${path}`));
/** The Rust client's confirmed `merge_ring` event, its output opens under no fixture key. */
const fixture = decode.record(
  JSON.parse(
    readFileSync(
      new URL("../../../../client/tests/fixtures/confirmed-merge-event.json", import.meta.url),
      "utf8",
    ),
  ),
  "fixture",
);
const expected = decode.record(fixture["expected"], "expected");
const ring = decode.address(fixture["ring"], "ring");
const SIGNATURE = "5".repeat(87) as Signature;

function bytes(value: unknown): Uint8Array {
  const text = decode.string(value, "hex");
  if (!/^(?:[a-f0-9]{2})*$/u.test(text)) throw new Error("fixture hex");
  return Uint8Array.from(Buffer.from(text, "hex"));
}

function field(value: unknown): Bytes32 {
  const result = bytes(value);
  if (result.length !== 32) throw new Error("fixture field");
  return result as Bytes32;
}

const output = decode.record(decode.list(expected["outputs"], "outputs")[0], "output");
const TREE_ID = Number(decode.integer(output["treeId"], "treeId"));
const UNOPENED: IndexedShieldedTransaction = {
  slot: 7n,
  txSignature: SIGNATURE,
  eventIndex: 0,
  proofless: false,
  ringProgramId: ring,
  nullifiers: decode.list(expected["nullifiersHex"], "nullifiers").map(field),
  messages: [],
  outputSlots: [
    {
      viewTag: field(output["viewTagHex"]),
      payload: bytes(output["payloadHex"]),
      outputContext: {
        hash: field(output["hashHex"]),
        tree: treeAddress(TREE_ID),
        treeId: TREE_ID,
        leafIndex: decode.integer(output["leafIndex"], "leafIndex"),
      },
    },
  ],
};

const OWNER_MEMBER = new Uint8Array(32).fill(23) as Bytes32;

function memberOf(index: number): Bytes32 {
  const value = new Uint8Array(32);
  value[30] = index >> 8;
  value[31] = index & 0xff;
  return value as Bytes32;
}

/** Every transaction is a tag 18 merge, the binding is the origin tests' concern. */
const MERGES: TransactionOrigin = {
  confirmedTransaction: async (transaction) => ({
    kind: "historicalMerge",
    transaction,
    instruction: Uint8Array.of(20),
  }),
};

const EMPTY_DISCLOSURE = {
  proof: new Uint8Array(192),
  ephemeralPublicKey: new Uint8Array(33) as Bytes33,
  ciphertext: new Uint8Array(32) as Bytes32,
  fields: [],
};

/** A ring merge whose output the member's escrowed key opens. */
function escrowedMerge(input: Readonly<{ member: Bytes32; key: NullifierKey }>) {
  const firstNullifier = memberOf(0x77);
  const salt = new Uint8Array(16).fill(3) as Bytes16;
  const ringDataHash = memberOf(0x55);
  const amount = 9n;
  const blinding = mergeOutputBlinding(input.key, firstNullifier);
  const commitment = ownerUtxoHash({
    owner: poseidon([input.member, input.key.publicKey()]),
    asset: SOL_MINT,
    amount,
    blinding,
    treeId: TREE_ID,
    ringDataHash,
    ringProgramId: ring,
  });
  const ciphertext = encryptMergeOutput(
    { amount, mint: SOL_MINT },
    mergeOutputKey(input.key, firstNullifier),
    salt,
  );
  const transaction: IndexedShieldedTransaction = {
    ...UNOPENED,
    txSignature: "6".repeat(87) as Signature,
    nullifiers: [firstNullifier, memberOf(0x78)],
    outputSlots: [
      {
        viewTag: firstNullifier,
        payload: encodeMergeOutputData({ salt, ciphertext, ringDataHash }),
        outputContext: {
          ...UNOPENED.outputSlots[0]!.outputContext,
          hash: commitment,
        },
      },
    ],
  };
  return { transaction, commitment, blinding, ringDataHash, amount, salt };
}

function scanClient(input: Readonly<{ transactions: readonly IndexedShieldedTransaction[][] }>) {
  const transactionPages = vi.fn(async (request: { paginationToken?: string }) => {
    const at = request.paginationToken === undefined ? 0 : Number(request.paginationToken);
    const last = at + 1 === input.transactions.length;
    return transactionsPage({
      data: transactionItems(input.transactions[at] ?? []),
      paginationToken: last ? null : String(at + 1),
    });
  });
  return {
    client: {
      ...kitReads({ solanaRpc: solanaRpcReads({}) }),
      getShieldedTransactionsByTags: transactionPages,
    },
    transactionPages,
  };
}

describe("auditRingMerges", () => {
  it("walks every history page and leaves a merge without a disclosure to the historical reader", async () => {
    const auditor = X25519Keypair.generate();
    const { client, transactionPages } = scanClient({
      transactions: [[UNOPENED], []],
    });
    const result = await auditRingMerges({
      client,
      ringProgramId: ring,
      auditor,
      origin: MERGES,
    });
    expect(transactionPages).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({ merges: [], skipped: [] });
    expect(result.historical).toEqual([
      { slot: UNOPENED.slot, signature: SIGNATURE, eventIndex: 0 },
    ]);
    expect(result.nextCursor).toBeUndefined();
  });

  it("refuses a merge read twice", async () => {
    const auditor = X25519Keypair.generate();
    const twice = scanClient({ transactions: [[UNOPENED], [UNOPENED]] });
    await expect(
      auditRingMergesV3({
        client: twice.client,
        ringProgramId: ring,
        auditor,
        origin: {
          confirmedTransaction: async (transaction) => ({
            kind: "historicalMergeV3",
            transaction,
            disclosure: EMPTY_DISCLOSURE,
          }),
        },
      }),
    ).rejects.toMatchObject({
      code: "RING_RPC",
      details: { reason: "duplicate merge" },
    });
  });
});

describe("auditRingMergesV3 rows", () => {
  const auditor = X25519Keypair.generate();
  const listed = {
    slot: UNOPENED.slot,
    signature: UNOPENED.txSignature,
    eventIndex: UNOPENED.eventIndex,
    reason: "invalidAuditData",
  };

  it("opens the proved input list with a noncanonical native ciphertext field", async () => {
    const owner = NullifierKey.fromSecret(new Uint8Array(31).fill(5) as Bytes31);
    const merge = escrowedMerge({ member: OWNER_MEMBER, key: owner });
    const transaction = {
      ...merge.transaction,
      outputSlots: merge.transaction.outputSlots.map((slot) => ({
        ...slot,
        payload: encodeMergeOutputData({
          salt: merge.salt,
          ciphertext: [bigIntToBytes(BN254_SCALAR_ORDER) as Bytes32, memberOf(0), memberOf(0)],
          ringDataHash: merge.ringDataHash,
        }),
      })),
    };
    const list = Array.from({ length: 8 }, (_, slot) =>
      slot < 2 ? memberOf(slot + 1) : memberOf(0),
    );
    const { disclosure } = sealRingMergeDisclosure(list, merge.salt, auditor.publicKey());
    const origin: TransactionOrigin = {
      confirmedTransaction: async (confirmed) => ({
        kind: "historicalMergeV3",
        transaction: confirmed,
        disclosure: { ...disclosure, proof: new Uint8Array(192) },
      }),
    };
    const { client } = scanClient({ transactions: [[transaction]] });
    const result = await auditRingMergesV3({
      client,
      ringProgramId: ring,
      auditor,
      origin,
    });
    expect(result.spent).toEqual(list.slice(0, 2));
    expect(result.skipped).toEqual([]);
    expect(result.unresolved).toHaveLength(1);
    owner.destroy();
  });

  it.each<readonly [string, TransactionOrigin]>([
    [
      "does not decode",
      {
        confirmedTransaction: async () => {
          throw new RingError("RING_ORIGIN_DECODE");
        },
      },
    ],
    [
      "fails its disclosure",
      {
        confirmedTransaction: async (transaction) => ({
          kind: "historicalMergeV3",
          transaction,
          disclosure: EMPTY_DISCLOSURE,
        }),
      },
    ],
    [
      "publishes two outputs",
      {
        confirmedTransaction: async (transaction) => ({
          kind: "historicalMergeV3",
          transaction: {
            ...transaction,
            outputSlots: [...transaction.outputSlots, ...transaction.outputSlots],
          },
          disclosure: EMPTY_DISCLOSURE,
        }),
      },
    ],
  ])("lists a merge that %s", async (_name, origin) => {
    const { client } = scanClient({ transactions: [[UNOPENED]] });
    await expect(
      auditRingMergesV3({ client, ringProgramId: ring, auditor, origin }),
    ).resolves.toMatchObject({
      spent: [],
      outputs: [],
      unresolved: [],
      skipped: [listed],
    });
  });

  it("lists a disclosure under another auditor key and spends nothing", async () => {
    const owner = NullifierKey.fromSecret(new Uint8Array(31).fill(5) as Bytes31);
    const { transaction, salt } = escrowedMerge({
      member: OWNER_MEMBER,
      key: owner,
    });
    const other = X25519Keypair.generate();
    const list = Array.from({ length: 8 }, (_, slot) =>
      slot < 2 ? memberOf(slot + 1) : memberOf(0),
    );
    const { disclosure } = sealRingMergeDisclosure(list, salt, other.publicKey());
    const origin: TransactionOrigin = {
      confirmedTransaction: async (confirmed) => ({
        kind: "historicalMergeV3",
        transaction: confirmed,
        disclosure: { ...disclosure, proof: new Uint8Array(192) },
      }),
    };
    const { client } = scanClient({ transactions: [[transaction]] });
    const result = await auditRingMergesV3({
      client,
      ringProgramId: ring,
      auditor,
      origin,
    });
    expect(result.spent).toEqual([]);
    expect(result.skipped.map((row) => row.signature)).toEqual([transaction.txSignature]);
    other.destroy();
    owner.destroy();
  });

  it("stops at a failed origin read", async () => {
    const { client } = scanClient({ transactions: [[UNOPENED]] });
    const origin: TransactionOrigin = {
      confirmedTransaction: async () => {
        throw new RingError("RING_ORIGIN_UNAVAILABLE");
      },
    };
    await expect(
      auditRingMergesV3({ client, ringProgramId: ring, auditor, origin }),
    ).rejects.toMatchObject({ code: "RING_ORIGIN_UNAVAILABLE" });
  });
});

describe("recoverMergeOpening", () => {
  it("opens a merge with the member's key and derives its nullifier", () => {
    const key = NullifierKey.fromSecret(new Uint8Array(31).fill(5) as Bytes31);
    const merge = escrowedMerge({ member: OWNER_MEMBER, key });
    const opened = recoverMergeOpening(
      { member: OWNER_MEMBER, nullifierKey: key, ringProgramId: ring },
      merge.transaction,
    );
    expect(opened).toEqual({
      member: OWNER_MEMBER,
      asset: SOL_MINT,
      amount: merge.amount,
      blinding: merge.blinding,
      outputContext: merge.transaction.outputSlots[0]?.outputContext,
      nullifier: key.nullifier(merge.commitment, merge.blinding),
      ringDataHash: merge.ringDataHash,
    });
    key.destroy();
  });

  it("reads undefined under another key, another member and a merge it did not seal", () => {
    const key = NullifierKey.fromSecret(new Uint8Array(31).fill(5) as Bytes31);
    const other = NullifierKey.fromSecret(new Uint8Array(31).fill(6) as Bytes31);
    const { transaction } = escrowedMerge({ member: OWNER_MEMBER, key });
    const open = (member: Bytes32, nullifierKey: NullifierKey, row = transaction) =>
      recoverMergeOpening({ member, nullifierKey, ringProgramId: ring }, row);
    expect(open(OWNER_MEMBER, other)).toBeUndefined();
    expect(open(memberOf(9), key)).toBeUndefined();
    expect(open(OWNER_MEMBER, key, UNOPENED)).toBeUndefined();
    key.destroy();
    other.destroy();
  });
});

describe("the tag 57 reader", () => {
  const hex = (value: string): Uint8Array => hexToBytes(value.replace(/^0x/u, ""));
  const vectorAuditor = (): X25519Keypair =>
    X25519Keypair.fromBytes(hex(mergeVector.auditor_sk) as Bytes32);
  const v4Ring = encodeBase58(new Uint8Array(32).fill(0x90));
  const TREE = 9;
  const REAL = memberOf(0x77);
  type Case = (typeof mergeVector.cases)[number];

  /** The vector's record over `v4Ring`, position 2 real and every other past the first padding. */
  function row(entry: Case, overrides: Readonly<{ hash?: Bytes32; sealed?: SealedRecord }> = {}) {
    const { request } = entry;
    const seed = hex(request.seed) as Bytes32;
    const firstNullifier = hex(request.firstNullifier) as Bytes32;
    const ringDataHash = hex(request.outputRingDataHash) as Bytes32;
    const record = hex(entry.record);
    const mint = encodeBase58(record.subarray(48, 80));
    const hash =
      overrides.hash ??
      knownUtxoHash(
        {
          ownerKey: record.slice(16, 48) as Bytes32,
          owner: { kind: "keyed", nullifierPk: hex(request.nullifierPk) as Bytes32 },
          asset: hashBytes(addressBytes(mint)) as Bytes32,
          amount: BigInt(request.amount),
          blinding: seededMergeOutputBlinding(seed, firstNullifier),
          dataHash: ZERO_32,
          ringDataHash,
          treeId: TREE,
        },
        ringIdField(v4Ring),
      );
    const transaction: IndexedShieldedTransaction = {
      slot: 7n,
      txSignature: SIGNATURE,
      eventIndex: 0,
      proofless: false,
      ringProgramId: v4Ring,
      nullifiers: [
        firstNullifier,
        seededMergeDummyNullifier(seed, firstNullifier, 1),
        REAL,
        ...Array.from({ length: 5 }, (_, slot) =>
          seededMergeDummyNullifier(seed, firstNullifier, slot + 3),
        ),
      ],
      messages: [],
      outputSlots: [
        {
          viewTag: new Uint8Array(32) as Bytes32,
          payload: encodeMergeOutputData({
            ringDataHash,
            salt: new Uint8Array(16) as Bytes16,
            ciphertext: [ZERO_32, ZERO_32, ZERO_32],
            ringV2: true,
          }),
          outputContext: { hash, tree: treeAddress(TREE), treeId: TREE, leafIndex: 0n },
        },
      ],
    };
    return {
      kind: "merge" as const,
      transaction,
      sealedRecord: overrides.sealed ?? {
        ephemeralPublicKey: hex(mergeVector.eph_pk) as Bytes33,
        ciphertext: hex(entry.ciphertext),
      },
      authority: MergeRingAuthority.ownerSigned,
    };
  }

  type SealedRecord = Pick<SealedMergeRecord, "ephemeralPublicKey" | "ciphertext">;

  /** The first vector's opening with `edit` applied, sealed to the vector's auditor. */
  function resealed(edit: Partial<AuditRecord>, seed = hex(mergeVector.cases[0]!.request.seed)) {
    const record = hex(mergeVector.cases[0]!.record);
    return sealMergeRecord({
      auditorPublicKey: vectorAuditor().publicKey(),
      opening: {
        record: {
          kind: RecordKind.ring,
          amount: 12n,
          ownerKey: record.slice(16, 48) as Bytes32,
          mint: encodeBase58(record.subarray(48, 80)),
          nullifierPk: record.slice(80, 112) as Bytes32,
          ...edit,
        },
        secret: seed as Bytes32,
      },
    }).sealed;
  }

  it.each(mergeVector.cases)("rebuilds the $name output from its record alone", (entry) => {
    const opened = openRingMerge({
      confirmed: row(entry),
      eventIndex: 0,
      auditor: vectorAuditor(),
    });
    const record = hex(entry.record);
    expect(opened.utxo).toEqual({
      ownerKey: record.slice(16, 48),
      nullifierPk: hex(entry.request.nullifierPk),
      asset: hashBytes(record.subarray(48, 80)),
      mint: encodeBase58(record.subarray(48, 80)),
      amount: 12n,
      blinding: hex(entry.output_blinding),
      dataHash: ZERO_32,
      ringDataHash: hex(entry.request.outputRingDataHash),
    });
    expect(opened.authority).toBe(MergeRingAuthority.ownerSigned);
    expect(opened.nullifiers.map(({ state }) => state.kind)).toEqual([
      "unresolvedReal",
      "padding",
      "unresolvedReal",
      "padding",
      "padding",
      "padding",
      "padding",
      "padding",
    ]);
  });

  it("identifies the zero key and the enrolled key from each record", () => {
    const [enrolled, zero] = mergeVector.cases;
    const keyOf = (entry: Case) =>
      openRingMerge({ confirmed: row(entry), eventIndex: 0, auditor: vectorAuditor() }).utxo
        .nullifierPk;
    expect(keyOf(zero!)).toEqual(ZERO_NULLIFIER_PK);
    expect(keyOf(enrolled!)).not.toEqual(ZERO_NULLIFIER_PK);
  });

  it("resolves a nullifier through the known notes and never a padding position", () => {
    const entry = mergeVector.cases[0]!;
    const commitment = memberOf(0x33);
    const utxo = {
      ownerKey: memberOf(1),
      owner: { kind: "keyed" as const, nullifierPk: memberOf(2) },
      asset: memberOf(3),
      amount: 1n,
      blinding: memberOf(4),
      dataHash: ZERO_32,
      ringDataHash: ZERO_32,
      treeId: TREE,
    };
    const known: KnownUtxos = {
      utxo: () => undefined,
      byNullifier: (nullifier) => (equalBytes(nullifier, REAL) ? { commitment, utxo } : undefined),
    };
    const opened = openRingMerge({
      confirmed: row(entry),
      eventIndex: 0,
      auditor: vectorAuditor(),
      known,
    });
    expect(opened.nullifiers[2]?.state).toEqual({
      kind: "resolved",
      note: { commitment, utxo },
    });
    expect(opened.nullifiers[1]?.state).toEqual({ kind: "padding" });
  });

  it.each(mergeVector.cases)(
    "classifies the $name padding from its seed at its position",
    (entry) => {
      const seed = hex(entry.request.seed) as Bytes32;
      const firstNullifier = hex(entry.request.firstNullifier) as Bytes32;
      const nullifier = seededMergeDummyNullifier(seed, firstNullifier, 3);
      const kindOf = (fields: Readonly<{ seed: Bytes32; position: number }>) =>
        classifyMergeNullifier({ firstNullifier, nullifier, ...fields }).kind;
      expect(kindOf({ seed, position: 3 })).toBe("padding");
      expect(kindOf({ seed, position: 4 })).toBe("unresolvedReal");
      expect(kindOf({ seed: memberOf(0x99), position: 3 })).toBe("unresolvedReal");
    },
  );

  it("refuses a record off the commitment, a dummy kind and a noncanonical key or seed", () => {
    const entry = mergeVector.cases[0]!;
    const open = (confirmed: ReturnType<typeof row>) => () =>
      openRingMerge({ confirmed, eventIndex: 0, auditor: vectorAuditor() });
    expect(open(row(entry, { hash: memberOf(1) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_OUTPUT_MISMATCH" }),
    );
    expect(open(row(entry, { sealed: resealed({ amount: 13n }) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_OUTPUT_MISMATCH" }),
    );
    expect(open(row(entry, { sealed: resealed({ kind: RecordKind.exit }) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_MESSAGE", details: { reason: "merge record" } }),
    );
    const noncanonical = new Uint8Array(32).fill(0xff) as Bytes32;
    expect(open(row(entry, { sealed: resealed({ nullifierPk: noncanonical }) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_MESSAGE", details: { reason: "merge record" } }),
    );
    expect(open(row(entry, { sealed: resealed({}, noncanonical) }))).toThrow(
      expect.objectContaining({ code: "RING_AUDIT_MESSAGE", details: { reason: "merge record" } }),
    );
  });

  it("refuses a row of two outputs, a count off every width and no ring", () => {
    const confirmed = row(mergeVector.cases[0]!);
    const { transaction } = confirmed;
    const open = (edited: IndexedShieldedTransaction) => () =>
      openRingMerge({
        confirmed: { ...confirmed, transaction: edited },
        eventIndex: 0,
        auditor: vectorAuditor(),
      });
    const { ringProgramId: _ring, ...ringless } = transaction;
    for (const edited of [
      { ...transaction, outputSlots: [...transaction.outputSlots, ...transaction.outputSlots] },
      { ...transaction, nullifiers: [] },
      ringless,
    ])
      expect(open(edited)).toThrow(expect.objectContaining({ code: "RING_ORIGIN_DECODE" }));
  });

  it("lists a record of another auditor and a tampered record, and reads a good row", async () => {
    const entry = mergeVector.cases[0]!;
    const good = row(entry);
    const bad = {
      ...row(entry),
      transaction: { ...good.transaction, txSignature: "6".repeat(87) as Signature },
    };
    const tampered = bad.sealedRecord.ciphertext.slice();
    tampered[8] = (tampered[8] ?? 0) ^ 1;
    const { client } = scanClient({ transactions: [[good.transaction, bad.transaction]] });
    const page = await auditRingMerges({
      client,
      ringProgramId: v4Ring,
      auditor: vectorAuditor(),
      origin: {
        confirmedTransaction: async (transaction) =>
          transaction === good.transaction
            ? good
            : {
                ...bad,
                transaction,
                sealedRecord: { ...bad.sealedRecord, ciphertext: tampered },
              },
      },
    });
    expect(page.merges.map(({ signature }) => signature)).toEqual([SIGNATURE]);
    expect(page.historical).toEqual([]);
    expect(page.skipped.map(({ signature }) => signature)).toEqual([bad.transaction.txSignature]);
    const { client: other } = scanClient({ transactions: [[good.transaction]] });
    const foreign = await auditRingMerges({
      client: other,
      ringProgramId: v4Ring,
      auditor: X25519Keypair.generate(),
      origin: { confirmedTransaction: async () => good },
    });
    expect(foreign.merges).toEqual([]);
    expect(foreign.skipped).toHaveLength(1);
  });

  it("refuses a tag 57 row read twice", async () => {
    const good = row(mergeVector.cases[0]!);
    const { client } = scanClient({ transactions: [[good.transaction], [good.transaction]] });
    await expect(
      auditRingMerges({
        client,
        ringProgramId: v4Ring,
        auditor: vectorAuditor(),
        origin: { confirmedTransaction: async () => good },
      }),
    ).rejects.toMatchObject({ code: "RING_RPC", details: { reason: "duplicate merge" } });
  });
});
