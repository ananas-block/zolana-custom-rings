import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

import {
  wireDecoder,
  treeAddress,
  mergeOutputBlinding,
  mergeOutputKey,
  poseidon,
  encodeMergeOutputData,
  encryptMergeOutput,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes16, Bytes31, Bytes32, Bytes33, Signature } from "@heliuslabs/zolana/interface";
import { NullifierKey, X25519Keypair } from "@heliuslabs/zolana/keypair";
import { SOL_MINT, ownerUtxoHash } from "@heliuslabs/zolana/transaction";
import type { IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";
import { auditRingMerges, recoverMergeOpening } from "../../../src/operations/audit/audit-merge.js";
import { sealRingMergeDisclosure } from "../../../src/crypto/audit/merge-disclosure.js";
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

/** Every transaction is a confirmed merge of the ring, the binding is the origin tests' concern. */
const MERGES: TransactionOrigin = {
  confirmedTransaction: async (transaction) => ({ kind: "merge", transaction }),
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
    expect(result).toMatchObject({
      spent: [],
      outputs: [],
      unresolved: [],
      skipped: [],
    });
    expect(result.historical).toEqual([
      { slot: UNOPENED.slot, signature: SIGNATURE, eventIndex: 0 },
    ]);
    expect(result.nextCursor).toBeUndefined();
  });

  it("refuses a merge read twice", async () => {
    const auditor = X25519Keypair.generate();
    const twice = scanClient({ transactions: [[UNOPENED], [UNOPENED]] });
    await expect(
      auditRingMerges({
        client: twice.client,
        ringProgramId: ring,
        auditor,
        origin: MERGES,
      }),
    ).rejects.toMatchObject({
      code: "RING_RPC",
      details: { reason: "duplicate merge" },
    });
  });
});

describe("auditRingMerges rows", () => {
  const auditor = X25519Keypair.generate();
  const listed = {
    slot: UNOPENED.slot,
    signature: UNOPENED.txSignature,
    eventIndex: UNOPENED.eventIndex,
    reason: "invalidAuditData",
  };
  const emptyDisclosure = {
    proof: new Uint8Array(192),
    ephemeralPublicKey: new Uint8Array(33) as Bytes33,
    ciphertext: new Uint8Array(32) as Bytes32,
    fields: [],
  };

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
          kind: "merge",
          transaction,
          disclosure: emptyDisclosure,
        }),
      },
    ],
    [
      "publishes two outputs",
      {
        confirmedTransaction: async (transaction) => ({
          kind: "merge",
          transaction: {
            ...transaction,
            outputSlots: [...transaction.outputSlots, ...transaction.outputSlots],
          },
          disclosure: emptyDisclosure,
        }),
      },
    ],
  ])("lists a merge that %s", async (_name, origin) => {
    const { client } = scanClient({ transactions: [[UNOPENED]] });
    await expect(
      auditRingMerges({ client, ringProgramId: ring, auditor, origin }),
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
        kind: "merge",
        transaction: confirmed,
        disclosure: { ...disclosure, proof: new Uint8Array(192) },
      }),
    };
    const { client } = scanClient({ transactions: [[transaction]] });
    const result = await auditRingMerges({
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
      auditRingMerges({ client, ringProgramId: ring, auditor, origin }),
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
