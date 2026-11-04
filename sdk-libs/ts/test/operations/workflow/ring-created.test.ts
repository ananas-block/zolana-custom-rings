import { address, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  hashBytes,
  addressBytes,
  treeAddress,
  bigIntToBytes,
  mergeOutputKey,
  encodeMergeOutputData,
  encryptMergeOutput,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { ShieldedKeypair, X25519Keypair } from "@heliuslabs/zolana/keypair";
import { SOL_MINT, Utxo, ownerUtxoHash } from "@heliuslabs/zolana/transaction";
import type { IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";
import {
  createdRingUtxos,
  scanCreatedRingUtxos,
} from "../../../src/operations/workflow/created-utxos.js";
import { RecordKind } from "../../../src/protocol/codec/audit-stream.js";
import { sealRingDepositOpenings } from "../../../src/proof/deposit-audit.js";
import {
  ConfirmedDeposit,
  type TransactionOrigin,
} from "../../../src/protocol/transaction/origin.js";
import { RingError } from "../../../src/protocol/error.js";
import { ringAuditReader } from "../../helpers/clients.js";
import { transactionsPage } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import {
  confirmedDepositTransaction,
  ringDepositPayload,
} from "../../helpers/confirmed-deposits.js";
import { transactionItems } from "../../../../../zolana/sdk-libs/ts/test/helpers/pages.js";
import { historyCursor } from "../../../src/rpc/history.js";

await initializePoseidon();

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE_ID = 0;
const SIGNATURE = "1".repeat(87) as Signature;
const ZERO = new Uint8Array(32) as Bytes32;
const SOL_ASSET = hashBytes(addressBytes(SOL_MINT)) as Bytes32;

function field(value: bigint): Bytes32 {
  return bigIntToBytes(value) as Bytes32;
}

function transaction(
  input: Pick<IndexedShieldedTransaction, "outputSlots" | "nullifiers" | "proofless">,
): IndexedShieldedTransaction {
  return {
    slot: 1n,
    txSignature: SIGNATURE,
    eventIndex: 0,
    messages: [],
    ringProgramId: RING,
    ...input,
  };
}

function outputContext(hash: Bytes32, leafIndex: bigint) {
  return { hash, tree: treeAddress(TREE_ID), treeId: TREE_ID, leafIndex };
}

/** One deposit paying an anonymous ring's owner then a confidential ring's. */
function deposits(auditor: X25519Keypair) {
  const anonymous = ShieldedKeypair.generate();
  const confidential = ShieldedKeypair.generate();
  const blinding = field(5n);
  const ownerKeys = [
    anonymous.signingPublicKey().ed25519(),
    confidential.signingPublicKey().confidentialViewTag(),
  ];
  const sealed = sealRingDepositOpenings(
    [anonymous, confidential].map((keypair, index) => ({
      record: {
        kind: RecordKind.ring,
        amount: 1n,
        ownerKey: ownerKeys[index]!,
        mint: SOL_MINT,
        nullifierPk: keypair.nullifierPublicKey(),
      },
      blinding,
      recipientCiphertext: Uint8Array.of(index + 1),
    })),
    auditor.publicKey(),
  );
  const owners = [anonymous, confidential].map((keypair) =>
    ownerUtxoHash(keypair.ownerHash(), blinding),
  );
  const commitments = [anonymous, confidential].map((keypair) =>
    new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 1n,
      blinding,
      ringProgramId: RING,
    }).hash(keypair.nullifierPublicKey(), TREE_ID),
  );
  return {
    sealed,
    commitments,
    bindings: ConfirmedDeposit.fromTransaction(
      confirmedDepositTransaction(RING, SIGNATURE, sealed.capsules, owners),
      SIGNATURE,
      0,
      RING,
    ),
    outputSlots: sealed.capsules.map((capsule, index) => ({
      viewTag: ZERO,
      outputContext: outputContext(commitments[index]!, BigInt(index)),
      payload: ringDepositPayload({
        ring: RING,
        ownerCommitment: owners[index]!,
        asset: SOL_MINT,
        amount: 1n,
        capsule,
      }),
    })),
    created: [anonymous, confidential].map((keypair, index) => ({
      commitment: commitments[index],
      slotIndex: index,
      utxo: {
        ownerKey: ownerKeys[index],
        owner: { kind: "keyed", nullifierPk: keypair.nullifierPublicKey() },
        asset: SOL_ASSET,
        mint: SOL_MINT,
        amount: 1n,
        blinding,
        dataHash: ZERO,
        ringDataHash: ZERO,
        treeId: TREE_ID,
      },
    })),
  };
}

describe("createdRingUtxos", () => {
  it("opens every deposit's UTXO by its owner hash and disclosed owner key", () => {
    const auditor = X25519Keypair.generate();
    const deposit = deposits(auditor);
    try {
      const created = (outputSlots: typeof deposit.outputSlots) =>
        createdRingUtxos({
          confirmed: {
            kind: "deposit",
            transaction: transaction({
              outputSlots,
              nullifiers: [],
              proofless: true,
            }),
            deposits: deposit.bindings,
          },
          ringProgramId: RING,
          auditor,
        });
      expect(created(deposit.outputSlots)).toEqual(deposit.created);
      const moved = deposit.outputSlots.map((slot, index) =>
        index === 0
          ? {
              ...slot,
              outputContext: outputContext(deposit.commitments[1]!, 0n),
            }
          : slot,
      );
      expect(() => created(moved)).toThrow(expect.objectContaining({ code: "RING_AUDIT_MESSAGE" }));
    } finally {
      deposit.sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("scans the ring's history for created UTXOs and stops at the page cap", async () => {
    const auditor = X25519Keypair.generate();
    const deposit = deposits(auditor);
    try {
      const indexed = transaction({
        outputSlots: deposit.outputSlots,
        nullifiers: [],
        proofless: true,
      });
      const transfer = { ...indexed, txSignature: "2".repeat(87) as Signature };
      const origin: TransactionOrigin = {
        confirmedTransaction: async (event) =>
          event.txSignature === SIGNATURE
            ? {
                kind: "deposit",
                transaction: event,
                deposits: deposit.bindings,
              }
            : {
                kind: "transfer",
                transaction: event,
                inputTreeIds: [],
                layout: {
                  key: { class: 24, entry: false },
                  inputs: 1,
                  outputs: 2,
                  capacity: 2,
                  hasData: false,
                },
                rail: "confidential",
                noSpend: false,
                hasData: false,
                entry: false,
              },
      };
      const scan = (page: Parameters<typeof transactionsPage>[0], maxPages?: number) =>
        scanCreatedRingUtxos({
          client: ringAuditReader({
            getShieldedTransactionsByTags: async () => transactionsPage(page),
          }),
          ringProgramId: RING,
          auditor,
          origin,
          ...(maxPages === undefined ? {} : { maxPages }),
        });
      const scanned = await scan({
        data: transactionItems([indexed, transfer]),
      });
      expect(scanned).toEqual({
        utxos: deposit.created,
        merges: [],
        skipped: [],
      });
      const failing = (code: "RING_ORIGIN_DECODE" | "RING_ORIGIN_UNAVAILABLE") =>
        scanCreatedRingUtxos({
          client: ringAuditReader({
            getShieldedTransactionsByTags: async () =>
              transactionsPage({
                data: transactionItems([transfer, indexed]),
              }),
          }),
          ringProgramId: RING,
          auditor,
          origin: {
            confirmedTransaction: async (row, ring) => {
              if (row.txSignature === transfer.txSignature) throw new RingError(code);
              return origin.confirmedTransaction(row, ring);
            },
          },
        });
      await expect(failing("RING_ORIGIN_DECODE")).resolves.toEqual({
        utxos: deposit.created,
        merges: [],
        skipped: [
          {
            slot: transfer.slot,
            signature: transfer.txSignature,
            eventIndex: transfer.eventIndex,
            reason: "invalidAuditData",
          },
        ],
      });
      await expect(failing("RING_ORIGIN_UNAVAILABLE")).rejects.toMatchObject({
        code: "RING_ORIGIN_UNAVAILABLE",
      });
      const foreign = await scan({
        data: transactionItems([
          {
            ...indexed,
            ringProgramId: address("11111111111111111111111111111111"),
          },
        ]),
      });
      expect(foreign).toEqual({ utxos: [], merges: [], skipped: [] });
      const capped = await scan({ data: transactionItems([transfer]), paginationToken: "t7" }, 1);
      expect(capped).toEqual({
        utxos: [],
        merges: [],
        skipped: [],
        nextCursor: historyCursor(RING, "ring", "t7"),
      });
      await expect(scan({}, 0)).rejects.toMatchObject({
        code: "RING_RPC",
        details: { reason: "invalid scan limit", name: "maxPages" },
      });
    } finally {
      deposit.sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("opens no note of a merge", () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const nullifiers = [field(7n), field(8n)];
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const ringDataHash = field(0xd0n);
    const commitment = ownerUtxoHash({
      owner: owner.ownerHash(),
      asset: SOL_MINT,
      amount: 12n,
      blinding: field(11n),
      treeId: TREE_ID,
      ringDataHash,
      ringProgramId: RING,
    });
    const merge = transaction({
      outputSlots: [
        {
          viewTag: nullifiers[0]!,
          outputContext: outputContext(commitment, 3n),
          payload: encodeMergeOutputData({
            salt,
            ciphertext: encryptMergeOutput(
              { amount: 12n, mint: SOL_MINT },
              mergeOutputKey(owner.nullifierKey(), nullifiers[0]!),
              salt,
            ),
            ringDataHash,
          }),
        },
      ],
      nullifiers,
      proofless: false,
    });
    const confirmed = {
      kind: "merge",
      transaction: merge,
      sealedRecord: {
        ephemeralPublicKey: new Uint8Array(33) as Bytes33,
        ciphertext: new Uint8Array(144),
      },
      authority: 0,
    } as const;
    expect(createdRingUtxos({ confirmed, ringProgramId: RING, auditor })).toEqual([]);
    auditor.destroy();
  });
});
