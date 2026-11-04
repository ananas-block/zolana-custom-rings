import { getBase58Decoder, type Signature } from "@solana/kit";

import {
  ClientError,
  type GetByNullifiersRequest,
  type GetByTagsRequest,
} from "@heliuslabs/zolana/client";
import { addressBytes, concatBytes, encodeOutputData } from "@heliuslabs/zolana/internal";
import { InstructionTag, type Bytes32, type Bytes33 } from "@heliuslabs/zolana/interface";
import {
  randomSalt,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type ShieldedAddress,
  type ViewTag,
} from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Data,
  EncryptedScheme,
  ownerUtxoHash,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  type IndexedShieldedTransaction,
  type OutputSlot,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";

import { AnonymousPlan, RingOutputRail } from "../../src/operations/payments/output-rail.js";
import type { ReplyMetadata } from "../../src/protocol/codec/anonymous-delivery.js";
import {
  encodeRingDepositCapsule,
  RING_DEPOSIT_OPENING_LENGTH,
} from "../../src/protocol/codec/ring-deposit-capsule.js";
import { encodeRingDepositPlaintext } from "../../src/protocol/codec/ring-deposit-plaintext.js";
import {
  AnonymousSync,
  type AnonymousScan,
  type AnonymousSyncClient,
} from "../../src/state/anonymous-sync.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import {
  outputItems,
  transactionItems,
} from "../../../../zolana/sdk-libs/ts/test/helpers/pages.js";
import { TREE, TREE_ID, randomAddress, walletKeys } from "./ring-pipeline.js";

export const RING = randomAddress();
export const PAYER = randomAddress();
export const ASSETS = new AssetRegistry();

const CONTEXT_FLOOR = 1n << 40n;
const ZERO = new Uint8Array(32) as Bytes32;

export function keypair(seed: number): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );
}

/** A canonical field value distinct per pair. */
export function field(seed: number, index: number): Bytes32 {
  const value = new Uint8Array(32).fill(0x11);
  value[30] = seed;
  value[31] = index;
  return value as Bytes32;
}

export function signature(leaf: bigint): Signature {
  const bytes = new Uint8Array(64).fill(0x5a);
  new DataView(bytes.buffer).setBigUint64(0, leaf);
  return getBase58Decoder().decode(bytes) as Signature;
}

export function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

type DepositRow = Readonly<{ slot: bigint; txSignature: Signature; outputSlot: OutputSlot }>;

/** Serves the by-ring read as Photon does, ordered by `(slot, signature)`, `limit` counting transactions. */
export class ScanIndexer {
  readonly transactions: IndexedShieldedTransaction[] = [];
  readonly deposits: DepositRow[] = [];
  readonly ringReads: GetByTagsRequest[] = [];
  /** Tags named on the by-tags read, zero for a wallet that scans. */
  transactionTagReads = 0;
  /** Snapshot slot of each next page, past them the highest row or the floor. */
  readonly contexts: bigint[] = [];
  /** Answers the next by-ring read with the refusal. */
  refuseAt: Readonly<{ read: number; error: Error }> | undefined;
  responseLimit: number | undefined;
  #nextLeaf = 0n;

  publish(transaction: IndexedShieldedTransaction): void {
    this.transactions.push(transaction);
  }

  leaves(count: number): bigint {
    const first = this.#nextLeaf;
    this.#nextLeaf += BigInt(count);
    return first;
  }

  client(): AnonymousSyncClient {
    const tagged = (request: GetByTagsRequest) => {
      const tags = new Set(request.tags.map(hex));
      return (slot: Readonly<{ viewTag: Bytes32 }>) => tags.has(hex(slot.viewTag));
    };
    const context = { slot: CONTEXT_FLOOR, blockTime: 0n };
    return {
      getShieldedTransactionsByTags: async (request: GetByTagsRequest) => {
        if (request.ringProgramId === undefined) {
          this.transactionTagReads += request.tags.length;
          return { context, paginationToken: null, data: [] };
        }
        this.ringReads.push(request);
        if (this.refuseAt?.read === this.ringReads.length) throw this.refuseAt.error;
        if (this.responseLimit !== undefined && (request.limit ?? 1000) > this.responseLimit)
          throw new ClientError("CLIENT_INDEXER_RESPONSE_TOO_LARGE", {
            details: { method: "getShieldedTransactionsByTags" },
          });
        return this.#ringPage(request);
      },
      getEncryptedUtxosByTags: async (request: GetByTagsRequest) => ({
        context,
        paginationToken: null,
        data: outputItems(this.deposits.filter((deposit) => tagged(request)(deposit.outputSlot))),
      }),
      getShieldedTransactionsByNullifiers: async (request: GetByNullifiersRequest) => {
        const wanted = new Set(request.nullifiers.map(hex));
        return {
          context,
          paginationToken: null,
          data: transactionItems(
            this.transactions.filter((tx) =>
              tx.nullifiers.some((nullifier) => wanted.has(hex(nullifier))),
            ),
          ),
        };
      },
    };
  }

  #ringPage(request: GetByTagsRequest) {
    const limit = request.limit ?? 1000;
    const floor = request.filters?.slot?.gt;
    const [tokenSlot, tokenSignature] = request.paginationToken?.split(":") ?? [];
    const ordered = this.transactions
      .filter(
        (tx) =>
          tx.ringProgramId === request.ringProgramId && (floor === undefined || tx.slot > floor),
      )
      .sort((left, right) =>
        left.slot === right.slot
          ? left.txSignature < right.txSignature
            ? -1
            : 1
          : left.slot < right.slot
            ? -1
            : 1,
      )
      .filter(
        (tx) =>
          tokenSlot === undefined ||
          tx.slot > BigInt(tokenSlot) ||
          (tx.slot === BigInt(tokenSlot) && tx.txSignature > (tokenSignature ?? "")),
      );
    const page = ordered.slice(0, limit);
    const last = page.at(-1);
    const highest = this.transactions.reduce(
      (high, tx) => (tx.slot > high ? tx.slot : high),
      floor ?? 0n,
    );
    return {
      context: { slot: this.contexts.shift() ?? highest, blockTime: 0n },
      paginationToken:
        ordered.length > page.length && last !== undefined
          ? `${last.slot}:${last.txSignature}`
          : null,
      data: transactionItems(page),
    };
  }
}

export interface Pay {
  readonly to: ShieldedAddress;
  readonly amount: bigint;
  readonly reply?: ReplyMetadata;
}

export type SealedTransfer = IndexedShieldedTransaction;

/** A wallet enrolled on `RING` that pays through the real rail. */
export class ScanWallet {
  readonly keypair: ShieldedKeypair;
  readonly keys: ReturnType<typeof walletKeys>;
  readonly #funding: ProofInputUtxo[];

  constructor(seed: number) {
    this.keypair = keypair(seed);
    this.keys = walletKeys(this.keypair);
    this.#funding = Array.from({ length: 8 }, (_, index) =>
      ProofInputUtxo.fromKeypair(
        new Utxo({
          owner: this.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 100n,
          blinding: field(seed, index),
          ringProgramId: RING,
        }),
        this.keypair,
        {},
        TREE_ID,
      ),
    );
  }

  get address(): ShieldedAddress {
    return this.keypair.shieldedAddress();
  }

  get viewingKey(): ShieldedAddress["viewingPublicKey"] {
    return this.address.viewingPublicKey;
  }

  /** A history that reads `RING` from its start. */
  fresh(): ViewingHistory {
    return ViewingHistory.create(this.viewingKey, 0n).withRing(RING);
  }

  async pay(
    indexer: ScanIndexer,
    payments: readonly Pay[],
    options: Readonly<{ compact?: boolean; slot?: bigint }> = {},
  ): Promise<SealedTransfer> {
    const tx = this.seal(indexer, payments, options);
    indexer.publish(tx);
    return tx;
  }

  /** Seals one anonymous transfer from the next funding note, its leaves taken, unpublished. */
  seal(
    indexer: ScanIndexer,
    payments: readonly Pay[],
    options: Readonly<{ compact?: boolean; slot?: bigint }> = {},
  ): SealedTransfer {
    const plan = payments.reduce(
      (planned, pay) =>
        planned.withPayment({ recipient: pay.to.viewingPublicKey, reply: pay.reply ?? null }),
      AnonymousPlan.create(),
    );
    const input = this.#funding.shift();
    if (input === undefined) throw new Error("no funding left");
    const transfer = (
      options.compact === true
        ? ConfidentialTransfer.compact(this.address, [input], PAYER)
        : new ConfidentialTransfer(this.address, [input], PAYER)
    )
      .withRingProgramId(RING)
      .withOutputTreeId(TREE_ID);
    for (const pay of payments) transfer.sendToRing(pay.to, SOL_MINT, pay.amount, RING);
    const prepared = transfer.prepare();
    const rail = new RingOutputRail(
      this.keypair.transactionViewingKey(prepared.firstNullifier),
      prepared.firstNullifier,
      { kind: "anonymous", plan },
    );
    const proof = rail.encrypt({
      prepared,
      sender: this.address,
      assets: ASSETS,
      instructionDiscriminator: InstructionTag.ringTransact,
    });
    const { outputs, resolvedOwnerTags, messages } = proof.externalData;
    const leaf = indexer.leaves(outputs.length);
    return {
      slot: options.slot ?? leaf + 1n,
      txSignature: signature(leaf),
      eventIndex: 0,
      txViewingPublicKey: rail.txViewingKey.publicKey(),
      salt: rail.salt,
      outputSlots: outputs.map((output, index) => ({
        viewTag: resolvedOwnerTags[index] ?? ZERO,
        outputContext: {
          hash: output.utxoHash,
          tree: TREE,
          treeId: TREE_ID,
          leafIndex: leaf + BigInt(index),
        },
        payload: output.data ?? new Uint8Array(),
      })),
      messages,
      nullifiers: proof.inputUtxos.map((spent) => spent.nullifier()),
      proofless: false,
      ringProgramId: RING,
    };
  }

  sync(indexer: ScanIndexer, history: ViewingHistory, held: readonly WalletUtxo[] = []) {
    return AnonymousSync.create(this.keys, ASSETS)
      .withHeldNotes(held)
      .fetch(indexer.client(), history);
  }

  fullScan(indexer: ScanIndexer, history: ViewingHistory = this.fresh()) {
    return AnonymousSync.create(this.keys, ASSETS).fullScan(indexer.client(), history, RING);
  }

  /** The claim the wallet confirms, its own viewing key the sender's. */
  replyTo(): ReplyMetadata {
    return {
      viewingKey: this.viewingKey,
      ownerKey: this.address.signingPublicKey.confidentialViewTag(),
      nullifierPk: this.address.nullifierPublicKey,
      data: new Data(),
    };
  }
}

export function output(tx: IndexedShieldedTransaction, position: number): Bytes32 {
  const slot = tx.outputSlots[position];
  if (slot === undefined) throw new Error("no output");
  return slot.outputContext.hash;
}

export function found(scan: Pick<AnonymousScan, "found">): readonly string[] {
  return scan.found.map((utxo) => hex(utxo.utxoHash));
}

/** `ownerUtxoHash ‖ asset ‖ u64le(amount) ‖ no data hash ‖ ring ‖ ring data hash ‖ envelope`. */
export function depositRow(
  owner: ShieldedAddress,
  tag: ViewTag,
  capsule: boolean,
  blinding: Bytes32,
): DepositRow {
  const envelope = ViewingKey.generate();
  const salt = randomSalt();
  const recipientCiphertext = envelope.encryptRingDeposit(
    owner.viewingPublicKey,
    encodeRingDepositPlaintext({ blinding, ringData: new Uint8Array() }),
    salt,
  );
  const ciphertext = capsule
    ? encodeRingDepositCapsule({
        slotIndex: 0,
        ephemeralPublicKey: new Uint8Array(33).fill(2) as Bytes33,
        ciphertext: new Uint8Array(RING_DEPOSIT_OPENING_LENGTH),
        recipientCiphertext,
      })
    : new TextEncoder().encode("CRDEP001");
  const amount = new Uint8Array(8);
  new DataView(amount.buffer).setBigUint64(0, 25n, true);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, ciphertext.length, true);
  const body = concatBytes(
    ownerUtxoHash(owner.ownerHash(), blinding),
    new Uint8Array(32),
    amount,
    Uint8Array.of(0),
    addressBytes(RING),
    new Uint8Array(32),
    envelope.publicKey().toBytes(),
    salt,
    length,
    ciphertext,
  );
  envelope.destroy();
  const hash = new Utxo({
    owner: owner.signingPublicKey,
    asset: SOL_MINT,
    amount: 25n,
    blinding,
    ringProgramId: RING,
  }).hash(owner.nullifierPublicKey, TREE_ID);
  return {
    slot: 1n,
    txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(blinding[31] ?? 0)) as Signature,
    outputSlot: {
      viewTag: tag,
      outputContext: {
        hash,
        tree: TREE,
        treeId: TREE_ID,
        leafIndex: 500n + BigInt(blinding[31] ?? 0),
      },
      payload: encodeOutputData(EncryptedScheme.ringDeposit, body),
    },
  };
}

/** One proofless row of a by-ring page, as a deposit lands. */
export function depositTransaction(row: DepositRow, slot: bigint): IndexedShieldedTransaction {
  return {
    slot,
    txSignature: row.txSignature,
    eventIndex: 0,
    outputSlots: [row.outputSlot],
    messages: [],
    nullifiers: [],
    proofless: true,
    ringProgramId: RING,
  };
}
