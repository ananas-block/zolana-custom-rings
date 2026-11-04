import { bytesKey } from "@heliuslabs/zolana/internal";
import {
  assertIsFullySignedTransaction,
  assertIsTransactionWithinSizeLimit,
  getSignatureFromTransaction,
  isSolanaError,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM,
  SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE,
  SOLANA_ERROR__TRANSACTION_ERROR__BLOCKHASH_NOT_FOUND,
  type Address,
  type Instruction,
  type Signature,
  type TransactionPartialSigner,
} from "@solana/kit";
import {
  isClientError,
  runKitRpc,
  type UtxoReservation,
  equalBytes,
  assertVersion1Transaction,
  compileUnsignedTransaction,
} from "@heliuslabs/zolana/internal";
import type { BlockhashProvider, ChainReader, KitRpcAccess } from "@heliuslabs/zolana/client";
import type { ViewingHistory } from "../../state/viewing-history.js";
import { savePersistedWallet, type WalletPersistence } from "@heliuslabs/zolana/wallet";
import type { Bytes32, RequestContext, Transaction } from "@heliuslabs/zolana/interface";
import {
  type Wallet,
  type WalletUtxo,
  type PendingWalletSubmission,
} from "@heliuslabs/zolana/transaction";
import type {
  RingSubmissionPending,
  RingSubmissionStatus,
  RingSubmissionTransport,
} from "../../rpc/ports.js";
import { fetchRingPolicy, fetchStorageRegistry } from "../../protocol/membership/config.js";
import { RingError, RingProgramError } from "../../protocol/error.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import { fetchTrackingRegistry } from "../../rpc/tracking-resolver.js";
import { ringComputeUnitLimit } from "../management/admin.js";
import { BufferedFrame } from "../payments/buffered-frame.js";
import { TransactionFit } from "./address-ceiling.js";
import {
  boundState,
  fitBudget,
  fitSigners,
  transactTag,
  type ProvenRingTransfer,
  type RingBoundState,
  type RingTransactionFrame,
} from "./pipeline.js";

/** Keeps the signed intent and validity bounds of one transaction attempt. */
export interface RingSubmissionAttempt extends RingBoundState {
  /** The transaction that spends, a frame past one transaction settles here from its buffer. */
  readonly transaction: Transaction;
  readonly lastValidBlockHeight: bigint;
  readonly intentHash: Bytes32;
  readonly ringInstructionIndex: number;
  /** The anonymous depositor's viewing history past the attempt's tag, every attempt the same. */
  readonly viewingHistory?: ViewingHistory;
  readonly upload?: RingFrameUpload;
}

/** What lands ahead of a buffered attempt's settlement. */
export interface RingFrameUpload {
  readonly frame: BufferedFrame;
  /** Signs and pays every write and the close, each under its own fresh lifetime. */
  readonly writer: Address;
  readonly chain: Pick<ChainReader, "getAccount"> & BlockhashProvider;
}

/** Returns a resolved submission's buffer rent, a wallet's record names neither its ring nor its writer. */
export interface RingBufferReclaim {
  readonly ringProgramId: Address;
  readonly writer: Address;
  readonly chain: Pick<ChainReader, "getAccount"> & BlockhashProvider;
  readonly transport: RingSubmissionTransport;
}

export type RingSubmissionResult =
  | Readonly<{
      kind: "confirmed";
      signature: Signature;
      slot: bigint;
      attempts: number;
    }>
  | Readonly<{ kind: "unknown"; signature: Signature; attempts: number }>
  | Readonly<{
      kind: "failed";
      signature: Signature;
      attempts: number;
      instructionIndex?: number;
      customCode?: number;
    }>;

/** @internal Retains the same notes and intent across proof rebuilds. */
export interface RingSubmissionBuildState {
  lifetime?: "submission";
  entries?: readonly WalletUtxo[];
  reservation?: UtxoReservation;
  intent?: Bytes32;
}

/** Keeps selected notes unavailable until submission resolves. */
export interface ReservationHold {
  release(): void;
  extend(): void;
}

export type RingSubmissionBuild = (context?: RequestContext) => Promise<RingSubmissionAttempt>;

const MAX_ATTEMPTS = 3;
/** Rust `reproof_fixes` codes, a fresh proof fixes a revoked root or a rebound registry. */
const STALE_PROOF_CODES: ReadonlySet<number> = new Set([
  RingProgramError.rootNotServed,
  RingProgramError.unboundRegistry,
]);
const NO_RESERVATION: ReservationHold = Object.freeze({ release() {}, extend() {} });

/**
 * The buffer nonce of a submission, the first eight bytes of its id.
 *
 * A wallet's pending record holds the id and the settlement's signature and no buffer address, and a digest nonce would
 * name a frame the record does not keep. Deriving from the id lets a restarted wallet find the buffer from the record
 * alone. Every attempt of a submission shares the one address, a retry rebuilds only after the close lands, and a frame
 * of another length cannot meet a buffer sized for the last one.
 */
export function submissionBufferNonce(id: string): bigint {
  return BigInt(`0x${id.slice(0, 16)}`);
}

/**
 * One proven transfer as an attempt, Rust `RingSubmission::send`'s choice over the complete transaction, setup included.
 * Without `bufferNonce` a transfer stays inline, a caller holding one transaction has nowhere to land writes.
 */
export async function provenRingAttempt(
  input: Readonly<{
    proven: ProvenRingTransfer;
    feePayer: Address;
    chain: RingFrameUpload["chain"];
    transaction: RingTransactionFrame;
    intentHash: Bytes32;
    bufferNonce?: bigint;
  }>,
  context?: RequestContext,
): Promise<RingSubmissionAttempt> {
  const { proven, feePayer, chain, transaction: frame } = input;
  const [inline, lifetime] = await Promise.all([
    proven.instruction(),
    chain.getLatestBlockhash(context),
  ]);
  const computeUnitLimit = ringComputeUnitLimit(transactTag(proven.data.rail));
  const signers = fitSigners(feePayer, frame);
  const budget = { ...fitBudget(frame), computeUnitLimit };
  const fit =
    input.bufferNonce === undefined
      ? TransactionFit.inline(inline, signers, budget)
      : await TransactionFit.of(inline, signers, budget);
  const upload =
    input.bufferNonce !== undefined && fit.transport === "buffered"
      ? await BufferedFrame.of(inline, feePayer, input.bufferNonce)
      : undefined;
  return Object.freeze({
    transaction: compileUnsignedTransaction({
      ...frame,
      feePayer,
      lifetime,
      computeUnitLimit:
        upload === undefined
          ? computeUnitLimit
          : ringComputeUnitLimit(RingInstructionTag.settleBuffered),
      instructions: [upload === undefined ? inline : upload.settle()],
    }),
    lastValidBlockHeight: lifetime.lastValidBlockHeight,
    intentHash: input.intentHash,
    ringInstructionIndex: frame.setupInstructions?.length ?? 0,
    ...boundState(proven),
    ...(upload === undefined ? {} : { upload: { frame: upload, writer: feePayer, chain } }),
  });
}

/** One broadcast and what the chain says of it so far. */
type Landing = Readonly<{ signature: Signature; status: RingSubmissionStatus }>;

/** An attempt that can no longer land, held until its buffer is gone. */
type ConcludedAttempt = Readonly<{
  signature: Signature;
  status: Extract<RingSubmissionStatus, { kind: "failed" | "expired" }>;
  retry: boolean;
}>;

/** Resolves each broadcast before retrying an unchanged payment intent. */
export class RingTransactionSubmission {
  readonly #intent: Bytes32;
  readonly #build: RingSubmissionBuild;
  readonly #reservation: ReservationHold;
  readonly #registry: Pick<ChainReader, "getAccount"> | undefined;
  readonly #wallet: Wallet | undefined;
  readonly #id: string;
  readonly #utxoHashes: readonly Bytes32[];
  #persistence: WalletPersistence | undefined;
  #persistedSignature: Signature | undefined;
  #attempt: RingSubmissionAttempt;
  #pending: Signature | undefined;
  /** Signed and not yet broadcast, cleared ahead of the one broadcast. */
  #unsent: Transaction | undefined;
  /** The current attempt's confirmed writes, a write landing resumes after them. */
  #written = 0;
  /** The write or close on its way, read and never resent until it resolves. */
  #inFlight: RingSubmissionPending | undefined;
  #concluded: ConcludedAttempt | undefined;
  #attempts = 0;
  #terminal = false;
  #busy = false;

  constructor(
    input: Readonly<{
      first: RingSubmissionAttempt;
      build: RingSubmissionBuild;
      reservation?: ReservationHold;
      /** Reads the bound registries when a proof fails. */
      registry?: Pick<ChainReader, "getAccount">;
      wallet?: Wallet;
      reservationId?: string;
      utxoHashes?: readonly Bytes32[];
    }>,
  ) {
    this.#attempt = input.first;
    this.#intent = new Uint8Array(input.first.intentHash) as Bytes32;
    this.#build = input.build;
    this.#reservation = input.reservation ?? NO_RESERVATION;
    this.#registry = input.registry;
    this.#wallet = input.wallet;
    this.#id = input.reservationId ?? bytesKey(crypto.getRandomValues(new Uint8Array(16)));
    this.#utxoHashes = (input.utxoHashes ?? []).map((hash) => new Uint8Array(hash) as Bytes32);
  }

  /** An anonymous depositor stores it before the first `send`. */
  get viewingHistory(): ViewingHistory | undefined {
    return this.#attempt.viewingHistory;
  }

  /** @internal The reservation `build` records outlives every attempt. */
  static async fromBuilder(
    input: Readonly<{
      wallet: Wallet;
      build: (
        retry: RingSubmissionBuildState,
        context?: RequestContext,
      ) => Promise<RingSubmissionAttempt>;
      registry?: Pick<ChainReader, "getAccount">;
    }>,
    context?: RequestContext,
  ): Promise<RingTransactionSubmission> {
    const retry: RingSubmissionBuildState = { lifetime: "submission" };
    const build: RingSubmissionBuild = (context) => input.build(retry, context);
    let first: RingSubmissionAttempt;
    try {
      first = await build(context);
    } catch (cause) {
      if (retry.reservation !== undefined) input.wallet._releaseReservation(retry.reservation.id);
      throw cause;
    }
    return new RingTransactionSubmission({
      first,
      build,
      wallet: input.wallet,
      ...(input.registry === undefined ? {} : { registry: input.registry }),
      ...(retry.reservation === undefined
        ? {}
        : {
            reservationId: retry.reservation.id,
            utxoHashes: retry.reservation.utxoHashes,
          }),
      reservation: {
        release: () => {
          if (retry.reservation !== undefined) {
            input.wallet._releaseReservation(retry.reservation.id);
          }
        },
        extend: () => {
          if (retry.entries !== undefined) checkRetainedEntries(input.wallet, retry.entries);
        },
      },
    });
  }

  async sendPersisted(
    input: WalletPersistence & Readonly<{ transport: RingSubmissionTransport }>,
    context?: RequestContext,
  ): Promise<RingSubmissionResult> {
    if (
      this.#busy ||
      (this.#wallet !== undefined && this.#wallet !== input.wallet) ||
      (this.#persistence !== undefined &&
        (this.#persistence.wallet !== input.wallet ||
          this.#persistence.store !== input.store ||
          this.#persistence.cipher !== input.cipher))
    )
      throw new RingError("RING_SUBMISSION_PENDING");
    this.#persistence = input;
    return this.send(input.transport, context);
  }

  async #checkpoint(signature: Signature): Promise<void> {
    const wallet = this.#wallet ?? this.#persistence?.wallet;
    wallet?._setPendingSubmission({
      id: this.#id,
      intentHash: this.#intent,
      utxoHashes: this.#utxoHashes,
      attempts: this.#attempts,
      signature,
      lastValidBlockHeight: this.#attempt.lastValidBlockHeight,
    });
    if (this.#persistence !== undefined) {
      await savePersistedWallet(this.#persistence);
      this.#persistedSignature = signature;
    }
  }

  /** Rust `BoundState::moved`. */
  async #moved(context?: RequestContext): Promise<boolean> {
    const { roots = [], trackingRoot, policy } = this.#attempt;
    const chain = this.#registry;
    if (chain === undefined) return false;
    if (trackingRoot !== undefined) {
      const tracking = await fetchTrackingRegistry(chain, trackingRoot.registry, context);
      const held = tracking.roots.some(
        (root) =>
          root?.revision === trackingRoot.revision && equalBytes(root.hash, trackingRoot.root),
      );
      if (!held) return true;
    }
    for (const bound of roots) {
      // Expiry is not checked here, an expired root fails on chain as `rootNotServed` and a reproof follows.
      const registry = await fetchStorageRegistry(chain, bound.registry, context);
      const held = registry.roots.some(
        (root) => root?.revision === bound.revision && equalBytes(root.hash, bound.root),
      );
      if (!held) return true;
    }
    if (policy === undefined) return false;
    const ringPolicy = await fetchRingPolicy(chain, policy.ringProgramId, context);
    return !equalBytes(ringPolicy.policyHash, policy.policyHash);
  }

  async #settleFailed(): Promise<void> {
    (this.#wallet ?? this.#persistence?.wallet)?._removePendingSubmission(this.#id);
    if (this.#persistence !== undefined) await savePersistedWallet(this.#persistence);
  }

  cancel(): void {
    if (this.#busy || this.#pending !== undefined) throw new RingError("RING_SUBMISSION_PENDING");
    this.#terminal = true;
    this.#reservation.release();
  }

  /** Unknown submissions must resolve before another broadcast. */
  async send(
    transport: RingSubmissionTransport,
    context?: RequestContext,
  ): Promise<RingSubmissionResult> {
    if (this.#busy || this.#terminal) throw new RingError("RING_SUBMISSION_PENDING");
    this.#busy = true;
    try {
      if (
        this.#pending !== undefined &&
        this.#persistence !== undefined &&
        this.#persistedSignature !== this.#pending
      )
        await this.#checkpoint(this.#pending);
      for (;;) {
        let concluded = this.#concluded;
        if (concluded === undefined) {
          // 1. The attempt signs and checkpoints ahead of any write. A restart then finds its record, reads its
          // signature to a conclusion and reaches the buffer through the record's id.
          const signature = this.#pending ?? (await this.#signAttempt(transport, context));
          // 2. Writes land in order, then the settlement broadcasts once, nothing else spends.
          const landed = await this.#land(signature, transport, context);
          if (landed.status.kind === "unknown")
            return { kind: "unknown", signature: landed.signature, attempts: this.#attempts };
          if (landed.status.kind === "confirmed") {
            this.#terminal = true;
            return {
              kind: "confirmed",
              signature: landed.signature,
              slot: landed.status.slot,
              attempts: this.#attempts,
            };
          }
          concluded = await this.#conclude(landed.signature, landed.status, context);
          this.#concluded = concluded;
        }
        // 3. Conclusive by here, an expired or refused settlement can no longer land and a failed write never let it
        // broadcast. The close precedes any rebuild, the next attempt writes to the same address.
        const closing = await this.#closeBuffer(transport, context);
        if (closing !== undefined)
          return { kind: "unknown", signature: closing, attempts: this.#attempts };
        // 4. The record leaves last, an interruption before here still names the buffer to a restarted wallet.
        this.#pending = undefined;
        this.#unsent = undefined;
        this.#written = 0;
        this.#concluded = undefined;
        await this.#settleFailed();
        if (!concluded.retry || this.#attempts >= MAX_ATTEMPTS) {
          this.#terminal = true;
          this.#reservation.release();
          return failedSubmission(
            { signature: concluded.signature, attempts: this.#attempts },
            concluded.status,
          );
        }
        this.#attempt = await this.#build(context);
      }
    } catch (cause) {
      if (this.#pending === undefined) {
        (this.#wallet ?? this.#persistence?.wallet)?._removePendingSubmission(this.#id);
        this.#terminal = true;
        this.#reservation.release();
      }
      throw cause;
    } finally {
      this.#busy = false;
    }
  }

  async #signAttempt(
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<Signature> {
    if (!equalBytes(this.#intent, this.#attempt.intentHash))
      throw new RingError("RING_INTENT_MISMATCH");
    this.#reservation.extend();
    const { signed, signature } = await signUnchanged(
      transport,
      this.#attempt.transaction,
      context,
    );
    this.#attempts += 1;
    await this.#checkpoint(signature);
    this.#pending = signature;
    this.#unsent = signed;
    return signature;
  }

  async #land(
    signature: Signature,
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<Landing> {
    const unsent = this.#unsent;
    let status: RingSubmissionStatus | undefined;
    if (unsent !== undefined) {
      const write = await this.#landWrites(transport, context);
      if (write !== undefined) return write;
      // Cleared first, an aborted broadcast stays pending and never sends again.
      this.#unsent = undefined;
      status = await broadcast(transport, unsent, context);
    }
    return {
      signature,
      status:
        status ??
        (await readStatus(
          transport,
          { signature, lastValidBlockHeight: this.#attempt.lastValidBlockHeight },
          context,
        )),
    };
  }

  /** `undefined` once every write is confirmed, each overwrites its own range so an unresolved one is only read. */
  async #landWrites(
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<Landing | undefined> {
    const upload = this.#attempt.upload;
    if (upload === undefined) return undefined;
    const writes = upload.frame.writes();
    for (const write of writes.slice(this.#written)) {
      const landed = await this.#landWriter(
        upload,
        write,
        RingInstructionTag.writeFrame,
        transport,
        context,
      );
      if (landed.status.kind !== "confirmed") return landed;
      this.#written += 1;
    }
    return undefined;
  }

  /** Runs without a priority fee, `BufferedFrame.writes` sizes each chunk to the header alone. */
  async #landWriter(
    upload: RingFrameUpload,
    instruction: Instruction,
    tag: RingInstructionTag,
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<Landing> {
    let status: RingSubmissionStatus | undefined;
    if (this.#inFlight === undefined) {
      const lifetime = await upload.chain.getLatestBlockhash(context);
      const { signed, signature } = await signUnchanged(
        transport,
        compileUnsignedTransaction({
          feePayer: upload.writer,
          lifetime,
          computeUnitLimit: ringComputeUnitLimit(tag),
          instructions: [instruction],
        }),
        context,
      );
      this.#inFlight = { signature, lastValidBlockHeight: lifetime.lastValidBlockHeight };
      status = await broadcast(transport, signed, context);
    }
    const inFlight = this.#inFlight;
    status ??= await readStatus(transport, inFlight, context);
    if (status.kind !== "unknown") this.#inFlight = undefined;
    return { signature: inFlight.signature, status };
  }

  async #conclude(
    signature: Signature,
    status: ConcludedAttempt["status"],
    context: RequestContext | undefined,
  ): Promise<ConcludedAttempt> {
    const ringCode =
      status.kind === "failed" && status.instructionIndex === this.#attempt.ringInstructionIndex
        ? status.customCode
        : undefined;
    // A failed registry, tree or slot read keeps the signature pending for the next call.
    const moved =
      ringCode === RingProgramError.proofVerificationFailed && (await this.#moved(context));
    return {
      signature,
      status,
      retry:
        status.kind === "expired" ||
        moved ||
        (ringCode !== undefined && STALE_PROOF_CODES.has(ringCode)),
    };
  }

  /**
   * `undefined` once the buffer is gone, else the close still on its way. An expired close sends again on the next
   * call, and a buffer no write created stays a miss. A refused close throws with the record kept, its rent and the
   * notes wait on the writer, `reconcileRingSubmissions` without `reclaim` gives the rent up.
   */
  async #closeBuffer(
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<Signature | undefined> {
    const upload = this.#attempt.upload;
    if (upload === undefined) return undefined;
    const { frame, chain } = upload;
    if (this.#inFlight === undefined && !(await bufferHeld(chain, frame.buffer, context)))
      return undefined;
    const close = await this.#landWriter(
      upload,
      frame.close(),
      RingInstructionTag.closeFrameBuffer,
      transport,
      context,
    );
    if (close.status.kind === "confirmed") return undefined;
    if (close.status.kind !== "failed") return close.signature;
    if (!(await bufferHeld(chain, frame.buffer, context))) return undefined;
    throw new RingError("RING_FRAME_BUFFER_CLOSE", {
      details: { buffer: frame.buffer, signature: close.signature },
    });
  }
}

/**
 * Reads each record to a conclusion. With `reclaim` a concluded attempt's buffer closes ahead of the record's removal,
 * a read past a still open close finds the buffer gone or sends again, and a repeated close costs at most its fee.
 */
export async function reconcileRingSubmissions(
  input: WalletPersistence &
    Readonly<{
      transport: Pick<RingSubmissionTransport, "status">;
      reclaim?: RingBufferReclaim;
    }>,
  context?: RequestContext,
): Promise<readonly RingSubmissionResult[]> {
  const results: RingSubmissionResult[] = [];
  for (const pending of input.wallet.pendingSubmissions()) {
    const status = await input.transport.status(pending, context);
    const current = input.wallet.pendingSubmissions().find((entry) => entry.id === pending.id);
    if (current?.signature !== pending.signature) continue;
    if (status.kind === "unknown") {
      results.push({ kind: "unknown", signature: pending.signature, attempts: pending.attempts });
      continue;
    }
    if (status.kind === "confirmed") {
      const unspent = new Set(
        input.wallet
          .utxos()
          .filter((entry) => !entry.spent)
          .map((entry) => bytesKey(entry.outputContext.hash)),
      );
      if (!pending.utxoHashes.some((hash) => unspent.has(bytesKey(hash)))) {
        input.wallet._releaseReservation(pending.id);
        input.wallet._removePendingSubmission(pending.id);
      }
      results.push({
        kind: "confirmed",
        signature: pending.signature,
        attempts: pending.attempts,
        slot: status.slot,
      });
    } else {
      const closing =
        input.reclaim === undefined
          ? undefined
          : await sendBufferClose(input.reclaim, pending.id, context);
      if (closing !== undefined) {
        results.push({ kind: "unknown", signature: closing, attempts: pending.attempts });
        continue;
      }
      input.wallet._releaseReservation(pending.id);
      input.wallet._removePendingSubmission(pending.id);
      results.push(failedSubmission(pending, status));
    }
  }
  await savePersistedWallet(input);
  return results;
}

/** The signature of a close on its way, `undefined` when no buffer stands at the record's address. */
async function sendBufferClose(
  reclaim: RingBufferReclaim,
  id: string,
  context: RequestContext | undefined,
): Promise<Signature | undefined> {
  const { chain, transport, writer } = reclaim;
  // The address and the close read the ring, the writer and the nonce, no frame byte.
  const frame = await BufferedFrame.of(
    {
      programAddress: reclaim.ringProgramId,
      data: Uint8Array.of(RingInstructionTag.transfer),
    },
    writer,
    submissionBufferNonce(id),
  );
  if (!(await bufferHeld(chain, frame.buffer, context))) return undefined;
  const lifetime = await chain.getLatestBlockhash(context);
  const { signed, signature } = await signUnchanged(
    transport,
    compileUnsignedTransaction({
      feePayer: writer,
      lifetime,
      computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.closeFrameBuffer),
      instructions: [frame.close()],
    }),
    context,
  );
  const refused = await broadcast(transport, signed, context);
  if (refused?.kind === "failed")
    throw new RingError("RING_FRAME_BUFFER_CLOSE", {
      details: { buffer: frame.buffer, signature },
    });
  return signature;
}

async function bufferHeld(
  chain: Pick<ChainReader, "getAccount">,
  buffer: Address,
  context: RequestContext | undefined,
): Promise<boolean> {
  return (await chain.getAccount(buffer, context)) !== undefined;
}

/** A signer that changes the message would sign a transaction the wallet never approved. */
async function signUnchanged(
  transport: RingSubmissionTransport,
  transaction: Transaction,
  context: RequestContext | undefined,
): Promise<Readonly<{ signed: Transaction; signature: Signature }>> {
  const approvedMessage = new Uint8Array(transaction.messageBytes);
  const signed = await transport.sign(transaction, context);
  if (!equalBytes(new Uint8Array(signed.messageBytes), approvedMessage))
    throw new RingError("RING_INTENT_MISMATCH");
  assertIsFullySignedTransaction(signed);
  return { signed, signature: getSignatureFromTransaction(signed) };
}

async function broadcast(
  transport: RingSubmissionTransport,
  signed: Transaction,
  context: RequestContext | undefined,
): Promise<RingSubmissionStatus | undefined> {
  try {
    return await transport.send(signed, context);
  } catch (cause) {
    // A send error leaves the signature pending.
    if (isClientError(cause) && cause.code === "CLIENT_ABORTED") throw cause;
    return undefined;
  }
}

async function readStatus(
  transport: RingSubmissionTransport,
  pending: RingSubmissionPending,
  context: RequestContext | undefined,
): Promise<RingSubmissionStatus> {
  try {
    return await transport.status(pending, context);
  } catch {
    return { kind: "unknown" };
  }
}

function failedSubmission(
  pending: Pick<PendingWalletSubmission, "signature" | "attempts">,
  status: Extract<RingSubmissionStatus, { kind: "failed" | "expired" }>,
): RingSubmissionResult {
  return {
    kind: "failed",
    signature: pending.signature,
    attempts: pending.attempts,
    ...(status.kind !== "failed" || status.instructionIndex === undefined
      ? {}
      : { instructionIndex: status.instructionIndex }),
    ...(status.kind !== "failed" || status.customCode === undefined
      ? {}
      : { customCode: status.customCode }),
  };
}

/** @internal */
export function checkRetainedEntries(wallet: Wallet, entries: readonly WalletUtxo[]): void {
  const current = wallet.utxos();
  for (const entry of entries) {
    const unspent = current.some(
      (known) => !known.spent && equalBytes(known.outputContext.hash, entry.outputContext.hash),
    );
    if (!unspent) {
      throw new RingError("RING_RESERVED_INPUT_SPENT", {
        details: { utxoHash: bytesKey(entry.outputContext.hash) },
      });
    }
  }
}

export function createKitRingSubmissionTransport(
  client: KitRpcAccess,
  signers: readonly TransactionPartialSigner[],
): RingSubmissionTransport {
  const heldSigners = [...signers];
  const send = sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc });
  return {
    // A write names its writer alone, and the kit refuses a signer the message does not name.
    sign: async (transaction, context) =>
      runKitRpc("signTransaction", context, (abortSignal) =>
        signTransactionWithSigners(
          heldSigners.filter((signer) => signer.address in transaction.signatures),
          transaction,
          { abortSignal },
        ),
      ),
    send: async (transaction, context) => {
      assertIsFullySignedTransaction(transaction);
      assertIsTransactionWithinSizeLimit(transaction);
      assertVersion1Transaction(transaction);
      return runKitRpc("sendTransaction", context, async (abortSignal) => {
        try {
          await send(transaction, { commitment: client.commitment, abortSignal });
          return undefined;
        } catch (cause) {
          const refusal = preflightRefusal(cause);
          if (refusal === undefined) throw cause;
          return refusal;
        }
      });
    },
    status: async (pending, context) => {
      const status = await readSignatureStatus(client, pending.signature, context);
      if (status !== null) return status;
      const height = await runKitRpc("getBlockHeight", context, (abortSignal) =>
        client.solanaRpc.getBlockHeight({ commitment: client.commitment }).send({ abortSignal }),
      );
      if (height <= pending.lastValidBlockHeight) return { kind: "unknown" };
      // Expiry cannot settle an absence observed before the last valid block.
      return (
        (await readSignatureStatus(client, pending.signature, context)) ?? {
          kind: "expired",
        }
      );
    },
  };
}

async function readSignatureStatus(
  client: KitRpcAccess,
  signature: Signature,
  context?: RequestContext,
): Promise<RingSubmissionStatus | null> {
  const response = await runKitRpc("getSignatureStatuses", context, (abortSignal) =>
    client.solanaRpc
      .getSignatureStatuses([signature], { searchTransactionHistory: true })
      .send({ abortSignal }),
  );
  if (response.value.length !== 1) return { kind: "unknown" };
  const status = response.value[0];
  if (status === undefined) return { kind: "unknown" };
  if (status === null) return null;
  if (status.confirmationStatus !== "confirmed" && status.confirmationStatus !== "finalized")
    return { kind: "unknown" };
  if (status.err === null) return { kind: "confirmed", slot: status.slot };
  return failedStatus(status.err);
}

/** The node's simulation refused the transaction, nothing was broadcast. */
function preflightRefusal(cause: unknown): RingSubmissionStatus | undefined {
  if (
    !isSolanaError(cause, SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE)
  )
    return undefined;
  const refusal: unknown = cause.cause;
  // Past its window, an upload outlasting the settlement's blockhash rebuilds as Rust `reproof_fixes` does.
  if (isSolanaError(refusal, SOLANA_ERROR__TRANSACTION_ERROR__BLOCKHASH_NOT_FOUND))
    return { kind: "expired" };
  if (isSolanaError(refusal, SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM)) {
    return {
      kind: "failed",
      instructionIndex: refusal.context.index,
      customCode: refusal.context.code,
    };
  }
  return { kind: "failed" };
}

/** Only `InstructionError: [index, { Custom }]` carries a program code. */
function failedStatus(error: unknown): RingSubmissionStatus {
  if (
    typeof error !== "object" ||
    error === null ||
    !("InstructionError" in error) ||
    !Array.isArray(error.InstructionError)
  )
    return { kind: "failed" };
  const [index, detail] = error.InstructionError;
  if (
    typeof index !== "number" ||
    !Number.isSafeInteger(index) ||
    index < 0 ||
    typeof detail !== "object" ||
    detail === null ||
    !("Custom" in detail) ||
    typeof detail.Custom !== "number" ||
    !Number.isSafeInteger(detail.Custom)
  )
    return { kind: "failed" };
  return { kind: "failed", instructionIndex: index, customCode: detail.Custom };
}
