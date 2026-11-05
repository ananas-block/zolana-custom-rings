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
  addressBytes,
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
import { frameBufferWriter } from "../../protocol/transaction/frame-buffer.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import { fetchTrackingRegistry } from "../../rpc/tracking-resolver.js";
import { ringComputeUnitLimit } from "../management/admin.js";
import { BufferedFrame, closeFrameBuffer } from "../payments/buffered-frame.js";
import { TransactionFit } from "./address-ceiling.js";
import type { RingBufferLedger, RingBufferTransaction } from "./buffer-ledger.js";
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

/** What `closeAbandonedFrameBuffers` closes through, a wallet's record names neither ring nor writer. */
export interface RingBufferReclaim {
  readonly ringProgramId: Address;
  readonly writer: Address;
  readonly chain: Pick<ChainReader, "getProgramAccounts"> & BlockhashProvider;
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

/** @internal Rust `REPROOF`, pinned row for row by the parity test. */
export const REPROOF: ReadonlyMap<number, "fixes" | "ifMoved"> = new Map([
  [RingProgramError.rootNotServed, "fixes"],
  [RingProgramError.trackingRootBelowFloor, "fixes"],
  [RingProgramError.unboundRegistry, "fixes"],
  [RingProgramError.proofVerificationFailed, "ifMoved"],
]);
const NO_RESERVATION: ReservationHold = Object.freeze({ release() {}, extend() {} });

/**
 * One proven transfer as an attempt, Rust `RingSubmission::send`'s choice over the complete transaction, setup included.
 * Clear `buffered` keeps a transfer inline, a caller holding one transaction has nowhere to land writes.
 */
export async function provenRingAttempt(
  input: Readonly<{
    proven: ProvenRingTransfer;
    feePayer: Address;
    chain: RingFrameUpload["chain"];
    transaction: RingTransactionFrame;
    intentHash: Bytes32;
    buffered: boolean;
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
  const fit = input.buffered
    ? await TransactionFit.of(inline, signers, budget)
    : TransactionFit.inline(inline, signers, budget);
  const upload =
    fit.transport === "buffered" ? await BufferedFrame.forWriter(inline, feePayer) : undefined;
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

type WriteLanding = Readonly<{
  signature: Signature;
  status: Exclude<RingSubmissionStatus, { kind: "confirmed" }>;
}>;

/** An attempt that can no longer land, held until its buffer is gone. */
type ConcludedAttempt = Readonly<{
  signature: Signature;
  status: Extract<RingSubmissionStatus, { kind: "failed" | "expired" }>;
  retry: boolean;
}>;

interface HeldTransaction extends RingSubmissionPending {
  unsent: Transaction | undefined;
}

/** Rust `Stage`, with the close the buffer ledger also waits on. */
type AttemptPhase = UploadPhase | SettlePhase | ClosePhase;
type UploadPhase = Readonly<{
  kind: "upload";
  settlement: HeldTransaction;
  upload: RingFrameUpload;
  /** Confirmed writes, a write landing resumes after them. */
  written: number;
  write: HeldTransaction | undefined;
}>;
type SettlePhase = Readonly<{ kind: "settle"; settlement: HeldTransaction }>;
type ClosePhase = Readonly<{
  kind: "close";
  settlement: HeldTransaction;
  upload: RingFrameUpload | undefined;
  concluded: ConcludedAttempt;
  close: HeldTransaction | undefined;
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
  #buffers: RingBufferLedger | undefined;
  #attempt: RingSubmissionAttempt;
  /** `undefined` until the attempt's settlement signs and its record saves. */
  #phase: AttemptPhase | undefined;
  #record: (RingSubmissionPending & { saved: boolean }) | undefined;
  /** A record the wallet held and no longer lists was settled by `reconcileRingSubmissions`. */
  #held = false;
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
    input: WalletPersistence &
      Readonly<{ transport: RingSubmissionTransport; buffers: RingBufferLedger }>,
    context?: RequestContext,
  ): Promise<RingSubmissionResult> {
    if (
      this.#busy ||
      (this.#buffers !== undefined && this.#buffers !== input.buffers) ||
      (this.#wallet !== undefined && this.#wallet !== input.wallet) ||
      (this.#persistence !== undefined &&
        (this.#persistence.wallet !== input.wallet ||
          this.#persistence.store !== input.store ||
          this.#persistence.cipher !== input.cipher))
    )
      throw new RingError("RING_SUBMISSION_PENDING");
    this.#persistence = input;
    this.#buffers = input.buffers;
    return this.send(input.transport, context);
  }

  cancel(): void {
    if (this.#busy || this.#phase !== undefined) throw new RingError("RING_SUBMISSION_PENDING");
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
      await this.#save();
      for (;;) {
        // 1. The settlement signs and its record saves ahead of any write. The record holds the notes until the
        // settlement resolves.
        let phase = this.#phase ?? (await this.#signSettlement(transport, context));
        // 2. Writes land in order, each held in the buffer ledger ahead of its broadcast. A refused or expired write
        // never lets the settlement broadcast.
        if (phase.kind === "upload") {
          const write = await this.#landWrites(phase, transport, context);
          if (write === undefined) {
            phase = this.#enter({ kind: "settle", settlement: phase.settlement });
          } else {
            const { signature, status } = write;
            if (status.kind === "unknown") return this.#unknown(signature);
            phase = await this.#conclude(phase, { signature, status }, context);
          }
        }
        // 3. The settlement broadcasts once, nothing else spends.
        if (phase.kind === "settle") {
          const { signature } = phase.settlement;
          const status: RingSubmissionStatus = this.#withheld(phase.settlement)
            ? { kind: "expired" }
            : await land(phase.settlement, transport, context);
          if (status.kind === "unknown") return this.#unknown(signature);
          if (status.kind === "confirmed") {
            // The settlement closed the buffer, no write of the attempt can land after it.
            await this.#buffers?._drop(this.#id);
            this.#terminal = true;
            return { kind: "confirmed", signature, slot: status.slot, attempts: this.#attempts };
          }
          phase = await this.#conclude(phase, { signature, status }, context);
        }
        // 4. Conclusive by here, an expired or refused settlement can no longer land and a failed write never let it
        // broadcast. A rebuilt frame takes another digest and another buffer, so the rent of the old one returns now.
        const closing = await this.#closeBuffer(phase, transport, context);
        if (closing !== undefined) return this.#unknown(closing);
        // 5. The ledger entry and the record leave last, an interruption before here keeps the buffer from reading as
        // abandoned. A record reconcile already settled released its notes, so no rebuild follows.
        const { concluded } = phase;
        const reconciled = this.#reconciled();
        this.#phase = undefined;
        await this.#buffers?._drop(this.#id);
        await this.#dropRecord();
        if (reconciled || !concluded.retry || this.#attempts >= MAX_ATTEMPTS) {
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
      if (this.#phase === undefined) {
        this.#holder()?._removePendingSubmission(this.#id);
        this.#record = undefined;
        this.#held = false;
        this.#terminal = true;
        this.#reservation.release();
      }
      throw cause;
    } finally {
      this.#busy = false;
    }
  }

  async #signSettlement(
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<UploadPhase | SettlePhase> {
    if (!equalBytes(this.#intent, this.#attempt.intentHash))
      throw new RingError("RING_INTENT_MISMATCH");
    this.#reservation.extend();
    const { signed, signature } = await signUnchanged(
      transport,
      this.#attempt.transaction,
      context,
    );
    this.#attempts += 1;
    const { lastValidBlockHeight, upload } = this.#attempt;
    const settlement = { signature, lastValidBlockHeight, unsent: signed };
    await this.#checkpoint(settlement);
    return this.#enter(
      upload === undefined
        ? { kind: "settle", settlement }
        : { kind: "upload", settlement, upload, written: 0, write: undefined },
    );
  }

  /** `undefined` once every write is confirmed, each overwrites its own range so an unresolved one is only read. */
  async #landWrites(
    phase: UploadPhase,
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<WriteLanding | undefined> {
    for (const instruction of phase.upload.frame.writes().slice(phase.written)) {
      if (phase.write === undefined && this.#withheld(phase.settlement))
        return { signature: phase.settlement.signature, status: { kind: "expired" } };
      const write =
        phase.write ??
        (await this.#signBufferTransaction(
          { upload: phase.upload, instruction, phase: "write" },
          transport,
          context,
        ));
      phase = this.#enter({ ...phase, write });
      const status = await land(write, transport, context);
      if (status.kind !== "confirmed") return { signature: write.signature, status };
      phase = this.#enter({ ...phase, written: phase.written + 1, write: undefined });
    }
    return undefined;
  }

  /** Runs without a priority fee, `BufferedFrame.writes` sizes each chunk to the header alone. */
  async #signBufferTransaction(
    owed: Readonly<{
      upload: RingFrameUpload;
      instruction: Instruction;
      phase: RingBufferTransaction["phase"];
    }>,
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<HeldTransaction> {
    const { upload, instruction, phase } = owed;
    const { writer, chain } = upload;
    const tag =
      phase === "write" ? RingInstructionTag.writeFrame : RingInstructionTag.closeFrameBuffer;
    const lifetime = await chain.getLatestBlockhash(context);
    const { signed, signature } = await signUnchanged(
      transport,
      compileUnsignedTransaction({
        feePayer: writer,
        lifetime,
        computeUnitLimit: ringComputeUnitLimit(tag),
        instructions: [instruction],
      }),
      context,
    );
    const { lastValidBlockHeight } = lifetime;
    await this.#buffers?._hold({ submission: this.#id, phase, signature, lastValidBlockHeight });
    return { signature, lastValidBlockHeight, unsent: signed };
  }

  /** Enters the close phase only once the retry decision is made, a failed read keeps the signature to read again. */
  async #conclude(
    phase: UploadPhase | SettlePhase,
    landed: Readonly<{ signature: Signature; status: ConcludedAttempt["status"] }>,
    context: RequestContext | undefined,
  ): Promise<ClosePhase> {
    const { signature, status } = landed;
    const ringCode =
      status.kind === "failed" && status.instructionIndex === this.#attempt.ringInstructionIndex
        ? status.customCode
        : undefined;
    const reproof = ringCode === undefined ? undefined : REPROOF.get(ringCode);
    const retry =
      status.kind === "expired" ||
      reproof === "fixes" ||
      (reproof === "ifMoved" && (await this.#moved(context)));
    return this.#enter({
      kind: "close",
      settlement: phase.settlement,
      upload: this.#attempt.upload,
      concluded: { signature, status, retry },
      close: undefined,
    });
  }

  /**
   * `undefined` once the buffer is gone, else the close still on its way. An expired close signs again on the next
   * call, and a buffer no write created stays a miss. A refused close throws with the record kept, its rent and the
   * notes wait on the writer, `reconcileRingSubmissions` settles the record and leaves the buffer to a later close.
   */
  async #closeBuffer(
    phase: ClosePhase,
    transport: RingSubmissionTransport,
    context: RequestContext | undefined,
  ): Promise<Signature | undefined> {
    const { upload } = phase;
    if (upload === undefined) return undefined;
    const { frame, chain } = upload;
    if (phase.close === undefined && !(await bufferHeld(chain, frame.buffer, context)))
      return undefined;
    const close =
      phase.close ??
      (await this.#signBufferTransaction(
        { upload, instruction: frame.close(), phase: "close" },
        transport,
        context,
      ));
    this.#enter({ ...phase, close });
    const status = await land(close, transport, context);
    if (status.kind === "unknown") return close.signature;
    this.#enter({ ...phase, close: undefined });
    if (status.kind === "confirmed") return undefined;
    if (status.kind === "expired") return close.signature;
    if (!(await bufferHeld(chain, frame.buffer, context))) return undefined;
    throw new RingError("RING_FRAME_BUFFER_CLOSE", {
      details: { buffer: frame.buffer, transactionId: close.signature },
    });
  }

  #enter<Phase extends AttemptPhase>(phase: Phase): Phase {
    this.#phase = phase;
    return phase;
  }

  #unknown(signature: Signature): RingSubmissionResult {
    return { kind: "unknown", signature, attempts: this.#attempts };
  }

  #holder(): Wallet | undefined {
    return this.#wallet ?? this.#persistence?.wallet;
  }

  async #checkpoint(settlement: RingSubmissionPending): Promise<void> {
    const { signature, lastValidBlockHeight } = settlement;
    this.#record = { signature, lastValidBlockHeight, saved: false };
    await this.#save();
  }

  /** A settlement never sent stays unsent once reconcile freed its notes, the attempt goes to its close. */
  #withheld(settlement: HeldTransaction): boolean {
    if (settlement.unsent === undefined || !this.#reconciled()) return false;
    settlement.unsent = undefined;
    return true;
  }

  #reconciled(): boolean {
    const holder = this.#holder();
    return (
      this.#held &&
      holder !== undefined &&
      !holder.pendingSubmissions().some((pending) => pending.id === this.#id)
    );
  }

  async #save(): Promise<void> {
    const record = this.#record;
    if (record === undefined || record.saved) return;
    // A record written back after its reservation was released leaves a snapshot that no longer loads.
    if (this.#reconciled()) {
      this.#terminal = true;
      throw new RingError("RING_SUBMISSION_PENDING", { details: { reason: "reconciled" } });
    }
    const holder = this.#holder();
    if (holder !== undefined) {
      holder._setPendingSubmission({
        id: this.#id,
        intentHash: this.#intent,
        utxoHashes: this.#utxoHashes,
        attempts: this.#attempts,
        signature: record.signature,
        lastValidBlockHeight: record.lastValidBlockHeight,
      });
      this.#held = true;
    }
    if (this.#persistence === undefined) return;
    await savePersistedWallet(this.#persistence);
    record.saved = true;
  }

  async #dropRecord(): Promise<void> {
    this.#record = undefined;
    this.#held = false;
    this.#holder()?._removePendingSubmission(this.#id);
    if (this.#persistence !== undefined) await savePersistedWallet(this.#persistence);
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
}

/** Settles each record and buffer ledger entry whose signature resolved, an unknown signature or a confirmed record with unspent notes stays held. */
export async function reconcileRingSubmissions(
  input: WalletPersistence &
    Readonly<{ transport: Pick<RingSubmissionTransport, "status">; buffers: RingBufferLedger }>,
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
      input.wallet._releaseReservation(pending.id);
      input.wallet._removePendingSubmission(pending.id);
      results.push(failedSubmission(pending, status));
    }
  }
  await savePersistedWallet(input);
  // A write or close can outlive its record, its entry waits for its own signature.
  for (const held of input.buffers.entries()) {
    const { signature, lastValidBlockHeight } = held;
    const status = await input.transport.status({ signature, lastValidBlockHeight }, context);
    if (status.kind !== "unknown") await input.buffers._settle(held);
  }
  return results;
}

/**
 * Returns the rent of the buffers `writer` left on the ring, the signatures of the closes sent, empty once none stands.
 *
 * A wallet's record holds no buffer address and a digest nonce names a frame it does not keep, so the chain names them.
 * A record or a ledger entry refuses with `RING_SUBMISSION_PENDING`, a settlement, write or close of the wallet's own
 * can still land on its buffer. A writer another wallet shares can lose a buffer that wallet's upload still needs,
 * its settlement then fails before spending and the submission retries.
 */
export async function closeAbandonedFrameBuffers(
  input: RingBufferReclaim & Readonly<{ wallet: Wallet; buffers: RingBufferLedger }>,
  context?: RequestContext,
): Promise<readonly Signature[]> {
  const { chain, transport, writer, ringProgramId } = input;
  if (input.wallet.pendingSubmissions().length > 0 || input.buffers.entries().length > 0)
    throw new RingError("RING_SUBMISSION_PENDING");
  const held = await chain.getProgramAccounts(ringProgramId, context);
  const owned = held.filter(({ account }) => {
    const bufferWriter = frameBufferWriter(account.data);
    return bufferWriter !== undefined && equalBytes(bufferWriter, addressBytes(writer));
  });
  const signatures: Signature[] = [];
  for (const { address: buffer } of owned) {
    const lifetime = await chain.getLatestBlockhash(context);
    const { signed, signature } = await signUnchanged(
      transport,
      compileUnsignedTransaction({
        feePayer: writer,
        lifetime,
        computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.closeFrameBuffer),
        instructions: [closeFrameBuffer(ringProgramId, writer, buffer)],
      }),
      context,
    );
    const refused = await broadcast(transport, signed, context);
    if (refused?.kind === "failed")
      throw new RingError("RING_FRAME_BUFFER_CLOSE", {
        details: { buffer, transactionId: signature },
      });
    signatures.push(signature);
  }
  return Object.freeze(signatures);
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

async function land(
  held: HeldTransaction,
  transport: RingSubmissionTransport,
  context: RequestContext | undefined,
): Promise<RingSubmissionStatus> {
  const { signature, lastValidBlockHeight, unsent } = held;
  // Cleared first, an aborted broadcast stays held and never sends again.
  held.unsent = undefined;
  const status = unsent === undefined ? undefined : await broadcast(transport, unsent, context);
  return status ?? (await readStatus(transport, { signature, lastValidBlockHeight }, context));
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
