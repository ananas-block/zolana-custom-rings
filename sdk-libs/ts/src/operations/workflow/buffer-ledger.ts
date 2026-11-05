/**
 * A wallet's frame buffer writes and closes that can still land, kept beside the wallet's submission records.
 *
 * Read `RingTransactionSubmission` first. It holds an entry from before each buffer broadcast until its attempt ends,
 * `reconcileRingSubmissions` settles an entry once its signature resolves, and `closeAbandonedFrameBuffers` waits for
 * an empty ledger. The wallet record covers the settlement and its notes, a refused settlement settles that record
 * while its close can still land.
 */
import { isSignature } from "@solana/kit";
import type { WalletStateStore } from "@heliuslabs/zolana/wallet";

import { RingError } from "../../protocol/error.js";
import type { RingSubmissionPending } from "../../rpc/ports.js";

export interface RingBufferTransaction extends RingSubmissionPending {
  /** The id of the wallet record the transaction's attempt belongs to. */
  readonly submission: string;
  readonly phase: "write" | "close";
}

const VERSION = 1;
const SUBMISSION_ID = /^[0-9a-f]{32}$/u;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

export class RingBufferLedger {
  readonly #store: WalletStateStore;
  #entries: readonly RingBufferTransaction[];
  #saving: Promise<void> = Promise.resolve();
  /** A failed save left the store behind the entries, the next change saves even when it changes nothing. */
  #dirty = false;

  private constructor(store: WalletStateStore, entries: readonly RingBufferTransaction[]) {
    this.#store = store;
    this.#entries = entries;
  }

  /** The document holds signatures and lifetimes alone, every one public on chain. */
  static async load(store: WalletStateStore): Promise<RingBufferLedger> {
    const document = await store.load();
    return new RingBufferLedger(store, document === undefined ? [] : parseLedger(document));
  }

  entries(): readonly RingBufferTransaction[] {
    return this.#entries;
  }

  /** @internal Saved before it returns, one entry per submission, the newer transaction replacing the older. */
  async _hold(entry: RingBufferTransaction): Promise<void> {
    await this.#commit([
      ...this.#entries.filter((held) => held.submission !== entry.submission),
      Object.freeze({ ...entry }),
    ]);
  }

  /** @internal Leaves a newer transaction of the same submission in place. */
  async _settle(entry: Pick<RingBufferTransaction, "submission" | "signature">): Promise<void> {
    if (!this.#dirty && !this.#entries.some((held) => matches(held, entry))) return;
    await this.#commit(this.#entries.filter((held) => !matches(held, entry)));
  }

  /** @internal The attempt ended, its last buffer transaction resolved. */
  async _drop(submission: string): Promise<void> {
    if (!this.#dirty && !this.#entries.some((held) => held.submission === submission)) return;
    await this.#commit(this.#entries.filter((held) => held.submission !== submission));
  }

  /** Saves run one at a time, each writes the entries current when it starts and so covers every earlier change. */
  async #commit(entries: readonly RingBufferTransaction[]): Promise<void> {
    this.#entries = Object.freeze(entries);
    const saved = this.#saving
      .catch(() => undefined)
      .then(() => this.#store.save(this.#document()));
    this.#saving = saved;
    try {
      await saved;
      this.#dirty = false;
    } catch (cause) {
      this.#dirty = true;
      throw cause;
    }
  }

  #document(): string {
    return JSON.stringify({
      version: VERSION,
      entries: this.#entries.map((entry) => ({
        submission: entry.submission,
        phase: entry.phase,
        signature: entry.signature,
        lastValidBlockHeight: entry.lastValidBlockHeight.toString(),
      })),
    });
  }
}

function matches(
  held: RingBufferTransaction,
  entry: Pick<RingBufferTransaction, "submission" | "signature">,
): boolean {
  return held.submission === entry.submission && held.signature === entry.signature;
}

function parseLedger(document: string): readonly RingBufferTransaction[] {
  let stored: unknown;
  try {
    stored = JSON.parse(document);
  } catch {
    throw invalid("is not JSON");
  }
  const { version, entries, ...other } = record(stored, "is not an object");
  if (version !== VERSION || Object.keys(other).length > 0 || !Array.isArray(entries))
    throw invalid("is not a version 1 buffer ledger");
  const parsed = entries.map(parseEntry);
  if (new Set(parsed.map((entry) => entry.submission)).size !== parsed.length)
    throw invalid("names one submission twice");
  return Object.freeze(parsed);
}

function parseEntry(value: unknown): RingBufferTransaction {
  const { submission, phase, signature, lastValidBlockHeight, ...other } = record(
    value,
    "holds an entry that is not an object",
  );
  if (Object.keys(other).length > 0) throw invalid("holds an entry with other fields");
  if (typeof submission !== "string" || !SUBMISSION_ID.test(submission))
    throw invalid("holds an invalid submission id");
  if (phase !== "write" && phase !== "close") throw invalid("holds an unknown phase");
  if (typeof signature !== "string" || !isSignature(signature))
    throw invalid("holds an invalid signature");
  if (
    typeof lastValidBlockHeight !== "string" ||
    !/^(0|[1-9]\d{0,19})$/u.test(lastValidBlockHeight)
  )
    throw invalid("holds an invalid lifetime");
  const height = BigInt(lastValidBlockHeight);
  if (height > U64_MAX) throw invalid("holds an invalid lifetime");
  return Object.freeze({
    submission,
    phase,
    signature,
    lastValidBlockHeight: height,
  });
}

function record(value: unknown, reason: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid(reason);
  return value as Readonly<Record<string, unknown>>;
}

function invalid(reason: string): RingError {
  return new RingError("RING_WALLET_DOCUMENT", { details: { document: "buffer ledger", reason } });
}
