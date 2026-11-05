/** One document holds a wallet's scan progress and everything it covers, one write stores both. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { bytesKey } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import { X25519PublicKey, type ViewTag } from "@heliuslabs/zolana/keypair";
import type { Wallet, WalletUtxo } from "@heliuslabs/zolana/transaction";

import { RingError } from "../protocol/error.js";
import { exactlyOne, unseen } from "./batch.js";
import { mintBalances, noteState, type MintBalance, type NoteState } from "./exposed-notes.js";
import { consumeScan, type AnonymousScan } from "./anonymous-sync.js";
import type { RingKeys } from "./ring-keys.js";
import { RingWallet, type NoteCommit, type NoteDelta } from "./ring-wallet.js";
import { parseExact, viewTagStream, ViewingHistory, type EntryStream } from "./viewing-history.js";

/** A reply read from a note, what a sender wrote about itself and nothing the proof binds. */
export interface PendingClaim {
  readonly utxoHash: Bytes32;
  readonly claimedViewingKey: X25519PublicKey;
  readonly claimedOwnerKey: Bytes32;
  readonly claimedNullifierPk: Bytes32;
}

/** What one confidential sync stores beside its notes, Rust `ScanCommit`. */
export interface ConfidentialCommit extends NoteDelta {
  /** The held keys the sync read and the slot their tag reads are complete through. */
  readonly tagPosition?: Readonly<{ keys: readonly X25519PublicKey[]; afterSlot: bigint }>;
  /** Stored retries whose spend row the sync read again. */
  readonly retried: readonly Bytes32[];
}

export class AnonymousWallet {
  readonly #notes: RingWallet;
  #history: ViewingHistory;
  #claims: readonly PendingClaim[];
  /** Spent by a merge whose output named an unregistered mint, each confidential sync reads the spend again. A Rust sync writes them, a TS sync stores such an output as pending. */
  #mergeRetries: ReadonlyMap<string, Bytes32>;

  private constructor(
    fields: Readonly<{
      notes: RingWallet;
      history: ViewingHistory;
      claims: readonly PendingClaim[];
      mergeRetries: readonly Bytes32[];
    }>,
  ) {
    this.#notes = fields.notes;
    this.#history = fields.history;
    this.#claims = fields.claims;
    this.#mergeRetries = new Map(
      fields.mergeRetries.map((nullifier) => [bytesKey(nullifier), nullifier]),
    );
  }

  static create(wallet: Wallet, history: ViewingHistory): AnonymousWallet {
    return new AnonymousWallet({
      notes: RingWallet.create(wallet),
      history,
      claims: [],
      mergeRetries: [],
    });
  }

  /** Holds the notes and spends, a transfer selects from it. */
  get wallet(): Wallet {
    return this.#notes.wallet;
  }

  history(): ViewingHistory {
    return this.#history;
  }

  notes(): readonly WalletUtxo[] {
    return this.wallet.utxos();
  }

  noteState(note: WalletUtxo): NoteState {
    return noteState(note);
  }

  /** Unspent zero-key notes, only a public spend naming the wallet takes one. */
  exposedNotes(): readonly WalletUtxo[] {
    return this.wallet.utxos().filter((note) => noteState(note) === "exposedIfSpent");
  }

  balances(): ReadonlyMap<Address, MintBalance> {
    return mintBalances(this.wallet.utxos());
  }

  /** Stored and unspendable, the next absorb or `promotePending` moves each once its mint registers. */
  pendingOpenings(): readonly WalletUtxo[] {
    return this.#notes.pendingOpenings();
  }

  /** Replies the wallet has not confirmed, none reads as a verified sender. */
  pendingClaims(): readonly PendingClaim[] {
    return this.#claims;
  }

  /** The wallet's own decision to trust a claimed sender, nothing else confirms one. */
  confirmClaim(claimed: X25519PublicKey): void {
    if (!this.#claims.some((claim) => claim.claimedViewingKey.equals(claimed)))
      throw new RingError("RING_UNKNOWN_SENDER_CLAIM");
    this.#history = this.#history.withConfirmedSender(claimed);
    this.#claims = this.#claims.filter((claim) => !claim.claimedViewingKey.equals(claimed));
  }

  /** Takes a scan's notes, spends, claims and progress together and consumes it. */
  async absorb(scan: AnonymousScan): Promise<void> {
    return this.wallet._withSyncLock(async () => {
      consumeScan(scan, this.#history);
      const claimed = new Set(this.#claims.map((claim) => bytesKey(claim.utxoHash)));
      const claims = scan.senderClaims
        .filter((claim) => unseen(claimed, bytesKey(claim.utxoHash)))
        .map(({ utxoHash, claim: { claimed: reply } }): PendingClaim =>
          Object.freeze({
            utxoHash,
            claimedViewingKey: reply.viewingKey,
            claimedOwnerKey: reply.ownerKey,
            claimedNullifierPk: reply.nullifierPk,
          }),
        );
      this.#notes._absorb(
        {
          notes: [...scan.utxos, ...scan.pendingOpenings],
          spentNullifiers: scan.spentNullifiers,
        },
        this.wallet,
        (commit) => this.wallet._replace({ ...this.wallet._state(), ...commit }),
      );
      this.#claims = [...this.#claims, ...claims];
      this.#history = this.#history._withScanProgress(scan.history);
    });
  }

  /** @internal */
  _mergeRetries(): readonly Bytes32[] {
    return [...this.#mergeRetries.values()];
  }

  /**
   * @internal Lands one confidential sync, the caller holds the sync lock.
   *
   * `write` stores the wallet fields and the core checkpoints, a refusal there leaves the positions and retries unmoved.
   */
  _absorbConfidential(
    commit: ConfidentialCommit,
    base: Wallet,
    write: (fields: NoteCommit) => void,
  ): void {
    this.#notes._absorb(commit, base, write);
    const { tagPosition } = commit;
    if (tagPosition !== undefined)
      this.#history = this.#history._withTagPosition(tagPosition.keys, tagPosition.afterSlot);
    // A retry leaves only once the indexer returned its spend row, a lagging indexer keeps it stored.
    const retries = new Map(this.#mergeRetries);
    for (const nullifier of commit.retried) retries.delete(bytesKey(nullifier));
    this.#mergeRetries = retries;
  }

  /** Moves each pending note whose mint now registers into the spendable notes, the moved ones returned. */
  promotePending(): Promise<readonly WalletUtxo[]> {
    return this.#notes.promotePending();
  }

  /** Only raises a tag counter or adds a key. */
  updateHistory(updated: ViewingHistory): void {
    if (!updated._progressMatches(this.#history)) throw new RingError("RING_SCAN_PROGRESS_MOVED");
    this.#history = updated;
  }

  /** The current key's next sender tag, concurrent callers never share one. */
  takeSenderTag(keys: RingKeys, context?: RequestContext): Promise<ViewTag> {
    return this.#takeTag(keys, "tx", context);
  }

  /** A fresh `recipientRequestViewTag`, concurrent callers never share one. */
  takeRequestTag(keys: RingKeys, context?: RequestContext): Promise<ViewTag> {
    return this.#takeTag(keys, "request", context);
  }

  /** A holder failure burns the index, the gap scan passes it. */
  async #takeTag(
    keys: RingKeys,
    stream: EntryStream,
    context: RequestContext | undefined,
  ): Promise<ViewTag> {
    const current = this.#history.current();
    const { index, counter } = current[stream].takeNext();
    this.#history = this.#history.withEntry(
      this.#history.entries.length - 1,
      current.withCounter(stream, counter),
    );
    return exactlyOne(
      await keys.viewTags(
        [{ viewingPublicKey: current.viewingPublicKey, stream: viewTagStream(stream, index) }],
        context,
      ),
    );
  }

  /** Its notes open the wallet's funds, store it as key material under one atomic replace. */
  toJson(): string {
    const claims = this.#claims.map((claim) => ({
      utxoHash: bytesToHex(claim.utxoHash),
      claimedViewingKey: bytesToHex(claim.claimedViewingKey.toBytes()),
      claimedOwnerKey: bytesToHex(claim.claimedOwnerKey),
      claimedNullifierPk: bytesToHex(claim.claimedNullifierPk),
    }));
    const { wallet, pending } = this.#notes._documentFields();
    return (
      `{"history":${this.#history.toJson()},` +
      `"wallet":${JSON.stringify(wallet)},` +
      `"pending":${JSON.stringify(pending)},` +
      `"claims":${JSON.stringify(claims)},` +
      `"mergeRetries":${JSON.stringify([...this.#mergeRetries.keys()].sort())}}`
    );
  }

  static fromJson(text: string): AnonymousWallet {
    const stored = document(parseExact(text));
    const { history, wallet, pending, claims, mergeRetries } = stored;
    const known = ["history", "wallet", "pending", "claims", "mergeRetries"];
    if (Object.keys(stored).some((key) => !known.includes(key)))
      throw invalid("the document names other fields");
    if (!Array.isArray(claims)) throw invalid("claims is not a list");
    if (!Array.isArray(mergeRetries)) throw invalid("mergeRetries is not a list");
    return new AnonymousWallet({
      notes: RingWallet._fromDocument(wallet, pending),
      history: ViewingHistory._fromValue(history),
      claims: claims.map(storedClaim),
      mergeRetries: mergeRetries.map(field),
    });
  }
}

function storedClaim(value: unknown): PendingClaim {
  const claim = document(value);
  try {
    return Object.freeze({
      utxoHash: field(claim["utxoHash"]),
      claimedViewingKey: X25519PublicKey.fromBytes(hexToBytes(String(claim["claimedViewingKey"]))),
      claimedOwnerKey: field(claim["claimedOwnerKey"]),
      claimedNullifierPk: field(claim["claimedNullifierPk"]),
    });
  } catch (cause) {
    if (cause instanceof RingError) throw cause;
    throw invalid("a claimed viewing key is not tagged");
  }
}

function field(value: unknown): Bytes32 {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value))
    throw invalid("a stored value is not 32 hex bytes");
  return hexToBytes(value) as Bytes32;
}

function document(value: unknown): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw invalid("is not an object");
  return value as Readonly<Record<string, unknown>>;
}

function invalid(reason: string): RingError {
  return new RingError("RING_WALLET_DOCUMENT", { details: { reason } });
}
