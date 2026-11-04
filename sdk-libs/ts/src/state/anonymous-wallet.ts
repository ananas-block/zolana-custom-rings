/** One document holds a wallet's scan progress and everything it covers, one write stores both. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { bytesKey } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import { X25519PublicKey, type ShieldedAddress, type ViewTag } from "@heliuslabs/zolana/keypair";
import {
  deserializeWallet,
  serializeWallet,
  Wallet,
  type AssetRegistry,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";

import { RingError } from "../protocol/error.js";
import { exactlyOne, unseen } from "./batch.js";
import { mintBalances, noteState, type MintBalance, type NoteState } from "./exposed-notes.js";
import { consumeScan, type AnonymousScan } from "./anonymous-sync.js";
import { registeredMint } from "../operations/workflow/recover.js";
import type { RingKeys } from "./ring-keys.js";
import { parseExact, viewTagStream, ViewingHistory, type EntryStream } from "./viewing-history.js";

export const ANONYMOUS_WALLET_VERSION = 1;

/** A reply read from a note, what a sender wrote about itself and nothing the proof binds. */
export interface PendingClaim {
  readonly utxoHash: Bytes32;
  readonly claimedViewingKey: X25519PublicKey;
  readonly claimedOwnerKey: Bytes32;
  readonly claimedNullifierPk: Bytes32;
}

export class AnonymousWallet {
  /** Holds the notes and spends, a transfer selects from it. */
  readonly wallet: Wallet;
  /** Notes under a mint the registry lacks, a transfer never selects from it. */
  readonly #pending: Wallet;
  #history: ViewingHistory;
  #claims: readonly PendingClaim[];

  private constructor(
    fields: Readonly<{
      wallet: Wallet;
      pending: Wallet;
      history: ViewingHistory;
      claims: readonly PendingClaim[];
    }>,
  ) {
    this.wallet = fields.wallet;
    this.#pending = fields.pending;
    this.#history = fields.history;
    this.#claims = fields.claims;
  }

  static create(wallet: Wallet, history: ViewingHistory): AnonymousWallet {
    return new AnonymousWallet({
      wallet,
      pending: new Wallet({ identity: wallet.identity, registry: wallet.registry }),
      history,
      claims: [],
    });
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

  /** Stored and unspendable, `promotePending` moves each once its mint registers, no rescan needed. */
  pendingOpenings(): readonly WalletUtxo[] {
    return this.#pending.utxos();
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
      const state = this.wallet._state();
      const nullifiers = new Set([...state.nullifiers, ...scan.spentNullifiers.map(bytesKey)]);
      const pendingState = this.#pending._state();
      const hashes = new Set(
        [...state.utxos, ...pendingState.utxos].map((entry) => bytesKey(entry.outputContext.hash)),
      );
      const fresh = scan.utxos.filter((entry) =>
        unseen(hashes, bytesKey(entry.outputContext.hash)),
      );
      const freshPending = scan.pendingOpenings.filter((entry) =>
        unseen(hashes, bytesKey(entry.outputContext.hash)),
      );
      const marked = (notes: readonly WalletUtxo[]): readonly WalletUtxo[] =>
        notes.map((entry) =>
          nullifiers.has(bytesKey(entry.nullifier)) ? { ...entry, spent: true } : entry,
        );
      const claimed = new Set(this.#claims.map((claim) => bytesKey(claim.utxoHash)));
      const claims = scan.replyClaims
        .filter((claim) => unseen(claimed, bytesKey(claim.utxoHash)))
        .map(({ utxoHash, reply }): PendingClaim =>
          Object.freeze({
            utxoHash,
            claimedViewingKey: reply.viewingKey,
            claimedOwnerKey: reply.ownerKey,
            claimedNullifierPk: reply.nullifierPk,
          }),
        );
      this.wallet._replace({
        ...state,
        utxos: marked([...state.utxos, ...fresh]),
        nullifiers,
      });
      this.#pending._replace({
        ...pendingState,
        utxos: marked([...pendingState.utxos, ...freshPending]),
      });
      this.#claims = [...this.#claims, ...claims];
      this.#history = this.#history._withScanProgress(scan.history);
    });
  }

  /** Moves each pending note whose mint now registers into the spendable notes, the moved ones returned. */
  promotePending(): Promise<readonly WalletUtxo[]> {
    return this.wallet._withSyncLock(async () => {
      const state = this.wallet._state();
      const pendingState = this.#pending._state();
      const registered = (entry: WalletUtxo): boolean =>
        registeredMint(this.wallet.registry, entry.utxo.asset) !== undefined;
      const moved = pendingState.utxos.filter(registered);
      if (moved.length === 0) return moved;
      this.wallet._replace({ ...state, utxos: [...state.utxos, ...moved] });
      this.#pending._replace({
        ...pendingState,
        utxos: pendingState.utxos.filter((entry) => !registered(entry)),
      });
      return moved;
    });
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
    return (
      `{"walletVersion":${ANONYMOUS_WALLET_VERSION},"history":${this.#history.toJson()},` +
      `"wallet":${JSON.stringify(serializeWallet(this.wallet))},` +
      `"pending":${JSON.stringify(serializeWallet(this.#pending))},` +
      `"claims":${JSON.stringify(claims)}}`
    );
  }

  /** A bare version 7 history migrates with no notes and no positions, any other bare history is refused. */
  static fromJson(
    text: string,
    fresh: Readonly<{ identity: ShieldedAddress; registry?: AssetRegistry }>,
  ): AnonymousWallet {
    const stored = document(parseExact(text));
    if (stored["walletVersion"] === undefined) {
      if (stored["version"] !== 7n) throw invalid("a bare history is no wallet document");
      return AnonymousWallet.create(
        new Wallet({
          identity: fresh.identity,
          ...(fresh.registry === undefined ? {} : { registry: fresh.registry }),
        }),
        ViewingHistory._fromValue(stored),
      );
    }
    if (stored["walletVersion"] !== BigInt(ANONYMOUS_WALLET_VERSION))
      throw invalid(`version ${String(stored["walletVersion"])} is unknown`);
    const { history, wallet, pending, claims } = stored;
    const known = ["walletVersion", "history", "wallet", "pending", "claims"];
    if (
      Object.keys(stored).some((key) => !known.includes(key)) ||
      typeof wallet !== "string" ||
      typeof pending !== "string"
    )
      throw invalid("the document names other fields");
    if (!Array.isArray(claims)) throw invalid("claims is not a list");
    return new AnonymousWallet({
      wallet: deserializeWallet(wallet),
      pending: deserializeWallet(pending),
      history: ViewingHistory._fromValue(history),
      claims: claims.map(storedClaim),
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
