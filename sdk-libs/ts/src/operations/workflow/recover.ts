import type { Address } from "@solana/kit";

import { initializePoseidon } from "@heliuslabs/zolana";
import type { IndexerReader } from "@heliuslabs/zolana/client";
import { PAGE_LIMIT, ZERO_NULLIFIER_PK, bytesKey, equalBytes } from "@heliuslabs/zolana/internal";
import type { Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import { ownerHash } from "@heliuslabs/zolana/keypair";
import type { NullifierKey, ShieldedAddress, X25519Keypair } from "@heliuslabs/zolana/keypair";
import type {
  AssetRegistry,
  IndexedShieldedTransaction,
  OutputContext,
  WalletUtxo,
} from "@heliuslabs/zolana/transaction";
import { Utxo } from "@heliuslabs/zolana/transaction";

import { nextHistoryToken } from "../../rpc/history.js";
import {
  KnownUtxoIndex,
  auditConfirmedRingHistory,
  knownUtxoOwnerHash,
  openedUtxo,
  type KnownUtxo,
  type RingAuditReader,
} from "../audit/audit.js";
import { createdDepositUtxo, openConfirmedDeposit } from "./created-utxos.js";
import { ringDepositOutput } from "../../proof/deposit-audit.js";
import { RingError } from "../../protocol/error.js";
import { rowDisposition, RowOrigins } from "../audit/row-origins.js";
import { readRingHistory, scanLimits, type ScanLimits } from "../../rpc/history.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";
import {
  RpcTransactionOrigin,
  type ConfirmedDeposit,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../../protocol/transaction/origin.js";
import { outputTreeId } from "../../protocol/membership/trees.js";
import { zeroKeyNullifier } from "../../state/exposed-notes.js";

export type RingRecoveryClient = RingAuditReader;

/** Mirrors Rust `MemberRecovery`, a source member's notes from the auditor's view and its nullifier key. */
export interface RingRecoveryParams {
  readonly client: RingRecoveryClient;
  readonly ringProgramId: Address;
  readonly auditor: X25519Keypair;
  readonly source: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
  readonly assets: AssetRegistry;
  readonly origin?: TransactionOrigin;
  readonly pageSize?: number;
  readonly maxPages?: number;
}

/** Mirrors Rust `RecoveredNotes`, verified unspent notes with the coverage left unresolved. */
export interface RecoveredRingNotes {
  readonly notes: readonly WalletUtxo[];
  /** Commitments that cannot yet become spendable notes, unknown mints among them. */
  readonly unopened: readonly Bytes32[];
  /** Tagged deposits whose ownership and spentness are unknown. */
  readonly unsupportedDeposits: readonly Bytes32[];
  /** Verified mints missing from the asset registry, their notes stay in `unopened`. */
  readonly unknownMints: readonly Address[];
  /** Nullifiers of inputs no note matches, a complete anonymous history leaves none. */
  readonly unseenInputs: readonly Bytes32[];
}

export async function recoverRingMemberNotes(
  input: RingRecoveryParams,
  context?: RequestContext,
): Promise<RecoveredRingNotes> {
  await initializePoseidon();
  if (!equalBytes(input.nullifierKey.publicKey(), input.source.nullifierPublicKey))
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  const origin = input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc);
  const history: RecoveryHistory = {
    rows: new RowOrigins(origin, input.ringProgramId, context),
    transactions: [],
    limits: scanLimits({
      pageSize: input.pageSize ?? Number(PAGE_LIMIT),
      maxPages: input.maxPages,
    }),
  };
  const found = new Found();
  // Deposits are found by ring, never by their recipient view tags.
  const unsupportedDeposits = await recoverDeposits(input, history, found, context);
  const audited = auditConfirmedRingHistory({
    auditor: input.auditor,
    ringProgramId: input.ringProgramId,
    history: history.transactions,
    rows: history.rows,
    known: found.created,
  });
  refuseSkipped(history.rows.skipped);
  const unresolvedReal: Bytes32[] = [];
  for (const transaction of audited) {
    for (const { nullifier, opening } of transaction.inputs)
      if (opening.kind === "unresolvedReal") unresolvedReal.push(nullifier);
    // An unopened slot could hide a source UTXO.
    const [unopened] = transaction.payloadErrors;
    if (unopened !== undefined)
      throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
        details: { reason: "unopened", slotIndex: unopened.slotIndex },
      });
    for (const { opening, outputContext } of transaction.outputs)
      if (opening.kind === "ring")
        keepSourceNote(
          input,
          found,
          openedUtxo(opening.utxo, outputTreeId(outputContext)),
          outputContext,
        );
  }
  // The audit opened every merge from its sealed record, a skipped one refused above.
  for (const confirmed of history.transactions) {
    const slot = confirmed.kind === "merge" ? confirmed.transaction.outputSlots[0] : undefined;
    const opening = slot === undefined ? undefined : found.created.utxo(slot.outputContext.hash);
    if (slot !== undefined && opening !== undefined)
      keepSourceNote(input, found, opening, slot.outputContext);
  }
  const spent = new Set(
    history.transactions.flatMap(({ transaction }) => transaction.nullifiers.map(bytesKey)),
  );
  return Object.freeze({
    notes: Object.freeze(found.candidates.filter((note) => !spent.has(bytesKey(note.nullifier)))),
    unopened: Object.freeze(
      found.unresolved
        .filter(({ nullifier }) => !spent.has(bytesKey(nullifier)))
        .map(({ commitment }) => commitment),
    ),
    unsupportedDeposits: Object.freeze(unsupportedDeposits),
    unknownMints: Object.freeze([...found.unknownMints]),
    unseenInputs: Object.freeze(
      unresolvedReal.filter(
        (nullifier) =>
          !found.candidates.some((candidate) => equalBytes(candidate.nullifier, nullifier)),
      ),
    ),
  });
}

interface RecoveryHistory {
  readonly rows: RowOrigins;
  readonly limits: ScanLimits;
  readonly transactions: ConfirmedRingTransaction[];
}

/** A row left unread can hold a source note or its spend, Rust `complete`. */
function refuseSkipped(skipped: readonly SkippedRingTransaction[]): void {
  const row = skipped[0];
  if (row !== undefined)
    throw new RingError("RING_RECOVERY_INCOMPLETE", {
      details: {
        reason: "skipped row",
        transactionId: row.signature,
        eventIndex: row.eventIndex,
      },
    });
}

/** Notes found so far, by the commitments already claimed. */
class Found {
  readonly candidates: WalletUtxo[] = [];
  /** Source commitments without a spendable opening, with their nullifiers. */
  readonly unresolved: {
    readonly commitment: Bytes32;
    readonly nullifier: Bytes32;
  }[] = [];
  readonly unknownMints = new Set<Address>();
  /** Every deposit and merge UTXO the auditor opened, a transfer disclosure names them by hash. */
  readonly created = new KnownUtxoIndex();
  readonly #seen = new Set<string>();

  /** `false` when the commitment was already claimed. */
  claim(commitment: Bytes32): boolean {
    const key = bytesKey(commitment);
    if (this.#seen.has(key)) return false;
    this.#seen.add(key);
    return true;
  }

  seen(commitment: Bytes32): boolean {
    return this.#seen.has(bytesKey(commitment));
  }

  unresolve(commitment: Bytes32, nullifier: Bytes32): void {
    this.unresolved.push(Object.freeze({ commitment, nullifier }));
  }
}

/** A ring note the audit opened, kept when the source's signing key owns it under its nullifier key or the zero key. */
function keepSourceNote(
  input: Pick<RingRecoveryParams, "source" | "nullifierKey" | "assets" | "ringProgramId">,
  found: Found,
  opening: KnownUtxo,
  outputContext: OutputContext,
): void {
  const nullifierPk = sourceNullifierPk(input.source, knownUtxoOwnerHash(opening));
  if (nullifierPk === undefined || !found.claim(outputContext.hash)) return;
  const nullifier = sourceNullifier(input, nullifierPk, outputContext.hash, opening.blinding);
  const mint = registeredMint(input.assets, opening.mint);
  if (mint === undefined) {
    // Ownership and spentness stay known, without a registered mint the note stays unspendable.
    if (opening.mint !== undefined) found.unknownMints.add(opening.mint);
    found.unresolve(outputContext.hash, nullifier);
    return;
  }
  const opened = sourceWalletUtxo(input, {
    utxo: new Utxo({
      owner: input.source.signingPublicKey,
      asset: mint,
      amount: opening.amount,
      blinding: opening.blinding,
      ringProgramId: input.ringProgramId,
    }),
    nullifierPk,
    outputContext,
    hashes: { dataHash: opening.dataHash, ringDataHash: opening.ringDataHash },
  });
  if (opened.opens) found.candidates.push(opened.utxo);
  else found.unresolve(outputContext.hash, opened.utxo.nullifier);
}

/** The key a source note sits under, `undefined` for another owner. */
function sourceNullifierPk(source: ShieldedAddress, owner: Bytes32): Bytes32 | undefined {
  if (equalBytes(owner, source.ownerHash())) return source.nullifierPublicKey;
  const zeroKeyOwner = ownerHash(source.signingPublicKey.ownerProofInputHash(), ZERO_NULLIFIER_PK);
  return equalBytes(owner, zeroKeyOwner) ? (ZERO_NULLIFIER_PK as Bytes32) : undefined;
}

/** A zero-key note's nullifier needs no secret, anyone with the opening derives it. */
function sourceNullifier(
  input: Pick<RingRecoveryParams, "nullifierKey">,
  nullifierPk: Bytes32,
  commitment: Bytes32,
  blinding: Bytes32,
): Bytes32 {
  return equalBytes(nullifierPk, ZERO_NULLIFIER_PK)
    ? zeroKeyNullifier(commitment, blinding)
    : input.nullifierKey.nullifier(commitment, blinding);
}

/** Rust `SourceMember::wallet_utxo`, the UTXO at `outputContext` and whether it reproduces the leaf. */
function sourceWalletUtxo(
  input: Pick<RingRecoveryParams, "nullifierKey">,
  candidate: Readonly<{
    utxo: Utxo;
    nullifierPk: Bytes32;
    outputContext: OutputContext;
    hashes: Readonly<{ dataHash?: Bytes32; ringDataHash?: Bytes32 }>;
  }>,
): Readonly<{ utxo: WalletUtxo; opens: boolean }> {
  const { utxo, nullifierPk, outputContext } = candidate;
  const dataHash = nonZero(candidate.hashes.dataHash);
  const ringDataHash = nonZero(candidate.hashes.ringDataHash);
  const walletUtxo: WalletUtxo = Object.freeze({
    utxo,
    outputContext,
    nullifier: sourceNullifier(input, nullifierPk, outputContext.hash, utxo.blinding),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(ringDataHash === undefined ? {} : { ringDataHash }),
    spent: false,
  });
  const commitment = utxo.hash(nullifierPk, outputTreeId(outputContext), dataHash, ringDataHash);
  return Object.freeze({
    utxo: walletUtxo,
    opens: equalBytes(commitment, outputContext.hash),
  });
}

/** Mirrors Rust `ring_history`, `deposited_utxos` and `CreatedUtxos::open` in one read. */
async function recoverDeposits(
  input: RingRecoveryParams,
  history: RecoveryHistory,
  found: Found,
  context: RequestContext | undefined,
): Promise<Bytes32[]> {
  const processed = new Set<string>();
  const unsupported: Bytes32[] = [];
  const stopped = await readRingHistory(
    { client: input.client, ringProgramId: input.ringProgramId, ...history },
    (confirmed) => {
      if (confirmed.kind !== "deposit") {
        history.transactions.push(confirmed);
        return;
      }
      for (const [slotIndex, slot] of confirmed.transaction.outputSlots.entries()) {
        const deposit = ringDepositOutput(slot.payload, input.ringProgramId);
        const commitment = slot.outputContext.hash;
        const key = bytesKey(commitment);
        if (deposit === undefined || processed.has(key) || found.seen(commitment)) continue;
        processed.add(key);
        const binding = confirmed.deposits.find(
          (candidate: ConfirmedDeposit) => candidate.slotIndex === slotIndex,
        );
        if (binding === undefined) {
          unsupported.push(commitment);
          continue;
        }
        let opening;
        try {
          opening = openConfirmedDeposit({ output: deposit, auditor: input.auditor, binding });
        } catch (error) {
          if (rowDisposition(error) === "retry") throw error;
          unsupported.push(commitment);
          continue;
        }
        try {
          const created = createdDepositUtxo({
            ringProgramId: input.ringProgramId,
            slotIndex,
            slot,
            output: deposit,
            opening,
          });
          found.created.insert(commitment, created.utxo);
          const nullifierPk = sourceNullifierPk(input.source, opening.ownerHash);
          if (nullifierPk === undefined) continue;
          // The deposit proof binds the raw mint, its commitment opens without the registry.
          const opened = sourceWalletUtxo(input, {
            utxo: new Utxo({
              owner: input.source.signingPublicKey,
              asset: deposit.asset,
              amount: deposit.amount,
              blinding: opening.blinding,
              ringProgramId: input.ringProgramId,
            }),
            nullifierPk,
            outputContext: slot.outputContext,
            hashes: {
              ...(deposit.dataHash === undefined ? {} : { dataHash: deposit.dataHash }),
              ringDataHash: deposit.ringDataHash,
            },
          });
          if (!opened.opens)
            throw new RingError("RING_AUDIT_MESSAGE", {
              details: { reason: "deposit opening" },
            });
          found.claim(commitment);
          if (registeredMint(input.assets, deposit.asset) !== undefined)
            found.candidates.push(opened.utxo);
          else {
            found.unknownMints.add(deposit.asset);
            found.unresolve(commitment, opened.utxo.nullifier);
          }
        } finally {
          opening.ownerHash.fill(0);
          opening.blinding.fill(0);
        }
      }
    },
    context,
  );
  if (stopped.nextCursor !== undefined) throw new RingError("RING_RECOVERY_INCOMPLETE");
  return unsupported;
}

/** Every transaction spending one of `nullifiers`, `budget` bounds the queries. */
export async function spendingTransactions(
  client: Pick<IndexerReader, "getShieldedTransactionsByNullifiers">,
  nullifiers: readonly Bytes32[],
  budget: { remaining: number },
  context: RequestContext | undefined,
): Promise<readonly IndexedShieldedTransaction[]> {
  const transactions: IndexedShieldedTransaction[] = [];
  for (let start = 0; start < nullifiers.length; start += Number(PAGE_LIMIT)) {
    const batch = nullifiers.slice(start, start + Number(PAGE_LIMIT));
    let token: string | undefined;
    for (;;) {
      if (budget.remaining <= 0) throw new RingError("RING_RECOVERY_INCOMPLETE");
      budget.remaining--;
      const page = await client.getShieldedTransactionsByNullifiers(
        {
          nullifiers: batch,
          ...(token === undefined ? {} : { paginationToken: token }),
        },
        undefined,
        context,
      );
      transactions.push(...page.data.flatMap((item) => item.events));
      const next = nextHistoryToken(token, page);
      if (next === undefined) break;
      token = next;
    }
  }
  return transactions;
}

/** The mint the registry knows, `undefined` for an absent or unregistered one. */
export function registeredMint(
  assets: AssetRegistry,
  mint: Address | undefined,
): Address | undefined {
  if (mint === undefined) return undefined;
  try {
    assets.assetId(mint);
    return mint;
  } catch {
    return undefined;
  }
}

function nonZero(hash: Bytes32 | undefined): Bytes32 | undefined {
  return hash === undefined || hash.every((byte) => byte === 0) ? undefined : hash;
}
