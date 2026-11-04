import type { Address } from "@solana/kit";

import { initializePoseidon } from "@heliuslabs/zolana";
import type { IndexerReader } from "@heliuslabs/zolana/client";
import {
  solanaOwnerIdentity,
  mergePaddedInputCount,
  PAGE_LIMIT,
  equalBytes,
  bytesKey,
  hashBytes,
  addressBytes,
  ZERO_32,
} from "@heliuslabs/zolana/internal";
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
  type RingAuditReader,
} from "../audit/audit.js";
import { recoverMergeOpening } from "../audit/audit-merge.js";
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
import { reconstructMergeOutput } from "../../state/merge-ledger.js";

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
  const sourceOwner = input.source.ownerHash();
  const unseenInputs: { hash: Bytes32; nullifier: Bytes32 }[] = [];
  for (const transaction of audited) {
    for (const { nullifier, opening } of transaction.inputs)
      if (opening.kind === "unseenHash") unseenInputs.push({ hash: opening.hash, nullifier });
    for (const error of transaction.payloadErrors) {
      // Any other unopened slot could hide a source UTXO.
      if (error.kind !== "unknownAsset")
        throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
          details: { reason: "unopened", slotIndex: error.slotIndex },
        });
      const commitment = transaction.outputCommitments[error.slotIndex];
      if (commitment !== undefined) found.unknownAssets.push(commitment);
    }
    for (const output of transaction.outputs) {
      if (output.opening.kind !== "ring") continue;
      const { utxo } = output.opening;
      const context = output.outputContext;
      if (
        !equalBytes(ownerHash(solanaOwnerIdentity(utxo.ownerKey), utxo.nullifierPk), sourceOwner) ||
        !found.claim(context.hash)
      )
        continue;
      const mint = registeredMint(input.assets, utxo.mint);
      if (mint === undefined) {
        // The opening derives its nullifier, without a registered mint the note stays unspendable.
        if (utxo.mint !== undefined) found.unknownMints.add(utxo.mint);
        found.unresolve(context.hash, input.nullifierKey.nullifier(context.hash, utxo.blinding));
        continue;
      }
      const opened = sourceWalletUtxo(input, {
        utxo: new Utxo({
          owner: input.source.signingPublicKey,
          asset: mint,
          amount: utxo.amount,
          blinding: utxo.blinding,
          ringProgramId: input.ringProgramId,
        }),
        outputContext: context,
        hashes: { dataHash: utxo.dataHash, ringDataHash: utxo.ringDataHash },
      });
      if (opened.opens) found.candidates.push(opened.utxo);
      else found.unresolve(context.hash, opened.utxo.nullifier);
    }
  }
  const spent = followSpends(input, history, found);
  refuseSkipped(history.rows.skipped);
  return Object.freeze({
    notes: Object.freeze(found.candidates.filter((note) => !spent.has(bytesKey(note.nullifier)))),
    unopened: Object.freeze(
      found.unresolved
        .filter(({ nullifier }) => nullifier === undefined || !spent.has(bytesKey(nullifier)))
        .map(({ commitment }) => commitment)
        .concat(found.unknownAssets),
    ),
    unsupportedDeposits: Object.freeze(unsupportedDeposits),
    unknownMints: Object.freeze([...found.unknownMints]),
    unseenInputs: Object.freeze(
      unseenInputs
        .filter(
          ({ hash }) =>
            found.created.utxo(hash) === undefined && found.created.merged(hash) === undefined,
        )
        .map(({ nullifier }) => nullifier),
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
  /** Commitments without a verified opening, with their nullifier when the key derives one. */
  readonly unresolved: {
    readonly commitment: Bytes32;
    readonly nullifier?: Bytes32;
  }[] = [];
  readonly unknownMints = new Set<Address>();
  /** Commitments of delivered slots no registered asset rebuilds. */
  readonly unknownAssets: Bytes32[] = [];
  /** Every deposit and merge UTXO of an anonymous ring, its transfer disclosures name them by hash or prefix. */
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

  unresolve(commitment: Bytes32, nullifier?: Bytes32): void {
    this.unresolved.push(
      Object.freeze({
        commitment,
        ...(nullifier === undefined ? {} : { nullifier }),
      }),
    );
  }
}

/** Rust `SourceMember::wallet_utxo`, the UTXO at `outputContext` and whether it reproduces the leaf. */
function sourceWalletUtxo(
  input: Pick<RingRecoveryParams, "source" | "nullifierKey">,
  candidate: Readonly<{
    utxo: Utxo;
    outputContext: OutputContext;
    hashes: Readonly<{ dataHash?: Bytes32; ringDataHash?: Bytes32 }>;
  }>,
): Readonly<{ utxo: WalletUtxo; opens: boolean }> {
  const { utxo, outputContext } = candidate;
  const dataHash = nonZero(candidate.hashes.dataHash);
  const ringDataHash = nonZero(candidate.hashes.ringDataHash);
  const walletUtxo: WalletUtxo = Object.freeze({
    utxo,
    outputContext,
    nullifier: utxo.nullifier(outputContext.hash, input.nullifierKey),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(ringDataHash === undefined ? {} : { ringDataHash }),
    spent: false,
  });
  const commitment = utxo.hash(
    input.source.nullifierPublicKey,
    outputTreeId(outputContext),
    dataHash,
    ringDataHash,
  );
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
  const sourceOwner = input.source.ownerHash();
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
          if (!equalBytes(opening.ownerHash, sourceOwner)) continue;
          // The deposit proof binds the raw mint, its commitment opens without the registry.
          const opened = sourceWalletUtxo(input, {
            utxo: new Utxo({
              owner: input.source.signingPublicKey,
              asset: deposit.asset,
              amount: deposit.amount,
              blinding: opening.blinding,
              ringProgramId: input.ringProgramId,
            }),
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

function followSpends(
  input: RingRecoveryParams,
  { transactions }: RecoveryHistory,
  found: Found,
): Set<string> {
  const spent = new Set(
    transactions.flatMap(({ transaction }) => transaction.nullifiers.map(bytesKey)),
  );
  const merges = transactions.flatMap((confirmed) =>
    confirmed.kind !== "merge" ||
    confirmed.transaction.outputSlots.length !== 1 ||
    mergePaddedInputCount(confirmed.transaction.nullifiers.length) === undefined
      ? []
      : [confirmed.transaction],
  );
  const relevant = new Map<string, IndexedShieldedTransaction>();
  for (;;) {
    const sourceNullifiers = new Set([
      ...found.candidates.map((candidate) => bytesKey(candidate.nullifier)),
      ...found.unresolved.flatMap(({ nullifier }) =>
        nullifier === undefined ? [] : [bytesKey(nullifier)],
      ),
    ]);
    const before = found.candidates.length;
    const unresolvedBefore = found.unresolved.length;
    for (const transaction of merges) {
      const commitment = transaction.outputSlots[0]!.outputContext.hash;
      if (found.seen(commitment)) continue;
      const resolved = found.created.mergeOutput(commitment);
      if (
        !transaction.nullifiers.some((nullifier) => sourceNullifiers.has(bytesKey(nullifier))) &&
        (resolved === undefined ||
          !equalBytes(knownUtxoOwnerHash(resolved), input.source.ownerHash()))
      )
        continue;
      relevant.set(bytesKey(commitment), transaction);
      const utxo =
        resolved === undefined
          ? undefined
          : reconstructMergeOutput({
              output: resolved,
              nullifierKey: input.nullifierKey,
              ringProgramId: input.ringProgramId,
            });
      const owned =
        utxo !== undefined && equalBytes(knownUtxoOwnerHash(utxo), input.source.ownerHash())
          ? utxo
          : undefined;
      const inherited =
        owned?.mint === undefined
          ? undefined
          : {
              member: input.source.signingPublicKey.ownerProofInputHash(),
              asset: owned.mint,
              amount: owned.amount,
              blinding: owned.blinding,
              outputContext: transaction.outputSlots[0]!.outputContext,
              nullifier: input.nullifierKey.nullifier(commitment, owned.blinding),
              ringDataHash: owned.ringDataHash,
            };
      const opening =
        inherited ??
        recoverMergeOpening(
          {
            member: input.source.signingPublicKey.ownerProofInputHash(),
            nullifierKey: input.nullifierKey,
            ringProgramId: input.ringProgramId,
          },
          transaction,
        );
      if (opening === undefined) {
        if (owned !== undefined) {
          found.claim(commitment);
          found.unresolve(commitment, input.nullifierKey.nullifier(commitment, owned.blinding));
        }
        continue;
      }
      found.created.insert(
        commitment,
        openedUtxo(
          {
            ownerKey: input.source.confidentialViewTag(),
            nullifierPk: input.nullifierKey.publicKey(),
            asset: hashBytes(addressBytes(opening.asset)) as Bytes32,
            mint: opening.asset,
            amount: opening.amount,
            blinding: opening.blinding,
            dataHash: ZERO_32,
            ringDataHash: opening.ringDataHash ?? ZERO_32,
          },
          outputTreeId(opening.outputContext),
        ),
      );
      found.claim(commitment);
      if (registeredMint(input.assets, opening.asset) === undefined) {
        found.unknownMints.add(opening.asset);
        found.unresolve(commitment, opening.nullifier);
        continue;
      }
      found.candidates.push(
        Object.freeze({
          utxo: new Utxo({
            owner: input.source.signingPublicKey,
            asset: opening.asset,
            amount: opening.amount,
            blinding: opening.blinding,
            ringProgramId: input.ringProgramId,
          }),
          outputContext: opening.outputContext,
          nullifier: opening.nullifier,
          ...(opening.ringDataHash === undefined ? {} : { ringDataHash: opening.ringDataHash }),
          spent: false,
        }),
      );
    }
    if (found.candidates.length === before && found.unresolved.length === unresolvedBefore) {
      for (const transaction of relevant.values()) {
        const commitment = transaction.outputSlots[0]!.outputContext.hash;
        if (!found.seen(commitment)) found.unresolve(commitment);
      }
      return spent;
    }
  }
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
