import type { IndexerReader, KitRpcAccess } from "@heliuslabs/zolana/client";
import { initializePoseidon } from "@heliuslabs/zolana";
import {
  isCanonicalField,
  mergePaddedInputCount,
  mergeOutputBlinding,
  mergeOutputKey,
  equalBytes,
  poseidon,
  MERGE_OUTPUT_BODY_LENGTH,
  decryptMergeOutput,
  readMergeOutputBody,
} from "@heliuslabs/zolana/internal";
import type {
  Address,
  Bytes16,
  Bytes32,
  RequestContext,
  Signature,
} from "@heliuslabs/zolana/interface";
import type { NullifierKey, X25519Keypair } from "@heliuslabs/zolana/keypair";
import type { IndexedShieldedTransaction, OutputContext } from "@heliuslabs/zolana/transaction";
import { ownerUtxoHash } from "@heliuslabs/zolana/transaction";

import { RingError } from "../../protocol/error.js";
import { RowOrigins } from "./row-origins.js";
import { readRingHistory, scanLimits } from "../../rpc/history.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";
import {
  openRingMergeDisclosure,
  type RingMergeDisclosure,
} from "../../crypto/audit/merge-disclosure.js";
import { RpcTransactionOrigin, type TransactionOrigin } from "../../protocol/transaction/origin.js";
import { outputTreeId } from "../../protocol/membership/trees.js";
import {
  MergeLedger,
  mergeInputOf,
  realMergeInputs,
  type AuditedMergeOutput,
  type ConfirmedMerge,
  type KnownMergeInput,
} from "../../state/merge-ledger.js";
import type { KnownUtxos } from "./audit.js";

export type RingMergeAuditReader = KitRpcAccess &
  Pick<IndexerReader, "getShieldedTransactionsByTags">;

/** A merge row whose frame carries no v3 disclosure, the historical reader owns it. */
export interface HistoricalMergeRow {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
}

export interface RingMergeAuditPage {
  /** Every nonzero list entry the page applied, known to the auditor or not. */
  readonly spent: readonly Bytes32[];
  /** Audit records the page resolved, descendants included. */
  readonly outputs: readonly AuditedMergeOutput[];
  /** Every merge the ledger holds on an unknown input. */
  readonly unresolved: readonly ConfirmedMerge[];
  readonly historical: readonly HistoricalMergeRow[];
  /** Rows that do not decode or fail their disclosure, each opens nothing. */
  readonly skipped: readonly SkippedRingTransaction[];
  /** Set only when the page cap stopped the history scan. */
  readonly nextCursor?: string;
}

/** Rust `MergeAudit`. */
export async function auditRingMerges(
  input: Readonly<{
    client: RingMergeAuditReader;
    ringProgramId: Address;
    auditor: X25519Keypair;
    origin?: TransactionOrigin;
    cursor?: string;
    pageSize?: number;
    maxPages?: number;
    /** The auditor's openings, a merge of an unknown input stays unresolved. */
    knownUtxos?: Pick<KnownUtxos, "utxo">;
    /** One per ring across pages, a later opening resolves what an earlier page held. */
    ledger?: MergeLedger;
  }>,
  context?: RequestContext,
): Promise<RingMergeAuditPage> {
  await initializePoseidon();
  const rows = new RowOrigins(
    input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
    input.ringProgramId,
    context,
  );
  const merges: ConfirmedMerge[] = [];
  const historical: HistoricalMergeRow[] = [];
  const seen = new Set<string>();
  const { nextCursor } = await readRingHistory(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      rows,
      ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
      limits: scanLimits(input),
    },
    (confirmed, eventIndex) => {
      if (confirmed.kind !== "merge") return;
      const { transaction, disclosure } = confirmed;
      const event = `${transaction.txSignature}:${String(eventIndex)}`;
      if (seen.has(event))
        throw new RingError("RING_RPC", {
          details: { reason: "duplicate merge" },
        });
      seen.add(event);
      const merge = confirmedMerge({
        transaction,
        eventIndex,
        disclosure,
        auditor: input.auditor,
      });
      if (merge === undefined)
        historical.push(
          Object.freeze({
            slot: transaction.slot,
            signature: transaction.txSignature,
            eventIndex,
          }),
        );
      else merges.push(merge);
    },
    context,
  );
  const ledger = input.ledger ?? new MergeLedger();
  const known: KnownMergeInput = (commitment) => {
    const utxo = input.knownUtxos?.utxo(commitment);
    return utxo === undefined ? undefined : mergeInputOf(utxo);
  };
  const spent: Bytes32[] = [];
  const outputs: AuditedMergeOutput[] = [];
  for (const merge of merges) {
    // Listed ahead of the ledger, a retried page over a carried ledger still names its inputs.
    spent.push(...merge.inputs);
    outputs.push(...ledger.apply(merge, known).resolved);
  }
  outputs.push(...ledger.resolve(known));
  return Object.freeze({
    spent: Object.freeze(spent),
    outputs: Object.freeze(outputs),
    unresolved: ledger.unresolved(),
    historical: Object.freeze(historical),
    skipped: Object.freeze(rows.skipped),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  });
}

/** `undefined` on a frame with no v3 disclosure. */
export function confirmedMerge(
  input: Readonly<{
    transaction: IndexedShieldedTransaction;
    eventIndex: number;
    disclosure: RingMergeDisclosure | undefined;
    auditor: X25519Keypair;
  }>,
): ConfirmedMerge | undefined {
  if (input.disclosure === undefined) return undefined;
  const { transaction, eventIndex } = input;
  const slot = transaction.outputSlots[0];
  const firstNullifier = transaction.nullifiers[0];
  const width = mergePaddedInputCount(transaction.nullifiers.length);
  const body = slot === undefined ? undefined : readMergeOutputBody(slot.payload);
  const ringDataHash = body?.ringDataHash;
  if (
    slot === undefined ||
    firstNullifier === undefined ||
    transaction.outputSlots.length !== 1 ||
    width === undefined ||
    body === undefined ||
    ringDataHash === undefined ||
    body.encrypted.length !== MERGE_OUTPUT_BODY_LENGTH ||
    !isCanonicalField(firstNullifier) ||
    !isCanonicalField(slot.outputContext.hash) ||
    !isCanonicalField(ringDataHash)
  )
    throw new RingError("RING_ORIGIN_DECODE", {
      details: { reason: "ring merge output" },
    });
  const salt = body.encrypted.slice(0, 16) as Bytes16;
  const list = openRingMergeDisclosure(input.auditor, input.disclosure, salt);
  if (list.length !== width)
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "merge disclosure width" },
    });
  return Object.freeze({
    slot: transaction.slot,
    signature: transaction.txSignature,
    eventIndex,
    outputCommitment: slot.outputContext.hash,
    treeId: outputTreeId(slot.outputContext),
    leafIndex: slot.outputContext.leafIndex,
    firstNullifier,
    ringDataHash,
    inputs: realMergeInputs(list, transaction.nullifiers.length),
  });
}

/** A verified merge opening when only the registered member hash is known. */
export interface MergeAuditorOpening {
  readonly member: Bytes32;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly outputContext: OutputContext;
  readonly nullifier: Bytes32;
  readonly ringDataHash?: Bytes32;
}

/** The merge output the member's key decrypts, `undefined` unless it reproduces the settled commitment. */
export function recoverMergeOpening(
  input: Readonly<{
    member: Bytes32;
    nullifierKey: NullifierKey;
    ringProgramId: Address;
  }>,
  transaction: IndexedShieldedTransaction,
): MergeAuditorOpening | undefined {
  const firstNullifier = transaction.nullifiers[0];
  const slot = transaction.outputSlots[0];
  if (
    firstNullifier === undefined ||
    slot === undefined ||
    mergePaddedInputCount(transaction.nullifiers.length) === undefined
  )
    return undefined;
  const body = readMergeOutputBody(slot.payload);
  const ringDataHash = body?.ringDataHash;
  if (body === undefined || ringDataHash === undefined) return undefined;
  const outputKey = mergeOutputKey(input.nullifierKey, firstNullifier);
  let plaintext;
  try {
    plaintext = decryptMergeOutput(body.encrypted, outputKey);
  } catch {
    return undefined;
  } finally {
    outputKey.fill(0);
  }
  const blinding = mergeOutputBlinding(input.nullifierKey, firstNullifier);
  const commitment = ownerUtxoHash({
    owner: poseidon([input.member, input.nullifierKey.publicKey()]),
    asset: plaintext.mint,
    amount: plaintext.amount,
    blinding,
    treeId: outputTreeId(slot.outputContext),
    ringDataHash,
    ringProgramId: input.ringProgramId,
  });
  if (!equalBytes(commitment, slot.outputContext.hash)) return undefined;
  return Object.freeze({
    member: input.member,
    asset: plaintext.mint,
    amount: plaintext.amount,
    blinding,
    outputContext: slot.outputContext,
    nullifier: input.nullifierKey.nullifier(slot.outputContext.hash, blinding),
    ...(ringDataHash.some((byte) => byte !== 0) ? { ringDataHash } : {}),
  });
}
