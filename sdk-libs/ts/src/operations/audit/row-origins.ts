import type { Address } from "@solana/kit";

import type { RequestContext } from "@heliuslabs/zolana/interface";
import { KeypairError } from "@heliuslabs/zolana/keypair";
import type { IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";

import { RingKeyError } from "../../crypto/error.js";
import { RingError, type RingErrorCode } from "../../protocol/error.js";
import type {
  ConfirmedRingTransaction,
  TransactionOrigin,
} from "../../protocol/transaction/origin.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";

/** The failures a retry never changes, any other code stops the scan with its cursor unmoved. */
const ROW_FAILURES: ReadonlySet<RingErrorCode> = new Set<RingErrorCode>([
  "RING_ORIGIN_DECODE",
  "RING_TRANSACT_DATA_INVALID",
  "RING_AUDIT_MESSAGE",
  "RING_AUDIT_KEY_MISMATCH",
  "RING_AUDIT_NONCANONICAL_KEY",
  "RING_AUDIT_UNSEALED",
  "RING_INVALID_LENGTH",
]);

/** Rust `RowOrigins`, a row that fails opens nothing and stays listed for the caller. */
export class RowOrigins {
  readonly skipped: SkippedRingTransaction[] = [];

  constructor(
    private readonly origin: TransactionOrigin,
    private readonly ring: Address,
    private readonly context: RequestContext | undefined,
  ) {}

  /** `undefined` for a row of another event or one now in `skipped`. */
  async read(row: IndexedShieldedTransaction): Promise<ConfirmedRingTransaction | undefined> {
    rowEventIndex(row);
    try {
      return await this.origin.confirmedTransaction(row, this.ring, this.context);
    } catch (error) {
      this.skip(row, error);
      return undefined;
    }
  }

  /** `undefined` once `row` is in `skipped`. */
  attempt<T>(row: IndexedShieldedTransaction, open: () => T): T | undefined {
    try {
      return open();
    } catch (error) {
      this.skip(row, error);
      return undefined;
    }
  }

  private skip(row: IndexedShieldedTransaction, error: unknown): void {
    if (!isRowFailure(error)) throw error;
    this.skipped.push(
      Object.freeze({
        slot: row.slot,
        signature: row.txSignature,
        eventIndex: rowEventIndex(row),
        reason: "invalidAuditData",
      }),
    );
  }
}

export function rowEventIndex(row: IndexedShieldedTransaction): number {
  if (row.eventIndex === undefined)
    throw new RingError("RING_RPC", { details: { reason: "missing event index" } });
  return row.eventIndex;
}

/** The program keeps the auditor message last, its absence names a faulty RPC or another auditor. */
function isRowFailure(error: unknown): boolean {
  if (error instanceof RingKeyError || error instanceof KeypairError) return true;
  return (
    error instanceof RingError &&
    ROW_FAILURES.has(error.code) &&
    !(error.code === "RING_AUDIT_MESSAGE" && error.details?.["reason"] === "missing")
  );
}
