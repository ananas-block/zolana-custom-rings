import { blockhash } from "@solana/kit";
import {
  compileUnsignedTransaction,
  type TransactionCompilerOptions,
} from "@heliuslabs/zolana/internal";

type LatestBlockhash = TransactionCompilerOptions["lifetime"];

/** Any well-formed blockhash sizes a message the same. */
export const SIZE_PROBE_LIFETIME: LatestBlockhash = Object.freeze({
  blockhash: blockhash("11111111111111111111111111111111"),
  lastValidBlockHeight: 0n,
});

/** The transaction fits version 1, checked before any proof or signature exists. */
export function checkTransactionFits(options: Omit<TransactionCompilerOptions, "lifetime">): void {
  compileUnsignedTransaction({ ...options, lifetime: SIZE_PROBE_LIFETIME });
}
