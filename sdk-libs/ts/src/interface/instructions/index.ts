import type { AccountMeta } from "@solana/kit";
import type { Address } from "@heliuslabs/zolana";
import { meta } from "@heliuslabs/zolana/internal";
import type { SignerAccount } from "@heliuslabs/zolana/instructions";
import { ringSpendWindowAddress } from "../pda/index.js";

/** An unset co-signer repeats the PDA, the message signer flag comes from the address. */
export function ringCoSignerMetas(
  cosignerPda: Address,
  cosigner: SignerAccount | undefined,
): AccountMeta[] {
  return [
    meta(cosignerPda, false, false),
    cosigner === undefined ? meta(cosignerPda, false, false) : meta(cosigner, true, false),
  ];
}

/** One writable spend window slot per public leg, in leg order. */
export async function ringSpendWindowMetas(
  ringProgramId: Address,
  mints: readonly Address[],
): Promise<AccountMeta[]> {
  const windows = await Promise.all(
    mints.map((mint) => ringSpendWindowAddress(ringProgramId, mint)),
  );
  return windows.map((window) => meta(window, false, true));
}
