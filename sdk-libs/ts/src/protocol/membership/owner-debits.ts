/** The one formula of the proof and the co-signer, Rust `zolana_ring_policy::owner_debits`. */
import { bytesKey, equalBytes } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

export interface DebitInput {
  readonly owner: Bytes32;
  readonly asset: Bytes32;
  readonly amount: bigint;
}

export interface DebitOutput extends DebitInput {
  /** A live output of the ring, an exit to the same owner counts as leaving. */
  readonly ring: boolean;
}

export interface OwnerDebit {
  readonly owner: Bytes32;
  readonly asset: Bytes32;
  readonly debit: bigint;
}

/** Keyed by owner identity, nullifier key versions aggregate. */
export function ownerDebits(
  input: Readonly<{
    senders: readonly Bytes32[];
    assets: readonly Bytes32[];
    inputs: readonly DebitInput[];
    outputs: readonly DebitOutput[];
  }>,
): readonly OwnerDebit[] {
  const seen = new Set<string>();
  const debits: OwnerDebit[] = [];
  for (const owner of input.senders)
    for (const asset of input.assets) {
      const key = `${bytesKey(owner)}:${bytesKey(asset)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const held = (slot: DebitInput): boolean =>
        equalBytes(slot.owner, owner) && equalBytes(slot.asset, asset);
      const sum = (slots: readonly DebitInput[]): bigint =>
        slots.filter(held).reduce((total, slot) => total + slot.amount, 0n);
      const owned = sum(input.inputs);
      const returned = sum(input.outputs.filter((output) => output.ring));
      if (owned > returned) debits.push(Object.freeze({ owner, asset, debit: owned - returned }));
    }
  return Object.freeze(debits);
}
