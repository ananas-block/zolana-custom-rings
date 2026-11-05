import type { ChainReader, TreeContext } from "@heliuslabs/zolana/client";
import {
  equalBytes,
  selectUtxos,
  ZERO_NULLIFIER_PK,
  type SpendPolicy,
  type SpendSelectionErrors,
} from "@heliuslabs/zolana/internal";
import {
  MAX_INPUT_TREES,
  type Address,
  type Bytes32,
  type RequestContext,
} from "@heliuslabs/zolana/interface";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";
import { ProofInputUtxo } from "@heliuslabs/zolana/transaction";
import type { Wallet, WalletUtxo } from "@heliuslabs/zolana/transaction";

import { RingError } from "../../protocol/error.js";
import { ringTreeIdResolver } from "../../protocol/membership/trees.js";

export interface Cover {
  readonly asset: Address;
  readonly amount: bigint;
}

/** Every mint from one shared tree set, the fewest trees, then UTXOs, then change. */
export function selectAcrossTrees(
  input: Readonly<{
    wallet: Wallet;
    covers: readonly Cover[];
    policy: Omit<SpendPolicy, "tree">;
    /** At most `MAX_INPUT_TREES`, below it where the rail's builder takes fewer. */
    maxTrees?: number;
  }>,
): readonly WalletUtxo[] {
  const { wallet, covers, policy, maxTrees = MAX_INPUT_TREES } = input;
  const eligible = wallet
    .utxos()
    .filter(
      (entry) =>
        !entry.spent &&
        entry.utxo.amount > 0n &&
        covers.some((cover) => cover.asset === entry.utxo.asset) &&
        policy.eligible(entry),
    );
  const held = (trees: readonly Address[], asset: Address) =>
    covered(
      eligible.filter(
        (entry) => entry.utxo.asset === asset && trees.includes(entry.outputContext.tree),
      ),
    );
  // Each mint in turn takes what the earlier mints leave of the input budget.
  const attempt = (trees: readonly Address[]) => {
    const entries: WalletUtxo[] = [];
    for (const [funded, cover] of covers.entries()) {
      try {
        entries.push(
          ...selectUtxos({
            wallet,
            asset: cover.asset,
            target: { kind: "cover", amount: cover.amount },
            policy: {
              ...policy,
              eligible: (entry) =>
                trees.includes(entry.outputContext.tree) && policy.eligible(entry),
              maxInputs: policy.maxInputs - entries.length,
              tree: { kind: "infer", maxTrees: trees.length },
            },
          }).entries,
        );
      } catch (error) {
        return { kind: "short" as const, rank: [BigInt(funded), held(trees, cover.asset)], error };
      }
    }
    return { kind: "funded" as const, entries };
  };
  const sets = treeSets(
    [...new Set(eligible.map((entry) => entry.outputContext.tree))],
    Math.min(maxTrees, MAX_INPUT_TREES),
  );
  let best: { rank: readonly bigint[]; entries: readonly WalletUtxo[] } | undefined;
  let furthest: { rank: readonly bigint[]; error: unknown } | undefined;
  // With no eligible note the empty set still runs, its selection names the refusal.
  for (const trees of sets.length === 0 ? [[]] : sets) {
    const outcome = attempt(trees);
    if (outcome.kind === "short") {
      if (furthest === undefined || precedes(furthest.rank, outcome.rank)) furthest = outcome;
      continue;
    }
    // A pair whose picks sit on one tree repeats that tree's own selection.
    if (spannedTrees(outcome.entries) !== trees.length) continue;
    const rank = [BigInt(trees.length), BigInt(outcome.entries.length), covered(outcome.entries)];
    if (best === undefined || precedes(rank, best.rank)) best = { rank, entries: outcome.entries };
  }
  if (best !== undefined) return best.entries;
  // The set funding the most mints, then holding the most of the short one, names the refusal.
  throw furthest?.error;
}

/** Proof inputs at each note's own tree, a second tree's id read once from its account. */
export async function ringProofInputs(
  entries: readonly WalletUtxo[],
  ownerOf: (entry: WalletUtxo) => ShieldedAddress,
  client: TreeContext & Pick<ChainReader, "getAccount">,
  context?: RequestContext,
): Promise<readonly ProofInputUtxo[]> {
  const treeId = ringTreeIdResolver(client, [client], context);
  return Promise.all(
    entries.map(async (entry) => {
      const tree = entry.outputContext.tree;
      return ringProofInput(entry, ownerOf(entry), { tree, treeId: await treeId(tree) });
    }),
  );
}

/** A note spends at its own tree, the stored nullifier was derived for that tree. */
export function ringProofInput(
  entry: WalletUtxo,
  owner: ShieldedAddress,
  client: TreeContext,
): ProofInputUtxo {
  if (entry.outputContext.tree !== client.tree) {
    throw new RingError("RING_TREE_MISMATCH", {
      details: { tree: entry.outputContext.tree, clientTree: client.tree },
    });
  }
  return new ProofInputUtxo({
    utxo: entry.utxo,
    nullifierPublicKey: noteNullifierPublicKey(entry, owner, client.treeId),
    nullifier: entry.nullifier,
    treeId: client.treeId,
    ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
    ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
  });
}

/** The zero key on a note a program owner's sender named, the note holds no key of its own. */
export function noteNullifierPublicKey(
  entry: WalletUtxo,
  owner: ShieldedAddress,
  treeId: number,
): Bytes32 {
  const rebuilds = (key: Bytes32): boolean =>
    equalBytes(
      entry.utxo.proofInput(key, treeId, entry.dataHash, entry.ringDataHash).hash(),
      entry.outputContext.hash,
    );
  return !rebuilds(owner.nullifierPublicKey) && rebuilds(ZERO_NULLIFIER_PK)
    ? ZERO_NULLIFIER_PK
    : owner.nullifierPublicKey;
}

export function ringIntentMismatch(field: string): RingError {
  return new RingError("RING_INTENT_MISMATCH", { details: { field } });
}

/** @internal */
export const ringSelectionErrors: SpendSelectionErrors = {
  insufficient: ({ asset, requested, available }) =>
    new RingError("RING_INSUFFICIENT_BALANCE", {
      details: { asset, requested: requested.toString(), available: available.toString() },
    }),
  tooManyInputs: ({ eligible, max }) =>
    new RingError("RING_TOO_MANY_INPUTS", { details: { selected: eligible, maximum: max } }),
  overflow: ({ available }) =>
    new RingError("RING_SELECTED_BALANCE_OVERFLOW", {
      details: { available: available.toString() },
    }),
};

/** Every set of up to `maxTrees` trees, one tree before two, each in first-seen order. */
function treeSets(trees: readonly Address[], maxTrees: number): readonly (readonly Address[])[] {
  const sets: Address[][] = [];
  let frontier: { set: Address[]; next: number }[] = [{ set: [], next: 0 }];
  for (let size = 1; size <= maxTrees; size += 1) {
    // A set grows only by a later tree, no set repeats in another order.
    frontier = frontier.flatMap(({ set, next }) =>
      trees.slice(next).map((tree, offset) => ({ set: [...set, tree], next: next + offset + 1 })),
    );
    sets.push(...frontier.map(({ set }) => set));
  }
  return sets;
}

function covered(entries: readonly WalletUtxo[]): bigint {
  return entries.reduce((sum, entry) => sum + entry.utxo.amount, 0n);
}

function spannedTrees(entries: readonly WalletUtxo[]): number {
  return new Set(entries.map((entry) => entry.outputContext.tree)).size;
}

/** Lexicographic, a tie keeps the earlier option. */
function precedes(left: readonly bigint[], right: readonly bigint[]): boolean {
  const index = left.findIndex((value, at) => value !== right[at]);
  const [mine, theirs] = [left[index], right[index]];
  return mine !== undefined && theirs !== undefined && mine < theirs;
}
