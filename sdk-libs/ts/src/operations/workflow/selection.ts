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

/** Preferred trees, a failed pool falls back to the remaining pairs. */
export const PAIR_POOL_TREES = 8;

/** Every mint from one tree, two trees only when no tree alone funds, then the fewest UTXOs, then change. */
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
  // 1. Group covered unspent notes by tree, a tree with no covered mint never enters the search.
  const byTree = new Map<Address, WalletUtxo[]>();
  for (const entry of wallet.utxos()) {
    if (
      !entry.spent &&
      entry.utxo.amount > 0n &&
      covers.some((cover) => cover.asset === entry.utxo.asset) &&
      policy.eligible(entry)
    ) {
      const notes = byTree.get(entry.outputContext.tree);
      if (notes === undefined) byTree.set(entry.outputContext.tree, [entry]);
      else notes.push(entry);
    }
  }
  const held = (trees: readonly Address[], asset: Address) =>
    covered(
      trees.flatMap((tree) =>
        (byTree.get(tree) ?? []).filter((entry) => entry.utxo.asset === asset),
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
  // 2. Each mint's best trees by reach within the input budget form the pair pool.
  const trees = [...byTree.keys()];
  const pool = new Set(
    covers.flatMap((cover) => {
      const reach = (tree: Address) =>
        (byTree.get(tree) ?? [])
          .filter((entry) => entry.utxo.asset === cover.asset)
          .map((entry) => entry.utxo.amount)
          .sort(descending)
          .slice(0, policy.maxInputs)
          .reduce((sum, amount) => sum + amount, 0n);
      // The sort is stable, an equal reach keeps the first-seen tree first.
      return trees
        .map((tree) => ({ tree, reach: reach(tree) }))
        .sort((left, right) => descending(left.reach, right.reach))
        .slice(0, PAIR_POOL_TREES)
        .map(({ tree }) => tree);
    }),
  );
  if (covers.length === 1) {
    const pair = pairCover(byTree, covers[0]!, policy.maxInputs);
    if (pair === undefined) pool.clear();
    else for (const tree of pair) pool.add(tree);
  }
  let furthest: { rank: readonly bigint[]; error: unknown } | undefined;
  // 3. A pair runs only when no tree alone funds, its picks always span both trees.
  const consider = (set: readonly Address[]) => {
    const outcome = attempt(set);
    if (outcome.kind === "short") {
      if (furthest === undefined || precedes(furthest.rank, outcome.rank)) furthest = outcome;
      return undefined;
    }
    return outcome.entries;
  };
  // With no eligible note the empty set still runs, its selection names the refusal.
  const funded =
    trees.length === 0
      ? found(consider([]))
      : stagedTreeSearch(
          trees,
          maxTrees >= 2 ? trees.filter((tree) => pool.has(tree)) : [],
          consider,
        );
  let best: { rank: readonly bigint[]; entries: readonly WalletUtxo[] } | undefined;
  for (const entries of funded) {
    const rank = [BigInt(entries.length), covered(entries)];
    if (best === undefined || precedes(rank, best.rank)) best = { rank, entries };
  }
  if (best !== undefined) return best.entries;
  // The set funding the most mints, then holding the most of the short one, names the refusal.
  throw furthest?.error;
}

function pairCover(
  byTree: ReadonlyMap<Address, readonly WalletUtxo[]>,
  cover: Cover,
  maxInputs: number,
): readonly Address[] | undefined {
  const leaders: { tree: Address; amount: bigint }[][] = Array.from(
    { length: maxInputs },
    () => [],
  );
  for (const [tree, notes] of byTree) {
    const amounts = notes
      .filter((note) => note.utxo.asset === cover.asset)
      .map((note) => note.utxo.amount)
      .sort(descending);
    let amount = 0n;
    for (let budget = 1; budget < maxInputs; budget++) {
      amount += amounts[budget - 1] ?? 0n;
      const best = leaders[budget]!;
      best.push({ tree, amount });
      best.sort((left, right) => descending(left.amount, right.amount));
      best.splice(2);
    }
  }
  let best: { trees: readonly Address[]; amount: bigint } | undefined;
  for (let budget = 1; budget < maxInputs; budget++) {
    for (const left of leaders[budget]!) {
      for (const right of leaders[maxInputs - budget]!) {
        const amount = left.amount + right.amount;
        if (
          left.tree !== right.tree &&
          amount >= cover.amount &&
          (best === undefined || amount > best.amount)
        ) {
          best = { trees: [left.tree, right.tree], amount };
        }
      }
    }
  }
  return best?.trees;
}

export function stagedTreeSearch<T>(
  trees: readonly Address[],
  pool: readonly Address[],
  fund: (set: readonly Address[]) => T | undefined,
): readonly T[] {
  const singles = trees.flatMap((tree) => found(fund([tree])));
  if (singles.length > 0) return singles;
  const preferred = pool.flatMap((first, at) =>
    pool.slice(at + 1).flatMap((second) => found(fund([first, second]))),
  );
  if (preferred.length > 0 || pool.length === 0) return preferred;
  const selected = new Set(pool);
  for (let first = 0; first < trees.length; first++) {
    for (let second = first + 1; second < trees.length; second++) {
      const left = trees[first]!;
      const right = trees[second]!;
      if (selected.has(left) && selected.has(right)) continue;
      const candidate = fund([left, right]);
      if (candidate !== undefined) return [candidate];
    }
  }
  return [];
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

function descending(left: bigint, right: bigint): number {
  return left < right ? 1 : left > right ? -1 : 0;
}

function found<T>(value: T | undefined): readonly T[] {
  return value === undefined ? [] : [value];
}

function covered(entries: readonly WalletUtxo[]): bigint {
  return entries.reduce((sum, entry) => sum + entry.utxo.amount, 0n);
}

/** Lexicographic, a tie keeps the earlier option. */
function precedes(left: readonly bigint[], right: readonly bigint[]): boolean {
  const index = left.findIndex((value, at) => value !== right[at]);
  const [mine, theirs] = [left[index], right[index]];
  return mine !== undefined && theirs !== undefined && mine < theirs;
}
