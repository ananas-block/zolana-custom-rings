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

/** Preferred trees per mint, their pairs run ahead of the complete pair search, Rust `PAIR_POOL_TREES`. */
export const PAIR_POOL_TREES = 8;

/**
 * Every mint from one tree, two trees only when no tree alone fits, then the fewest UTXOs,
 * then change.
 */
export function selectAcrossTrees(
  input: Readonly<{
    wallet: Wallet;
    covers: readonly Cover[];
    policy: Omit<SpendPolicy, "tree">;
    /** At most `MAX_INPUT_TREES`, below it where the rail's builder takes fewer. */
    maxTrees?: number;
    /** Only infeasible selections leave the refusal to the caller's shape check. */
    feasible?: (entries: readonly WalletUtxo[]) => boolean;
  }>,
): readonly WalletUtxo[] {
  const { wallet, covers, policy, maxTrees = MAX_INPUT_TREES, feasible = () => true } = input;
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
  const notesOf = (trees: readonly Address[], asset: Address) =>
    trees.flatMap((tree) => (byTree.get(tree) ?? []).filter((entry) => entry.utxo.asset === asset));
  // Each mint in turn takes what the earlier mints leave of the input budget.
  const attempt = (trees: readonly Address[], wanted: readonly Cover[] = covers) => {
    const entries: WalletUtxo[] = [];
    for (const [funded, cover] of wanted.entries()) {
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
        const held = covered(notesOf(trees, cover.asset));
        return { kind: "short" as const, rank: [BigInt(funded), held], error };
      }
    }
    return { kind: "funded" as const, entries };
  };
  let furthest: { rank: readonly bigint[]; error: unknown } | undefined;
  const consider = (set: readonly Address[]): Trial<readonly WalletUtxo[]> | undefined => {
    const outcome = attempt(set);
    if (outcome.kind === "short") {
      if (furthest === undefined || precedes(furthest.rank, outcome.rank)) furthest = outcome;
      return undefined;
    }
    // Picks on one tree repeat that tree's own trial.
    if (spannedTrees(outcome.entries) !== set.length) return undefined;
    return { found: outcome.entries, feasible: feasible(outcome.entries) };
  };
  // 2. Each mint's reach bounds its funding, the mints share the input budget.
  const allTrees = [...byTree.keys()];
  const reaches = covers.map(
    (cover) => new TreeReach(notesOf(allTrees, cover.asset), policy.maxInputs),
  );
  // With no eligible note the empty set still runs, its selection names the refusal.
  const funded =
    allTrees.length === 0
      ? found(consider([])?.found)
      : treeSearch({
          ...rankedTrees(reaches),
          maxTrees,
          reaches: (set) => covers.every((cover, at) => reaches[at]!.of(set) >= cover.amount),
          fund: consider,
        });
  let best: { rank: readonly bigint[]; entries: readonly WalletUtxo[] } | undefined;
  for (const entries of funded) {
    const rank = [BigInt(entries.length), covered(entries)];
    if (best === undefined || precedes(rank, best.rank)) best = { rank, entries };
  }
  if (best !== undefined) return best.entries;
  // 3. A mint no set reaches names the refusal alone, at its furthest set.
  const short = covers.findIndex(
    (cover, at) => !reaches[at]!.reachesAnywhere(cover.amount, maxTrees),
  );
  if (short !== -1) {
    const outcome = attempt(reaches[short]!.furthest(maxTrees) ?? [], [covers[short]!]);
    if (outcome.kind === "short") throw outcome.error;
  }
  // Every mint reaches alone, the furthest set run or a mint's furthest set names the refusal.
  for (const reach of reaches) {
    if (furthest !== undefined) break;
    const set = reach.furthest(maxTrees);
    if (set !== undefined) consider(set);
  }
  throw furthest?.error;
}

/** @internal A funding tree set, infeasible when no keyed shape holds it, Rust `Trial`. */
export interface Trial<T> {
  readonly found: T;
  readonly feasible: boolean;
}

/** @internal Per tree, the sum of its largest notes at each count up to the input budget, Rust `Reach`. */
export class TreeReach {
  readonly #budget: number;
  readonly #prefixes = new Map<Address, readonly bigint[]>();

  constructor(notes: readonly WalletUtxo[], budget: number) {
    this.#budget = budget;
    const amounts = new Map<Address, bigint[]>();
    for (const note of notes) {
      const held = amounts.get(note.outputContext.tree);
      if (held === undefined) amounts.set(note.outputContext.tree, [note.utxo.amount]);
      else held.push(note.utxo.amount);
    }
    for (const [tree, held] of amounts) {
      const sums = [0n];
      for (const amount of held.sort(descending).slice(0, budget)) sums.push(sums.at(-1)! + amount);
      this.#prefixes.set(tree, sums);
    }
  }

  /** The most a largest first pick of at most `budget` notes takes from `set`. */
  of(set: readonly Address[]): bigint {
    const largest = (tree: Address, count: number) => {
      const sums = this.#prefixes.get(tree) ?? [0n];
      return sums[Math.min(count, sums.length - 1)]!;
    };
    const [left, right] = set;
    if (left === undefined) return 0n;
    if (right === undefined) return largest(left, this.#budget);
    // The union's largest notes split between the trees at one count.
    let most = 0n;
    for (let count = 0; count <= this.#budget; count += 1) {
      const sum = largest(left, count) + largest(right, this.#budget - count);
      if (sum > most) most = sum;
    }
    return most;
  }

  /** Whether any tree or, with `maxTrees` past one, any pair reaches `amount`. */
  reachesAnywhere(amount: bigint, maxTrees: number): boolean {
    const set = this.furthest(maxTrees);
    return set !== undefined && this.of(set) >= amount;
  }

  /** The tree or pair of the greatest reach, the earlier on a tie. */
  furthest(maxTrees: number): readonly Address[] | undefined {
    const trees = [...this.#prefixes.keys()];
    let best: readonly Address[] | undefined;
    for (const set of [...trees.map((tree) => [tree]), ...(maxTrees >= 2 ? pairs(trees) : [])])
      if (best === undefined || this.of(set) > this.of(best)) best = set;
    return best;
  }

  /** The trees holding the mint, the greatest reach first, an equal reach in first-seen order. */
  ranked(): readonly Address[] {
    return [...this.#prefixes.keys()]
      .map((tree) => ({ tree, reach: this.of([tree]) }))
      .sort((left, right) => descending(left.reach, right.reach))
      .map(({ tree }) => tree);
  }
}

/** @internal Trees holding a spend's mints, each mint's `PAIR_POOL_TREES` best leading as the pool. */
export function rankedTrees(
  reaches: readonly TreeReach[],
): Readonly<{ trees: readonly Address[]; pool: readonly Address[] }> {
  const ranked = reaches.map((reach) => reach.ranked());
  const pool = [...new Set(ranked.flatMap((trees) => trees.slice(0, PAIR_POOL_TREES)))];
  return { trees: [...new Set([...pool, ...ranked.flat()])], pool };
}

/** @internal Singles, pool pairs, then the other pairs, a stage with a feasible set ends the search, Rust `TreeSearch`. */
export function treeSearch<T>(
  input: Readonly<{
    trees: readonly Address[];
    pool: readonly Address[];
    maxTrees: number;
    reaches: (set: readonly Address[]) => boolean;
    fund: (set: readonly Address[]) => Trial<T> | undefined;
  }>,
): readonly T[] {
  const { trees, pool, reaches, fund } = input;
  const infeasible: T[] = [];
  const stage = (sets: readonly (readonly Address[])[]): readonly T[] => {
    const feasible: T[] = [];
    for (const set of sets) {
      if (!reaches(set)) continue;
      const trial = fund(set);
      if (trial === undefined) continue;
      (trial.feasible ? feasible : infeasible).push(trial.found);
    }
    return feasible;
  };
  const inPool = new Set(pool);
  const stages = [
    () => trees.map((tree) => [tree]),
    () => (input.maxTrees >= 2 ? pairs(pool) : []),
    // Complete over every pair of T trees, a reach check prunes each pair before any selection.
    () =>
      input.maxTrees >= 2
        ? pairs(trees).filter((pair) => !pair.every((tree) => inPool.has(tree)))
        : [],
  ];
  for (const sets of stages) {
    const feasible = stage(sets());
    if (feasible.length > 0) return feasible;
  }
  return infeasible;
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

/** Every pair of `trees`, in their order. */
function pairs(trees: readonly Address[]): readonly (readonly Address[])[] {
  return trees.flatMap((first, at) => trees.slice(at + 1).map((second) => [first, second]));
}

function found<T>(value: T | undefined): readonly T[] {
  return value === undefined ? [] : [value];
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
