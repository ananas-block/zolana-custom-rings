import type { ChainReader, TreeContext } from "@heliuslabs/zolana/client";
import {
  equalBytes,
  selectUtxos,
  ZERO_NULLIFIER_PK,
  type SpendPolicy,
  type SpendSelectionErrors,
  type SpendTarget,
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

/** The fewest UTXOs over the fewest input trees covering `target`, then the least change. */
export function selectAcrossTrees(
  input: Readonly<{
    wallet: Wallet;
    asset: Address;
    target: Extract<SpendTarget, { kind: "cover" }>;
    policy: Omit<SpendPolicy, "tree">;
  }>,
): readonly WalletUtxo[] {
  const { wallet, asset, target, policy } = input;
  const eligible = wallet
    .utxos()
    .filter(
      (entry) =>
        !entry.spent &&
        entry.utxo.asset === asset &&
        entry.utxo.amount > 0n &&
        policy.eligible(entry),
    );
  const sets = treeSets([...new Set(eligible.map((entry) => entry.outputContext.tree))]);
  const select = (trees: readonly Address[]) =>
    selectUtxos({
      wallet,
      asset,
      target,
      policy: {
        ...policy,
        eligible: (entry) => trees.includes(entry.outputContext.tree) && policy.eligible(entry),
        tree: { kind: "infer", maxTrees: trees.length },
      },
    }).entries;
  const funded = sets.flatMap((trees) => {
    try {
      const entries = select(trees);
      // A pair whose largest notes sit on one tree repeats that tree's own selection.
      return spannedTrees(entries) === trees.length ? [{ trees, entries }] : [];
    } catch {
      return [];
    }
  });
  const covered = (entries: readonly WalletUtxo[]) =>
    entries.reduce((sum, entry) => sum + entry.utxo.amount, 0n);
  const rank = (option: (typeof funded)[number]) => [
    BigInt(option.trees.length),
    BigInt(option.entries.length),
    covered(option.entries),
  ];
  const best = funded.reduce<(typeof funded)[number] | undefined>(
    (chosen, next) => (chosen === undefined || precedes(rank(next), rank(chosen)) ? next : chosen),
    undefined,
  );
  if (best !== undefined) return best.entries;
  // The set holding the most names the shortfall, a wider spend never reaches more.
  const held = (trees: readonly Address[]) =>
    covered(eligible.filter((entry) => trees.includes(entry.outputContext.tree)));
  const richest = sets.reduce<readonly Address[] | undefined>(
    (chosen, trees) => (chosen === undefined || held(trees) > held(chosen) ? trees : chosen),
    undefined,
  );
  if (richest === undefined)
    throw policy.errors.insufficient({ asset, requested: target.amount, available: 0n });
  return select(richest);
}

/** Proof inputs at each note's own tree, a second tree's id read once from its account. */
export async function ringProofInputs(
  entries: readonly WalletUtxo[],
  owner: ShieldedAddress,
  client: TreeContext & Pick<ChainReader, "getAccount">,
  context?: RequestContext,
): Promise<readonly ProofInputUtxo[]> {
  const treeId = ringTreeIdResolver(client, [client], context);
  return Promise.all(
    entries.map(async (entry) => {
      const tree = entry.outputContext.tree;
      return ringProofInput(entry, owner, { tree, treeId: await treeId(tree) });
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

/** Every set of up to `MAX_INPUT_TREES` trees, one tree before two, each in first-seen order. */
function treeSets(trees: readonly Address[]): readonly (readonly Address[])[] {
  const sets: Address[][] = [];
  let frontier: { set: Address[]; next: number }[] = [{ set: [], next: 0 }];
  for (let size = 1; size <= MAX_INPUT_TREES; size += 1) {
    // A set grows only by a later tree, no set repeats in another order.
    frontier = frontier.flatMap(({ set, next }) =>
      trees.slice(next).map((tree, offset) => ({ set: [...set, tree], next: next + offset + 1 })),
    );
    sets.push(...frontier.map(({ set }) => set));
  }
  return sets;
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
