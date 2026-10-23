import type { ChainReader, TreeContext } from "@heliuslabs/zolana/client";
import { decodeTreeId, treeAddress } from "@heliuslabs/zolana/internal";
import { SHIELDED_POOL_PROGRAM_ID, type Address, type RequestContext } from "@heliuslabs/zolana";
import type { TreeId } from "@heliuslabs/zolana/transaction";
import { RingError } from "./error.js";

export async function resolveRingOutputTree(
  client: TreeContext & Pick<ChainReader, "getAccount">,
  outputTree: Address | undefined,
  context?: RequestContext,
): Promise<TreeContext> {
  const tree = outputTree ?? client.tree;
  const treeId = tree === client.tree ? client.treeId : await readTreeId(client, tree, context);
  if (treeAddress(treeId) !== tree)
    throw new RingError("RING_TREE_MISMATCH", { details: { tree, treeId } });
  return { tree, treeId };
}

/** Cached per tree until a read fails, a `known` pair is trusted as given. */
export function ringTreeIdResolver(
  client: Pick<ChainReader, "getAccount">,
  known: readonly TreeContext[],
  context?: RequestContext,
): (tree: Address) => Promise<TreeId> {
  const ids = new Map<Address, Promise<TreeId>>(
    known.map(({ tree, treeId }) => [tree, Promise.resolve(treeId)]),
  );
  return (tree) => {
    const cached = ids.get(tree);
    if (cached !== undefined) return cached;
    const id = readTreeId(client, tree, context).then((treeId) => {
      if (treeAddress(treeId) !== tree)
        throw new RingError("RING_TREE_MISMATCH", { details: { tree, treeId } });
      return treeId;
    });
    ids.set(tree, id);
    void id.catch(() => {
      if (ids.get(tree) === id) ids.delete(tree);
    });
    return id;
  };
}

async function readTreeId(
  client: Pick<ChainReader, "getAccount">,
  tree: Address,
  context: RequestContext | undefined,
): Promise<TreeId> {
  const account = await client.getAccount(tree, context);
  if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID)
    throw new RingError("RING_TREE_MISMATCH", { details: { tree } });
  return decodeTreeId(account.data);
}
