import type { TreeContext } from "@heliuslabs/zolana/client";
import {
  equalBytes,
  ZERO_NULLIFIER_PK,
  type SpendSelectionErrors,
} from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";
import { ProofInputUtxo } from "@heliuslabs/zolana/transaction";
import type { WalletUtxo } from "@heliuslabs/zolana/transaction";

import { RingError } from "../../protocol/error.js";

/** Ring notes are spent from the client's tree, the stored nullifier was derived for that tree. */
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
