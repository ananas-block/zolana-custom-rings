/**
 * A wallet's viewing key rotation through zolana's `UserRecord`, Rust
 * `ViewingRotation` and `UpdateViewingKey`.
 *
 * Read before `rpc/viewing-key-resolver.ts`, whose read confirms the record
 * once the owner's update lands. Read after `LocalRingKeys` and
 * `ViewingHistory`, the two halves of a wallet a rotation moves together.
 *
 * A rotation runs in three steps. `rotateViewingKey` is local, and the wallet
 * stores the new viewing secret and the rotated history before the owner signs
 * what `updateViewingKey` builds. A record naming a key the wallet lost routes
 * every later payment to notes nobody opens. `confirmViewingKey` reads the
 * record back once the update lands. The record holds only the current key, the
 * history keeps every earlier one, and notes sealed to an earlier key open
 * through it.
 */
import type { Address } from "@solana/kit";

import type { BlockhashProvider, ChainReader } from "@heliuslabs/zolana/client";
import type { RequestContext, Transaction } from "@heliuslabs/zolana/interface";
import type { ViewingKey } from "@heliuslabs/zolana/keypair";
import { buildKeyUpdateTransaction } from "@heliuslabs/zolana/wallet";

import { RingError } from "../../protocol/error.js";
import {
  resolveViewingKey,
  type ResolvedViewingKey,
  type ViewingKeyClient,
} from "../../rpc/viewing-key-resolver.js";
import type { LocalRingKeys, RingKeys } from "../../state/ring-keys.js";
import type { ViewingHistory } from "../../state/viewing-history.js";

/** `rotateViewingKey` moves both to one current key. */
export interface ViewingRotation {
  readonly keys: LocalRingKeys;
  readonly history: ViewingHistory;
}

export type ViewingKeyUpdateClient = Pick<ChainReader, "getAccount"> & BlockhashProvider;

/** `next` becomes current in both, every earlier key stays held and scanned. */
export function rotateViewingKey(
  input: Readonly<ViewingRotation & { next: ViewingKey; rotatedAt: bigint }>,
): ViewingRotation {
  const history = input.history.withRotatedKey(input.next.publicKey(), input.rotatedAt);
  return Object.freeze({ keys: input.keys.rotate(input.next), history });
}

/** The unsigned `UPDATE_KEYS` of the holder's current key, `undefined` when the record already holds it. */
export async function updateViewingKey(
  input: Readonly<{
    client: ViewingKeyUpdateClient;
    owner: Address;
    keys: RingKeys;
    history: ViewingHistory;
    /** Pays the fee, the owner when absent. */
    payer?: Address;
  }>,
  context?: RequestContext,
): Promise<Transaction | undefined> {
  // 1. No sync reads a key the history lacks. Publishing one routes payments
  // to notes the wallet never finds.
  const address = input.keys.address();
  if (!input.history.current().viewingPublicKey.equals(address.viewingPublicKey))
    throw new RingError("RING_VIEWING_HISTORY_NOT_CURRENT");
  // 2. zolana refuses a missing record and a changed nullifier key, and the
  // program refuses the changed key again.
  return buildKeyUpdateTransaction(
    {
      client: input.client,
      owner: input.owner,
      address,
      ...(input.payer === undefined ? {} : { payer: input.payer }),
    },
    context,
  );
}

/** Resolves once the record holds the holder's current key, any other key refuses. */
export async function confirmViewingKey(
  input: Readonly<{ client: ViewingKeyClient; owner: Address; keys: RingKeys }>,
  context?: RequestContext,
): Promise<ResolvedViewingKey> {
  const address = input.keys.address();
  const resolved = await resolveViewingKey(
    {
      client: input.client,
      owner: input.owner,
      nullifierPublicKey: address.nullifierPublicKey,
    },
    context,
  );
  if (resolved === undefined || !resolved.viewingPublicKey.equals(address.viewingPublicKey))
    throw new RingError("RING_VIEWING_KEY_NOT_PUBLISHED", { details: { owner: input.owner } });
  return resolved;
}
