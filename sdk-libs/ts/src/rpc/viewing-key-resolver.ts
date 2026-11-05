/**
 * The current viewing key of an owner, read from its zolana `UserRecord`.
 *
 * Before the ring checks, `fetchUserRecord` reads only the canonical record
 * PDA and refuses a foreign program owner, a bad size, discriminator or merge
 * scheme, a stored owner other than the one asked for and a non canonical
 * bump. Old notes stay readable through `ViewingHistory` since the record
 * holds only the current key.
 */
import type { Address } from "@solana/kit";

import type { ChainReader } from "@heliuslabs/zolana/client";
import { equalBytes } from "@heliuslabs/zolana/internal";
import type { Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import { fetchUserRecord } from "@heliuslabs/zolana/wallet";

import { RingError } from "../protocol/error.js";

export type ViewingKeyClient = Pick<ChainReader, "getAccount">;

export interface ResolvedViewingKey {
  readonly viewingPublicKey: X25519PublicKey;
}

/** `undefined` only when no record exists, a failed read throws. */
export async function resolveViewingKey(
  input: Readonly<{
    client: ViewingKeyClient;
    owner: Address;
    /** The enrolled nullifier key, the record must hold the same one. */
    nullifierPublicKey?: Bytes32;
  }>,
  context?: RequestContext,
): Promise<ResolvedViewingKey | undefined> {
  // 1. zolana refuses a record its program did not write for the owner asked for.
  const record = await fetchUserRecord({ rpc: input.client, owner: input.owner }, context);
  if (record === undefined) return undefined;
  // 2. Neither REGISTER nor UPDATE_KEYS checks the key encoding, and a sender
  // seals only to the one canonical form.
  let viewingPublicKey: X25519PublicKey;
  try {
    viewingPublicKey = X25519PublicKey.fromBytes(record.viewingPublicKey);
  } catch (cause) {
    throw new RingError("RING_NONCANONICAL_VIEWING_KEY", {
      details: { owner: input.owner },
      cause,
    });
  }
  // 3. The record never rotates its nullifier key. A mismatch names another
  // identity, and a note sealed to its viewing key would not open for the
  // enrolled owner.
  if (
    input.nullifierPublicKey !== undefined &&
    !equalBytes(record.nullifierPublicKey, input.nullifierPublicKey)
  )
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH", { details: { owner: input.owner } });
  return Object.freeze({ viewingPublicKey });
}
