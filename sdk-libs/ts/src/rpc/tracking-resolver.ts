import type { Address } from "@solana/kit";

import type { ChainReader } from "@heliuslabs/zolana/client";
import { equalBytes, ZERO_NULLIFIER_PK } from "@heliuslabs/zolana/internal";
import type { Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";

import { listTagOf } from "../crypto/keys/ring-nullifier-key.js";
import type { RingAddress } from "../crypto/keys/ring-address.js";
import { x25519FromU } from "../crypto/keys/x25519.js";
import { RingError } from "../protocol/error.js";
import {
  decodeTrackingRegistry,
  verifyTrackingOpening,
  type TrackingRegistry,
} from "../protocol/membership/tracking.js";
import type { BoundRoot } from "./registered-record.js";
import type { TrackingReader } from "./ports.js";

export type RingRecipientClient = Pick<ChainReader, "getAccount"> &
  Pick<TrackingReader, "getTrackingOpenings">;

export type TrackingRoot = BoundRoot;

export type ResolvedRecipient =
  /** The row's viewing key is newer than any the address carries. */
  | Readonly<{
      kind: "enrolled";
      root: TrackingRoot;
      nullifierPk: Bytes32;
      viewingPublicKey: X25519PublicKey;
      revision: bigint;
      listTag: Bytes32;
    }>
  /** Named under the zero key, a row's absence under the frame's root admits it. */
  | Readonly<{ kind: "zeroKey"; root: TrackingRoot }>;

/** Refuses what the output rule refuses. */
export async function resolveRingRecipient(
  input: Readonly<{ client: RingRecipientClient; trackingRegistry: Address; to: RingAddress }>,
  context?: RequestContext,
): Promise<ResolvedRecipient> {
  const { client, trackingRegistry, to } = input;
  const root = await newestTrackingRoot(
    { client, trackingRegistry, ring: to.ringProgramId },
    context,
  );
  const member = to.recipient.signingPublicKey.ownerProofInputHash();
  const { openings } = await client.getTrackingOpenings(
    { registry: trackingRegistry, members: [member], expectedRoot: root.root },
    context,
  );
  const [opening] = openings;
  if (opening === undefined)
    throw new RingError("RING_TRACKING_INVALID", { details: { reason: "openings" } });
  const row = verifyTrackingOpening(opening, root.root, member);
  const named = to.recipient.nullifierPublicKey;
  if (equalBytes(named, ZERO_NULLIFIER_PK)) {
    if (row !== undefined) throw new RingError("RING_RECIPIENT_ENROLLED");
    return Object.freeze({ kind: "zeroKey", root });
  }
  if (row === undefined) throw new RingError("RING_RECIPIENT_NOT_ENROLLED");
  if (!equalBytes(row.nullifierPk, named))
    throw new RingError("RING_ADDRESS_MISMATCH", { details: { field: "nullifierPk" } });
  if (!equalBytes(row.listTag, listTagOf(to.listSalt)))
    throw new RingError("RING_ADDRESS_MISMATCH", { details: { field: "listSalt" } });
  return Object.freeze({
    kind: "enrolled",
    root,
    nullifierPk: row.nullifierPk,
    viewingPublicKey: x25519FromU(row.viewingU),
    revision: row.revision,
    listTag: row.listTag,
  });
}

export async function newestTrackingRoot(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    trackingRegistry: Address;
    ring: Address;
  }>,
  context?: RequestContext,
): Promise<TrackingRoot> {
  const registry = await fetchTrackingRegistry(input.client, input.trackingRegistry, context);
  const newest = registry.roots[0];
  if (newest === undefined)
    throw new RingError("RING_TRACKING_INVALID", { details: { reason: "no root" } });
  return Object.freeze({
    ringProgramId: input.ring,
    registry: input.trackingRegistry,
    revision: newest.revision,
    root: newest.hash,
  });
}

export async function fetchTrackingRegistry(
  client: Pick<ChainReader, "getAccount">,
  address: Address,
  context?: RequestContext,
): Promise<TrackingRegistry> {
  const account = await client.getAccount(address, context);
  if (account === undefined)
    throw new RingError("RING_TRACKING_INVALID", { details: { reason: "registry" } });
  return decodeTrackingRegistry(account.data);
}
