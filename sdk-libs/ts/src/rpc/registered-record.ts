import {
  type RingMemberOpening,
  type RingRecordReader,
  type StorageRoot,
  type TrackingReader,
} from "./ports.js";
import { type PresentRecordOpening } from "./prover/types.js";
import { MAX_RING_MEMBER_BATCH } from "../protocol/indexer/indexer-limits.js";
import type { ChainReader } from "@heliuslabs/zolana/client";
import {
  bytesKey,
  equalBytes,
  waitForProjection,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";

import { fetchRingPolicy, fetchStorageRegistry } from "../protocol/membership/config.js";
import { RingError } from "../protocol/error.js";
import {
  MemberOpeningRead,
  ownerEscrowed,
  verifyRecordPool,
} from "../protocol/membership/member-opening.js";
import { verifyTrackingOpening } from "../protocol/membership/tracking.js";
import type { RecordPool } from "../protocol/membership/member-registry.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "./projection.js";
import { newestTrackingRoot } from "./tracking-resolver.js";

export type RingRecordReadClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getStorageMemberOpenings">;

/** A storage root a proof binds, named by the revision the program reads it back by. */
export interface BoundRoot {
  readonly ringProgramId: Address;
  readonly registry: Address;
  readonly revision: bigint;
  readonly root: Bytes32;
}

/** The newest root the live `registry` holds. */
export async function fetchBoundRoot(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    ringProgramId: Address;
    registry: Address;
  }>,
  context?: RequestContext,
): Promise<BoundRoot> {
  const root = await fetchRegistryRoot(input, context);
  return Object.freeze({ ...root, ringProgramId: input.ringProgramId });
}

/** No ring proof binds the root. */
export async function fetchRegistryRoot(
  input: Readonly<{ client: Pick<ChainReader, "getAccount">; registry: Address }>,
  context?: RequestContext,
): Promise<RegistryRoot> {
  const current = (await fetchStorageRegistry(input.client, input.registry, context)).roots[0];
  if (current === undefined)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { registry: input.registry } });
  return Object.freeze({
    registry: input.registry,
    revision: current.revision,
    root: current.hash,
  });
}

export type RegistryRoot = Omit<BoundRoot, "ringProgramId">;

/** A member's present record under the ring's newest own root. */
export interface RegisteredRecord {
  readonly root: BoundRoot;
  readonly record: PresentRecordOpening;
  /** `hash_bytes` of the sealed key ciphertext. */
  readonly ctHash: Bytes32;
}

/** Members' records under the ring's newest own root, in member order, Rust `MemberRecords::read`. */
export async function readMemberRecords(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<readonly MemberOpeningRead[]> {
  return (await readOwnRecords(input, context)).reads;
}

/** @internal `readMemberRecords` with the root the reads verify under. */
export function readOwnRecords(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<Readonly<{ root: BoundRoot; reads: readonly MemberOpeningRead[] }>> {
  return waitForProjection(
    async (attempt) => {
      const policy = await fetchRingPolicy(input.client, input.ringProgramId, attempt);
      const root = await fetchBoundRoot(
        { client: input.client, ringProgramId: input.ringProgramId, registry: policy.records },
        attempt,
      );
      const reads = await readMemberOpenings(
        { client: input.client, root, members: input.members },
        attempt,
      );
      return { root, reads };
    },
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}

/** Under key escrow the first recipient with no applied row for its nullifier key is refused. */
export async function checkEscrowedRecipients(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount"> & Pick<TrackingReader, "getTrackingOpenings">;
    ringProgramId: Address;
    recipients: readonly ShieldedAddress[];
  }>,
  context?: RequestContext,
): Promise<void> {
  const { client, ringProgramId } = input;
  const config = await fetchRingPolicy(client, ringProgramId, context);
  if (config.mode !== "confidentialEscrow") return;
  // The zero nullifier key escrows nothing.
  const recipients = input.recipients.filter(
    (recipient) => !equalBytes(recipient.nullifierPublicKey, ZERO_NULLIFIER_PK),
  );
  if (recipients.length === 0) return;
  const { root } = await newestTrackingRoot(
    { client, trackingRegistry: config.tracking, ring: ringProgramId },
    context,
  );
  for (let offset = 0; offset < recipients.length; offset += MAX_RING_MEMBER_BATCH) {
    const chunk = recipients.slice(offset, offset + MAX_RING_MEMBER_BATCH);
    const members = chunk.map((recipient) => recipient.signingPublicKey.ownerProofInputHash());
    const { openings } = await client.getTrackingOpenings(
      { registry: config.tracking, members, expectedRoot: root },
      context,
    );
    chunk.forEach((recipient, at) => {
      const member = members[at];
      const opening = openings[at];
      if (member === undefined || opening === undefined)
        throw new RingError("RING_TRACKING_INVALID", { details: { reason: "openings" } });
      const row = verifyTrackingOpening(opening, root, member);
      if (row === undefined || !equalBytes(row.nullifierPk, recipient.nullifierPublicKey))
        throw new RingError("RING_UNREGISTERED_OUTPUT_KEY", {
          details: { owner: bytesKey(member) },
        });
    });
  }
}

/** One opening per member in member order, each verified against `root`, Rust `RecordReads::read`. */
export function readMemberOpenings(
  input: Readonly<{
    client: Pick<RingRecordReader, "getStorageMemberOpenings">;
    root: RegistryRoot;
    members: readonly Bytes32[];
  }>,
  context?: RequestContext,
): Promise<readonly MemberOpeningRead[]> {
  const { root } = input;
  return openingsInBatches(input.members, root.root, async (members) => {
    const served = await input.client.getStorageMemberOpenings(
      { registry: root.registry, members, expectedRoot: root.root },
      context,
    );
    checkServedRoot(served.root, root, "openings");
    return served.openings;
  });
}

/** A pool verified under its root, with every member's read in member order. */
export interface RecordPoolRead {
  /** Records and subjects repeat cyclically up to the pool capacity. */
  readonly pool: RecordPool;
  readonly reads: readonly MemberOpeningRead[];
}

/** `members` under `root` in one pool of `openings` records. */
export async function readRecordPool(
  input: Readonly<{
    client: Pick<RingRecordReader, "getStorageRecordPool">;
    root: BoundRoot;
    members: readonly Bytes32[];
    openings: number;
  }>,
  context?: RequestContext,
): Promise<RecordPoolRead> {
  const { members, openings, root } = input;
  if (members.length < 1 || members.length > openings)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "poolCapacity" } });
  const served = await input.client.getStorageRecordPool(
    { registry: root.registry, members, expectedRoot: root.root, openings },
    context,
  );
  checkServedRoot(served.root, root, "pool");
  const reads = verifyRecordPool(served, root.root, members, openings);
  const records = cyclic(served.records, openings);
  return Object.freeze({
    pool: Object.freeze({
      records: Object.freeze(records.map(({ record }) => record)),
      canopy: Object.freeze([...served.canopy]),
      paths: Object.freeze(records.map(({ path }) => path)),
      subjects: Object.freeze(
        cyclic(
          members.map((member, index) =>
            Object.freeze({ member, recordIndex: served.subjects[index] ?? 0 }),
          ),
          openings,
        ),
      ),
    }),
    reads,
  });
}

/** The indexer's opening checked against the ring's newest own root. */
export function readRegisteredRecord(
  input: Readonly<{
    client: RingRecordReadClient;
    ringProgramId: Address;
    member: Bytes32;
    /** The nullifier key the owner must have enrolled. */
    escrowed: Bytes32;
  }>,
  context?: RequestContext,
): Promise<RegisteredRecord> {
  return waitForProjection(
    async (attempt) => {
      const policy = await fetchRingPolicy(input.client, input.ringProgramId, attempt);
      const root = await fetchBoundRoot(
        { client: input.client, ringProgramId: input.ringProgramId, registry: policy.records },
        attempt,
      );
      const [read] = await readMemberOpenings(
        { client: input.client, root, members: [input.member] },
        attempt,
      );
      const escrowed = ownerEscrowed(input.member, read, input.escrowed);
      return Object.freeze({
        root,
        record: Object.freeze({
          kind: "present" as const,
          record: escrowed.record,
          path: escrowed.path,
        }),
        ctHash: escrowed.ctHash,
      });
    },
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}

/** An indexer answer under a root or revision other than the bound one is refused. */
function checkServedRoot(served: StorageRoot, bound: RegistryRoot, reason: string): void {
  if (!equalBytes(served.root, bound.root) || served.revision !== bound.revision)
    throw new RingError("RING_ROOT_NOT_SERVED", {
      details: { reason, registry: bound.registry, revision: served.revision.toString() },
    });
}

async function openingsInBatches(
  members: readonly Bytes32[],
  root: Bytes32,
  fetch: (members: readonly Bytes32[]) => Promise<readonly RingMemberOpening[]>,
): Promise<readonly MemberOpeningRead[]> {
  const reads: MemberOpeningRead[] = [];
  for (let offset = 0; offset < members.length; offset += MAX_RING_MEMBER_BATCH) {
    const chunk = members.slice(offset, offset + MAX_RING_MEMBER_BATCH);
    const openings = await fetch(chunk);
    if (openings.length !== chunk.length)
      throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
    chunk.forEach((member, index) => {
      const opening = openings[index];
      if (opening === undefined)
        throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
      reads.push(MemberOpeningRead.verify(opening, root, member));
    });
  }
  return reads;
}

function cyclic<T>(values: readonly T[], length: number): readonly T[] {
  return Array.from({ length }, (_, index) => values[index % values.length] as T);
}
