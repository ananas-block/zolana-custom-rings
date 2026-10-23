import type { Address } from "@heliuslabs/zolana";
import type { indexerTypes } from "@heliuslabs/zolana/internal";

type Hash = indexerTypes.Hash;
type Base64String = indexerTypes.Base64String;
type IndexerContext = indexerTypes.IndexerContext;

export interface RingMemberRequest {
  readonly ringProgramId: Address;
  readonly member: Hash;
}

export interface RingMemberProofRequest extends RingMemberRequest {
  readonly expectedRoot: Hash;
  readonly expectedNextIndex: bigint;
}

/** Reports the projection cursor and root of a member proof. */
export interface RingMemberProofContext {
  readonly context: IndexerContext;
  readonly root: Hash;
  readonly nextIndex: bigint;
  readonly member: Hash;
}

/** `record` is `null` until the member registers. */
export interface GetRingSpendRecordResponse {
  readonly context: IndexerContext;
  readonly record: Readonly<{
    transaction: indexerTypes.IndexedShieldedTransaction;
    outputIndex: number;
  }> | null;
}

export interface RingKeyRegistryRegisterProof extends RingMemberProofContext {
  readonly lowMember: Hash;
  readonly lowNext: Hash;
  readonly lowKeyHash: Hash;
  readonly lowIndex: bigint;
  readonly lowProof: readonly Hash[];
  readonly newProof: readonly Hash[];
}

/** Carries the encrypted nullifier key and its registry path. */
export interface RingKeyRegistryEntry extends RingMemberProofContext {
  readonly next: Hash;
  readonly index: bigint;
  readonly ephPk: Base64String;
  readonly ciphertext: Base64String;
  readonly proof: readonly Hash[];
}
