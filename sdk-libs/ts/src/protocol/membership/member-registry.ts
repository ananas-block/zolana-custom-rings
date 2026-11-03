import type { MintPolicy } from "./mint-policy.js";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

/** Rust `QUAD_ARITY` and `QUAD_HEIGHT`, the 4-ary record tree of a ring's member registry. */
export const QUAD_ARITY = 4;
export const QUAD_HEIGHT = 10;
/** Rust `MEMBER_REGISTRY_CAPACITY`, `4^10` leaves. */
export const MEMBER_REGISTRY_CAPACITY = 1n << BigInt(2 * QUAD_HEIGHT);
/** Rust `ROOT_HISTORY`, the roots a registry keeps. */
export const ROOT_HISTORY = 32;
/** Rust `APPLY_BATCH`, the writes the larger apply key proves. */
export const APPLY_BATCH = 16;

export interface MemberRecord {
  readonly member: Bytes32;
  readonly next: Bytes32;
  /** Bit `id - 1` marks list `id`. */
  readonly lists: bigint;
  /** Zero until the member registers a key. */
  readonly escrowKey: Bytes32;
  readonly mintPolicy: MintPolicy;
  /** Zero until the owner's enrollment is applied. */
  readonly addressHash: Bytes32;
}

/** The preimage of a record's `address_hash`, the indexer serves it beside the record. */
export interface AuthorizedAddress {
  /** `hash_bytes` of the ring program id, a record of another ring does not open. */
  readonly ringId: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly viewingU: Bytes32;
  readonly addressRevision: bigint;
}

/** A leaf index and three siblings per level in ascending child order, leaf level first. */
export interface QuadPath {
  readonly index: number;
  readonly siblings: readonly (readonly Bytes32[])[];
}

/** The least `levels` with `4^levels >= openings`, at most `QUAD_HEIGHT`. */
export function canopyLevels(openings: number): number {
  let levels = 0;
  while (levels < QUAD_HEIGHT && QUAD_ARITY ** levels < openings) levels += 1;
  return levels;
}

/** Go `PooledSubject`, `recordIndex` the record holding or bracketing `member`. */
export interface PoolSubject {
  readonly member: Bytes32;
  readonly recordIndex: number;
}

/** Go `PooledRecord` rows, their `SharedRegistryProof` and the `PooledSubject` rows they open. */
export interface RecordPool {
  readonly records: readonly MemberRecord[];
  readonly canopy: readonly Bytes32[];
  /** `paths[i]` opens `records[i]` up to the canopy, leaf level first. */
  readonly paths: readonly QuadPath[];
  readonly subjects: readonly PoolSubject[];
}

/** A member under one root, its record or the low record bracketing it. */
export type RecordOpening =
  | Readonly<{ kind: "present"; record: MemberRecord; path: QuadPath }>
  | Readonly<{ kind: "absent"; low: MemberRecord; path: QuadPath }>;

/** `lists' = (lists & !mask) | value`, the escrow key fills once, an owner-signed write alone sets an address. */
export interface QueueEntry {
  readonly member: Bytes32;
  readonly mask: bigint;
  readonly value: bigint;
  readonly escrowKey: Bytes32;
  readonly mintPolicy?: MintPolicy;
  /** Absent preserves the record's address. */
  readonly addressHash?: Bytes32;
}

/** Both preimages hold one nullifier key, the apply proof refuses any other pair. */
export interface AddressEscrowPair {
  readonly nullifierPk: Bytes32;
  readonly addressRing: Bytes32;
  readonly view0: Bytes32;
  readonly view1: Bytes32;
  readonly addressRevision: bigint;
  readonly escrowCiphertextHash: Bytes32;
}

/** One queued write's apply proof input, Rust `RecordWriteProofInput`. */
export interface RecordWriteProofInput {
  readonly entry: QueueEntry;
  readonly exists: boolean;
  /** An absent member reads its low record's `next` and empty lists. */
  readonly oldNext: Bytes32;
  readonly oldLists: bigint;
  readonly oldEscrow: Bytes32;
  readonly oldMintPolicy: MintPolicy;
  readonly oldAddressHash: Bytes32;
  /** The written record's address and escrow preimages, read while a write pairs them. */
  readonly pair?: AddressEscrowPair;
  /** The record's leaf, for an absent member the leaf at `next_index`. */
  readonly slot: QuadPath;
  /** An absent member's low record and its path before the relink, empty for a present member. */
  readonly low: MemberRecord;
  readonly lowPath: QuadPath;
}

/** One application's proof inputs, Rust `ApplyProofInputs`. */
export interface ApplyProofInputs {
  readonly oldRoot: Bytes32;
  readonly newRoot: Bytes32;
  readonly oldNextIndex: number;
  readonly newNextIndex: number;
  /** `chain(head - 1)`. */
  readonly chainStart: Bytes32;
  /** `chain(tail - 1)`. */
  readonly chainEnd: Bytes32;
  /** Queue order. */
  readonly writes: readonly RecordWriteProofInput[];
}
