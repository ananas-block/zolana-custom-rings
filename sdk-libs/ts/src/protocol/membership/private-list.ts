/** A private list source read by a salt holder, Go `circuits/privatelist`. */
import { bigIntBytes, equalBytes, poseidon, ZERO_32 } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import { domainField, RingDomain } from "../../crypto/derivation/ring-domain.js";

/** `Poseidon(CRPL, owner_pk_hash, list_salt)`, salt zero for a subject with no tracking row. */
export function listPosition(ownerPkHash: Bytes32, listSalt: Bytes32): Bytes32 {
  return poseidon([domainField(RingDomain.listPosition), ownerPkHash, listSalt]) as Bytes32;
}

/** `Poseidon(CRPU, list_salt, write_counter)`. */
export function listLeafSalt(listSalt: Bytes32, writeCounter: bigint): Bytes32 {
  return poseidon([
    domainField(RingDomain.listLeafSalt),
    listSalt,
    bigIntBytes(writeCounter, 32) as Bytes32,
  ]) as Bytes32;
}

/** `Poseidon(CRPV, position, lists, leaf_salt)`. */
export function listLeaf(position: Bytes32, lists: bigint, leafSalt: Bytes32): Bytes32 {
  return poseidon([
    domainField(RingDomain.listLeaf),
    position,
    bigIntBytes(lists, 32) as Bytes32,
    leafSalt,
  ]) as Bytes32;
}

/** What a tree read serves for one position, a zero `leaf` is unwritten. */
export interface PublishedListLeaf {
  readonly leaf: Bytes32;
  readonly writeCounter: bigint;
}

/** Zero on an unwritten position. */
export function openListLeaf(
  input: Readonly<{
    ownerPkHash: Bytes32;
    listSalt: Bytes32;
    published: PublishedListLeaf;
    /** The list bytes to try, a leaf hides them. */
    candidates: readonly bigint[];
  }>,
): bigint | undefined {
  const { published, listSalt } = input;
  if (equalBytes(published.leaf, ZERO_32)) return 0n;
  const position = listPosition(input.ownerPkHash, listSalt);
  const leafSalt = listLeafSalt(listSalt, published.writeCounter);
  return input.candidates.find((lists) =>
    equalBytes(listLeaf(position, lists, leafSalt), published.leaf),
  );
}

export type PresentRead =
  | Readonly<{ kind: "granted" }>
  | Readonly<{ kind: "notListed" }>
  /** Allowlisted at salt zero and enrolled, refused until the curator writes the salted position. */
  | Readonly<{ kind: "saltedWriteMissing" }>;

/** `salted` is undefined for a subject with no tracking row. */
export function presentRead(input: Readonly<{ salted?: boolean; saltZero: boolean }>): PresentRead {
  const { salted, saltZero } = input;
  if (salted === true || (salted === undefined && saltZero))
    return Object.freeze({ kind: "granted" });
  return Object.freeze({ kind: salted === false && saltZero ? "saltedWriteMissing" : "notListed" });
}
