/**
 * The credential section of a transfer or deposit proof, Go `CredentialParams`, and the frame's
 * `CredentialRead` that names the same roots to the program.
 *
 * Each live owner opens its credential once. A present opening proves the credential leaf under a
 * state root of its tree, an absent one proves the address gap under the address root. The
 * statement binds one root per tree and one address root, so every opening comes from one
 * `resolveCredentials` snapshot. The program rereads each root from its tree account at the index
 * the frame names and pads the table with its first entry, a table built otherwise states another
 * statement.
 *
 * Read after `rpc/credential-resolver.ts` and `protocol/codec/credential-read.ts`.
 * Read before `proof/policy-proof.ts`.
 */
import type { Address } from "@solana/kit";

import { encodeBase58, equalBytes, hashBytes, treeAddress } from "@heliuslabs/zolana/internal";
import {
  decodeTreeHeadRoots,
  NULLIFIER_TREE_HEIGHT,
  SHIELDED_POOL_PROGRAM_ID,
  STATE_HEIGHT,
  type Bytes32,
  type RequestContext,
} from "@heliuslabs/zolana/interface";
import type { ShieldedPublicKey } from "@heliuslabs/zolana/keypair";
import type { TreeId } from "@heliuslabs/zolana/transaction";

import { packBytesBe } from "../crypto/derivation/hasher.js";
import {
  CredentialRead,
  CredentialRoots,
  type CredentialStateRoot,
} from "../protocol/codec/credential-read.js";
import { RingError } from "../protocol/error.js";
import {
  ADDRESS_TREE_ID,
  credentialOwnerHash,
  credentialPda,
  rootSequence,
  stateRootAt,
  type AddressRoot,
  type AuditCredential,
} from "../protocol/membership/credential.js";
import { taggedX25519 } from "../protocol/transaction/transact.js";
import { CredentialTrees } from "../operations/workflow/address-ceiling.js";
import {
  checkAbsenceFloor,
  resolveCredentials,
  type CredentialClient,
  type CredentialLookup,
} from "../rpc/credential-resolver.js";
import type {
  CredentialLeafProofInput,
  CredentialOpeningProofInput,
  CredentialProofInputs,
} from "../rpc/prover/ring.js";

/** A live owner by its member identity and the account its credential address derives from. */
export interface CredentialSubject {
  readonly member: Bytes32;
  readonly owner: Address;
}

/** The proof's credential inputs, the frame's read of the same roots and the accounts it names. */
export interface CredentialSection {
  readonly inputs: CredentialProofInputs;
  readonly read: CredentialRead;
  /** Tree 0, then each state tree in table order, the accounts the program reads the roots from. */
  readonly trees: CredentialTrees;
  /** The present credential of a live member, `undefined` for a proven absence. */
  credentialOf(member: Bytes32): AuditCredential | undefined;
}

/** The subject of a shielded owner key. */
export function credentialSubject(owner: ShieldedPublicKey): CredentialSubject {
  return Object.freeze({
    member: owner.ownerProofInputHash(),
    owner: encodeBase58(owner.confidentialViewTag()) as Address,
  });
}

/** Opens every subject once, `K` openings, rows and outputs index them. */
export async function readCredentials(
  input: Readonly<{
    client: CredentialClient;
    ringProgramId: Address;
    /** Distinct live members in opening order, at most `capacity`. */
    subjects: readonly CredentialSubject[];
    /** The key's `K`. */
    capacity: number;
    /** The highest floor of a source the frame reads a salted list through, zero otherwise. */
    absenceFloor: bigint;
    /** At the key's owner rows, a zero row indexes opening 0. */
    rows: readonly Bytes32[];
    /** At the key's output slots, `undefined` off a live ring output. */
    outputs: readonly (Bytes32 | undefined)[];
  }>,
  context?: RequestContext,
): Promise<CredentialSection> {
  const { client, subjects, capacity } = input;
  if (subjects.length > capacity)
    throw new RingError("RING_FIT_CREDENTIAL_CAPACITY", {
      details: { subjects: subjects.length, capacity },
    });
  // 1. One snapshot answers every subject. Unknown is no absence, the caller retries later.
  const lookups = await resolveCredentials(
    { client, ring: input.ringProgramId, owners: subjects.map((subject) => subject.owner) },
    context,
  );
  const present = new Map<string, Extract<CredentialLookup, { kind: "present" }>>();
  const absent: Extract<CredentialLookup, { kind: "absent" }>[] = [];
  lookups.forEach((lookup, index) => {
    const { member } = subjects[index] as CredentialSubject;
    if (lookup.kind === "unknown")
      throw new RingError("RING_CREDENTIAL_UNKNOWN", {
        details: { reason: lookup.reason, member: encodeBase58(member) },
      });
    if (lookup.kind === "present") present.set(key(member), lookup);
    else absent.push(lookup);
  });
  // 2. The present trees ascending. With none, tree 0's newest state root fills the table, the
  // program requires one state read and tree 0 is already among the accounts.
  const stateRoots = new Map<TreeId, Readonly<{ rootIndex: number; root: Bytes32 }>>();
  for (const lookup of present.values()) stateRoots.set(lookup.treeId, lookup.root);
  const head =
    stateRoots.size === 0 || absent.length === 0
      ? await sppTree(client, ADDRESS_TREE_ID, context)
      : undefined;
  if (stateRoots.size === 0) {
    const { stateRootIndex, stateRoot } = decodeTreeHeadRoots(head as Uint8Array);
    stateRoots.set(ADDRESS_TREE_ID, { rootIndex: stateRootIndex, root: stateRoot });
  }
  const table = [...stateRoots].sort(([left], [right]) => left - right);
  // 3. An absence names its own root, without one the newest tree 0 root serves. Either must
  // meet every salted source floor, the program reads the same checkpoint.
  const addressRoot = absent[0]?.root ?? newestAddressRoot(head as Uint8Array);
  checkAbsenceFloor({ root: addressRoot }, input.absenceFloor);
  const roots = CredentialRoots.selected({
    ownerHash: credentialOwnerHash(await credentialPda(input.ringProgramId)),
    addressRoot: addressRoot.root,
    stateRoots: table.map(([treeId, { root }]): CredentialStateRoot => ({ treeId, root })),
    capacity,
  });
  const read = CredentialRead.create(
    addressRoot.rootIndex,
    table.map(([, { rootIndex }]) => rootIndex),
  );
  read.checkCapacity(capacity);
  // 4. Opening `i` is subject `i`, zero openings pad the pool to `K`.
  const slotOf = (treeId: TreeId): number => table.findIndex(([id]) => id === treeId);
  const openings = subjects.map((subject, index): CredentialOpeningProofInput => {
    const lookup = lookups[index] as CredentialLookup;
    return lookup.kind === "present"
      ? presentOpening(lookup, slotOf(lookup.treeId))
      : absentOpening(subject.member, lookup as Extract<CredentialLookup, { kind: "absent" }>);
  });
  const position = new Map(subjects.map((subject, index) => [key(subject.member), index]));
  const entry = (member: Bytes32 | undefined): number =>
    member === undefined ? 0 : (position.get(key(member)) ?? 0);
  return Object.freeze({
    inputs: Object.freeze({
      credentialRoots: roots,
      credentialOpenings: Object.freeze([
        ...openings,
        ...Array.from({ length: capacity - openings.length }, () => PADDING_OPENING),
      ]),
      rowEntries: Object.freeze(input.rows.map((row) => entry(row))),
      outputEntries: Object.freeze(input.outputs.map(entry)),
    }),
    read,
    trees: CredentialTrees.of(
      table.map(([treeId]) => treeId),
      capacity,
    ),
    credentialOf: (member: Bytes32) => present.get(key(member))?.credential,
  });
}

/** A credential root a proof binds, the program rereads it from `tree` at `rootIndex`. */
export interface BoundCredentialRoot {
  readonly tree: Address;
  readonly kind: "address" | "state";
  readonly rootIndex: number;
  readonly root: Bytes32;
}

/** The address root, then each state root the frame names. */
export function boundCredentialRoots(section: CredentialSection): readonly BoundCredentialRoot[] {
  const { read, trees } = section;
  const roots = section.inputs.credentialRoots;
  return Object.freeze([
    Object.freeze({
      tree: treeAddress(ADDRESS_TREE_ID),
      kind: "address" as const,
      rootIndex: read.addressRootIndex,
      root: roots.addressRoot,
    }),
    ...read.stateRootIndexes.map((rootIndex, slot) =>
      Object.freeze({
        tree: treeAddress(trees.state[slot] as TreeId),
        kind: "state" as const,
        rootIndex,
        root: (roots.stateRoots[slot] as CredentialStateRoot).root,
      }),
    ),
  ]);
}

/** A root the history no longer holds at its index fails on chain, the caller proves again. */
export async function credentialRootsHeld(
  client: Pick<CredentialClient, "getAccount">,
  roots: readonly BoundCredentialRoot[],
  context?: RequestContext,
): Promise<boolean> {
  for (const bound of roots) {
    const account = await client.getAccount(bound.tree, context);
    if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID) return false;
    const held =
      bound.kind === "address"
        ? rootSequence(account.data, bound.rootIndex)?.root
        : stateRootAt(account.data, bound.rootIndex);
    if (held === undefined || !equalBytes(held, bound.root)) return false;
  }
  return true;
}

/** The leaf columns the circuit rehashes into the credential's UTXO hash. */
export function credentialLeaf(
  credential: AuditCredential,
  opening: Readonly<{
    blinding: Bytes32;
    treeSlot: number;
    leafIndex: bigint;
    path: readonly Bytes32[];
  }>,
): CredentialLeafProofInput {
  return Object.freeze({
    member: credential.member,
    nullifierPk: credential.nullifierPk,
    listTag: credential.listTag,
    aud: packBytesBe(credential.auditorPubkey) as unknown as readonly [Bytes32, Bytes32],
    eph: packBytesBe(taggedX25519(credential.ephU)) as unknown as readonly [Bytes32, Bytes32],
    ctHash: hashBytes(credential.ciphertext) as Bytes32,
    blinding: opening.blinding,
    treeSlot: opening.treeSlot,
    stateIndex: opening.leafIndex,
    statePath: opening.path,
  });
}

const ZERO = new Uint8Array(32) as Bytes32;
const ZERO_GAP = Object.freeze({
  lowValue: ZERO,
  lowNext: ZERO,
  lowIndex: 0n,
  lowPath: Object.freeze(Array.from({ length: NULLIFIER_TREE_HEIGHT }, () => ZERO)),
});
const ZERO_LEAF: CredentialLeafProofInput = Object.freeze({
  member: ZERO,
  nullifierPk: ZERO,
  listTag: ZERO,
  aud: Object.freeze([ZERO, ZERO] as const),
  eph: Object.freeze([ZERO, ZERO] as const),
  ctHash: ZERO,
  blinding: ZERO,
  treeSlot: 0,
  stateIndex: 0n,
  statePath: Object.freeze(Array.from({ length: STATE_HEIGHT }, () => ZERO)),
});
/** A zero member opens neither branch. */
const PADDING_OPENING: CredentialOpeningProofInput = Object.freeze({
  present: false,
  ...ZERO_LEAF,
  ...ZERO_GAP,
});

function presentOpening(
  lookup: Extract<CredentialLookup, { kind: "present" }>,
  treeSlot: number,
): CredentialOpeningProofInput {
  return Object.freeze({
    present: true,
    ...credentialLeaf(lookup.credential, { ...lookup, treeSlot }),
    ...ZERO_GAP,
  });
}

/** An absent entry keeps only its member, the circuit derives the address from it. */
function absentOpening(
  member: Bytes32,
  lookup: Extract<CredentialLookup, { kind: "absent" }>,
): CredentialOpeningProofInput {
  return Object.freeze({
    present: false,
    ...ZERO_LEAF,
    member,
    lowValue: lookup.low,
    lowNext: lookup.next,
    lowIndex: lookup.lowIndex,
    lowPath: lookup.path,
  });
}

function newestAddressRoot(data: Uint8Array): AddressRoot {
  const root = rootSequence(data, decodeTreeHeadRoots(data).nullifierRootIndex);
  if (root === undefined)
    throw new RingError("RING_CREDENTIAL_INVALID", {
      details: { reason: "addressRootNotAccepted" },
    });
  return root;
}

async function sppTree(
  client: CredentialClient,
  treeId: TreeId,
  context: RequestContext | undefined,
): Promise<Uint8Array> {
  const tree = treeAddress(treeId);
  const account = await client.getAccount(tree, context);
  if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID)
    throw new RingError("RING_CREDENTIAL_INVALID", { details: { reason: "invalidTree", tree } });
  return account.data;
}

function key(member: Bytes32): string {
  return encodeBase58(member);
}
