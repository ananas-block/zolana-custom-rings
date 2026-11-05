/**
 * A ring member's audit credential, found through Photon and authenticated against SPP tree
 * accounts, Rust `CredentialResolver`.
 *
 * Photon only names candidates. A credential is present once the UTXO hash rebuilt from the
 * plaintext `Enroll` output folds to a state root its tree account holds. Only `Enroll` signs
 * for the credential PDA, so inclusion proves the enrollment. A credential is absent once the
 * address gap folds to a root tree 0 holds and the address has no queue PDA, both read in one
 * account snapshot. Every other answer is unknown or a refusal, and unknown never selects the
 * zero key.
 *
 * Read after `protocol/membership/credential.ts` and `rpc/viewing-key-resolver.ts`.
 */
import type { Address, Signature } from "@solana/kit";

import {
  atSlot,
  type ChainReader,
  type IndexerReader,
  type ProofReader,
  type RpcAccount,
} from "@heliuslabs/zolana/client";
import {
  addressBytes,
  decodeTreeId,
  encodeBase58,
  equalBytes,
  nullifierPdaAddress,
  poseidon,
  solanaOwnerIdentity,
  SYSTEM_PROGRAM,
  treeAddress,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import {
  NULLIFIER_TREE_HEIGHT,
  SHIELDED_POOL_PROGRAM_ID,
  STATE_HEIGHT,
  type Bytes32,
  type RequestContext,
} from "@heliuslabs/zolana/interface";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { IndexedShieldedTransaction, TreeId } from "@heliuslabs/zolana/transaction";

import { ringIdField } from "../crypto/derivation/ring-stream.js";
import { listTagOf } from "../crypto/keys/list-salt.js";
import type { RingAddress } from "../crypto/keys/ring-address.js";
import { RingError } from "../protocol/error.js";
import {
  ADDRESS_TREE_ID,
  credentialAddress,
  credentialBlinding,
  credentialOutput,
  credentialPda,
  credentialSeed,
  credentialUtxoHash,
  rootSequence,
  stateRootAt,
  type AddressRoot,
  type AuditCredential,
} from "../protocol/membership/credential.js";
import { compareField } from "../protocol/membership/owner-debits.js";
import { outputTreeId } from "../protocol/membership/trees.js";
import { resolveViewingKey, type ViewingKeyClient } from "./viewing-key-resolver.js";

export type CredentialClient = Pick<ChainReader, "getAccount" | "getMultipleAccounts"> &
  Pick<IndexerReader, "getShieldedTransactionsByNullifiers"> &
  Pick<ProofReader, "getMerkleProofs" | "getNonInclusionProofs">;

export interface CredentialQuery {
  readonly client: CredentialClient;
  readonly ring: Address;
  readonly owner: Address;
  /** A credential holding another key is refused. */
  readonly nullifierPk?: Bytes32;
  /** A credential holding another tag is refused. */
  readonly listTag?: Bytes32;
}

export interface StateRoot {
  readonly rootIndex: number;
  readonly root: Bytes32;
}

/** A state inclusion proof under a root the tree account held when read. */
export interface PresentCredential {
  readonly kind: "present";
  readonly credential: AuditCredential;
  readonly address: Bytes32;
  readonly blinding: Bytes32;
  readonly treeId: TreeId;
  readonly leafIndex: bigint;
  readonly path: readonly Bytes32[];
  readonly root: StateRoot;
  readonly enrollment: Signature;
}

/** The address gap in tree 0 under a root the snapshot held while the address had no queue PDA. */
export interface AbsentCredential {
  readonly kind: "absent";
  readonly address: Bytes32;
  readonly low: Bytes32;
  readonly next: Bytes32;
  readonly lowIndex: bigint;
  readonly path: readonly Bytes32[];
  readonly root: AddressRoot;
}

export type UnknownCredential =
  /** The address holds a queue PDA and the indexer serves no enrollment for it. */
  | "queued"
  /** The indexer serves the enrollment without a state proof of its leaf. */
  | "stateProofMissing"
  /** The indexer serves neither an enrollment nor an address gap. */
  | "absenceProofMissing"
  /** The indexer ended an empty answer with a continuation. */
  | "partialPage"
  /** One answer folded leaves of one tree to different roots. */
  | "splitRoot";

export type CredentialLookup =
  | PresentCredential
  | AbsentCredential
  | Readonly<{ kind: "unknown"; reason: UnknownCredential }>;

export type RecipientKeys =
  /** The request names the key the credential holds. */
  | Readonly<{
      kind: "registered";
      nullifierPk: Bytes32;
      viewingPublicKey: X25519PublicKey;
      credential: PresentCredential;
    }>
  /** The request names the zero key and the owner holds no credential. */
  | Readonly<{
      kind: "zeroKey";
      nullifierPk: Bytes32;
      viewingPublicKey: X25519PublicKey;
      absence: AbsentCredential;
    }>
  /** The caller accepted a zero key note the enrolled owner cannot spend privately. */
  | Readonly<{
      kind: "zeroKeyToEnrolled";
      nullifierPk: Bytes32;
      viewingPublicKey: X25519PublicKey;
      credential: PresentCredential;
    }>;

interface CredentialIdentity {
  readonly ringId: Bytes32;
  readonly member: Bytes32;
  readonly pda: Address;
  readonly address: Bytes32;
}

/** A failed read throws, it never resolves to absent. */
export async function resolveCredential(
  query: CredentialQuery,
  context?: RequestContext,
): Promise<CredentialLookup> {
  const [lookup] = await resolveCredentials(
    { client: query.client, ring: query.ring, owners: [query.owner] },
    context,
  );
  if (lookup?.kind !== "present") return lookup as CredentialLookup;
  // A credential naming another key or tag is refused before a caller proves under it.
  if (
    query.nullifierPk !== undefined &&
    !equalBytes(query.nullifierPk, lookup.credential.nullifierPk)
  )
    throw new RingError("RING_CREDENTIAL_NULLIFIER_KEY_MISMATCH");
  if (query.listTag !== undefined && !equalBytes(query.listTag, lookup.credential.listTag))
    throw new RingError("RING_CREDENTIAL_LIST_TAG_MISMATCH");
  return lookup;
}

/**
 * One lookup per owner in one snapshot a single proof can bind. Every present credential of a
 * tree folds to one state root and every absence to one address root, the statement holds one
 * root per tree and one address root.
 */
export async function resolveCredentials(
  query: Readonly<{ client: CredentialClient; ring: Address; owners: readonly Address[] }>,
  context?: RequestContext,
): Promise<readonly CredentialLookup[]> {
  const { client } = query;
  const identities = await Promise.all(
    query.owners.map((owner) => credentialIdentity(query.ring, owner)),
  );
  if (identities.length === 0) return Object.freeze([]);
  // 1. The address is the nullifier of the enrollment's address slot, so the one transaction
  // publishing it as a nullifier is the enrollment. An empty answer proves nothing yet.
  const page = await client.getShieldedTransactionsByNullifiers(
    { nullifiers: identities.map((identity) => identity.address) },
    undefined,
    context,
  );
  const events = page.data.flatMap((group) => group.events);
  const lookups: CredentialLookup[] = [];
  const enrolled: EnrolledLeaf[] = [];
  const absentAt: number[] = [];
  identities.forEach((identity, at) => {
    const found = events.filter((event) =>
      event.nullifiers.some((nullifier) => equalBytes(nullifier, identity.address)),
    );
    const [enrollment] = found;
    if (found.length > 1) throw invalid("enrollmentCount", { count: found.length });
    if (enrollment !== undefined) enrolled.push(enrolledLeaf(identity, enrollment, at));
    else if (page.paginationToken !== null) lookups[at] = unknown("partialPage");
    else absentAt.push(at);
  });
  // 2. One proof call per tree keeps every credential of that tree under one root.
  const trees = new Map<TreeId, EnrolledLeaf[]>();
  for (const leaf of enrolled) trees.set(leaf.treeId, [...(trees.get(leaf.treeId) ?? []), leaf]);
  for (const [treeId, leaves] of trees)
    for (const [at, lookup] of await present(client, treeId, leaves, context)) lookups[at] = lookup;
  // 3. One gap call and one account snapshot for every absent owner.
  const gaps = await absent(
    client,
    absentAt.map((at) => identities[at] as CredentialIdentity),
    context,
  );
  absentAt.forEach((at, position) => {
    lookups[at] = gaps[position] as CredentialLookup;
  });
  return Object.freeze(lookups);
}

/** A salted read accepts only an address root at or above every source floor it reads through. */
export function checkAbsenceFloor(absence: Pick<AbsentCredential, "root">, floor: bigint): void {
  if (absence.root.sequence < floor)
    throw new RingError("RING_ABSENCE_ROOT_BELOW_FLOOR", {
      details: { sequence: absence.root.sequence, floor },
    });
}

/** Rust `RecipientKeyResolver`, an unknown lookup throws rather than select the zero key. */
export async function resolveRecipientKeys(
  input: Readonly<{
    client: CredentialClient & ViewingKeyClient;
    to: RingAddress;
    /** Accept a zero key note to an enrolled owner, only a public spend opens it. */
    zeroKeyToEnrolled?: true;
  }>,
  context?: RequestContext,
): Promise<RecipientKeys> {
  const { client, to } = input;
  const { recipient, ringProgramId: ring } = to;
  const owner = encodeBase58(recipient.signingPublicKey.confidentialViewTag());
  // 1. A request naming a key binds the lookup to that key and its list tag. The zero key
  // request binds nothing, the lookup only decides whether the owner holds a credential.
  if (!equalBytes(recipient.nullifierPublicKey, ZERO_NULLIFIER_PK)) {
    const lookup = await resolveCredential(
      {
        client,
        ring,
        owner,
        nullifierPk: recipient.nullifierPublicKey,
        listTag: listTagOf(to.listSalt),
      },
      context,
    );
    if (lookup.kind === "absent") throw new RingError("RING_RECIPIENT_NOT_ENROLLED");
    if (lookup.kind === "unknown") throw unknownError(lookup.reason);
    // 2. The record key must belong to the credential key. Without a record the request key
    // serves, since step 1 matched the request key to the credential.
    const record = await resolveViewingKey(
      { client, owner, nullifierPublicKey: lookup.credential.nullifierPk },
      context,
    );
    return Object.freeze({
      kind: "registered",
      nullifierPk: lookup.credential.nullifierPk,
      viewingPublicKey: record?.viewingPublicKey ?? recipient.viewingPublicKey,
      credential: lookup,
    });
  }
  // 3. A zero key note to an enrolled owner leaves the owner's private spend path, so it needs
  // the caller's opt in and a record bound to the credential key.
  const lookup = await resolveCredential({ client, ring, owner }, context);
  if (lookup.kind === "unknown") throw unknownError(lookup.reason);
  if (lookup.kind === "present") {
    if (input.zeroKeyToEnrolled !== true) throw new RingError("RING_RECIPIENT_ENROLLED");
    const record = await resolveViewingKey(
      { client, owner, nullifierPublicKey: lookup.credential.nullifierPk },
      context,
    );
    if (record === undefined) throw new RingError("RING_VIEWING_KEY_UNVERIFIED");
    return Object.freeze({
      kind: "zeroKeyToEnrolled",
      nullifierPk: ZERO_NULLIFIER_PK as Bytes32,
      viewingPublicKey: record.viewingPublicKey,
      credential: lookup,
    });
  }
  const record = await resolveViewingKey({ client, owner }, context);
  return Object.freeze({
    kind: "zeroKey",
    nullifierPk: ZERO_NULLIFIER_PK as Bytes32,
    viewingPublicKey: record?.viewingPublicKey ?? recipient.viewingPublicKey,
    absence: lookup,
  });
}

async function credentialIdentity(ring: Address, owner: Address): Promise<CredentialIdentity> {
  const ringId = ringIdField(ring);
  const member = solanaOwnerIdentity(addressBytes(owner)) as Bytes32;
  const pda = await credentialPda(ring);
  const address = credentialAddress(pda, credentialSeed(ringId, member));
  return Object.freeze({ ringId, member, pda, address });
}

/** An enrollment's rebuilt leaf before any proof read, `at` its owner's position. */
interface EnrolledLeaf {
  readonly at: number;
  readonly identity: CredentialIdentity;
  readonly credential: AuditCredential;
  readonly treeId: TreeId;
  readonly blinding: Bytes32;
  readonly leaf: Bytes32;
  readonly leafIndex: bigint;
  readonly enrollment: IndexedShieldedTransaction;
}

/** The plaintext is untrusted until its rebuilt leaf folds to an on chain root. */
function enrolledLeaf(
  identity: CredentialIdentity,
  enrollment: IndexedShieldedTransaction,
  at: number,
): EnrolledLeaf {
  // 1. A credential naming another ring or owner is refused before any proof read.
  const { credential, output } = enrolledCredential(identity, enrollment);
  if (
    !equalBytes(credential.ringId, identity.ringId) ||
    !equalBytes(credential.member, identity.member)
  )
    throw new RingError("RING_CREDENTIAL_MISMATCH");
  // 2. `Enroll` writes the credential as its only output, so the blinding derives from the
  // address alone, and the leaf commits to the credential PDA and the tree it landed in.
  const treeId = outputTreeId(output.outputContext);
  const leaf = credentialUtxoHash({
    pda: identity.pda,
    address: identity.address,
    credential,
    treeId,
  });
  if (!equalBytes(leaf, output.outputContext.hash)) throw invalid("malformedEnrollment");
  return Object.freeze({
    at,
    identity,
    credential,
    treeId,
    blinding: credentialBlinding(identity.address),
    leaf,
    leafIndex: output.outputContext.leafIndex,
    enrollment,
  });
}

async function present(
  client: CredentialClient,
  treeId: TreeId,
  leaves: readonly EnrolledLeaf[],
  context: RequestContext | undefined,
): Promise<ReadonlyMap<number, CredentialLookup>> {
  // 1. Requiring the newest enrollment slot keeps a lagging indexer from answering without a leaf.
  const tree = treeAddress(treeId);
  const slot = leaves.reduce(
    (max, leaf) => (leaf.enrollment.slot > max ? leaf.enrollment.slot : max),
    0n,
  );
  const { proofs } = await client.getMerkleProofs(
    tree,
    leaves.map((leaf) => leaf.leaf),
    atSlot(slot),
    context,
  );
  if (proofs.length > leaves.length) throw invalid("malformedProof");
  const answered = leaves.map((leaf) => proofs.find((proof) => equalBytes(proof.leaf, leaf.leaf)));
  const [first] = proofs;
  // 2. Every proof of the tree folds to one root, the statement holds one root per tree.
  const split =
    first !== undefined &&
    proofs.some(
      (proof) => proof.rootIndex !== first.rootIndex || !equalBytes(proof.root, first.root),
    );
  const lookups = new Map<number, CredentialLookup>();
  if (first === undefined || split) {
    for (const leaf of leaves)
      lookups.set(leaf.at, unknown(split ? "splitRoot" : "stateProofMissing"));
    return lookups;
  }
  // 3. The root must be in the history SPP accepts roots from. A paused or full tree keeps its
  // history, so its credentials stay readable.
  const data = sppTree(tree, await client.getAccount(tree, context));
  if (decodeTreeId(data) !== treeId) throw invalid("invalidTree", { tree });
  const held = stateRootAt(data, first.rootIndex);
  if (held === undefined || !equalBytes(held, first.root)) throw invalid("stateRootNotAccepted");
  leaves.forEach((leaf, index) => {
    const proof = answered[index];
    if (proof === undefined) {
      lookups.set(leaf.at, unknown("stateProofMissing"));
      return;
    }
    if (proof.merkleContext.tree !== tree || proof.leafIndex !== leaf.leafIndex)
      throw invalid("malformedProof");
    const path = fixedPath(proof.path, proof.leafIndex, STATE_HEIGHT);
    if (!equalBytes(foldPath(leaf.leaf, proof.leafIndex, path), proof.root))
      throw invalid("invalidStateProof");
    lookups.set(
      leaf.at,
      Object.freeze({
        kind: "present",
        credential: leaf.credential,
        address: leaf.identity.address,
        blinding: leaf.blinding,
        treeId,
        leafIndex: proof.leafIndex,
        path,
        root: Object.freeze({ rootIndex: proof.rootIndex, root: proof.root }),
        enrollment: leaf.enrollment.txSignature,
      }),
    );
  });
  return lookups;
}

async function absent(
  client: CredentialClient,
  identities: readonly CredentialIdentity[],
  context: RequestContext | undefined,
): Promise<readonly CredentialLookup[]> {
  if (identities.length === 0) return [];
  const tree = treeAddress(ADDRESS_TREE_ID);
  const addresses = identities.map((identity) => identity.address);
  const queues = await Promise.all(addresses.map((address) => nullifierPdaAddress(tree, address)));
  // 1. The gaps are checked before the snapshot, the snapshot then decides the roots they may use.
  const { proofs } = await client.getNonInclusionProofs(tree, addresses, undefined, context);
  if (proofs.length > addresses.length) throw invalid("malformedProof");
  const gaps = addresses.map((address) => proofs.find((gap) => equalBytes(gap.leaf, address)));
  const [first] = proofs;
  if (
    first !== undefined &&
    proofs.some((gap) => gap.rootIndex !== first.rootIndex || !equalBytes(gap.root, first.root))
  )
    return identities.map(() => unknown("splitRoot"));
  const paths = gaps.map((gap, index) => {
    if (gap === undefined) return undefined;
    const address = addresses[index] as Bytes32;
    if (gap.merkleContext.tree !== tree) throw invalid("malformedProof");
    const path = fixedPath(gap.path, gap.lowElementIndex, NULLIFIER_TREE_HEIGHT);
    const brackets =
      compareField(gap.lowElement, address) < 0 && compareField(address, gap.highElement) < 0;
    const lowLeaf = poseidon([gap.lowElement, gap.highElement]) as Bytes32;
    if (!brackets || !equalBytes(foldPath(lowLeaf, gap.lowElementIndex, path), gap.root))
      throw invalid("invalidAbsenceProof");
    return path;
  });
  // 2. An address enters the queue before any root holds it. Its queue PDA closes only after
  // every root in the history holds the address, so an empty PDA and a gap under a root of
  // the same snapshot cover both the queue and the tree.
  const answers = await client.getMultipleAccounts([tree, ...queues], context);
  // A short answer would read as an empty queue PDA.
  if (answers.length !== 1 + queues.length)
    throw new RingError("RING_RPC", { details: { reason: "accountCount", count: answers.length } });
  const [treeAccount, ...queueAccounts] = answers;
  const data = sppTree(tree, treeAccount);
  if (decodeTreeId(data) !== ADDRESS_TREE_ID) throw invalid("invalidTree", { tree });
  const root = first === undefined ? undefined : rootSequence(data, first.rootIndex);
  if (first !== undefined && (root === undefined || !equalBytes(root.root, first.root)))
    throw invalid("addressRootNotAccepted");
  return identities.map((identity, index): CredentialLookup => {
    const queue = queueAccounts[index];
    if (queue !== undefined && (queue.owner !== SYSTEM_PROGRAM || queue.data.length > 0))
      return unknown("queued");
    const gap = gaps[index];
    const path = paths[index];
    if (gap === undefined || path === undefined || root === undefined)
      return unknown("absenceProofMissing");
    return Object.freeze({
      kind: "absent",
      address: identity.address,
      low: gap.lowElement,
      next: gap.highElement,
      lowIndex: gap.lowElementIndex,
      path,
      root,
    });
  });
}

/** The one plaintext output carrying `address || Borsh(credential)` and the context it landed in. */
function enrolledCredential(
  identity: CredentialIdentity,
  enrollment: IndexedShieldedTransaction,
): Readonly<{
  credential: AuditCredential;
  output: IndexedShieldedTransaction["outputSlots"][number];
}> {
  const [first] = enrollment.nullifiers;
  if (first === undefined || !equalBytes(first, identity.address))
    throw invalid("malformedEnrollment");
  const credentials = enrollment.outputSlots.flatMap((output) => {
    const credential = credentialOutput(output.payload, identity.address);
    return credential === undefined ? [] : [{ credential, output }];
  });
  const [only] = credentials;
  if (credentials.length !== 1 || only === undefined) throw invalid("malformedEnrollment");
  return only;
}

function sppTree(tree: Address, account: RpcAccount | undefined): Uint8Array {
  if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID)
    throw invalid("invalidTree", { tree });
  return account.data;
}

/** A leaf index past the tree width has no path, its high bits would be ignored by the fold. */
function fixedPath(
  path: readonly Bytes32[],
  leafIndex: bigint,
  height: number,
): readonly Bytes32[] {
  if (path.length !== height || leafIndex < 0n || leafIndex >> BigInt(height) !== 0n)
    throw invalid("malformedProof");
  return Object.freeze([...path]);
}

/** Bit `level` of the index places the node left on zero, as the circuit's Merkle gadget does. */
function foldPath(leaf: Bytes32, leafIndex: bigint, path: readonly Bytes32[]): Bytes32 {
  return path.reduce<Bytes32>(
    (node, sibling, level) =>
      poseidon(
        ((leafIndex >> BigInt(level)) & 1n) === 0n ? [node, sibling] : [sibling, node],
      ) as Bytes32,
    leaf,
  );
}

function unknown(reason: UnknownCredential): CredentialLookup {
  return Object.freeze({ kind: "unknown", reason });
}

function unknownError(reason: UnknownCredential): RingError {
  return new RingError("RING_CREDENTIAL_UNKNOWN", { details: { reason } });
}

function invalid(reason: string, details: Record<string, unknown> = {}): RingError {
  return new RingError("RING_CREDENTIAL_INVALID", { details: { reason, ...details } });
}
