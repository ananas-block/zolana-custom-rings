/**
 * Whether an owner holds an audit credential in a ring, decided at one chain snapshot,
 * Rust `CredentialResolver`.
 *
 * Photon names the `Enroll` transaction by the credential address, the nullifier of its
 * address slot. Every value it serves is recomputed and checked against a root the snapshot
 * holds. A settled credential can wait in the tree 0 queue while every root still excludes
 * its address, so absence needs a non inclusion proof under the newest tree 0 root and no
 * queue PDA in the same snapshot. Every other outcome is unknown or a refusal, and unknown
 * never stands for absence or for the zero key.
 *
 * Read after `protocol/membership/credential.ts`.
 */
import type { Address } from "@solana/kit";

import type {
  ChainReader,
  IndexerReader,
  NonInclusionProof,
  ProofReader,
  RpcAccount,
} from "@heliuslabs/zolana/client";
import {
  decodeTreeId,
  equalBytes,
  isZero,
  nullifierPdaAddress,
  poseidon,
  treeAddress,
} from "@heliuslabs/zolana/internal";
import {
  NULLIFIER_TREE_HEIGHT,
  SHIELDED_POOL_PROGRAM_ID,
  STATE_HEIGHT,
  UTXO_ROOT_HISTORY_LEN_OFFSET,
  UTXO_ROOT_HISTORY_OFFSET,
  decodeTreeHeadRoots,
  type Bytes32,
  type RequestContext,
} from "@heliuslabs/zolana/interface";
import type { TreeId } from "@heliuslabs/zolana/transaction";

import { ringIdField } from "../crypto/derivation/ring-stream.js";
import { RingError } from "../protocol/error.js";
import {
  ADDRESS_TREE_ID,
  credentialAddress,
  credentialBlinding,
  credentialPda,
  credentialSeed,
  credentialUtxoHash,
  decodeCredentialOutput,
  rootSequence,
  type AddressCheckpoint,
  type AuditCredential,
} from "../protocol/membership/credential.js";
import { compareField } from "../protocol/membership/owner-debits.js";

export type CredentialClient = Pick<ChainReader, "getMultipleAccounts"> &
  Pick<IndexerReader, "getShieldedTransactionsByNullifiers"> &
  Pick<ProofReader, "getMerkleProofs" | "getNonInclusionProofs">;

export interface CredentialLookup {
  readonly client: CredentialClient;
  readonly ring: Address;
  /** `solanaOwnerIdentity` of the owner. */
  readonly member: Bytes32;
  /** The highest `absence_floor` over every source read through a salted list, zero with none. */
  readonly absenceFloor: bigint;
  /** The key a payment request names, a credential holding another one refuses. */
  readonly nullifierPk?: Bytes32;
  readonly listTag?: Bytes32;
}

/** The credential's leaf under a root its tree holds. */
export interface CredentialLeaf {
  readonly credential: AuditCredential;
  readonly tree: Address;
  readonly treeId: TreeId;
  readonly utxoHash: Bytes32;
  readonly blinding: Bytes32;
  readonly leafIndex: bigint;
  /** Siblings from the leaf level up. */
  readonly path: readonly Bytes32[];
  readonly root: Bytes32;
  readonly rootIndex: number;
}

/** The tree 0 leaf bracketing the address, under the checkpoint's root. */
export interface AddressGap {
  readonly low: Bytes32;
  readonly next: Bytes32;
  readonly lowIndex: bigint;
  /** Siblings from the leaf level up. */
  readonly path: readonly Bytes32[];
  readonly checkpoint: AddressCheckpoint;
}

/** Neither reason rules out a credential. */
export type UnknownCredential = "queued" | "rootNotHeld";

export type ResolvedCredential =
  | Readonly<{ kind: "present"; address: Bytes32; leaf: CredentialLeaf }>
  | Readonly<{ kind: "absent"; address: Bytes32; gap: AddressGap }>
  | Readonly<{ kind: "unknown"; address: Bytes32; reason: UnknownCredential }>;

interface Creation {
  readonly credential: AuditCredential;
  readonly tree: Address;
  readonly outputHash: Bytes32;
  readonly leafIndex: bigint;
}

/** A failed read throws, it never resolves to absent. */
export async function resolveCredential(
  input: CredentialLookup,
  context?: RequestContext,
): Promise<ResolvedCredential> {
  const { client, ring, member } = input;
  // 1. The address binds ring and member alone, one owner has one credential address per ring.
  const pda = await credentialPda(ring);
  const ringId = ringIdField(ring);
  const address = credentialAddress(pda, credentialSeed(ringId, member));
  const addressTree = treeAddress(ADDRESS_TREE_ID);
  const queue = await nullifierPdaAddress(addressTree, address);
  // 2. Photon names the creating transaction and its leaf. Step 4 checks both before use.
  const created = await creation({ client, address, ringId, member }, context);
  const merkle =
    created === undefined
      ? undefined
      : await client.getMerkleProofs(created.tree, [created.outputHash], undefined, context);
  // 3. One account read is one slot, the queue PDA and both trees come from the same state.
  const stateTree = created?.tree ?? addressTree;
  const reads = stateTree === addressTree ? [addressTree, queue] : [addressTree, queue, stateTree];
  const [tree0, reserved, ownTree] = await client.getMultipleAccounts(reads, context);
  const addressTreeData = sppTree(tree0, addressTree);
  if (created !== undefined && merkle !== undefined) {
    // 4. A credential leaf under a held root shows the credential exists, queued or applied.
    const stateTreeData = stateTree === addressTree ? addressTreeData : sppTree(ownTree, stateTree);
    const leaf = presentLeaf({ pda, address, created, stateTreeData, proofs: merkle.proofs });
    if (leaf === undefined)
      return Object.freeze({ kind: "unknown", address, reason: "rootNotHeld" });
    expectKeys(input, leaf.credential);
    return Object.freeze({ kind: "present", address, leaf });
  }
  // 5. A queue PDA closes only after its batch applies, so a live one marks an enrollment
  // Photon has not served. The credential exists, and the zero key would misread it.
  if (reserved !== undefined && reserved.owner === SHIELDED_POOL_PROGRAM_ID)
    return Object.freeze({ kind: "unknown", address, reason: "queued" });
  // 6. With no reservation, the newest root decides. An older root misses an address
  // applied after it whose queue PDA has since closed.
  const { proofs } = await client.getNonInclusionProofs(addressTree, [address], undefined, context);
  const head = decodeTreeHeadRoots(addressTreeData);
  const [proof] = proofs;
  if (proofs.length !== 1 || proof === undefined) throw invalid("gapCount");
  if (proof.rootIndex !== head.nullifierRootIndex || !equalBytes(proof.root, head.nullifierRoot))
    return Object.freeze({ kind: "unknown", address, reason: "rootNotHeld" });
  const gap = addressGap({
    address,
    addressTree,
    proof,
    checkpoint: rootSequence(addressTreeData, proof.rootIndex),
  });
  // 7. The program refuses an absence root below the floor any private write raised.
  if (gap.checkpoint.sequence < input.absenceFloor)
    throw new RingError("RING_ABSENCE_ROOT_BELOW_FLOOR", {
      details: { sequence: gap.checkpoint.sequence, floor: input.absenceFloor },
    });
  return Object.freeze({ kind: "absent", address, gap });
}

/** Only `Enroll` spends the address slot, and its one output is the credential. */
async function creation(
  input: Readonly<{ client: CredentialClient; address: Bytes32; ringId: Bytes32; member: Bytes32 }>,
  context: RequestContext | undefined,
): Promise<Creation | undefined> {
  const page = await input.client.getShieldedTransactionsByNullifiers(
    { nullifiers: [input.address] },
    undefined,
    context,
  );
  const spends = page.data
    .flatMap((item) => item.events)
    .filter((event) => event.nullifiers.some((nullifier) => equalBytes(nullifier, input.address)));
  if (spends.length === 0) return undefined;
  const [spend] = spends;
  if (spends.length !== 1 || spend === undefined) throw invalid("creationCount");
  const [firstNullifier] = spend.nullifiers;
  const [output] = spend.outputSlots;
  if (
    firstNullifier === undefined ||
    !equalBytes(firstNullifier, input.address) ||
    output === undefined
  )
    throw invalid("creation");
  const { address, credential } = decodeCredentialOutput(output.payload);
  if (
    !equalBytes(address, input.address) ||
    !equalBytes(credential.ringId, input.ringId) ||
    !equalBytes(credential.member, input.member)
  )
    throw invalid("creationOutput");
  return Object.freeze({
    credential,
    tree: output.outputContext.tree,
    outputHash: output.outputContext.hash,
    leafIndex: output.outputContext.leafIndex,
  });
}

/** `undefined` when the proof's root is not in the snapshot's history. */
function presentLeaf(
  input: Readonly<{
    pda: Address;
    address: Bytes32;
    created: Creation;
    stateTreeData: Uint8Array;
    proofs: readonly Readonly<{
      leaf: Bytes32;
      merkleContext: Readonly<{ tree: Address }>;
      path: readonly Bytes32[];
      leafIndex: bigint;
      root: Bytes32;
      rootIndex: number;
    }>[];
  }>,
): CredentialLeaf | undefined {
  const { pda, address, created, stateTreeData, proofs } = input;
  // 1. The tree id comes from the account, Photon's copy is not authenticated.
  const treeId = decodeTreeId(stateTreeData);
  const utxoHash = credentialUtxoHash({ pda, address, credential: created.credential, treeId });
  // 2. A substituted credential changes the hash the transaction published.
  if (!equalBytes(utxoHash, created.outputHash)) throw invalid("outputHash");
  const [proof] = proofs;
  if (
    proofs.length !== 1 ||
    proof === undefined ||
    !equalBytes(proof.leaf, utxoHash) ||
    proof.merkleContext.tree !== created.tree ||
    proof.leafIndex !== created.leafIndex ||
    !equalBytes(merkleRoot(utxoHash, proof.leafIndex, proof.path, STATE_HEIGHT), proof.root)
  )
    throw invalid("statePath");
  // 3. A paused or full tree keeps its history, the read never checks the tree state.
  const held = heldStateRoot(stateTreeData, proof.rootIndex);
  if (held === undefined || !equalBytes(held, proof.root)) return undefined;
  return Object.freeze({
    credential: created.credential,
    tree: created.tree,
    treeId,
    utxoHash,
    blinding: credentialBlinding(address),
    leafIndex: proof.leafIndex,
    path: Object.freeze([...proof.path]),
    root: proof.root,
    rootIndex: proof.rootIndex,
  });
}

function addressGap(
  input: Readonly<{
    address: Bytes32;
    addressTree: Address;
    proof: NonInclusionProof;
    checkpoint: AddressCheckpoint;
  }>,
): AddressGap {
  const { address, addressTree, proof, checkpoint } = input;
  const low = proof.lowElement;
  const next = proof.highElement;
  if (
    !equalBytes(proof.leaf, address) ||
    proof.merkleContext.tree !== addressTree ||
    compareField(low, address) >= 0 ||
    compareField(address, next) >= 0 ||
    !equalBytes(
      merkleRoot(
        poseidon([low, next]) as Bytes32,
        proof.lowElementIndex,
        proof.path,
        NULLIFIER_TREE_HEIGHT,
      ),
      checkpoint.root,
    )
  )
    throw invalid("addressGap");
  return Object.freeze({
    low,
    next,
    lowIndex: proof.lowElementIndex,
    path: Object.freeze([...proof.path]),
    checkpoint,
  });
}

function expectKeys(input: CredentialLookup, credential: AuditCredential): void {
  if (input.nullifierPk !== undefined && !equalBytes(credential.nullifierPk, input.nullifierPk))
    throw new RingError("RING_ADDRESS_MISMATCH", { details: { field: "nullifierPk" } });
  if (input.listTag !== undefined && !equalBytes(credential.listTag, input.listTag))
    throw new RingError("RING_ADDRESS_MISMATCH", { details: { field: "listTag" } });
}

function sppTree(account: RpcAccount | undefined, tree: Address): Uint8Array {
  if (account === undefined || account.owner !== SHIELDED_POOL_PROGRAM_ID) throw invalid("tree");
  if (treeAddress(decodeTreeId(account.data)) !== tree) throw invalid("tree");
  return account.data;
}

/** A slot past the written length or still zero holds no root the program accepts. */
function heldStateRoot(tree: Uint8Array, rootIndex: number): Bytes32 | undefined {
  decodeTreeHeadRoots(tree);
  const written = new DataView(tree.buffer, tree.byteOffset, tree.byteLength).getUint16(
    UTXO_ROOT_HISTORY_LEN_OFFSET,
    true,
  );
  if (!Number.isInteger(rootIndex) || rootIndex < 0 || rootIndex >= written) return undefined;
  const start = UTXO_ROOT_HISTORY_OFFSET + rootIndex * 32;
  const root = tree.slice(start, start + 32) as Bytes32;
  return isZero(root) ? undefined : root;
}

/** Bit `level` of `index` set puts the node on the right, as `ProveParentHash` does. */
function merkleRoot(
  leaf: Bytes32,
  index: bigint,
  path: readonly Bytes32[],
  height: number,
): Bytes32 {
  if (path.length !== height || index < 0n || index >= 1n << BigInt(height))
    throw invalid("pathShape");
  return path.reduce<Bytes32>(
    (node, sibling, level) =>
      poseidon(
        ((index >> BigInt(level)) & 1n) === 1n ? [sibling, node] : [node, sibling],
      ) as Bytes32,
    leaf,
  );
}

function invalid(reason: string): RingError {
  return new RingError("RING_CREDENTIAL_INVALID", { details: { reason } });
}
