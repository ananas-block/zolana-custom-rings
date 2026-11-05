import { address, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { NonInclusionProof } from "@heliuslabs/zolana/client";
import type { IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";
import {
  bigIntBytes,
  concatBytes,
  hashChain4,
  nullifierPdaAddress,
  poseidon,
  treeAddress,
} from "@heliuslabs/zolana/internal";
import {
  NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET,
  NULLIFIER_ROOT_HISTORY_OFFSET,
  NULLIFIER_TREE_HEIGHT,
  SHIELDED_POOL_PROGRAM_ID,
  STATE_HEIGHT,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  UTXO_ROOT_HISTORY_CAPACITY,
  UTXO_ROOT_HISTORY_CAPACITY_OFFSET,
  UTXO_ROOT_HISTORY_CURSOR_OFFSET,
  UTXO_ROOT_HISTORY_LEN_OFFSET,
  UTXO_ROOT_HISTORY_OFFSET,
  UTXO_SUBTREES_LEN_OFFSET,
  type Bytes32,
  type Bytes33,
  type Bytes64,
} from "@heliuslabs/zolana/interface";

import { RingDomain } from "../../src/crypto/derivation/ring-domain.js";
import { ringIdField } from "../../src/crypto/derivation/ring-stream.js";
import {
  ADDRESS_TREE_ID,
  EMPTY_CREDENTIAL_READ,
  NULLIFIER_SEQUENCE_OFFSET,
  credentialAddress,
  credentialBlinding,
  credentialElements,
  credentialPda,
  credentialSeed,
  credentialStateHash,
  credentialUtxoHash,
  encodeAuditCredential,
  encodeCredentialRead,
  rootSequence,
  type AuditCredential,
} from "../../src/protocol/membership/credential.js";
import { FIELD_MAX } from "../../src/protocol/membership/member-opening.js";
import { registerKeyStatementHash } from "../../src/protocol/proof/statement.js";
import {
  resolveCredential,
  type CredentialClient,
  type ResolvedCredential,
} from "../../src/rpc/credential-resolver.js";
import { stateTreeAt } from "../helpers/state-tree.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const SYSTEM = address("11111111111111111111111111111111");
const field = (value: number) => bigIntBytes(BigInt(value)) as Bytes32;
const ADDRESS_TREE = treeAddress(ADDRESS_TREE_ID);
const STATE_TREE_ID = 3;
const STATE_TREE = treeAddress(STATE_TREE_ID);
const LEAF_INDEX = 5n;
const SEQUENCE = 40n;
const MEMBER = field(7);

// Hashing waits for the Poseidon setup hook.
let credential: AuditCredential;
beforeAll(() => {
  credential = Object.freeze({
    ringId: ringIdField(RING),
    member: MEMBER,
    nullifierPk: field(11),
    listTag: field(12),
    auditorPubkey: concatBytes(Uint8Array.of(4), field(14)) as Bytes33,
    ephU: field(13),
    ciphertext: new Uint8Array(64).fill(0x21) as Bytes64,
  });
});

interface Tree {
  readonly treeId: number;
  /** State roots by history slot, the last slot is the newest. */
  readonly stateRoots: readonly Bytes32[];
  /** Nullifier roots by history slot, `cursor` names the slot past the newest. */
  readonly nullifierRoots: ReadonlyMap<number, Bytes32>;
  readonly cursor: bigint;
  readonly sequence: bigint;
  readonly paused?: boolean;
}

function treeAccount(tree: Tree): Uint8Array {
  const data = new Uint8Array(TREE_ACCOUNT_SIZE);
  const view = new DataView(data.buffer);
  data[0] = StateDiscriminator.treeAccount;
  data[1] = tree.paused === true ? 2 : 1;
  view.setUint16(2, tree.treeId, true);
  view.setUint16(UTXO_ROOT_HISTORY_CURSOR_OFFSET, tree.stateRoots.length - 1, true);
  view.setUint16(UTXO_ROOT_HISTORY_LEN_OFFSET, tree.stateRoots.length, true);
  view.setUint16(UTXO_ROOT_HISTORY_CAPACITY_OFFSET, UTXO_ROOT_HISTORY_CAPACITY, true);
  data[UTXO_SUBTREES_LEN_OFFSET] = STATE_HEIGHT;
  tree.stateRoots.forEach((root, slot) => data.set(root, UTXO_ROOT_HISTORY_OFFSET + 32 * slot));
  view.setBigUint64(NULLIFIER_SEQUENCE_OFFSET, tree.sequence, true);
  view.setBigUint64(NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET, tree.cursor, true);
  for (const [slot, root] of tree.nullifierRoots)
    data.set(root, NULLIFIER_ROOT_HISTORY_OFFSET + 32 * slot);
  return data;
}

function nullifierRoot(leaf: Bytes32, index: bigint, path: readonly Bytes32[]): Bytes32 {
  let node = leaf;
  path.forEach((sibling, level) => {
    node = poseidon(
      ((index >> BigInt(level)) & 1n) === 1n ? [sibling, node] : [node, sibling],
    ) as Bytes32;
  });
  return node;
}

interface World {
  /** `true` serves the creation as `Enroll` wrote it, a function serves what it returns. */
  readonly creation?: true | ((created: IndexedShieldedTransaction) => IndexedShieldedTransaction);
  readonly merkleRootIndex?: number;
  readonly queue?: Address;
  readonly gap?: Partial<NonInclusionProof>;
  readonly gapRootIndex?: number;
  readonly stateTreeId?: number;
  readonly paused?: boolean;
}

/** One ring member, its credential leaf and its address gap, served as `world` names. */
async function chain(world: World) {
  const pda = await credentialPda(RING);
  const credentialAt = credentialAddress(pda, credentialSeed(ringIdField(RING), MEMBER));
  const queue = await nullifierPdaAddress(ADDRESS_TREE, credentialAt);
  const treeId = world.stateTreeId ?? STATE_TREE_ID;
  const tree = treeAddress(treeId);
  const utxoHash = credentialUtxoHash({ pda, address: credentialAt, credential, treeId });
  const state = stateTreeAt(new Map([[Number(LEAF_INDEX), utxoHash]]));
  const low = field(1);
  const next = FIELD_MAX;
  const gapPath = Array.from({ length: NULLIFIER_TREE_HEIGHT }, (_, level) => field(100 + level));
  const gapRoot = nullifierRoot(poseidon([low, next]) as Bytes32, 9n, gapPath);
  // Slot 3 holds the newest nullifier root, slot 2 the root one apply before it.
  const nullifierRoots = new Map([
    [2, field(77)],
    [3, gapRoot],
  ]);
  const stateRoots = [field(55), state.root];
  const accounts = new Map<Address, { owner: Address; data: Uint8Array; lamports: bigint }>();
  const addressTreeState: Tree = {
    treeId: ADDRESS_TREE_ID,
    stateRoots: treeId === ADDRESS_TREE_ID ? stateRoots : [field(56)],
    nullifierRoots,
    cursor: 4n,
    sequence: SEQUENCE,
    paused: world.paused ?? false,
  };
  accounts.set(ADDRESS_TREE, {
    owner: SHIELDED_POOL_PROGRAM_ID,
    data: treeAccount(addressTreeState),
    lamports: 1n,
  });
  if (treeId !== ADDRESS_TREE_ID)
    accounts.set(tree, {
      owner: SHIELDED_POOL_PROGRAM_ID,
      data: treeAccount({
        treeId,
        stateRoots,
        nullifierRoots: new Map([[0, field(57)]]),
        cursor: 1n,
        sequence: 0n,
        paused: world.paused ?? false,
      }),
      lamports: 1n,
    });
  if (world.queue !== undefined)
    accounts.set(queue, { owner: world.queue, data: new Uint8Array(8), lamports: 1n });
  const payload = concatBytes(
    Uint8Array.of(0, 33, 1, 0, 0),
    credentialAt,
    encodeAuditCredential(credential),
  );
  const creation: IndexedShieldedTransaction = {
    slot: 9n,
    txSignature: "sig" as IndexedShieldedTransaction["txSignature"],
    outputSlots: [
      {
        viewTag: field(0),
        outputContext: { hash: utxoHash, tree, treeId, leafIndex: LEAF_INDEX },
        payload,
      },
    ],
    messages: [],
    nullifiers: [credentialAt, field(3)],
    proofless: false,
  };
  const getNonInclusionProofs = vi.fn(async () => ({
    context: { slot: 1n, blockTime: 0n },
    proofs: [
      {
        leaf: credentialAt,
        merkleContext: { treeType: 0, tree: ADDRESS_TREE },
        path: gapPath,
        lowElement: low,
        lowElementIndex: 9n,
        highElement: next,
        highElementIndex: 10n,
        root: gapRoot,
        rootSeq: SEQUENCE,
        rootIndex: world.gapRootIndex ?? 3,
        ...world.gap,
      },
    ],
  }));
  const client = {
    getMultipleAccounts: async (addresses: readonly Address[]) =>
      addresses.map((key) => accounts.get(key)),
    getShieldedTransactionsByNullifiers: async () => ({
      context: { slot: 1n, blockTime: 0n },
      data:
        world.creation === undefined
          ? []
          : [
              {
                slot: 9n,
                signature: creation.txSignature,
                events: [world.creation === true ? creation : world.creation(creation)],
              },
            ],
      paginationToken: null,
    }),
    getMerkleProofs: async () => ({
      context: { slot: 1n, blockTime: 0n },
      proofs: [
        {
          leaf: utxoHash,
          merkleContext: { treeType: 0, tree },
          path: state.path(Number(LEAF_INDEX)),
          leafIndex: LEAF_INDEX,
          root: state.root,
          rootSeq: 1n,
          rootIndex: world.merkleRootIndex ?? 1,
        },
      ],
    }),
    getNonInclusionProofs,
  } as unknown as CredentialClient;
  return { client, creation, credentialAt, utxoHash, state, gapRoot, getNonInclusionProofs, low };
}

function withPayloadBit(
  created: IndexedShieldedTransaction,
  at: number,
): IndexedShieldedTransaction {
  const [slot] = created.outputSlots;
  if (slot === undefined) throw new Error("slot");
  const payload = slot.payload.slice();
  const index = at < 0 ? payload.length + at : at;
  payload[index] = (payload[index] ?? 0) ^ 1;
  return { ...created, outputSlots: [{ ...slot, payload }] };
}

function resolve(
  client: CredentialClient,
  extra: Partial<Parameters<typeof resolveCredential>[0]> = {},
) {
  return resolveCredential({ client, ring: RING, member: MEMBER, absenceFloor: 0n, ...extra });
}

function kind(resolved: ResolvedCredential, expected: ResolvedCredential["kind"]) {
  expect(resolved.kind).toBe(expected);
  return resolved;
}

describe("resolveCredential", () => {
  it("opens a settled credential whose address still waits in the queue", async () => {
    const { client, utxoHash, state, credentialAt } = await chain({
      queue: SHIELDED_POOL_PROGRAM_ID,
      creation: true,
    });
    const resolved = kind(
      await resolve(client, { nullifierPk: field(11), listTag: field(12) }),
      "present",
    );
    if (resolved.kind !== "present") return;
    expect(resolved.leaf).toMatchObject({
      credential,
      tree: STATE_TREE,
      treeId: STATE_TREE_ID,
      utxoHash,
      blinding: credentialBlinding(credentialAt),
      leafIndex: LEAF_INDEX,
      root: state.root,
      rootIndex: 1,
    });
  });

  it("opens a credential in tree 0 and in a paused tree", async () => {
    for (const world of [{ stateTreeId: ADDRESS_TREE_ID }, { paused: true }]) {
      const { client } = await chain({ ...world, creation: true });
      kind(await resolve(client), "present");
    }
  });

  it("reads a root Photon proved but the snapshot does not hold as unknown", async () => {
    const { client } = await chain({ creation: true, merkleRootIndex: 0 });
    expect(await resolve(client)).toMatchObject({ kind: "unknown", reason: "rootNotHeld" });
  });

  it("refuses a credential holding another nullifier key or list tag", async () => {
    const { client } = await chain({ creation: true });
    for (const [name, wrong] of [
      ["nullifierPk", { nullifierPk: field(99) }],
      ["listTag", { listTag: field(99) }],
    ] as const)
      await expect(resolve(client, wrong)).rejects.toMatchObject({
        code: "RING_ADDRESS_MISMATCH",
        details: { field: name },
      });
  });

  it("refuses a served credential whose hash differs from the published output", async () => {
    const { client } = await chain({ creation: (created) => withPayloadBit(created, -1) });
    await expect(resolve(client)).rejects.toMatchObject({
      code: "RING_CREDENTIAL_INVALID",
      details: { reason: "outputHash" },
    });
  });

  it("refuses a creation naming another member or not spending the address first", async () => {
    // Byte 69 opens the member, after the frame header, the address and the ring id.
    for (const [reason, served] of [
      ["creationOutput", (created: IndexedShieldedTransaction) => withPayloadBit(created, 69)],
      [
        "creation",
        (created: IndexedShieldedTransaction) => ({
          ...created,
          nullifiers: [...created.nullifiers].reverse(),
        }),
      ],
    ] as const) {
      const { client } = await chain({ creation: served });
      await expect(resolve(client)).rejects.toMatchObject({
        code: "RING_CREDENTIAL_INVALID",
        details: { reason },
      });
    }
  });

  it("proves absence under the newest root at the floor and refuses one sequence below", async () => {
    const { client, gapRoot } = await chain({});
    const resolved = await resolve(client, { absenceFloor: SEQUENCE });
    expect(resolved).toMatchObject({
      kind: "absent",
      gap: { lowIndex: 9n, checkpoint: { root: gapRoot, rootIndex: 3, sequence: SEQUENCE } },
    });
    await expect(resolve(client, { absenceFloor: SEQUENCE + 1n })).rejects.toMatchObject({
      code: "RING_ABSENCE_ROOT_BELOW_FLOOR",
    });
  });

  it("reads a queued reservation Photon has not served as unknown, never absent", async () => {
    const { client, getNonInclusionProofs } = await chain({ queue: SHIELDED_POOL_PROGRAM_ID });
    expect(await resolve(client)).toMatchObject({ kind: "unknown", reason: "queued" });
    expect(getNonInclusionProofs).not.toHaveBeenCalled();
  });

  it("takes lamports donated to the queue PDA as no reservation", async () => {
    const { client } = await chain({ queue: SYSTEM });
    kind(await resolve(client), "absent");
  });

  it("reads a gap under an older root as unknown", async () => {
    const { client } = await chain({ gapRootIndex: 2, gap: { root: field(77) } });
    expect(await resolve(client)).toMatchObject({ kind: "unknown", reason: "rootNotHeld" });
  });

  it("refuses a gap that does not bracket the address", async () => {
    const { credentialAt } = await chain({});
    const { client } = await chain({ gap: { lowElement: credentialAt } });
    await expect(resolve(client)).rejects.toMatchObject({
      code: "RING_CREDENTIAL_INVALID",
      details: { reason: "addressGap" },
    });
  });
});

describe("rootSequence", () => {
  const roots = new Map([
    [0, field(20)],
    [1, field(21)],
    [98, field(28)],
    [99, field(29)],
  ]);
  const at = (cursor: bigint, sequence: bigint, treeId = ADDRESS_TREE_ID) =>
    treeAccount({ treeId, stateRoots: [field(1)], nullifierRoots: roots, cursor, sequence });

  it("counts each slot behind the newest root as one sequence behind, across the wrap", () => {
    expect(rootSequence(at(2n, 500n), 1)).toMatchObject({ root: field(21), sequence: 500n });
    expect(rootSequence(at(2n, 500n), 0).sequence).toBe(499n);
    expect(rootSequence(at(2n, 500n), 99).sequence).toBe(498n);
    expect(rootSequence(at(0n, 500n), 98).sequence).toBe(499n);
  });

  it("refuses an empty slot, a distance past the count and a tree other than tree 0", () => {
    for (const [reason, run] of [
      ["emptyRoot", () => rootSequence(at(2n, 500n), 50)],
      ["rootSequence", () => rootSequence(at(2n, 1n), 99)],
      ["rootIndex", () => rootSequence(at(2n, 500n), 100)],
      ["addressTree", () => rootSequence(at(2n, 500n, 4), 1)],
    ] as const)
      expect(run).toThrow(
        expect.objectContaining({ code: "RING_CREDENTIAL_INVALID", details: { reason } }),
      );
  });
});

describe("credential hashes and reads", () => {
  it("keeps the RegisterKey hash and moves only the domain for the state hash", () => {
    expect(hashChain4(credentialElements(credential, RingDomain.registerKey))).toEqual(
      registerKeyStatementHash(credential),
    );
    const [stateDomain, ...stateFields] = credentialElements(
      credential,
      RingDomain.credentialState,
    );
    const [, ...keyFields] = credentialElements(credential, RingDomain.registerKey);
    expect(stateFields).toEqual(keyFields);
    expect(stateDomain).toEqual(field(RingDomain.credentialState));
    expect(credentialStateHash(credential)).not.toEqual(registerKeyStatementHash(credential));
  });

  it("encodes the empty read as three zero bytes and refuses a root index with no state read", () => {
    expect(encodeCredentialRead(EMPTY_CREDENTIAL_READ)).toEqual(new Uint8Array(3));
    expect(
      encodeCredentialRead({ addressRootIndex: 0x0102, stateRootIndexes: [7, 0x0304] }),
    ).toEqual(Uint8Array.of(2, 1, 2, 7, 0, 4, 3));
    expect(() => encodeCredentialRead({ addressRootIndex: 1, stateRootIndexes: [] })).toThrow(
      expect.objectContaining({
        code: "RING_CREDENTIAL_INVALID",
        details: { reason: "emptyRead" },
      }),
    );
  });
});
