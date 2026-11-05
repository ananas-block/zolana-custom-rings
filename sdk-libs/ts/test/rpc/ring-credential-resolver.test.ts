import { address, getAddressEncoder, getProgramDerivedAddress, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { MerkleProof, NonInclusionProof, RpcAccount } from "@heliuslabs/zolana/client";
import {
  bigIntBytes,
  concatBytes,
  encodeBase58,
  hashChain4,
  nullifierPdaAddress,
  poseidon,
  solanaOwnerIdentity,
  SYSTEM_PROGRAM,
  treeAddress,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import {
  NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET,
  NULLIFIER_ROOT_HISTORY_OFFSET,
  NULLIFIER_TREE_HEIGHT,
  SHIELDED_POOL_PROGRAM_ID,
  STATE_HEIGHT,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  USER_REGISTRY_PROGRAM_ID,
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
import {
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import type { IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";

import { RingDomain } from "../../src/crypto/derivation/ring-domain.js";
import { ringIdField } from "../../src/crypto/derivation/ring-stream.js";
import { listSaltOf, listTagOf } from "../../src/crypto/keys/list-salt.js";
import { RingAddress } from "../../src/crypto/keys/ring-address.js";
import {
  ADDRESS_TREE_ID,
  EMPTY_CREDENTIAL_READ,
  NULLIFIER_SEQUENCE_OFFSET,
  credentialAddress,
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
  checkAbsenceFloor,
  resolveCredential,
  resolveRecipientKeys,
  type CredentialClient,
  type CredentialLookup,
  type CredentialQuery,
} from "../../src/rpc/credential-resolver.js";
import { stateTreeAt } from "../helpers/state-tree.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE_ID = 3;
const LEAF_INDEX = 5n;
const ENROLLMENT_SLOT = 9n;
const ADDRESS_ROOT_SEQUENCE = 6n;
const field = (value: number) => bigIntBytes(BigInt(value)) as Bytes32;

const holder = () =>
  ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(7) as Bytes32));

function owner(): Address {
  return encodeBase58(holder().shieldedAddress().signingPublicKey.confidentialViewTag());
}

function listSalt(): Bytes32 {
  return listSaltOf(holder().viewingKey(), RING);
}

function credential(): AuditCredential {
  return Object.freeze({
    ringId: ringIdField(RING),
    member: solanaOwnerIdentity(getAddressEncoder().encode(owner()) as Uint8Array) as Bytes32,
    nullifierPk: holder().nullifierPublicKey(),
    listTag: listTagOf(listSalt()),
    auditorPubkey: concatBytes(Uint8Array.of(4), field(14)) as Bytes33,
    ephU: field(13),
    ciphertext: new Uint8Array(64).fill(0x21) as Bytes64,
  });
}

async function identity() {
  const pda = await credentialPda(RING);
  const served = credential();
  return { pda, address: credentialAddress(pda, credentialSeed(served.ringId, served.member)) };
}

interface Tree {
  readonly treeId: number;
  /** State roots by history slot, the last slot is the newest. */
  readonly stateRoots: readonly Bytes32[];
  /** Nullifier roots by history slot, `cursor` names the slot past the newest. */
  readonly nullifierRoots: ReadonlyMap<number, Bytes32>;
  readonly cursor: bigint;
  readonly sequence: bigint;
}

function treeAccount(tree: Tree): RpcAccount {
  const data = new Uint8Array(TREE_ACCOUNT_SIZE);
  const view = new DataView(data.buffer);
  data[0] = StateDiscriminator.treeAccount;
  data[1] = 1;
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
  return { owner: SHIELDED_POOL_PROGRAM_ID, data, lamports: 1n };
}

function fold(leaf: Bytes32, index: bigint, path: readonly Bytes32[]): Bytes32 {
  return path.reduce<Bytes32>(
    (node, sibling, level) =>
      poseidon(
        ((index >> BigInt(level)) & 1n) === 1n ? [sibling, node] : [node, sibling],
      ) as Bytes32,
    leaf,
  );
}

class Ledger {
  readonly accounts = new Map<Address, RpcAccount>();
  enrollments: IndexedShieldedTransaction[] = [];
  continuation: string | null = null;
  stateProofs: MerkleProof[] = [];
  gaps: NonInclusionProof[] = [];

  /** The credential leaf sits at `LEAF_INDEX` of `TREE_ID`, its root in history slot 1. */
  static async enrolled(served: AuditCredential): Promise<Ledger> {
    const ledger = new Ledger();
    const { pda, address } = await identity();
    const leaf = credentialUtxoHash({ pda, address, credential: served, treeId: TREE_ID });
    const state = stateTreeAt(new Map([[Number(LEAF_INDEX), leaf]]));
    const tree = treeAddress(TREE_ID);
    ledger.accounts.set(
      tree,
      treeAccount({
        treeId: TREE_ID,
        stateRoots: [field(55), state.root],
        nullifierRoots: new Map([[0, field(57)]]),
        cursor: 1n,
        sequence: 0n,
      }),
    );
    ledger.enrollments.push({
      slot: ENROLLMENT_SLOT,
      txSignature: "enroll" as IndexedShieldedTransaction["txSignature"],
      outputSlots: [
        {
          viewTag: ZERO_32,
          outputContext: { hash: leaf, tree, treeId: TREE_ID, leafIndex: LEAF_INDEX },
          payload: concatBytes(
            Uint8Array.of(0, 33, 1, 0, 0),
            address,
            encodeAuditCredential(served),
          ),
        },
      ],
      messages: [],
      nullifiers: [address, field(3)],
      proofless: false,
    });
    ledger.stateProofs.push({
      leaf,
      merkleContext: { treeType: 0, tree },
      path: state.path(Number(LEAF_INDEX)),
      leafIndex: LEAF_INDEX,
      root: state.root,
      rootSeq: 1n,
      rootIndex: 1,
    });
    return ledger;
  }

  /** Tree 0 holds the gap root in slot 0, one apply behind the latest root. */
  static async absent(): Promise<Ledger> {
    const ledger = new Ledger();
    const { address } = await identity();
    const low = field(1);
    const path = Array.from({ length: NULLIFIER_TREE_HEIGHT }, (_, level) => field(100 + level));
    const root = fold(poseidon([low, FIELD_MAX]) as Bytes32, 9n, path);
    ledger.accounts.set(
      treeAddress(ADDRESS_TREE_ID),
      treeAccount({
        treeId: ADDRESS_TREE_ID,
        stateRoots: [field(56)],
        nullifierRoots: new Map([
          [0, root],
          [1, field(9)],
        ]),
        cursor: 2n,
        sequence: ADDRESS_ROOT_SEQUENCE + 1n,
      }),
    );
    ledger.gaps.push({
      leaf: address,
      merkleContext: { treeType: 0, tree: treeAddress(ADDRESS_TREE_ID) },
      path,
      lowElement: low,
      lowElementIndex: 9n,
      highElement: FIELD_MAX,
      highElementIndex: 10n,
      root,
      rootSeq: ADDRESS_ROOT_SEQUENCE,
      rootIndex: 0,
    });
    return ledger;
  }

  async queue(queueOwner: Address = SHIELDED_POOL_PROGRAM_ID, data = new Uint8Array(8)) {
    const { address } = await identity();
    const queue = await nullifierPdaAddress(treeAddress(ADDRESS_TREE_ID), address);
    this.accounts.set(queue, { owner: queueOwner, data, lamports: 1n });
  }

  async register(nullifierPk: Bytes32, viewing: X25519PublicKey) {
    const encoder = getAddressEncoder();
    const [pda, bump] = await getProgramDerivedAddress({
      programAddress: USER_REGISTRY_PROGRAM_ID,
      seeds: [new TextEncoder().encode("zolana/registry/v0"), encoder.encode(owner())],
    });
    const data = new Uint8Array(100);
    data[0] = 1;
    data.set(encoder.encode(owner()), 1);
    data[33] = bump;
    data.set(nullifierPk, 34);
    data.set(viewing.toBytes(), 66);
    this.accounts.set(pda, { owner: USER_REGISTRY_PROGRAM_ID, data, lamports: 1n });
  }

  client(): CredentialClient {
    const context = { slot: 1n, blockTime: 0n };
    return {
      getAccount: async (key) => this.accounts.get(key),
      getMultipleAccounts: async (keys) => keys.map((key) => this.accounts.get(key)),
      getShieldedTransactionsByNullifiers: async () => ({
        context,
        data: this.enrollments.map((event) => ({
          slot: event.slot,
          signature: event.txSignature,
          events: [event],
        })),
        paginationToken: this.continuation,
      }),
      getMerkleProofs: async () => ({ context, proofs: this.stateProofs }),
      getNonInclusionProofs: async () => ({ context, proofs: this.gaps }),
    } as CredentialClient;
  }

  resolve(query: Partial<Omit<CredentialQuery, "client">> = {}): Promise<CredentialLookup> {
    return resolveCredential({ client: this.client(), ring: RING, owner: owner(), ...query });
  }
}

async function registeredAddress(): Promise<RingAddress> {
  return RingAddress.enrolled(holder(), RING, listSalt());
}

function zeroKeyAddress(): RingAddress {
  const shielded = holder().shieldedAddress();
  return new RingAddress({
    recipient: ShieldedAddress.fromPublicKeys(
      shielded.signingPublicKey,
      ZERO_NULLIFIER_PK as Bytes32,
      shielded.viewingPublicKey,
    ),
    ringProgramId: RING,
    listSalt: ZERO_32,
  });
}

function invalid(reason: string) {
  return expect.objectContaining({
    code: "RING_CREDENTIAL_INVALID",
    details: expect.objectContaining({ reason }),
  });
}

describe("resolveCredential", () => {
  it("opens a present credential under its tree root, also when the tree is paused", async () => {
    const served = credential();
    const ledger = await Ledger.enrolled(served);
    const opened = await ledger.resolve({
      nullifierPk: served.nullifierPk,
      listTag: served.listTag,
    });
    const [proof] = ledger.stateProofs;
    expect(opened).toMatchObject({
      kind: "present",
      credential: served,
      address: (await identity()).address,
      treeId: TREE_ID,
      leafIndex: LEAF_INDEX,
      root: { rootIndex: proof?.rootIndex, root: proof?.root },
      enrollment: "enroll",
    });
    const paused = ledger.accounts.get(treeAddress(TREE_ID));
    if (paused !== undefined) paused.data[1] = 2;
    expect(await ledger.resolve()).toEqual(opened);
  });

  it("finds an owner without enrollment absent at its root sequence", async () => {
    const opened = await (await Ledger.absent()).resolve();
    if (opened.kind !== "absent") throw new Error(opened.kind);
    expect(opened.address).toEqual((await identity()).address);
    expect(opened.root).toMatchObject({ rootIndex: 0, sequence: ADDRESS_ROOT_SEQUENCE });
    checkAbsenceFloor(opened, ADDRESS_ROOT_SEQUENCE);
    expect(() => checkAbsenceFloor(opened, ADDRESS_ROOT_SEQUENCE + 1n)).toThrow(
      expect.objectContaining({
        code: "RING_ABSENCE_ROOT_BELOW_FLOOR",
        details: { sequence: "6", floor: "7" },
      }),
    );
  });

  it("reads a queued address the indexer has not served as unknown, not donated lamports", async () => {
    const queued = await Ledger.absent();
    await queued.queue();
    expect(await queued.resolve()).toEqual({ kind: "unknown", reason: "queued" });
    const donated = await Ledger.absent();
    await donated.queue(SYSTEM_PROGRAM, new Uint8Array());
    expect((await donated.resolve()).kind).toBe("absent");
  });

  it("refuses a root outside the history or a path off the root", async () => {
    const staleState = await Ledger.enrolled(credential());
    staleState.stateProofs = staleState.stateProofs.map((proof) => ({ ...proof, rootIndex: 0 }));
    await expect(staleState.resolve()).rejects.toEqual(invalid("stateRootNotAccepted"));

    const forgedPath = await Ledger.enrolled(credential());
    forgedPath.stateProofs = forgedPath.stateProofs.map((proof) => ({
      ...proof,
      path: proof.path.map((node, level) => (level === 4 ? field(1) : node)),
    }));
    await expect(forgedPath.resolve()).rejects.toEqual(invalid("invalidStateProof"));

    const staleAddress = await Ledger.absent();
    staleAddress.gaps = staleAddress.gaps.map((gap) => ({ ...gap, rootIndex: 1 }));
    await expect(staleAddress.resolve()).rejects.toEqual(invalid("addressRootNotAccepted"));

    const coveringGap = await Ledger.absent();
    const { address } = await identity();
    coveringGap.gaps = coveringGap.gaps.map((gap) => ({ ...gap, lowElement: address }));
    await expect(coveringGap.resolve()).rejects.toEqual(invalid("invalidAbsenceProof"));
  });

  it("refuses a credential of another ring, owner, key or tag", async () => {
    const ledger = await Ledger.enrolled(credential());
    await expect(ledger.resolve({ nullifierPk: field(1) })).rejects.toMatchObject({
      code: "RING_CREDENTIAL_NULLIFIER_KEY_MISMATCH",
    });
    await expect(ledger.resolve({ listTag: field(1) })).rejects.toMatchObject({
      code: "RING_CREDENTIAL_LIST_TAG_MISMATCH",
    });
    for (const served of [
      { ...credential(), ringId: field(1) },
      { ...credential(), member: field(1) },
    ])
      await expect((await Ledger.enrolled(served)).resolve()).rejects.toMatchObject({
        code: "RING_CREDENTIAL_MISMATCH",
      });
  });

  it("refuses an enrollment output whose credential does not rebuild the published leaf", async () => {
    const ledger = await Ledger.enrolled(credential());
    ledger.enrollments = ledger.enrollments.map((enrollment) => ({
      ...enrollment,
      outputSlots: enrollment.outputSlots.map((slot) => {
        const payload = slot.payload.slice();
        payload[payload.length - 1] = (payload[payload.length - 1] ?? 0) ^ 1;
        return { ...slot, payload };
      }),
    }));
    await expect(ledger.resolve()).rejects.toEqual(invalid("malformedEnrollment"));
  });

  it("refuses an account answer short of the queue PDA", async () => {
    const ledger = await Ledger.absent();
    await ledger.queue();
    const client = ledger.client();
    const short: CredentialClient = {
      ...client,
      getMultipleAccounts: async (keys) => (await client.getMultipleAccounts(keys)).slice(0, 1),
    };
    await expect(
      resolveCredential({ client: short, ring: RING, owner: owner() }),
    ).rejects.toMatchObject({ code: "RING_RPC", details: { reason: "accountCount", count: 1 } });
  });

  it("keeps partial indexer answers unknown or refused", async () => {
    const withoutProof = await Ledger.enrolled(credential());
    withoutProof.stateProofs = [];
    expect(await withoutProof.resolve()).toEqual({ kind: "unknown", reason: "stateProofMissing" });

    const withoutGap = await Ledger.absent();
    withoutGap.gaps = [];
    expect(await withoutGap.resolve()).toEqual({ kind: "unknown", reason: "absenceProofMissing" });

    const continued = await Ledger.absent();
    continued.continuation = "next";
    expect(await continued.resolve()).toEqual({ kind: "unknown", reason: "partialPage" });

    const twice = await Ledger.enrolled(credential());
    twice.enrollments = [...twice.enrollments, ...twice.enrollments];
    await expect(twice.resolve()).rejects.toEqual(
      expect.objectContaining({ details: { reason: "enrollmentCount", count: 2 } }),
    );
  });
});

describe("resolveRecipientKeys", () => {
  it("takes the registered key and the record bound to it", async () => {
    const served = credential();
    const to = await registeredAddress();
    const ledger = await Ledger.enrolled(served);
    const keys = await resolveRecipientKeys({ client: ledger.client(), to });
    expect(keys).toMatchObject({ kind: "registered", nullifierPk: served.nullifierPk });
    expect(keys.viewingPublicKey.toBytes()).toEqual(to.recipient.viewingPublicKey.toBytes());

    const rotated = ViewingKey.generate().publicKey();
    await ledger.register(served.nullifierPk, rotated);
    const recorded = await resolveRecipientKeys({ client: ledger.client(), to });
    expect(recorded.viewingPublicKey.toBytes()).toEqual(rotated.toBytes());

    await ledger.register(field(1), rotated);
    await expect(resolveRecipientKeys({ client: ledger.client(), to })).rejects.toMatchObject({
      code: "RING_NULLIFIER_KEY_MISMATCH",
    });

    await expect(
      resolveRecipientKeys({ client: (await Ledger.absent()).client(), to }),
    ).rejects.toMatchObject({ code: "RING_RECIPIENT_NOT_ENROLLED" });
  });

  it("needs an absent owner or an opt in for the zero key", async () => {
    const to = zeroKeyAddress();
    const keys = await resolveRecipientKeys({ client: (await Ledger.absent()).client(), to });
    expect(keys).toMatchObject({ kind: "zeroKey", nullifierPk: ZERO_NULLIFIER_PK });

    const queued = await Ledger.absent();
    await queued.queue();
    await expect(resolveRecipientKeys({ client: queued.client(), to })).rejects.toMatchObject({
      code: "RING_CREDENTIAL_UNKNOWN",
      details: { reason: "queued" },
    });

    const served = credential();
    const enrolled = await Ledger.enrolled(served);
    await expect(resolveRecipientKeys({ client: enrolled.client(), to })).rejects.toMatchObject({
      code: "RING_RECIPIENT_ENROLLED",
    });
    await expect(
      resolveRecipientKeys({ client: enrolled.client(), to, zeroKeyToEnrolled: true }),
    ).rejects.toMatchObject({ code: "RING_VIEWING_KEY_UNVERIFIED" });

    const viewing = ViewingKey.generate().publicKey();
    await enrolled.register(served.nullifierPk, viewing);
    const opted = await resolveRecipientKeys({
      client: enrolled.client(),
      to,
      zeroKeyToEnrolled: true,
    });
    expect(opted).toMatchObject({ kind: "zeroKeyToEnrolled", nullifierPk: ZERO_NULLIFIER_PK });
    expect(opted.viewingPublicKey.toBytes()).toEqual(viewing.toBytes());
  });
});

describe("rootSequence", () => {
  const roots = new Map([
    [0, field(20)],
    [1, field(21)],
    [98, field(28)],
    [99, field(29)],
  ]);
  const at = (cursor: bigint, sequence: bigint) =>
    treeAccount({
      treeId: ADDRESS_TREE_ID,
      stateRoots: [field(1)],
      nullifierRoots: roots,
      cursor,
      sequence,
    }).data;

  it("counts each slot behind the newest root as one sequence behind, across the wrap", () => {
    expect(rootSequence(at(2n, 500n), 1)).toEqual({
      rootIndex: 1,
      root: field(21),
      sequence: 500n,
    });
    expect(rootSequence(at(2n, 500n), 0)?.sequence).toBe(499n);
    expect(rootSequence(at(2n, 500n), 99)?.sequence).toBe(498n);
    expect(rootSequence(at(0n, 500n), 98)?.sequence).toBe(499n);
  });

  it("holds no root at an empty slot, a distance past the count or an index past the history", () => {
    expect(rootSequence(at(2n, 500n), 50)).toBeUndefined();
    expect(rootSequence(at(2n, 1n), 99)).toBeUndefined();
    expect(rootSequence(at(2n, 500n), 100)).toBeUndefined();
  });
});

describe("credential hashes and reads", () => {
  it("keeps the RegisterKey hash and moves only the domain for the state hash", () => {
    const served = credential();
    expect(hashChain4(credentialElements(served, RingDomain.registerKey))).toEqual(
      registerKeyStatementHash(served),
    );
    const [stateDomain, ...stateFields] = credentialElements(served, RingDomain.credentialState);
    const [, ...keyFields] = credentialElements(served, RingDomain.registerKey);
    expect(stateFields).toEqual(keyFields);
    expect(stateDomain).toEqual(field(RingDomain.credentialState));
    expect(credentialStateHash(served)).not.toEqual(registerKeyStatementHash(served));
  });

  it("encodes the empty read as three zero bytes and refuses a root index with no state read", () => {
    expect(encodeCredentialRead(EMPTY_CREDENTIAL_READ)).toEqual(new Uint8Array(3));
    expect(
      encodeCredentialRead({ addressRootIndex: 0x0102, stateRootIndexes: [7, 0x0304] }),
    ).toEqual(Uint8Array.of(2, 1, 2, 7, 0, 4, 3));
    expect(() => encodeCredentialRead({ addressRootIndex: 1, stateRootIndexes: [] })).toThrow(
      invalid("emptyRead"),
    );
  });
});
