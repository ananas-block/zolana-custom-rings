import { address, type Address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import records from "../../../../../test-vectors/registry/ring-records.json" with { type: "json" };
import type { RpcAccount } from "@heliuslabs/zolana/client";
import { initializePoseidon } from "@heliuslabs/zolana";
import {
  addressBytes,
  bytesToBigInt,
  equalBytes,
  hashBytes,
  poseidon,
  Writer,
} from "@heliuslabs/zolana/internal";
import type { Bytes31, Bytes32 } from "@heliuslabs/zolana/interface";
import {
  NullifierKey,
  ShieldedKeypair,
  SigningKey,
  X25519Keypair,
} from "@heliuslabs/zolana/keypair";
import { ringPolicyPda, STORAGE_PROGRAM_ID } from "../../../src/protocol/pda/index.js";
import { MEMBER_REGISTRY_EMPTY_ROOT } from "../../../src/protocol/membership/member-opening.js";
import { memberOfTag } from "../../../src/protocol/membership/policy.js";
import {
  fetchRingSealedKey,
  openNullifierKey,
  openRingSealedKey,
  sealNullifierKey,
  sealNullifierKeyWith,
} from "../../../src/operations/management/register-key.js";
import {
  TRACKING_QUAD_HEIGHT,
  TRACKING_SENTINEL,
  trackingRecordHash,
  type TrackingRecord,
} from "../../../src/protocol/membership/tracking.js";
import { QUAD_ARITY, ROOT_HISTORY } from "../../../src/protocol/membership/member-registry.js";
import type {
  ServedTrackingOpening,
  TrackingOpeningsRequest,
  TrackingSeal,
} from "../../../src/protocol/indexer/tracking-codec.js";
import { recordTree } from "../../helpers/member-registry.js";
import { ownedAccount, ringPolicyData } from "../../helpers/ring-accounts.js";

// sdk-libs/client/src/crypto/encryption/mod.rs `the_sealed_key_and_its_escrow_key_match_the_pinned_vector`.
const AUDITOR_SK = hex("01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c");
const EPHEMERAL_SK = hex("011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e");
const NULLIFIER_SECRET = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const NULLIFIER_PK = hex("2d1faf6cf358763421511eb637adf7b6609443d38edc4ed2b042dfbf834b03f5");
const EPH_PK = hex("043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63");
const CIPHERTEXT = hex("44409b9e390ec45df98e391d4a86c1e57b52cbd8d60eb9f7426442ed822616ba");

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const AUTHORITY = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const TRACKING = address("6NxnStrvfxkDAnWHyvc6SVXkZvBKtpHS3Bd9WfCSgUSv");
const REVISION = 2n;
const AUDITOR = X25519Keypair.fromBytes(AUDITOR_SK);

beforeAll(initializePoseidon);

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function actor(seed: number) {
  const keypair = ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );
  const shielded = keypair.shieldedAddress();
  const signer = shielded.solanaAddress();
  return { keypair, shielded, signer, member: memberOfTag(addressBytes(signer)) };
}

/** A tracking tree of height 13 holding the sentinel at leaf 0 and `row` at leaf 1. */
function trackingTree(row: TrackingRecord) {
  const sentinel: TrackingRecord = { ...TRACKING_SENTINEL, next: row.member };
  const zeros: Bytes32[] = [new Uint8Array(32) as Bytes32];
  for (let level = 0; level < TRACKING_QUAD_HEIGHT; level += 1) {
    const below = zeros[level] as Bytes32;
    zeros.push(poseidon(Array.from({ length: QUAD_ARITY }, () => below)) as Bytes32);
  }
  const above = zeros.slice(1, TRACKING_QUAD_HEIGHT).map((zero) => [zero, zero, zero]);
  const zero = zeros[0] as Bytes32;
  const path = (index: number, neighbour: TrackingRecord) => ({
    index,
    siblings: [[trackingRecordHash(neighbour), zero, zero], ...above],
  });
  const root = above.reduce<Bytes32>(
    (node, siblings) => poseidon([node, ...siblings]) as Bytes32,
    poseidon([trackingRecordHash(sentinel), trackingRecordHash(row), zero, zero]) as Bytes32,
  );
  return {
    root,
    rowPath: path(1, sentinel),
    /** The opening of a member sorted around `row`, its low row bracketing it. */
    absent: (member: Bytes32): ServedTrackingOpening =>
      bytesToBigInt(member) > bytesToBigInt(row.member)
        ? { kind: "absent", low: row, path: path(1, sentinel) }
        : { kind: "absent", low: sentinel, path: path(0, row) },
  };
}

/** The chain and indexer of a ring whose tracking registry holds `who`, serving `seal`. */
async function ring(who: ReturnType<typeof enrolled>, seal: TrackingSeal | undefined = who.seal) {
  const { root, rowPath, absent } = trackingTree(who.row);
  const [policy, policyBump] = await ringPolicyPda(RING);
  const accounts = new Map<Address, RpcAccount>([
    [
      policy,
      ownedAccount(
        RING,
        ringPolicyData({
          bump: policyBump,
          roles: { policy: AUTHORITY },
          auditorPublicKey: AUDITOR.publicKey().toBytes(),
          mode: "confidential",
          policyHash: new Uint8Array(32).fill(1) as Bytes32,
          tracking: TRACKING,
        }),
      ),
    ],
    [TRACKING, ownedAccount(STORAGE_PROGRAM_ID, trackingRegistryData(root))],
  ]);
  const getTrackingOpenings = vi.fn(async (request: TrackingOpeningsRequest) => ({
    slot: 1n,
    root: request.expectedRoot,
    revision: REVISION,
    openings: request.members.map((member): ServedTrackingOpening =>
      equalBytes(member, who.row.member)
        ? {
            kind: "present",
            record: who.row,
            path: rowPath,
            ...(seal === undefined ? {} : { seal }),
          }
        : absent(member),
    ),
  }));
  return {
    root,
    client: {
      getAccount: async (account: Address) => accounts.get(account),
      getTrackingOpenings,
    },
  };
}

/** Rust `TrackingRegistry` with `root` the newest of its history. */
function trackingRegistryData(root: Bytes32): Uint8Array {
  const writer = new Writer()
    .u8(3, "discriminator")
    .u8(255, "bump")
    .bytes(new Uint8Array(32), 32, "ringId")
    .bytes(AUDITOR.publicKey().toBytes(), 33, "auditor")
    .u32(2, "nextIndex")
    .u32(2, "reservedLeaves");
  for (let slot = 0; slot < ROOT_HISTORY; slot += 1)
    writer
      .bytes(slot === 0 ? root : new Uint8Array(32), 32, "hash")
      .u64(slot === 0 ? REVISION : 0n, "revision")
      .u64(0n, "expiresAt");
  return writer.finish();
}

/** An owner whose applied tracking row binds its sealed key. */
function enrolled(seed: number) {
  const who = actor(seed);
  const envelope = sealNullifierKey(who.keypair.nullifierKey(), AUDITOR.publicKey());
  envelope.ephemeralSecret.fill(0);
  const seal: TrackingSeal = {
    owner: who.signer,
    ephPk: envelope.sealed.ephemeralPublicKey.toBytes(),
    ciphertext: envelope.sealed.ciphertext,
  };
  const row: TrackingRecord = {
    ...TRACKING_SENTINEL,
    member: who.member,
    nullifierPk: envelope.nullifierPublicKey,
    ctHash: hashBytes(envelope.sealed.ciphertext) as Bytes32,
    viewingU: new Uint8Array(32).fill(9) as Bytes32,
    revision: 1n,
    listTag: new Uint8Array(32).fill(3) as Bytes32,
  };
  return { ...who, seal, row, envelope };
}

describe("nullifier key envelope", () => {
  it("matches the Rust vector and opens only for the auditor", () => {
    const ephemeral = X25519Keypair.fromBytes(EPHEMERAL_SK);
    const nullifierKey = NullifierKey.fromSecret(NULLIFIER_SECRET as Bytes31);
    const envelope = sealNullifierKeyWith(ephemeral, nullifierKey, AUDITOR.publicKey());
    expect(envelope.nullifierPublicKey).toEqual(NULLIFIER_PK);
    expect(envelope.sealed.ephemeralPublicKey.toBytes()).toEqual(EPH_PK);
    expect(envelope.sealed.ciphertext).toEqual(CIPHERTEXT);
    expect(openNullifierKey(envelope.sealed, AUDITOR).secretBytes()).toEqual(NULLIFIER_SECRET);
    const fresh = sealNullifierKey(nullifierKey, AUDITOR.publicKey());
    expect(fresh.sealed.ciphertext).not.toEqual(CIPHERTEXT);
    expect(openNullifierKey(fresh.sealed, AUDITOR).secretBytes()).toEqual(NULLIFIER_SECRET);
  });

  it("pins the sentinel-only root the registry starts from", () => {
    expect(Buffer.from(MEMBER_REGISTRY_EMPTY_ROOT).toString("hex")).toBe(records.empty_root);
    expect(recordTree().root).toEqual(MEMBER_REGISTRY_EMPTY_ROOT);
  });
});

describe("enrolled keys", () => {
  it("opens an enrolled owner's key for the auditor only", async () => {
    const who = enrolled(11);
    const { client, root } = await ring(who);
    const entry = await fetchRingSealedKey({ client, ringProgramId: RING, member: who.member });
    expect(entry.root).toEqual(root);
    expect(entry.record).toEqual(who.row);
    expect(entry.sealed.ciphertext).toEqual(who.seal.ciphertext);
    expect(entry.sealed.nullifierPk).toEqual(who.row.nullifierPk);
    expect(client.getTrackingOpenings).toHaveBeenCalledWith(
      { registry: TRACKING, members: [who.member], expectedRoot: root },
      expect.anything(),
    );
    expect(openRingSealedKey(entry, AUDITOR).secretBytes()).toEqual(
      who.keypair.nullifierKey().secretBytes(),
    );
    expect(() => openRingSealedKey(entry, X25519Keypair.generate())).toThrow(
      expect.objectContaining({ code: "RING_KEY_ENVELOPE_INVALID" }),
    );
  });

  it("refuses a seal the row does not bind, another owner's seal and an owner with no seal", async () => {
    const who = enrolled(12);
    const ciphertext = Uint8Array.from(who.seal.ciphertext);
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    for (const seal of [
      { ...who.seal, ciphertext },
      { ...who.seal, owner: actor(14).signer },
    ]) {
      const { client } = await ring(who, seal);
      await expect(
        fetchRingSealedKey({ client, ringProgramId: RING, member: who.member }),
      ).rejects.toMatchObject({ code: "RING_KEY_NOT_REGISTERED" });
    }
  });

  it("refuses an unenrolled owner proven absent under the root", async () => {
    const { client } = await ring(enrolled(15));
    await expect(
      fetchRingSealedKey({ client, ringProgramId: RING, member: actor(13).member }),
    ).rejects.toMatchObject({ code: "RING_KEY_NOT_REGISTERED" });
  });

  it("refuses a key whose row and path disagree with the root", async () => {
    const who = enrolled(16);
    const { client } = await ring(who);
    const tampered = {
      ...client,
      getTrackingOpenings: async (request: TrackingOpeningsRequest) => {
        const served = await client.getTrackingOpenings(request);
        const [opening] = served.openings;
        if (opening?.kind !== "present") throw new Error("expected a present row");
        const record = { ...opening.record, revision: opening.record.revision + 1n };
        return { ...served, openings: [{ ...opening, record }] };
      },
    };
    await expect(
      fetchRingSealedKey({ client: tampered, ringProgramId: RING, member: who.member }),
    ).rejects.toMatchObject({ code: "RING_TRACKING_INVALID", details: { reason: "RootMismatch" } });
  });
});
