import { address } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { poseidon, ZERO_32, ZERO_NULLIFIER_PK } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { ShieldedAddress, ShieldedKeypair, SigningKey } from "@heliuslabs/zolana/keypair";

import { RingAddress } from "../../src/crypto/keys/ring-address.js";
import { listTagOf } from "../../src/crypto/keys/list-salt.js";
import {
  TRACKING_QUAD_HEIGHT,
  TRACKING_SENTINEL,
  trackingRecordHash,
  type TrackingOpening,
  type TrackingRecord,
} from "../../src/protocol/membership/tracking.js";
import { resolveRingRecipient, type RingRecipientClient } from "../../src/rpc/tracking-resolver.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const REGISTRY = address("Stor111111111111111111111111111111111111111");

const holder = () =>
  ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(7) as Bytes32));

function zeroSiblings(): readonly (readonly Bytes32[])[] {
  const levels: Bytes32[][] = [];
  let zero: Bytes32 = ZERO_32;
  for (let level = 0; level < TRACKING_QUAD_HEIGHT; level += 1) {
    levels.push([zero, zero, zero]);
    zero = poseidon([zero, zero, zero, zero]) as Bytes32;
  }
  return levels;
}

/** The tree holding only `leaf` at index 0, served as `opening`. */
function chain(leaf: TrackingRecord, kind: "present" | "absent"): RingRecipientClient {
  const siblings = zeroSiblings();
  let root = trackingRecordHash(leaf);
  for (const level of siblings) root = poseidon([root, ...level]) as Bytes32;
  const data = new Uint8Array(1611);
  data[0] = 3;
  new DataView(data.buffer).setUint32(67, 1, true);
  data.set(root, 75);
  const path = { index: 0, siblings };
  const opening: TrackingOpening =
    kind === "present" ? { kind, record: leaf, path } : { kind, low: leaf, path };
  return {
    getAccount: async () => ({ data }),
    getTrackingOpenings: async () => ({ slot: 1n, root, revision: 0n, openings: [opening] }),
  } as unknown as RingRecipientClient;
}

async function addressed() {
  const wallet = holder();
  const to = await RingAddress.enrolled(wallet, RING);
  const member = to.recipient.signingPublicKey.ownerProofInputHash();
  const row: TrackingRecord = {
    ...TRACKING_SENTINEL,
    member,
    nullifierPk: wallet.nullifierPublicKey(),
    viewingU: new Uint8Array(32).fill(9) as Bytes32,
    revision: 3n,
    listTag: listTagOf(to.listSalt),
  };
  return { to, row, wallet };
}

beforeAll(initializePoseidon);

describe("resolveRingRecipient", () => {
  it("returns the row's key, newer viewing key, revision and tag, never a salt", async () => {
    const { to, row } = await addressed();
    const resolved = await resolveRingRecipient({
      client: chain(row, "present"),
      trackingRegistry: REGISTRY,
      to,
    });
    if (resolved.kind !== "enrolled") throw new Error("enrolled");
    expect(resolved.nullifierPk).toEqual(row.nullifierPk);
    expect(resolved.viewingPublicKey.u()).toEqual(row.viewingU);
    expect(resolved.revision).toBe(3n);
    expect(resolved.listTag).toEqual(listTagOf(to.listSalt));
    expect(Object.keys(resolved)).not.toContain("listSalt");
  });

  it("refuses a key or salt the verified row does not hold", async () => {
    const { to, row } = await addressed();
    for (const [name, wrong] of [
      ["nullifierPk", { nullifierPk: new Uint8Array(32).fill(5) as Bytes32 }],
      ["listSalt", { listTag: new Uint8Array(32).fill(5) as Bytes32 }],
    ] as const)
      await expect(
        resolveRingRecipient({
          client: chain({ ...row, ...wrong }, "present"),
          trackingRegistry: REGISTRY,
          to,
        }),
      ).rejects.toMatchObject({ code: "RING_ADDRESS_MISMATCH", details: { field: name } });
  });

  it("refuses a keyed address with no row, a pending enrollment grants nothing", async () => {
    const { to } = await addressed();
    await expect(
      resolveRingRecipient({
        client: chain(TRACKING_SENTINEL, "absent"),
        trackingRegistry: REGISTRY,
        to,
      }),
    ).rejects.toMatchObject({ code: "RING_RECIPIENT_NOT_ENROLLED" });
  });

  describe("under the zero key", () => {
    const zeroAddressed = (wallet: ShieldedKeypair) => {
      const address_ = wallet.shieldedAddress();
      return new RingAddress({
        recipient: ShieldedAddress.fromPublicKeys(
          address_.signingPublicKey,
          ZERO_NULLIFIER_PK as Bytes32,
          address_.viewingPublicKey,
        ),
        ringProgramId: RING,
        listSalt: ZERO_32,
      });
    };

    it("admits an owner with no row", async () => {
      const resolved = await resolveRingRecipient({
        client: chain(TRACKING_SENTINEL, "absent"),
        trackingRegistry: REGISTRY,
        to: zeroAddressed(holder()),
      });
      expect(resolved.kind).toBe("zeroKey");
    });

    it("refuses an enrolled owner", async () => {
      const { row, wallet } = await addressed();
      await expect(
        resolveRingRecipient({
          client: chain(row, "present"),
          trackingRegistry: REGISTRY,
          to: zeroAddressed(wallet),
        }),
      ).rejects.toMatchObject({ code: "RING_RECIPIENT_ENROLLED" });
    });
  });

  it("refuses an opening under another root", async () => {
    const { to, row } = await addressed();
    const client = chain(row, "present");
    const other = chain({ ...row, revision: 9n }, "present");
    await expect(
      resolveRingRecipient({
        client: { ...client, getTrackingOpenings: other.getTrackingOpenings },
        trackingRegistry: REGISTRY,
        to,
      }),
    ).rejects.toMatchObject({ code: "RING_TRACKING_INVALID" });
  });
});
