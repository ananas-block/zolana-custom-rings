import { address, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { addressBytes } from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32 } from "@heliuslabs/zolana/interface";
import { ShieldedKeypair, SigningKey, ViewingKey } from "@heliuslabs/zolana/keypair";

import { ENROLL_TAG } from "../../../src/operations/management/enrollment.js";
import {
  confirmViewingKey,
  rotateViewingKey,
  updateViewingKey,
} from "../../../src/operations/management/viewing-rotation.js";
import { trackingAuthorizationPda } from "../../../src/protocol/pda/index.js";
import { LocalRingKeys } from "../../../src/state/ring-keys.js";
import { ViewingHistory } from "../../../src/state/viewing-history.js";

const OWNER = address("7xKqmYUZ7pQHXcQnaZaZzR1oPjQb8kk8gA7XN3XxKzKq");
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const REGISTRY = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const SALT = new Uint8Array(16).fill(5) as Bytes16;

const wallet = (seed: number) =>
  ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );

/** `OWNER`'s tracking authorization for `holder`, `land` applies a pending rotation. */
async function enrolled(holder: ShieldedKeypair) {
  const [pda] = await trackingAuthorizationPda(REGISTRY, OWNER);
  const data = new Uint8Array(273);
  data[0] = 4;
  data.set(addressBytes(REGISTRY), 1);
  data.set(addressBytes(OWNER), 33);
  data.set(holder.nullifierPublicKey(), 65);
  data.fill(0x11, 97, 129);
  data.set(holder.viewingPublicKey().u(), 129);
  data.fill(0x22, 161, 193);
  data.fill(0x33, 193, 257);
  const view = new DataView(data.buffer);
  view.setBigUint64(257, 1n, true);
  view.setBigUint64(265, 1n, true);
  const client = {
    getAccount: async (read: Address) =>
      read === pda ? { owner: REGISTRY, data: data.slice(), lamports: 1n } : undefined,
  };
  // The program raises the revision on Enroll, the applier folds it into the tree.
  const enroll = (viewingU: Uint8Array) => {
    data.set(viewingU, 129);
    view.setBigUint64(257, 2n, true);
  };
  const apply = () => view.setBigUint64(265, 2n, true);
  return { client, enroll, apply };
}

function rotation(holder: ShieldedKeypair, next: ViewingKey) {
  return rotateViewingKey({
    keys: LocalRingKeys.fromKeypair(holder),
    history: ViewingHistory.create(holder.viewingPublicKey(), 0n),
    next,
    rotatedAt: 1n,
  });
}

describe("viewing key rotation through the tracking row", () => {
  it("enrolls the new key without a proof and confirms it only once applied", async () => {
    const holder = wallet(1);
    const { client, enroll, apply } = await enrolled(holder);
    const rotated = rotation(holder, ViewingKey.generate());
    const current = rotated.keys.address().viewingPublicKey.u();
    const update = () =>
      updateViewingKey({
        client,
        payer: PAYER,
        owner: OWNER,
        trackingRegistry: REGISTRY,
        keys: rotated.keys,
        history: rotated.history,
      });
    const confirm = () =>
      confirmViewingKey({ client, owner: OWNER, trackingRegistry: REGISTRY, keys: rotated.keys });

    // 1. The rotation repeats the seal, carries the new key and no proof.
    const instruction = await update();
    expect(instruction?.data?.[0]).toBe(ENROLL_TAG);
    expect(instruction?.data).toHaveLength(1 + 192);
    expect(instruction?.data?.subarray(65, 97)).toEqual(current);
    await expect(confirm()).rejects.toMatchObject({ code: "RING_VIEWING_KEY_NOT_PUBLISHED" });

    // 2. A pending revision confirms nothing, the applied one does.
    enroll(current);
    await expect(confirm()).rejects.toMatchObject({ code: "RING_VIEWING_KEY_NOT_PUBLISHED" });
    apply();
    expect((await confirm()).viewingU).toEqual(current);
    expect(await update()).toBeUndefined();
  });

  it("opens a note sealed to the old key only with the retained key", async () => {
    const holder = wallet(2);
    const next = ViewingKey.generate();
    const rotated = rotation(holder, next);
    const tx = ViewingKey.generate();
    const old = holder.viewingPublicKey();
    const plaintext = new TextEncoder().encode("old note");
    const request = {
      ciphertext: tx.encryptSlot(old, plaintext, SALT, 0),
      viewingPublicKey: old,
      txViewingPublicKey: tx.publicKey(),
      salt: SALT,
      slotIndex: 0,
      label: "transfer",
    } as const;
    expect(await rotated.keys.decrypt([request])).toEqual([plaintext]);

    const currentOnly = LocalRingKeys.fromKeys({
      address: rotated.keys.address(),
      viewingKeys: [next],
      listRoot: holder.viewingKey(),
      nullifierKey: holder.nullifierKey(),
    });
    await expect(currentOnly.decrypt([request])).rejects.toThrow();
  });

  it("refuses a holder of another nullifier key and one ahead of its history", async () => {
    const holder = wallet(3);
    const { client } = await enrolled(holder);
    const stranger = rotation(wallet(4), ViewingKey.generate());
    const input = { client, payer: PAYER, owner: OWNER, trackingRegistry: REGISTRY };
    await expect(
      updateViewingKey({ ...input, keys: stranger.keys, history: stranger.history }),
    ).rejects.toMatchObject({ code: "RING_ENROLLMENT_KEY_MISMATCH" });
    await expect(
      updateViewingKey({
        ...input,
        keys: LocalRingKeys.fromKeypair(holder).rotate(ViewingKey.generate()),
        history: ViewingHistory.create(holder.viewingPublicKey(), 0n),
      }),
    ).rejects.toMatchObject({ code: "RING_VIEWING_HISTORY_NOT_CURRENT" });
  });
});
