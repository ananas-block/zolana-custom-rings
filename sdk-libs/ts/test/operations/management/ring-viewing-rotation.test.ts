import { getAddressEncoder, getProgramDerivedAddress, address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { USER_REGISTRY_PROGRAM_ID, type Bytes16, type Bytes32 } from "@heliuslabs/zolana/interface";
import { ShieldedKeypair, SigningKey, ViewingKey } from "@heliuslabs/zolana/keypair";

import {
  confirmViewingKey,
  rotateViewingKey,
  updateViewingKey,
  type ViewingKeyUpdateClient,
} from "../../../src/operations/management/viewing-rotation.js";
import { LocalRingKeys } from "../../../src/state/ring-keys.js";
import { ViewingHistory } from "../../../src/state/viewing-history.js";

const OWNER = address("7xKqmYUZ7pQHXcQnaZaZzR1oPjQb8kk8gA7XN3XxKzKq");
const SALT = new Uint8Array(16).fill(5) as Bytes16;

const wallet = (seed: number) =>
  ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );

/** One user record of `OWNER`, `land` sets its viewing key. */
async function registry(holder: ShieldedKeypair) {
  const [pda, bump] = await getProgramDerivedAddress({
    programAddress: USER_REGISTRY_PROGRAM_ID,
    seeds: [new TextEncoder().encode("zolana/registry/v0"), getAddressEncoder().encode(OWNER)],
  });
  const data = new Uint8Array(100);
  data[0] = 1;
  data.set(getAddressEncoder().encode(OWNER), 1);
  data[33] = bump;
  data.set(holder.nullifierPublicKey(), 34);
  data.set(holder.viewingPublicKey().toBytes(), 66);
  const client: ViewingKeyUpdateClient = {
    getAccount: async (read) =>
      read === pda
        ? { owner: USER_REGISTRY_PROGRAM_ID, data: data.slice(), lamports: 1n }
        : undefined,
    getLatestBlockhash: async () => ({
      blockhash: "11111111111111111111111111111111" as never,
      lastValidBlockHeight: 1n,
    }),
  };
  const land = (viewingPublicKey: Uint8Array) => data.set(viewingPublicKey, 66);
  return { client, land };
}

function rotation(holder: ShieldedKeypair, next: ViewingKey) {
  return rotateViewingKey({
    keys: LocalRingKeys.fromKeypair(holder),
    history: ViewingHistory.create(holder.viewingPublicKey(), 0n),
    next,
    rotatedAt: 1n,
  });
}

const contains = (haystack: ArrayLike<number>, needle: Uint8Array) =>
  Buffer.from(haystack).includes(Buffer.from(needle));

describe("viewing key rotation", () => {
  it("resolves the new key once the update lands, and a repeat builds nothing", async () => {
    const holder = wallet(1);
    const { client, land } = await registry(holder);
    const rotated = rotation(holder, ViewingKey.generate());
    const current = rotated.keys.address().viewingPublicKey;
    const update = () =>
      updateViewingKey({ client, owner: OWNER, keys: rotated.keys, history: rotated.history });

    const transaction = await update();
    expect(transaction).toBeDefined();
    expect(contains(transaction!.messageBytes, current.toBytes())).toBe(true);
    await expect(
      confirmViewingKey({ client, owner: OWNER, keys: rotated.keys }),
    ).rejects.toMatchObject({ code: "RING_VIEWING_KEY_NOT_PUBLISHED" });

    land(current.toBytes());
    const resolved = await confirmViewingKey({ client, owner: OWNER, keys: rotated.keys });
    expect(resolved.viewingPublicKey.equals(current)).toBe(true);
    expect(rotated.history.current().viewingPublicKey.equals(current)).toBe(true);
    expect(rotated.history.entry(holder.viewingPublicKey())).toBeDefined();
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

  it("refuses a rotation under another nullifier key before any transaction", async () => {
    const { client } = await registry(wallet(3));
    const stranger = rotation(wallet(4), ViewingKey.generate());
    await expect(
      updateViewingKey({ client, owner: OWNER, keys: stranger.keys, history: stranger.history }),
    ).rejects.toMatchObject({
      code: "WALLET_BUILD_KEY_UPDATE",
      causeCode: "WALLET_USER_RECORD_NULLIFIER_KEY_MISMATCH",
    });
  });

  it("refuses a holder ahead of its history before any transaction", async () => {
    const holder = wallet(5);
    const { client } = await registry(holder);
    await expect(
      updateViewingKey({
        client,
        owner: OWNER,
        keys: LocalRingKeys.fromKeypair(holder).rotate(ViewingKey.generate()),
        history: ViewingHistory.create(holder.viewingPublicKey(), 0n),
      }),
    ).rejects.toMatchObject({ code: "RING_VIEWING_HISTORY_NOT_CURRENT" });
  });
});
