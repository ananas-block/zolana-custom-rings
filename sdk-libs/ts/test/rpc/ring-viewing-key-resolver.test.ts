import { address, getAddressEncoder, getProgramDerivedAddress, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { USER_REGISTRY_PROGRAM_ID, type Bytes32 } from "@heliuslabs/zolana/interface";
import { ShieldedKeypair, SigningKey } from "@heliuslabs/zolana/keypair";

import { resolveViewingKey, type ViewingKeyClient } from "../../src/rpc/viewing-key-resolver.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";

const OWNER = address("7xKqmYUZ7pQHXcQnaZaZzR1oPjQb8kk8gA7XN3XxKzKq");
const OTHER = address("3DzKPyV33som4oRrXKA46xe47cQryGN7AdkYXA3wg2WP");
const addressEncoder = getAddressEncoder();

const holder = (seed: number) =>
  ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );

/** Derived apart from zolana so a drifted seed fails here. */
async function canonicalPda(owner: Address) {
  const [pda, bump] = await getProgramDerivedAddress({
    programAddress: USER_REGISTRY_PROGRAM_ID,
    seeds: [new TextEncoder().encode("zolana/registry/v0"), addressEncoder.encode(owner)],
  });
  return { pda, bump };
}

type RecordFields = Readonly<{
  owner: Address;
  bump: number;
  nullifierPublicKey: Uint8Array;
  viewingPublicKey: Uint8Array;
}>;

function recordData(fields: RecordFields): Uint8Array {
  const data = new Uint8Array(100);
  data[0] = 1;
  data.set(addressEncoder.encode(fields.owner), 1);
  data[33] = fields.bump;
  data.set(fields.nullifierPublicKey, 34);
  data.set(fields.viewingPublicKey, 66);
  return data;
}

async function chain(
  overrides: Partial<RecordFields> & Readonly<{ program?: Address; data?: Uint8Array }> = {},
) {
  const wallet = holder(7);
  const { pda, bump } = await canonicalPda(OWNER);
  const data =
    overrides.data ??
    recordData({
      owner: overrides.owner ?? OWNER,
      bump: overrides.bump ?? bump,
      nullifierPublicKey: overrides.nullifierPublicKey ?? wallet.nullifierPublicKey(),
      viewingPublicKey: overrides.viewingPublicKey ?? wallet.viewingPublicKey().toBytes(),
    });
  const reads: Address[] = [];
  const client: ViewingKeyClient = {
    getAccount: async (read) => {
      reads.push(read);
      if (read !== pda) return undefined;
      return { owner: overrides.program ?? USER_REGISTRY_PROGRAM_ID, data, lamports: 1n };
    },
  };
  return { client, reads, pda, bump, wallet };
}

function walletRefusal(causeCode: string) {
  return expect.objectContaining({ code: "WALLET_FETCH_USER_RECORD", causeCode });
}

describe("resolveViewingKey", () => {
  it("returns the record's keys from one read of the canonical PDA", async () => {
    const { client, reads, pda, wallet } = await chain();
    const resolved = await resolveViewingKey({
      client,
      owner: OWNER,
      nullifierPublicKey: wallet.nullifierPublicKey(),
    });
    expect(reads).toEqual([pda]);
    expect(resolved?.viewingPublicKey.equals(wallet.viewingPublicKey())).toBe(true);
    expect(resolved?.nullifierPublicKey).toEqual(wallet.nullifierPublicKey());
  });

  it("reports a missing record as undefined", async () => {
    const { client } = await chain();
    expect(await resolveViewingKey({ client, owner: OTHER })).toBeUndefined();
  });

  it("throws on an RPC failure rather than report a missing record", async () => {
    const client: ViewingKeyClient = {
      getAccount: async () => {
        throw new Error("transport");
      },
    };
    await expect(resolveViewingKey({ client, owner: OWNER })).rejects.toMatchObject({
      code: "WALLET_FETCH_USER_RECORD",
    });
  });

  it("refuses a stored bump other than the canonical one", async () => {
    const { bump } = await canonicalPda(OWNER);
    const { client } = await chain({ bump: bump - 1 });
    await expect(resolveViewingKey({ client, owner: OWNER })).rejects.toEqual(
      walletRefusal("WALLET_USER_RECORD_BUMP_MISMATCH"),
    );
  });

  it("refuses a record a foreign program owns", async () => {
    const { client } = await chain({ program: OTHER });
    await expect(resolveViewingKey({ client, owner: OWNER })).rejects.toEqual(
      walletRefusal("WALLET_USER_RECORD_PROGRAM_MISMATCH"),
    );
  });

  it("refuses a record with another discriminator", async () => {
    const data = recordData({
      owner: OWNER,
      bump: (await canonicalPda(OWNER)).bump,
      nullifierPublicKey: holder(7).nullifierPublicKey(),
      viewingPublicKey: holder(7).viewingPublicKey().toBytes(),
    });
    data[0] = 2;
    const { client } = await chain({ data });
    await expect(resolveViewingKey({ client, owner: OWNER })).rejects.toEqual(
      walletRefusal("WALLET_INVALID_USER_RECORD"),
    );
  });

  it("refuses a stored owner other than the one asked for", async () => {
    const { client } = await chain({ owner: OTHER });
    await expect(resolveViewingKey({ client, owner: OWNER })).rejects.toEqual(
      walletRefusal("WALLET_USER_RECORD_OWNER_MISMATCH"),
    );
  });

  it("refuses a viewing key without the 0x04 tag", async () => {
    const key = holder(7).viewingPublicKey().toBytes();
    key[0] = 2;
    const { client } = await chain({ viewingPublicKey: key });
    await expect(resolveViewingKey({ client, owner: OWNER })).rejects.toMatchObject({
      code: "RING_NONCANONICAL_VIEWING_KEY",
    });
  });

  it("refuses a viewing key whose u is not below the field modulus", async () => {
    const modulus = new Uint8Array(33);
    modulus[0] = 4;
    modulus.set([0xed, ...new Uint8Array(30).fill(0xff), 0x7f], 1);
    const { client } = await chain({ viewingPublicKey: modulus });
    await expect(resolveViewingKey({ client, owner: OWNER })).rejects.toMatchObject({
      code: "RING_NONCANONICAL_VIEWING_KEY",
    });
  });

  it("refuses a record whose nullifier key differs from the credential's", async () => {
    const { client } = await chain();
    await expect(
      resolveViewingKey({
        client,
        owner: OWNER,
        nullifierPublicKey: holder(8).nullifierPublicKey(),
      }),
    ).rejects.toMatchObject({ code: "RING_NULLIFIER_KEY_MISMATCH" });
  });

  it("returns the rotated key while the history keeps the old one", async () => {
    const wallet = holder(7);
    const rotated = holder(8).viewingPublicKey();
    const { client } = await chain({ viewingPublicKey: rotated.toBytes() });
    const resolved = await resolveViewingKey({
      client,
      owner: OWNER,
      nullifierPublicKey: wallet.nullifierPublicKey(),
    });
    if (resolved === undefined) throw new Error("registered");
    expect(resolved.viewingPublicKey.equals(rotated)).toBe(true);
    const history = ViewingHistory.create(wallet.viewingPublicKey(), 1n).withRotatedKey(
      resolved.viewingPublicKey,
      2n,
    );
    expect(history.current().viewingPublicKey.equals(rotated)).toBe(true);
    expect(history.entry(wallet.viewingPublicKey())).toBeDefined();
  });
});
