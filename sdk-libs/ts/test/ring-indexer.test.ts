import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  decodeRingKeyRegistryEntry,
  decodeRingKeyRegistryRegisterProof,
  decodeRingSpendRecordResponse,
  encodeRingMemberProofRequest,
} from "../src/indexer/codec.js";
import { indexerScalars, treeAddress, ZolanaApi } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana";
import { RingIndexer } from "../src/client/indexer.js";

const { hash } = indexerScalars;
// base58 of 32 zero bytes.
const TAG = hash("11111111111111111111111111111111");
const RING = address("8hcir6LNDXjqKSof1KV41SBZxGaEQFB3WTtcoYn3Atpg");

describe("ring spend record wire", () => {
  const output = {
    viewTag: TAG,
    outputContext: { hash: TAG, tree: treeAddress(7), treeId: 7, leafIndex: 3 },
    payload: "",
  };
  const transaction = {
    slot: 1,
    txSignature: "1".repeat(64),
    outputSlots: [output],
    messages: [],
    nullifiers: [],
    proofless: false,
  };
  const found = {
    context: { slot: 1, blockTime: 2 },
    record: { transaction, outputIndex: 0 },
  };

  it("accepts an unregistered member and requires the record output to exist", () => {
    expect(decodeRingSpendRecordResponse({ ...found, record: null })).toEqual({
      context: { slot: 1n, blockTime: 2n },
      record: null,
    });
    expect(decodeRingSpendRecordResponse(found).record?.outputIndex).toBe(0);
    for (const changed of [
      { record: { transaction, outputIndex: 1 } },
      { record: { transaction } },
      { record: undefined },
      { extra: true },
    ])
      expect(() => decodeRingSpendRecordResponse({ ...found, ...changed })).toThrow();
  });

  it("sends only the ring and member and converts the record transaction", async () => {
    const zero = new Uint8Array(32) as Bytes32;
    const requests: unknown[] = [];
    const indexerFor = (result: unknown) =>
      new RingIndexer(
        new ZolanaApi({
          url: "https://indexer.example",
          fetch: async (_url, init) => {
            requests.push(JSON.parse(String(init?.body)).params);
            return Response.json({ jsonrpc: "2.0", id: "test-account", result });
          },
        }),
      );
    const request = { ringProgramId: RING, member: zero };
    await expect(
      indexerFor({ ...found, record: null }).getRingSpendRecord(request),
    ).resolves.toMatchObject({ record: null });
    const lookup = await indexerFor(found).getRingSpendRecord(request);
    expect(lookup.record?.outputIndex).toBe(0);
    expect(lookup.record?.transaction.outputSlots[0]?.outputContext.tree).toBe(treeAddress(7));
    expect(requests).toEqual([
      { ringProgramId: RING, member: TAG },
      { ringProgramId: RING, member: TAG },
    ]);
  });

  it("bounds the key registry cursor at forty bits", () => {
    expect(
      encodeRingMemberProofRequest({
        ringProgramId: RING,
        member: TAG,
        expectedRoot: TAG,
        expectedNextIndex: 1n << 40n,
      }),
    ).toMatchObject({ expectedNextIndex: 2 ** 40 });
    expect(() =>
      encodeRingMemberProofRequest({
        ringProgramId: RING,
        member: TAG,
        expectedRoot: TAG,
        expectedNextIndex: (1n << 40n) + 1n,
      }),
    ).toThrow();
  });
});

describe("key registry wire", () => {
  const proof = {
    context: { slot: 1, blockTime: 2 },
    root: TAG,
    member: TAG,
    nextIndex: 1,
    lowMember: TAG,
    lowNext: TAG,
    lowKeyHash: TAG,
    lowIndex: 0,
    lowProof: Array.from({ length: 40 }, () => TAG),
    newProof: Array.from({ length: 40 }, () => TAG),
  };
  const entry = {
    context: { slot: 1, blockTime: 2 },
    root: TAG,
    member: TAG,
    nextIndex: 2,
    next: TAG,
    index: 1,
    ephPk: Buffer.from(
      "040900000000000000000000000000000000000000000000000000000000000000",
      "hex",
    ).toString("base64"),
    ciphertext: Buffer.alloc(32, 7).toString("base64"),
    proof: Array.from({ length: 40 }, () => TAG),
  };

  it("names the predecessor key hash and keeps the entry inside the cursor", () => {
    expect(decodeRingKeyRegistryRegisterProof(proof)).toMatchObject({ lowIndex: 0n });
    expect(() => decodeRingKeyRegistryRegisterProof({ ...proof, lowKey: TAG })).toThrow();
    expect(decodeRingKeyRegistryEntry(entry)).toMatchObject({ index: 1n, nextIndex: 2n });
    for (const changed of [{ index: 0 }, { index: 2 }, { proof: [] }, { ephPk: 3 }])
      expect(() => decodeRingKeyRegistryEntry({ ...entry, ...changed })).toThrow();
  });

  it("distinguishes every typed registry RPC failure and rejects a malformed entry", async () => {
    const zero = new Uint8Array(32) as Bytes32;
    const request = {
      ringProgramId: RING,
      member: zero,
      expectedRoot: zero,
      expectedNextIndex: 2n,
    };
    const indexerFor = (body: Readonly<Record<string, unknown>>) =>
      new RingIndexer(
        new ZolanaApi({
          url: "https://indexer.example",
          fetch: async () => Response.json({ jsonrpc: "2.0", id: "test-account", ...body }),
        }),
      );
    for (const [rpcCode, code] of [
      [-32070, "RING_KEY_REGISTRY_OUT_OF_SYNC"],
      [-32071, "RING_KEY_REGISTRY_ROOT_CHANGED"],
      [-32072, "RING_KEY_REGISTRY_MEMBER_UNREGISTERED"],
      [-32073, "RING_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED"],
      [-32074, "RING_SPEND_RECORD_OUT_OF_SYNC"],
    ] as const) {
      const indexer = indexerFor({ error: { code: rpcCode, message: "private diagnostics" } });
      await expect(indexer.getRingKeyRegistryEntry(request)).rejects.toMatchObject({ code });
      await expect(indexer.getRingKeyRegistryRegisterProof(request)).rejects.toMatchObject({
        code,
      });
    }
    const decoded = await indexerFor({ result: entry }).getRingKeyRegistryEntry(request);
    expect(decoded.ephemeralPublicKey.toBytes()[0]).toBe(0x04);
    expect(decoded.ciphertext).toEqual(new Uint8Array(32).fill(7));
    for (const changed of [
      { ciphertext: Buffer.alloc(31, 7).toString("base64") },
      { ephPk: Buffer.alloc(33, 9).toString("base64") },
      { nextIndex: 3 },
    ])
      await expect(
        indexerFor({ result: { ...entry, ...changed } }).getRingKeyRegistryEntry(request),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_RPC_RESPONSE" });
  });
});
