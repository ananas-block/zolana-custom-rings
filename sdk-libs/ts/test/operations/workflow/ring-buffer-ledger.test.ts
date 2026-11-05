import type { Signature } from "@solana/kit";
import { expect, it } from "vitest";

import {
  RingBufferLedger,
  type RingBufferTransaction,
} from "../../../src/operations/workflow/buffer-ledger.js";

const ID = "0123456789abcdef0123456789abcdef";
const OLDER = "1".repeat(64) as Signature;
const NEWER = "2".repeat(88) as Signature;
const ENTRY = { submission: ID, phase: "close", signature: OLDER, lastValidBlockHeight: "7" };

function storeOf(document?: string) {
  let stored = document;
  return {
    load: async () => stored,
    save: async (next: string) => {
      stored = next;
    },
  };
}

it("reads back what it saved and keeps a newer transaction of the same submission", async () => {
  const store = storeOf();
  const ledger = await RingBufferLedger.load(store);
  const older: RingBufferTransaction = {
    submission: ID,
    phase: "write",
    signature: OLDER,
    lastValidBlockHeight: 5n,
  };
  await ledger._hold(older);
  await ledger._hold({ ...older, phase: "close", signature: NEWER, lastValidBlockHeight: 9n });
  await ledger._settle(older);
  expect((await RingBufferLedger.load(store)).entries()).toEqual([
    { submission: ID, phase: "close", signature: NEWER, lastValidBlockHeight: 9n },
  ]);
});

it("saves again after a failed save even when the next change finds nothing to drop", async () => {
  const store = storeOf();
  const ledger = await RingBufferLedger.load(store);
  await ledger._hold({
    submission: ID,
    phase: "write",
    signature: OLDER,
    lastValidBlockHeight: 5n,
  });
  const save = store.save;
  store.save = async () => {
    throw new Error("disk unavailable");
  };
  await expect(ledger._drop(ID)).rejects.toThrow("disk unavailable");
  store.save = save;
  await ledger._drop(ID);
  expect((await RingBufferLedger.load(store)).entries()).toEqual([]);
});

it("reads the entry every refusal below changes in one field", async () => {
  const ledger = await RingBufferLedger.load(
    storeOf(JSON.stringify({ version: 1, entries: [ENTRY] })),
  );
  expect(ledger.entries()).toEqual([{ ...ENTRY, lastValidBlockHeight: 7n }]);
});

it.each([
  ["not JSON", "{"],
  ["another version", JSON.stringify({ version: 2, entries: [] })],
  ["another field", JSON.stringify({ version: 1, entries: [], extra: 1 })],
  ["an unknown phase", JSON.stringify({ version: 1, entries: [{ ...ENTRY, phase: "settle" }] })],
  [
    "a signature of 88 zero bytes",
    JSON.stringify({ version: 1, entries: [{ ...ENTRY, signature: "1".repeat(88) }] }),
  ],
  ["a short id", JSON.stringify({ version: 1, entries: [{ ...ENTRY, submission: "ab" }] })],
  [
    "a lifetime past u64",
    JSON.stringify({
      version: 1,
      entries: [{ ...ENTRY, lastValidBlockHeight: "18446744073709551616" }],
    }),
  ],
  ["one submission twice", JSON.stringify({ version: 1, entries: [ENTRY, ENTRY] })],
])("refuses a ledger with %s", async (_, document) => {
  await expect(RingBufferLedger.load(storeOf(document))).rejects.toMatchObject({
    code: "RING_WALLET_DOCUMENT",
  });
});
