import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

import { rolldown } from "rolldown";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import {
  answerScanRequest,
  plainTagFrame,
  scanWorkerMatcher,
  type PlainTagFrame,
  type ScanWorkerReply,
} from "../../src/state/anonymous-scan.js";
import { AnonymousSync } from "../../src/state/anonymous-sync.js";
import type { RingTagFrame } from "../../src/state/ring-keys.js";
import {
  ASSETS,
  found,
  hex,
  output,
  ScanIndexer,
  ScanWallet,
  type SealedTransfer,
} from "../helpers/ring-scan.js";

await initializePoseidon();

const core = fileURLToPath(new URL("../../../../zolana/sdk-libs/ts/src/", import.meta.url));

/** vitest transforms no worker thread, the entry runs as the bundle a package consumer gets. */
async function bundledEntry(directory: string): Promise<string> {
  const build = await rolldown({
    input: fileURLToPath(new URL("../../src/state/anonymous-scan-worker.ts", import.meta.url)),
    platform: "node",
    resolve: {
      alias: {
        "@heliuslabs/zolana/internal": `${core}internal.ts`,
        "@heliuslabs/zolana/interface": `${core}interface/index.ts`,
        "@heliuslabs/zolana/keypair": `${core}keypair/index.ts`,
        "@heliuslabs/zolana/transaction": `${core}transaction/index.ts`,
        "@heliuslabs/zolana/client": `${core}client/index.ts`,
        "@heliuslabs/zolana": `${core}index.ts`,
      },
    },
  });
  const file = join(directory, "scan-worker.mjs");
  await build.write({ file, format: "esm" });
  await build.close();
  return file;
}

function frameOf(tx: SealedTransfer, reader: ScanWallet): RingTagFrame {
  const { txViewingPublicKey, salt, nullifiers } = tx;
  const [firstNullifier] = nullifiers;
  if (txViewingPublicKey === undefined || salt === undefined || firstNullifier === undefined)
    throw new Error("no slot context");
  return {
    viewingPublicKey: reader.viewingKey,
    txViewingPublicKey,
    salt,
    firstNullifier,
    probes: [
      ...tx.outputSlots.flatMap((slot, outputIndex) =>
        slot.payload.length === 0
          ? []
          : [{ kind: "recipient" as const, outputIndex, tag: slot.viewTag }],
      ),
      ...tx.messages.map((message) => ({
        kind: "senderBundle" as const,
        outputIndex: tx.outputSlots.length,
        tag: message.viewTag,
      })),
    ],
  };
}

describe("scan worker", () => {
  let directory: string;
  let entry: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "ring-scan-worker-"));
    entry = await bundledEntry(directory);
  }, 120_000);

  afterAll(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  function ask(viewingSecret: Bytes32, frames: readonly PlainTagFrame[]) {
    const worker = new Worker(entry);
    return new Promise<ScanWorkerReply>((resolve, reject) => {
      worker.once("message", (reply: ScanWorkerReply) => resolve(reply));
      worker.once("error", reject);
      worker.postMessage({ viewingSecret, frames });
    }).finally(() => worker.terminate());
  }

  it("answers the candidate step in a worker thread as on the holder", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const frames = [
      alice.seal(indexer, [{ to: bob.address, amount: 1n }]),
      alice.seal(indexer, [{ to: new ScanWallet(3).address, amount: 2n }]),
    ].map((tx) => frameOf(tx, bob));
    const onHolder = await bob.keys.ringTagMatches(frames);
    expect(onHolder[0]?.some((answer) => answer !== undefined)).toBe(true);
    expect(onHolder[1]?.every((answer) => answer === undefined)).toBe(true);
    const reply = await ask(bob.keypair.viewingKey().secretBytes(), frames.map(plainTagFrame));
    expect(reply).toEqual(onHolder);
  });

  it("finds the same notes when a scan's tag test leaves for the worker", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const paid = await alice.pay(indexer, [{ to: bob.address, amount: 9n }]);
    const scan = await AnonymousSync.create(bob.keys, ASSETS)
      .withTagMatcher(
        scanWorkerMatcher((_, frames) => ask(bob.keypair.viewingKey().secretBytes(), frames)),
      )
      .fetch(indexer.client(), bob.fresh());
    expect(found(scan)).toEqual([hex(output(paid, 1))]);
  });

  it("wipes the request's secret once answered", async () => {
    const bob = new ScanWallet(2);
    const viewingSecret = bob.keypair.viewingKey().secretBytes();
    await answerScanRequest({ viewingSecret, frames: [] });
    expect(viewingSecret.every((byte) => byte === 0)).toBe(true);
  });
});
