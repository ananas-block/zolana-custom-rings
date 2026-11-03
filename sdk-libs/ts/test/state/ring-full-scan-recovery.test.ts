import { getBase58Decoder, type Signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes16, Bytes32 } from "@heliuslabs/zolana/interface";
import { randomSalt, ShieldedAddress, ViewingKey, type ViewTag } from "@heliuslabs/zolana/keypair";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
  mergeOutputBlinding,
  mergeOutputKey,
} from "@heliuslabs/zolana/internal";
import { SOL_MINT, Utxo, type IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";

import { deliveredSlotSecret } from "../../src/crypto/derivation/ring-stream.js";
import { sealRecipientBody } from "../../src/protocol/codec/anonymous-delivery.js";
import { encodeRingOutput, RingScheme } from "../../src/protocol/transaction/output.js";
import { AnonymousSync } from "../../src/state/anonymous-sync.js";
import { LocalRingKeys } from "../../src/state/ring-keys.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import { TREE, TREE_ID, randomAddress } from "../helpers/ring-pipeline.js";
import {
  ASSETS,
  depositRow,
  depositTransaction,
  field,
  found,
  hex,
  keypair,
  output,
  RING,
  ScanIndexer,
  ScanWallet,
} from "../helpers/ring-scan.js";

await initializePoseidon();

function randomTag(): ViewTag {
  return globalThis.crypto.getRandomValues(new Uint8Array(32)) as ViewTag;
}

/** Every published tag replaced, a live proof refuses the frame. */
function underWrongTags(tx: IndexedShieldedTransaction): IndexedShieldedTransaction {
  return {
    ...tx,
    outputSlots: tx.outputSlots.map((slot) => ({ ...slot, viewTag: randomTag() })),
    messages: tx.messages.map((message) => ({ ...message, viewTag: randomTag() })),
  };
}

function recover(
  wallet: ScanWallet,
  indexer: ScanIndexer,
  options: Readonly<{ pageSize?: number; maxPages?: number }> = {},
) {
  return AnonymousSync.create(wallet.keys, ASSETS)
    .withScanLimits(options)
    .fullScan(indexer.client(), ViewingHistory.create(wallet.viewingKey, 0n), RING);
}

describe("full scan recovery", () => {
  it("finds a note under a wrong tag only in recovery", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const wrong = underWrongTags(alice.seal(indexer, [{ to: bob.address, amount: 30n }]));
    indexer.publish(wrong);
    expect((await bob.sync(indexer, bob.fresh())).utxos).toEqual([]);
    expect((await alice.sync(indexer, alice.fresh())).utxos).toEqual([]);
    const recovered = await recover(bob, indexer);
    expect(found(recovered)).toEqual([hex(output(wrong, 1))]);
    expect(recovered.found[0]?.stream).toEqual({ kind: "fullScan" });
    expect((await recover(alice, indexer)).utxos.map((note) => note.utxo.amount)).toEqual([70n]);
  });

  it("recovers a body and a bundle under wrong tags, under a retired key too", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = keypair(2);
    const retired = keypair(3);
    const bobRetired = ShieldedAddress.fromPublicKeys(
      bob.shieldedAddress().signingPublicKey,
      bob.shieldedAddress().nullifierPublicKey,
      retired.shieldedAddress().viewingPublicKey,
    );
    const tx = underWrongTags(
      alice.seal(indexer, [
        { to: bob.shieldedAddress(), amount: 30n },
        { to: bobRetired, amount: 20n },
      ]),
    );
    indexer.publish(tx);

    const sender = await recover(alice, indexer);
    expect(sender.found.map(({ utxoHash, stream }) => [hex(utxoHash), stream])).toEqual([
      [hex(output(tx, 0)), { kind: "fullScan" }],
    ]);
    expect(sender.utxos.map((note) => note.utxo.amount)).toEqual([50n]);
    expect(sender.sent.map((row) => [row.position, row.amount, row.check])).toEqual([
      [1, 30n, { kind: "unverified" }],
      [2, 20n, { kind: "unverified" }],
    ]);

    const holder = LocalRingKeys.fromKeys({
      address: bob.shieldedAddress(),
      viewingKeys: [bob.viewingKey(), retired.viewingKey()],
      nullifierKey: bob.nullifierKey(),
    });
    const recipient = await AnonymousSync.create(holder, ASSETS).fullScan(
      indexer.client(),
      ViewingHistory.create(bob.viewingKey().publicKey(), 0n).withRotatedKey(
        retired.viewingKey().publicKey(),
        1n,
      ),
      RING,
    );
    expect(recipient.utxos.map((note) => note.utxo.amount)).toEqual([30n, 20n]);
    expect(recipient.found.map(({ viewingPublicKey }) => viewingPublicKey.u())).toEqual([
      bob.viewingKey().publicKey().u(),
      retired.viewingKey().publicKey().u(),
    ]);
    expect(recipient.sent).toEqual([]);

    const stranger = await recover(new ScanWallet(4), indexer);
    expect(stranger.utxos).toEqual([]);
    expect(stranger.spentNullifiers).toEqual([]);
  });

  it("takes every row once across a page split inside one slot and a repeated row", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    const rows = [
      await alice.pay(indexer, [{ to: bob.address, amount: 1n }], { slot: 10n }),
      await alice.pay(indexer, [{ to: bob.address, amount: 2n }], { slot: 10n }),
      await alice.pay(indexer, [{ to: bob.address, amount: 3n }], { slot: 10n }),
    ];
    indexer.contexts.push(10n, 10n, 12n);
    const recovered = await recover(bob, indexer, { pageSize: 1 });
    expect(indexer.ringReads).toHaveLength(3);
    expect([...found(recovered)].sort()).toEqual(rows.map((row) => hex(output(row, 1))).sort());
    expect(recovered.history.entry(bob.viewingKey)?.ringPosition(RING)).toBe(12n);
  });

  it("reads from the start and leaves the position alone past a capped read, a restart finds the rest", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    for (const amount of [1n, 2n])
      await alice.pay(indexer, [{ to: bob.address, amount }], { slot: 10n + amount });
    const capped = await recover(bob, indexer, { pageSize: 1, maxPages: 1 });
    expect(capped.utxos.map((note) => note.utxo.amount)).toEqual([1n]);
    expect(capped.history.current().ringPosition(RING)).toBeUndefined();
    const restarted = await recover(bob, indexer);
    expect(restarted.utxos.map((note) => note.utxo.amount)).toEqual([1n, 2n]);
    expect(indexer.ringReads.at(-1)?.filters).toBeUndefined();
  });

  it("recovers change and no-change bundles", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 100n }]);
    await alice.pay(indexer, [{ to: bob.address, amount: 40n }]);
    const recovered = await recover(alice, indexer);
    expect(recovered.utxos.map((note) => note.utxo.amount)).toEqual([0n, 60n]);
    expect(recovered.sent.map((row) => row.amount)).toEqual([100n, 40n]);
  });

  it("opens deposits by trial on proofless rows, whatever their tag", async () => {
    const indexer = new ScanIndexer();
    const bob = new ScanWallet(2);
    const row = depositRow(bob.address, randomTag(), true, field(7, 1));
    indexer.publish(depositTransaction(row, 5n));
    const other = depositRow(new ScanWallet(3).address, randomTag(), true, field(7, 2));
    indexer.publish(depositTransaction(other, 6n));
    const recovered = await recover(bob, indexer);
    expect(recovered.found.map((note) => [hex(note.utxoHash), note.stream])).toEqual([
      [hex(row.outputSlot.outputContext.hash), { kind: "fullScan" }],
    ]);
    expect(recovered.utxos.map((note) => note.utxo.amount)).toEqual([25n]);
  });

  it("opens merges and resolves spends locally from the same pages", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    await alice.pay(indexer, [{ to: bob.address, amount: 70n }], { slot: 5n });
    await alice.pay(indexer, [{ to: bob.address, amount: 30n }], { slot: 6n });
    const held = await recover(bob, indexer);
    const nullifiers = held.utxos.map((utxo) => utxo.nullifier);
    const [first] = nullifiers;
    if (first === undefined) throw new Error("no notes");
    const nullifierKey = bob.keypair.nullifierKey();
    const merged = new Utxo({
      owner: bob.address.signingPublicKey,
      asset: SOL_MINT,
      amount: 100n,
      blinding: mergeOutputBlinding(nullifierKey, first),
      ringProgramId: RING,
    });
    const mergedHash = merged.hash(bob.address.nullifierPublicKey, TREE_ID);
    const salt = new Uint8Array(16).fill(8) as Bytes16;
    indexer.publish({
      slot: 7n,
      txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(0x99)) as Signature,
      eventIndex: 0,
      outputSlots: [
        {
          viewTag: first,
          outputContext: {
            hash: mergedHash,
            tree: TREE,
            treeId: TREE_ID,
            leafIndex: indexer.leaves(1),
          },
          payload: encodeMergeOutputData({
            salt,
            ciphertext: encryptMergeOutput(
              { amount: 100n, mint: SOL_MINT },
              mergeOutputKey(nullifierKey, first),
              salt,
            ),
            ringDataHash: new Uint8Array(32) as Bytes32,
          }),
        },
      ],
      messages: [],
      nullifiers,
      proofless: false,
      ringProgramId: RING,
    });
    const byNullifier = vi.fn();
    const recovered = await AnonymousSync.create(bob.keys, ASSETS).fullScan(
      { ...indexer.client(), getShieldedTransactionsByNullifiers: byNullifier },
      ViewingHistory.create(bob.viewingKey, 0n),
      RING,
    );
    expect(byNullifier).not.toHaveBeenCalled();
    expect(recovered.found.at(-1)?.stream).toEqual({ kind: "merge", firstNullifier: first });
    expect(recovered.utxos.filter((utxo) => !utxo.spent).map((utxo) => utxo.utxo.amount)).toEqual([
      100n,
    ]);
    expect(recovered.spentNullifiers.map(hex).sort()).toEqual(nullifiers.map(hex).sort());
  });

  it("finds what a tag scan finds on one history", async () => {
    const indexer = new ScanIndexer();
    const alice = new ScanWallet(1);
    const bob = new ScanWallet(2);
    for (const amount of [11n, 12n, 13n]) await alice.pay(indexer, [{ to: bob.address, amount }]);
    const scan = await bob.sync(indexer, bob.fresh());
    const recovered = await recover(bob, indexer);
    expect(found(recovered)).toEqual(found(scan));
    const change = await alice.sync(indexer, alice.fresh());
    expect(found(await recover(alice, indexer))).toEqual(found(change));
  });

  it("names a rebuilt mint the registry lacks and leaves its note out", async () => {
    const bob = new ScanWallet(2);
    const indexer = new ScanIndexer();
    const mint = randomAddress();
    const txKey = ViewingKey.generate();
    const salt = randomSalt();
    const firstNullifier = new Uint8Array(32).fill(0x0f) as Bytes32;
    const blinding = new Uint8Array(32).fill(0x12) as Bytes32;
    const { address } = bob;
    const agreement = txKey.ecdh(address.viewingPublicKey);
    const body = sealRecipientBody(
      deliveredSlotSecret({
        agreement,
        txViewingKey: txKey.publicKey(),
        recipientViewingKey: address.viewingPublicKey,
        salt,
        outputIndex: 0,
        firstNullifier,
      }),
      { blinding, amount: 7n, mint },
    );
    const hash = new Utxo({
      owner: address.signingPublicKey,
      asset: mint,
      amount: 7n,
      blinding,
      ringProgramId: RING,
    }).hash(address.nullifierPublicKey, TREE_ID);
    indexer.publish({
      slot: 1n,
      txSignature: getBase58Decoder().decode(new Uint8Array(64).fill(0x5b)) as Signature,
      eventIndex: 0,
      txViewingPublicKey: txKey.publicKey(),
      salt,
      outputSlots: [
        {
          viewTag: randomTag(),
          outputContext: { hash, tree: TREE, treeId: TREE_ID, leafIndex: 0n },
          payload: encodeRingOutput(RingScheme.ringRecipientBody, body),
        },
      ],
      messages: [],
      nullifiers: [firstNullifier],
      proofless: false,
      ringProgramId: RING,
    });
    const recovered = await recover(bob, indexer);
    expect(recovered.utxos).toEqual([]);
    expect(recovered.pendingOpenings.map((note) => note.utxo.amount)).toEqual([7n]);
    expect(recovered.unknownMints).toEqual([mint]);
    expect(recovered.unmatched.map(hex)).toEqual([hex(hash)]);
  });
});
