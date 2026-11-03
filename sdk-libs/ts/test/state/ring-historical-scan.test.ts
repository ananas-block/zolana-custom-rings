import { beforeAll, describe, expect, it } from "vitest";

import vector from "../../../../test-vectors/wallet/anonymous-bodies.json" with { type: "json" };
import { initializePoseidon, SOL_MINT } from "@heliuslabs/zolana";
import { encodeBase58 } from "@heliuslabs/zolana/internal";
import type { Address, Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import {
  ShieldedAddress,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
  X25519PublicKey,
  type Bytes34,
} from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  Wallet,
  type IndexedShieldedTransaction,
} from "@heliuslabs/zolana/transaction";

import { HistoricalScheme } from "../../src/protocol/historical/anonymous-body.js";
import { AnonymousSync } from "../../src/state/anonymous-sync.js";
import { AnonymousWallet } from "../../src/state/anonymous-wallet.js";
import { LocalRingKeys } from "../../src/state/ring-keys.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import { hex, ScanIndexer, signature } from "../helpers/ring-scan.js";

type Party = (typeof vector.recipients)[number];

const SLOT = 40n;
const HIDDEN = new Uint8Array(32).fill(0xd7);
const raw = (text: string): Uint8Array => Uint8Array.from(Buffer.from(text, "hex"));
const ring = encodeBase58(raw(vector.ring_program_id)) as Address;
const [mintRow] = vector.mints;
if (mintRow === undefined) throw new Error("no mint");
const mint = encodeBase58(raw(mintRow.asset)) as Address;
const [paid, shared] = vector.recipients;
if (paid === undefined || shared === undefined) throw new Error("no recipients");

function frame(scheme: HistoricalScheme, body: Uint8Array): Uint8Array {
  const framed = new Uint8Array(6 + body.length);
  framed[0] = 1;
  new DataView(framed.buffer).setUint32(1, 1 + body.length, true);
  framed[5] = scheme;
  framed.set(body, 6);
  return framed;
}

function assets(...named: readonly (readonly [bigint, Address])[]): AssetRegistry {
  const registry = new AssetRegistry();
  registry.register(1n, SOL_MINT);
  for (const [assetId, address] of named) registry.register(assetId, address);
  return registry;
}

function addressOf(party: Party): ShieldedAddress {
  return ShieldedAddress.fromPublicKeys(
    ShieldedPublicKey.fromBytes(raw(party.owner_pubkey) as Bytes34),
    raw(party.nullifier_pubkey) as Bytes32,
    X25519PublicKey.fromBytes(raw(party.viewing_pubkey) as Bytes33),
  );
}

function holderOf(party: Party): LocalRingKeys {
  const viewing = ViewingKey.fromBytes(raw(party.viewing_secret) as Bytes32);
  return LocalRingKeys.fromKeys({
    address: addressOf(party),
    viewingKeys: [viewing],
    nullifierKey: ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(raw(party.ed25519_seed) as Bytes32),
    ).nullifierKey(),
  });
}

function historyOf(party: Party): ViewingHistory {
  return ViewingHistory.create(addressOf(party).viewingPublicKey, 0n).withRing(ring);
}

function sealedRow(
  overrides: Partial<IndexedShieldedTransaction> = {},
): IndexedShieldedTransaction {
  return {
    slot: SLOT,
    txSignature: signature(91n),
    eventIndex: 0,
    txViewingPublicKey: X25519PublicKey.fromBytes(raw(vector.tx_viewing_pk) as Bytes33),
    salt: raw(vector.salt) as Bytes16,
    outputSlots: vector.outputs.map((output) => ({
      outputContext: {
        hash: raw(output.utxo_hash) as Bytes32,
        tree: ring,
        treeId: vector.tree_id,
        leafIndex: BigInt(output.position),
      },
      viewTag: HIDDEN as Bytes32,
      payload:
        output.ciphertext === null
          ? new Uint8Array(0)
          : frame(HistoricalScheme.anonymousRecipient, raw(output.ciphertext)),
    })),
    messages: [
      {
        viewTag: HIDDEN as Bytes32,
        data: frame(HistoricalScheme.anonymousSender, raw(vector.sender_bundle.ciphertext)),
      },
    ],
    nullifiers: [raw(vector.first_nullifier) as Bytes32],
    proofless: false,
    ringProgramId: ring,
    ...overrides,
  } as IndexedShieldedTransaction;
}

function published(row = sealedRow()): ScanIndexer {
  const indexer = new ScanIndexer();
  indexer.publish(row);
  return indexer;
}

describe("historical bodies on the routine scan", () => {
  beforeAll(initializePoseidon);

  it("finds a scheme 1 note under its reader's key at the output it rebuilds", async () => {
    const scan = await AnonymousSync.create(holderOf(paid), assets([2n, mint])).fetch(
      published().client(),
      historyOf(paid),
    );
    const opened = vector.outputs[1]?.opened;
    expect(scan.utxos.map((note) => [hex(note.outputContext.hash), note.utxo.amount])).toEqual([
      [vector.outputs[1]?.utxo_hash, BigInt(opened?.amount ?? 0)],
    ]);
    expect(scan.utxos[0]?.utxo.asset).toBe(mint);
    expect(scan.utxos[0]?.utxo.ringProgramId).toBe(ring);
    expect(scan.found[0]?.stream).toEqual({ kind: "historical" });
    expect(scan.history.current().ringPosition(ring)).toBeGreaterThanOrEqual(SLOT);
  });

  it("finds the scheme 2 change at output 0 under the sender's key, read past the outputs", async () => {
    const scan = await AnonymousSync.create(holderOf(vector.sender), assets([2n, mint])).fetch(
      published().client(),
      historyOf(vector.sender),
    );
    const [change] = vector.sender_bundle.change;
    expect(scan.utxos.map((note) => [hex(note.outputContext.hash), note.utxo.amount])).toEqual([
      [change?.rebuilt_hash, BigInt(change?.amount ?? 0)],
    ]);
    expect(scan.utxos[0]?.utxo.asset).toBe(SOL_MINT);
  });

  it("holds a note under an unregistered mint while the position moves, spendable once it registers", async () => {
    const indexer = published();
    const scan = await AnonymousSync.create(holderOf(paid), assets()).fetch(
      indexer.client(),
      historyOf(paid),
    );
    expect(scan.utxos).toEqual([]);
    expect(scan.unknownMints).toEqual([mint]);
    expect(scan.pendingOpenings.map((note) => hex(note.outputContext.hash))).toEqual([
      vector.outputs[1]?.utxo_hash,
    ]);
    expect(scan.history.current().ringPosition(ring)).toBeGreaterThanOrEqual(SLOT);

    const wallet = AnonymousWallet.create(
      new Wallet({ identity: addressOf(paid), registry: assets() }),
      historyOf(paid),
    );
    await wallet.absorb(scan);
    expect(wallet.notes()).toEqual([]);
    const reads = indexer.ringReads.length;
    wallet.wallet.ensureAsset(2n, mint);
    expect((await wallet.promotePending()).map((note) => note.utxo.asset)).toEqual([mint]);
    expect(wallet.pendingOpenings()).toEqual([]);
    expect(indexer.ringReads).toHaveLength(reads);
  });

  it("finds a scheme 1 note on a recovery", async () => {
    const scan = await AnonymousSync.create(holderOf(shared), assets([2n, mint])).fullScan(
      published().client(),
      historyOf(shared),
      ring,
    );
    expect(scan.utxos.map((note) => hex(note.outputContext.hash))).toEqual([
      vector.outputs[2]?.utxo_hash,
    ]);
    expect(scan.found[0]?.stream).toEqual({ kind: "historical" });
  });

  it("keeps no note from a tampered commitment and moves on", async () => {
    const tampered = sealedRow();
    const moved = {
      ...tampered,
      outputSlots: tampered.outputSlots.map((slot) => ({
        ...slot,
        outputContext: { ...slot.outputContext, hash: new Uint8Array(32).fill(1) as Bytes32 },
      })),
    };
    const stale = await AnonymousSync.create(holderOf(paid), assets([2n, mint])).fetch(
      published(moved).client(),
      historyOf(paid),
    );
    expect(stale.utxos).toEqual([]);
    expect(stale.pendingOpenings).toEqual([]);
    expect(stale.history.current().ringPosition(ring)).toBeGreaterThanOrEqual(SLOT);
  });

  it("reads past a hostile row whose scheme 1 and 2 bodies are empty", async () => {
    const row = sealedRow();
    const [first] = row.outputSlots;
    if (first === undefined) throw new Error("no slot");
    const hostile = sealedRow({
      txSignature: signature(92n),
      outputSlots: [
        {
          ...first,
          payload: frame(HistoricalScheme.anonymousRecipient, new Uint8Array(0)),
        },
      ],
      messages: [
        {
          viewTag: HIDDEN as Bytes32,
          data: frame(HistoricalScheme.anonymousSender, new Uint8Array(0)),
        },
      ],
    });
    const indexer = published(hostile);
    indexer.publish(row);
    const scan = await AnonymousSync.create(holderOf(paid), assets([2n, mint])).fetch(
      indexer.client(),
      historyOf(paid),
    );
    expect(scan.utxos.map((note) => hex(note.outputContext.hash))).toEqual([
      vector.outputs[1]?.utxo_hash,
    ]);
  });

  it("refuses the scan when the holder cannot decrypt", async () => {
    const holder = holderOf(paid);
    const refusing = new Proxy(holder, {
      get(target, property) {
        if (property === "decrypt") return () => Promise.reject(new Error("holder offline"));
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await expect(
      AnonymousSync.create(refusing, assets([2n, mint])).fetch(
        published().client(),
        historyOf(paid),
      ),
    ).rejects.toThrow("holder offline");
  });
});
