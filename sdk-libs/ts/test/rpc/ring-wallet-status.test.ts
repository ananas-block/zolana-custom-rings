import { address, getBase58Decoder, generateKeyPairSigner, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "@heliuslabs/zolana/interface";

import {
  RingRpc,
  spendCoverageAttestation,
  walletStatusAttestation,
  type RingReadSigner,
  type RingReadTarget,
} from "../../src/rpc/ring-rpc.js";

const base58 = getBase58Decoder();
const addressOf = (value: number): Address =>
  base58.decode(new Uint8Array(32).fill(value)) as Address;
const hashOf = (value: number): string => base58.decode(new Uint8Array(32).fill(value));
const SIGNATURE = base58.decode(new Uint8Array(64).fill(9));
const NONCE = new Uint8Array(32).fill(4) as Bytes32;
const TARGET: RingReadTarget = {
  cluster: new Uint8Array(32).fill(1) as Bytes32,
  service: addressOf(2),
  ringProgramId: addressOf(7),
};
const WALLET = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TARGET_LINES = `cluster: ${hashOf(1)}\nservice: ${addressOf(2)}\nring: ${addressOf(7)}`;
const NONCE_BASE64 = Buffer.from(NONCE).toString("base64");

function capture(result: unknown) {
  const bodies: Record<string, unknown>[] = [];
  const rpc = new RingRpc("http://ring.example", {
    allowInsecureHttp: true,
    fetch: (async (_input: URL | string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch,
  });
  return { rpc, bodies };
}

const reader: RingReadSigner = {
  reader: Uint8Array.of(1, 0, ...new Uint8Array(32).fill(3)),
  sign: async () => new Uint8Array(64).fill(8),
};

function noteWire(status: string, overrides: Readonly<Record<string, unknown>> = {}) {
  return {
    utxoHash: hashOf(0x11),
    status,
    nullifierPk: hashOf(0x12),
    asset: hashOf(0x13),
    amount: 500,
    blinding: hashOf(0x14),
    dataHash: hashOf(0),
    ringDataHash: hashOf(0),
    treeId: 3,
    leafIndex: 77,
    slot: 40,
    txSignature: SIGNATURE,
    eventIndex: 2,
    slotIndex: 1,
    ...overrides,
  };
}

describe("wallet status attestation", () => {
  it("writes the lines Rust `WalletStatusAttestation::message` writes", () => {
    const message = walletStatusAttestation({
      target: TARGET,
      wallet: WALLET,
      timestamp: 1_700_000_000n,
      nonce: NONCE,
    });
    expect(new TextDecoder().decode(message)).toBe(
      `zolana/ring-rpc-wallet-status\n${TARGET_LINES}\ntimestamp: 1700000000\nnonce: ${NONCE_BASE64}\nwallet: ${WALLET}\ncursor: `,
    );
  });

  it("writes the lines Rust `SpendCoverageAttestation::message` writes", () => {
    const message = spendCoverageAttestation({
      target: TARGET,
      authority: WALLET,
      timestamp: 1_700_000_000n,
      nonce: NONCE,
    });
    expect(new TextDecoder().decode(message)).toBe(
      `zolana/ring-rpc-spend-coverage\n${TARGET_LINES}\nauthority: ${WALLET}\ntimestamp: 1700000000\nnonce: ${NONCE_BASE64}`,
    );
  });
});

describe("getWalletStatus", () => {
  const page = {
    historyThrough: 41,
    balances: [{ asset: hashOf(0x13), amount: 500 }],
    notes: [
      noteWire("unspent"),
      noteWire("spent"),
      noteWire("unknown"),
      noteWire("exposedIfSpent", { nullifierPk: undefined }),
    ],
    cursor: null,
  };

  it("reads each status and sends the wallet under a reader's signature", async () => {
    const { rpc, bodies } = capture(page);
    const status = await rpc.getWalletStatus({ target: TARGET, signer: reader, wallet: WALLET });
    expect(status.historyThrough).toBe(41n);
    expect(status.notes.map((note) => note.status)).toEqual([
      "unspent",
      "spent",
      "unknown",
      "exposedIfSpent",
    ]);
    expect(status.notes[3]?.nullifierPk).toBeUndefined();
    expect(status.balances).toEqual([{ asset: new Uint8Array(32).fill(0x13), amount: 500n }]);
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(bodies[0]?.["method"]).toBe("getWalletStatus");
    expect(params["wallet"]).toBe(WALLET);
    expect(params["ringProgramId"]).toBe(TARGET.ringProgramId);
  });

  it("keeps the restart refusal when a wallet snapshot changes", async () => {
    const rpc = new RingRpc("http://ring.example", {
      allowInsecureHttp: true,
      fetch: (async () =>
        new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            error: {
              code: -32172,
              message: "wallet state changed, discard prior pages and restart without a cursor",
            },
          }),
          { headers: { "content-type": "application/json" } },
        )) as typeof globalThis.fetch,
    });
    await expect(
      rpc.getWalletStatus({
        target: TARGET,
        signer: reader,
        wallet: WALLET,
        cursor: new Uint8Array(129).fill(1),
      }),
    ).rejects.toMatchObject({
      code: "RING_RPC_REFUSED",
      details: { refusal: "walletSnapshotChanged", rpcCode: -32172 },
    });
  });

  it("refuses a status it does not know, never reading it as unspent", async () => {
    const { rpc } = capture({ ...page, notes: [noteWire("resolved")] });
    await expect(
      rpc.getWalletStatus({ target: TARGET, signer: reader, wallet: WALLET }),
    ).rejects.toMatchObject({ code: "RING_RPC" });
  });
});

describe("getSpendCoverage", () => {
  it("reads the operator's rows under the authority's signature", async () => {
    const frame = { slot: 9, txSignature: SIGNATURE, eventIndex: 0 };
    const { rpc, bodies } = capture({
      positionSlot: 12,
      historyThrough: 11,
      observed: 5,
      padding: 2,
      external: 1,
      resolved: 1,
      unresolvedReal: [{ nullifier: hashOf(0x20), frame }],
      unreadable: [frame],
      integrityFaults: [],
    });
    const authority = await generateKeyPairSigner();
    const coverage = await rpc.getSpendCoverage({ target: TARGET, authority });
    expect(coverage.unresolvedReal[0]?.nullifier).toEqual(new Uint8Array(32).fill(0x20));
    expect(coverage.unreadable).toHaveLength(1);
    expect(coverage.positionSlot).toBe(12n);
    const params = bodies[0]?.["params"] as Record<string, unknown>;
    expect(bodies[0]?.["method"]).toBe("getSpendCoverage");
    expect(params["authority"]).toBe(authority.address);
    expect(params["ring"]).toBe(TARGET.ringProgramId);
  });
});
