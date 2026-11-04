import { hexToBytes } from "@noble/hashes/utils.js";
import {
  generateKeyPairSigner,
  getAddressDecoder,
  getBase58Decoder,
  getBase58Encoder,
  type Address,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import unspentVector from "../../../../test-vectors/rpc/unspent_utxos.json" with { type: "json" };
import { assetField } from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { X25519Keypair } from "@heliuslabs/zolana/keypair";
import { SOL_MINT } from "@heliuslabs/zolana/transaction";

import {
  GET_UNSPENT_UTXOS,
  RING_READ_CURSOR_LIMIT,
  RingReadRequest,
  RingRpc,
  RingUnspentUtxosRequest,
  messageSignerReader,
  unspentUtxosAttestation,
  type RingReadSigner,
  type RingReadTarget,
} from "../../src/rpc/ring-rpc.js";

await initializePoseidon();

function filled(byte: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function base58Of(byte: number): string {
  return getBase58Decoder().decode(filled(byte));
}

function addressOf(byte: number): Address {
  return getAddressDecoder().decode(filled(byte));
}

function signatureOf(byte: number): string {
  return getBase58Decoder().decode(filled(byte, 64));
}

/** Rust `rpc::tests::target`. */
const TARGET: RingReadTarget = {
  cluster: filled(1) as Bytes32,
  service: addressOf(2),
  ringProgramId: addressOf(7),
};
const OWNER = filled(9) as Bytes32;

type Wire = Record<string, unknown>;

function openedView(): Wire {
  return {
    utxoHash: base58Of(1),
    asset: getBase58Decoder().decode(assetField(SOL_MINT)),
    mint: SOL_MINT,
    amount: 9,
    kind: { kind: "opened", blinding: base58Of(2), treeId: 4 },
    slot: 12,
    txSignature: signatureOf(1),
    eventIndex: 1,
    slotIndex: 3,
  };
}

function mergeOutputView(): Wire {
  return {
    utxoHash: base58Of(3),
    asset: base58Of(5),
    amount: 21,
    kind: { kind: "mergeOutput" },
    slot: 13,
    txSignature: signatureOf(2),
    eventIndex: 0,
    slotIndex: 0,
  };
}

function unresolvedRow(): Wire {
  return {
    slot: 14,
    txSignature: signatureOf(3),
    eventIndex: 2,
    reason: "unknownMergeInput",
    inputs: [base58Of(6)],
  };
}

function page(): Wire {
  return {
    utxos: [openedView(), mergeOutputView()],
    coverage: { fromSlot: 10, throughSlot: 20, complete: false },
    unresolved: [unresolvedRow()],
    cursor: null,
  };
}

interface VectorView {
  readonly utxoHash: string;
  readonly asset: string;
  readonly mint?: string;
  readonly amount: number;
  readonly kind:
    | Readonly<{ kind: "opened"; blinding: string; treeId: number }>
    | Readonly<{ kind: "mergeOutput" }>;
  readonly slot: number;
  readonly txSignature: string;
  readonly eventIndex: number;
  readonly slotIndex: number;
}

interface VectorPage {
  readonly utxos: readonly VectorView[];
  readonly coverage: Readonly<{ fromSlot: number; throughSlot: number; complete: boolean }>;
  readonly unresolved: readonly Readonly<{
    slot: number;
    txSignature: string;
    eventIndex: number;
    reason: string;
    inputs: readonly string[];
  }>[];
  readonly cursor: string | null;
}

interface VectorResponse {
  readonly name: string;
  readonly wire: VectorPage;
}

function base58Bytes(text: string): Uint8Array {
  return Uint8Array.from(getBase58Encoder().encode(text));
}

function withoutMints(wire: VectorPage): VectorPage {
  return {
    ...wire,
    utxos: wire.utxos.map(({ mint: _mint, ...view }) => view),
  };
}

function decodedPage({ utxos, coverage, unresolved, cursor }: VectorPage) {
  return {
    utxos: utxos.map(({ txSignature, kind, ...view }) => ({
      ...view,
      utxoHash: base58Bytes(view.utxoHash),
      asset: base58Bytes(view.asset),
      amount: BigInt(view.amount),
      kind:
        kind.kind === "opened"
          ? { kind: "opened", blinding: base58Bytes(kind.blinding), treeId: kind.treeId }
          : { kind: "mergeOutput" },
      slot: BigInt(view.slot),
      signature: txSignature,
    })),
    coverage: {
      fromSlot: BigInt(coverage.fromSlot),
      throughSlot: BigInt(coverage.throughSlot),
      complete: coverage.complete,
    },
    unresolved: unresolved.map(({ txSignature, inputs, ...row }) => ({
      ...row,
      slot: BigInt(row.slot),
      signature: txSignature,
      inputs: inputs.map(base58Bytes),
    })),
    ...(cursor === null ? {} : { cursor: Uint8Array.from(Buffer.from(cursor, "base64")) }),
  };
}

function answering(result: unknown): { rpc: RingRpc; bodies: Wire[] } {
  const bodies: Wire[] = [];
  const fetch = (async (_input: URL | string, init?: RequestInit) => {
    bodies.push(JSON.parse(String(init?.body)) as Wire);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  return {
    rpc: new RingRpc("http://ring.example", { fetch, allowInsecureHttp: true }),
    bodies,
  };
}

async function reader(): Promise<RingReadSigner> {
  return messageSignerReader(await generateKeyPairSigner());
}

async function read(result: unknown) {
  return answering(result).rpc.getUnspentUtxos({
    target: TARGET,
    owner: OWNER,
    signer: await reader(),
  });
}

describe("unspent UTXO attestation", () => {
  const signed = {
    target: TARGET,
    timestamp: 1_700_000_000n,
    nonce: filled(4) as Bytes32,
    owner: OWNER,
  };
  const prefix =
    "zolana/ring-rpc-unspent-utxos/v1\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nowner: cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN\ncursor: ";

  it("signs an empty cursor line and no wallet line on a ring-wide first page", () => {
    expect(new TextDecoder().decode(unspentUtxosAttestation(signed))).toBe(prefix);
  });

  it("ends in the cursor and the wallet in Rust line order", () => {
    const message = unspentUtxosAttestation({
      ...signed,
      cursor: Uint8Array.of(1, 2, 3),
      wallet: addressOf(5),
    });
    expect(new TextDecoder().decode(message)).toBe(
      `${prefix}AQID\nwallet: LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY`,
    );
  });
});

describe("RingUnspentUtxosRequest", () => {
  it("sends the fields it signed under the method name", async () => {
    const { rpc, bodies } = answering(page());
    const signer = await reader();
    await rpc.getUnspentUtxos({
      target: TARGET,
      owner: OWNER,
      signer,
      cursor: Uint8Array.of(1, 2, 3),
      wallet: addressOf(5),
      timestamp: 1_700_000_000n,
    });
    const body = bodies[0];
    expect(body?.["method"]).toBe(GET_UNSPENT_UTXOS);
    const params = body?.["params"] as Wire;
    expect(params).toMatchObject({
      ringProgramId: TARGET.ringProgramId,
      owner: base58Of(9),
      cursor: "AQID",
      wallet: addressOf(5),
      auth: { timestamp: 1_700_000_000 },
    });
    expect(Object.keys(params).sort()).toEqual(
      ["auth", "cursor", "owner", "ringProgramId", "wallet"].sort(),
    );
  });

  it("refuses a cursor out of bounds and an owner off its length before signing", () => {
    const request = RingUnspentUtxosRequest.read(TARGET, OWNER);
    for (const cursor of [new Uint8Array(0), new Uint8Array(RING_READ_CURSOR_LIMIT + 1)])
      expect(() => request.withCursor(cursor)).toThrow(
        expect.objectContaining({ code: "RING_READ_CURSOR" }),
      );
    expect(() => RingUnspentUtxosRequest.read(TARGET, filled(9, 31) as Bytes32)).toThrow(
      expect.objectContaining({ code: "RING_RPC" }),
    );
  });

  it("refuses a signed read with a field it does not name", async () => {
    const signed = await RingUnspentUtxosRequest.read(TARGET, OWNER).sign(await reader());
    const { rpc, bodies } = answering(page());
    await expect(
      rpc.readSignedUnspentUtxos({ ...signed, limit: 1n } as typeof signed),
    ).rejects.toMatchObject({
      code: "RING_RPC",
      details: { field: "request.shape" },
    });
    expect(bodies).toEqual([]);
  });
});

describe("getUnspentUtxos response", () => {
  it("decodes an opened note, a merge output record and the coverage", async () => {
    await expect(read(page())).resolves.toEqual({
      utxos: [
        {
          utxoHash: filled(1),
          asset: assetField(SOL_MINT),
          mint: SOL_MINT,
          amount: 9n,
          kind: { kind: "opened", blinding: filled(2), treeId: 4 },
          slot: 12n,
          signature: signatureOf(1),
          eventIndex: 1,
          slotIndex: 3,
        },
        {
          utxoHash: filled(3),
          asset: filled(5),
          amount: 21n,
          kind: { kind: "mergeOutput" },
          slot: 13n,
          signature: signatureOf(2),
          eventIndex: 0,
          slotIndex: 0,
        },
      ],
      coverage: { fromSlot: 10n, throughSlot: 20n, complete: false },
      unresolved: [
        {
          slot: 14n,
          signature: signatureOf(3),
          eventIndex: 2,
          reason: "unknownMergeInput",
          inputs: [filled(6)],
        },
      ],
    });
  });

  it("returns a next cursor and refuses one equal to the request's", async () => {
    await expect(read({ ...page(), cursor: "AQID" })).resolves.toMatchObject({
      cursor: Uint8Array.of(1, 2, 3),
    });
    const { rpc } = answering({ ...page(), cursor: "AQID" });
    await expect(
      rpc.getUnspentUtxos({
        target: TARGET,
        owner: OWNER,
        signer: await reader(),
        cursor: Uint8Array.of(1, 2, 3),
      }),
    ).rejects.toMatchObject({
      code: "RING_RPC",
      details: { path: "result.cursor" },
    });
  });

  it("reads a wallet scoped page as incomplete with no unresolved row", async () => {
    await expect(
      read({
        ...page(),
        coverage: { fromSlot: 10, throughSlot: 20, complete: false },
        unresolved: [],
      }),
    ).resolves.toMatchObject({
      coverage: { complete: false },
      unresolved: [],
    });
  });

  it("refuses a complete page that keeps an unresolved row", async () => {
    await expect(
      read({
        ...page(),
        coverage: { fromSlot: 10, throughSlot: 20, complete: true },
      }),
    ).rejects.toMatchObject({ details: { path: "result.coverage.complete" } });
  });

  it.each([
    ["below", 9],
    ["above", 21],
  ])("refuses a note %s the covered slots", async (_name, slot) => {
    await expect(read({ ...page(), utxos: [{ ...openedView(), slot }] })).rejects.toMatchObject({
      details: { path: "result.utxos" },
    });
  });

  it("refuses a mint that does not derive the asset", async () => {
    await expect(
      read({ ...page(), utxos: [{ ...openedView(), mint: addressOf(8) }] }),
    ).rejects.toMatchObject({ details: { path: "result.utxos[0].mint" } });
  });

  it.each<readonly [string, () => Wire, string]>([
    ["a page field", () => ({ ...page(), context: {} }), "result.shape"],
    [
      "a note field",
      () => ({ ...page(), utxos: [{ ...openedView(), utxo: {} }] }),
      "result.utxos[0].shape",
    ],
    [
      "an opened kind field",
      () => ({
        ...page(),
        utxos: [
          {
            ...openedView(),
            kind: { kind: "opened", blinding: base58Of(2), treeId: 4, tree: 1 },
          },
        ],
      }),
      "result.utxos[0].kind.shape",
    ],
    [
      "a merge output kind field",
      () => ({
        ...page(),
        utxos: [
          {
            ...mergeOutputView(),
            kind: { kind: "mergeOutput", blinding: base58Of(2) },
          },
        ],
      }),
      "result.utxos[0].kind.shape",
    ],
    [
      "a coverage field",
      () => ({
        ...page(),
        coverage: { fromSlot: 10, throughSlot: 20, complete: false, more: 1 },
      }),
      "result.coverage.shape",
    ],
    [
      "an unresolved field",
      () => ({
        ...page(),
        unresolved: [{ ...unresolvedRow(), owner: base58Of(1) }],
      }),
      "result.unresolved[0].shape",
    ],
  ])("denies an unknown %s", async (_name, wire, path) => {
    await expect(read(wire())).rejects.toMatchObject({
      code: "RING_RPC",
      details: { path },
    });
  });

  it.each<readonly [string, () => Wire, string]>([
    [
      "a missing cursor",
      () => {
        const { cursor: _cursor, ...rest } = page();
        return rest;
      },
      "result.cursor",
    ],
    [
      "a missing coverage slot",
      () => ({ ...page(), coverage: { fromSlot: 10, complete: false } }),
      "result.coverage.throughSlot",
    ],
    [
      "a coverage flag off its type",
      () => ({
        ...page(),
        coverage: { fromSlot: 10, throughSlot: 20, complete: 0 },
      }),
      "result.coverage.complete",
    ],
    [
      "another kind",
      () => ({
        ...page(),
        utxos: [{ ...openedView(), kind: { kind: "unspent" } }],
      }),
      "result.utxos[0].kind.kind",
    ],
    [
      "another unresolved reason",
      () => ({
        ...page(),
        unresolved: [{ ...unresolvedRow(), reason: "other" }],
      }),
      "result.unresolved[0].reason",
    ],
    [
      "a noncanonical hash",
      () => ({
        ...page(),
        utxos: [
          {
            ...openedView(),
            utxoHash: getBase58Decoder().decode(filled(0xff)),
          },
        ],
      }),
      "result.utxos[0].utxoHash",
    ],
  ])("refuses %s", async (_name, wire, path) => {
    await expect(read(wire())).rejects.toMatchObject({
      code: "RING_RPC",
      details: { path },
    });
  });

  describe("the shared vector", () => {
    const target: RingReadTarget = {
      cluster: hexToBytes(unspentVector.cluster) as Bytes32,
      service: unspentVector.service as Address,
      ringProgramId: unspentVector.ring as Address,
    };
    const owner = hexToBytes(unspentVector.owner) as Bytes32;
    const responses = unspentVector.responses as readonly VectorResponse[];

    async function readWire(wire: VectorPage, wallet?: Address) {
      const { rpc, bodies } = answering(wire);
      let request = RingUnspentUtxosRequest.read(target, owner);
      if (wallet !== undefined) request = request.withWallet(wallet);
      const page = rpc.readSignedUnspentUtxos(await request.sign(await reader()));
      return { page, bodies };
    }

    it.each(unspentVector.attestations)("signs $name", ({ name, message }) => {
      const scope =
        name === "a wallet read with a cursor"
          ? { cursor: filled(2), wallet: addressOf(0x0b) }
          : {};
      const attestation = unspentUtxosAttestation({
        target,
        timestamp: BigInt(unspentVector.timestamp),
        nonce: hexToBytes(unspentVector.nonce) as Bytes32,
        owner,
        ...scope,
      });
      expect(new TextDecoder().decode(attestation)).toBe(message);
    });

    it.each(responses)("reads $name", async ({ wire }) => {
      const scoped = wire.utxos.length === 0 ? addressOf(0x0b) : undefined;
      const { page, bodies } = await readWire(wire, scoped);
      await expect(page).resolves.toEqual(decodedPage(wire));
      expect(bodies[0]?.["method"]).toBe(unspentVector.method);
    });

    it.each(responses)("reads $name apart from the mint", async ({ wire }) => {
      const scoped = wire.utxos.length === 0 ? addressOf(0x0b) : undefined;
      const bare = withoutMints(wire);
      const { page } = await readWire(bare, scoped);
      await expect(page).resolves.toEqual(decodedPage(bare));
    });

    it.each(responses.filter(({ wire }) => wire.utxos.length > 0))(
      "refuses $name under a mint off its asset",
      async ({ wire }) => {
        const { page } = await readWire({
          ...wire,
          utxos: wire.utxos.map((view, index) =>
            index === 0 ? { ...view, mint: addressOf(0x0c) } : view,
          ),
        });
        await expect(page).rejects.toMatchObject({
          code: "RING_RPC",
          details: { path: "result.utxos[0].mint" },
        });
      },
    );
  });
});

describe("audited merge records", () => {
  const opened = {
    slot: 12,
    txSignature: signatureOf(1),
    eventIndex: 0,
    outputCommitment: base58Of(1),
    ownerKey: base58Of(8),
    asset: base58Of(5),
    amount: 21,
    inputCommitments: [base58Of(6), base58Of(7)],
  };
  const unresolved = {
    slot: 13,
    txSignature: signatureOf(2),
    eventIndex: 1,
    outputCommitment: base58Of(2),
    inputCommitments: [base58Of(3)],
  };

  async function merges(opened: readonly Wire[], unresolved: readonly Wire[] = []) {
    const { rpc } = answering({
      context: { slot: 14, blockTime: 1 },
      value: { opened, unresolved, cursor: null },
    });
    const read = await RingReadRequest.auditedMerges(TARGET).sign(await reader());
    return rpc.readSignedMerges(read);
  }

  it("reads an inherited record and a held merge", async () => {
    await expect(merges([opened], [unresolved])).resolves.toEqual({
      slot: 14n,
      blockTime: 1n,
      opened: [
        {
          slot: 12n,
          signature: signatureOf(1),
          eventIndex: 0,
          outputCommitment: filled(1),
          ownerKey: filled(8),
          asset: filled(5),
          amount: 21n,
          inputCommitments: [filled(6), filled(7)],
          realNullifiers: [],
        },
      ],
      unresolved: [
        {
          slot: 13n,
          signature: signatureOf(2),
          eventIndex: 1,
          outputCommitment: filled(2),
          inputCommitments: [filled(3)],
        },
      ],
    });
  });

  it.each<readonly [string, Wire, string]>([
    ["a blinding", { ...opened, blinding: base58Of(3) }, "result.value.opened[0].shape"],
    ["a mint off its asset", { ...opened, mint: addressOf(8) }, "result.value.opened[0].mint"],
    ["no inputs", { ...opened, inputCommitments: [] }, "result.value.opened[0].inputCommitments"],
  ])("refuses a record with %s", async (_name, record, path) => {
    await expect(merges([record])).rejects.toMatchObject({ details: { path } });
  });
});
