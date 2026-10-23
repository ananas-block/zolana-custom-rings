import { x25519 } from "@noble/curves/ed25519.js";
import { getBase58Decoder } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { CustomRingClient } from "../src/client/client.js";
import { wireDecoder, ProverClient, treeAddress, hashChain } from "@heliuslabs/zolana/internal";
import { parseProof } from "@heliuslabs/zolana/client";
import type { Bytes16, Bytes32 } from "@heliuslabs/zolana";
import { inputTreeSlots, treeSlotsHashChain } from "@heliuslabs/zolana/interface";
import {
  CustomRingProver,
  customRingCompressedPolicyProofRequest,
  customRingPolicyProofRequest,
  customRingRegisterKeyProofRequest,
} from "../src/client/prover/client.js";
import { proofFor } from "./helpers/proofs.js";
import { disabledRuleAnswer, velocityProofInputOff } from "../src/client/prover/types.js";
import type { IndexedPolicyInputs } from "../src/client/ports.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingOpening,
  CustomRingPolicyProofRequest,
} from "../src/client/prover/types.js";

function ringProver(fetch: typeof globalThis.fetch): CustomRingProver {
  return new CustomRingProver(new ProverClient({ url: "http://127.0.0.1:3001", fetch }));
}

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** Canonical X25519 coordinate of a secret with every byte equal to 4. */
const AUDITOR_PK_HEX = `0x${Buffer.from(x25519.getPublicKey(new Uint8Array(32).fill(4))).toString("hex")}`;

function fieldHex(byte: number): string {
  return `0x${byte.toString(16).padStart(2, "0").repeat(32)}`;
}

function zeroOpening(): CustomRingOpening {
  return {
    domain: bytes(0),
    treeId: bytes(0),
    ownerPkHash: bytes(0),
    nullifierPk: bytes(0),
    asset: bytes(0),
    amount: bytes(0),
    blinding: bytes(0),
    dataHash: bytes(0),
    ringDataHash: bytes(0),
    ringProgramId: bytes(0),
  };
}

/** The Rust wire-format test's request, `the_request_matches_the_server_wire_format`. */
function ringRequest(auditorPublicKey: Uint8Array): CustomRingPolicyProofRequest {
  return {
    publicInputHash: bytes(0),
    privateTxHash: bytes(1),
    txViewingSecret: bytes(2),
    ephemeralSecret: bytes(3),
    auditorPublicKey,
    salt: new Uint8Array(16) as Bytes16,
    nIn: 2,
    nOut: 2,
    inputs: Array.from({ length: 5 }, () => zeroOpening()),
    outputs: Array.from({ length: 4 }, () => zeroOpening()),
    addressChain: bytes(0),
    privateTxBlinding: bytes(7),
    sources: Array.from({ length: 8 }, () => ({ listId: 0, ownerHash: bytes(0) })),
    policyLen: 1,
    rules: Array.from({ length: 16 }, () => bytes(0)),
    inlineAssets: Array.from({ length: 8 }, () => bytes(0)),
    inlineLimits: Array.from({ length: 8 }, () => 0n),
    inlineCount: 0,
    treeSlots: [{ id: 3, utxoRoot: bytes(8), nullifierRoot: bytes(9) }],
    addressTreeId: 3,
    velocity: velocityProofInputOff({ ringId: bytes(10), namespaceOwnerHash: bytes(11) }),
    answers: Array.from({ length: 10 }, () => disabledRuleAnswer()),
  };
}

/** The no-policy request, matching Rust `CustomRingBaseProofRequest`. */
function auditRequest(auditorPublicKey: Uint8Array): CustomRingBaseProofRequest {
  return {
    publicInputHash: bytes(0),
    privateTxHash: bytes(1),
    txViewingSecret: bytes(2),
    ephemeralSecret: bytes(3),
    auditorPublicKey,
    salt: new Uint8Array(16) as Bytes16,
    nOut: 2,
    outputs: Array.from({ length: 4 }, () => zeroOpening()),
  };
}

describe("compressed ring prover contracts", () => {
  it.each(["compressed", "delegate"] as const)(
    "decodes %s proofs and refuses malformed responses",
    async (kind) => {
      const proof = proofFor({ circuitType: `custom-ring-${kind}-policy` });
      const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(proof));
      const prover = ringProver(fetch);
      const policy = ringRequest(x25519.getPublicKey(bytes(4)));
      const prove = () =>
        kind === "compressed"
          ? prover.proveCustomRingCompressedPolicy({
              policy,
              transactionSalt: new Uint8Array(16) as Bytes16,
            })
          : prover.proveCustomRingDelegatePolicy(policy);
      await expect(prove()).resolves.toEqual(parseProof(proof));
      fetch.mockResolvedValueOnce(Response.json({ ...proof, ar: [] }));
      await expect(prove()).rejects.toMatchObject({ code: "CLIENT_PROOF_PARSE" });
      expect(fetch).toHaveBeenCalledTimes(2);
    },
  );

  it("nests the member policy beside the transaction salt only", () => {
    const request = {
      policy: ringRequest(x25519.getPublicKey(bytes(4))),
      transactionSalt: new Uint8Array(16) as Bytes16,
    };
    const body = customRingCompressedPolicyProofRequest(request);
    expect(body).toMatchObject({
      circuitType: "custom-ring-compressed-policy",
      policy: { circuitType: "custom-ring-policy" },
    });
    expect(Object.keys(body).sort()).toEqual(["circuitType", "policy", "transactionSalt"]);
  });

  it("serializes the key registration like Rust `RegisterKeyProofRequest::body`", async () => {
    const nullifierSecret = bytes(0);
    nullifierSecret[31] = 7;
    const request = {
      publicInputHash: bytes(0),
      registryOldRoot: bytes(1),
      registryNewRoot: bytes(2),
      member: bytes(3),
      newIndex: 1n,
      lowMember: bytes(0),
      lowNext: bytes(5),
      lowKey: bytes(0),
      lowIndex: 0n,
      lowProof: Array.from({ length: 40 }, () => bytes(0)),
      newProof: Array.from({ length: 40 }, () => bytes(0)),
      nullifierSecret,
      ephemeralSecret: bytes(6),
      auditorPublicKey: x25519.getPublicKey(bytes(4)),
    };
    const body = customRingRegisterKeyProofRequest(request);
    expect(body).toMatchObject({
      circuitType: "custom-ring-register-key",
      newIndex: `0x${"0".repeat(63)}1`,
      nullifierSecret: `0x${"0".repeat(62)}07`,
      ephSk: fieldHex(6),
    });
    expect(String(body["auditorPk"])).toHaveLength(66);
    expect(String(body["ephSk"])).toHaveLength(66);
    expect(body).not.toHaveProperty("key");
    expect(body["registryNewRoot"]).toBe(fieldHex(2));
    const high = bytes(0);
    high[0] = 1;
    expect(() => customRingRegisterKeyProofRequest({ ...request, nullifierSecret: high })).toThrow(
      "CLIENT_INVALID_PROOF_INPUTS",
    );
    expect(() => customRingRegisterKeyProofRequest({ ...request, lowIndex: -1n })).toThrow(
      "CLIENT_INVALID_INTEGER",
    );
    expect(() => customRingRegisterKeyProofRequest({ ...request, newIndex: 1n << 40n })).toThrow(
      "CLIENT_INVALID_INTEGER",
    );
    const proof = proofFor({ circuitType: "custom-ring-register-key" });
    const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(proof));
    const prover = ringProver(fetch);
    await expect(prover.proveCustomRingRegisterKey(request)).resolves.toEqual(parseProof(proof));
    fetch.mockResolvedValueOnce(Response.json({ ...proof, ar: [] }));
    await expect(prover.proveCustomRingRegisterKey(request)).rejects.toMatchObject({
      code: "CLIENT_PROOF_PARSE",
    });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("keeps delegate policy rows but sends no velocity charge", async () => {
    const bodies: unknown[] = [];
    const prover = ringProver(async (_url, init) => {
      bodies.push(JSON.parse(String(init?.body)));
      return Response.json(proofFor(String(init?.body)));
    });
    const request = ringRequest(x25519.getPublicKey(bytes(4)));
    const velocity = {
      ...request.velocity,
      windowSlots: 100n,
      rows: [{ asset: bytes(1), cap: 1n, cosignAbove: 1n }],
    };
    await prover.proveCustomRingDelegatePolicy({ ...request, velocity });
    expect(bodies).toMatchObject([
      {
        circuitType: "custom-ring-delegate-policy",
        policy: {
          circuitType: "custom-ring-policy",
          velocityCount: 1,
          windowSlots: 100,
          windowIndex: 0,
          approvalRequired: false,
        },
      },
    ]);
    await expect(
      prover.proveCustomRingDelegatePolicy({
        ...request,
        velocity: { ...velocity, approvalRequired: true },
      }),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_PROOF_INPUTS" });
    expect(bodies).toHaveLength(1);
  });
});

/** Key order from Rust `CustomRingBaseProofRequestJson` in `request_ring.rs`. */
const EXPECTED_AUDIT_BODY = {
  circuitType: "custom-ring-base",
  publicInputHash: fieldHex(0),
  privateTxHash: fieldHex(1),
  txViewingSk: fieldHex(2),
  ephSk: fieldHex(3),
  auditorPk: AUDITOR_PK_HEX,
  salt: "0x00000000000000000000000000000000",
  nOut: 2,
  outputs: Array.from({ length: 4 }, () => ({
    domain: fieldHex(0),
    treeId: fieldHex(0),
    ownerHash: fieldHex(0),
    asset: fieldHex(0),
    amount: fieldHex(0),
    blinding: fieldHex(0),
    dataHash: fieldHex(0),
    ringDataHash: fieldHex(0),
    ringProgramId: fieldHex(0),
  })),
};

const EXPECTED_OPENING = {
  domain: fieldHex(0),
  treeId: fieldHex(0),
  ownerPkHash: fieldHex(0),
  nullifierPk: fieldHex(0),
  asset: fieldHex(0),
  amount: fieldHex(0),
  blinding: fieldHex(0),
  dataHash: fieldHex(0),
  ringDataHash: fieldHex(0),
  ringProgramId: fieldHex(0),
};

const EXPECTED_RULE_ANSWER = {
  enabled: false,
  treeSlot: 0,
  mode: 1,
  listId: 1,
  state: 1,
  absentBranch: 1,
  member: fieldHex(0),
  contentHash: fieldHex(0),
  version: 0,
  blinding: fieldHex(0),
  low: fieldHex(0),
  next: fieldHex(0),
  nfPathElements: Array.from({ length: 40 }, () => fieldHex(0)),
  nfPathIndex: 0,
  statePathElements: Array.from({ length: 32 }, () => fieldHex(0)),
  statePathIndex: 0,
};

/** Key order from Rust `CustomRingPolicyProofRequestJson` in `request_ring.rs`. */
const EXPECTED_RING_BODY = {
  circuitType: "custom-ring-policy",
  publicInputHash: fieldHex(0),
  privateTxHash: fieldHex(1),
  txViewingSk: fieldHex(2),
  ephSk: fieldHex(3),
  auditorPk: AUDITOR_PK_HEX,
  salt: "0x00000000000000000000000000000000",
  nIn: 2,
  nOut: 2,
  inputs: Array.from({ length: 5 }, () => EXPECTED_OPENING),
  outputs: Array.from({ length: 4 }, () => EXPECTED_OPENING),
  addressChain: fieldHex(0),
  privateTxBlinding: fieldHex(7),
  sources: Array.from({ length: 8 }, () => ({ listId: 0, ownerHash: fieldHex(0) })),
  policyLen: 1,
  ruleEnc: Array.from({ length: 16 }, () => fieldHex(0)),
  inlineAssets: Array.from({ length: 8 }, () => fieldHex(0)),
  inlineLimits: Array.from({ length: 8 }, () => fieldHex(0)),
  inlineCount: 0,
  treeSlots: [{ id: `0x${"0".repeat(62)}03`, utxoRoot: fieldHex(8), nullifierRoot: fieldHex(9) }],
  addressTreeId: `0x${"0".repeat(62)}03`,
  windowSlots: 0,
  velocity: Array.from({ length: 8 }, () => ({
    asset: fieldHex(0),
    cap: fieldHex(0),
    cosignAbove: fieldHex(0),
  })),
  velocityCount: 0,
  ringId: fieldHex(10),
  namespaceOwnerHash: fieldHex(11),
  windowIndex: 0,
  approvalRequired: false,
  keyEscrow: false,
  keyRegistryRoot: fieldHex(0),
  record: {
    version: 0,
    window: 0,
    commitment: fieldHex(0),
    salt: fieldHex(0),
    assets: Array.from({ length: 8 }, () => fieldHex(0)),
    spent: Array.from({ length: 8 }, () => fieldHex(0)),
    nextSalt: fieldHex(0),
  },
  answers: Array.from({ length: 10 }, () => EXPECTED_RULE_ANSWER),
};

describe("ring prover request bodies", () => {
  it("encodes the custom-ring request byte for byte like Rust `CustomRingPolicyProofRequest::body`", async () => {
    const raw: string[] = [];
    const deliveries: (string | null)[] = [];
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      raw.push(String(init?.body));
      deliveries.push(new Headers(init?.headers).get("X-Sync"));
      return new Response(JSON.stringify(proofFor(JSON.parse(String(init?.body)))), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = ringProver(fetch);
    const auditorPublicKey = x25519.getPublicKey(bytes(4));

    await prover.proveCustomRingPolicy(ringRequest(auditorPublicKey));

    expect(raw[0]).toBe(JSON.stringify(EXPECTED_RING_BODY));
    expect(deliveries).toEqual([null]);
    const body = JSON.parse(raw[0] ?? "") as Record<string, unknown>;
    // The sorted key set of Rust `the_request_matches_the_server_wire_format`.
    expect(Object.keys(body).sort()).toEqual([
      "addressChain",
      "addressTreeId",
      "answers",
      "approvalRequired",
      "auditorPk",
      "circuitType",
      "ephSk",
      "inlineAssets",
      "inlineCount",
      "inlineLimits",
      "inputs",
      "keyEscrow",
      "keyRegistryRoot",
      "nIn",
      "nOut",
      "namespaceOwnerHash",
      "outputs",
      "policyLen",
      "privateTxBlinding",
      "privateTxHash",
      "publicInputHash",
      "record",
      "ringId",
      "ruleEnc",
      "salt",
      "sources",
      "treeSlots",
      "txViewingSk",
      "velocity",
      "velocityCount",
      "windowIndex",
      "windowSlots",
    ]);
    expect(body["circuitType"]).toBe("custom-ring-policy");
    expect(body["auditorPk"]).toHaveLength(66);
    expect(body["publicInputHash"]).toHaveLength(66);
    const answers = body["answers"] as Record<string, unknown>[];
    expect(answers).toHaveLength(10);
    expect(answers[0]?.["nfPathElements"]).toHaveLength(40);
    expect(answers[0]?.["statePathElements"]).toHaveLength(32);
    const sources = body["sources"] as Record<string, unknown>[];
    expect(sources).toHaveLength(8);
    expect(Object.keys(sources[0] ?? {}).sort()).toEqual(["listId", "ownerHash"]);

    for (const auditorPublicKey of [new Uint8Array(33).fill(2), new Uint8Array(65).fill(2)]) {
      await expect(
        prover.proveCustomRingPolicy(ringRequest(auditorPublicKey)),
      ).rejects.toMatchObject({
        code: "CLIENT_INVALID_PROOF_INPUTS",
      });
    }
    // The server rejects `answers.len() != 10`, an unpadded answers array must not leave the client.
    await expect(
      prover.proveCustomRingPolicy({ ...ringRequest(auditorPublicKey), answers: [] }),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_LENGTH" });
    for (const treeSlots of [
      [],
      Array.from({ length: 6 }, () => ringRequest(auditorPublicKey).treeSlots[0]!),
    ]) {
      await expect(
        prover.proveCustomRingPolicy({ ...ringRequest(auditorPublicKey), treeSlots }),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_LENGTH" });
    }
    expect(raw).toHaveLength(1);
  });

  it("sends each escrowed output key beside its opening like Go `writeRegistryKey`", async () => {
    const auditorPublicKey = x25519.getPublicKey(bytes(4));
    const key = {
      next: bytes(12),
      ctHash: bytes(13),
      index: 5n,
      path: Array.from({ length: 40 }, () => bytes(14)),
    };
    const request = ringRequest(auditorPublicKey);
    const escrowed = {
      ...request,
      keyRegistryRoot: bytes(15),
      outputs: request.outputs.map((opening, index) =>
        index === 1 ? { ...opening, key } : opening,
      ),
    };
    const body = customRingPolicyProofRequest(escrowed);
    expect(body).toMatchObject({ keyEscrow: true, keyRegistryRoot: fieldHex(15) });
    const outputs = body["outputs"] as Record<string, unknown>[];
    expect(outputs[0]).not.toHaveProperty("key");
    expect(outputs[1]?.["key"]).toEqual({
      next: fieldHex(12),
      ctHash: fieldHex(13),
      index: 5,
      path: Array.from({ length: 40 }, () => fieldHex(14)),
    });
    expect(() =>
      customRingPolicyProofRequest({
        ...escrowed,
        inputs: request.inputs.map((opening) => ({ ...opening, key })),
      }),
    ).toThrow(expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }));
    expect(() =>
      customRingPolicyProofRequest({
        ...escrowed,
        outputs: request.outputs.map((opening) => ({
          ...opening,
          key: { ...key, index: 1n << 40n },
        })),
      }),
    ).toThrow(expect.objectContaining({ code: "CLIENT_INVALID_INTEGER" }));
  });

  it("encodes the base request byte for byte like Rust `CustomRingBaseProofRequest::body`", async () => {
    const raw: string[] = [];
    const deliveries: (string | null)[] = [];
    const fetch = vi.fn(async (_input: URL | string, init?: RequestInit) => {
      raw.push(String(init?.body));
      deliveries.push(new Headers(init?.headers).get("X-Sync"));
      return new Response(JSON.stringify(proofFor(JSON.parse(String(init?.body)))), {
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    const prover = ringProver(fetch);
    const auditorPublicKey = x25519.getPublicKey(bytes(4));

    await prover.proveCustomRingBase(auditRequest(auditorPublicKey));

    expect(raw[0]).toBe(JSON.stringify(EXPECTED_AUDIT_BODY));
    // The audit proof is queued, never sent inline.
    expect(deliveries).toEqual([null]);
    const body = JSON.parse(raw[0] ?? "") as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "auditorPk",
      "circuitType",
      "ephSk",
      "nOut",
      "outputs",
      "privateTxHash",
      "publicInputHash",
      "salt",
      "txViewingSk",
    ]);
    expect(body["circuitType"]).toBe("custom-ring-base");
    expect(body["auditorPk"]).toHaveLength(66);

    for (const auditorPublicKey of [new Uint8Array(33).fill(2), new Uint8Array(65).fill(2)]) {
      await expect(
        prover.proveCustomRingBase(auditRequest(auditorPublicKey)),
      ).rejects.toMatchObject({ code: "CLIENT_INVALID_PROOF_INPUTS" });
    }
    expect(raw).toHaveLength(1);
  });
});

/** A policy request whose `resolution` the prover would answer with. */
function indexedPolicy(circuit: IndexedPolicyInputs["circuit"]) {
  const policy = ringRequest(x25519.getPublicKey(bytes(4)));
  const tree = {
    tree: treeAddress(3),
    id: 3,
    utxoRoot: bytes(8),
    nullifierRoot: bytes(9),
    utxoRootIndex: 7,
    nullifierRootIndex: 3,
  };
  const inputs: IndexedPolicyInputs = {
    circuit,
    policy,
    minContextSlot: 123n,
    trees: [tree],
    lookups: Array.from({ length: 10 }, () => ({
      treeSlot: 0,
      commitment: null,
      nullifier: null,
    })),
    publicInputs: Array.from(
      { length: circuit === "custom-ring-compressed-policy" ? 20 : 19 },
      () => bytes(1),
    ),
    ...(circuit === "custom-ring-compressed-policy" ? { transactionSalt: new Uint8Array(16) } : {}),
  };
  const hash = hashChain([
    inputs.publicInputs[0]!,
    treeSlotsHashChain(inputTreeSlots(policy.treeSlots)),
    ...inputs.publicInputs.slice(1),
  ]);
  const toHex = (value: Uint8Array) => `0x${Buffer.from(value).toString("hex")}`;
  const resolution = {
    trees: [{ ...tree, utxoRoot: toHex(tree.utxoRoot), nullifierRoot: toHex(tree.nullifierRoot) }],
    publicInputHash: toHex(hash),
  };
  const proof = {
    ...proofFor({ circuitType: circuit }),
    proofCommitment: ["0x1", "0x2"],
    proofCommitmentPok: ["0x0", "0x0"],
  };
  return { inputs, hash, resolution, proof, toHex };
}

describe("indexed policy proofs", () => {
  it.each([
    "custom-ring-policy",
    "custom-ring-compressed-policy",
    "custom-ring-delegate-policy",
  ] as const)("binds returned roots for %s", async (circuit) => {
    const { inputs, hash, resolution, proof, toHex } = indexedPolicy(circuit);
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      Response.json({ ...proof, resolution }),
    );
    const prover = ringProver(fetch);
    const result = await prover.proveIndexedPolicy(inputs);
    expect(result.resolution.publicInputHash).toEqual(hash);
    expect(String(fetch.mock.calls[0]?.[0])).toContain(
      `/prove/${circuit.replaceAll("-", "_")}/indexed`,
    );
    const wire: unknown = JSON.parse(String(fetch.mock.calls[0]?.[1]?.body));
    const decoder = wireDecoder(() => new Error("invalid body"));
    const body = decoder.record(wire, "body");
    const wrapped = decoder.record(body["prepared"], "prepared");
    const prepared =
      circuit === "custom-ring-policy" ? wrapped : decoder.record(wrapped["policy"], "policy");
    expect(body["minContextSlot"]).toBe(123);
    expect(wrapped["minContextSlot"]).toBeUndefined();
    expect(prepared["treeSlots"]).toBeUndefined();
    expect(
      decoder.record(decoder.list(prepared["answers"], "answers")[0], "answer")["nfPathElements"],
    ).toBeUndefined();
    const client = new CustomRingClient({
      fetch,
      indexerConfig: { requireSlot: 456n, poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n } },
    });
    await expect(
      client.proveIndexedRingPolicy({ ...inputs, minContextSlot: -1n }),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_PROOF_INPUTS" });
    for (const minContextSlot of [123n, 1000n]) {
      await client.proveIndexedRingPolicy({ ...inputs, minContextSlot });
      const clientWire: unknown = JSON.parse(String(fetch.mock.lastCall?.[1]?.body));
      expect(decoder.record(clientWire, "client body")["minContextSlot"]).toBe(
        Number(minContextSlot < 456n ? 456n : minContextSlot),
      );
    }
    for (const changed of [
      { ...resolution, publicInputHash: toHex(bytes(2)) },
      { ...resolution, trees: [{ ...resolution.trees[0], utxoRootIndex: 9 }] },
      { ...resolution, trees: [{ ...resolution.trees[0], utxoRoot: toHex(bytes(10)) }] },
      { ...resolution, trees: [{ ...resolution.trees[0], tree: treeAddress(4) }] },
    ]) {
      fetch.mockResolvedValueOnce(Response.json({ ...proof, resolution: changed }));
      await expect(prover.proveIndexedPolicy(inputs)).rejects.toMatchObject({
        code: "CLIENT_PROOF_PARSE",
      });
    }
  });
});

describe("indexed registry refusals", () => {
  const MEMBER = new Uint8Array(32).fill(0x2a);
  const SERVER_TEXT = "photon echoed caller data";

  function prove(fetch: typeof globalThis.fetch): Promise<unknown> {
    const prover = new CustomRingProver(
      new ProverClient({
        url: "http://127.0.0.1:3001",
        fetch,
        asyncPoll: { pollIntervalCapMs: 1, maxWaitMs: 1_000 },
      }),
    );
    return prover.proveIndexedPolicy(indexedPolicy("custom-ring-policy").inputs);
  }

  /** Refuses sync admission, queues, then reports `status` for the job. */
  function queued(status: Readonly<Record<string, unknown>>) {
    return vi.fn<typeof globalThis.fetch>(async (_url, init) => {
      if (init?.method !== "POST") return Response.json({ status: "failed", ...status });
      if (new Headers(init.headers).get("X-Sync") === "true")
        return new Response(null, { status: 429 });
      return Response.json({ jobId: "job-1" }, { status: 202 });
    });
  }

  it("names the refused registry member whether proved in the response or queued", async () => {
    const refusal = {
      code: "registry_member_missing",
      message: SERVER_TEXT,
      detail: { member: getBase58Decoder().decode(MEMBER) },
    };
    for (const fetch of [
      vi.fn<typeof globalThis.fetch>(async () => Response.json(refusal, { status: 422 })),
      queued({ ...refusal, error: SERVER_TEXT }),
    ]) {
      const error = await prove(fetch).catch((cause: unknown) => cause);
      expect(error).toMatchObject({
        code: "RING_KEY_REGISTRY_MEMBER_UNREGISTERED",
        details: { method: "prove", member: Buffer.from(MEMBER).toString("hex") },
      });
      expect(JSON.stringify(error)).not.toContain(SERVER_TEXT);
    }
    for (const member of ["0x2a", getBase58Decoder().decode(MEMBER.subarray(1))]) {
      await expect(
        prove(
          vi.fn<typeof globalThis.fetch>(async () =>
            Response.json({ ...refusal, detail: { member } }, { status: 422 }),
          ),
        ),
      ).rejects.toMatchObject({ code: "CLIENT_PROVER_JSON" });
    }
  });
});
