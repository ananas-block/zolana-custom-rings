import { address, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";
import { wireDecoder, prepareTransfer, bytesField, treeAddress } from "@heliuslabs/zolana/internal";
import {
  LocalKeys,
  type Bytes16,
  type Bytes31,
  type Bytes32,
  NullifierKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SOL_MINT,
  Utxo,
} from "@heliuslabs/zolana";
import { ZolanaClient, type SpendProof, type NonInclusionProof } from "@heliuslabs/zolana/client";
import {
  ProofInputUtxo,
  SppProofInputs,
  createExternalData,
  createProofOutput,
} from "@heliuslabs/zolana/transaction";
import { outputBlindingSeed, transactOutputBlinding } from "@heliuslabs/zolana/keypair";
import { withRecordSlotSecret } from "../src/ring/velocity.js";
import { proofFor } from "./helpers/proofs.js";

const TREE_ID = 0;
const TREE = treeAddress(TREE_ID);
const FOREIGN_TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** A root blinding seed is a field element, so its leading byte stays zero. */
function blindingSeed(value: number): Bytes32 {
  const seed = bytes(value);
  seed[0] = 0;
  return seed;
}

type ProofFixture = Readonly<{
  proofInputs: SppProofInputs;
  spendProof: SpendProof;
  /** One non-inclusion proof per padding input, at the spend proof's nullifier root. */
  dummyProofs: readonly NonInclusionProof[];
  keypair: ShieldedKeypair;
}>;

/**
 * One real spend of tree 0 plus `dummyInputs` padding slots, every output
 * blinding derived from the first nullifier and the root seed the way the
 * circuit checks it.
 */
function proofFixture(
  options: Readonly<{ dummyInputs?: number; outputTreeId?: number; ring?: Address }> = {},
): ProofFixture {
  const outputTreeId = options.outputTreeId ?? TREE_ID;
  const keypair = ShieldedKeypair.generate();
  const input = ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 7n,
      blinding: bytes(1),
      ...(options.ring === undefined ? {} : { ringProgramId: options.ring }),
    }),
    keypair,
  );
  const dummyInputs = Array.from({ length: options.dummyInputs ?? 0 }, (_, index) =>
    ProofInputUtxo.dummy(bytes(10 + index)),
  );
  const seed = blindingSeed(9);
  const firstNullifier = input.nullifier();
  const outputSeed = outputBlindingSeed(firstNullifier, seed);
  const slotBlinding = (index: number): Bytes32 =>
    transactOutputBlinding(firstNullifier, outputSeed, index);
  const ownerTag = bytes(8);
  const output = createProofOutput({
    ownerAddress: keypair.shieldedAddress(),
    asset: SOL_MINT,
    amount: 7n,
    blinding: slotBlinding(0),
    ...(options.ring === undefined ? {} : { ringProgramId: options.ring }),
  });
  // No supported shape has a single output, so the real one always gains a pad.
  const padOutputs = Math.max(dummyInputs.length, 1);
  const outputs = [
    output,
    ...Array.from({ length: padOutputs }, (_, index) =>
      createProofOutput({
        asset: SOL_MINT,
        amount: 0n,
        blinding: slotBlinding(index + 1),
        ownerTag,
      }),
    ),
  ];
  const proofInputs = new SppProofInputs({
    // The payer must own the input UTXOs. Only its own are provable.
    payer: keypair.shieldedAddress().solanaAddress(),
    inputUtxos: [input, ...dummyInputs],
    outputs,
    externalData: createExternalData({
      txViewingPublicKey: keypair.viewingPublicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: outputs.map((entry) => ({
        utxoHash: entry.hash(outputTreeId),
        ownerTag: { kind: "inline", value: ownerTag },
      })),
      resolvedOwnerTags: outputs.map(() => ownerTag),
      messages: [],
    }),
    blindingSeed: seed,
    outputTreeId,
  });
  const spendProof: SpendProof = {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: TREE },
      path: Array.from({ length: 32 }, () => bytes(0)),
      leafIndex: 0n,
      root: bytes(3),
      rootSeq: 1n,
      rootIndex: 4,
    },
    nullifier: {
      leaf: input.nullifier(),
      merkleContext: { treeType: 1, tree: TREE },
      path: Array.from({ length: 40 }, () => bytes(0)),
      lowElement: bytes(4),
      lowElementIndex: 0n,
      highElement: bytes(5),
      highElementIndex: 1n,
      root: bytes(6),
      rootSeq: 1n,
      rootIndex: 2,
    },
  };
  const dummyProofs = dummyInputs.map((dummy): NonInclusionProof => ({
    leaf: dummy.nullifier(),
    merkleContext: { treeType: 1, tree: TREE },
    path: Array.from({ length: 40 }, () => bytes(0)),
    lowElement: bytes(4),
    lowElementIndex: 0n,
    highElement: bytes(5),
    highElementIndex: 1n,
    root: bytes(6),
    rootSeq: 1n,
    rootIndex: 2,
  }));
  return { proofInputs, spendProof, dummyProofs, keypair };
}

describe("ring record slot proving", () => {
  it("completes the indexed record slot without fetching client proofs", async () => {
    const fixture = proofFixture({ dummyInputs: 1, ring: FOREIGN_TREE });
    const zeroKey = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
    const record = ProofInputUtxo.fromNullifierKey(
      new Utxo({
        owner: ShieldedPublicKey.fromEd25519(bytes(44)),
        asset: SOL_MINT,
        amount: 0n,
        blinding: bytes(2),
        ringProgramId: FOREIGN_TREE,
      }),
      zeroKey,
    );
    zeroKey.destroy();
    const transaction = new SppProofInputs({
      ...fixture.proofInputs,
      inputUtxos: [fixture.proofInputs.inputUtxos[0]!, record],
    });
    const tree = {
      tree: TREE,
      id: TREE_ID,
      utxoRoot: fixture.spendProof.state.root,
      nullifierRoot: fixture.spendProof.nullifier.root,
      utxoRootIndex: fixture.spendProof.state.rootIndex,
      nullifierRootIndex: fixture.spendProof.nullifier.rootIndex,
    };
    const prepared = prepareTransfer(transaction, { kind: "ring", ring: FOREIGN_TREE });
    const complete = prepared.finish([
      {
        treeId: TREE_ID,
        slot: tree,
        utxoRootIndex: tree.utxoRootIndex,
        nullifierRootIndex: tree.nullifierRootIndex,
      },
    ]);
    const hex = (value: Bytes32) => `0x${bytesField(value, "field").toString(16)}`;
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      Response.json({
        ...proofFor({ circuitType: "transfer-ring", nInputs: 2, nOutputs: 2 }),
        resolution: {
          publicInputHash: hex(complete.publicInputHash),
          trees: [
            { ...tree, utxoRoot: hex(tree.utxoRoot), nullifierRoot: hex(tree.nullifierRoot) },
          ],
        },
      }),
    );
    const instance = new ZolanaClient({ fetch });
    const state = vi.spyOn(instance, "getMerkleProofs");
    const nullifier = vi.spyOn(instance, "getNonInclusionProofs");
    const keys = LocalKeys.fromKeypair(fixture.keypair, instance.proofService);
    try {
      const result = await instance.proveRingTransact(
        transaction,
        FOREIGN_TREE,
        withRecordSlotSecret(keys, record.nullifier()),
      );
      expect(result.data.circuit.kind).toBe("confidentialRingEddsa");
      expect(state).not.toHaveBeenCalled();
      expect(nullifier).not.toHaveBeenCalled();
      expect(fetch).toHaveBeenCalledOnce();
      expect(String(fetch.mock.calls[0]?.[0])).toMatch(/\/prove\/transfer_ring_2_2\/indexed$/u);
      const body: unknown = JSON.parse(String(fetch.mock.calls[0]?.[1]?.body));
      const decoder = wireDecoder(() => new Error("invalid body"));
      const payload = decoder.record(decoder.record(body, "body")["prepared"], "prepared");
      const inputs = decoder.list(payload["inputs"], "inputs");
      expect(decoder.record(inputs[0], "input")["nullifierSecret"]).toMatch(
        /^0x[1-9a-f][0-9a-f]*$/u,
      );
      expect(decoder.record(inputs[1], "record")["nullifierSecret"]).toBe("0x0");
    } finally {
      keys.destroy();
      fixture.keypair.destroy();
    }
  });
});
