import { address, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";
import {
  type Bytes32,
  ShieldedKeypair,
  SigningKey,
  Data,
  Utxo,
  Wallet,
  SOL_MINT,
  LocalKeys,
  type ProofService,
} from "@heliuslabs/zolana";
import { X25519Keypair } from "@heliuslabs/zolana/keypair";
import { AssetRegistry, approveIntent, type ApprovalRequest } from "@heliuslabs/zolana/transaction";
import {
  MAX_SPEND_INPUTS,
  isPlainUtxo,
  selectUtxos,
  type SpendSelectionErrors,
  treeAddress,
} from "@heliuslabs/zolana/internal";
import { MAX_INPUT_TREES } from "@heliuslabs/zolana/interface";
import { ringConfigPda } from "../src/interface/pda/index.js";
import { RING_INPUT_SLOTS } from "../src/client/prover/types.js";
import {
  buildRingEntryTransaction,
  buildRingTransferTransaction,
  selectRingInputs,
} from "../src/ring/transfer.js";
import { ringTransferClient } from "./helpers/clients.js";
import { ringProgramConfigData } from "./helpers/ring-accounts.js";

const TREE = treeAddress(0);
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
}

/** Unit tests never reach the prover; the keys still need one to exist. */
function localKeys(keypair: ShieldedKeypair): LocalKeys {
  const proofs: ProofService = {
    prove: vi.fn(async () => {
      throw new Error("prove must not be called");
    }),
    proveMerge: vi.fn(async () => {
      throw new Error("proveMerge must not be called");
    }),
  };
  return LocalKeys.fromKeypair(keypair, proofs);
}

/** Records every approval a build asks for and grants it. */
function recordingApproval(): Readonly<{
  approve: (request: ApprovalRequest) => Promise<ReturnType<typeof approveIntent>>;
  requests: ApprovalRequest[];
}> {
  const requests: ApprovalRequest[] = [];
  return {
    approve: (request) => {
      requests.push(request);
      return Promise.resolve(approveIntent(request.intent));
    },
    requests,
  };
}

function ringUtxoWallet(
  keypair: ShieldedKeypair,
  utxos: readonly (readonly [bigint, Address | undefined, Address?])[],
): Wallet {
  const wallet = new Wallet({ identity: keypair.shieldedAddress(), registry: new AssetRegistry() });
  wallet._replace({
    utxos: utxos.map(([amount, ringProgramId, tree], index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: filled(index + 1),
        data: new Data(),
        ...(ringProgramId === undefined ? {} : { ringProgramId }),
      }),
      outputContext: { hash: filled(index + 1), tree: tree ?? TREE, leafIndex: BigInt(index) },
      nullifier: filled(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

const errors: SpendSelectionErrors = {
  insufficient: ({ requested, available }) =>
    new Error(`insufficient ${String(requested)} ${String(available)}`),
  tooManyInputs: ({ eligible, max }) => new Error(`tooMany ${String(eligible)} ${String(max)}`),
  overflow: () => new Error("overflow"),
  multipleTrees: ({ treeCount }) => new Error(`trees ${String(treeCount)}`),
  tooFewUtxos: ({ eligible, minimum }) =>
    new Error(`tooFew ${String(eligible)} ${String(minimum)}`),
};

describe("ring UTXO selection", () => {
  it("allows wide eligible ring balances without changing the default rail's u64 check", () => {
    const half = (1n << 63n) + 1n;
    const amount = (1n << 64n) - 1n;
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [half, undefined],
      [half, undefined],
    ]);
    const before = wallet.utxos();
    const selected = selectRingInputs({
      wallet,
      ringProgramId: RECIPIENT,
      asset: SOL_MINT,
      amount,
      inputs: "default",
      tree: TREE,
      maxInputs: RING_INPUT_SLOTS,
    });
    expect(selected).toHaveLength(2);
    expect(selected.reduce((sum, entry) => sum + entry.utxo.amount, 0n) - amount).toBe(3n);
    expect(() =>
      selectUtxos({
        wallet,
        asset: SOL_MINT,
        target: { kind: "cover", amount },
        policy: {
          eligible: isPlainUtxo,
          ordering: "largestFirst",
          maxInputs: MAX_SPEND_INPUTS,
          tree: { kind: "infer", maxTrees: MAX_INPUT_TREES },
          errors,
        },
      }),
    ).toThrow("overflow");
    expect(wallet.utxos()).toEqual(before);
  });
});

describe("selectRingInputs", () => {
  it("refuses a zero amount", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [[10n, RING]]);
    expect(() =>
      selectRingInputs({
        wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 0n,
        inputs: "ring",
        tree: TREE,
        maxInputs: RING_INPUT_SLOTS,
      }),
    ).toThrow("RING_ZERO_AMOUNT");
  });

  it("keeps default UTXOs out of ring funding unless the entry opts in", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [10n, undefined],
      [10n, RING],
    ]);
    expect(() =>
      selectRingInputs({
        wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 15n,
        inputs: "ring",
        tree: TREE,
        maxInputs: RING_INPUT_SLOTS,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
    const selected = selectRingInputs({
      wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 15n,
      inputs: "ring-or-default",
      tree: TREE,
      maxInputs: RING_INPUT_SLOTS,
    });
    expect(selected).toHaveLength(2);
  });

  it("funds a default-only entry even when a ring UTXO covers", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [100n, RING],
      [25n, undefined],
    ]);
    const selected = selectRingInputs({
      wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 25n,
      inputs: "default",
      tree: TREE,
      maxInputs: RING_INPUT_SLOTS,
    });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.ringProgramId).toBeUndefined();
    expect(() =>
      selectRingInputs({
        wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 30n,
        inputs: "default",
        tree: TREE,
        maxInputs: RING_INPUT_SLOTS,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
  });

  it("never offers a UTXO outside the requested tree", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [50n, RING, RECIPIENT],
      [20n, RING],
    ]);
    const selected = selectRingInputs({
      wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 20n,
      inputs: "ring",
      tree: TREE,
      maxInputs: RING_INPUT_SLOTS,
    });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.amount).toBe(20n);
    expect(() =>
      selectRingInputs({
        wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 30n,
        inputs: "ring",
        tree: TREE,
        maxInputs: RING_INPUT_SLOTS,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
  });

  it("covers a fragmented balance with the largest UTXO", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      ...Array.from({ length: 6 }, () => [5n, RING] as const),
      [100n, RING],
    ]);
    const selected = selectRingInputs({
      wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 100n,
      inputs: "ring",
      tree: TREE,
      maxInputs: RING_INPUT_SLOTS,
    });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.amount).toBe(100n);
  });

  it("refuses a cover wider than the input cap", () => {
    const wallet = ringUtxoWallet(
      spendingKeypair(),
      Array.from({ length: 6 }, () => [5n, RING] as const),
    );
    expect(() =>
      selectRingInputs({
        wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 30n,
        inputs: "ring",
        tree: TREE,
        maxInputs: RING_INPUT_SLOTS,
      }),
    ).toThrow("RING_TOO_MANY_INPUTS");
  });

  it("never offers another ring's UTXOs under either mode", () => {
    const wallet = ringUtxoWallet(spendingKeypair(), [
      [50n, RECIPIENT],
      [20n, undefined],
    ]);
    const selected = selectRingInputs({
      wallet,
      ringProgramId: RING,
      asset: SOL_MINT,
      amount: 20n,
      inputs: "ring-or-default",
      tree: TREE,
      maxInputs: RING_INPUT_SLOTS,
    });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.utxo.ringProgramId).toBeUndefined();
    expect(() =>
      selectRingInputs({
        wallet,
        ringProgramId: RING,
        asset: SOL_MINT,
        amount: 30n,
        inputs: "ring-or-default",
        tree: TREE,
        maxInputs: RING_INPUT_SLOTS,
      }),
    ).toThrow("RING_INSUFFICIENT_BALANCE");
  });
});

describe("ring approval summary", () => {
  async function approvalClient(_keypair: ShieldedKeypair) {
    const [config, bump] = await ringConfigPda(RING);
    return ringTransferClient({
      tree: TREE,
      getAccount: async (address) =>
        address === config
          ? {
              owner: RING,
              lamports: 1n,
              data: ringProgramConfigData({
                authority: PAYER,
                auditorPublicKey: X25519Keypair.fromBytes(new Uint8Array(32).fill(9))
                  .publicKey()
                  .toBytes(),
                bump,
                hasPolicy: false,
              }),
            }
          : undefined,
    });
  }
  it("approves the exact amount moved into the ring", async () => {
    const keypair = spendingKeypair();
    const wallet = ringUtxoWallet(keypair, [[40n, undefined]]);
    const { approve, requests } = recordingApproval();

    await expect(
      buildRingEntryTransaction({
        client: await approvalClient(keypair),
        ringProgramId: RING,
        wallet,
        keys: localKeys(keypair),
        approve,
        feePayer: keypair.shieldedAddress().solanaAddress(),
        amount: 25n,
      }),
    ).rejects.toMatchObject({ code: "RING_BUILD_ENTRY" });
    expect(requests.map((request) => request.summary)).toEqual([
      `ring entry of 25 SOL into ring ${RING}`,
    ]);
    expect(requests[0]?.intent).toMatchObject({ kind: "ringEntry", amount: 25n });
  });

  async function capturedSummary(
    utxos: readonly (readonly [bigint, Address | undefined])[],
    amount: bigint,
    inputs: "ring" | "ring-or-default" | "default",
  ): Promise<string> {
    const keypair = spendingKeypair();
    const wallet = ringUtxoWallet(keypair, utxos);
    const { approve, requests } = recordingApproval();
    await expect(
      buildRingTransferTransaction({
        client: await approvalClient(keypair),
        ringProgramId: RING,
        wallet,
        keys: localKeys(keypair),
        approve,
        feePayer: keypair.shieldedAddress().solanaAddress(),
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        amount,
        inputs,
      }),
    ).rejects.toMatchObject({ code: "RING_BUILD_TRANSFER" });
    const summary = requests[0]?.summary;
    if (summary === undefined) throw new Error("approval not requested");
    return summary;
  }

  it("names the whole default UTXO crossing into the ring, change included", async () => {
    const summary = await capturedSummary([[40n, undefined]], 25n, "default");
    expect(summary).toContain("ring entry of 25 SOL");
    expect(summary).toContain("moves 40 SOL of default UTXOs into the ring");
  });

  it("counts only the default share of mixed funding", async () => {
    const summary = await capturedSummary(
      [
        [30n, undefined],
        [10n, RING],
      ],
      35n,
      "ring-or-default",
    );
    expect(summary).toContain("ring entry of 35 SOL");
    expect(summary).toContain("moves 30 SOL of default UTXOs into the ring");
  });

  it("stays a transfer with no crossing clause on ring-only funding", async () => {
    const summary = await capturedSummary([[40n, RING]], 25n, "ring");
    expect(summary).toContain("ring transfer of 25 SOL");
    expect(summary).not.toContain("default UTXOs");
  });
});
