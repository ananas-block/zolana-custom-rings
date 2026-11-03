import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { getBase58Decoder, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import ledgerVector from "../../../../test-vectors/audit/merge_ledger.json" with { type: "json" };

import {
  encodeMergeOutputData,
  encryptMergeOutput,
  mergeOutputKey,
  treeAddress,
  BN254_SCALAR_ORDER,
  bigIntToBytes,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes16, Bytes31, Bytes32, Signature } from "@heliuslabs/zolana/interface";
import { NullifierKey, X25519Keypair } from "@heliuslabs/zolana/keypair";
import { SOL_MINT, type IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";

import {
  kitReads,
  solanaRpcReads,
  transactionsPage,
} from "../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { sealRingMergeDisclosure } from "../../src/crypto/audit/merge-disclosure.js";
import { auditRingMerges } from "../../src/operations/audit/audit-merge.js";
import { knownUtxoOwnerHash, type KnownUtxo } from "../../src/operations/audit/audit.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../src/protocol/proof/custom-ring-proof.js";
import type { TransactionOrigin } from "../../src/protocol/transaction/origin.js";
import {
  MergeLedger,
  realMergeInputs,
  type ConfirmedMerge,
  type KnownMergeInput,
  type MergeInput,
  type MergeTransition,
} from "../../src/state/merge-ledger.js";
import { transactionItems } from "../../../../zolana/sdk-libs/ts/test/helpers/pages.js";

await initializePoseidon();

const OWNER_KEY = filled(1);
const NULLIFIER_PK = filled(2);
const ASSET = filled(7);
const MINT: Address = SOL_MINT;
const ZERO = filled(0);
const NOTHING: KnownMergeInput = () => undefined;

interface LedgerMerge {
  readonly slot: number;
  readonly txSignature: string;
  readonly eventIndex: number;
  readonly list: readonly string[];
  readonly outputCommitment: string;
  readonly treeId: number;
  readonly leafIndex: number;
  readonly firstNullifier: string;
}

interface LedgerStep {
  readonly opens: readonly Readonly<{ commitment: string; amount: number }>[];
  readonly merge: LedgerMerge | null;
  readonly spent: readonly string[];
  readonly resolved: readonly Readonly<{
    commitment: string;
    ownerKey: string;
    asset: string;
    amount: number;
  }>[];
  readonly unresolved: readonly string[];
}

interface LedgerCase {
  readonly name: string;
  readonly steps: readonly LedgerStep[];
}

function field(hex: string): Bytes32 {
  return hexToBytes(hex) as Bytes32;
}

function confirmedMerge(merge: LedgerMerge): ConfirmedMerge {
  return {
    slot: BigInt(merge.slot),
    signature: merge.txSignature as Signature,
    eventIndex: merge.eventIndex,
    outputCommitment: field(merge.outputCommitment),
    treeId: merge.treeId,
    leafIndex: BigInt(merge.leafIndex),
    firstNullifier: field(merge.firstNullifier),
    inputs: realMergeInputs(merge.list.map(field), merge.list.length),
  };
}

function filled(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

function signatureOf(byte: number): Signature {
  return getBase58Decoder().decode(new Uint8Array(64).fill(byte)) as Signature;
}

function note(amount: bigint): MergeInput {
  return {
    ownerKey: OWNER_KEY,
    owner: { kind: "keyed", nullifierPk: NULLIFIER_PK },
    asset: ASSET,
    mint: MINT,
    amount,
  };
}

function merge(id: number, inputs: readonly number[], output: number): ConfirmedMerge {
  return {
    slot: BigInt(id),
    signature: signatureOf(id),
    eventIndex: 0,
    outputCommitment: filled(output),
    treeId: 1,
    leafIndex: BigInt(id),
    firstNullifier: filled(id),
    inputs: inputs.map(filled),
  };
}

function knownOnly(openings: Readonly<Record<number, bigint>>): KnownMergeInput {
  return (commitment) => {
    const amount = openings[commitment[0] ?? 0];
    return amount === undefined ? undefined : note(amount);
  };
}

describe("MergeLedger", () => {
  it("records the sum under the inherited owner and asset, with no wallet opening", () => {
    const ledger = new MergeLedger();
    const transition = ledger.apply(merge(1, [10, 11], 20), knownOnly({ 10: 10n, 11: 11n }));
    expect(transition.spent).toEqual([filled(10), filled(11)]);
    expect(transition.resolved).toEqual([
      {
        commitment: filled(20),
        slot: 1n,
        signature: signatureOf(1),
        eventIndex: 0,
        treeId: 1,
        leafIndex: 1n,
        ownerKey: OWNER_KEY,
        owner: { kind: "keyed", nullifierPk: NULLIFIER_PK },
        asset: ASSET,
        mint: MINT,
        amount: 21n,
        inputs: [filled(10), filled(11)],
      },
    ]);
    expect(ledger.output(filled(20))).toEqual(transition.resolved[0]);
    expect(ledger.outputs()).toEqual(transition.resolved);
  });

  it("applies each signature and event index once", () => {
    const ledger = new MergeLedger();
    const known = knownOnly({ 10: 5n });
    expect(ledger.apply(merge(1, [10], 20), known).spent).toEqual([filled(10)]);
    const first = ledger.outputs();
    expect(ledger.apply(merge(1, [10], 20), known)).toEqual({
      spent: [],
      resolved: [],
    });
    expect(ledger.outputs()).toEqual(first);
    const sameTransaction = { ...merge(1, [12], 21), eventIndex: 1 };
    expect(ledger.apply(sameTransaction, NOTHING).spent).toEqual([filled(12)]);
  });

  it("marks an unknown input spent and holds the merge and its descendant until it opens", () => {
    const ledger = new MergeLedger();
    ledger.apply(merge(2, [20, 12], 30), NOTHING);
    const parent = ledger.apply(merge(1, [10], 20), NOTHING);
    expect(parent.spent).toEqual([filled(10)]);
    expect(parent.resolved).toEqual([]);
    expect(ledger.unresolved().map(({ slot }) => slot)).toEqual([1n, 2n]);

    expect(ledger.resolve(knownOnly({ 10: 5n })).map(({ amount }) => amount)).toEqual([5n]);
    expect(ledger.unresolved().map(({ slot }) => slot)).toEqual([2n]);

    expect(ledger.resolve(knownOnly({ 10: 5n, 12: 6n })).map(({ amount }) => amount)).toEqual([
      11n,
    ]);
    expect(ledger.unresolved()).toEqual([]);
  });

  it("runs resolution through a chain of descendants to a fixed point", () => {
    const ledger = new MergeLedger();
    ledger.apply(merge(1, [10], 20), NOTHING);
    ledger.apply(merge(2, [20], 30), NOTHING);
    ledger.apply(merge(3, [30], 40), NOTHING);
    const resolved = ledger.resolve(knownOnly({ 10: 9n }));
    expect(resolved.map(({ commitment }) => commitment)).toEqual([
      filled(20),
      filled(30),
      filled(40),
    ]);
    expect(ledger.output(filled(40))?.amount).toBe(9n);
  });

  it.each([
    [10, 11],
    [11, 10],
  ])("resolves equal deposited and keyed owners through descendants in order %j", (...inputs) => {
    const keyed = note(5n);
    const deposited: MergeInput = {
      ...keyed,
      owner: { kind: "deposited", ownerHash: knownUtxoOwnerHash(keyed) },
    };
    const ledger = new MergeLedger();
    ledger.apply(merge(2, [20, 12], 30), NOTHING);
    ledger.apply(merge(1, inputs, 20), NOTHING);
    const known: KnownMergeInput = (commitment) => {
      switch (commitment[0]) {
        case 10:
          return deposited;
        case 11:
          return keyed;
        case 12:
          return note(7n);
        default:
          return undefined;
      }
    };
    expect(ledger.resolve(known)).toHaveLength(2);
    expect(ledger.output(filled(20))).toMatchObject({ owner: keyed.owner, amount: 10n });
    expect(ledger.output(filled(30))).toMatchObject({ owner: keyed.owner, amount: 17n });
    expect(ledger.unresolved()).toEqual([]);
  });

  it("reads a zero list entry as a dummy, never an input and never spent", () => {
    const inputs = realMergeInputs([filled(10), ZERO, filled(11), ZERO], 8);
    expect(inputs).toEqual([filled(10), filled(11)]);
    const ledger = new MergeLedger();
    const transition = ledger.apply({ ...merge(1, [], 20), inputs }, knownOnly({ 10: 4n, 11: 4n }));
    expect(transition.spent).toEqual(inputs);
    expect(transition.resolved[0]?.amount).toBe(8n);
  });

  it.each(["apply", "resolve"] as const)(
    "keeps the ledger unchanged when %s fails in a descendant owner check",
    (operation) => {
      const ledger = new MergeLedger();
      const parent = merge(1, [10], 20);
      const descendant = merge(2, [20, 11], 30);
      ledger.apply(parent, NOTHING);
      if (operation === "resolve") ledger.apply(descendant, NOTHING);
      const before = ledger.unresolved();
      const invalid: MergeInput = {
        ...note(5n),
        owner: {
          kind: "keyed",
          nullifierPk: bigIntToBytes(BN254_SCALAR_ORDER) as Bytes32,
        },
      };
      const known: KnownMergeInput = (commitment) => {
        if (commitment[0] === 10) return note(5n);
        if (commitment[0] === 11) return invalid;
        return undefined;
      };
      const resolve = (openings: KnownMergeInput) =>
        operation === "apply"
          ? ledger.apply(descendant, openings).resolved
          : ledger.resolve(openings);
      expect(() => resolve(known)).toThrow();
      expect(ledger.outputs()).toEqual([]);
      expect(ledger.unresolved()).toEqual(before);
      expect(resolve(knownOnly({ 10: 5n, 11: 7n }))).toHaveLength(2);
      expect(ledger.output(filled(30))?.amount).toBe(12n);
      expect(ledger.unresolved()).toEqual([]);
    },
  );

  it.each<readonly [string, MergeInput]>([
    ["two owner keys", { ...note(1n), ownerKey: filled(9) }],
    ["two nullifier keys", { ...note(1n), owner: { kind: "keyed", nullifierPk: filled(9) } }],
    [
      "a keyed and a deposited owner",
      { ...note(1n), owner: { kind: "deposited", ownerHash: filled(2) } },
    ],
    ["two assets", { ...note(1n), asset: filled(9) }],
    ["an amount past u64", { ...note(2n ** 64n - 1n) }],
  ])("never resolves inputs of %s", (_name, second) => {
    const ledger = new MergeLedger();
    const known: KnownMergeInput = (commitment) => (commitment[0] === 10 ? note(1n) : second);
    expect(ledger.apply(merge(1, [10, 11], 20), known).resolved).toEqual([]);
    expect(ledger.unresolved()).toHaveLength(1);
  });

  it("names the mint any input knows", () => {
    const ledger = new MergeLedger();
    const { mint: _mint, ...unnamed } = note(1n);
    const known: KnownMergeInput = (commitment) => (commitment[0] === 10 ? unnamed : note(1n));
    expect(ledger.apply(merge(1, [10, 11], 20), known).resolved[0]?.mint).toBe(MINT);
  });

  describe("the shared vector", () => {
    const pinned = ledgerVector.note;
    const inherited = {
      ownerKey: field(pinned.ownerKey),
      owner: { kind: "keyed", nullifierPk: field(pinned.nullifierPk) },
      asset: field(pinned.asset),
      mint: pinned.mint as Address,
    } satisfies Omit<MergeInput, "amount">;

    it.each(ledgerVector.cases as readonly LedgerCase[])("$name", ({ steps }) => {
      const ledger = new MergeLedger();
      const opened = new Map<string, bigint>();
      const known: KnownMergeInput = (commitment) => {
        const amount = opened.get(bytesToHex(commitment));
        return amount === undefined ? undefined : { ...inherited, amount };
      };
      for (const step of steps) {
        for (const { commitment, amount } of step.opens) opened.set(commitment, BigInt(amount));
        if (step.merge === null) {
          expect(step.spent).toEqual([]);
          expectResolved(ledger.resolve(known), step.resolved);
        } else {
          const transition = ledger.apply(confirmedMerge(step.merge), known);
          expect(transition.spent.map((input) => bytesToHex(input))).toEqual(step.spent);
          expectResolved(transition.resolved, step.resolved);
        }
        expect(ledger.unresolved().map((merge) => bytesToHex(merge.outputCommitment))).toEqual(
          step.unresolved,
        );
      }
    });

    function expectResolved(
      resolved: MergeTransition["resolved"],
      pinnedOutputs: LedgerStep["resolved"],
    ): void {
      expect(
        resolved.map((output) => ({
          commitment: bytesToHex(output.commitment),
          ownerKey: bytesToHex(output.ownerKey),
          asset: bytesToHex(output.asset),
          amount: Number(output.amount),
        })),
      ).toEqual(pinnedOutputs);
      for (const output of resolved) expect(output).toMatchObject(inherited);
    }
  });
});

describe("auditRingMerges", () => {
  const auditor = X25519Keypair.generate();
  const key = NullifierKey.fromSecret(new Uint8Array(31).fill(5) as Bytes31);
  const ring = getBase58Decoder().decode(filled(23)) as Address;

  /** Four published nullifiers pad to width 8, the list has `real.length` nonzero slots. */
  function disclosedMerge(real: readonly number[], listLength = 8, output = 40) {
    const firstNullifier = filled(0x11);
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const sealed = sealRingMergeDisclosure(
      Array.from({ length: listLength }, (_, index) => filled(real[index] ?? 0)),
      salt,
      auditor.publicKey(),
    );
    const transaction: IndexedShieldedTransaction = {
      slot: BigInt(output),
      txSignature: signatureOf(output),
      eventIndex: 0,
      proofless: false,
      ringProgramId: ring,
      nullifiers: [firstNullifier, filled(0x12), filled(0x13), filled(0x14)],
      messages: [],
      outputSlots: [
        {
          viewTag: firstNullifier,
          payload: encodeMergeOutputData({
            salt,
            ciphertext: encryptMergeOutput(
              { amount: 9n, mint: SOL_MINT },
              mergeOutputKey(key, firstNullifier),
              salt,
            ),
            ringDataHash: filled(0x15),
          }),
          outputContext: {
            hash: filled(output),
            tree: treeAddress(1),
            treeId: 1,
            leafIndex: 3n,
          },
        },
      ],
    };
    return {
      transaction,
      disclosure: {
        ...sealed.disclosure,
        proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
      },
    };
  }

  it("names a merge's inputs again when a page retries over a carried ledger", async () => {
    const ledger = new MergeLedger();
    const row = disclosedMerge([10, 11]);
    const first = await audit([row], { ledger });
    const retried = await audit([row], { ledger });
    expect(first.spent).toHaveLength(2);
    expect(retried.spent).toEqual(first.spent);
    expect(ledger.unresolved()).toHaveLength(1);
  });

  function audit(
    rows: readonly ReturnType<typeof disclosedMerge>[],
    extra: Readonly<{
      knownUtxos?: { utxo(commitment: Bytes32): KnownUtxo | undefined };
      ledger?: MergeLedger;
    }> = {},
    bare: readonly IndexedShieldedTransaction[] = [],
  ) {
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction) => {
        const row = rows.find((entry) => entry.transaction === transaction);
        return {
          kind: "merge",
          transaction,
          ...(row === undefined ? {} : { disclosure: row.disclosure }),
        };
      },
    };
    return auditRingMerges({
      client: {
        ...kitReads({ solanaRpc: solanaRpcReads({}) }),
        getShieldedTransactionsByTags: async () =>
          transactionsPage({
            data: transactionItems([...rows.map((row) => row.transaction), ...bare]),
          }),
      },
      ringProgramId: ring,
      auditor,
      origin,
      ...extra,
    });
  }

  function knownNote(amount: bigint): KnownUtxo {
    return {
      ...note(amount),
      blinding: filled(3),
      dataHash: ZERO,
      ringDataHash: ZERO,
      treeId: 1,
    };
  }

  it("spends every nonzero slot and never reads the published count as real inputs", async () => {
    const page = await audit([disclosedMerge([10, 11])], {
      knownUtxos: { utxo: () => knownNote(4n) },
    });
    expect(page.spent).toEqual([filled(10), filled(11)]);
    expect(page.outputs.map(({ amount, inputs }) => ({ amount, inputs }))).toEqual([
      { amount: 8n, inputs: [filled(10), filled(11)] },
    ]);
    expect(page.unresolved).toEqual([]);
    expect(page.skipped).toEqual([]);
  });

  it("holds a merge of an unknown input and resolves it on a later page of one ledger", async () => {
    const ledger = new MergeLedger();
    const row = disclosedMerge([10]);
    const held = await audit([row], { ledger });
    expect(held.spent).toEqual([filled(10)]);
    expect(held.outputs).toEqual([]);
    expect(held.unresolved.map(({ outputCommitment }) => outputCommitment)).toEqual([filled(40)]);

    const later = await audit([], {
      ledger,
      knownUtxos: { utxo: () => knownNote(6n) },
    });
    expect(later.spent).toEqual([]);
    expect(later.outputs.map(({ amount }) => amount)).toEqual([6n]);
    expect(later.unresolved).toEqual([]);
  });

  it("lists a disclosure of another width among the skipped rows", async () => {
    const page = await audit([disclosedMerge([10], 24)]);
    expect(page.spent).toEqual([]);
    expect(page.skipped.map(({ reason }) => reason)).toEqual(["invalidAuditData"]);
  });

  it("leaves a row without a v3 disclosure to the historical reader", async () => {
    const { transaction } = disclosedMerge([10]);
    const page = await audit([], {}, [transaction]);
    expect(page.spent).toEqual([]);
    expect(page.historical).toEqual([
      {
        slot: transaction.slot,
        signature: transaction.txSignature,
        eventIndex: 0,
      },
    ]);
  });
});
