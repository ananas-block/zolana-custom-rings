import { readFileSync } from "node:fs";

import {
  TRANSACTION_SIZE_LIMIT,
  type Address,
  type Bytes32,
  type Instruction,
} from "@heliuslabs/zolana/interface";
import { encodeBase58, treeAddress } from "@heliuslabs/zolana/internal";
import { ShieldedKeypair } from "@heliuslabs/zolana/keypair";
import { SOL_MINT } from "@heliuslabs/zolana/transaction";
import { AccountRole } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { field, ringFrame, ringInstructionData } from "../../helpers/ring-frame.js";
import { MAX_CPI_DATA_LEN } from "../../../src/protocol/transaction/frame-buffer.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { MAX_TRANSACTION_ADDRESSES as LIMIT } from "../../../src/operations/workflow/compile.js";
import { ringTransactInstruction } from "../../../src/operations/workflow/pipeline.js";
import { transactionSize } from "../../../src/operations/workflow/compile.js";
import {
  CredentialTrees,
  decideAddressCeiling,
  TransactionFit,
  type CeilingDecision,
  type MergeCapacity,
  type SpentInput,
} from "../../../src/operations/workflow/address-ceiling.js";

function address(seed: number): Address {
  const bytes = new Uint8Array(32).fill(0xaa);
  new DataView(bytes.buffer).setUint32(0, seed);
  return encodeBase58(bytes);
}

const owners = new Map<number, ShieldedKeypair>();
const ownerOf = (owner: number): ShieldedKeypair => {
  const held = owners.get(owner) ?? ShieldedKeypair.generate();
  owners.set(owner, held);
  return held;
};

const note = (owner: number, seed: number): SpentInput => ({
  owner: ownerOf(owner).signingPublicKey(),
  asset: SOL_MINT,
  nullifierPublicKey: new Uint8Array(32).fill(owner) as Bytes32,
  ringProgramId: address(0),
  treeId: 1,
  nullifierPda: address(1000 + seed),
});

function decide(
  inputs: readonly SpentInput[],
  other: number,
  mergeCapacity: MergeCapacity = { keyed: 45, zeroKey: 45 },
): Promise<CeilingDecision> {
  const accounts = [
    ...inputs.map((input) => input.nullifierPda),
    ...Array.from({ length: other }, (_, seed) => address(5000 + seed)),
  ].map((account) => ({ address: account, role: 1 }));
  const instruction = { programAddress: address(2), accounts } as unknown as Instruction;
  return decideAddressCeiling({
    payer: address(1),
    instruction,
    computeUnitLimit: 1_000_000,
    inputs,
    mergeCapacity,
  });
}

const notes = (owner: number, count: number): readonly SpentInput[] =>
  Array.from({ length: count }, (_, seed) => note(owner, seed));

const refused = async (inputs: readonly SpentInput[], other: number) => {
  try {
    await decide(inputs, other);
  } catch (error) {
    return (error as { code?: string; details?: unknown }).details;
  }
  throw new Error("under the ceiling");
};

/** A frame that parses under its rail, each message stretches it. */
const realFrame = (messages: readonly number[] = []): Instruction =>
  ({
    programAddress: address(2),
    accounts: [],
    data: ringInstructionData({
      ...ringFrame({ rail: "confidential", inputs: 1, outputs: 2 }),
      extensions: {
        messages: messages.map((length) => ({ viewTag: field(9), data: new Uint8Array(length) })),
      },
    }),
  }) as unknown as Instruction;

const signing = (key: number): Instruction =>
  ({
    programAddress: address(3),
    accounts: [{ address: address(key), role: 2 }],
  }) as unknown as Instruction;

const BUDGET = { computeUnitLimit: 1_000_000 };

describe("decideAddressCeiling, the cases of Rust `validation::address_ceiling`", () => {
  it("keeps a transaction at the ceiling one transaction", async () => {
    expect(await decide(notes(1, 10), LIMIT - 2 - 10)).toMatchObject({
      kind: "inline",
      size: { addresses: LIMIT },
    });
  });

  it("names only the groups the ceiling needs", async () => {
    const inputs = [...notes(1, 4), note(2, 4), note(2, 5)];
    const decision = await decide(inputs, LIMIT - 2 - 6 + 2);
    if (decision.kind !== "mergeFirst") throw new Error("merge first");
    expect(decision.addresses).toBe(LIMIT - 1);
    expect(decision.groups.map((group) => group.inputs)).toEqual([[0, 1, 2, 3]]);
    expect(decision.groups[0]?.owner.equals(inputs[0]?.owner as never)).toBe(true);
  });

  it("forms no group of mixed owners and reports the compiled count", async () => {
    const inputs = [0, 1, 2, 3].map((seed) => note(seed + 1, seed));
    expect(await refused(inputs, LIMIT - 2 - 4 + 1)).toEqual({
      compiled: LIMIT + 1,
      limit: LIMIT,
      afterMerging: LIMIT + 1,
      dataNotes: 0,
    });
  });

  it("keeps a data note out of every group", async () => {
    const inputs = notes(1, 4).map((input) => ({
      ...input,
      dataHash: new Uint8Array(32).fill(9) as Bytes32,
    }));
    expect(await refused(inputs, LIMIT - 2 - 4 + 1)).toMatchObject({
      afterMerging: LIMIT + 1,
      dataNotes: 4,
    });
  });

  it("merges no notes of another asset, key or tree", async () => {
    const inputs = [
      note(1, 0),
      { ...note(1, 1), asset: address(7) },
      { ...note(1, 2), nullifierPublicKey: new Uint8Array(32).fill(9) as Bytes32 },
      { ...note(1, 3), treeId: 2 },
    ];
    expect(await refused(inputs, LIMIT - 2 - 4 + 1)).toMatchObject({ afterMerging: LIMIT + 1 });
  });

  it("refuses consolidation short of the ceiling with how far it reached", async () => {
    expect(await refused(notes(1, 4), LIMIT - 2 - 4 + 5)).toMatchObject({
      compiled: LIMIT + 5,
      afterMerging: LIMIT + 2,
    });
  });

  it("names no merge for a lone note past the capacity", async () => {
    const decision = await decide(notes(1, 4), LIMIT - 2 - 4 + 1, { keyed: 3, zeroKey: 3 });
    if (decision.kind !== "mergeFirst") throw new Error("merge first");
    expect(decision.groups.map((group) => group.inputs)).toEqual([[0, 1, 2]]);
    expect(decision.addresses).toBe(LIMIT - 1);
  });

  it("reads a frame that parses under neither rail as unparsed, whatever its length", async () => {
    const data = new Uint8Array(1000);
    data[0] = RingInstructionTag.transfer;
    const instruction = {
      programAddress: address(2),
      accounts: [],
      data,
    } as unknown as Instruction;
    await expect(
      decideAddressCeiling({
        payer: address(1),
        instruction,
        computeUnitLimit: 1_000_000,
        inputs: [],
        mergeCapacity: { keyed: 45, zeroKey: 45 },
      }),
    ).rejects.toMatchObject({ code: "RING_FIT_UNPARSED_FRAME" });
  });
});

describe("TransactionFit, the refusals of Rust `TransactionFit`", () => {
  const payer = { payer: address(1) };

  it("keeps a frame under the ceiling inline and reads its CPI bytes", async () => {
    const fit = await TransactionFit.of(realFrame(), payer, BUDGET);
    expect(fit).toMatchObject({ transport: "inline", signatures: 1, addresses: 2 });
    expect(fit.cpiBytes).toBeGreaterThan(realFrame().data?.length ?? 0);
    expect(fit.setup).toEqual({ instructions: 0, signatures: 0, bytes: 0, addresses: 0 });
  });

  it("names no CPI bytes off the transfer tags", async () => {
    const fit = await TransactionFit.of(signing(4), payer, BUDGET);
    expect(fit.cpiBytes).toBeUndefined();
    expect(fit.signatures).toBe(2);
  });

  it("settles from a buffer past the byte ceiling, the figures the settlement's", async () => {
    const instruction = realFrame([4000]);
    const fit = await TransactionFit.of(instruction, payer, BUDGET);
    expect(fit.transport).toBe("buffered");
    expect(fit.bytes).toBeLessThan(TRANSACTION_SIZE_LIMIT);
  });

  it("refuses a buffer on the inline path by its bytes", () => {
    expect(() => TransactionFit.inline(realFrame([4096]), payer, BUDGET)).toThrowError(
      expect.objectContaining({ code: "RING_FIT_BYTES" }),
    );
  });

  it("refuses bytes on a tag no buffer takes", async () => {
    const instruction = {
      ...signing(4),
      data: new Uint8Array(TRANSACTION_SIZE_LIMIT).fill(0xff),
    } as unknown as Instruction;
    await expect(TransactionFit.of(instruction, payer, BUDGET)).rejects.toMatchObject({
      code: "RING_FIT_BYTES",
    });
  });

  it("refuses an expansion past one CPI under either transport, ahead of every other ceiling", async () => {
    const instruction = realFrame([MAX_CPI_DATA_LEN]);
    const refusal = { code: "RING_FIT_CPI_BYTES", details: { limit: MAX_CPI_DATA_LEN } };
    await expect(TransactionFit.of(instruction, payer, BUDGET)).rejects.toMatchObject(refusal);
    const crowded = Array.from({ length: 13 }, (_, key) => signing(50 + key));
    await expect(
      TransactionFit.of(instruction, { ...payer, setupInstructions: crowded }, BUDGET),
    ).rejects.toMatchObject(refusal);
  });

  it("counts a signer two instructions share once and refuses past twelve", async () => {
    const twelve = Array.from({ length: 11 }, (_, key) => signing(50 + key));
    const fit = await TransactionFit.of(
      signing(50),
      { ...payer, setupInstructions: twelve },
      BUDGET,
    );
    expect(fit.signatures).toBe(12);
    expect(fit.setup).toMatchObject({ instructions: 11, signatures: 10 });
    await expect(
      TransactionFit.of(signing(61), { ...payer, setupInstructions: twelve }, BUDGET),
    ).rejects.toMatchObject({
      code: "RING_FIT_SIGNATURES",
      details: { signers: 13, limit: 12 },
    });
  });

  it("refuses instructions past the v1 ceiling after signatures", async () => {
    const setupInstructions = Array.from({ length: 64 }, () => signing(4));
    await expect(
      TransactionFit.of(signing(4), { ...payer, setupInstructions }, BUDGET),
    ).rejects.toMatchObject({
      code: "RING_FIT_INSTRUCTIONS",
      details: { instructions: 65, limit: 64 },
    });
  });

  it("refuses addresses by their compiled count", async () => {
    const accounts = Array.from({ length: LIMIT }, (_, seed) => ({
      address: address(5000 + seed),
      role: 1,
    }));
    const instruction = { programAddress: address(2), accounts } as unknown as Instruction;
    await expect(TransactionFit.of(instruction, payer, BUDGET)).rejects.toMatchObject({
      code: "RING_FIT_ADDRESSES",
      details: { addresses: LIMIT + 2, limit: LIMIT },
    });
  });

  it("refuses the address a setup instruction adds past the ceiling", async () => {
    const accounts = Array.from({ length: LIMIT - 3 }, (_, seed) => ({
      address: address(5000 + seed),
      role: AccountRole.READONLY,
    }));
    const instruction = { programAddress: address(2), accounts } as unknown as Instruction;
    const setup = (extra: number): Instruction =>
      ({
        programAddress: address(3),
        accounts: Array.from({ length: extra }, (_, seed) => ({
          address: address(8000 + seed),
          role: AccountRole.READONLY,
        })),
      }) as unknown as Instruction;
    const fit = (extra: number) =>
      TransactionFit.of(instruction, { ...payer, setupInstructions: [setup(extra)] }, BUDGET);
    expect((await fit(0)).addresses).toBe(LIMIT);
    await expect(fit(1)).rejects.toMatchObject({
      code: "RING_FIT_ADDRESSES",
      details: { addresses: LIMIT + 1, limit: LIMIT },
    });
  });

  it("names what setup adds to the shared transaction", async () => {
    const fit = await TransactionFit.of(
      signing(4),
      { ...payer, setupInstructions: [signing(5)] },
      BUDGET,
    );
    expect(fit.setup).toMatchObject({ instructions: 1, signatures: 1, addresses: 1 });
    expect(fit.setup.bytes).toBeGreaterThan(0);
  });
});

/** Shared with the Rust fit test. */
const CREDENTIAL_FIT = JSON.parse(
  readFileSync(
    new URL("../../../../sdk/tests/fixtures/credential-fit.json", import.meta.url),
    "utf8",
  ),
) as Readonly<{
  payer: number;
  program: number;
  computeUnitLimit: number;
  trees: readonly string[];
  cases: readonly Readonly<{
    name: string;
    filler?: number;
    data?: number;
    named?: readonly number[];
    openings: readonly number[];
    capacity: number;
    refusal?: "addresses" | "bytes" | "credentialCapacity";
    addresses?: number;
    bytes?: number;
    trees?: number;
  }>[];
}>;

const refusalOf = (run: () => unknown): { code?: string; details?: unknown } => {
  try {
    run();
  } catch (error) {
    return error as { code?: string; details?: unknown };
  }
  throw new Error("fits");
};

describe("CredentialTrees in the preproof fit, the shared Rust cases", () => {
  it("derives the pinned tree accounts", () => {
    expect(CREDENTIAL_FIT.trees.map((_, treeId) => treeAddress(treeId))).toEqual(
      CREDENTIAL_FIT.trees,
    );
  });

  for (const fixture of CREDENTIAL_FIT.cases)
    it(fixture.name, () => {
      if (fixture.refusal === "credentialCapacity") {
        expect(
          refusalOf(() => CredentialTrees.of(fixture.openings, fixture.capacity)),
        ).toMatchObject({
          code: "RING_FIT_CREDENTIAL_CAPACITY",
          details: { trees: fixture.trees, capacity: fixture.capacity },
        });
        return;
      }
      const trees = CredentialTrees.of(fixture.openings, fixture.capacity);
      const instruction = {
        programAddress: address(CREDENTIAL_FIT.program),
        accounts: [
          ...Array.from({ length: fixture.filler ?? 0 }, (_, seed) => address(5000 + seed)),
          ...(fixture.named ?? []).map(treeAddress),
        ]
          .map((account) => ({ address: account, role: AccountRole.WRITABLE }))
          .concat(trees.metas()),
        data: new Uint8Array(fixture.data ?? 0),
      } as unknown as Instruction;
      const preproof = () =>
        TransactionFit.inline(
          instruction,
          { payer: address(CREDENTIAL_FIT.payer) },
          { computeUnitLimit: CREDENTIAL_FIT.computeUnitLimit },
        );
      switch (fixture.refusal) {
        case undefined:
          expect(preproof()).toMatchObject({ addresses: fixture.addresses, bytes: fixture.bytes });
          break;
        case "addresses":
          expect(refusalOf(preproof)).toMatchObject({
            code: "RING_FIT_ADDRESSES",
            details: { addresses: fixture.addresses, limit: LIMIT },
          });
          break;
        case "bytes":
          expect(refusalOf(preproof)).toMatchObject({
            code: "RING_FIT_BYTES",
            details: { bytes: fixture.bytes, limit: TRANSACTION_SIZE_LIMIT },
          });
          break;
      }
    });

  // The key's credential capacity admits each tree set below, only the compiled accounts refuse.
  it("names credential trees after the registries and refuses past the address ceiling before proving", async () => {
    const program = address(2);
    const data = ringFrame({ rail: "confidential", inputs: 1, outputs: 2 });
    const accounts = {
      payer: address(1),
      inputTrees: [treeAddress(0)],
      outputTree: treeAddress(0),
      ownerSigners: [],
      registries: [address(3)],
      coSigners: [],
    };
    const reading = (trees: readonly number[]) =>
      ringTransactInstruction(
        program,
        { ...accounts, credentialTrees: CredentialTrees.of(trees, trees.length + 1) },
        data,
      );
    const addresses = (instruction: Instruction) =>
      transactionSize({
        feePayer: accounts.payer,
        instructions: [instruction],
        computeUnitLimit: 0,
      }).addresses;
    const range = (count: number) => Array.from({ length: count }, (_, index) => 100 + index);
    const preproof = (instruction: Instruction) =>
      TransactionFit.inline(instruction, { payer: accounts.payer }, BUDGET);

    // 1. The address tree is tree 0 and holds the frame's notes, so only the state trees add addresses, right after the registries.
    const bare = await ringTransactInstruction(program, accounts, data);
    const named = await reading(range(2));
    const trees = CredentialTrees.of(range(2), 2).metas();
    expect(named.accounts?.slice(0, 2)).toEqual(bare.accounts?.slice(0, 2));
    expect(named.accounts?.slice(2, 5)).toEqual(trees);
    expect(named.accounts?.slice(5)).toEqual(bare.accounts?.slice(2));
    expect(addresses(named)).toBe(addresses(bare) + 2);

    // 2. The largest set fits at the ceiling and one more tree refuses.
    const fitting = LIMIT - addresses(bare);
    expect(preproof(await reading(range(fitting))).addresses).toBe(LIMIT);
    const past = await reading(range(fitting + 1));
    expect(refusalOf(() => preproof(past))).toMatchObject({
      code: "RING_FIT_ADDRESSES",
      details: { addresses: LIMIT + 1, limit: LIMIT },
    });
  });
});
