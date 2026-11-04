import { readFileSync } from "node:fs";

import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes32, Instruction } from "@heliuslabs/zolana/interface";
import { compileUnsignedTransaction, type indexerTypes } from "@heliuslabs/zolana/internal";
import { getCreateAssociatedTokenAccountInstructionAsync } from "@heliuslabs/zolana/instructions";
import { ShieldedKeypair, SigningKey, ViewingKey } from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  SOL_MINT,
  type ProofInputUtxo,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";
import {
  AccountRole,
  getBase64Decoder,
  getBase64Encoder,
  type Address,
  type TransactionPartialSigner,
} from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { RingAddress } from "../../../src/crypto/keys/ring-address.js";
import { ringSpendTransfer } from "../../../src/operations/payments/ring-spend.js";
import { signingKeySpendSigner } from "../../../src/operations/payments/anonymous.js";
import { BufferedFrame } from "../../../src/operations/payments/buffered-frame.js";
import {
  CustomRingTransfer,
  type AnonymousTransfer,
} from "../../../src/operations/payments/transfer-rails.js";
import { ringComputeUnitLimit } from "../../../src/operations/management/admin.js";
import { SIZE_PROBE_LIFETIME } from "../../../src/operations/workflow/compile.js";
import { RING_COSIGN_TRANSFERS } from "../../../src/protocol/codec/ring-codecs.js";
import type { RelayStatus } from "../../../src/protocol/ring-rpc/ring-rpc-types.js";
import {
  decodeRelayProofInputs,
  encodeRelayProofInputs,
} from "../../../src/protocol/ring-rpc/relay-proof-inputs.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { buildRuleTable } from "../../../src/protocol/membership/policy.js";
import { PendingRelaySignature, type RingRelayClient } from "../../../src/rpc/relay.js";
import {
  decodeRelayTransferTerms,
  encodeRelayTransferTerms,
  type RelayTransferTerms,
} from "../../../src/rpc/relay-message.js";
import {
  noteInput,
  randomAddress,
  ringFixture,
  TREE,
  walletKeys,
  type Fixture,
} from "../../helpers/ring-pipeline.js";

const assets = new AssetRegistry();
const RELAY_ID = "11111111111111111111111111111111" as indexerTypes.Hash;

function fakeSigner(address: Address): TransactionPartialSigner {
  return {
    address,
    signTransactions: async () => [{ [address]: new Uint8Array(64) }],
  } as unknown as TransactionPartialSigner;
}

function relayClient(relayId: indexerTypes.Hash = RELAY_ID) {
  return {
    getRelayQuote: vi.fn(),
    getRelayStatus: vi.fn(),
    prepareRelay: vi.fn(async () => ({
      step: "signMessage",
      relayId,
      message: getBase64Decoder().decode(new Uint8Array()),
    })),
    submitRelay: vi.fn(async (): Promise<RelayStatus> => ({ status: "awaitingSignature" })),
  } as unknown as RingRelayClient & { submitRelay: ReturnType<typeof vi.fn> };
}

function noteOf(input: ProofInputUtxo, leafIndex: number): WalletUtxo {
  return {
    utxo: input.utxo,
    outputContext: { hash: new Uint8Array(32), tree: TREE, leafIndex: BigInt(leafIndex) },
    nullifier: input.nullifier(),
    spent: false,
  } as unknown as WalletUtxo;
}

function messageOf(
  feePayer: Address,
  instructions: readonly Instruction[],
  tag: RingInstructionTag = RingInstructionTag.transfer,
): Uint8Array {
  const { messageBytes } = compileUnsignedTransaction({
    feePayer,
    lifetime: SIZE_PROBE_LIFETIME,
    instructions,
    computeUnitLimit: ringComputeUnitLimit(tag),
  });
  return new Uint8Array(messageBytes);
}

async function transferFor(fixture: Fixture, coSigner: Address, amount = 4n) {
  const signing = SigningKey.generate();
  const sender = ShieldedKeypair.fromKeypair(signing);
  const recipient = ShieldedKeypair.generate();
  fixture.enroll(sender.shieldedAddress());
  fixture.enroll(recipient.shieldedAddress());
  const input = noteInput(sender, 10n, fixture.ringProgramId);
  const transfer = new ConfidentialTransfer(sender.shieldedAddress(), [input], fixture.authority);
  transfer.send(recipient.shieldedAddress(), SOL_MINT, amount);
  const rail = CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: walletKeys(sender),
    transfer,
    assets,
    coSigners: [coSigner],
  }).withInProofOwner(signingKeySpendSigner(signing));
  const prepared = await rail.prepareRelay(fixture.client, {
    quote: { feePayer: fixture.authority, validUntilSlot: 100n },
    nullifierKey: sender.nullifierKey(),
    notes: [noteOf(input, 0)],
  });
  const proven = await rail.prove(fixture.client);
  return { prepared, proven, instruction: await proven.instruction() };
}

async function termsOf(prepared: Awaited<ReturnType<typeof transferFor>>["prepared"]) {
  const sent = await prepared.send(relayClient(prepared.relayId()));
  if (!(sent instanceof PendingRelaySignature)) throw new Error("the relay asks a signature");
  const terms = sent.transferTerms();
  if (terms === undefined) throw new Error("the sealing wallet holds terms");
  return terms;
}

async function fixtureWith(coSigner: Address) {
  return ringFixture({
    table: buildRuleTable({ rules: [] }),
    coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS },
  });
}

describe("relay transfer terms", () => {
  beforeAll(async () => {
    await initializePoseidon();
  });

  const pendingFor = async (
    fixture: Fixture,
    message: Uint8Array,
    terms: RelayTransferTerms,
  ): Promise<PendingRelaySignature> =>
    PendingRelaySignature.forTransferTerms(RELAY_ID, message, terms, {
      mode: "confidential",
      auditorPublicKey: fixture.auditor.publicKey(),
    });

  const refusal = (attempt: () => unknown): unknown => {
    try {
      attempt();
    } catch (error) {
      return (error as { details?: { mismatch?: unknown } }).details?.mismatch;
    }
    return "accepted";
  };

  it("lets a named co-signer sign the transfer its terms name, more than once", async () => {
    const coSigner = randomAddress();
    const fixture = await fixtureWith(coSigner);
    const { prepared, instruction } = await transferFor(fixture, coSigner);
    const terms = decodeRelayTransferTerms(encodeRelayTransferTerms(await termsOf(prepared)));
    expect(terms.signers).toContain(coSigner);

    const pending = await pendingFor(fixture, messageOf(fixture.authority, [instruction]), terms);
    expect(pending.verify(coSigner).signer).toBe(coSigner);
    const relay = relayClient();
    await pending.sign(relay, fakeSigner(coSigner));
    await pending.sign(relay, fakeSigner(coSigner));
    expect(relay.submitRelay).toHaveBeenCalledTimes(2);
  });

  it("refuses a key its terms do not name", async () => {
    const coSigner = randomAddress();
    const fixture = await fixtureWith(coSigner);
    const { prepared, instruction } = await transferFor(fixture, coSigner);
    const pending = await pendingFor(
      fixture,
      messageOf(fixture.authority, [instruction]),
      await termsOf(prepared),
    );
    expect(refusal(() => pending.verify(randomAddress()))).toBe("Unrequested");
  });

  it("refuses another transfer's frame under the terms of the first", async () => {
    const coSigner = randomAddress();
    const fixture = await fixtureWith(coSigner);
    const asked = await transferFor(fixture, coSigner);
    const other = await transferFor(fixture, coSigner, 5n);
    const terms = await termsOf(asked.prepared);
    const pending = await pendingFor(
      fixture,
      messageOf(fixture.authority, [other.instruction]),
      terms,
    );
    expect(refusal(() => pending.verify(coSigner))).toBe("TransactionKey");
  });

  it("refuses a slot, nullifier or leg that differs by a byte", async () => {
    const coSigner = randomAddress();
    const fixture = await fixtureWith(coSigner);
    const { prepared, instruction } = await transferFor(fixture, coSigner);
    const honest = await termsOf(prepared);
    const message = messageOf(fixture.authority, [instruction]);
    const flipped = (bytes: Uint8Array): Uint8Array => {
      const copy = Uint8Array.from(bytes);
      copy[0] = (copy[0] ?? 0) ^ 1;
      return copy;
    };
    const verdict = async (terms: RelayTransferTerms): Promise<unknown> => {
      const pending = await pendingFor(fixture, message, terms);
      return refusal(() => pending.verify(coSigner));
    };
    const [firstRecord, ...restRecords] = honest.records;
    const [firstNullifier, ...restNullifiers] = honest.nullifiers;
    expect(await verdict({ ...honest, records: [flipped(firstRecord!), ...restRecords] })).toBe(
      "Recipients",
    );
    expect(await verdict({ ...honest, records: restRecords })).toBe("Recipients");
    expect(
      await verdict({ ...honest, nullifiers: [flipped(firstNullifier!), ...restNullifiers] }),
    ).toBe("Data");
    expect(await verdict({ ...honest, legs: [new Uint8Array(1)] })).toBe("Data");
    expect(await verdict({ ...honest, tails: [new Uint8Array(1)] })).toBe("Data");
  });

  it("refuses setup the terms do not name and a frame that writes through the signer", async () => {
    const coSigner = randomAddress();
    const fixture = await fixtureWith(coSigner);
    const { prepared, instruction } = await transferFor(fixture, coSigner);
    const terms = await termsOf(prepared);
    const pending = async (instructions: readonly Instruction[]) =>
      pendingFor(fixture, messageOf(fixture.authority, instructions), terms);

    const extra = { programAddress: randomAddress(), accounts: [], data: new Uint8Array(1) };
    const padded = await pending([extra, instruction]);
    expect(refusal(() => padded.verify(coSigner))).toBe("Instructions");

    const accounts = (instruction.accounts ?? []).map((meta) =>
      meta.address === coSigner ? { ...meta, role: AccountRole.WRITABLE_SIGNER } : meta,
    );
    const writable = await pending([{ ...instruction, accounts }]);
    expect(refusal(() => writable.verify(coSigner))).toBe("Accounts");

    const elsewhere = await pending([{ ...instruction, programAddress: randomAddress() }]);
    expect(refusal(() => elsewhere.verify(coSigner))).toBe("Program");
  });

  it("names the setup the fee payer creates ahead of the ring instruction", async () => {
    const coSigner = randomAddress();
    const fixture = await fixtureWith(coSigner);
    const { prepared, instruction } = await transferFor(fixture, coSigner);
    const terms = await termsOf(prepared);
    const setup = { owner: randomAddress(), mint: randomAddress(), tokenProgram: randomAddress() };
    const pending = await pendingFor(fixture, messageOf(fixture.authority, [instruction]), {
      ...terms,
      setup: [setup],
    });
    expect(refusal(() => pending.verify(coSigner))).toBe("Instructions");

    const create = await getCreateAssociatedTokenAccountInstructionAsync({
      payer: fixture.authority,
      ...setup,
    });
    const named = await pendingFor(fixture, messageOf(fixture.authority, [create, instruction]), {
      ...terms,
      setup: [setup],
    });
    expect(named.verify(coSigner).signer).toBe(coSigner);
    const other = await pendingFor(fixture, messageOf(fixture.authority, [create, instruction]), {
      ...terms,
      setup: [{ ...setup, owner: randomAddress() }],
    });
    expect(refusal(() => other.verify(coSigner))).toBe("Instructions");
  });

  it("reads a settling frame from its buffer before the co-signer signs", async () => {
    const coSigner = randomAddress();
    const fixture = await fixtureWith(coSigner);
    const { prepared, instruction } = await transferFor(fixture, coSigner);
    const terms = await termsOf(prepared);
    const buffered = await BufferedFrame.forWriter(instruction, fixture.authority);
    const message = messageOf(
      fixture.authority,
      [buffered.settle()],
      RingInstructionTag.settleBuffered,
    );
    const pending = await pendingFor(fixture, message, terms);
    expect(refusal(() => pending.verify(coSigner))).toBe("SettlesBuffer");

    const relay = relayClient();
    const frame = Uint8Array.from(instruction.data ?? []);
    const held = Uint8Array.of(16, ...new Uint8Array(32), RingInstructionTag.frameEvent, ...frame);
    const getAccount = vi.fn(async () => ({ data: held }));
    await pending.signOnChain(relay, { getAccount } as never, fakeSigner(coSigner));
    expect(getAccount).toHaveBeenCalledWith(buffered.buffer, undefined);
    expect(relay.submitRelay).toHaveBeenCalledOnce();

    held[held.length - 1] = (held[held.length - 1] ?? 0) ^ 1;
    await expect(
      pending.signOnChain(relayClient(), { getAccount } as never, fakeSigner(coSigner)),
    ).rejects.toMatchObject({ details: { mismatch: "Data" } });
  });

  const anonymousPending = (
    fixture: Fixture,
    message: Uint8Array,
    terms: RelayTransferTerms,
  ): Promise<PendingRelaySignature> =>
    PendingRelaySignature.forTransferTerms(RELAY_ID, message, terms, {
      mode: "anonymous",
      auditorPublicKey: fixture.auditor.publicKey(),
    });

  const anonymousRail = (
    fixture: Fixture,
    signing: SigningKey,
    notes: readonly ProofInputUtxo[],
  ): AnonymousTransfer => {
    const sender = ShieldedKeypair.fromKeypair(signing);
    return CustomRingTransfer.new({
      ringProgramId: fixture.ringProgramId,
      keys: walletKeys(sender),
      transfer: ringSpendTransfer({
        owner: sender.shieldedAddress(),
        inputs: notes,
        feePayer: fixture.authority,
      }),
      assets,
    }).withAnonymousSigner(signingKeySpendSigner(signing));
  };

  const addressOf = (fixture: Fixture, owner: ShieldedKeypair): RingAddress =>
    new RingAddress({
      recipient: owner.shieldedAddress(),
      ringProgramId: fixture.ringProgramId,
      listSalt: new Uint8Array(32).fill(1) as Bytes32,
    });

  it("asks the recipient of a data note and leaves the hidden sender out", async () => {
    const fixture = await ringFixture({ mode: "anonymous" });
    const signing = SigningKey.generate();
    const sender = ShieldedKeypair.fromKeypair(signing);
    const payee = ShieldedKeypair.generate();
    fixture.enroll(sender.shieldedAddress());
    fixture.enroll(payee.shieldedAddress());
    const input = noteInput(sender, 10n, fixture.ringProgramId);
    const bytes = Uint8Array.of(1, 2, 3);
    const rail = anonymousRail(fixture, signing, [input]).withPayment({
      to: addressOf(fixture, payee),
      asset: SOL_MINT,
      amount: 4n,
      reply: null,
      data: { application: { hash: new Uint8Array(32).fill(4) as Bytes32, bytes } },
    });
    const { relay } = await rail.prepareRelay(fixture.client, {
      quote: { feePayer: fixture.authority, validUntilSlot: 100n },
      nullifierKey: sender.nullifierKey(),
      notes: [noteOf(input, 0)],
    });
    const terms = await termsOf(relay);
    const payeeAddress = payee.shieldedAddress().solanaAddress();
    expect(terms.signers).toEqual([payeeAddress]);
    expect(terms.tails).not.toHaveLength(0);

    const proven = await rail.prove(fixture.client);
    const pending = await anonymousPending(
      fixture,
      messageOf(fixture.authority, [await proven.instruction()]),
      terms,
    );
    expect(pending.verify(payeeAddress).signer).toBe(payeeAddress);
    expect(refusal(() => pending.verify(sender.shieldedAddress().solanaAddress()))).toBe(
      "Unrequested",
    );
    await expect(pending.sign(relayClient(), fakeSigner(payeeAddress))).resolves.toEqual({
      status: "awaitingSignature",
    });
  });

  it("carries a public co-owner's key across the wire and asks it to sign", async () => {
    const fixture = await ringFixture({ mode: "anonymous" });
    const signing = SigningKey.generate();
    const sender = ShieldedKeypair.fromKeypair(signing);
    const coOwner = ShieldedKeypair.generate();
    const payee = ShieldedKeypair.generate();
    for (const owner of [sender, coOwner, payee]) fixture.enroll(owner.shieldedAddress());
    const notes = [
      noteInput(sender, 10n, fixture.ringProgramId),
      noteInput(coOwner, 10n, fixture.ringProgramId),
    ];
    const owner = coOwner.shieldedAddress().solanaAddress();
    const rail = anonymousRail(fixture, signing, notes)
      .withCoOwner({ owner, nullifierKey: coOwner.nullifierKey() })
      .withPayment({
        to: addressOf(fixture, payee),
        asset: SOL_MINT,
        amount: 4n,
        reply: null,
      });
    const { relay } = await rail.prepareRelay(fixture.client, {
      quote: { feePayer: fixture.authority, validUntilSlot: 100n },
      nullifierKey: sender.nullifierKey(),
      notes: notes.map(noteOf),
    });
    const terms = await termsOf(relay);
    expect(terms.signers).toEqual([owner]);

    const { intent } = relay.request;
    if (intent.operation !== "anonymous") throw new Error("an anonymous relay");
    const decoded = await decodeRelayProofInputs(
      new Uint8Array(getBase64Encoder().encode(intent.proofInputs)),
      assets,
    );
    expect(decoded.coOwners.map((held) => held.owner)).toEqual([owner]);
    expect(decoded.inputs.map((spent) => spent.nullifier())).toEqual(
      notes.map((spent) => spent.nullifier()),
    );
    expect(encodeRelayProofInputs(decoded)).toEqual(
      new Uint8Array(getBase64Encoder().encode(intent.proofInputs)),
    );
    const unheld = expect.objectContaining({ code: "RING_RELAY_PROOF_INPUTS" });
    expect(() => encodeRelayProofInputs({ ...decoded, coOwners: [] })).toThrow(unheld);
    expect(() =>
      encodeRelayProofInputs({
        ...decoded,
        coOwners: [{ owner, nullifierKey: payee.nullifierKey() }],
      }),
    ).toThrow(unheld);
    const pending = await anonymousPending(
      fixture,
      messageOf(fixture.authority, [await (await rail.prove(fixture.client)).instruction()]),
      terms,
    );
    expect(pending.verify(owner).signer).toBe(owner);
  });

  it("writes and reads the terms as the Rust vector does", () => {
    const { wire } = JSON.parse(
      readFileSync(
        new URL("../../../../../test-vectors/rpc/relay_transfer_terms.json", import.meta.url),
        "utf8",
      ),
    ) as { wire: string };
    const terms = decodeRelayTransferTerms(wire);
    expect(terms.txViewingKey).toEqual(
      ViewingKey.fromBytes(new Uint8Array(32).fill(6) as Bytes32).secretBytes(),
    );
    expect(terms.records.map((record) => record.length)).toEqual([133, 133]);
    expect(terms.setup).toHaveLength(1);
    expect(encodeRelayTransferTerms(terms)).toBe(wire);
  });

  it("refuses unknown term fields as Rust does", async () => {
    const coSigner = randomAddress();
    const fixture = await fixtureWith(coSigner);
    const { prepared } = await transferFor(fixture, coSigner);
    const wire = JSON.parse(encodeRelayTransferTerms(await termsOf(prepared))) as object;
    expect(refusal(() => decodeRelayTransferTerms(JSON.stringify({ ...wire, extra: 1 })))).toBe(
      "Undecodable",
    );
    const setup = { owner: coSigner, mint: coSigner, tokenProgram: coSigner, extra: coSigner };
    expect(
      refusal(() => decodeRelayTransferTerms(JSON.stringify({ ...wire, setup: [setup] }))),
    ).toBe("Undecodable");
    expect(
      refusal(() =>
        decodeRelayTransferTerms(JSON.stringify({ ...wire, nullifiers: ["AAAAAAAA="] })),
      ),
    ).toBe("Undecodable");
  });
});
