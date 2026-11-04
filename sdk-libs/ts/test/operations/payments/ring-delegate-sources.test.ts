import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes32, Instruction } from "@heliuslabs/zolana/interface";
import { compileUnsignedTransaction } from "@heliuslabs/zolana/internal";
import { ShieldedKeypair, ViewingKey } from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  type ProofInputUtxo,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";
import { beforeAll, describe, expect, it } from "vitest";

import { openSealedDisclosure } from "../../../src/crypto/audit/ring-disclosure.js";
import { x25519FromU } from "../../../src/crypto/keys/x25519.js";
import { RecordKind } from "../../../src/protocol/codec/audit-stream.js";
import { ringComputeUnitLimit } from "../../../src/operations/management/admin.js";
import { buildRingDelegateRecoveredTransaction } from "../../../src/operations/management/delegate.js";
import { DelegateTransfer } from "../../../src/operations/payments/transfer-rails.js";
import { SIZE_PROBE_LIFETIME } from "../../../src/operations/workflow/compile.js";
import { buildRuleTable } from "../../../src/protocol/membership/policy.js";
import type { RingMode } from "../../../src/protocol/codec/ring-codecs.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { ringRailOf, RingTransactData } from "../../../src/protocol/transaction/transact.js";
import { checkRelayMessage, expectedDelegate } from "../../../src/rpc/relay-message.js";
import { BLOCKHASH, kitReads } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import {
  noteInput,
  PROOF_SERVICE,
  randomAddress,
  ringFixture,
  small,
  walletKeys,
  type Fixture,
} from "../../helpers/ring-pipeline.js";

const assets = new AssetRegistry();
const TX_VIEWING_KEY = (() => {
  const key = new Uint8Array(32).fill(6);
  key[0] = 0;
  key[31] = 0x46;
  return key as Bytes32;
})();

async function moveRing(mode: RingMode, owners: readonly ShieldedKeypair[]) {
  const delegate = randomAddress();
  const fixture = await ringFixture({ mode, table: buildRuleTable({ rules: [] }), delegate });
  for (const owner of owners) fixture.enroll(owner.shieldedAddress());
  return { fixture, delegate };
}

/** Change returns to the owner of the last note spent. */
function movingFrom(
  fixture: Fixture,
  delegate: string,
  sources: readonly ShieldedKeypair[],
  payee: ShieldedKeypair,
  amount: bigint,
): Readonly<{ transfer: DelegateTransfer; notes: readonly ProofInputUtxo[] }> {
  const notes = sources.map((source) => noteInput(source, 10n, fixture.ringProgramId));
  const change = sources.at(-1);
  if (change === undefined) throw new Error("a source");
  const transfer = sources
    .filter((source) => source !== change)
    .reduce(
      (built, source) =>
        built.withCoSource({
          owner: source.shieldedAddress().solanaAddress(),
          nullifierKey: source.nullifierKey(),
        }),
      DelegateTransfer.new({
        ringProgramId: fixture.ringProgramId,
        delegate: delegate as never,
        payer: fixture.authority,
        source: change.shieldedAddress(),
        sourceProofs: walletKeys(change),
        inputs: notes,
        outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount }],
        assets,
      }).withTxViewingKey(TX_VIEWING_KEY),
    );
  return { transfer, notes };
}

function messageOf(fixture: Fixture, instruction: Instruction): Uint8Array {
  const { messageBytes } = compileUnsignedTransaction({
    feePayer: fixture.authority,
    lifetime: SIZE_PROBE_LIFETIME,
    instructions: [instruction],
    computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.authorityTransfer),
  });
  return new Uint8Array(messageBytes);
}

const requestFor = (
  fixture: Fixture,
  delegate: string,
  sources: readonly ShieldedKeypair[],
  payee: ShieldedKeypair,
  amount: bigint,
) =>
  ({
    ring: fixture.ringProgramId,
    delegate,
    transfer: {
      sources: sources.map((source) => source.shieldedAddress()),
      mint: SOL_MINT,
      payments: [{ recipient: payee.shieldedAddress(), amount }],
    },
    txViewingKey: TX_VIEWING_KEY,
    timestamp: 0n,
    nonce: "",
    signature: "",
  }) as never;

describe("delegate sources", () => {
  beforeAll(async () => {
    await initializePoseidon();
  });

  describe.each(["confidential", "anonymous"] as const)("on the %s rail", (mode) => {
    it.each([
      ["its own", 1, 4n],
      ["one member's", 1, 4n],
      ["several members'", 2, 15n],
    ])("moves %s notes and the frame opens to the auditor", async (_name, count, amount) => {
      const sources = Array.from({ length: count }, () => ShieldedKeypair.generate());
      const payee = ShieldedKeypair.generate();
      const { fixture, delegate } = await moveRing(mode, [...sources, payee]);
      const { transfer } = movingFrom(fixture, delegate, sources, payee, amount);
      const instruction = await (await transfer.prove(fixture.client)).instruction();

      const config = { mode, auditorPublicKey: fixture.auditor.publicKey() };
      const quote = { feePayer: fixture.authority, validUntilSlot: 100n };
      const expected = await expectedDelegate(
        requestFor(fixture, delegate, sources, payee, amount),
        quote,
        config,
      );
      const message = messageOf(fixture, instruction);
      expect(checkRelayMessage(expected, message, delegate as never).signer).toBe(delegate);

      const frame = RingTransactData.parse(
        Uint8Array.from(instruction.data ?? []).subarray(1),
        ringRailOf(RingInstructionTag.authorityTransfer, mode),
      );
      const { records } = openSealedDisclosure(TX_VIEWING_KEY, fixture.auditor.publicKey(), {
        layout: RingTransactData.streamLayout(frame),
        salt: frame.salt,
        message: {
          ephemeralPublicKey: x25519FromU(frame.txViewingU),
          envelope: frame.envelope,
          records: frame.outputs.map((output) => output.record),
        },
      });
      const live = records.filter((record) => record.kind !== RecordKind.dummy);
      expect(live.reduce((total, record) => total + record.amount, 0n)).toBe(
        BigInt(sources.length) * 10n,
      );
      const keys = [...sources, payee].map((owner) =>
        Array.from(owner.shieldedAddress().signingPublicKey.confidentialViewTag()).join(),
      );
      for (const record of live) expect(keys).toContain(Array.from(record.ownerKey).join());
    });

    it("refuses change to an owner the request does not name", async () => {
      const [member, other, payee] = [
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
      ];
      const { fixture, delegate } = await moveRing(mode, [member, other, payee]);
      const { transfer } = movingFrom(fixture, delegate, [member, other], payee, 15n);
      const instruction = await (await transfer.prove(fixture.client)).instruction();
      const expected = await expectedDelegate(
        requestFor(fixture, delegate, [member], payee, 15n),
        { feePayer: fixture.authority, validUntilSlot: 100n },
        { mode, auditorPublicKey: fixture.auditor.publicKey() },
      );
      expect(() =>
        checkRelayMessage(expected, messageOf(fixture, instruction), delegate as never),
      ).toThrow(expect.objectContaining({ details: { mismatch: "Recipients" } }));
    });
  });

  describe("recovered move", () => {
    const noteOf = (fixture: Fixture, owner: ShieldedKeypair, leaf: number): WalletUtxo => {
      const input = noteInput(owner, 10n, fixture.ringProgramId);
      return {
        utxo: input.utxo,
        outputContext: {
          hash: small(leaf + 1),
          tree: fixture.client.tree,
          leafIndex: BigInt(leaf),
        },
        nullifier: input.nullifier(),
        spent: false,
      };
    };
    const clientOf = (fixture: Fixture) => ({
      ...fixture.client,
      proofService: PROOF_SERVICE,
      getLatestBlockhash: async () => BLOCKHASH,
      ...kitReads({ solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) } }),
    });
    const sourceOf = (fixture: Fixture, owner: ShieldedKeypair, leaf: number) => ({
      address: owner.shieldedAddress(),
      nullifierKey: owner.nullifierKey(),
      notes: [noteOf(fixture, owner, leaf)],
    });

    it("spends several owners' notes and pays the change to the last note's owner", async () => {
      const [member, other, payee] = [
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
        ShieldedKeypair.generate(),
      ];
      const { fixture, delegate } = await moveRing("confidential", [member, other, payee]);
      await buildRingDelegateRecoveredTransaction({
        client: clientOf(fixture),
        ringProgramId: fixture.ringProgramId,
        delegate: delegate as never,
        feePayer: fixture.authority,
        outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 15n }],
        sources: [sourceOf(fixture, member, 0), sourceOf(fixture, other, 1)],
        txViewingKey: TX_VIEWING_KEY,
      });
      const proofInputs = fixture.sppCalls.at(-1)?.proofInputs;
      expect(proofInputs?.externalData.txViewingPublicKey.u()).toEqual(
        ViewingKey.fromBytes(TX_VIEWING_KEY.slice() as Bytes32)
          .publicKey()
          .u(),
      );
      const spent = proofInputs?.inputUtxos.filter((input) => !input.isDummy()) ?? [];
      expect(spent).toHaveLength(2);
      const change = proofInputs?.outputs.find((output) => output.amount === 5n);
      expect(change?.ownerAddress?.signingPublicKey.equals(spent.at(-1)?.utxo.owner as never)).toBe(
        true,
      );
    });

    it("refuses a source named twice and no source", async () => {
      const [member, payee] = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
      const { fixture, delegate } = await moveRing("confidential", [member, payee]);
      const build = (sources: readonly ReturnType<typeof sourceOf>[]) =>
        buildRingDelegateRecoveredTransaction({
          client: clientOf(fixture),
          ringProgramId: fixture.ringProgramId,
          delegate: delegate as never,
          feePayer: fixture.authority,
          outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 4n }],
          sources,
        });
      await expect(
        build([sourceOf(fixture, member, 0), sourceOf(fixture, member, 1)]),
      ).rejects.toMatchObject({
        code: "RING_DELEGATE_INVALID",
        details: { reason: "repeatedSource" },
      });
      await expect(
        build([{ ...sourceOf(fixture, member, 0), nullifierKey: payee.nullifierKey() }]),
      ).rejects.toMatchObject({ code: "RING_NULLIFIER_KEY_MISMATCH" });
      await expect(build([])).rejects.toMatchObject({
        code: "RING_DELEGATE_INVALID",
        details: { reason: "inputs" },
      });
    });
  });

  it("refuses a note of an owner the move does not name", async () => {
    const [member, other, payee] = [
      ShieldedKeypair.generate(),
      ShieldedKeypair.generate(),
      ShieldedKeypair.generate(),
    ];
    const { fixture, delegate } = await moveRing("confidential", [member, other, payee]);
    const transfer = DelegateTransfer.new({
      ringProgramId: fixture.ringProgramId,
      delegate: delegate as never,
      payer: fixture.authority,
      source: other.shieldedAddress(),
      sourceProofs: walletKeys(other),
      inputs: [
        noteInput(member, 10n, fixture.ringProgramId),
        noteInput(other, 10n, fixture.ringProgramId),
      ],
      outputs: [{ recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 15n }],
      assets,
    });
    await expect(transfer.prove(fixture.client)).rejects.toMatchObject({
      code: "RING_DELEGATE_INVALID",
      details: { reason: "mixedOwners" },
    });
  });
});
