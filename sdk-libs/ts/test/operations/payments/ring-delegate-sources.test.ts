import { decompileTransactionMessage, getCompiledTransactionMessageDecoder } from "@solana/kit";
import { initializePoseidon, SHIELDED_POOL_PROGRAM_ID } from "@heliuslabs/zolana";
import { StateDiscriminator } from "@heliuslabs/zolana/interface";
import type { Address, Bytes32, Instruction } from "@heliuslabs/zolana/interface";
import {
  addressBytes,
  compileUnsignedTransaction,
  encodeBase58,
} from "@heliuslabs/zolana/internal";
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
import {
  ringRailOf,
  RingTransactData,
  type RingRail,
} from "../../../src/protocol/transaction/transact.js";
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

const USDC = address32(0x31);
const EURC = address32(0x32);
const SPL_MINTS = [
  { mint: USDC, assetId: 2n },
  { mint: EURC, assetId: 3n },
];

function address32(byte: number): Address {
  return encodeBase58(new Uint8Array(32).fill(byte)) as Address;
}

function registryAccount(mint: Address, assetId: bigint): string {
  const data = new Uint8Array(48);
  data[0] = StateDiscriminator.splAssetRegistry;
  data.set(addressBytes(mint), 8);
  new DataView(data.buffer).setBigUint64(40, assetId, true);
  return Buffer.from(data).toString("base64");
}

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

const requestOf = (
  fixture: Fixture,
  delegate: string,
  sources: readonly ShieldedKeypair[],
  payments: readonly Readonly<{ recipient: ShieldedKeypair; mint: Address; amount: bigint }>[],
) =>
  ({
    ring: fixture.ringProgramId,
    delegate,
    transfer: {
      sources: sources.map((source) => source.shieldedAddress()),
      payments: payments.map((payment) => ({
        ...payment,
        recipient: payment.recipient.shieldedAddress(),
      })),
    },
    txViewingKey: TX_VIEWING_KEY,
    timestamp: 0n,
    nonce: "",
    signature: "",
  }) as never;

const requestFor = (
  fixture: Fixture,
  delegate: string,
  sources: readonly ShieldedKeypair[],
  payee: ShieldedKeypair,
  amount: bigint,
) => requestOf(fixture, delegate, sources, [{ recipient: payee, mint: SOL_MINT, amount }]);

function liveRecords(fixture: Fixture, instruction: Instruction, rail: RingRail) {
  const frame = RingTransactData.parse(Uint8Array.from(instruction.data ?? []).subarray(1), rail);
  const { records } = openSealedDisclosure(TX_VIEWING_KEY, fixture.auditor.publicKey(), {
    layout: RingTransactData.streamLayout(frame),
    salt: frame.salt,
    message: {
      ephemeralPublicKey: x25519FromU(frame.txViewingU),
      envelope: frame.envelope,
      records: frame.outputs.map((output) => output.record),
    },
  });
  return records.filter((record) => record.kind !== RecordKind.dummy);
}

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

      const live = liveRecords(
        fixture,
        instruction,
        ringRailOf(RingInstructionTag.authorityTransfer, mode),
      );
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
    const noteOf = (
      fixture: Fixture,
      owner: ShieldedKeypair,
      leaf: number,
      asset: Address = SOL_MINT,
    ): WalletUtxo => {
      const input = noteInput(owner, 10n, fixture.ringProgramId, asset);
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
      ...kitReads({
        solanaRpc: {
          getProgramAccounts: () => ({
            send: async () =>
              SPL_MINTS.map(({ mint, assetId }) => ({
                account: {
                  owner: SHIELDED_POOL_PROGRAM_ID,
                  data: [registryAccount(mint, assetId), "base64"],
                },
              })),
          }),
        },
      }),
    });
    const sourceOf = (
      fixture: Fixture,
      owner: ShieldedKeypair,
      leaf: number,
      assets: readonly Address[] = [SOL_MINT],
    ) => ({
      address: owner.shieldedAddress(),
      nullifierKey: owner.nullifierKey(),
      notes: assets.map((asset, at) => noteOf(fixture, owner, leaf + at, asset)),
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

    it.each(["confidential", "anonymous"] as const)(
      "returns each mint's change to its owner on the %s rail",
      async (mode) => {
        const [member, other, payee] = [
          ShieldedKeypair.generate(),
          ShieldedKeypair.generate(),
          ShieldedKeypair.generate(),
        ];
        const { fixture, delegate } = await moveRing(mode, [member, other, payee]);
        const { messageBytes } = await buildRingDelegateRecoveredTransaction({
          client: clientOf(fixture),
          ringProgramId: fixture.ringProgramId,
          delegate: delegate as never,
          feePayer: fixture.authority,
          outputs: [
            { recipient: payee.shieldedAddress(), asset: SOL_MINT, amount: 4n },
            { recipient: payee.shieldedAddress(), asset: USDC, amount: 3n },
          ],
          sources: [sourceOf(fixture, member, 0), sourceOf(fixture, other, 1, [USDC])],
          txViewingKey: TX_VIEWING_KEY,
        });
        const message = new Uint8Array(messageBytes);
        const expected = await expectedDelegate(
          requestOf(
            fixture,
            delegate,
            [member, other],
            [
              { recipient: payee, mint: SOL_MINT, amount: 4n },
              { recipient: payee, mint: USDC, amount: 3n },
            ],
          ),
          { feePayer: fixture.authority, validUntilSlot: 100n },
          { mode, auditorPublicKey: fixture.auditor.publicKey() },
        );
        expect(checkRelayMessage(expected, message, delegate as never).signer).toBe(delegate);

        const [instruction] = decompileTransactionMessage(
          getCompiledTransactionMessageDecoder().decode(message) as Parameters<
            typeof decompileTransactionMessage
          >[0] & { version: 1 },
        ).instructions;
        const key = (owner: ShieldedKeypair) =>
          Array.from(owner.shieldedAddress().signingPublicKey.confidentialViewTag()).join();
        const moved = liveRecords(
          fixture,
          instruction as Instruction,
          ringRailOf(RingInstructionTag.authorityTransfer, mode),
        ).map((record) => [Array.from(record.ownerKey).join(), record.mint, record.amount]);
        expect(moved).toHaveLength(4);
        expect(moved).toEqual(
          expect.arrayContaining([
            [key(payee), SOL_MINT, 4n],
            [key(payee), USDC, 3n],
            [key(member), SOL_MINT, 6n],
            [key(other), USDC, 7n],
          ]),
        );
      },
    );

    it("refuses one owner's change on two SPL mints on the anonymous rail alone", async () => {
      const [member, payee] = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
      const build = async (mode: RingMode) => {
        const { fixture, delegate } = await moveRing(mode, [member, payee]);
        return buildRingDelegateRecoveredTransaction({
          client: clientOf(fixture),
          ringProgramId: fixture.ringProgramId,
          delegate: delegate as never,
          feePayer: fixture.authority,
          outputs: [
            { recipient: payee.shieldedAddress(), asset: USDC, amount: 3n },
            { recipient: payee.shieldedAddress(), asset: EURC, amount: 3n },
          ],
          sources: [sourceOf(fixture, member, 0, [USDC, EURC])],
          txViewingKey: TX_VIEWING_KEY,
        });
      };
      await expect(build("confidential")).resolves.toBeDefined();
      await expect(build("anonymous")).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_ANONYMOUS_CHANGE_COUNT",
      });
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
