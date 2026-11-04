/** Refuses a relay message that moves more than the request, against the Rust check's vectors. */
import { decompileTransactionMessage, getCompiledTransactionMessageDecoder } from "@solana/kit";
import type { Instruction } from "@heliuslabs/zolana/interface";
import { compileUnsignedTransaction } from "@heliuslabs/zolana/internal";
import { ringComputeUnitLimit } from "../../../src/operations/management/admin.js";
import { BufferedFrame } from "../../../src/operations/payments/buffered-frame.js";
import { SIZE_PROBE_LIFETIME } from "../../../src/operations/workflow/compile.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { readFileSync } from "node:fs";

import {
  getBase58Encoder,
  getBase64Encoder,
  type Address,
  type TransactionPartialSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import {
  DepositAsset,
  type Bytes16,
  type Bytes32,
  type Bytes33,
} from "@heliuslabs/zolana/interface";
import type { indexerTypes } from "@heliuslabs/zolana/internal";
import { ShieldedAddress } from "@heliuslabs/zolana/keypair";

import {
  checkRelayMessage,
  checkSettledDelegateMessage,
  settledBufferOf,
  type ExpectedDelegate,
  expectedDelegate,
  expectedDeposit,
  type ExpectedRelayMessage,
} from "../../../src/rpc/relay-message.js";
import { PendingRelaySignature, type RingRelayClient } from "../../../src/rpc/relay.js";
import type {
  PrepareAuthorityTransferRequest,
  RelayStatus,
} from "../../../src/protocol/ring-rpc/ring-rpc-types.js";

await initializePoseidon();

const base58 = getBase58Encoder();
const base64 = getBase64Encoder();

interface MessageCase {
  readonly name: string;
  readonly message: string;
  readonly verdict: string;
}

interface Vector<R> {
  readonly request: R;
  readonly cases: readonly MessageCase[];
}

interface DepositRequest {
  readonly ring: Address;
  readonly feePayer: Address;
  readonly tree: Address;
  readonly depositor: Address;
  readonly viewTag: string;
  readonly ownerUtxoHash: string;
  readonly amount: number;
  readonly ringDataHash: string;
  readonly txViewingPk: string;
  readonly salt: string;
  readonly ciphertext: string;
}

interface DelegateRequest {
  readonly prepare: {
    readonly ring: Address;
    readonly delegate: Address;
    readonly transfer: {
      readonly source: string;
      readonly mint: Address;
      readonly payments: readonly { readonly recipient: string; readonly amount: number }[];
    };
  };
  readonly feePayer: Address;
}

function vector<R>(name: string): Vector<R> {
  return JSON.parse(
    readFileSync(new URL(`../../../../../test-vectors/rpc/${name}`, import.meta.url), "utf8"),
  ) as Vector<R>;
}

function hex(text: string): Uint8Array {
  return Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function deposit(request: DepositRequest): Promise<ExpectedRelayMessage> {
  return expectedDeposit({
    ringProgramId: request.ring,
    feePayer: request.feePayer,
    tree: request.tree,
    depositor: request.depositor,
    deposit: {
      asset: DepositAsset.sol(),
      viewTag: hex(request.viewTag) as Bytes32,
      ownerUtxoHash: hex(request.ownerUtxoHash) as Bytes32,
      amount: BigInt(request.amount),
      ringDataHash: hex(request.ringDataHash) as Bytes32,
      encrypted: {
        txViewingPublicKey: hex(request.txViewingPk) as Bytes33,
        salt: hex(request.salt) as Bytes16,
        ciphertext: new Uint8Array(base64.encode(request.ciphertext)),
      },
    },
  });
}

function delegate(request: DelegateRequest): Promise<ExpectedRelayMessage> {
  const shielded = (text: string) => ShieldedAddress.fromBytes(new Uint8Array(base58.encode(text)));
  const { prepare } = request;
  return expectedDelegate(
    {
      ring: prepare.ring,
      delegate: prepare.delegate,
      transfer: {
        source: shielded(prepare.transfer.source),
        mint: prepare.transfer.mint,
        payments: prepare.transfer.payments.map((payment) => ({
          recipient: shielded(payment.recipient),
          amount: BigInt(payment.amount),
        })),
      },
    } as unknown as PrepareAuthorityTransferRequest,
    { feePayer: request.feePayer, validUntilSlot: 0n },
    "confidential",
  );
}

function verdict(expected: ExpectedRelayMessage, message: string): string {
  try {
    checkRelayMessage(expected, new Uint8Array(base64.encode(message)));
    return "Accepted";
  } catch (error) {
    return String((error as { details?: { mismatch?: unknown } }).details?.mismatch);
  }
}

function message(cases: readonly MessageCase[], name: string): Uint8Array {
  const found = cases.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(`no case ${name}`);
  return new Uint8Array(base64.encode(found.message));
}

/** The signature bytes are the relay's to verify, the check runs before any signer. */
function signer(address: Address): TransactionPartialSigner & { calls: number } {
  const fake = {
    address,
    calls: 0,
    signTransactions: async () => {
      fake.calls += 1;
      return [{ [address]: new Uint8Array(64) }];
    },
  };
  return fake as unknown as TransactionPartialSigner & { calls: number };
}

function relay(): RingRelayClient & { submitRelay: ReturnType<typeof vi.fn> } {
  return {
    getRelayQuote: vi.fn(),
    prepareRelay: vi.fn(),
    getRelayStatus: vi.fn(),
    submitRelay: vi.fn(async (): Promise<RelayStatus> => ({ status: "awaitingSignature" })),
  } as unknown as RingRelayClient & { submitRelay: ReturnType<typeof vi.fn> };
}

const RELAY_ID = "11111111111111111111111111111111" as indexerTypes.Hash;
const deposits = vector<DepositRequest>("relay_deposit_messages.json");
const delegates = vector<DelegateRequest>("relay_delegate_messages.json");

describe("relay message check", () => {
  it.each(deposits.cases)("reaches the Rust verdict on deposit message $name", async (entry) => {
    expect(verdict(await deposit(deposits.request), entry.message)).toBe(entry.verdict);
  });

  it.each(delegates.cases)("reaches the Rust verdict on delegate message $name", async (entry) => {
    expect(verdict(await delegate(delegates.request), entry.message)).toBe(entry.verdict);
  });

  it("refuses a deposit message with an extra SPL transfer from the depositor before signing", async () => {
    const expected = await deposit(deposits.request);
    const depositor = signer(deposits.request.depositor);
    const ringRpc = relay();
    const pending = new PendingRelaySignature(
      RELAY_ID,
      message(deposits.cases, "extraSplTransfer"),
      expected,
    );
    await expect(pending.sign(ringRpc, depositor)).rejects.toMatchObject({
      code: "RING_RELAY_MESSAGE_INVALID",
      details: { mismatch: "Instructions" },
    });
    expect(depositor.calls).toBe(0);
    expect(ringRpc.submitRelay).not.toHaveBeenCalled();
  });

  it("refuses a delegate message with a swapped recipient before signing", async () => {
    const expected = await delegate(delegates.request);
    const delegateSigner = signer(delegates.request.prepare.delegate);
    const ringRpc = relay();
    const pending = new PendingRelaySignature(
      RELAY_ID,
      message(delegates.cases, "swappedRecipient"),
      expected,
    );
    await expect(pending.sign(ringRpc, delegateSigner)).rejects.toMatchObject({
      details: { mismatch: "Recipients" },
    });
    expect(delegateSigner.calls).toBe(0);
  });

  describe("a delegate frame settled from a buffer", () => {
    const inlineOf = (name: string): Instruction => {
      const compiled = getCompiledTransactionMessageDecoder().decode(
        message(delegates.cases, name),
      );
      const [instruction] = decompileTransactionMessage(
        compiled as Parameters<typeof decompileTransactionMessage>[0] & { version: 1 },
      ).instructions;
      if (instruction === undefined) throw new Error("no instruction");
      return instruction as Instruction;
    };
    const settling = async (inline: Instruction): Promise<Uint8Array> => {
      const { feePayer } = delegates.request;
      const buffered = await BufferedFrame.forWriter(inline, feePayer);
      const { messageBytes } = compileUnsignedTransaction({
        feePayer,
        lifetime: SIZE_PROBE_LIFETIME,
        instructions: [buffered.settle()],
        computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.settleBuffered),
      });
      return new Uint8Array(messageBytes);
    };
    const held = (frame: Uint8Array): Uint8Array =>
      Uint8Array.of(16, ...new Uint8Array(32), RingInstructionTag.frameEvent, ...frame);
    const data = (inline: Instruction) => Uint8Array.from(inline.data ?? []);

    it("names the buffer and passes the frame its digest signs", async () => {
      const expected = (await delegate(delegates.request)) as ExpectedDelegate;
      const honest = inlineOf("honest");
      const settle = await settling(honest);
      const { buffer } = await BufferedFrame.forWriter(honest, delegates.request.feePayer);
      expect(settledBufferOf(expected, settle)).toBe(buffer);
      expect(settledBufferOf(expected, message(delegates.cases, "honest"))).toBeUndefined();
      expect(checkSettledDelegateMessage(expected, settle, held(data(honest))).signer).toBe(
        delegates.request.prepare.delegate,
      );
    });

    it("refuses the plain check, a rewritten buffer and a swapped recipient", async () => {
      const expected = (await delegate(delegates.request)) as ExpectedDelegate;
      const honest = inlineOf("honest");
      const settle = await settling(honest);
      const reason = (action: () => unknown) => {
        try {
          action();
        } catch (error) {
          return (error as { details?: { mismatch?: unknown } }).details?.mismatch;
        }
        return "Accepted";
      };
      expect(reason(() => checkRelayMessage(expected, settle))).toBe("SettlesBuffer");
      const rewritten = data(honest);
      rewritten[rewritten.length - 1] = (rewritten[rewritten.length - 1] ?? 0) ^ 1;
      expect(reason(() => checkSettledDelegateMessage(expected, settle, held(rewritten)))).toBe(
        "Data",
      );
      const swapped = inlineOf("swappedRecipient");
      expect(reason(() => checkSettledDelegateMessage(expected, settle, held(data(swapped))))).toBe(
        "Data",
      );
      const swappedSettle = await settling(swapped);
      expect(
        reason(() => checkSettledDelegateMessage(expected, swappedSettle, held(data(swapped)))),
      ).toBe("Recipients");
    });

    it("signs on chain after reading the buffer and refuses a missing one", async () => {
      const expected = await delegate(delegates.request);
      const honest = inlineOf("honest");
      const pending = new PendingRelaySignature(RELAY_ID, await settling(honest), expected);
      const delegateSigner = signer(delegates.request.prepare.delegate);
      const ringRpc = relay();
      await pending.signOnChain(
        ringRpc,
        { getAccount: async () => ({ data: held(data(honest)) }) } as never,
        delegateSigner,
      );
      expect(ringRpc.submitRelay).toHaveBeenCalledOnce();
      await expect(
        pending.signOnChain(
          ringRpc,
          { getAccount: async () => undefined } as never,
          delegateSigner,
        ),
      ).rejects.toMatchObject({ details: { mismatch: "Accounts" } });
      await expect(pending.sign(ringRpc, delegateSigner)).rejects.toMatchObject({
        details: { mismatch: "SettlesBuffer" },
      });
    });
  });

  it("signs the honest messages the relay builds", async () => {
    for (const [expected, cases, address] of [
      [await deposit(deposits.request), deposits.cases, deposits.request.depositor],
      [await delegate(delegates.request), delegates.cases, delegates.request.prepare.delegate],
    ] as const) {
      const ringRpc = relay();
      await new PendingRelaySignature(RELAY_ID, message(cases, "honest"), expected).sign(
        ringRpc,
        signer(address),
      );
      expect(ringRpc.submitRelay).toHaveBeenCalledWith(
        expect.objectContaining({ relayId: RELAY_ID, signer: address }),
        undefined,
      );
    }
  });
});
