import {
  address,
  generateKeyPairSigner,
  signTransactionWithSigners,
  type Address,
} from "@solana/kit";
import { compileUnsignedTransaction } from "@heliuslabs/zolana/internal";
import type {
  Bytes32,
  Instruction,
  RequestContext,
  Transaction,
} from "@heliuslabs/zolana/interface";
import { ShieldedKeypair } from "@heliuslabs/zolana/keypair";
import { AssetRegistry, Wallet } from "@heliuslabs/zolana/transaction";
import { walletSnapshotCipher } from "@heliuslabs/zolana/wallet";
import { describe, expect, it, vi } from "vitest";

import { BLOCKHASH } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { BufferedFrame } from "../../../src/operations/payments/buffered-frame.js";
import {
  reconcileRingSubmissions,
  RingTransactionSubmission,
  submissionBufferNonce,
  type RingSubmissionAttempt,
} from "../../../src/operations/workflow/submission.js";
import { RingProgramError } from "../../../src/protocol/error.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import type { RingSubmissionStatus, RingSubmissionTransport } from "../../../src/rpc/ports.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const HASH = new Uint8Array(32) as Bytes32;
const ID = "0123456789abcdef0123456789abcdef";
const CONFIRMED: RingSubmissionStatus = { kind: "confirmed", slot: 5n };
const STALE_ROOT: RingSubmissionStatus = {
  kind: "failed",
  instructionIndex: 0,
  customCode: RingProgramError.rootNotServed,
};

function inlineFrame(): Instruction {
  const data = new Uint8Array(6_000).fill(3);
  data[0] = RingInstructionTag.transfer;
  return { programAddress: RING, accounts: [], data };
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  for (let start = 0; start + needle.length <= haystack.length; start += 1)
    if (needle.every((byte, offset) => haystack[start + offset] === byte)) return true;
  return false;
}

/** A buffered attempt over a chain that answers each sent transaction from `outcomes`, then confirms. */
async function fixture(outcomes: readonly (RingSubmissionStatus | undefined)[] = []) {
  const payer = await generateKeyPairSigner();
  const frame = await BufferedFrame.of(inlineFrame(), payer.address, submissionBufferNonce(ID));
  let bufferHeld = true;
  const chain = {
    getAccount: vi.fn(async (_buffer: Address, _context?: RequestContext) =>
      bufferHeld ? ({} as never) : undefined,
    ),
    getLatestBlockhash: vi.fn(async () => BLOCKHASH),
  };
  const build = vi.fn(
    async (): Promise<RingSubmissionAttempt> => ({
      transaction: compileUnsignedTransaction({
        feePayer: payer.address,
        lifetime: BLOCKHASH,
        instructions: [frame.settle()],
        computeUnitLimit: 1_000_000,
      }),
      lastValidBlockHeight: 100n,
      intentHash: HASH,
      ringInstructionIndex: 0,
      upload: { frame, writer: payer.address, chain },
    }),
  );
  const sent: Transaction[] = [];
  const queue = [...outcomes];
  const send = vi.fn(async (transaction: Transaction) => {
    sent.push(transaction);
    return queue.shift();
  });
  const status = vi.fn(async (): Promise<RingSubmissionStatus> => CONFIRMED);
  const sign = vi.fn(async (transaction: Transaction) =>
    signTransactionWithSigners([payer], transaction),
  );
  const transport: RingSubmissionTransport = { sign, send, status };
  const release = vi.fn();
  const owner = ShieldedKeypair.generate();
  const wallet = new Wallet({
    identity: owner.shieldedAddress(),
    registry: new AssetRegistry(),
  });
  const submission = new RingTransactionSubmission({
    first: await build(),
    build,
    wallet,
    reservationId: ID,
    reservation: { release, extend: vi.fn() },
  });
  const carried = (index: number, instruction: Instruction): boolean =>
    containsBytes(
      new Uint8Array(sent[index]?.messageBytes ?? new Uint8Array()),
      Uint8Array.from(instruction.data ?? []),
    );
  return {
    owner,
    payer,
    frame,
    chain,
    build,
    sent,
    send,
    status,
    sign,
    transport,
    release,
    wallet,
    submission,
    carried,
    dropBuffer: () => {
      bufferHeld = false;
    },
  };
}

describe("a buffered ring submission", () => {
  it("lands every write in order, then broadcasts the settlement once", async () => {
    const f = await fixture();
    const writes = f.frame.writes();
    expect(writes.length).toBeGreaterThan(1);
    const result = await f.submission.send(f.transport);
    expect(result.kind).toBe("confirmed");
    expect(f.sent).toHaveLength(writes.length + 1);
    writes.forEach((write, index) => expect(f.carried(index, write)).toBe(true));
    expect(f.carried(writes.length, f.frame.settle())).toBe(true);
    expect(f.build).toHaveBeenCalledTimes(1);
    expect(f.release).not.toHaveBeenCalled();
  });

  it("records the settlement's signature ahead of the first write", async () => {
    const f = await fixture();
    f.send.mockImplementationOnce(async (transaction) => {
      f.sent.push(transaction);
      expect(f.wallet.pendingSubmissions()).toHaveLength(1);
      return undefined;
    });
    const result = await f.submission.send(f.transport);
    expect(f.wallet.pendingSubmissions()[0]?.signature).toBe(result.signature);
    expect(f.wallet.pendingSubmissions()[0]?.lastValidBlockHeight).toBe(100n);
  });

  it("resumes an unresolved write by reading it, never by sending it again", async () => {
    const f = await fixture();
    f.status.mockResolvedValueOnce({ kind: "unknown" });
    const first = await f.submission.send(f.transport);
    expect(first.kind).toBe("unknown");
    expect(f.sent).toHaveLength(1);
    const second = await f.submission.send(f.transport);
    expect(second.kind).toBe("confirmed");
    expect(f.sent).toHaveLength(f.frame.writes().length + 1);
    expect(f.carried(1, f.frame.writes()[1] as Instruction)).toBe(true);
    expect(f.sign).toHaveBeenCalledTimes(f.frame.writes().length + 1);
  });

  it("refuses a cancel while a write is unresolved and keeps the record", async () => {
    const f = await fixture();
    f.status.mockResolvedValueOnce({ kind: "unknown" });
    await f.submission.send(f.transport);
    expect(() => f.submission.cancel()).toThrow("RING_SUBMISSION_PENDING");
    expect(f.wallet.pendingSubmissions()).toHaveLength(1);
  });

  it("never broadcasts the settlement after a refused write, and closes the buffer", async () => {
    const f = await fixture([{ kind: "failed", instructionIndex: 0, customCode: 1 }]);
    const result = await f.submission.send(f.transport);
    expect(result).toMatchObject({ kind: "failed", customCode: 1, attempts: 1 });
    expect(f.sent).toHaveLength(2);
    expect(f.carried(1, f.frame.close())).toBe(true);
    expect(f.carried(1, f.frame.settle())).toBe(false);
    expect(f.release).toHaveBeenCalledTimes(1);
    expect(f.wallet.pendingSubmissions()).toHaveLength(0);
  });

  it("closes the buffer ahead of the rebuild a stale proof takes", async () => {
    const writes = (await fixture()).frame.writes().length;
    const f = await fixture([...Array.from({ length: writes }, () => undefined), STALE_ROOT]);
    const result = await f.submission.send(f.transport);
    expect(result).toMatchObject({ kind: "confirmed", attempts: 2 });
    expect(f.build).toHaveBeenCalledTimes(2);
    // Each attempt's writes and settlement, the close standing between them.
    expect(f.sent).toHaveLength(2 * (writes + 1) + 1);
    expect(f.carried(writes, f.frame.settle())).toBe(true);
    expect(f.carried(writes + 1, f.frame.close())).toBe(true);
    expect(f.carried(writes + 2, f.frame.writes()[0] as Instruction)).toBe(true);
  });

  it("holds the rebuild and the record while the close is unresolved", async () => {
    const writes = (await fixture()).frame.writes().length;
    const f = await fixture([...Array.from({ length: writes }, () => undefined), STALE_ROOT]);
    f.status.mockImplementation(async () => ({ kind: "unknown" }));
    for (let index = 0; index < writes; index += 1) {
      f.status.mockResolvedValueOnce(CONFIRMED);
    }
    const closing = await f.submission.send(f.transport);
    expect(closing.kind).toBe("unknown");
    expect(f.carried(writes + 1, f.frame.close())).toBe(true);
    const builds = f.build.mock.calls.length;
    await f.submission.send(f.transport);
    expect(f.build).toHaveBeenCalledTimes(builds);
    expect(f.sent).toHaveLength(writes + 2);
    expect(f.wallet.pendingSubmissions()).toHaveLength(1);
    expect(f.release).not.toHaveBeenCalled();
  });

  it("misses a buffer no write created", async () => {
    const f = await fixture([{ kind: "failed", instructionIndex: 0, customCode: 1 }]);
    f.dropBuffer();
    const result = await f.submission.send(f.transport);
    expect(result.kind).toBe("failed");
    expect(f.sent).toHaveLength(1);
  });

  it("throws on a refused close over a standing buffer and keeps the record", async () => {
    const f = await fixture([
      { kind: "failed", instructionIndex: 0, customCode: 1 },
      { kind: "failed", instructionIndex: 0, customCode: 2 },
    ]);
    await expect(f.submission.send(f.transport)).rejects.toMatchObject({
      code: "RING_FRAME_BUFFER_CLOSE",
    });
    expect(f.wallet.pendingSubmissions()).toHaveLength(1);
    expect(f.release).not.toHaveBeenCalled();
  });

  it("treats a settlement status that stays unknown as neither failed nor closable", async () => {
    const writes = (await fixture()).frame.writes().length;
    const f = await fixture();
    for (let index = 0; index < writes; index += 1) f.status.mockResolvedValueOnce(CONFIRMED);
    f.status.mockResolvedValueOnce({ kind: "unknown" });
    const result = await f.submission.send(f.transport);
    expect(result.kind).toBe("unknown");
    expect(f.sent).toHaveLength(writes + 1);
    expect(f.chain.getAccount).not.toHaveBeenCalled();
  });
});

describe("reconcileRingSubmissions over a buffered record", () => {
  async function recorded() {
    const f = await fixture();
    f.status.mockResolvedValue({ kind: "unknown" });
    await f.submission.send(f.transport);
    const store = { save: vi.fn(async () => undefined) };
    const cipher = walletSnapshotCipher(f.owner);
    const reclaim = {
      ringProgramId: RING,
      writer: f.payer.address,
      chain: f.chain,
      transport: f.transport,
    };
    const persistence = { wallet: f.wallet, store, cipher };
    return { ...f, reclaim, persistence };
  }

  it("closes the buffer named by the record's id, the record stays until it is gone", async () => {
    const f = await recorded();
    const sentBefore = f.sent.length;
    const statusOf = { status: async () => ({ kind: "expired" as const }) };
    const closing = await reconcileRingSubmissions({
      ...f.persistence,
      transport: statusOf,
      reclaim: f.reclaim,
    });
    expect(closing[0]?.kind).toBe("unknown");
    expect(f.chain.getAccount).toHaveBeenCalledWith(f.frame.buffer, undefined);
    expect(f.sent).toHaveLength(sentBefore + 1);
    expect(f.carried(sentBefore, f.frame.close())).toBe(true);
    expect(f.wallet.pendingSubmissions()).toHaveLength(1);
    f.dropBuffer();
    const closed = await reconcileRingSubmissions({
      ...f.persistence,
      transport: statusOf,
      reclaim: f.reclaim,
    });
    expect(closed[0]?.kind).toBe("failed");
    expect(f.sent).toHaveLength(sentBefore + 1);
    expect(f.wallet.pendingSubmissions()).toHaveLength(0);
  });

  it("leaves the buffer alone while the settlement is unresolved", async () => {
    const f = await recorded();
    const sentBefore = f.sent.length;
    const results = await reconcileRingSubmissions({
      ...f.persistence,
      transport: { status: async () => ({ kind: "unknown" as const }) },
      reclaim: f.reclaim,
    });
    expect(results[0]?.kind).toBe("unknown");
    expect(f.sent).toHaveLength(sentBefore);
    expect(f.wallet.pendingSubmissions()).toHaveLength(1);
  });

  it("removes the record with no close when the caller names no reclaim", async () => {
    const f = await recorded();
    const sentBefore = f.sent.length;
    const results = await reconcileRingSubmissions({
      ...f.persistence,
      transport: { status: async () => ({ kind: "expired" as const }) },
    });
    expect(results[0]?.kind).toBe("failed");
    expect(f.sent).toHaveLength(sentBefore);
    expect(f.wallet.pendingSubmissions()).toHaveLength(0);
  });
});
