import {
  address,
  generateKeyPairSigner,
  signTransactionWithSigners,
  type Address,
} from "@solana/kit";
import { addressBytes, compileUnsignedTransaction } from "@heliuslabs/zolana/internal";
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
  closeAbandonedFrameBuffers,
  reconcileRingSubmissions,
  RingTransactionSubmission,
  type RingSubmissionAttempt,
} from "../../../src/operations/workflow/submission.js";
import { RingProgramError } from "../../../src/protocol/error.js";
import { FRAME_BUFFER_HEADER_LEN } from "../../../src/protocol/transaction/frame-buffer.js";
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
  const frame = await BufferedFrame.forWriter(inlineFrame(), payer.address);
  let bufferHeld = true;
  const chain = {
    getAccount: vi.fn(async (_buffer: Address, _context?: RequestContext) =>
      bufferHeld ? ({} as never) : undefined,
    ),
    getLatestBlockhash: vi.fn(async () => BLOCKHASH),
  };
  const build = vi.fn(async (): Promise<RingSubmissionAttempt> => ({
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
  }));
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
  it("names one buffer per writer and frame, a resend finds its own", async () => {
    const f = await fixture();
    const again = await BufferedFrame.forWriter(inlineFrame(), f.payer.address);
    expect(again.buffer).toBe(f.frame.buffer);
    const data = Uint8Array.from(inlineFrame().data ?? []);
    data[1] = 4;
    const other = await BufferedFrame.forWriter({ ...inlineFrame(), data }, f.payer.address);
    expect(other.buffer).not.toBe(f.frame.buffer);
  });

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

describe("a buffered record after a restart", () => {
  async function recorded() {
    const f = await fixture();
    f.status.mockResolvedValue({ kind: "unknown" });
    await f.submission.send(f.transport);
    const persistence = {
      wallet: f.wallet,
      store: { save: vi.fn(async () => undefined) },
      cipher: walletSnapshotCipher(f.owner),
    };
    const buffer = (writer: Address) => {
      const data = new Uint8Array(FRAME_BUFFER_HEADER_LEN + 8);
      data[0] = 16;
      data.set(addressBytes(writer), 1);
      return data;
    };
    const stranger = await generateKeyPairSigner();
    const accounts = [
      { address: f.frame.buffer, account: { data: buffer(f.payer.address) } },
      { address: stranger.address, account: { data: buffer(stranger.address) } },
      { address: RING, account: { data: new Uint8Array(64) } },
    ];
    const reclaim = {
      ringProgramId: RING,
      writer: f.payer.address,
      chain: {
        getProgramAccounts: vi.fn(async () => accounts as never),
        getLatestBlockhash: async () => BLOCKHASH,
      },
      transport: f.transport,
    };
    return { ...f, persistence, reclaim };
  }

  it("settles the record by its signature and sends nothing", async () => {
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

  it("closes no buffer while the wallet holds a record", async () => {
    const f = await recorded();
    await expect(
      closeAbandonedFrameBuffers({ ...f.reclaim, wallet: f.wallet }),
    ).rejects.toMatchObject({ code: "RING_SUBMISSION_PENDING" });
    expect(f.reclaim.chain.getProgramAccounts).not.toHaveBeenCalled();
  });

  it("closes only the writer's own buffers once no record stands", async () => {
    const f = await recorded();
    await reconcileRingSubmissions({
      ...f.persistence,
      transport: { status: async () => ({ kind: "expired" as const }) },
    });
    const sentBefore = f.sent.length;
    const closed = await closeAbandonedFrameBuffers({ ...f.reclaim, wallet: f.wallet });
    expect(closed).toHaveLength(1);
    expect(f.sent).toHaveLength(sentBefore + 1);
    const message = new Uint8Array(f.sent[sentBefore]?.messageBytes ?? new Uint8Array());
    expect(containsBytes(message, addressBytes(f.frame.buffer))).toBe(true);
  });

  it("throws on a refused close", async () => {
    const f = await recorded();
    await reconcileRingSubmissions({
      ...f.persistence,
      transport: { status: async () => ({ kind: "expired" as const }) },
    });
    f.send.mockResolvedValueOnce({ kind: "failed", customCode: 1 });
    await expect(
      closeAbandonedFrameBuffers({ ...f.reclaim, wallet: f.wallet }),
    ).rejects.toMatchObject({ code: "RING_FRAME_BUFFER_CLOSE" });
  });
});
