import { getAddressDecoder } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type Bytes32,
  type Bytes64,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  LocalShieldedKeys,
  type ShieldedKeys,
  SOL_MINT,
} from "@heliuslabs/zolana";
import { X25519Keypair } from "@heliuslabs/zolana/keypair";
import { createProofOutput, AssetRegistry } from "@heliuslabs/zolana/transaction";
import { withTransactionKey } from "@heliuslabs/zolana/internal";
import { encryptCustomRingTransfer } from "../src/transaction/wallet/encrypt-rails.js";
import { RING_SPEND_COUNTERS_SLOT_INDEX } from "../src/ring/counters.js";

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function signingKey(): SigningKey {
  return SigningKey.fromEd25519Bytes(filled(11));
}

function keypairKeys(): ShieldedKeys {
  return LocalShieldedKeys.fromKeypair(ShieldedKeypair.fromKeypair(signingKey()));
}

function derivedKeys(): ShieldedKeys {
  const signing = signingKey();
  const solanaPublicKey = getAddressDecoder().decode(signing.publicKey().ed25519());
  return LocalShieldedKeys.fromDerivationSeed({
    solanaPublicKey,
    derivationSeed: signing.derivationSeed() as Bytes64,
  });
}

function trackMintedTxViewingKeys(): ViewingKey[] {
  const minted: ViewingKey[] = [];
  const original = ViewingKey.prototype.transactionViewingKey;
  vi.spyOn(ViewingKey.prototype, "transactionViewingKey").mockImplementation(function (
    this: ViewingKey,
    firstNullifier: Bytes32,
  ) {
    const key = original.call(this, firstNullifier);
    minted.push(key);
    return key;
  });
  return minted;
}

function recipientOutput() {
  return createProofOutput({
    ownerAddress: ShieldedKeypair.generate().shieldedAddress(),
    asset: SOL_MINT,
    amount: 5n,
    blinding: filled(3),
  });
}

function expectWiped(minted: readonly ViewingKey[]): void {
  expect(minted).toHaveLength(1);
  expect(() => minted[0]?.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("custom ring transfer keeps the audit secrets past the wiped transaction key", () => {
  for (const [name, make] of [
    ["keypair keys", keypairKeys],
    ["derivation-seed keys", derivedKeys],
  ] as const) {
    it(`${name} custom ring transfer keeps the audit secrets readable`, async () => {
      const keys = make();
      const auditor = X25519Keypair.generate();
      const minted = trackMintedTxViewingKeys();
      const encrypted = await withTransactionKey(keys, filled(1), (tx) =>
        encryptCustomRingTransfer(tx, {
          outputs: [recipientOutput()],
          assets: new AssetRegistry(),
          auditorPublicKey: auditor.publicKey(),
          outputTreeId: 0,
        }),
      );
      expectWiped(minted);
      expect(encrypted.audit.txViewingSecret.some((byte: number) => byte !== 0)).toBe(true);
      expect(encrypted.audit.ephemeralSecret.some((byte: number) => byte !== 0)).toBe(true);
    });
  }
});

describe("custom ring transfer seals each slot once", () => {
  const message = (slotIndex: number) => ({
    viewTag: filled(9),
    plaintext: Uint8Array.of(1, 2, 3),
    slotIndex,
  });

  const encrypt = (
    extra: Readonly<{
      sealedMessages?: readonly ReturnType<typeof message>[];
      counterMessage?: Omit<ReturnType<typeof message>, "slotIndex">;
      recordOutputIndex?: number;
    }>,
  ) =>
    withTransactionKey(keypairKeys(), filled(1), (tx) =>
      encryptCustomRingTransfer(tx, {
        outputs: [recipientOutput()],
        assets: new AssetRegistry(),
        auditorPublicKey: X25519Keypair.generate().publicKey(),
        outputTreeId: 0,
        ...extra,
      }),
    );

  it("rejects two caller messages on one slot", async () => {
    await expect(encrypt({ sealedMessages: [message(5), message(5)] })).rejects.toMatchObject({
      code: "TRANSACTION_DUPLICATE_SLOT_INDEX",
    });
  });

  it("rejects a caller message on an output slot", async () => {
    await expect(encrypt({ sealedMessages: [message(0)] })).rejects.toMatchObject({
      code: "TRANSACTION_DUPLICATE_SLOT_INDEX",
    });
  });

  it("encrypts with the slot indices that were validated", async () => {
    let reads = 0;
    const changing = {
      ...message(5),
      get slotIndex() {
        reads += 1;
        return reads <= 2 ? 5 : 6;
      },
    };
    const encryptSlot = vi.spyOn(ViewingKey.prototype, "encryptSlot");
    try {
      const encrypted = await encrypt({ sealedMessages: [changing, message(6)] });
      expect(reads).toBe(1);
      expect(encryptSlot.mock.calls.slice(0, 2).map((call) => call[3])).toEqual([5, 6]);
      encrypted.audit.txViewingSecret.fill(0);
      encrypted.audit.ephemeralSecret.fill(0);
    } finally {
      encryptSlot.mockRestore();
    }
  });

  it("rejects a caller message on the protocol counter slot", async () => {
    await expect(
      encrypt({
        sealedMessages: [message(RING_SPEND_COUNTERS_SLOT_INDEX)],
        counterMessage: message(RING_SPEND_COUNTERS_SLOT_INDEX),
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_DUPLICATE_SLOT_INDEX" });
  });

  it("reserves the counter slot without a counter message", async () => {
    const minted = trackMintedTxViewingKeys();
    await expect(
      encrypt({ sealedMessages: [message(RING_SPEND_COUNTERS_SLOT_INDEX)] }),
    ).rejects.toMatchObject({ code: "TRANSACTION_DUPLICATE_SLOT_INDEX" });
    expectWiped(minted);
  });

  it("assigns the protocol counter slot before encryption", async () => {
    const encryptSlot = vi.spyOn(ViewingKey.prototype, "encryptSlot");
    try {
      const encrypted = await encrypt({ counterMessage: message(7) });
      expect(encrypted.sealedMessages).toHaveLength(1);
      expect(encryptSlot.mock.calls[0]?.[3]).toBe(RING_SPEND_COUNTERS_SLOT_INDEX);
      encrypted.audit.txViewingSecret.fill(0);
      encrypted.audit.ephemeralSecret.fill(0);
    } finally {
      encryptSlot.mockRestore();
    }
  });

  it("seals the protocol counter on its own slot", async () => {
    const encrypted = await encrypt({ counterMessage: message(RING_SPEND_COUNTERS_SLOT_INDEX) });
    expect(encrypted.sealedMessages).toHaveLength(1);
  });

  it("refuses an invalid protocol output position and wipes the transaction key", async () => {
    const minted = trackMintedTxViewingKeys();
    await expect(encrypt({ recordOutputIndex: 1 })).rejects.toMatchObject({
      code: "TRANSACTION_INVALID_OUTPUT_POSITION",
    });
    expectWiped(minted);
  });

  it("does not turn an ordinary payment into a protocol carrier", async () => {
    const minted = trackMintedTxViewingKeys();
    await expect(encrypt({ recordOutputIndex: 0 })).rejects.toMatchObject({
      code: "TRANSACTION_OUTPUT_DATA_MISMATCH",
    });
    expectWiped(minted);
  });
});
