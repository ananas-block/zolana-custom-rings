import { readFileSync } from "node:fs";

import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { RingAddress, RingPaymentRequest } from "../../src/crypto/keys/ring-address.js";
import { RingKeyError } from "../../src/crypto/error.js";
import {
  KeypairError,
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type Bytes32,
} from "@heliuslabs/zolana/keypair";

type ValidCase = Readonly<{
  name: string;
  uri: string;
  recipient: string;
  ring_program_id: string;
  deposit_tag: string | null;
  amount: string | null;
  mint: string | null;
  label: string | null;
}>;

type RejectedCase = Readonly<{ name: string; uri: string; error: string }>;

const vectors = JSON.parse(
  readFileSync(
    new URL("../../../../test-vectors/wallet/ring_address.json", import.meta.url),
    "utf8",
  ),
) as Readonly<{ valid: readonly ValidCase[]; rejected: readonly RejectedCase[] }>;

function bytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function rustVariant(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof KeypairError || error instanceof RingKeyError)
      return error.rustVariant ?? error.code;
    throw error;
  }
  throw new Error("expected a key error");
}

function taggedUri(): string {
  return vectors.valid.find((row) => row.deposit_tag !== null)?.uri ?? "";
}

describe("shared ring address vectors (test-vectors/wallet/ring_address.json)", () => {
  it("parses and prints every valid request", () => {
    expect(vectors.valid.length).toBeGreaterThanOrEqual(3);
    for (const vector of vectors.valid) {
      const request = RingPaymentRequest.parse(vector.uri);
      expect(request.toString(), vector.name).toBe(vector.uri);
      expect(hex(request.address.recipient.toBytes())).toBe(vector.recipient);
      expect(request.address.ringProgramId).toBe(vector.ring_program_id);
      expect(request.depositTag === undefined ? null : hex(request.depositTag)).toBe(
        vector.deposit_tag,
      );
      expect(request.amount).toBe(vector.amount === null ? undefined : BigInt(vector.amount));
      expect(request.mint).toBe(vector.mint ?? undefined);
      expect(request.label).toBe(vector.label ?? undefined);
      expect(RingAddress.fromBase58(request.address.toBase58()).toBytes()).toEqual(
        request.address.toBytes(),
      );
    }
  });

  it("rejects every malformed request with the Rust variant", () => {
    expect(vectors.rejected.length).toBeGreaterThanOrEqual(17);
    for (const vector of vectors.rejected) {
      expect(
        rustVariant(() => RingPaymentRequest.parse(vector.uri)),
        vector.name,
      ).toBe(vector.error);
    }
  });

  it("builds the fixture request from the wallet keys and its request tag 0", () => {
    const vector = vectors.valid.find((row) => row.name === "bare");
    if (vector === undefined) throw new Error("no valid vector");
    const wallet = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(7) as Bytes32),
    ).shieldedAddress();
    const ring = address(vector.ring_program_id);
    const viewing = ViewingKey.fromBytes(new Uint8Array(32).fill(0x21) as Bytes32);
    const ringAddress = new RingAddress({
      recipient: ShieldedAddress.fromPublicKeys(
        wallet.signingPublicKey,
        wallet.nullifierPublicKey,
        viewing.publicKey(),
      ),
      ringProgramId: ring,
    });
    const request = new RingPaymentRequest({
      address: ringAddress,
      depositTag: viewing.recipientRequestViewTag(0n),
    });
    viewing.destroy();
    expect(request.toString()).toBe(vector.uri);
    expect(hex(ShieldedAddress.fromBytes(bytes(vector.recipient)).toBytes())).toBe(
      vector.recipient,
    );
  });

  it("prints a request with no deposit tag and refuses the old tag key", () => {
    const base = RingPaymentRequest.parse(taggedUri());
    const bare = new RingPaymentRequest({ address: base.address, amount: 5n });
    expect(bare.depositTag).toBeUndefined();
    expect(RingPaymentRequest.parse(bare.toString()).amount).toBe(5n);
    expect(bare.toString()).toContain("?amount=5");
    expect(new RingPaymentRequest({ address: base.address }).toString()).not.toContain("?");
    const tag = hex(base.depositTag ?? new Uint8Array());
    expect(
      rustVariant(() => RingPaymentRequest.parse(`zolana:${base.address.toBase58()}?tag=${tag}`)),
    ).toBe("UnknownRingPaymentKey");
  });

  it("refuses a deposit tag that no derivation takes before printing it", () => {
    const base = RingPaymentRequest.parse(taggedUri());
    const tag = Uint8Array.from(base.depositTag ?? new Uint8Array(32));
    tag[0] = 1;
    expect(rustVariant(() => new RingPaymentRequest({ ...base, depositTag: tag as Bytes32 }))).toBe(
      "InvalidRingPaymentTag",
    );
  });

  it("round-trips every field", () => {
    const base = RingPaymentRequest.parse(taggedUri());
    const request = new RingPaymentRequest({
      address: base.address,
      depositTag: base.depositTag,
      amount: (1n << 64n) - 1n,
      mint: address("5i1Ty3d3n2c3hYwdeaxkhtgMMSJUCiKYdpZK9TmPc5un"),
      label: "a=b&c?d/\u00e9 !*'()",
    });
    const parsed = RingPaymentRequest.parse(request.toString());
    expect(parsed.toString()).toBe(request.toString());
    expect(parsed.amount).toBe(request.amount);
    expect(parsed.mint).toBe(request.mint);
    expect(parsed.label).toBe(request.label);
    expect(parsed.depositTag).toEqual(request.depositTag);
  });
});
