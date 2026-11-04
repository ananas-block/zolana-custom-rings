import { describe, expect, it, vi } from "vitest";

import vector from "../../../../test-vectors/merge/merge_v2.json" with { type: "json" };
import { initializePoseidon } from "@heliuslabs/zolana";
import {
  Reader,
  Writer,
  ZERO_32,
  bigIntToBytes,
  bytesToBigInt,
  fieldAdd,
} from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { X25519Keypair, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import { DISCLOSURE_CHUNK_BYTES } from "../../src/protocol/historical/v3/layout.js";
import {
  mergeDisclosureFieldCount,
  openRingMergeDisclosure,
  sealRingMergeDisclosure,
  sealRingMergeDisclosureWith,
  readRingMergeDisclosure,
  ringMergePublicInputHash,
  writeRingMergeDisclosure,
  type RingMergeDisclosure,
  type RingMergeOpening,
} from "../../src/protocol/historical/v3/merge-disclosure.js";

const request = vector.request;

function bytes<T extends Uint8Array>(value: string, length: number): T {
  const decoded = Uint8Array.from(Buffer.from(value.replace(/^0x/, ""), "hex"));
  if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function disclosure(): RingMergeDisclosure {
  return {
    proof: new Uint8Array(192).fill(7),
    ephemeralPublicKey: bytes<Bytes33>(vector.eph_pk, 33),
    ciphertext: bytes<Bytes32>(vector.envelope_ciphertext, 32),
    fields: vector.fields.map((field) => bytes<Bytes32>(field, 32)),
  };
}

function opening(): RingMergeOpening {
  return vector.input_commitments.map((value) => bytes<Bytes32>(value, 32));
}

/** A disclosure sealed under fresh keys, slot `dummy` zero. */
function sealed(width: number, dummy: number) {
  const auditor = X25519Keypair.generate();
  const salt = new Uint8Array(16).fill(5) as Bytes16;
  const hashes = Array.from({ length: width }, (_, slot) =>
    slot === dummy ? ZERO_32 : (new Uint8Array(32).fill(slot + 1) as Bytes32),
  );
  const {
    disclosure: body,
    ephemeralSecret,
    disclosureKey,
  } = sealRingMergeDisclosure(hashes, salt, auditor.publicKey());
  ephemeralSecret.fill(0);
  disclosureKey.fill(0);
  return { auditor, salt, hashes, disclosure: { ...body, proof: new Uint8Array(192) } };
}

describe("ring merge disclosure (test-vectors/merge/merge_v2.json)", () => {
  it("opens the Go disclosure and hashes the Go statement", async () => {
    await initializePoseidon();
    const auditor = X25519Keypair.fromBytes(bytes(vector.auditor_sk, 32));
    const salt = bytes<Bytes16>(vector.salt, 16);
    expect(openRingMergeDisclosure(auditor, disclosure(), salt)).toEqual(opening());
    const otherSalt = salt.slice() as Bytes16;
    otherSalt[0] = (otherSalt[0] ?? 0) ^ 1;
    expect(() => openRingMergeDisclosure(auditor, disclosure(), otherSalt)).toThrow();

    expect(vector.elements).toHaveLength(18);
    const hash = ringMergePublicInputHash({
      partyIdentities: request.partyIdentities.map((value) => bytes<Bytes32>(value, 32)) as [
        Bytes32,
        Bytes32,
        Bytes32,
      ],
      privateTxHash: bytes(request.privateTxHash, 32),
      outputUtxoHash: bytes(request.outputUtxoHash, 32),
      firstNullifier: bytes(request.firstNullifier, 32),
      ringId: bytes(request.ringProgramId, 32),
      auditorPublicKey: X25519PublicKey.fromBytes(bytes(vector.auditor_pk, 33)),
      disclosure: disclosure(),
      salt,
      inputCount: request.inputCount,
      ...(request.keyEscrow
        ? { memberRegistryRoot: bytes<Bytes32>(request.memberRegistryRoot, 32) }
        : {}),
    });
    expect(`0x${Buffer.from(hash).toString("hex")}`).toBe(vector.public_input_hash);
  });

  it("opens every slot in order, a dummy reads zero", async () => {
    await initializePoseidon();
    for (const width of [8, 24]) {
      const { auditor, salt, hashes, disclosure: body } = sealed(width, width - 1);
      expect(body.fields).toHaveLength(mergeDisclosureFieldCount(width));
      expect(openRingMergeDisclosure(auditor, body, salt)).toEqual(hashes);
      auditor.destroy();
    }
  });

  it("refuses nonzero padding, a field count off the keys and a width off the keys", async () => {
    await initializePoseidon();
    const { auditor, salt, disclosure: body } = sealed(8, 7);
    const refused = (fields: readonly Bytes32[]) => () =>
      openRingMergeDisclosure(auditor, { ...body, fields }, salt);
    const reason = (name: string) =>
      expect.objectContaining({ code: "RING_AUDIT_MESSAGE", details: { reason: name } });
    expect(
      refused(
        body.fields.with(
          -1,
          bigIntToBytes(fieldAdd(bytesToBigInt(body.fields.at(-1) ?? ZERO_32), 1n)) as Bytes32,
        ),
      ),
    ).toThrow(reason("disclosure padding"));
    expect(refused(body.fields.slice(1))).toThrow(reason("disclosure width"));
    for (const width of [2, 9, 52])
      expect(() =>
        sealRingMergeDisclosure(
          Array.from({ length: width }, () => ZERO_32),
          salt,
          auditor.publicKey(),
        ),
      ).toThrow(expect.objectContaining({ code: "RING_MERGE_TOO_WIDE" }));
    auditor.destroy();
  });

  it("refuses an opened hash past the field", async () => {
    await initializePoseidon();
    const auditor = X25519Keypair.generate();
    const salt = new Uint8Array(16).fill(6) as Bytes16;
    const hashes = Array.from({ length: 8 }, () => new Uint8Array(32).fill(0xff) as Bytes32);
    const { disclosure: body } = sealRingMergeDisclosure(hashes, salt, auditor.publicKey());
    expect(() =>
      openRingMergeDisclosure(auditor, { ...body, proof: new Uint8Array(192) }, salt),
    ).toThrow(
      expect.objectContaining({
        code: "RING_AUDIT_MESSAGE",
        details: { reason: "disclosure input" },
      }),
    );
    auditor.destroy();
  });

  it("binds the input count, the escrow flag and its root in the statement", async () => {
    await initializePoseidon();
    const { auditor, salt, disclosure: body } = sealed(8, 7);
    const statement = {
      partyIdentities: [ZERO_32, ZERO_32, ZERO_32] as const,
      privateTxHash: new Uint8Array(32).fill(1) as Bytes32,
      outputUtxoHash: new Uint8Array(32).fill(2) as Bytes32,
      firstNullifier: new Uint8Array(32).fill(3) as Bytes32,
      ringId: new Uint8Array(32).fill(4) as Bytes32,
      auditorPublicKey: auditor.publicKey(),
      disclosure: body,
      salt,
      inputCount: 2,
    };
    const root = new Uint8Array(32).fill(7) as Bytes32;
    const hashes = [
      statement,
      { ...statement, inputCount: 3 },
      { ...statement, memberRegistryRoot: root },
      { ...statement, memberRegistryRoot: ZERO_32 },
    ].map((input) => Buffer.from(ringMergePublicInputHash(input)).toString("hex"));
    expect(new Set(hashes).size).toBe(hashes.length);
    auditor.destroy();
  });

  it("seals the Go disclosure under the vector keys", async () => {
    await initializePoseidon();
    const auditor = X25519Keypair.fromBytes(bytes(vector.auditor_sk, 32));
    const ephemeral = X25519Keypair.fromBytes(bytes(vector.request.ephSk, 32));
    try {
      const sealed = sealRingMergeDisclosureWith({
        opening: opening(),
        salt: bytes(vector.salt, 16),
        auditor: auditor.publicKey(),
        ephemeral,
        disclosureKey: bytes(vector.request.disclosureKey, 32),
      });
      expect(sealed.disclosure).toEqual({
        ephemeralPublicKey: bytes(vector.eph_pk, 33),
        ciphertext: bytes(vector.envelope_ciphertext, 32),
        fields: vector.fields.map((field) => bytes(field, 32)),
      });
      expect(sealed.ephemeralSecret).toEqual(bytes(vector.request.ephSk, 32));
    } finally {
      ephemeral.destroy();
      auditor.destroy();
    }
  });

  it("wipes the opening when the auditor key exchange throws", async () => {
    await initializePoseidon();
    const auditor = X25519Keypair.fromBytes(bytes(vector.auditor_sk, 32));
    const ephemeral = X25519Keypair.fromBytes(bytes(vector.request.ephSk, 32));
    vi.spyOn(ephemeral, "ecdh").mockImplementation(() => {
      throw new RangeError("small order");
    });
    const fill = vi.spyOn(Uint8Array.prototype, "fill");
    try {
      expect(() =>
        sealRingMergeDisclosureWith({
          opening: opening(),
          salt: bytes(vector.salt, 16),
          auditor: auditor.publicKey(),
          ephemeral,
          disclosureKey: bytes(vector.request.disclosureKey, 32),
        }),
      ).toThrow("small order");
      const length = mergeDisclosureFieldCount(vector.width) * DISCLOSURE_CHUNK_BYTES;
      const wiped = fill.mock.contexts.filter(
        (buffer): buffer is Uint8Array => buffer instanceof Uint8Array && buffer.length === length,
      );
      expect(wiped).not.toHaveLength(0);
      for (const buffer of wiped) expect(buffer.every((byte) => byte === 0)).toBe(true);
    } finally {
      fill.mockRestore();
      ephemeral.destroy();
      auditor.destroy();
    }
  });

  it("copies no secret out of a refused seal", async () => {
    await initializePoseidon();
    const auditor = X25519Keypair.fromBytes(bytes(vector.auditor_sk, 32));
    const ephemeral = X25519Keypair.fromBytes(bytes(vector.request.ephSk, 32));
    const secretBytes = vi.spyOn(ephemeral, "secretBytes");
    try {
      expect(() =>
        sealRingMergeDisclosureWith({
          opening: opening(),
          salt: new Uint8Array(15) as Bytes16,
          auditor: auditor.publicKey(),
          ephemeral,
          disclosureKey: bytes(vector.request.disclosureKey, 32),
        }),
      ).toThrow();
      expect(secretBytes).not.toHaveBeenCalled();
    } finally {
      ephemeral.destroy();
      auditor.destroy();
    }
  });

  it("writes the disclosure ahead of the SPP body and reads back its own layout", () => {
    expect([8, 24, 52].map(mergeDisclosureFieldCount)).toEqual([9, 25, 54]);
    const present = writeRingMergeDisclosure(new Writer(), disclosure()).finish();
    expect(present.length).toBe(192 + 33 + 32 + 1 + 32 * vector.fields.length);
    expect(readRingMergeDisclosure(new Reader(present))).toEqual(disclosure());
    expect(() => readRingMergeDisclosure(new Reader(present.slice(0, -1)))).toThrow();
  });
});
