import { beforeAll, describe, expect, it, vi } from "vitest";

import stream from "../../../../test-vectors/audit/auditor-stream.json" with { type: "json" };
import { BN254_SCALAR_ORDER, bigIntToBytes } from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { X25519Keypair, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  ANONYMOUS_RECORD_LEN,
  envelopeRegion,
  recordRegion,
  recordSlots,
  type AuditStreamLayout,
} from "../../src/protocol/codec/ring-disclosure-layout.js";
import type * as Audit from "../../src/crypto/audit/audit.js";
import {
  AUDIT_ENC_INFO,
  auditSharedSecret,
  auditorMessageData,
  openAuditorRegions,
  openTransactionViewingSecret,
  parseAuditorMessage,
  symmetricAuditApply,
} from "../../src/crypto/audit/audit.js";
import {
  anonymousCommitments,
  decodeDisclosure,
  disclosurePlaintext,
  inputPrefix,
  inputPrefixes,
  openRingDisclosure,
  sealRingDisclosure,
  type InputPrefix,
  type RingDisclosure,
} from "../../src/crypto/audit/ring-disclosure.js";
import { openDeliveredBody, sealDeliveredBody } from "../../src/protocol/transaction/output.js";

const sealedPlaintexts = vi.hoisted((): Uint8Array[] => []);
vi.mock("../../src/crypto/audit/audit.js", async (importOriginal) => {
  const actual = await importOriginal<typeof Audit>();
  return {
    ...actual,
    sealAuditorStream: (input: Parameters<typeof actual.sealAuditorStream>[0]) => {
      sealedPlaintexts.push(input.envelope, ...input.records.map((record) => record.bytes));
      return actual.sealAuditorStream(input);
    },
  };
});

beforeAll(initializePoseidon);

const MODULUS = bigIntToBytes(BN254_SCALAR_ORDER) as Bytes32;
const TX_SECRET = new Uint8Array(32).fill(0x48) as Bytes32;

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function field(byte: number): Bytes32 {
  const out = new Uint8Array(32).fill(byte);
  out[0] = 0;
  return out as Bytes32;
}

function bytes(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

function prefix(hash: Bytes32): InputPrefix {
  const value = inputPrefix(hash);
  if (value === undefined) throw new Error("hash without a prefix");
  return value;
}

/** An exit at slots 1 and 4, the other slots publish a delivered body. */
function delivered(
  keyEscrow = false,
  inputPrefixesNamed = true,
): Extract<RingDisclosure, { kind: "delivered" }> {
  const exit = (byte: number, amount: bigint) => ({
    kind: "exit" as const,
    nullifierPk: keyEscrow ? undefined : field(byte),
    asset: field(byte + 1),
    amount,
  });
  const body = { kind: "body" as const };
  return {
    kind: "delivered",
    layout: {
      key: { kind: "confidential", class: 16, inputPrefixes: inputPrefixesNamed },
      keyEscrow,
      inputs: 2,
      outputs: 8,
      exits: 0b1_0010n,
    },
    inputs: inputPrefixesNamed
      ? { kind: "prefixes", prefixes: inputPrefixes([field(0x60), undefined]) }
      : { kind: "none" },
    outputs: [body, exit(0x20, 0n), body, body, exit(0x24, 40n), body, body, body],
  };
}

/** The entry key at two published inputs, slot 1 an exit and slot 2 a dummy. */
function entry(): Extract<RingDisclosure, { kind: "anonymous" }> {
  return {
    kind: "anonymous",
    layout: {
      key: { kind: "entry", class: 8 },
      keyEscrow: false,
      inputs: 2,
      outputs: 4,
      exits: 0b10n,
    },
    outputs: [
      {
        kind: "ring",
        ownerKey: bytes(0xb5),
        nullifierPk: field(0x25),
        asset: field(0x15),
        amount: 70n,
      },
      { kind: "exit", nullifierPk: field(0x26), asset: field(0x27), amount: 0n },
      { kind: "dummy" },
      {
        kind: "ring",
        ownerKey: bytes(0xa1),
        nullifierPk: field(0x5a),
        asset: field(0x17),
        amount: (1n << 64n) - 1n,
      },
    ],
    inputs: {
      kind: "openings",
      senderKey: bytes(0xa1),
      senderNullifierPk: field(0x5a),
      inputs: [{ asset: field(0x60), amount: 5000n, blinding: field(0x61) }, undefined],
    },
  };
}

function commitments(): Extract<RingDisclosure, { kind: "anonymous" }> {
  return {
    ...entry(),
    layout: {
      key: { kind: "commitment", class: 16 },
      keyEscrow: false,
      inputs: 4,
      outputs: 4,
      exits: 0b10n,
    },
    inputs: anonymousCommitments([field(0x60), field(0x61), undefined, field(0x63)]),
  };
}

describe("auditor-stream.json", () => {
  it.each([...stream.labels, ...stream.records])(
    "$name reads the worked stream at its counter",
    (vector) => {
      const secret = hex(vector.secret) as Bytes32;
      const position = {
        label: new TextEncoder().encode(vector.label),
        counter: vector.counter,
      };
      expect(symmetricAuditApply(secret, position, hex(vector.plaintext))).toEqual(
        hex(vector.ciphertext),
      );
      expect(symmetricAuditApply(secret, position, hex(vector.ciphertext))).toEqual(
        hex(vector.plaintext),
      );
    },
  );

  it("roots the auditor stream in the agreement of both tagged keys", () => {
    const eph = X25519Keypair.fromBytes(hex(stream.eph_sk) as Bytes32);
    expect(eph.publicKey().u()).toEqual(hex(stream.eph_u));
    const auditor = X25519PublicKey.fromBytes(
      Uint8Array.of(4, ...hex(stream.auditor_u)) as Bytes33,
    );
    const secret = auditSharedSecret(eph.ecdh(auditor), eph.publicKey(), auditor);
    const signer = stream.labels.find((vector) => vector.name === "envelope_signer");
    expect(signer === undefined ? "" : hex(signer.secret)).toEqual(secret);
  });

  it.each([
    ["envelope_commitment_n2", { kind: "commitment", class: 24 }, 2],
    ["envelope_entry_n1", { kind: "entry", class: 8 }, 1],
    ["envelope_in_proof_n2", { kind: "confidential", class: 32, inputPrefixes: true }, 2],
    ["envelope_signer", { kind: "confidential", class: 32, inputPrefixes: false }, 2],
  ] as const)("%s decodes under its layout", (name, key, inputs) => {
    const vector = stream.labels.find((candidate) => candidate.name === name);
    if (vector === undefined) throw new Error(`no ${name} vector`);
    const plaintext = hex(vector.plaintext);
    const layout: AuditStreamLayout = {
      key,
      keyEscrow: false,
      inputs,
      outputs: 2,
      exits: 0n,
    };
    expect(plaintext.length).toBe(envelopeRegion(layout).length);
    const anonymous = key.kind !== "confidential";
    const records = anonymous
      ? recordSlots(layout).map(() => new Uint8Array(ANONYMOUS_RECORD_LEN))
      : [];
    const opened = decodeDisclosure(layout, { evidence: plaintext.subarray(32), records });
    expect(disclosurePlaintext(opened).evidence).toEqual(plaintext.subarray(32));
  });

  it.each(["body_keyed", "body_key_escrow"])("%s opens to its fields", (name) => {
    const vector = stream.labels.find((candidate) => candidate.name === name);
    if (vector === undefined) throw new Error(`no ${name} vector`);
    const plaintext = hex(vector.plaintext);
    const opened = openDeliveredBody(hex(vector.secret) as Bytes32, hex(vector.ciphertext));
    expect(opened.blinding).toEqual(plaintext.subarray(0, 32));
    expect(opened.ownerKey).toEqual(plaintext.subarray(40, 72));
    expect(opened.nullifierPk).toEqual(
      plaintext.length === 72 ? undefined : plaintext.subarray(72),
    );
    expect(sealDeliveredBody(hex(vector.secret) as Bytes32, opened)).toEqual(
      hex(vector.ciphertext),
    );
  });
});

describe("ring disclosure codec", () => {
  it.each([
    ["delivered with input prefixes", delivered],
    ["delivered on the signer rail", () => delivered(false, false)],
    ["delivered under key escrow", () => delivered(true)],
    ["the entry key", entry],
    ["the commitment key", commitments],
  ] as const)("reads back %s", (_, build) => {
    const disclosure = build();
    expect(decodeDisclosure(disclosure.layout, disclosurePlaintext(disclosure))).toEqual(
      disclosure,
    );
  });

  it("transmits nothing past the published input count and no delivered slot record", () => {
    const plaintext = disclosurePlaintext(delivered());
    expect(plaintext.evidence).toHaveLength(32);
    expect(plaintext.evidence.subarray(0, 16)).toEqual(field(0x60).subarray(0, 16));
    expect(plaintext.evidence.subarray(16)).toEqual(new Uint8Array(16));
    expect(plaintext.records.map((record) => record.length)).toEqual([72, 72]);
    expect(disclosurePlaintext(delivered(true)).records.map((record) => record.length)).toEqual([
      40, 40,
    ]);
    expect(disclosurePlaintext(delivered(false, false)).evidence).toHaveLength(0);
  });

  it("lays out every record and the entry evidence as the contract names them", () => {
    const disclosure = entry();
    const { evidence, records } = disclosurePlaintext(disclosure);
    expect(evidence).toHaveLength(64 + 2 * 72);
    expect(evidence.subarray(0, 32)).toEqual(bytes(0xa1));
    expect(evidence.subarray(32, 64)).toEqual(field(0x5a));
    expect(evidence.subarray(64, 72)).toEqual(bigIntToBytes(5000n, 8));
    expect(evidence.subarray(72, 104)).toEqual(field(0x60));
    expect(evidence.subarray(104, 136)).toEqual(field(0x61));
    expect(evidence.subarray(136)).toEqual(new Uint8Array(72));
    expect(records[0]?.subarray(0, 32)).toEqual(bytes(0xb5));
    expect(records[0]?.subarray(32, 64)).toEqual(field(0x15));
    expect(records[0]?.subarray(64, 72)).toEqual(bigIntToBytes(70n, 8));
    expect(records[0]?.subarray(72)).toEqual(field(0x25));
    expect(records[1]?.subarray(0, 32)).toEqual(field(0x27));
    expect(records[1]?.subarray(32, 40)).toEqual(new Uint8Array(8));
    expect(records[1]?.subarray(40)).toEqual(field(0x26));
    expect(records[2]).toEqual(new Uint8Array(ANONYMOUS_RECORD_LEN));
  });

  it("names spent UTXO 0 by its hash and every later one by its prefix", () => {
    const { evidence } = disclosurePlaintext(commitments());
    expect(evidence).toHaveLength(32 + 3 * 16);
    expect(evidence.subarray(0, 32)).toEqual(field(0x60));
    expect(evidence.subarray(32, 48)).toEqual(field(0x61).subarray(0, 16));
    expect(evidence.subarray(48, 64)).toEqual(new Uint8Array(16));
    expect(evidence.subarray(64)).toEqual(field(0x63).subarray(0, 16));
  });

  it("refuses spent UTXO 0 as a dummy, a later hash below 2^128 and a prefix no hash has", () => {
    const short = new Uint8Array(32) as Bytes32;
    short[31] = 1;
    expect(() => anonymousCommitments([undefined, field(0x61)])).toThrow(
      "KEYPAIR_DISCLOSURE_SHAPE",
    );
    expect(() => anonymousCommitments([field(0x60), short])).toThrow("KEYPAIR_DISCLOSURE_FIELD");
    const disclosure = commitments();
    const decode = (change: (evidence: Uint8Array) => void) => () => {
      const plaintext = disclosurePlaintext(disclosure);
      change(plaintext.evidence);
      return decodeDisclosure(disclosure.layout, plaintext);
    };
    expect(decode((evidence) => evidence.fill(0, 0, 32))).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(decode((evidence) => evidence.fill(0xff, 32, 48))).toThrow("KEYPAIR_DISCLOSURE_FIELD");
    expect(decode((evidence) => evidence.set(MODULUS, 0))).toThrow("KEYPAIR_DISCLOSURE_FIELD");
  });

  it("reads a prefix at the modulus prefix and no zero prefix", () => {
    const top = prefix(bigIntToBytes(BN254_SCALAR_ORDER - 1n) as Bytes32);
    expect(top).toBe(BN254_SCALAR_ORDER >> 128n);
    expect(inputPrefix(MODULUS)).toBeUndefined();
    const short = new Uint8Array(32) as Bytes32;
    short[16] = 1;
    expect(inputPrefix(short)).toBeUndefined();
  });

  it("reads a record as a dummy only when every byte is zero and refuses a field off the modulus", () => {
    const disclosure = entry();
    const decode = (change: (records: readonly Uint8Array[]) => void) => () => {
      const plaintext = disclosurePlaintext(disclosure);
      change(plaintext.records);
      return decodeDisclosure(disclosure.layout, plaintext);
    };
    expect(decode(() => {})().outputs[2]).toEqual({ kind: "dummy" });
    expect(decode((records) => records[2]?.set([1], 5))().outputs[2]).toMatchObject({
      kind: "ring",
      nullifierPk: new Uint8Array(32),
    });
    expect(decode((records) => records[0]?.set(MODULUS, 32))).toThrow("KEYPAIR_DISCLOSURE_FIELD");
    expect(decode((records) => records[1]?.set(MODULUS, 40))).toThrow("KEYPAIR_DISCLOSURE_FIELD");
  });

  it("refuses an exit its layout does not flag and an evidence or record of another length", () => {
    const disclosure = entry();
    expect(() =>
      disclosurePlaintext({ ...disclosure, layout: { ...disclosure.layout, exits: 0n } }),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    const delivering = delivered();
    expect(() =>
      disclosurePlaintext({
        ...delivering,
        layout: { ...delivering.layout, exits: 0b1n },
      }),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    const plaintext = disclosurePlaintext(disclosure);
    expect(() =>
      decodeDisclosure(disclosure.layout, {
        evidence: plaintext.evidence.subarray(1),
        records: plaintext.records,
      }),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(() =>
      decodeDisclosure(disclosure.layout, {
        evidence: plaintext.evidence,
        records: plaintext.records.slice(1),
      }),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
  });
});

describe("auditor message", () => {
  const auditor = X25519Keypair.generate();

  it.each([
    ["delivered", delivered],
    ["the entry key", entry],
    ["the commitment key", commitments],
  ] as const)("seals and opens %s at the regions the layout fixes", (_, build) => {
    const disclosure = build();
    const sealed = sealRingDisclosure({
      txViewingSecret: TX_SECRET,
      auditorPublicKey: auditor.publicKey(),
      disclosure,
    });
    const { data, viewTag } = auditorMessageData(sealed, auditor.publicKey());
    expect(viewTag).toEqual(auditor.publicKey().u());
    const message = parseAuditorMessage(data, disclosure.layout);
    expect(message.envelope).toEqual(sealed.envelope);
    expect(message.records).toEqual(sealed.records);
    expect(openTransactionViewingSecret(auditor, message)).toEqual(TX_SECRET);
    expect(openRingDisclosure(auditor, { layout: disclosure.layout, message })).toEqual(disclosure);
    expect(() => parseAuditorMessage(data.subarray(1), disclosure.layout)).toThrow();
    expect(() => parseAuditorMessage(Uint8Array.of(...data, 0), disclosure.layout)).toThrow();
    sealed.ephemeralSecret.fill(0);
  });

  it("wipes the envelope and every record plaintext once sealed", () => {
    sealedPlaintexts.length = 0;
    const sealed = sealRingDisclosure({
      txViewingSecret: TX_SECRET,
      auditorPublicKey: auditor.publicKey(),
      disclosure: entry(),
    });
    expect(sealedPlaintexts.length).toBeGreaterThan(1);
    expect(sealedPlaintexts.filter((bytes) => bytes.some((byte) => byte !== 0))).toEqual([]);
    sealed.ephemeralSecret.fill(0);
  });

  it("keeps every region of one stream on its own keystream", () => {
    const disclosure = commitments();
    const { layout } = disclosure;
    const sealed = sealRingDisclosure({
      txViewingSecret: TX_SECRET,
      auditorPublicKey: auditor.publicKey(),
      disclosure,
    });
    const [zeros] = openAuditorRegions(auditor, sealed.ephemeralPublicKey, [
      { counter: 2, bytes: new Uint8Array(16 * 256) },
    ]);
    const keystream = zeros ?? new Uint8Array();
    const plaintext = disclosurePlaintext(disclosure);
    recordSlots(layout).forEach((slot, index) => {
      const offset = 16 * (recordRegion(layout, slot).startCounter - 2);
      const record = plaintext.records[index] ?? new Uint8Array();
      const expected = record.map((byte, at) => byte ^ (keystream[offset + at] ?? 0));
      expect(sealed.records[index]).toEqual(expected);
    });
    expect(recordRegion(layout, 0).startCounter).toBe(2 + envelopeRegion(layout).maxBlocks);
    sealed.ephemeralSecret.fill(0);
  });

  it("uses the one label of the auditor stream", () => {
    expect(new TextDecoder().decode(AUDIT_ENC_INFO)).toBe("CRING/adt1");
    expect(() =>
      symmetricAuditApply(TX_SECRET, { label: AUDIT_ENC_INFO, counter: 1 }, new Uint8Array(1)),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(() =>
      symmetricAuditApply(
        TX_SECRET,
        { label: AUDIT_ENC_INFO.subarray(1), counter: 2 },
        new Uint8Array(1),
      ),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
  });
});
