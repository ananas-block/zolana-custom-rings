import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import type { Bytes16, Bytes32, Signature } from "@heliuslabs/zolana/interface";
import { bytesToBigInt } from "@heliuslabs/zolana/internal";
import { X25519Keypair } from "@heliuslabs/zolana/keypair";

import {
  mergeDisclosureFieldCount,
  openRingMergeDisclosure,
  sealRingMergeDisclosure,
  type RingMergeDisclosure,
} from "../../src/protocol/historical/v3/merge-disclosure.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../src/protocol/proof/custom-ring-proof.js";
import { MergeLedger, realMergeInputs, type ConfirmedMerge } from "../../src/state/merge-ledger.js";

const SALT = new Uint8Array(16).fill(3) as Bytes16;
const field = (byte: number): Bytes32 => {
  const value = new Uint8Array(32);
  value[31] = byte;
  return value as Bytes32;
};
const ZERO = field(0);
const FIRST = field(7);
const SECOND = field(8);
const KNOWN = new Map([FIRST, SECOND].map((hash) => [bytesToBigInt(hash), hash] as const));

function sealed(auditor: X25519Keypair): RingMergeDisclosure {
  const list = [FIRST, SECOND, ...Array.from({ length: 6 }, () => ZERO)];
  const { disclosure } = sealRingMergeDisclosure(list, SALT, auditor.publicKey());
  return { ...disclosure, proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH) };
}

/** The ledger over a list the disclosure opened, only a list of known notes resolves. */
function ledgerOutputs(list: readonly Bytes32[]): number {
  const merge: ConfirmedMerge = {
    slot: 1n,
    signature: "tamper" as Signature,
    eventIndex: 0,
    outputCommitment: field(40),
    treeId: 0,
    leafIndex: 0n,
    firstNullifier: field(41),
    ringDataHash: new Uint8Array(32) as Bytes32,
    inputs: realMergeInputs(list, 2),
  };
  const transition = new MergeLedger().apply(merge, (commitment) =>
    KNOWN.has(bytesToBigInt(commitment))
      ? {
          ownerKey: field(50),
          owner: { kind: "deposited", ownerHash: field(51) },
          asset: field(52),
          amount: 5n,
        }
      : undefined,
  );
  return transition.resolved.length;
}

describe("a merge disclosure tampered after its proof", () => {
  beforeAll(initializePoseidon);

  it("resolves an untampered list", () => {
    const auditor = X25519Keypair.generate();
    expect(ledgerOutputs(openRingMergeDisclosure(auditor, sealed(auditor), SALT))).toBe(1);
  });

  it("reads no known note from a tampered entry", () => {
    const auditor = X25519Keypair.generate();
    const disclosure = sealed(auditor);
    const fields = [...disclosure.fields];
    const tampered = (fields[0] as Bytes32).slice() as Bytes32;
    tampered[31] = (tampered[31] ?? 0) ^ 1;
    fields[0] = tampered;
    const opened = () => openRingMergeDisclosure(auditor, { ...disclosure, fields }, SALT);
    // The pad leaves a flipped byte in the list, the entry is another hash or out of the field.
    let outputs = 0;
    try {
      const list = opened();
      expect(list[0]).not.toEqual(FIRST);
      outputs = ledgerOutputs(list);
    } catch (error) {
      expect((error as { code?: string }).code).toMatch(
        /^(RING_AUDIT_MESSAGE|KEYPAIR_DISCLOSURE_)/u,
      );
    }
    expect(outputs).toBe(0);
  });

  it("refuses a field list off every key's width", () => {
    const auditor = X25519Keypair.generate();
    const disclosure = sealed(auditor);
    expect(disclosure.fields.length).toBe(mergeDisclosureFieldCount(8));
    const short = { ...disclosure, fields: disclosure.fields.slice(1) };
    expect(() => openRingMergeDisclosure(auditor, short, SALT)).toThrow();
  });

  it("refuses an entry past the published count and a dummy at slot 0", () => {
    expect(() => realMergeInputs([FIRST, SECOND, FIRST, ZERO], 2)).toThrow();
    expect(() => realMergeInputs([ZERO, SECOND, ZERO, ZERO], 2)).toThrow();
    expect(realMergeInputs([FIRST, ZERO, ZERO, ZERO], 2)).toEqual([FIRST]);
  });

  it("reads no known note from swapped fields, each pad binds its position", () => {
    const auditor = X25519Keypair.generate();
    const disclosure = sealed(auditor);
    const fields = [...disclosure.fields];
    const [first, second] = fields as [Bytes32, Bytes32];
    fields[0] = second;
    fields[1] = first;
    let outputs = 0;
    try {
      const list = openRingMergeDisclosure(auditor, { ...disclosure, fields }, SALT);
      expect(list.slice(0, 2)).not.toEqual([SECOND, FIRST]);
      outputs = ledgerOutputs(list);
    } catch (error) {
      expect((error as { code?: string }).code).toMatch(
        /^(RING_AUDIT_MESSAGE|KEYPAIR_DISCLOSURE_)/u,
      );
    }
    expect(outputs).toBe(0);
  });
});
