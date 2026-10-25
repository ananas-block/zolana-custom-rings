import { describe, expect, it } from "vitest";

import secrets from "../../../../test-vectors/ring-secrets.json" with { type: "json" };
import tags from "../../../../test-vectors/ring-tags.json" with { type: "json" };
import {
  BN254_SCALAR_ORDER,
  hashBytes,
  solanaOwnerIdentity,
  bigIntToBytes,
  DOMAIN_PRIVATE_TX_BLINDING_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
} from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import {
  outputBlindingSeed,
  privateTxBlinding,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import { RingDomain, depositBlinding } from "../../src/crypto/ring-domain.js";
import { RING_DELIVERED_BODY_LEN } from "../../src/protocol/transaction/output.js";
import {
  EPOCH_SLOTS,
  J_INBOX,
  J_PAIR,
  K_PAIR_EPOCHS,
  TAG_LEN,
  deliveredSlotSecret,
  inboxKey,
  inboxTag,
  pairKey,
  pairTag,
  ringTag,
  senderCommitment,
  tagEpoch,
  tagIndex,
} from "../../src/crypto/ring-stream.js";
import {
  anonymousRingData,
  ringBlindingSeed,
  ringOutputBlinding,
} from "../../src/crypto/blinding.js";

/** The epoch ring-secrets.json tags its anonymous outputs in. */
const SECRETS_TAG_EPOCH = 6734n;

function bytes<T extends Uint8Array>(value: string, length: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function ascii(tag: string): number {
  return Buffer.from(tag, "ascii").readUInt32BE(0);
}

function ringId(): Bytes32 {
  return hashBytes(bytes<Bytes32>(tags.ring_program_id, 32)) as Bytes32;
}

describe("ring domains", () => {
  it("spells every domain from its ASCII tag, no two alike", () => {
    expect(RingDomain).toEqual({
      auditStatement: ascii("CRAU"),
      deliveredSlotSecret: ascii("CRDS"),
      blindingSeed: ascii("CRBS"),
      anonymousRingData: ascii("CRAT"),
      inboxKey: ascii("CRIK"),
      inboxTag: ascii("CRIT"),
      pairKey: ascii("CRPK"),
      pairTag: ascii("CRPT"),
      senderCommitment: ascii("CRSC"),
      disclosurePad: ascii("CROD"),
      policyStatement: ascii("CRPO"),
      policyTable: ascii("CRTB"),
      queueWrite: ascii("CRQW"),
      applyRecords: ascii("CRAP"),
      registerKey: ascii("CRRG"),
      depositBlinding: ascii("CRDB"),
    });
    const values = [
      ...Object.values(RingDomain),
      DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
      DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
      DOMAIN_PRIVATE_TX_BLINDING_V1,
    ];
    expect(new Set(values).size).toBe(values.length);
  });
});

describe("ring-tags.json", () => {
  it("pins the stream constants", () => {
    expect({
      epoch_slots: Number(EPOCH_SLOTS),
      j_inbox: J_INBOX,
      j_pair: J_PAIR,
      k_pair_epochs: Number(K_PAIR_EPOCHS),
      tag_len: TAG_LEN,
      body_len: RING_DELIVERED_BODY_LEN,
    }).toEqual(tags.constants);
  });

  it("derives the inbox and pair streams", () => {
    expect(hex(ringId())).toBe(tags.ring_id);
    const inbox = inboxKey(
      ringId(),
      X25519PublicKey.fromBytes(bytes<Bytes33>(tags.viewing_pk, 33)),
    );
    expect(hex(inbox)).toBe(tags.inbox_key);
    for (const entry of tags.inbox_tags)
      expect(hex(inboxTag(inbox, BigInt(entry.epoch), tagIndex(entry.index)))).toBe(entry.tag);
    const pair = pairKey(bytes<Bytes32>(tags.first_contact_secret, 32));
    expect(hex(pair)).toBe(tags.pair_key);
    for (const entry of tags.pair_tags)
      expect(hex(pairTag(pair, BigInt(entry.epoch), tagIndex(entry.index)))).toBe(entry.tag);
  });

  it("takes low128 of canonical fields and maps slots to epochs", () => {
    for (const entry of tags.low128)
      expect(hex(ringTag(bytes<Bytes32>(entry.value, 32)))).toBe(entry.tag);
    for (const entry of tags.epochs) expect(tagEpoch(BigInt(entry.slot))).toBe(BigInt(entry.epoch));
  });

  it("refuses an index past the stream and a field at the modulus", () => {
    expect(() => tagIndex(J_INBOX)).toThrow("KEYPAIR_TAG_INDEX_OUT_OF_RANGE");
    expect(() => ringTag(bigIntToBytes(BN254_SCALAR_ORDER) as Bytes32)).toThrow(
      "KEYPAIR_NONCANONICAL_FIELD",
    );
  });
});

describe("ring-secrets.json", () => {
  const txSecret = bytes<Bytes32>(secrets.tx_viewing_secret, 32);
  const txViewingKey = X25519PublicKey.fromBytes(bytes<Bytes33>(secrets.tx_viewing_pk, 33));
  const recipientViewingKey = X25519PublicKey.fromBytes(
    bytes<Bytes33>(secrets.recipient_viewing_pk, 33),
  );
  const salt = bytes<Bytes16>(secrets.salt, 16);
  const firstNullifier = bytes<Bytes32>(secrets.first_nullifier, 32);

  it("reaches one agreement from the sender and the recipient", () => {
    const sender = X25519Keypair.fromBytes(txSecret);
    const recipient = X25519Keypair.fromBytes(bytes<Bytes32>(secrets.recipient_viewing_secret, 32));
    try {
      expect(sender.publicKey().equals(txViewingKey)).toBe(true);
      expect(recipient.publicKey().equals(recipientViewingKey)).toBe(true);
      expect(hex(sender.ecdh(recipientViewingKey))).toBe(secrets.agreement);
      expect(hex(recipient.ecdh(txViewingKey))).toBe(secrets.agreement);
    } finally {
      sender.destroy();
      recipient.destroy();
    }
  });

  it("derives the blinding seed, every slot secret, ring data and output blinding", () => {
    const blindingSeed = ringBlindingSeed(txSecret, salt);
    expect(hex(blindingSeed)).toBe(secrets.blinding_seed);
    expect(hex(outputBlindingSeed(firstNullifier, blindingSeed))).toBe(
      secrets.output_blinding_seed,
    );
    const inbox = inboxKey(ringId(), recipientViewingKey);
    for (const output of secrets.outputs) {
      const outputIndex = output.output_index;
      const delivered = deliveredSlotSecret({
        agreement: bytes<Bytes32>(secrets.agreement, 32),
        txViewingKey,
        recipientViewingKey,
        salt,
        outputIndex,
        firstNullifier,
      });
      expect(hex(delivered)).toBe(output.delivered_slot_secret);
      const tag = inboxTag(inbox, SECRETS_TAG_EPOCH, tagIndex(outputIndex));
      expect(hex(tag)).toBe(output.tag);
      expect(hex(anonymousRingData(delivered, tag))).toBe(output.anonymous_ring_data);
      expect(hex(ringOutputBlinding({ firstNullifier, blindingSeed, outputIndex }))).toBe(
        output.blinding,
      );
    }
    expect(hex(depositBlinding(bytes<Bytes32>(secrets.deposit_blinding_secret, 32)))).toBe(
      secrets.deposit_blinding,
    );
  });

  it("commits the hidden sender of the same transaction", () => {
    const senderPkHash = solanaOwnerIdentity(bytes<Bytes32>(secrets.sender_key, 32)) as Bytes32;
    expect(hex(senderPkHash)).toBe(secrets.sender_pk_hash);
    const blinding = privateTxBlinding(firstNullifier, bytes<Bytes32>(secrets.blinding_seed, 32));
    expect(hex(blinding)).toBe(secrets.private_tx_blinding);
    expect(hex(senderCommitment({ senderPkHash, privateTxBlinding: blinding }))).toBe(
      secrets.sender_commitment,
    );
  });
});
