/** Ring output bodies in SPP's output framing, Rust `custom_ring_interface::output`. */
import type { Bytes16, Bytes32 } from "@heliuslabs/zolana";
import {
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  decodeConfidential,
  encodeConfidential,
  splitEmbeddedKey,
  u64be,
  type ConfidentialOutputPlaintext,
} from "@heliuslabs/zolana/internal";
import type { ViewingKeyLike, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import { TransactionError, type Data } from "@heliuslabs/zolana/transaction";

import { symmetricAuditApply } from "../crypto/audit.js";
import { checkedCounter } from "../crypto/error.js";

/** The schemes a ring output publishes, 10 and 11 ring-owned, SPP stores both unparsed. */
export const RingScheme = Object.freeze({
  confidential: 3,
  ringAnonymous: 9,
  ringConfidentialDelivered: 10,
  /** The packed ring output without the ring id, its ring the transfer's. */
  ringConfidentialPacked: 11,
} as const);
export type RingScheme = (typeof RingScheme)[keyof typeof RingScheme];

/** `be32(blinding) ‖ u64be(amount)` under the audit stream, Rust `RING_DELIVERED_BODY_LEN`. */
export const RING_DELIVERED_BODY_LEN = 40;
/** `0x04 ‖ u`, the recipient key a scheme 3 or scheme 11 body leads with. */
export const RECIPIENT_KEY_LEN = 33;
/** Asset id, amount and blinding open every confidential plaintext. */
const CONFIDENTIAL_PLAINTEXT_HEAD_LEN = 8 + 8 + 32;
/** Scheme 3 body of an output with no data and no ring id, each one zero byte. */
export const CONFIDENTIAL_DATA_FREE_BODY_LEN =
  RECIPIENT_KEY_LEN + CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 2;
/** Scheme 11 body of an output with no data. */
export const RING_PACKED_DATA_FREE_BODY_LEN =
  RECIPIENT_KEY_LEN + CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 1;

const ENCODING_TAGS = ["plaintext", "encrypted", "verifiable"] as const;
export type RingOutputEncoding = (typeof ENCODING_TAGS)[number];

export interface RingOutputFrame {
  readonly encoding: RingOutputEncoding;
  readonly scheme: number;
  readonly body: Uint8Array;
}

/** `Encrypted(u32le(len) ‖ scheme ‖ payload)`, the length counting the scheme byte. */
export function encodeRingOutput(scheme: RingScheme, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + 4 + 1 + payload.length);
  out[0] = 1;
  new DataView(out.buffer).setUint32(1, 1 + payload.length, true);
  out[5] = scheme;
  out.set(payload, 6);
  return out;
}

/** Any scheme byte, the caller checks the scheme and the encoding it expects. */
export function readRingOutput(bytes: Uint8Array): RingOutputFrame {
  const encoding = ENCODING_TAGS[bytes[0] ?? -1];
  if (encoding === undefined || bytes.length < 6) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { field: "outputData" });
  }
  const length = new DataView(bytes.buffer, bytes.byteOffset + 1, 4).getUint32(0, true);
  if (length === 0 || length !== bytes.length - 5) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      field: "encryptedOutput",
      expected: bytes.length - 5,
      actual: length,
    });
  }
  return Object.freeze({ encoding, scheme: bytes[5] ?? 0, body: bytes.slice(6) });
}

/** What a scheme 9 or 10 body opens to, its asset matched against the published commitment. */
export interface DeliveredBodyOpening {
  readonly blinding: Bytes32;
  readonly amount: bigint;
}

/** AES-256-CTR of `be32(blinding) ‖ u64be(amount)` under the slot secret's audit stream. */
export function sealDeliveredBody(slotSecret: Bytes32, opening: DeliveredBodyOpening): Uint8Array {
  const plaintext = concatBytes(
    checkedBytes<Bytes32>(opening.blinding, 32, "blinding"),
    u64be(checkedCounter(opening.amount, "amount")),
  );
  try {
    return symmetricAuditApply(checkedBytes<Bytes32>(slotSecret, 32, "slot secret"), plaintext);
  } finally {
    plaintext.fill(0);
  }
}

/** The cipher is unauthenticated, only the rebuilt commitment tells a body of another key. */
export function openDeliveredBody(slotSecret: Bytes32, body: Uint8Array): DeliveredBodyOpening {
  const plaintext = symmetricAuditApply(
    checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
    checkedBytes(body, RING_DELIVERED_BODY_LEN, "delivered body"),
  );
  try {
    return Object.freeze({
      blinding: checkedBytes<Bytes32>(plaintext.subarray(0, 32), 32, "blinding"),
      amount: bytesToBigInt(plaintext.subarray(32)),
    });
  } finally {
    plaintext.fill(0);
  }
}

/** Rust `RingPackedPlaintext`, the plaintext of a scheme 11 slot, its ring the transfer's. */
export interface RingPackedPlaintext {
  readonly assetId: bigint;
  readonly amount: bigint;
  readonly blinding: ConfidentialOutputPlaintext["blinding"];
  readonly data: Data;
}

/** The confidential plaintext without its ring id option, whose absent byte sits after the head. */
export function encodeRingPacked(value: RingPackedPlaintext): Uint8Array {
  const confidential = encodeConfidential({
    assetId: value.assetId,
    amount: value.amount,
    blinding: value.blinding,
    data: value.data,
  });
  return new Uint8Array([
    ...confidential.subarray(0, CONFIDENTIAL_PLAINTEXT_HEAD_LEN),
    ...confidential.subarray(CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 1),
  ]);
}

export function decodeRingPacked(bytes: Uint8Array): RingPackedPlaintext {
  if (bytes.length < CONFIDENTIAL_PLAINTEXT_HEAD_LEN) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      expectedMinimum: CONFIDENTIAL_PLAINTEXT_HEAD_LEN,
      actual: bytes.length,
    });
  }
  const { assetId, amount, blinding, data } = decodeConfidential(
    new Uint8Array([
      ...bytes.subarray(0, CONFIDENTIAL_PLAINTEXT_HEAD_LEN),
      0,
      ...bytes.subarray(CONFIDENTIAL_PLAINTEXT_HEAD_LEN),
    ]),
  );
  return Object.freeze({ assetId, amount, blinding, data });
}

/** `recipient ‖ ciphertext` under the scheme 3 key schedule, Rust `RingPacked`. */
export function encryptRingPacked(
  tx: ViewingKeyLike,
  recipient: X25519PublicKey,
  value: RingPackedPlaintext,
  salt: Bytes16,
  slotIndex: number,
): Uint8Array {
  const ciphertext = inTransactionCategory(() =>
    tx.encryptSlot(recipient, encodeRingPacked(value), salt, slotIndex),
  );
  return new Uint8Array([...recipient.toBytes(), ...ciphertext]);
}

/** Rust `RingPacked::decrypt_with_tx_key`, the sender's opening under its transaction key. */
export function decryptRingPackedAsSender(
  tx: ViewingKeyLike,
  body: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
): RingPackedPlaintext {
  const { key, rest } = inTransactionCategory(() => splitEmbeddedKey(body));
  return decodeRingPacked(
    inTransactionCategory(() => tx.decryptSlotEphemeral(key, rest, salt, slotIndex)),
  );
}

function inTransactionCategory<T>(run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (error instanceof TransactionError) throw error;
    const code = (error as { code?: unknown }).code;
    throw new TransactionError(
      "TRANSACTION_KEYPAIR",
      typeof code === "string" ? { keypair: code } : {},
    );
  }
}
