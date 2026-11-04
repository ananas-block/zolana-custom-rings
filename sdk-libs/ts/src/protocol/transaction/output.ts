/** Ring output bodies in SPP's output framing, Rust `custom_ring_interface::output`. */
import { TransactionError } from "@heliuslabs/zolana/transaction";

/** The schemes a ring output publishes, SPP stores the ring-owned ones unparsed. */
export const RingScheme = Object.freeze({
  confidential: 3,
  /** Read-only, frames before statement version 4. */
  ringConfidentialDelivered: 10,
  /** Read-only, frames before statement version 4. */
  ringRecipientBody: 11,
  ringSenderBundle: 12,
  /** `u16le(body_len) ‖ body ‖ reply`, one form on every rail. */
  ringBody: 13,
} as const);
export type RingScheme = (typeof RingScheme)[keyof typeof RingScheme];

/** `0x04 ‖ u`, the recipient key a scheme 3 body leads with. */
export const RECIPIENT_KEY_LEN = 33;
/** Asset id, amount and blinding open every confidential plaintext. */
const CONFIDENTIAL_PLAINTEXT_HEAD_LEN = 8 + 8 + 32;
/** Scheme 3 body of an output with no data and no ring id, each one zero byte. */
export const CONFIDENTIAL_DATA_FREE_BODY_LEN =
  RECIPIENT_KEY_LEN + CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 2;

/** `be32(blinding) ‖ u64be(amount) ‖ mint`. */
const RING_BODY_MIN_LEN = 72;

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

/** Scheme 13, Rust `encode_ring_body_output`. */
export function encodeRingBodyOutput(body: Uint8Array, reply: Uint8Array): Uint8Array {
  if (body.length > 0xffff)
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      field: "ringBody",
      expected: 0xffff,
      actual: body.length,
    });
  const payload = new Uint8Array(2 + body.length + reply.length);
  new DataView(payload.buffer).setUint16(0, body.length, true);
  payload.set(body, 2);
  payload.set(reply, 2 + body.length);
  return encodeRingOutput(RingScheme.ringBody, payload);
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

/** The body and reply of a scheme 13 output, `undefined` below the plain body's length, Rust `ring_body_output`. */
export function ringBodyOutput(
  data: Uint8Array,
): Readonly<{ body: Uint8Array; reply: Uint8Array }> | undefined {
  const payload = encryptedOutputBody(data, RingScheme.ringBody);
  if (payload === undefined || payload.length < 2) return undefined;
  const length = new DataView(payload.buffer, payload.byteOffset, 2).getUint16(0, true);
  const rest = payload.subarray(2);
  if (length < RING_BODY_MIN_LEN || length > rest.length) return undefined;
  return Object.freeze({ body: rest.subarray(0, length), reply: rest.subarray(length) });
}

/** The scheme 11 payload of a frame before statement version 4. */
export function historicalRecipientOutputBody(data: Uint8Array): Uint8Array | undefined {
  return encryptedOutputBody(data, RingScheme.ringRecipientBody);
}

export function senderBundleOutputBody(data: Uint8Array): Uint8Array | undefined {
  return encryptedOutputBody(data, RingScheme.ringSenderBundle);
}

function encryptedOutputBody(data: Uint8Array, scheme: RingScheme): Uint8Array | undefined {
  let frame: RingOutputFrame;
  try {
    frame = readRingOutput(data);
  } catch {
    return undefined;
  }
  return frame.encoding === "encrypted" && frame.scheme === scheme ? frame.body : undefined;
}

