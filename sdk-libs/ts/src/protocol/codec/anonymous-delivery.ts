/** Rust `custom_ring_interface::audit_stream` bodies and `zolana_ring_transaction::recipient_delivery`. */
import {
  addressBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  encodeBase58,
  encodeData,
  Reader,
  readData,
  u64be,
} from "@heliuslabs/zolana/internal";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { Data } from "@heliuslabs/zolana/transaction";

import {
  RECIPIENT_BODY_ENC_INFO,
  REPLY_ENC_INFO,
  SENDER_BUNDLE_ENC_INFO,
  symmetricAuditApply,
} from "../../crypto/audit/audit.js";
import { checkedCounter } from "../../crypto/error.js";
import { x25519FromU } from "../../crypto/keys/x25519.js";
import { checkedViewingU } from "../membership/member-opening.js";
const STREAM_FIRST_COUNTER = 2;
import { RingError } from "../error.js";

const FIELD_LEN = 32;
const AMOUNT_LEN = 8;
/** `be32(blinding) ‖ u64be(amount) ‖ mint`. */
export const RECIPIENT_BODY_LEN = FIELD_LEN + AMOUNT_LEN + FIELD_LEN;
/** `viewing_u ‖ owner_key ‖ nullifier_pk`, the reply's fields ahead of its data. */
const REPLY_HEAD_LEN = 3 * FIELD_LEN;
/** A reply holding empty data. */
export const MIN_REPLY_LEN = REPLY_HEAD_LEN + 1;
/** `mint0 ‖ u64be(amount0) ‖ u64be(amount1) ‖ output_seed`, ahead of one key per slot. */
const SENDER_BUNDLE_HEAD_LEN = FIELD_LEN + 2 * AMOUNT_LEN + FIELD_LEN;

/** The length follows the published slots alone. */
export function senderBundleLen(outputs: number): number {
  return SENDER_BUNDLE_HEAD_LEN + FIELD_LEN * outputs;
}

/** A ring body plaintext, the recipient rebuilds the commitment with its own bound keys, Rust `RecipientBody`. */
export interface RecipientBody {
  readonly blinding: Bytes32;
  readonly amount: bigint;
  readonly mint: Address;
  /** The commitment covers it, a nonzero value travels with the note. */
  readonly ringDataHash?: Bytes32;
  /** The `data_hash` then the application data under it, empty on a plain note. */
  readonly data?: Uint8Array;
}

/** Semantics unproved, the statement binds only its presence, length and bytes. */
export interface ReplyMetadata {
  readonly viewingKey: X25519PublicKey;
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly data: Data;
}

/** A decrypted reply, an unverified sender claim no authorization reads, Rust `ReplyClaim`. */
export interface ReplyClaim {
  readonly claimed: ReplyMetadata;
}

/** What the sender bundle opens to, the sender rebuilds its change from it. */
export interface SenderBundle {
  /** Slot 0's mint under `change_bits` bit 0, else the zero address. */
  readonly mint: Address;
  /** Slot 0's amount under `change_bits` bit 0, else zero. */
  readonly amount: bigint;
  /** Slot 1's SOL amount under `change_bits` bit 1, else zero. */
  readonly solAmount: bigint;
  readonly outputSeed: Bytes32;
  /** One per published slot, zero on change, exit and dummy. */
  readonly recipientKeys: readonly Bytes32[];
}

/** A plain note is exactly the head, an extended one follows it with one presence byte. */
export function encodeRecipientBody(body: RecipientBody): Uint8Array {
  const { ringDataHash, data = new Uint8Array() } = body;
  const head = concatBytes(
    checkedBytes<Bytes32>(body.blinding, FIELD_LEN, "blinding"),
    u64be(checkedCounter(body.amount, "amount")),
    addressBytes(body.mint, "mint"),
  );
  if (ringDataHash === undefined && data.length === 0) return head;
  return concatBytes(
    head,
    Uint8Array.of(ringDataHash === undefined ? 0 : 1),
    ...(ringDataHash === undefined
      ? []
      : [checkedBytes<Bytes32>(ringDataHash, FIELD_LEN, "ring data hash")]),
    data,
  );
}

/** Refuses a short head and a presence byte off its two values. */
export function decodeRecipientBody(plaintext: Uint8Array): RecipientBody {
  if (plaintext.length < RECIPIENT_BODY_LEN) throw bodyInvalid("length");
  const head = {
    blinding: plaintext.slice(0, FIELD_LEN) as Bytes32,
    amount: bytesToBigInt(plaintext.subarray(FIELD_LEN, FIELD_LEN + AMOUNT_LEN)),
    mint: encodeBase58(plaintext.subarray(FIELD_LEN + AMOUNT_LEN, RECIPIENT_BODY_LEN)),
  };
  if (plaintext.length === RECIPIENT_BODY_LEN) return Object.freeze(head);
  const presence = plaintext[RECIPIENT_BODY_LEN];
  const rest = plaintext.subarray(RECIPIENT_BODY_LEN + 1);
  if (presence === 0) return Object.freeze({ ...head, data: rest.slice() });
  if (presence !== 1 || rest.length < FIELD_LEN) throw bodyInvalid("presence");
  return Object.freeze({
    ...head,
    ringDataHash: rest.slice(0, FIELD_LEN) as Bytes32,
    data: rest.slice(FIELD_LEN),
  });
}

export function sealRecipientBody(slotSecret: Bytes32, body: RecipientBody): Uint8Array {
  return seal(slotSecret, RECIPIENT_BODY_ENC_INFO, () => encodeRecipientBody(body));
}

/** The cipher is unauthenticated, only the commitment a reader rebuilds proves ownership. */
export function openRecipientBody(slotSecret: Bytes32, body: Uint8Array): RecipientBody {
  return open(slotSecret, RECIPIENT_BODY_ENC_INFO, body, body.length, decodeRecipientBody);
}

/** The longest reply `replies` encode to, every body of a frame shares one length. */
export function replyLength(replies: readonly ReplyMetadata[]): number {
  return replies.reduce(
    (longest, reply) => Math.max(longest, REPLY_HEAD_LEN + encodeData(reply.data).length),
    MIN_REPLY_LEN,
  );
}

/** Its own label gives the reply its own key and nonce, the body's counter never restarts. */
export function sealReply(slotSecret: Bytes32, reply: ReplyMetadata, length: number): Uint8Array {
  const data = encodeData(reply.data);
  if (length < REPLY_HEAD_LEN + data.length) throw replyInvalid("length");
  return seal(slotSecret, REPLY_ENC_INFO, () => {
    const plaintext = new Uint8Array(length);
    plaintext.set(reply.viewingKey.u(), 0);
    plaintext.set(checkedBytes<Bytes32>(reply.ownerKey, FIELD_LEN, "ownerKey"), FIELD_LEN);
    plaintext.set(
      checkedBytes<Bytes32>(reply.nullifierPk, FIELD_LEN, "nullifierPk"),
      2 * FIELD_LEN,
    );
    plaintext.set(data, REPLY_HEAD_LEN);
    return plaintext;
  });
}

/** The proof binds the bytes alone, `undefined` on a reply that never decodes. */
export function openReply(slotSecret: Bytes32, ciphertext: Uint8Array): ReplyClaim | undefined {
  if (ciphertext.length < MIN_REPLY_LEN) return undefined;
  return open(slotSecret, REPLY_ENC_INFO, ciphertext, ciphertext.length, (plaintext) => {
    const data = readReplyData(plaintext.subarray(REPLY_HEAD_LEN));
    const viewingKey = replyKey(plaintext.slice(0, FIELD_LEN) as Bytes32);
    if (data === undefined || viewingKey === undefined) return undefined;
    return Object.freeze({
      claimed: Object.freeze({
        viewingKey,
        ownerKey: plaintext.slice(FIELD_LEN, 2 * FIELD_LEN) as Bytes32,
        nullifierPk: plaintext.slice(2 * FIELD_LEN, REPLY_HEAD_LEN) as Bytes32,
        data,
      }),
    });
  });
}

export function sealSenderBundle(slotSecret: Bytes32, bundle: SenderBundle): Uint8Array {
  return seal(slotSecret, SENDER_BUNDLE_ENC_INFO, () =>
    concatBytes(
      addressBytes(bundle.mint, "mint"),
      u64be(checkedCounter(bundle.amount, "amount")),
      u64be(checkedCounter(bundle.solAmount, "solAmount")),
      checkedBytes<Bytes32>(bundle.outputSeed, FIELD_LEN, "outputSeed"),
      ...bundle.recipientKeys.map((key) => checkedBytes<Bytes32>(key, FIELD_LEN, "recipientKey")),
    ),
  );
}

/** `publishedOutputs` is the frame's `m`, the secret's index, past every body's index. */
export function openSenderBundle(
  slotSecret: Bytes32,
  ciphertext: Uint8Array,
  publishedOutputs: number,
): SenderBundle {
  return open(
    slotSecret,
    SENDER_BUNDLE_ENC_INFO,
    ciphertext,
    senderBundleLen(publishedOutputs),
    (plaintext) => {
      const seedAt = FIELD_LEN + 2 * AMOUNT_LEN;
      const keysAt = seedAt + FIELD_LEN;
      return Object.freeze({
        mint: encodeBase58(plaintext.subarray(0, FIELD_LEN)),
        amount: bytesToBigInt(plaintext.subarray(FIELD_LEN, FIELD_LEN + AMOUNT_LEN)),
        solAmount: bytesToBigInt(plaintext.subarray(FIELD_LEN + AMOUNT_LEN, seedAt)),
        outputSeed: plaintext.slice(seedAt, keysAt) as Bytes32,
        recipientKeys: Object.freeze(
          Array.from(
            { length: publishedOutputs },
            (_, slot) =>
              plaintext.slice(
                keysAt + FIELD_LEN * slot,
                keysAt + FIELD_LEN * (slot + 1),
              ) as Bytes32,
          ),
        ),
      });
    },
  );
}

/** One data field then zero padding, `undefined` on any other bytes. */
function readReplyData(bytes: Uint8Array): Data | undefined {
  try {
    const data = readData(new Reader(bytes), "reply.data");
    return bytes.subarray(encodeData(data).length).every((byte) => byte === 0) ? data : undefined;
  } catch {
    return undefined;
  }
}

/** A zero or noncanonical key makes the claim malformed, unauthenticated as it stays. */
function replyKey(u: Bytes32): X25519PublicKey | undefined {
  try {
    return x25519FromU(checkedViewingU(u));
  } catch {
    return undefined;
  }
}

function seal(secret: Bytes32, label: Uint8Array, plaintext: () => Uint8Array): Uint8Array {
  const bytes = plaintext();
  try {
    return symmetricAuditApply(
      checkedBytes<Bytes32>(secret, FIELD_LEN, "slot secret"),
      position(label),
      bytes,
    );
  } finally {
    bytes.fill(0);
  }
}

function open<T>(
  secret: Bytes32,
  label: Uint8Array,
  ciphertext: Uint8Array,
  length: number,
  read: (plaintext: Uint8Array) => T,
): T {
  const plaintext = symmetricAuditApply(
    checkedBytes<Bytes32>(secret, FIELD_LEN, "slot secret"),
    position(label),
    checkedBytes(ciphertext, length, "ciphertext"),
  );
  try {
    return read(plaintext);
  } finally {
    plaintext.fill(0);
  }
}

function position(label: Uint8Array) {
  return Object.freeze({ label, counter: STREAM_FIRST_COUNTER });
}

function bodyInvalid(reason: string): RingError {
  return new RingError("RING_TRANSACT_DATA_INVALID", {
    details: { reason: "RingTransactLength", name: reason },
  });
}

function replyInvalid(reason: string): RingError {
  return new RingError("RING_REPLY_INVALID", { details: { reason } });
}
