import { ctr } from "@noble/ciphers/aes.js";

import {
  fieldAdd,
  fieldSub,
  isCanonicalField,
  bigIntToBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  copyBytes,
  u32be,
} from "@heliuslabs/zolana/internal";
import type { MessageData } from "@heliuslabs/zolana/interface";
import {
  type Bytes16,
  type Bytes32,
  poseidon,
  X25519Keypair,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import {
  DISCLOSURE_CHUNK_BYTES,
  ENVELOPE_KEY_LEN,
  STREAM_FIRST_COUNTER,
  TAGGED_KEY_LEN,
  auditorMessageLen,
  envelopeRegion,
  recordLen,
  recordSlots,
  type AuditStreamLayout,
} from "../../protocol/codec/ring-disclosure-layout.js";
import { packBytesBe } from "../derivation/hasher.js";

import { RingKeyError } from "../error.js";

/** Schedule labels, one secret under two labels gives two unrelated keys. */
export const AUDIT_ENC_INFO = new TextEncoder().encode("CRING/adt1");
export const DELIVERED_BODY_ENC_INFO = new TextEncoder().encode("CRING/bdy1");
export const NF_KEY_ENC_INFO = new TextEncoder().encode("CRING/nfk1");
export const DEPOSIT_ENC_INFO = new TextEncoder().encode("CRING/dep1");
export const RECIPIENT_BODY_ENC_INFO = new TextEncoder().encode("CRING/rcp1");
export const REPLY_ENC_INFO = new TextEncoder().encode("CRING/rpl1");
export const SENDER_BUNDLE_ENC_INFO = new TextEncoder().encode("CRING/snd1");

/** `"CR_S"`, Rust `DOM_SEP_CR_SHARED`. */
const DOM_SEP_CR_SHARED = 0x4352_5f53;
/** `"CR_MD"`, Go `MergeDisclosureDomain`, a merge pad never repeats another pad. */
const MERGE_DISCLOSURE_DOMAIN = 0x4352_5f4d44n;
const STREAM_LABEL_BYTES = 10;
const U32_MAX = 0xffff_ffff;

export interface StreamPosition {
  readonly label: Uint8Array;
  /** The first block's counter, a counter that serves two plaintexts reveals their XOR. */
  readonly counter: number;
}

export interface AuditorRegion {
  readonly counter: number;
  readonly bytes: Uint8Array;
}

/** The sealed stream of one transfer, `ephemeralSecret` the proof's input. */
export interface AuditorEnvelope {
  readonly ephemeralSecret: Bytes32;
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly envelope: Uint8Array;
  readonly records: readonly Uint8Array[];
}

/** The one message a ring transfer publishes under the auditor's view tag. */
export interface AuditorMessage {
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly envelope: Uint8Array;
  /** The records of the slots that have one, in slot order. */
  readonly records: readonly Uint8Array[];
}

/** One label and secret fix one schedule, each region applies it at its own counter. */
export class AuditSchedule {
  readonly #key: Uint8Array;
  readonly #nonce: Uint8Array;

  private constructor(key: Uint8Array, nonce: Uint8Array) {
    this.#key = key;
    this.#nonce = nonce;
  }

  /** Two Poseidon outputs supply 31 key bytes, then one key byte and a 12-byte nonce. */
  static derive(secret: Bytes32, label: Uint8Array): AuditSchedule {
    checkLabel(label);
    const tag = new Uint8Array(STREAM_LABEL_BYTES + 1);
    tag.set(label);
    let head: Uint8Array | undefined;
    let tail: Uint8Array | undefined;
    try {
      head = poseidon([rightAlign(tag), secret]);
      tag[STREAM_LABEL_BYTES] = 1;
      tail = poseidon([rightAlign(tag), secret]);
      const key = new Uint8Array(32);
      key.set(head.subarray(1), 0);
      key[31] = tail[19] ?? 0;
      return new AuditSchedule(key, tail.slice(20));
    } finally {
      tag.fill(0);
      head?.fill(0);
      tail?.fill(0);
    }
  }

  apply(firstCounter: number, data: Uint8Array): Uint8Array {
    checkCounter(firstCounter);
    const counter = new Uint8Array(16);
    try {
      counter.set(this.#nonce, 0);
      counter.set(u32be(firstCounter), 12);
      return ctr(this.#key, counter).encrypt(copyBytes(data));
    } finally {
      counter.fill(0);
    }
  }

  destroy(): void {
    this.#key.fill(0);
    this.#nonce.fill(0);
  }
}

export function symmetricAuditApply(
  secret: Bytes32,
  position: StreamPosition,
  data: Uint8Array,
): Uint8Array {
  checkLabel(position.label);
  checkCounter(position.counter);
  const schedule = AuditSchedule.derive(secret, position.label);
  try {
    return schedule.apply(position.counter, data);
  } finally {
    schedule.destroy();
  }
}

/** Binds the ECDH x-coordinate to both public keys, one shared point serves one key pair. */
export function auditSharedSecret(
  dh: Bytes32,
  ephemeralPublicKey: X25519PublicKey,
  auditorPublicKey: X25519PublicKey,
): Bytes32 {
  const packedDh = packBytesBe(checkedBytes<Bytes32>(dh, 32, "shared secret"));
  try {
    return poseidon([
      rightAlign(u32be(DOM_SEP_CR_SHARED)),
      ...packedDh,
      ...packBytesBe(ephemeralPublicKey.toBytes()),
      ...packBytesBe(auditorPublicKey.toBytes()),
    ]) as Bytes32;
  } finally {
    for (const field of packedDh) field.fill(0);
  }
}

/** A fresh ephemeral key per call, a reused one repeats the keystream over another plaintext. */
export function sealAuditorStream(
  input: Readonly<{
    auditorPublicKey: X25519PublicKey;
    envelope: Uint8Array;
    records: readonly AuditorRegion[];
  }>,
): AuditorEnvelope {
  const { auditorPublicKey } = input;
  const ephemeral = X25519Keypair.generate();
  let shared: Bytes32 | undefined;
  let schedule: AuditSchedule | undefined;
  try {
    const ephemeralPublicKey = ephemeral.publicKey();
    shared = envelopeSecret(ephemeral, auditorPublicKey, ephemeralPublicKey, auditorPublicKey);
    const stream = (schedule = AuditSchedule.derive(shared, AUDIT_ENC_INFO));
    const envelope = stream.apply(STREAM_FIRST_COUNTER, input.envelope);
    const records = Object.freeze(
      input.records.map(({ counter, bytes }) => stream.apply(counter, bytes)),
    );
    return Object.freeze({
      ephemeralSecret: ephemeral.secretBytes(),
      ephemeralPublicKey,
      envelope,
      records,
    });
  } finally {
    ephemeral.destroy();
    shared?.fill(0);
    schedule?.destroy();
  }
}

/** The schedule `sealAuditorStream` encrypted under, the caller destroys it. */
export function auditorSchedule(
  auditor: X25519Keypair,
  ephemeralPublicKey: X25519PublicKey,
): AuditSchedule {
  const shared = envelopeSecret(
    auditor,
    ephemeralPublicKey,
    ephemeralPublicKey,
    auditor.publicKey(),
  );
  try {
    return AuditSchedule.derive(shared, AUDIT_ENC_INFO);
  } finally {
    shared.fill(0);
  }
}

/** The auditor's side of `sealAuditorStream`, one plaintext per region. */
export function openAuditorRegions(
  auditor: X25519Keypair,
  ephemeralPublicKey: X25519PublicKey,
  regions: readonly AuditorRegion[],
): readonly Uint8Array[] {
  const schedule = auditorSchedule(auditor, ephemeralPublicKey);
  try {
    return regions.map(({ counter, bytes }) => schedule.apply(counter, bytes));
  } finally {
    schedule.destroy();
  }
}

/** The envelope's leading bytes, the evidence behind them opens with the transfer's layout. */
export function openTransactionViewingSecret(
  auditor: X25519Keypair,
  message: Pick<AuditorMessage, "ephemeralPublicKey" | "envelope">,
): Bytes32 {
  const bytes = message.envelope.subarray(0, ENVELOPE_KEY_LEN);
  if (bytes.length !== ENVELOPE_KEY_LEN)
    throw new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name: "envelope" });
  const [secret] = openAuditorRegions(auditor, message.ephemeralPublicKey, [
    { counter: STREAM_FIRST_COUNTER, bytes },
  ]);
  return secret as Bytes32;
}

export function auditorViewTag(auditorPublicKey: X25519PublicKey): Bytes32 {
  return auditorPublicKey.u();
}

/** `0x04 ‖ eph_u ‖ envelope_ct ‖ record_ct...` under the auditor's view tag. */
export function auditorMessageData(
  message: AuditorMessage,
  auditorPublicKey: X25519PublicKey,
): MessageData {
  return Object.freeze({
    viewTag: auditorViewTag(auditorPublicKey),
    data: concatBytes(message.ephemeralPublicKey.toBytes(), message.envelope, ...message.records),
  });
}

/** The layout fixes every length, a message of any other length is refused. */
export function parseAuditorMessage(data: Uint8Array, layout: AuditStreamLayout): AuditorMessage {
  const bytes = checkedBytes(data, auditorMessageLen(layout), "auditor message");
  const envelopeEnd = TAGGED_KEY_LEN + envelopeRegion(layout).length;
  let offset = envelopeEnd;
  const records = recordSlots(layout).map((slot) => {
    const start = offset;
    offset += recordLen(layout, slot);
    return bytes.subarray(start, offset);
  });
  return Object.freeze({
    ephemeralPublicKey: X25519PublicKey.fromBytes(bytes.subarray(0, TAGGED_KEY_LEN)),
    envelope: bytes.subarray(TAGGED_KEY_LEN, envelopeEnd),
    records: Object.freeze(records),
  });
}

/** Rust `pack_disclosure`, a short last chunk is zero padded at its end. */
export function packDisclosure(plaintext: Uint8Array): readonly Bytes32[] {
  return Array.from(
    { length: Math.ceil(plaintext.length / DISCLOSURE_CHUNK_BYTES) },
    (_, index) => {
      const field = new Uint8Array(32);
      const start = index * DISCLOSURE_CHUNK_BYTES;
      field.set(plaintext.subarray(start, start + DISCLOSURE_CHUNK_BYTES), 1);
      return field as Bytes32;
    },
  );
}

/** Rust `unpack_disclosure`, a field with bytes outside its chunk is refused. */
export function unpackDisclosure(fields: readonly Bytes32[], length: number): Uint8Array {
  if (fields.length !== Math.ceil(length / DISCLOSURE_CHUNK_BYTES))
    throw new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { expected: length, actual: fields.length });
  const plaintext = new Uint8Array(length);
  fields.forEach((field, index) => {
    const chunk = Math.min(length - index * DISCLOSURE_CHUNK_BYTES, DISCLOSURE_CHUNK_BYTES);
    if (field[0] !== 0 || field.subarray(1 + chunk).some((byte) => byte !== 0))
      throw new RingKeyError("KEYPAIR_DISCLOSURE_PADDING", { index });
    plaintext.set(field.subarray(1, 1 + chunk), index * DISCLOSURE_CHUNK_BYTES);
  });
  return plaintext;
}

/** Masks a merge disclosure plaintext already zero padded to whole chunks, Rust `MergeDisclosureEncryption::seal`. */
export function sealMergeDisclosureFields(
  key: Bytes32,
  salt: Bytes16,
  plaintext: Uint8Array,
): readonly Bytes32[] {
  if (plaintext.length % DISCLOSURE_CHUNK_BYTES !== 0)
    throw new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name: "merge" });
  const chunks = packDisclosure(plaintext);
  try {
    return applyDisclosurePad(key, salt, chunks, true, MERGE_DISCLOSURE_DOMAIN);
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

/** Unmasks an anonymous merge disclosure, the plaintext zero padded to whole chunks, Rust `open_merge_disclosure`. */
export function openMergeDisclosureFields(
  key: Bytes32,
  salt: Bytes16,
  fields: readonly Bytes32[],
): Uint8Array {
  const chunks = applyDisclosurePad(key, salt, fields, false, MERGE_DISCLOSURE_DOMAIN);
  return unpackDisclosure(chunks, chunks.length * DISCLOSURE_CHUNK_BYTES);
}

function checkLabel(label: Uint8Array): void {
  if (label.length !== STREAM_LABEL_BYTES)
    throw new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name: "label" });
}

function checkCounter(counter: number): void {
  if (!Number.isInteger(counter) || counter < STREAM_FIRST_COUNTER || counter > U32_MAX)
    throw new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name: "counter" });
}

function envelopeSecret(
  local: X25519Keypair,
  remote: X25519PublicKey,
  ephemeralPublicKey: X25519PublicKey,
  auditorPublicKey: X25519PublicKey,
): Bytes32 {
  const dh = local.ecdh(remote);
  try {
    return auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
  } finally {
    dh.fill(0);
  }
}

/** Masks (`seal`) or unmasks the published values with the keystream at their positions. */
function applyDisclosurePad(
  secret: Bytes32,
  salt: Bytes16,
  values: readonly Bytes32[],
  seal: boolean,
  domain: bigint,
): readonly Bytes32[] {
  values.forEach((value, index) => {
    if (!isCanonicalField(value))
      throw new RingKeyError("KEYPAIR_DISCLOSURE_FIELD", { name: "field", index });
  });
  const packedKey = packBytesBe(checkedBytes<Bytes32>(secret, 32, "disclosure key"));
  const seed = new Uint8Array(32);
  try {
    seed.set(
      poseidon([
        bigIntToBytes(domain) as Bytes32,
        ...packedKey,
        rightAlign(checkedBytes<Bytes16>(salt, 16, "salt")),
      ]),
    );
    return Object.freeze(
      values.map((value, index) => {
        const mask = bytesToBigInt(poseidon([seed, bigIntToBytes(BigInt(index)) as Bytes32]));
        const masked = seal
          ? fieldAdd(bytesToBigInt(value), mask)
          : fieldSub(bytesToBigInt(value), mask);
        return bigIntToBytes(masked) as Bytes32;
      }),
    );
  } finally {
    for (const field of packedKey) field.fill(0);
    seed.fill(0);
  }
}

function rightAlign(bytes: Uint8Array): Bytes32 {
  const output = new Uint8Array(32);
  output.set(bytes, 32 - bytes.length);
  return output as Bytes32;
}
