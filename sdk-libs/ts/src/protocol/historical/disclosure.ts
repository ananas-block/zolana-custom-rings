import {
  BN254_SCALAR_ORDER,
  isCanonicalField,
  bytesToBigInt,
  checkedBytes,
} from "@heliuslabs/zolana/internal";
import {
  X25519PublicKey,
  type Bytes32,
  type ViewingKey,
  type X25519Keypair,
} from "@heliuslabs/zolana/keypair";

import {
  auditorSchedule,
  type AuditSchedule,
  type AuditorMessage,
  type AuditorRegion,
} from "../../crypto/audit/audit.js";
import { canonicalViewingKey } from "../../crypto/audit/ring-disclosure.js";
import { RingKeyError } from "../../crypto/error.js";
import {
  ENTRY_INPUT_LEN,
  ENVELOPE_KEY_LEN,
  INPUT_PREFIX_BYTES,
  STREAM_FIRST_COUNTER,
  TAGGED_KEY_LEN,
  anonymousAuditKey,
  auditorMessageLen,
  checkedStreamLayout,
  confidentialAuditKey,
  envelopeRegion,
  evidenceBytes,
  isExitSlot,
  recordLen,
  recordRegion,
  recordSlots,
  type AuditStreamLayout,
} from "./layout.js";

export type DummySlot = Readonly<{ kind: "dummy" }>;

export type DeliveredOutputOpening =
  | Readonly<{ kind: "body" }>
  /** `nullifierPk` is `undefined` under key escrow. */
  | Readonly<{ kind: "exit"; nullifierPk: Bytes32 | undefined; asset: Bytes32; amount: bigint }>;

export type AnonymousOutputOpening =
  | Readonly<{
      kind: "ring";
      ownerKey: Bytes32;
      nullifierPk: Bytes32;
      asset: Bytes32;
      amount: bigint;
    }>
  | Readonly<{ kind: "exit"; nullifierPk: Bytes32; asset: Bytes32; amount: bigint }>
  | DummySlot;

export interface AnonymousInputOpening {
  readonly asset: Bytes32;
  readonly amount: bigint;
  readonly blinding: Bytes32;
}

/** The first `INPUT_PREFIX_BYTES` of a canonical spent hash read big endian, never zero. */
export type InputPrefix = bigint & { readonly __inputPrefix: true };

export type DeliveredInputs =
  | Readonly<{ kind: "none" }>
  | Readonly<{ kind: "prefixes"; prefixes: readonly (InputPrefix | undefined)[] }>;

export type AnonymousInputs =
  | Readonly<{
      kind: "commitments";
      first: Bytes32;
      prefixes: readonly (InputPrefix | undefined)[];
    }>
  | Readonly<{
      kind: "openings";
      senderKey: Bytes32;
      senderNullifierPk: Bytes32;
      inputs: readonly (AnonymousInputOpening | undefined)[];
    }>;

export type RingDisclosure =
  | Readonly<{
      kind: "delivered";
      layout: AuditStreamLayout;
      inputs: DeliveredInputs;
      outputs: readonly DeliveredOutputOpening[];
    }>
  | Readonly<{
      kind: "anonymous";
      layout: AuditStreamLayout;
      inputs: AnonymousInputs;
      outputs: readonly AnonymousOutputOpening[];
    }>;

export interface PublishedAudit {
  readonly layout: AuditStreamLayout;
  readonly message: AuditorMessage;
}

export interface DisclosurePlaintext {
  readonly evidence: Uint8Array;
  /** The slots that have one, in slot order. */
  readonly records: readonly Uint8Array[];
}

/** A dummy names no input, any other hash below `2^128` is refused. */
export function inputPrefixes(
  hashes: readonly (Bytes32 | undefined)[],
): readonly (InputPrefix | undefined)[] {
  return Object.freeze(
    hashes.map((hash) => {
      if (hash === undefined) return undefined;
      const prefix = inputPrefix(hash);
      if (prefix === undefined)
        throw new RingKeyError("KEYPAIR_DISCLOSURE_FIELD", { name: "inputHash" });
      return prefix;
    }),
  );
}

/** `undefined` for a hash at or above the modulus or below `2^128`. */
export function inputPrefix(hash: Bytes32): InputPrefix | undefined {
  const value = checkedBytes<Bytes32>(hash, 32, "inputHash");
  if (!isCanonicalField(value)) return undefined;
  const prefix = bytesToBigInt(value.subarray(0, INPUT_PREFIX_BYTES));
  return prefix === 0n ? undefined : (prefix as InputPrefix);
}

/** `undefined` for bytes off the length, for zero and past the prefix of any canonical hash. */
export function inputPrefixFromBytes(bytes: Uint8Array): InputPrefix | undefined {
  if (bytes.length !== INPUT_PREFIX_BYTES) return undefined;
  const prefix = bytesToBigInt(bytes);
  return prefix === 0n || prefix > MAX_INPUT_PREFIX ? undefined : (prefix as InputPrefix);
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

/** `layout` is the one the frame fixed. */
export function openRingDisclosure(
  auditor: X25519Keypair,
  published: PublishedAudit,
): RingDisclosure {
  const regions = recordRegions(published);
  const stream = openStream(auditor, published.message);
  try {
    return disclosureOf(published.layout, stream, regions);
  } finally {
    closeStream(stream);
  }
}

export class OpenedAudit {
  readonly #stream: OpenedStream;
  readonly #published: PublishedAudit;

  constructor(
    readonly txViewingKey: ViewingKey,
    stream: OpenedStream,
    published: PublishedAudit,
  ) {
    this.#stream = stream;
    this.#published = published;
  }

  disclosure(): RingDisclosure {
    return disclosureOf(this.#published.layout, this.#stream, recordRegions(this.#published));
  }

  destroy(): void {
    this.txViewingKey.destroy();
    closeStream(this.#stream);
  }
}

export function openAuditEnvelope(auditor: X25519Keypair, published: PublishedAudit): OpenedAudit {
  const stream = openStream(auditor, published.message);
  try {
    const secret = stream.envelope.slice(0, ENVELOPE_KEY_LEN) as Bytes32;
    return new OpenedAudit(canonicalViewingKey(secret), stream, published);
  } catch (error) {
    closeStream(stream);
    throw error;
  }
}

/** Refuses a field at or above the modulus and any nonzero padding, the result shares no bytes with `plaintext`. */
export function decodeDisclosure(
  layout: AuditStreamLayout,
  plaintext: DisclosurePlaintext,
): RingDisclosure {
  const checked = checkedLayout(layout);
  const slots = recordSlots(checked);
  const { evidence, records } = plaintext;
  if (evidence.length !== evidenceBytes(checked) || records.length !== slots.length)
    throw shapeError("plaintext");
  slots.forEach((slot, index) => {
    if (required(records[index]).length !== recordLen(checked, slot)) throw shapeError("records");
  });
  const record = new Map(slots.map((slot, index) => [slot, required(records[index])]));
  if (checked.key.kind === "confidential")
    return Object.freeze({
      kind: "delivered",
      layout: checked,
      inputs: readDeliveredInputs(evidence, checked),
      outputs: Object.freeze(
        Array.from({ length: checked.outputs }, (_, slot) => {
          const bytes = record.get(slot);
          return bytes === undefined ? BODY : readExit(bytes, checked.keyEscrow);
        }),
      ),
    });
  return Object.freeze({
    kind: "anonymous",
    layout: checked,
    inputs: readAnonymousInputs(evidence, checked),
    outputs: Object.freeze(
      Array.from({ length: checked.outputs }, (_, slot) => {
        const bytes = required(record.get(slot));
        return isExitSlot(checked, slot)
          ? (readExit(bytes, false) as AnonymousOutputOpening)
          : readAnonymousRecord(bytes);
      }),
    ),
  });
}

const KEY_BYTES = 32;
const AMOUNT_BYTES = 8;
const BODY: DeliveredOutputOpening = Object.freeze({ kind: "body" });
const DUMMY: DummySlot = Object.freeze({ kind: "dummy" });
/** No canonical hash has a larger prefix. */
const MAX_INPUT_PREFIX = BN254_SCALAR_ORDER >> BigInt(8 * INPUT_PREFIX_BYTES);

interface OpenedStream {
  readonly schedule: AuditSchedule;
  readonly envelope: Uint8Array;
}

function openStream(
  auditor: X25519Keypair,
  message: Pick<AuditorMessage, "ephemeralPublicKey" | "envelope">,
): OpenedStream {
  const schedule = auditorSchedule(auditor, message.ephemeralPublicKey);
  return { schedule, envelope: schedule.apply(STREAM_FIRST_COUNTER, message.envelope) };
}

function closeStream({ schedule, envelope }: OpenedStream): void {
  envelope.fill(0);
  schedule.destroy();
}

function recordRegions({ layout, message }: PublishedAudit): readonly AuditorRegion[] {
  const slots = recordSlots(checkedLayout(layout));
  if (message.records.length !== slots.length) throw shapeError("records");
  return slots.map((slot, index) => ({
    counter: recordRegion(layout, slot).startCounter,
    bytes: required(message.records[index]),
  }));
}

function disclosureOf(
  layout: AuditStreamLayout,
  { schedule, envelope }: OpenedStream,
  regions: readonly AuditorRegion[],
): RingDisclosure {
  const records = regions.map(({ counter, bytes }) => schedule.apply(counter, bytes));
  try {
    return decodeDisclosure(layout, {
      evidence: envelope.subarray(ENVELOPE_KEY_LEN),
      records,
    });
  } finally {
    for (const record of records) record.fill(0);
  }
}

function checkedLayout(layout: AuditStreamLayout): AuditStreamLayout {
  try {
    checkedStreamLayout(layout);
  } catch {
    throw shapeError("layout");
  }
  if (!keyServes(layout)) throw shapeError("layout");
  return layout;
}

function keyServes(layout: AuditStreamLayout): boolean {
  const { key } = layout;
  if (key.kind === "confidential")
    return confidentialAuditKey(layout.outputs, key.inputPrefixes)?.class === key.class;
  const keyed = anonymousAuditKey({
    inputs: layout.inputs,
    outputs: layout.outputs,
    spendsDefaultRing: key.kind === "entry",
  });
  return keyed !== undefined && keyed.kind === key.kind && keyed.class === key.class;
}

function readExit(
  bytes: Uint8Array,
  keyEscrow: boolean,
): Extract<DeliveredOutputOpening, { kind: "exit" }> {
  const asset = key(bytes, 0, "asset");
  const amount = bytesToBigInt(bytes.subarray(KEY_BYTES, KEY_BYTES + AMOUNT_BYTES));
  return Object.freeze({
    kind: "exit",
    nullifierPk: keyEscrow
      ? undefined
      : canonical(key(bytes, KEY_BYTES + AMOUNT_BYTES, "nullifierPk"), "nullifierPk"),
    asset: canonical(asset, "asset"),
    amount,
  });
}

/** A hidden dummy is the all zero record, a live record may name a zero nullifier key. */
function readAnonymousRecord(bytes: Uint8Array): AnonymousOutputOpening {
  if (isZero(bytes)) return DUMMY;
  return Object.freeze({
    kind: "ring",
    ownerKey: key(bytes, 0, "ownerKey"),
    nullifierPk: canonical(key(bytes, 2 * KEY_BYTES + AMOUNT_BYTES, "nullifierPk"), "nullifierPk"),
    asset: canonical(key(bytes, KEY_BYTES, "asset"), "asset"),
    amount: bytesToBigInt(bytes.subarray(2 * KEY_BYTES, 2 * KEY_BYTES + AMOUNT_BYTES)),
  });
}

function readDeliveredInputs(evidence: Uint8Array, layout: AuditStreamLayout): DeliveredInputs {
  if (layout.key.kind !== "confidential" || !layout.key.inputPrefixes)
    return Object.freeze({ kind: "none" });
  return Object.freeze({ kind: "prefixes", prefixes: readPrefixes(evidence, layout.inputs) });
}

function readAnonymousInputs(evidence: Uint8Array, layout: AuditStreamLayout): AnonymousInputs {
  if (layout.key.kind === "commitment") {
    const first = canonical(key(evidence, 0, "inputHash"), "inputHash");
    // A zero hash at slot 0 contradicts the proof of a real spent UTXO 0.
    if (isZero(first)) throw shapeError("inputs");
    return Object.freeze({
      kind: "commitments",
      first,
      prefixes: readPrefixes(evidence.subarray(KEY_BYTES), layout.inputs - 1),
    });
  }
  const head = 2 * KEY_BYTES;
  return Object.freeze({
    kind: "openings",
    senderKey: key(evidence, 0, "senderKey"),
    senderNullifierPk: canonical(
      key(evidence, KEY_BYTES, "senderNullifierPk"),
      "senderNullifierPk",
    ),
    inputs: Object.freeze(
      Array.from({ length: layout.inputs }, (_, index) => {
        const start = head + index * ENTRY_INPUT_LEN;
        const input = evidence.subarray(start, start + ENTRY_INPUT_LEN);
        if (isZero(input)) return undefined;
        return Object.freeze({
          amount: bytesToBigInt(input.subarray(0, AMOUNT_BYTES)),
          asset: canonical(key(input, AMOUNT_BYTES, "inputAsset"), "inputAsset"),
          blinding: canonical(
            key(input, AMOUNT_BYTES + KEY_BYTES, "inputBlinding"),
            "inputBlinding",
          ),
        });
      }),
    ),
  });
}

/** Refuses a prefix no canonical hash has, zero bytes name a published dummy. */
function readPrefixes(bytes: Uint8Array, count: number): readonly (InputPrefix | undefined)[] {
  return Object.freeze(
    Array.from({ length: count }, (_, index) => {
      const start = index * INPUT_PREFIX_BYTES;
      const prefix = bytesToBigInt(bytes.subarray(start, start + INPUT_PREFIX_BYTES));
      if (prefix > MAX_INPUT_PREFIX)
        throw new RingKeyError("KEYPAIR_DISCLOSURE_FIELD", { name: "inputPrefix" });
      return prefix === 0n ? undefined : (prefix as InputPrefix);
    }),
  );
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw shapeError("fields");
  return value;
}

function canonical(value: Bytes32, name: string): Bytes32 {
  if (!isCanonicalField(value)) throw new RingKeyError("KEYPAIR_DISCLOSURE_FIELD", { name });
  return value;
}

function key(bytes: Uint8Array, at: number, name: string): Bytes32 {
  return checkedBytes<Bytes32>(bytes.subarray(at, at + KEY_BYTES), 32, name);
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

function shapeError(name: string): RingKeyError {
  return new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name });
}
