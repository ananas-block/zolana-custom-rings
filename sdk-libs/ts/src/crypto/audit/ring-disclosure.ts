/** The evidence and record codecs of the auditor stream, Rust `custom_ring_interface::audit_stream`. */
import {
  clampViewingSecret,
  isCanonicalField,
  bigIntToBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
} from "@heliuslabs/zolana/internal";
import {
  ViewingKey,
  type Bytes32,
  type X25519Keypair,
  type X25519PublicKey,
} from "@heliuslabs/zolana/keypair";

import { RingError } from "../../protocol/error.js";
import { RingKeyError } from "../error.js";
import {
  ANONYMOUS_RECORD_LEN,
  ENTRY_INPUT_LEN,
  ENVELOPE_KEY_LEN,
  INPUT_HASH_LEN,
  STREAM_FIRST_COUNTER,
  checkedStreamLayout,
  evidenceBytes,
  isExitSlot,
  recordLen,
  recordRegion,
  recordSlots,
  transferAuditKey,
  type AuditStreamLayout,
} from "../../protocol/codec/ring-disclosure-layout.js";

import {
  auditorSchedule,
  sealAuditorStream,
  type AuditSchedule,
  type AuditorEnvelope,
  type AuditorMessage,
  type AuditorRegion,
} from "./audit.js";

export type DummySlot = Readonly<{ kind: "dummy" }>;

/** The delivered body opens a ring output and a hidden dummy, an exit's owner is its owner tag. */
export type DeliveredOutputOpening =
  | Readonly<{ kind: "body" }>
  /** `nullifierPk` is `undefined` under key escrow. */
  | Readonly<{ kind: "exit"; nullifierPk: Bytes32 | undefined; asset: Bytes32; amount: bigint }>;

/** The record opens every live slot's asset and amount. */
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

/** A spent UTXO of the hidden sender, its data hashes zero. */
export interface AnonymousInputOpening {
  /** The published commitment, the entry key binds it to the opened fields. */
  readonly hash: Bytes32;
  readonly asset: Bytes32;
  readonly amount: bigint;
  readonly blinding: Bytes32;
}

/** The evidence of the signer, in-proof, authority and commitment keys, `undefined` for a dummy. */
export type InputCommitments = Readonly<{
  kind: "commitments";
  hashes: readonly (Bytes32 | undefined)[];
}>;

/** The entry key opens every spent UTXO, all under the sender's key and one nullifier key. */
export type InputOpenings = Readonly<{
  kind: "openings";
  senderKey: Bytes32;
  senderNullifierPk: Bytes32;
  inputs: readonly (AnonymousInputOpening | undefined)[];
}>;

export type RingDisclosure =
  | Readonly<{
      kind: "delivered";
      layout: AuditStreamLayout;
      inputs: InputCommitments;
      outputs: readonly DeliveredOutputOpening[];
    }>
  | Readonly<{
      kind: "anonymous";
      layout: AuditStreamLayout;
      inputs: InputCommitments | InputOpenings;
      outputs: readonly AnonymousOutputOpening[];
    }>;

/** `layout` is the one the program verified. */
export interface PublishedAudit {
  readonly layout: AuditStreamLayout;
  readonly message: AuditorMessage;
}

/** The plaintexts of one auditor stream behind `tx_viewing_sk`. */
export interface DisclosurePlaintext {
  readonly evidence: Uint8Array;
  /** The records of the slots that have one, in slot order. */
  readonly records: readonly Uint8Array[];
}

/** Refuses a disclosure off its layout before any ephemeral key exists. */
export function sealRingDisclosure(
  input: Readonly<{
    txViewingSecret: Bytes32;
    auditorPublicKey: X25519PublicKey;
    disclosure: RingDisclosure;
  }>,
): AuditorEnvelope {
  const { disclosure } = input;
  const plaintext = disclosurePlaintext(disclosure);
  const envelope = concatBytes(
    checkedBytes<Bytes32>(input.txViewingSecret, ENVELOPE_KEY_LEN, "tx viewing secret"),
    plaintext.evidence,
  );
  try {
    return sealAuditorStream({
      auditorPublicKey: input.auditorPublicKey,
      envelope,
      records: recordSlots(disclosure.layout).map((slot, index) => ({
        counter: recordRegion(disclosure.layout, slot).startCounter,
        bytes: required(plaintext.records[index]),
      })),
    });
  } finally {
    envelope.fill(0);
    plaintext.evidence.fill(0);
    for (const record of plaintext.records) record.fill(0);
  }
}

/** Opens the evidence and every record under the layout the program verified. */
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

/** @internal Rust `OpenedAudit`, the evidence and records read from the envelope's schedule. */
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

/** @internal Rust `AuditEnvelope::open`, one agreement and one schedule behind the key and the disclosure. */
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

/** Wipes `recovered`, the circuit seals the clamped encoding and an alias is refused. */
export function canonicalViewingKey(recovered: Bytes32): ViewingKey {
  const canonical = clampViewingSecret(recovered);
  try {
    let difference = 0;
    for (let index = 0; index < ENVELOPE_KEY_LEN; index++)
      difference |= (recovered[index] ?? 0) ^ (canonical[index] ?? 0);
    if (difference !== 0) throw new RingError("RING_AUDIT_NONCANONICAL_KEY");
    return ViewingKey.fromBytes(recovered);
  } finally {
    canonical.fill(0);
    recovered.fill(0);
  }
}

/** The evidence and records the layout fixes, the caller wipes them. */
export function disclosurePlaintext(disclosure: RingDisclosure): DisclosurePlaintext {
  const layout = checkedLayout(disclosure.layout);
  checkCount(disclosure.outputs.length, layout.outputs);
  const evidence = encodeEvidence(disclosure.inputs, layout);
  if (evidence.length !== evidenceBytes(layout)) {
    evidence.fill(0);
    throw shapeError("inputs");
  }
  const records: Uint8Array[] = [];
  try {
    for (const slot of recordSlots(layout)) records.push(encodeRecord(disclosure, slot));
    // A delivered slot publishes no record, its opening must still name no exit.
    disclosure.outputs.forEach((output, slot) => {
      if ((output.kind === "exit") !== isExitSlot(layout, slot)) throw shapeError("exits");
    });
    return Object.freeze({ evidence, records: Object.freeze(records) });
  } catch (error) {
    evidence.fill(0);
    for (const record of records) record.fill(0);
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
      inputs: readCommitments(evidence, checked.inputs),
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
    inputs:
      checked.key.kind === "entry"
        ? readOpenings(evidence, checked.inputs)
        : readCommitments(evidence, checked.inputs),
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
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const BODY: DeliveredOutputOpening = Object.freeze({ kind: "body" });
const DUMMY: DummySlot = Object.freeze({ kind: "dummy" });

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

/** A structural layout names one key of the catalog, its counts within what that key serves. */
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
  const keyed = transferAuditKey({
    rail: key.kind === "confidential" ? "confidential" : "anonymous",
    inputs: layout.inputs,
    capacity: layout.capacity,
    spendsDefaultRing: key.kind === "entry",
  });
  return keyed !== undefined && keyed.kind === key.kind && keyed.class === key.class;
}

function encodeEvidence(
  inputs: InputCommitments | InputOpenings,
  layout: AuditStreamLayout,
): Uint8Array {
  if (inputs.kind === "commitments") {
    checkCount(inputs.hashes.length, layout.inputs);
    return joined(inputs.hashes.map((hash) => new Uint8Array(field(hash ?? zero(), "inputHash"))));
  }
  checkCount(inputs.inputs.length, layout.inputs);
  return joined([
    checkedBytes<Bytes32>(inputs.senderKey, KEY_BYTES, "senderKey"),
    new Uint8Array(field(inputs.senderNullifierPk, "senderNullifierPk")),
    ...inputs.inputs.flatMap((input) => [
      new Uint8Array(field(input?.hash ?? zero(), "inputHash")),
      amountBytes(input?.amount ?? 0n),
      new Uint8Array(field(input?.asset ?? zero(), "inputAsset")),
      new Uint8Array(field(input?.blinding ?? zero(), "inputBlinding")),
    ]),
  ]);
}

/** The record of `slot`, an opening that fits no record of the slot's kind is refused. */
function encodeRecord(disclosure: RingDisclosure, slot: number): Uint8Array {
  const { layout } = disclosure;
  const output = disclosure.outputs[slot];
  if (output === undefined) throw shapeError("outputs");
  if (isExitSlot(layout, slot)) {
    if (output.kind !== "exit") throw shapeError("exits");
    return exitRecord(output, layout.keyEscrow);
  }
  if (output.kind === "dummy") return new Uint8Array(ANONYMOUS_RECORD_LEN);
  if (output.kind !== "ring") throw shapeError("exits");
  return joined([
    checkedBytes<Bytes32>(output.ownerKey, KEY_BYTES, "ownerKey"),
    new Uint8Array(field(output.asset, "asset")),
    amountBytes(output.amount),
    new Uint8Array(field(output.nullifierPk, "nullifierPk")),
  ]);
}

function exitRecord(
  output: Readonly<{ nullifierPk: Bytes32 | undefined; asset: Bytes32; amount: bigint }>,
  keyEscrow: boolean,
): Uint8Array {
  if (keyEscrow !== (output.nullifierPk === undefined)) throw shapeError("nullifierPk");
  return joined([
    new Uint8Array(field(output.asset, "asset")),
    amountBytes(output.amount),
    ...(output.nullifierPk === undefined
      ? []
      : [new Uint8Array(field(output.nullifierPk, "nullifierPk"))]),
  ]);
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

/** A zero hash names a dummy, the proof holds each entry to an opened commitment. */
function readCommitments(evidence: Uint8Array, count: number): InputCommitments {
  return Object.freeze({
    kind: "commitments",
    hashes: Object.freeze(
      Array.from({ length: count }, (_, index) => {
        const hash = canonical(key(evidence, INPUT_HASH_LEN * index, "inputHash"), "inputHash");
        return isZero(hash) ? undefined : hash;
      }),
    ),
  });
}

function readOpenings(evidence: Uint8Array, count: number): InputOpenings {
  const head = 2 * KEY_BYTES;
  return Object.freeze({
    kind: "openings",
    senderKey: key(evidence, 0, "senderKey"),
    senderNullifierPk: canonical(
      key(evidence, KEY_BYTES, "senderNullifierPk"),
      "senderNullifierPk",
    ),
    inputs: Object.freeze(
      Array.from({ length: count }, (_, index) => {
        const start = head + index * ENTRY_INPUT_LEN;
        const input = evidence.subarray(start, start + ENTRY_INPUT_LEN);
        if (isZero(input)) return undefined;
        const assetAt = KEY_BYTES + AMOUNT_BYTES;
        return Object.freeze({
          hash: canonical(key(input, 0, "inputHash"), "inputHash"),
          amount: bytesToBigInt(input.subarray(KEY_BYTES, assetAt)),
          asset: canonical(key(input, assetAt, "inputAsset"), "inputAsset"),
          blinding: canonical(key(input, assetAt + KEY_BYTES, "inputBlinding"), "inputBlinding"),
        });
      }),
    ),
  });
}

/** Concatenates the fresh `parts` and wipes them. */
function joined(parts: readonly Uint8Array[]): Uint8Array {
  try {
    return concatBytes(...parts);
  } finally {
    for (const part of parts) part.fill(0);
  }
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw shapeError("fields");
  return value;
}

function checkCount(found: number, expected: number): void {
  if (found !== expected) throw shapeError("count");
}

function amountBytes(amount: bigint): Uint8Array {
  if (typeof amount !== "bigint" || amount < 0n || amount > U64_MAX)
    throw new RingKeyError("KEYPAIR_DISCLOSURE_FIELD", { name: "amount" });
  return bigIntToBytes(amount, AMOUNT_BYTES);
}

/** The circuit bounds every field value to its canonical encoding. */
function field(value: Uint8Array, name: string): Bytes32 {
  return canonical(checkedBytes<Bytes32>(value, 32, name), name);
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

function zero(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}

function shapeError(name: string): RingKeyError {
  return new RingKeyError("KEYPAIR_DISCLOSURE_SHAPE", { name });
}
