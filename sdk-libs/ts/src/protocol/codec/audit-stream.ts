/** Every plaintext of the ring auditor stream, Rust `custom_ring_interface::audit_stream`. */
import {
  addressBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  encodeBase58,
  equalBytes,
  u64be,
} from "@heliuslabs/zolana/internal";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";

import { checkedCounter } from "../../crypto/error.js";
import {
  AUDIT_RECORD_LEN,
  DATA_TAIL_LEN,
  DEFAULT_INPUT_BITS_LEN,
  ENTRY_INPUT_LEN,
  ENVELOPE_KEY_LEN,
  OPENING_RECORD_LEN,
  RECORD_STRIDE,
  envelopeRegion,
  type AuditStreamLayout,
} from "./ring-disclosure-layout.js";
import { RingError } from "../error.js";

const FIELD_LEN = 32;
const AMOUNT_LEN = 8;
const ZERO = new Uint8Array(FIELD_LEN) as Bytes32;
const ZERO_MINT = encodeBase58(ZERO);
const NO_EVIDENCE: AuditEvidence = Object.freeze({ kind: "none" });

/** A record's first byte, the circuit derives it from the slot's domain and ring id, Rust `RecordKind`. */
export const RecordKind = Object.freeze({ dummy: 0, ring: 1, exit: 2 } as const);
export type RecordKind = (typeof RecordKind)[keyof typeof RecordKind];

/** One published slot, the proof holds a dummy's plaintext to zero, Rust `AuditRecord`. */
export interface AuditRecord {
  readonly kind: RecordKind;
  readonly amount: bigint;
  readonly ownerKey: Bytes32;
  readonly mint: Address;
  readonly nullifierPk: Bytes32;
}

/** A deposit or merge record, `secret` the deposit's blinding or the merge's seed, Rust `OpeningRecord`. */
export interface OpeningRecord {
  readonly record: AuditRecord;
  readonly secret: Bytes32;
}

/** Zero fields while `hasData` is clear and on a dummy, Rust `DataTail`. */
export interface DataTail {
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
}

/** One default-ring input's opening, zero fields on any other slot, never a secret, Rust `EntryInput`. */
export interface EntryInput {
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly amount: bigint;
  readonly mint: Address;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
}

/** The envelope past its sealed key and count, Rust `AuditEvidence`. */
export type AuditEvidence =
  | Readonly<{ kind: "none" }>
  | Readonly<{
      kind: "entry";
      /** Bit `i` set when input `i` is a live default-ring note. */
      defaultInputBits: bigint;
      /** One per published input. */
      inputs: readonly EntryInput[];
    }>;

/** `tx_viewing_sk ‖ R ‖ default_input_bits ‖ entries`, Rust `AuditEnvelope`. */
export interface AuditEnvelope {
  readonly txViewingSecret: Bytes32;
  /** `R`, nullifiers at or past it are padding. */
  readonly realInputs: number;
  readonly evidence: AuditEvidence;
}

export const DUMMY_RECORD: AuditRecord = Object.freeze({
  kind: RecordKind.dummy,
  amount: 0n,
  ownerKey: ZERO,
  mint: ZERO_MINT,
  nullifierPk: ZERO,
});

export const EMPTY_TAIL: DataTail = Object.freeze({ dataHash: ZERO, ringDataHash: ZERO });

export const EMPTY_ENTRY_INPUT: EntryInput = Object.freeze({
  ownerKey: ZERO,
  nullifierPk: ZERO,
  amount: 0n,
  mint: ZERO_MINT,
  blinding: ZERO,
  dataHash: ZERO,
  ringDataHash: ZERO,
});

export function encodeAuditRecord(record: AuditRecord): Uint8Array {
  const out = new Uint8Array(AUDIT_RECORD_LEN);
  out[0] = record.kind;
  out.set(u64be(checkedCounter(record.amount, "amount")), 1);
  out.set(checkedBytes<Bytes32>(record.ownerKey, FIELD_LEN, "owner key"), 9);
  out.set(addressBytes(record.mint, "mint"), 41);
  out.set(checkedBytes<Bytes32>(record.nullifierPk, FIELD_LEN, "nullifier pk"), 73);
  return out;
}

/** Refuses a kind off the three and a dummy that carries a value. */
export function decodeAuditRecord(plaintext: Uint8Array): AuditRecord {
  if (plaintext.length !== AUDIT_RECORD_LEN) throw refused();
  const kind = plaintext[0];
  if (kind !== RecordKind.dummy && kind !== RecordKind.ring && kind !== RecordKind.exit)
    throw refused();
  const body = plaintext.subarray(1);
  if (kind === RecordKind.dummy && body.some((byte) => byte !== 0)) throw refused();
  return Object.freeze({
    kind,
    amount: bytesToBigInt(plaintext.subarray(1, 9)),
    ownerKey: plaintext.slice(9, 41) as Bytes32,
    mint: encodeBase58(plaintext.subarray(41, 73)),
    nullifierPk: plaintext.slice(73, 105) as Bytes32,
  });
}

export function encodeOpeningRecord(opening: OpeningRecord): Uint8Array {
  const out = new Uint8Array(OPENING_RECORD_LEN);
  out.set(encodeAuditRecord(opening.record));
  out.set(checkedBytes<Bytes32>(opening.secret, FIELD_LEN, "secret"), RECORD_STRIDE);
  return out;
}

export function decodeOpeningRecord(plaintext: Uint8Array): OpeningRecord {
  if (plaintext.length !== OPENING_RECORD_LEN) throw refused();
  if (plaintext.subarray(AUDIT_RECORD_LEN, RECORD_STRIDE).some((byte) => byte !== 0))
    throw refused();
  return Object.freeze({
    record: decodeAuditRecord(plaintext.subarray(0, AUDIT_RECORD_LEN)),
    secret: plaintext.slice(RECORD_STRIDE) as Bytes32,
  });
}

export function encodeDataTail(tail: DataTail): Uint8Array {
  return concatBytes(
    checkedBytes<Bytes32>(tail.dataHash, FIELD_LEN, "data hash"),
    checkedBytes<Bytes32>(tail.ringDataHash, FIELD_LEN, "ring data hash"),
  );
}

export function decodeDataTail(plaintext: Uint8Array): DataTail {
  if (plaintext.length !== DATA_TAIL_LEN) throw refused();
  return Object.freeze({
    dataHash: plaintext.slice(0, FIELD_LEN) as Bytes32,
    ringDataHash: plaintext.slice(FIELD_LEN) as Bytes32,
  });
}

export function encodeAuditEnvelope(envelope: AuditEnvelope): Uint8Array {
  const { evidence, realInputs } = envelope;
  if (!Number.isInteger(realInputs) || realInputs < 0 || realInputs > 0xff) throw refused();
  const head = concatBytes(
    checkedBytes<Bytes32>(envelope.txViewingSecret, ENVELOPE_KEY_LEN, "tx viewing secret"),
    Uint8Array.of(realInputs),
  );
  if (evidence.kind === "none") return head;
  return concatBytes(
    head,
    u64be(checkedCounter(evidence.defaultInputBits, "default input bits")),
    ...evidence.inputs.map(encodeEntryInput),
  );
}

/** Refuses any length other than `layout`'s. */
export function decodeAuditEnvelope(
  plaintext: Uint8Array,
  layout: AuditStreamLayout,
): AuditEnvelope {
  if (plaintext.length !== envelopeRegion(layout).length) throw refused();
  const txViewingSecret = plaintext.slice(0, ENVELOPE_KEY_LEN) as Bytes32;
  const realInputs = plaintext[ENVELOPE_KEY_LEN] ?? 0;
  if (!layout.key.entry)
    return Object.freeze({ txViewingSecret, realInputs, evidence: NO_EVIDENCE });
  const bitsAt = ENVELOPE_KEY_LEN + 1;
  const entriesAt = bitsAt + DEFAULT_INPUT_BITS_LEN;
  return Object.freeze({
    txViewingSecret,
    realInputs,
    evidence: Object.freeze({
      kind: "entry",
      defaultInputBits: bytesToBigInt(plaintext.subarray(bitsAt, entriesAt)),
      inputs: Object.freeze(
        Array.from({ length: layout.inputs }, (_, input) =>
          decodeEntryInput(
            plaintext.subarray(
              entriesAt + input * ENTRY_INPUT_LEN,
              entriesAt + (input + 1) * ENTRY_INPUT_LEN,
            ),
          ),
        ),
      ),
    }),
  });
}

/** True on the all-zero entry a live ring input carries. */
export function isEmptyEntryInput(entry: EntryInput): boolean {
  return equalBytes(encodeEntryInput(entry), encodeEntryInput(EMPTY_ENTRY_INPUT));
}

function encodeEntryInput(input: EntryInput): Uint8Array {
  return concatBytes(
    checkedBytes<Bytes32>(input.ownerKey, FIELD_LEN, "owner key"),
    checkedBytes<Bytes32>(input.nullifierPk, FIELD_LEN, "nullifier pk"),
    u64be(checkedCounter(input.amount, "amount")),
    addressBytes(input.mint, "mint"),
    checkedBytes<Bytes32>(input.blinding, FIELD_LEN, "blinding"),
    checkedBytes<Bytes32>(input.dataHash, FIELD_LEN, "data hash"),
    checkedBytes<Bytes32>(input.ringDataHash, FIELD_LEN, "ring data hash"),
  );
}

function decodeEntryInput(bytes: Uint8Array): EntryInput {
  const mintAt = 2 * FIELD_LEN + AMOUNT_LEN;
  const field = (at: number): Bytes32 => bytes.slice(at, at + FIELD_LEN) as Bytes32;
  return Object.freeze({
    ownerKey: field(0),
    nullifierPk: field(FIELD_LEN),
    amount: bytesToBigInt(bytes.subarray(2 * FIELD_LEN, mintAt)),
    mint: encodeBase58(bytes.subarray(mintAt, mintAt + FIELD_LEN)),
    blinding: field(mintAt + FIELD_LEN),
    dataHash: field(mintAt + 2 * FIELD_LEN),
    ringDataHash: field(mintAt + 3 * FIELD_LEN),
  });
}

function refused(): RingError {
  return new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason: "RingTransactLength" } });
}
