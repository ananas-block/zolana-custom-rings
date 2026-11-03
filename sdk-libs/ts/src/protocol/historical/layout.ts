import { InterfaceError } from "@heliuslabs/zolana/interface";

/** The catalog frozen at statement version 2, output count to input class. */
const CONFIDENTIAL_CLASSES: ReadonlyMap<number, number> = new Map([
  [2, 32],
  [4, 24],
  [8, 16],
  [16, 5],
]);
const ANONYMOUS_CLASSES: ReadonlyMap<number, number> = new Map([
  [2, 24],
  [4, 16],
  [8, 5],
]);
const ENTRY_CLASSES: ReadonlyMap<number, number> = new Map([
  [2, 8],
  [4, 8],
  [8, 2],
]);

export const MERGE_WIDTHS: readonly number[] = Object.freeze([8, 24]);
export const DISCLOSURE_CHUNK_BYTES = 31;
export const INPUT_PREFIX_BYTES = 16;
export const STREAM_BLOCK_LEN = 16;
export const STREAM_FIRST_COUNTER = 2;
export const ENVELOPE_KEY_LEN = 32;
/** `be32(blinding) ‖ u64be(amount) ‖ owner_key`. */
export const ESCROWED_DELIVERED_BODY_LEN = 72;
/** `be32(blinding) ‖ u64be(amount) ‖ owner_key ‖ be32(nullifier_pk)`. */
export const DELIVERED_BODY_LEN = 104;
/** `owner_key ‖ be32(asset) ‖ u64be(amount) ‖ be32(nullifier_pk)`. */
export const ANONYMOUS_RECORD_LEN = 104;
/** `be32(asset) ‖ u64be(amount)`. */
export const ESCROWED_EXIT_RECORD_LEN = 40;
/** `be32(asset) ‖ u64be(amount) ‖ be32(nullifier_pk)`. */
export const EXIT_RECORD_LEN = 72;
/** `u64be(amount) ‖ be32(asset) ‖ be32(blinding)`. */
export const ENTRY_INPUT_LEN = 72;
/** `sender_key ‖ be32(sender_nullifier_pk)`. */
export const ENTRY_EVIDENCE_HEAD_LEN = 64;
/** `0x04 ‖ eph_u`. */
export const TAGGED_KEY_LEN = 33;

const FIELD_LEN = 32;
const ENVELOPE_KEY_BLOCKS = ENVELOPE_KEY_LEN / STREAM_BLOCK_LEN;

export function packedChunks(length: number): number {
  return Math.ceil(length / DISCLOSURE_CHUNK_BYTES);
}

export interface AuditLayout {
  readonly keyEscrow: boolean;
  readonly fullOpenings: boolean;
}

/** `key_escrow << 1 | full_openings << 3`, bits 0 and 2 stay clear. */
export function auditLayoutValue(layout: AuditLayout): number {
  const flags = [
    [layout.keyEscrow, 1],
    [layout.fullOpenings, 3],
  ] as const;
  if (flags.some(([flag]) => typeof flag !== "boolean")) throw shapeError("layout");
  return flags.reduce((value, [flag, bit]) => (flag ? value | (1 << bit) : value), 0);
}

export type AnonymousAuditKey =
  /** Spent UTXO 0 by its hash, every later one by its prefix. */
  | Readonly<{ kind: "commitment"; class: number }>
  /** Every spent UTXO opened. */
  | Readonly<{ kind: "entry"; class: number }>;

export type AuditKey =
  | Readonly<{
      kind: "confidential";
      class: number;
      /** The in-proof and authority rails, the signer rail discloses no input. */
      inputPrefixes: boolean;
    }>
  | AnonymousAuditKey;

export interface AnonymousSpend {
  readonly inputs: number;
  readonly outputs: number;
  readonly spendsDefaultRing: boolean;
}

export function anonymousAuditKey(spend: AnonymousSpend): AnonymousAuditKey | undefined {
  const inputClass = (spend.spendsDefaultRing ? ENTRY_CLASSES : ANONYMOUS_CLASSES).get(
    spend.outputs,
  );
  if (
    inputClass === undefined ||
    !Number.isInteger(spend.inputs) ||
    spend.inputs < 1 ||
    spend.inputs > inputClass
  )
    return undefined;
  return Object.freeze({
    kind: spend.spendsDefaultRing ? "entry" : "commitment",
    class: inputClass,
  });
}

export function confidentialAuditKey(
  outputs: number,
  inputPrefixes: boolean,
): AuditKey | undefined {
  const inputClass = CONFIDENTIAL_CLASSES.get(outputs);
  return inputClass === undefined
    ? undefined
    : Object.freeze({ kind: "confidential", class: inputClass, inputPrefixes });
}

/** `E_max`, one circuit serves every rail of a key. */
export function maxEvidenceBlocks(key: AuditKey): number {
  return Math.ceil(evidenceLen(key, key.class) / STREAM_BLOCK_LEN);
}

/** `R`. */
export function recordBlocks(key: AuditKey): number {
  const longest = key.kind === "confidential" ? EXIT_RECORD_LEN : ANONYMOUS_RECORD_LEN;
  return Math.ceil(longest / STREAM_BLOCK_LEN);
}

/** `R0`. */
export function firstRecordCounter(key: AuditKey): number {
  return STREAM_FIRST_COUNTER + ENVELOPE_KEY_BLOCKS + maxEvidenceBlocks(key);
}

export interface AuditStreamLayout {
  readonly key: AuditKey;
  readonly keyEscrow: boolean;
  /** `n`, the frame's nullifier count. */
  readonly inputs: number;
  readonly outputs: number;
  /** Bit `i` set when slot `i` exits. */
  readonly exits: bigint;
}

/** No counter serves two regions, a repeat reveals the XOR of two plaintexts. */
export interface AuditStreamRegion {
  readonly startCounter: number;
  readonly maxBlocks: number;
  readonly length: number;
}

export function checkedStreamLayout(layout: AuditStreamLayout): AuditStreamLayout {
  const { key, inputs, outputs, exits } = layout;
  const counted =
    Number.isInteger(inputs) &&
    inputs >= 1 &&
    inputs <= key.class &&
    Number.isInteger(outputs) &&
    outputs >= 1;
  if (
    !counted ||
    typeof layout.keyEscrow !== "boolean" ||
    typeof exits !== "bigint" ||
    exits < 0n ||
    exits >> BigInt(outputs) !== 0n
  )
    throw shapeError("layout");
  return layout;
}

/** Slots at or past `n` stay absent. */
export function evidenceBytes(layout: AuditStreamLayout): number {
  const { key, inputs } = layout;
  return key.kind === "confidential" && !key.inputPrefixes ? 0 : evidenceLen(key, inputs);
}

export function evidenceLen(key: AuditKey, count: number): number {
  switch (key.kind) {
    case "confidential":
      return INPUT_PREFIX_BYTES * count;
    case "commitment":
      return FIELD_LEN + INPUT_PREFIX_BYTES * (count - 1);
    case "entry":
      return ENTRY_EVIDENCE_HEAD_LEN + ENTRY_INPUT_LEN * count;
  }
}

export function envelopeRegion(layout: AuditStreamLayout): AuditStreamRegion {
  return Object.freeze({
    startCounter: STREAM_FIRST_COUNTER,
    maxBlocks: ENVELOPE_KEY_BLOCKS + maxEvidenceBlocks(layout.key),
    length: ENVELOPE_KEY_LEN + evidenceBytes(layout),
  });
}

export function recordRegion(layout: AuditStreamLayout, slot: number): AuditStreamRegion {
  const blocks = recordBlocks(layout.key);
  return Object.freeze({
    startCounter: firstRecordCounter(layout.key) + slot * blocks,
    maxBlocks: blocks,
    length: recordLen(layout, slot),
  });
}

export function isExitSlot(layout: Pick<AuditStreamLayout, "exits">, slot: number): boolean {
  return ((layout.exits >> BigInt(slot)) & 1n) === 1n;
}

export function deliveredBodyLen(keyEscrow: boolean): number {
  return keyEscrow ? ESCROWED_DELIVERED_BODY_LEN : DELIVERED_BODY_LEN;
}

export function exitRecordLen(keyEscrow: boolean): number {
  return keyEscrow ? ESCROWED_EXIT_RECORD_LEN : EXIT_RECORD_LEN;
}

/** Zero past the outputs and on a delivered slot. */
export function recordLen(layout: AuditStreamLayout, slot: number): number {
  if (slot >= layout.outputs) return 0;
  if (isExitSlot(layout, slot)) return exitRecordLen(layout.keyEscrow);
  return layout.key.kind === "confidential" ? 0 : ANONYMOUS_RECORD_LEN;
}

/** Zero past the outputs. */
export function ciphertextLen(layout: AuditStreamLayout, slot: number): number {
  if (slot >= layout.outputs) return 0;
  const record = recordLen(layout, slot);
  return record === 0 ? deliveredBodyLen(layout.keyEscrow) : record;
}

export function recordSlots(layout: AuditStreamLayout): readonly number[] {
  return Array.from({ length: layout.outputs }, (_, slot) => slot).filter(
    (slot) => recordLen(layout, slot) !== 0,
  );
}

/** `0x04 ‖ eph_u ‖ envelope_ct ‖ record_ct...`. */
export function auditorMessageLen(layout: AuditStreamLayout): number {
  return recordSlots(layout).reduce(
    (total, slot) => total + recordLen(layout, slot),
    TAGGED_KEY_LEN + envelopeRegion(layout).length,
  );
}

function shapeError(name: string): InterfaceError {
  return new InterfaceError("INTERFACE_INVALID_SHAPE", { name });
}
