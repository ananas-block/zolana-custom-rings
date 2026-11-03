/** Regions of the ring auditor stream and the lengths of its ciphertexts, Rust `custom_ring_interface::audit_stream`. */
import { InterfaceError } from "@heliuslabs/zolana/interface";

import { CONFIDENTIAL_TRANSFER_SHAPES, ringTransferCircuit } from "../proof/transfer-shapes.js";

/** Rust `DELIVERED_AUDIT_CAPACITIES`, the output counts of the confidential keys. */
export const DELIVERED_AUDIT_CAPACITIES: readonly number[] = Object.freeze([2, 4, 8, 16]);
/** Rust `MERGE_WIDTHS`, the merge widths whose disclosure still fits one v1 transaction. */
export const MERGE_WIDTHS: readonly number[] = Object.freeze([8, 24]);
/** Rust `PACK_BE_CHUNK_BYTES`, the bytes of one packed field. */
export const DISCLOSURE_CHUNK_BYTES = 31;
/** The first bytes of a spent hash the evidence discloses. */
export const INPUT_PREFIX_BYTES = 16;
export const STREAM_BLOCK_LEN = 16;
export const STREAM_FIRST_COUNTER = 2;
/** The sealed `tx_viewing_sk`, the envelope's first bytes. */
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
/** `0x04 ‖ eph_u` ahead of the auditor ciphertexts. */
export const TAGGED_KEY_LEN = 33;

const FIELD_LEN = 32;
const ENVELOPE_KEY_BLOCKS = ENVELOPE_KEY_LEN / STREAM_BLOCK_LEN;

/** Rust `pack_be_chunks`, the fields `length` bytes pack into. */
export function packedChunks(length: number): number {
  return Math.ceil(length / DISCLOSURE_CHUNK_BYTES);
}

/** The audit statement's layout element, Rust `AuditLayout`. */
export interface AuditLayout {
  /** The policy section escrows every output nullifier key the ciphertexts leave out. */
  readonly keyEscrow: boolean;
  /** The anonymous entry key, every spent UTXO opens in full. */
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

/** The audit key of an anonymous transfer, Rust `AnonymousAuditKey`. */
export type AnonymousAuditKey =
  /** Names spent UTXO 0 by its hash and every later one by its prefix, every spent UTXO a note of the ring. */
  | Readonly<{ kind: "commitment"; class: number }>
  /** Opens every spent UTXO, the key of a transfer that spends a default-ring note. */
  | Readonly<{ kind: "entry"; class: number }>;

/** The transfer key family at its input class, Rust `AuditKey`. */
export type AuditKey =
  | Readonly<{
      kind: "confidential";
      class: number;
      /** The in-proof and authority rails, the signer rail discloses no input. */
      inputPrefixes: boolean;
    }>
  | AnonymousAuditKey;

/** What picks an anonymous transfer's audit key, Rust `AnonymousSpend`. */
export interface AnonymousSpend {
  /** Published inputs. */
  readonly inputs: number;
  readonly outputs: number;
  /** A spent UTXO is a default-ring note, the commitment keys refuse ring id zero. */
  readonly spendsDefaultRing: boolean;
}

/** `undefined` when no key serves the spend, a larger entry spend splits, Rust `AnonymousSpend::audit_key`. */
export function anonymousAuditKey(spend: AnonymousSpend): AnonymousAuditKey | undefined {
  const circuit = ringTransferCircuit({
    rail: "anonymous",
    inputs: spend.inputs,
    outputs: spend.outputs,
    spendsDefaultRing: spend.spendsDefaultRing,
    legs: 0,
  });
  if (circuit === undefined || circuit.family === "transferConfidential") return undefined;
  return Object.freeze({
    kind: circuit.family === "transferAnonymousEntry" ? "entry" : "commitment",
    class: circuit.class,
  });
}

/** `undefined` off the capacities, the key of the delivered rails at `outputs`. */
export function confidentialAuditKey(
  outputs: number,
  inputPrefixes: boolean,
): AuditKey | undefined {
  const shape = CONFIDENTIAL_TRANSFER_SHAPES.find((keyed) => keyed.outputs === outputs);
  return shape === undefined
    ? undefined
    : Object.freeze({ kind: "confidential", class: shape.inputs, inputPrefixes });
}

/** `E_max`, the same at every rail of a key since one circuit serves them. */
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

/** Every length of one transfer's ring ciphertexts, a frame of any other length is refused, Rust `AuditStreamLayout`. */
export interface AuditStreamLayout {
  readonly key: AuditKey;
  readonly keyEscrow: boolean;
  /** `n`, the frame's nullifier count, never the key capacity or a private live count. */
  readonly inputs: number;
  readonly outputs: number;
  /** Bit `i` set when slot `i` exits. */
  readonly exits: bigint;
}

/** One stretch of the auditor keystream, no counter serves two regions, Rust `StreamRegion`. */
export interface AuditStreamRegion {
  readonly startCounter: number;
  readonly maxBlocks: number;
  /** Transmitted bytes, padding and unused blocks never leave the prover. */
  readonly length: number;
}

/** Refuses an input count off the key and an exit past the outputs. */
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

/** Slots at or past `n` stay absent from the evidence. */
export function evidenceBytes(layout: AuditStreamLayout): number {
  const { key, inputs } = layout;
  return key.kind === "confidential" && !key.inputPrefixes ? 0 : evidenceLen(key, inputs);
}

export function envelopeRegion(layout: AuditStreamLayout): AuditStreamRegion {
  return Object.freeze({
    startCounter: STREAM_FIRST_COUNTER,
    maxBlocks: ENVELOPE_KEY_BLOCKS + maxEvidenceBlocks(layout.key),
    length: ENVELOPE_KEY_LEN + evidenceBytes(layout),
  });
}

/** The range of `slot`, transmitting nothing on a delivered slot. */
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

/** The one ring disclosure ciphertext of `slot`, zero past the outputs. */
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

function evidenceLen(key: AuditKey, count: number): number {
  switch (key.kind) {
    case "confidential":
      return INPUT_PREFIX_BYTES * count;
    case "commitment":
      return FIELD_LEN + INPUT_PREFIX_BYTES * (count - 1);
    case "entry":
      return ENTRY_EVIDENCE_HEAD_LEN + ENTRY_INPUT_LEN * count;
  }
}

function shapeError(name: string): InterfaceError {
  return new InterfaceError("INTERFACE_INVALID_SHAPE", { name });
}
