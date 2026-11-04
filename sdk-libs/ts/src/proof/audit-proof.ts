/** The audit section of a ring transfer, the auditor stream and its opened slots. */
import { RING_INPUT_PADDING, ringInputOpening, ringOutputOpening } from "../rpc/prover/assembly.js";
import {
  bigIntBytes,
  bytesKey,
  isZero,
  mergeMintChunks,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import { equalBytes } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32, MessageData } from "@heliuslabs/zolana/interface";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { ProofInputUtxo, ProofOutputUtxo, TreeId } from "@heliuslabs/zolana/transaction";
import type {
  AuditEnvelopeProofInputs,
  EntryOpeningProofInput,
  OutputOpeningProofInput,
  RingSlotOpening,
} from "../rpc/prover/ring.js";
import {
  DUMMY_RECORD,
  EMPTY_ENTRY_INPUT,
  EMPTY_TAIL,
  RecordKind,
  type AuditEnvelope,
  type AuditRecord,
  type DataTail,
  type EntryInput,
} from "../protocol/codec/audit-stream.js";
import type { AuditLayout, AuditStreamLayout } from "../protocol/codec/ring-disclosure-layout.js";
import { compareField } from "../protocol/membership/owner-debits.js";
import { RingError } from "../protocol/error.js";
import { auditorMessageData } from "../crypto/audit/audit.js";
import { sealRingDisclosure, type RingDisclosure } from "../crypto/audit/ring-disclosure.js";

import type { PublishedSlot, RingOutputRail } from "../operations/payments/output-rail.js";

/** The auditor stream every transfer statement binds, Rust `SealedAudit`. */
export interface SealedAudit {
  /** The statement's layout element. */
  readonly audit: AuditLayout;
  readonly layout: AuditStreamLayout;
  readonly ephemeralPublicKey: X25519PublicKey;
  /** `tx_viewing_sk ‖ R ‖ evidence` under the auditor stream. */
  readonly envelope: Uint8Array;
  /** One per published slot. */
  readonly records: readonly Uint8Array[];
  /** One per published slot under `hasData`. */
  readonly tails?: readonly Uint8Array[];
  /** The proof's input, the caller wipes it once the proof returns. */
  readonly ephemeralSecret: Bytes32;
}

/** A fresh ephemeral key per build, one key and nonce serves one plaintext. */
export function sealAudit(
  input: Readonly<{
    rail: RingOutputRail;
    layout: AuditStreamLayout;
    published: readonly PublishedSlot[];
    /** The spent notes in SPP order, compact padding left out. */
    inputs: readonly ProofInputUtxo[];
    auditor: X25519PublicKey;
  }>,
): SealedAudit {
  const { layout } = input;
  const txViewingSecret = input.rail.txViewingKey.secretBytes();
  try {
    const sealed = sealRingDisclosure({
      layout,
      auditorPublicKey: input.auditor,
      disclosure: auditDisclosure({
        txViewingSecret,
        layout,
        outputs: input.published.map((slot) => slot.output),
        inputs: input.inputs,
      }),
    });
    return Object.freeze({
      audit: Object.freeze({ hasData: layout.hasData, entry: layout.key.entry }),
      layout,
      ...sealed,
    });
  } finally {
    txViewingSecret.fill(0);
  }
}

/** The message the program expands under the auditor's view tag, Rust `SealedAudit::message`. */
export function sealedAuditMessage(sealed: SealedAudit, auditor: X25519PublicKey): MessageData {
  return auditorMessageData(sealed, auditor);
}

/** Every plaintext of one transfer's stream, pure over its values. */
export function auditDisclosure(
  input: Readonly<{
    txViewingSecret: Bytes32;
    layout: AuditStreamLayout;
    /** The published slots' proof outputs. */
    outputs: readonly ProofOutputUtxo[];
    inputs: readonly ProofInputUtxo[];
  }>,
): RingDisclosure {
  const { layout, outputs, inputs } = input;
  return Object.freeze({
    envelope: auditEnvelopeOf(input.txViewingSecret, inputs, layout.key.entry),
    records: Object.freeze(outputs.map(outputRecord)),
    ...(layout.hasData ? { tails: Object.freeze(outputs.map(outputTail)) } : {}),
  });
}

/** `R ‖ default_input_bits ‖ entries` past the sealed key. */
function auditEnvelopeOf(
  txViewingSecret: Bytes32,
  inputs: readonly ProofInputUtxo[],
  entry: boolean,
): AuditEnvelope {
  const realInputs = realInputCount(inputs);
  if (!entry) return { txViewingSecret, realInputs, evidence: { kind: "none" } };
  return {
    txViewingSecret,
    realInputs,
    evidence: {
      kind: "entry",
      defaultInputBits: defaultInputBits(inputs),
      inputs: inputs.map(entryInput),
    },
  };
}

/** `R`, a live note past a dummy would escape the spend index. */
export function realInputCount(inputs: readonly ProofInputUtxo[]): number {
  const live = inputs.filter(isLive).length;
  if (inputs.slice(0, live).some((input) => !isLive(input)))
    throw new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason: "DummiesLast" } });
  return live;
}

/** Bit `i` set for a live default-ring input. */
export function defaultInputBits(inputs: readonly ProofInputUtxo[]): bigint {
  return inputs.reduce(
    (bits, input, index) => (isDefaultRing(input) ? bits | (1n << BigInt(index)) : bits),
    0n,
  );
}

/** Zero fields off a live default-ring input, never a secret. */
export function entryInput(input: ProofInputUtxo): EntryInput {
  if (!isDefaultRing(input)) return EMPTY_ENTRY_INPUT;
  const { utxo } = input;
  return Object.freeze({
    ownerKey: utxo.owner.confidentialViewTag() as Bytes32,
    nullifierPk: input.nullifierPublicKey,
    amount: utxo.amount,
    mint: utxo.asset,
    blinding: utxo.blinding,
    dataHash: input.dataHash ?? ZERO_32,
    ringDataHash: input.ringDataHash ?? ZERO_32,
  });
}

/** The circuit derives the kind from the slot's domain and ring id, a dummy's plaintext is zero. */
export function outputRecord(output: ProofOutputUtxo): AuditRecord {
  const owner = output.ownerAddress;
  if (owner === undefined) return DUMMY_RECORD;
  return Object.freeze({
    kind: output.ringProgramId === undefined ? RecordKind.exit : RecordKind.ring,
    amount: output.amount,
    ownerKey: owner.signingPublicKey.confidentialViewTag() as Bytes32,
    mint: output.asset,
    nullifierPk: owner.nullifierPublicKey,
  });
}

/** Zero on a dummy. */
export function outputTail(output: ProofOutputUtxo): DataTail {
  if (output.ownerAddress === undefined) return EMPTY_TAIL;
  return Object.freeze({
    dataHash: output.dataHash ?? ZERO_32,
    ringDataHash: output.ringDataHash ?? ZERO_32,
  });
}

/** Go `AuditParams`, the secret copied last, a refusal before it leaves no copy to wipe. */
export function auditEnvelope(
  input: Readonly<{
    rail: RingOutputRail;
    sealed: SealedAudit;
    firstNullifier: Bytes32;
    auditor: X25519PublicKey;
  }>,
): AuditEnvelopeProofInputs {
  return Object.freeze({
    firstNullifier: input.firstNullifier,
    ephSk: input.sealed.ephemeralSecret,
    auditorPk: input.auditor.u(),
    salt: input.rail.salt,
    layout: input.sealed.audit,
    txViewingSk: input.rail.txViewingKey.secretBytes(),
  });
}

/** Go `OutputOpening` per slot of the key's capacity, an omitted suffix slot runs on its own padding proof output. */
export function outputOpenings(
  outputs: readonly ProofOutputUtxo[],
  tree: TreeId,
): readonly OutputOpeningProofInput[] {
  return Object.freeze(
    outputs.map((output) =>
      Object.freeze({
        output: ringOutputOpening(output, tree),
        ...(output.ownerAddress === undefined
          ? zeroEntryOpening()
          : {
              ownerKey: output.ownerAddress.signingPublicKey.confidentialViewTag() as Bytes32,
              mintChunks: mintChunks(output.asset),
            }),
      }),
    ),
  );
}

/** The spent notes' openings in SPP order, padding past them to the key's input class. */
export function inputOpenings(
  inputs: readonly ProofInputUtxo[],
  inputClass: number,
): readonly RingSlotOpening[] {
  return Object.freeze([
    ...inputs.map(ringInputOpening),
    ...Array.from({ length: inputClass - inputs.length }, () => RING_INPUT_PADDING),
  ]);
}

/** Go `EntryOpening` per input slot on an entry key, zero off a default-ring input. */
export function entryOpenings(
  inputs: readonly ProofInputUtxo[],
  inputClass: number,
): readonly EntryOpeningProofInput[] {
  return Object.freeze(
    Array.from({ length: inputClass }, (_, slot) => {
      const input = inputs[slot];
      return input === undefined || !isDefaultRing(input)
        ? zeroEntryOpening()
        : {
            ownerKey: input.utxo.owner.confidentialViewTag() as Bytes32,
            mintChunks: mintChunks(input.utxo.asset),
          };
    }),
  );
}

/** Contract Output 4, distinct live input owners ascending as field integers, zero rows last, a delegate rail's zero-key note needs no row. */
export function ownerRows(
  input: Readonly<{
    inputs: readonly ProofInputUtxo[];
    delegate: boolean;
    /** The key's rows, absent returns the live rows alone. */
    slots?: number;
  }>,
): readonly Bytes32[] {
  const owners = new Map<string, Bytes32>();
  for (const spent of input.inputs) {
    if (!isLive(spent)) continue;
    if (input.delegate && equalBytes(spent.nullifierPublicKey, ZERO_NULLIFIER_PK)) continue;
    const owner = spent.utxo.owner.ownerProofInputHash();
    if (!isZero(owner)) owners.set(bytesKey(owner), owner);
  }
  const rows = [...owners.values()].sort(compareField);
  const { slots } = input;
  if (slots === undefined) return Object.freeze(rows);
  if (rows.length > slots)
    throw new RingError("RING_TOO_MANY_OWNERS", {
      details: { owners: rows.length, maximum: slots },
    });
  return Object.freeze([...rows, ...Array<Bytes32>(slots - rows.length).fill(ZERO_32)]);
}

function isLive(input: ProofInputUtxo): boolean {
  return !input.isCompact() && !input.isDummy();
}

function isDefaultRing(input: ProofInputUtxo): boolean {
  return isLive(input) && input.utxo.ringProgramId === undefined;
}

function zeroEntryOpening(): EntryOpeningProofInput {
  return { ownerKey: ZERO_32, mintChunks: [ZERO_32, ZERO_32] };
}

function mintChunks(mint: Address): readonly Bytes32[] {
  return mergeMintChunks(mint).map((chunk) => bigIntBytes(chunk) as Bytes32);
}
