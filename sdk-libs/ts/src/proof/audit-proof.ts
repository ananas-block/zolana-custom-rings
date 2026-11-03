/** The audit section of a ring transfer, the auditor stream and its opened slots, Rust `pipeline::audit`. */
import { EMPTY_RING_OPENING, ringInputOpening, ringOutputOpening } from "../rpc/prover/assembly.js";
import type { Bytes32, MessageData } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import { assetField, type SppProofInputs } from "@heliuslabs/zolana/transaction";
import type { ProofOutputUtxo } from "@heliuslabs/zolana/transaction";
import type {
  AnonymousSlotProofInputs,
  AuditEnvelopeProofInputs,
  DeliveredSlotProofInputs,
  RingSlotOpening,
} from "../rpc/prover/ring.js";
import {
  deliveredBodyLen,
  type AuditLayout,
  type AuditStreamLayout,
} from "../protocol/codec/ring-disclosure-layout.js";
import { auditorMessageData } from "../crypto/audit/audit.js";
import {
  anonymousCommitments,
  inputPrefixes,
  sealRingDisclosure,
  type AnonymousInputs,
  type AnonymousOutputOpening,
  type DeliveredInputs,
  type DeliveredOutputOpening,
  type RingDisclosure,
} from "../crypto/audit/ring-disclosure.js";

import type { PublishedSlot, RingOutputRail } from "../operations/payments/output-rail.js";

/** The auditor stream every transfer statement binds, Rust `SealedAudit`. */
export interface SealedAudit {
  /** The statement's layout element. */
  readonly audit: AuditLayout;
  readonly layout: AuditStreamLayout;
  readonly ephemeralPublicKey: X25519PublicKey;
  /** `tx_viewing_sk ‖ evidence` under the auditor stream. */
  readonly envelope: Uint8Array;
  /** The records of the slots that have one, in slot order. */
  readonly records: readonly Uint8Array[];
  /** The proof's input, the caller wipes it once the proof returns. */
  readonly ephemeralSecret: Bytes32;
}

/** Rust `AuditSeal::seal`, a fresh ephemeral key per build since one key and nonce serves one plaintext. */
export function sealAudit(
  input: Readonly<{
    rail: RingOutputRail;
    audit: AuditLayout;
    layout: AuditStreamLayout;
    published: readonly PublishedSlot[];
    proofInputs: SppProofInputs;
    sender: ShieldedAddress;
    auditor: X25519PublicKey;
  }>,
): SealedAudit {
  const disclosure = auditDisclosure(input);
  const txViewingSecret = input.rail.txViewingKey.secretBytes();
  try {
    const sealed = sealRingDisclosure({
      txViewingSecret,
      auditorPublicKey: input.auditor,
      disclosure,
    });
    return Object.freeze({ audit: input.audit, layout: input.layout, ...sealed });
  } finally {
    txViewingSecret.fill(0);
  }
}

/** The message the program expands under the auditor's view tag, Rust `SealedAudit::message`. */
export function sealedAuditMessage(sealed: SealedAudit, auditor: X25519PublicKey): MessageData {
  return auditorMessageData(sealed, auditor);
}

/** Go `AuditParams`, the secret copied last, a refusal before it leaves no copy to wipe. */
export function auditEnvelope(
  input: Readonly<{
    rail: RingOutputRail;
    sealed: SealedAudit;
    proofInputs: SppProofInputs;
    auditor: X25519PublicKey;
  }>,
): AuditEnvelopeProofInputs {
  return Object.freeze({
    firstNullifier: input.proofInputs.firstNullifier(),
    ephSk: input.sealed.ephemeralSecret,
    auditorPk: input.auditor.u(),
    salt: input.rail.salt,
    layout: input.sealed.audit,
    txViewingSk: input.rail.txViewingKey.secretBytes(),
  });
}

/** Rust `AuditSection::delivered_outputs`. */
export function deliveredSlots(
  published: readonly PublishedSlot[],
  tree: number,
  keyEscrow: boolean,
): readonly DeliveredSlotProofInputs[] {
  return published.map((slot) => deliveredSlot(slot, tree, keyEscrow));
}

/** Rust `AuditSection::anonymous_outputs`. */
export function anonymousSlots(
  published: readonly PublishedSlot[],
  tree: number,
): readonly AnonymousSlotProofInputs[] {
  return published.map((slot) => anonymousSlot(slot, tree));
}

/** The spent notes' openings in SPP order, zero past them to the key's input class, Rust `AuditSection::input_openings`. */
export function inputOpenings(
  proofInputs: SppProofInputs,
  inputClass: number,
): readonly RingSlotOpening[] {
  const openings = proofInputs.inputUtxos
    .filter((spent) => !spent.isCompact())
    .map(ringInputOpening);
  return [
    ...openings,
    ...Array.from({ length: inputClass - openings.length }, () => EMPTY_RING_OPENING),
  ];
}

/** Rust `AuditSeal::evidence` and `output_record` per slot. */
function auditDisclosure(
  input: Readonly<{
    layout: AuditStreamLayout;
    published: readonly PublishedSlot[];
    proofInputs: SppProofInputs;
    sender: ShieldedAddress;
  }>,
): RingDisclosure {
  const { layout, published } = input;
  if (layout.key.kind === "confidential")
    return {
      kind: "delivered",
      layout,
      inputs: deliveredInputs(layout.key.inputPrefixes, input.proofInputs),
      outputs: published.map((slot) => deliveredOpening(slot, layout.keyEscrow)),
    };
  return {
    kind: "anonymous",
    layout,
    outputs: published.map(anonymousOpening),
    inputs: anonymousInputs(layout.key.kind, input.proofInputs, input.sender),
  };
}

function deliveredInputs(named: boolean, proofInputs: SppProofInputs): DeliveredInputs {
  if (!named) return { kind: "none" };
  return { kind: "prefixes", prefixes: inputPrefixes(publishedInputHashes(proofInputs)) };
}

function publishedInputHashes(proofInputs: SppProofInputs): readonly (Bytes32 | undefined)[] {
  return proofInputs.inputUtxos
    .filter((input) => !input.isCompact())
    .map((input) => (input.isDummy() ? undefined : input.hash()));
}

function anonymousInputs(
  key: "commitment" | "entry",
  proofInputs: SppProofInputs,
  sender: ShieldedAddress,
): AnonymousInputs {
  if (key === "commitment") return anonymousCommitments(publishedInputHashes(proofInputs));
  const spent = proofInputs.inputUtxos.filter((input) => !input.isCompact());
  return {
    kind: "openings",
    senderKey: sender.signingPublicKey.confidentialViewTag(),
    senderNullifierPk: sender.nullifierPublicKey,
    inputs: spent.map((input) => {
      if (input.isDummy()) return undefined;
      return {
        asset: assetField(input.utxo.asset),
        amount: input.utxo.amount,
        blinding: input.utxo.blinding,
      };
    }),
  };
}

/** A dummy and a ring output publish a delivered body, only an exit has a record. */
function deliveredOpening(slot: PublishedSlot, keyEscrow: boolean): DeliveredOutputOpening {
  const { output, wire } = slot;
  const owner = output.ownerAddress;
  if (wire.kind !== "exit" || owner === undefined) return { kind: "body" };
  return {
    kind: "exit",
    nullifierPk: keyEscrow ? undefined : owner.nullifierPublicKey,
    asset: assetField(output.asset),
    amount: output.amount,
  };
}

function anonymousOpening(slot: PublishedSlot): AnonymousOutputOpening {
  const { output } = slot;
  const owner = output.ownerAddress;
  if (owner === undefined) return { kind: "dummy" };
  if (slot.wire.kind === "exit")
    return {
      kind: "exit",
      nullifierPk: owner.nullifierPublicKey,
      asset: assetField(output.asset),
      amount: output.amount,
    };
  return {
    kind: "ring",
    nullifierPk: owner.nullifierPublicKey,
    ownerKey: owner.signingPublicKey.confidentialViewTag(),
    asset: assetField(output.asset),
    amount: output.amount,
  };
}

/** A ring output opens its body for its recipient, padding binds its published key and body. */
function deliveredSlot(
  slot: PublishedSlot,
  tree: number,
  keyEscrow: boolean,
): DeliveredSlotProofInputs {
  const { output, wire } = slot;
  const zero = zeroField();
  const [recipientKey, body] =
    wire.kind === "delivered"
      ? [wire.u, wire.body]
      : [zero, new Uint8Array(deliveredBodyLen(keyEscrow))];
  const ring = !output.isDummy() && wire.kind !== "exit";
  return Object.freeze({
    output: ringOutputOpening(output, tree),
    recipientKey,
    ownerKey: ring ? slotOwnerKey(output) : zero,
    body,
  });
}

/** An exit's owner key stays where zolana publishes it, a dummy names none. */
function anonymousSlot(slot: PublishedSlot, tree: number): AnonymousSlotProofInputs {
  return Object.freeze({
    output: ringOutputOpening(slot.output, tree),
    ownerKey: slotOwnerKey(slot.output),
  });
}

/** The owner's Solana key a slot discloses, zero for padding, Rust `slot_owner_key`. */
function slotOwnerKey(output: ProofOutputUtxo): Bytes32 {
  return output.ownerAddress?.signingPublicKey.confidentialViewTag() ?? zeroField();
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}
