/**
 * One planned key per transfer, Rust `pipeline::plan`. The key fixes every counter of the auditor
 * stream, so sealing, the proof request, the relay terms and the fit check read one
 * `PlannedTransfer`. The Rust Ring RPC keeps the seal only where both streams open alike,
 * otherwise the owner seals again and signs the new message.
 *
 * Read after `protocol/proof/transfer-shapes.ts`. Read before `pipeline.ts`.
 */
import {
  firstRecordCounter,
  type AuditStreamLayout,
} from "../../protocol/codec/ring-disclosure-layout.js";
import { RingError } from "../../protocol/error.js";
import {
  fittedSpend,
  type PolicyPoolCapacity,
  type TransferKeyCircuit,
  type TransferSpend,
} from "../../protocol/proof/transfer-shapes.js";
import { transferKeyCircuit } from "../../proof/transfer-proof.js";

/** One of the two rows a transfer's counts select between, the frame header's wide flag, Rust `SealRow`. */
export type SealRow = "narrow" | "wide";

export const NO_RECORD_POOLS: PolicyPoolCapacity = Object.freeze({
  own: 0,
  curator: 0,
  tracking: 0,
});

/** Rust `PlannedTransfer`. */
export interface PlannedTransfer {
  readonly circuit: TransferKeyCircuit;
  readonly wideOwners: boolean;
  readonly layout: AuditStreamLayout;
  readonly settlement: "inline" | "buffered";
  /** A data tail or a disclosed approval opening spans every slot of the key's `N`. */
  readonly spansCapacity: boolean;
}

/** What a planner adds to a key, every value public before any record read. */
export interface PlanFrame {
  /** `pools` empty and `wide` clear, a plan fills them. */
  readonly subjects: TransferSpend;
  /** The stream layout of a frame under the header's wide flag. */
  layoutUnder(wideOwners: boolean): AuditStreamLayout;
  readonly settlement: PlannedTransfer["settlement"];
  readonly spansCapacity: boolean;
}

/** The narrowest key holding the counts and `pools`, empty pools ahead of every record read. */
export function planTransfer(frame: PlanFrame, pools: PolicyPoolCapacity): PlannedTransfer {
  return keyedPlan(frame, fittedSpend({ ...frame.subjects, pools }));
}

/** The key of `row` whatever the reads, the row a reseal names. */
export function planTransferAt(frame: PlanFrame, row: SealRow): PlannedTransfer {
  return keyedPlan(frame, { ...frame.subjects, wide: row === "wide" });
}

/**
 * The key `read` selects, carrying the seal made under `sealed` or refusing until resealed.
 * Mirrors Rust `TransferShape::seals_like` over the two layouts, a tail or an approval opening
 * also needs the same `N`.
 */
export function rekeyedPlan(sealed: PlannedTransfer, read: PlannedTransfer): PlannedTransfer {
  const opensAlike =
    firstRecordCounter(sealed.layout.key) === firstRecordCounter(read.layout.key) &&
    (!sealed.spansCapacity || sealed.layout.capacity === read.layout.capacity);
  if (!opensAlike)
    throw new RingError("RING_RESEAL_REQUIRED", {
      details: { row: read.wideOwners ? "wide" : "narrow" },
    });
  return read;
}

function keyedPlan(frame: PlanFrame, spend: TransferSpend): PlannedTransfer {
  return Object.freeze({
    circuit: transferKeyCircuit(spend),
    wideOwners: spend.wide,
    layout: frame.layoutUnder(spend.wide),
    settlement: frame.settlement,
    spansCapacity: frame.spansCapacity,
  });
}
