/** The transfer key catalog, Rust `key_catalog.rs` and `Shapes` in `prover/circuits/transfer`. */
import { firstRecordCounter } from "../codec/ring-disclosure-layout.js";
import type { RingRail } from "../transaction/transact.js";
import { N_PUBLIC_SLOTS } from "../transaction/spp.js";

/** One transfer key, Rust `TransferShape`. */
export interface TransferShape {
  readonly outputs: number;
  /** The widest published input count the key serves. */
  readonly inputs: number;
  readonly withdrawals: number;
  /** Owner rows the key opens. */
  readonly owners: number;
  /** One evidence slot per input, the key also spends default-ring notes. */
  readonly entry: boolean;
  /** A salted and a public record per owner fit. */
  readonly wide: boolean;
}

const shape = (
  outputs: number,
  inputs: number,
  withdrawals: number,
  owners: number,
  entry: boolean,
  wide: boolean,
): TransferShape => Object.freeze({ outputs, inputs, withdrawals, owners, entry, wide });

/** Ascending outputs, a frame takes the first that holds its SPP width. */
const NARROW_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(2, 24, 4, 4, false, false),
  shape(4, 24, 4, 4, false, false),
  shape(8, 16, 4, 4, false, false),
  shape(16, 5, 8, 5, false, false),
]);
/** The wide flag takes the first row holding the frame, the last only past 24 inputs. */
const WIDE_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(8, 24, 32, 24, false, true),
  shape(16, 5, 8, 5, false, true),
  // Sized by the 8x16 rows of `ring-frame-fit.md`, those frames settle buffered. Wide alone, a
  // narrow row would leave a salted read of the same frame with no key.
  shape(16, 8, 8, 8, false, true),
  shape(2, 49, 4, 12, false, true),
]);
/** A frame takes the first row holding its width, the last sized by the 4x8 rows of `ring-frame-fit.md`. */
const ENTRY_SHAPES: readonly TransferShape[] = Object.freeze([
  shape(4, 8, 4, 8, true, true),
  shape(8, 2, 4, 2, true, true),
  shape(8, 4, 4, 4, true, true),
]);
/** Sized by the entry table of `ring-frame-fit.md`. */
const WIDE_ENTRY_SHAPE = shape(2, 24, 32, 12, true, true);

export const TRANSFER_SHAPES: readonly TransferShape[] = Object.freeze([
  ...NARROW_SHAPES,
  ...WIDE_SHAPES,
  ...ENTRY_SHAPES,
  WIDE_ENTRY_SHAPE,
]);

/** What names a frame's key, nothing else moves a record's counter, Rust `FrameKey`. */
export interface FrameKey {
  readonly rail: RingRail;
  /** `n`, the frame's nullifier count. */
  readonly inputs: number;
  readonly outputs: number;
  readonly spendsDefaultRing: boolean;
  readonly wide: boolean;
}

/** `undefined` when the catalog keys none, Rust `FrameKey::shape`. */
export function frameKeyShape(key: FrameKey): TransferShape | undefined {
  const holds = (entry: TransferShape): boolean =>
    key.outputs <= entry.outputs && key.inputs <= entry.inputs;
  // SPP's authority rail holds every input to the ring.
  if (key.spendsDefaultRing) {
    if (key.rail === "delegate" || key.rail === "anonymousDelegate") return undefined;
    return (key.wide ? [WIDE_ENTRY_SHAPE] : ENTRY_SHAPES).find(holds);
  }
  return (key.wide ? WIDE_SHAPES : NARROW_SHAPES).find(holds);
}

/** A transfer key, Rust `RingCircuit::Transfer`. */
export interface TransferKeyCircuit {
  readonly family: "transfer";
  readonly outputs: number;
  /** The widest published input count. */
  readonly class: number;
  readonly withdrawals: number;
  readonly owners: number;
  readonly entry: boolean;
  /** A salted and a public record per owner fit. */
  readonly wide: boolean;
}

/** A key's record pool widths, Rust `RecordPools`. */
export interface PolicyPoolCapacity {
  readonly own: number;
  readonly curator: number;
  readonly tracking: number;
}

/** What selects a transfer key, Rust `TransferSpend`. */
export interface TransferSpend {
  readonly rail: RingRail;
  /** Published inputs, the spent notes. */
  readonly inputs: number;
  readonly outputs: number;
  readonly spendsDefaultRing: boolean;
  /** Public withdrawal legs. */
  readonly legs: number;
  /** Distinct live input owners. */
  readonly owners: number;
  /** Distinct records the spend opens in each pool, a salted read takes a row beside the public one. */
  readonly pools: PolicyPoolCapacity;
  readonly wide: boolean;
}

/** The wide flag follows the narrow key failing to hold the spend, Rust `TransferSpend::fitted`. */
export function fittedSpend(spend: TransferSpend): TransferSpend {
  const narrow = frameKeyShape({ ...spend, wide: false });
  return { ...spend, wide: narrow === undefined || !shapeHolds(narrow, spend) };
}

/**
 * The wide flag a wallet seals under ahead of every record read, `pools` from `unreadSubjectPools`.
 * The reasoning stands at Rust `TransferSpend::sealed_wide`.
 */
export function sealedWide(spend: TransferSpend, hasData: boolean): boolean {
  if (fittedSpend({ ...spend, pools: { own: 0, curator: 0, tracking: 0 } }).wide) return true;
  const narrow = frameKeyShape({ ...spend, wide: false });
  const wide = frameKeyShape({ ...spend, wide: true });
  return (
    fittedSpend(spend).wide &&
    narrow !== undefined &&
    wide !== undefined &&
    !sealsLike(narrow, wide, hasData)
  );
}

/** What a wallet counts ahead of its reads on a table with a salted list, Rust `UnreadSubjects`. */
export interface UnreadSubjects {
  /** Distinct live input and output owners, plus one per leg since a destination stays unread. */
  readonly owners: number;
  /** Distinct live input, output and public assets. */
  readonly assets: number;
}

/** The widest read of these subjects, every owner enrolled with a public and a salted record. */
export function unreadSubjectPools(subjects: UnreadSubjects): PolicyPoolCapacity {
  const records = 2 * subjects.owners + subjects.assets;
  return Object.freeze({ own: records, curator: records, tracking: subjects.owners });
}

/** The one transfer key serving the spend, `undefined` when the catalog keys none. */
export function ringTransferCircuit(spend: TransferSpend): TransferKeyCircuit | undefined {
  const found = frameKeyShape(spend);
  return found === undefined || !shapeHolds(found, spend) ? undefined : shapeCircuit(found);
}

/** `S`, the owner signer slots of a key's statement chain, Go `Sections.Signers`. */
export function signerSlots(circuit: TransferKeyCircuit): number {
  return circuit.class;
}

/** Rust `RingCircuit::record_pools`, each pool takes as many subjects as records. */
export function transferPoolCapacity(circuit: TransferKeyCircuit): PolicyPoolCapacity {
  // Withdrawals settle through the public slots, their assets are at most N_PUBLIC_SLOTS.
  const withdrawalAssets = Math.min(circuit.withdrawals, N_PUBLIC_SLOTS);
  // An input slot takes no row, its asset reads a payment's record or a free one and a spend past
  // the rows selects the wide key.
  const distinct = circuit.owners + 2 * circuit.outputs + circuit.withdrawals + saltedKeys(circuit);
  return Object.freeze({
    own: distinct + Math.max(withdrawalAssets, N_PUBLIC_SLOTS),
    curator: distinct + withdrawalAssets,
    tracking: circuit.owners + circuit.outputs + trackedWithdrawals(circuit),
  });
}

/** The circuit type the prover serves the key under, Go `Key.circuitType`. */
export function transferCircuitType(circuit: TransferKeyCircuit): string {
  const family = circuit.entry ? "transfer-entry" : circuit.wide ? "transfer-wide" : "transfer";
  return `custom-ring-${family}-${circuit.outputs}-in${circuit.class}-w${circuit.withdrawals}-s${circuit.owners}`;
}

/** Every transfer key in the catalog's order, Go `keys`. */
export function transferKeys(): readonly TransferKeyCircuit[] {
  return TRANSFER_SHAPES.map(shapeCircuit);
}

/** Rust `MAX_DEPOSIT_ASSETS`. */
const MAX_DEPOSIT_ASSETS = 5;
const DEPOSIT_CAPACITIES: readonly number[] = Object.freeze([1, 2, 4, 8]);

/** One record per recipient and asset, and per salted key on the widest key, Rust `DepositSubjects::pool_width`. */
export function depositPoolWidth(capacity: number): number {
  const salted = capacity === DEPOSIT_CAPACITIES.at(-1) ? capacity : 0;
  return capacity + Math.min(capacity, MAX_DEPOSIT_ASSETS) + salted;
}

/** The narrowest key holding the deposit, Rust `DepositSubjects::key_capacity`. */
export function depositKeyCapacity(
  subjects: Readonly<{ slots: number; recipients: number; assets: number; saltedKeys: number }>,
): number | undefined {
  const records = subjects.recipients + subjects.assets + subjects.saltedKeys;
  return DEPOSIT_CAPACITIES.find(
    (capacity) => subjects.slots <= capacity && records <= depositPoolWidth(capacity),
  );
}

/** Addresses SPP takes beside its nullifier PDAs. */
const SPP_ADDRESSES = 4;
/** Ring program, ring, ring config, own, curator, tracking. */
const RING_ADDRESSES = 6;
/** Rust `MAX_TRANSACTION_ADDRESSES`, the v1 ceiling. */
const MAX_TRANSACTION_ADDRESSES = 64;
/** Go `ownerAddresses`. */
const OWNER_ADDRESSES = MAX_TRANSACTION_ADDRESSES - SPP_ADDRESSES - RING_ADDRESSES;

/** What takes a v1 transaction's addresses beside its owner signers, Rust `TransferAddresses`. */
export interface TransferAddresses {
  /** The shape's nullifier PDAs. */
  readonly nInputs: number;
  readonly coSigners: number;
  readonly legs: number;
}

/** Contract Output 5, the owner signers that fit, a co-signer takes its record too. */
export function ownerSignerCapacity(addresses: TransferAddresses): number {
  const taken =
    SPP_ADDRESSES + RING_ADDRESSES + addresses.nInputs + 2 * addresses.coSigners + addresses.legs;
  return Math.max(0, MAX_TRANSACTION_ADDRESSES - taken);
}

function shapeCircuit(entry: TransferShape): TransferKeyCircuit {
  return Object.freeze({
    family: "transfer",
    outputs: entry.outputs,
    class: entry.inputs,
    withdrawals: entry.withdrawals,
    owners: entry.owners,
    entry: entry.entry,
    wide: entry.wide,
  });
}

/** Rust `TransferShape::holds`. */
function shapeHolds(entry: TransferShape, spend: TransferSpend): boolean {
  const pools = transferPoolCapacity(shapeCircuit(entry));
  return (
    Number.isInteger(spend.inputs) &&
    spend.inputs >= 1 &&
    spend.inputs <= entry.inputs &&
    spend.legs <= entry.withdrawals &&
    spend.owners <= entry.owners &&
    spend.pools.own <= pools.own &&
    spend.pools.curator <= pools.curator &&
    spend.pools.tracking <= pools.tracking
  );
}

/** Rust `TransferShape::seals_like`. */
function sealsLike(left: TransferShape, right: TransferShape, hasData: boolean): boolean {
  const recordCounter = (entry: TransferShape): number =>
    firstRecordCounter({ class: entry.inputs, entry: entry.entry });
  return (
    recordCounter(left) === recordCounter(right) && (!hasData || left.outputs === right.outputs)
  );
}

/** Go `publicOwners`. */
function publicOwners(circuit: TransferKeyCircuit): number {
  const fit = Math.floor((OWNER_ADDRESSES - circuit.withdrawals) / 2);
  return Math.min(circuit.owners, fit) + circuit.withdrawals;
}

/** Go `trackedWithdrawals`. */
function trackedWithdrawals(circuit: TransferKeyCircuit): number {
  return circuit.wide ? publicOwners(circuit) - circuit.owners : 0;
}

/** Go `saltedKeys`. */
function saltedKeys(circuit: TransferKeyCircuit): number {
  return circuit.wide
    ? 2 * publicOwners(circuit) + circuit.outputs - circuit.owners - circuit.withdrawals
    : 0;
}
