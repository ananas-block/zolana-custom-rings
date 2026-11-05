/** The transfer key catalog, Rust `key_catalog.rs` and `Shapes` in `prover/circuits/transfer`. */
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
  /** Tracking openings, Rust `RecordPools::tracking`. */
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

/** Rust `SPP_ADDRESSES`, the addresses SPP takes beside its nullifier PDAs. */
const SPP_ADDRESSES = 4;
/** Rust `RING_ADDRESSES`, ring program, policy, config, own, curator and tracking registries. */
const RING_ADDRESSES = 6;
/** Rust `MAX_TRANSACTION_ADDRESSES`, the v1 ceiling. */
export const MAX_TRANSACTION_ADDRESSES = 64;

/** What takes a v1 transaction's addresses beside its owner signers, Rust `TransferAddresses`. */
export interface TransferAddresses {
  /** The shape's nullifier PDAs. */
  readonly nInputs: number;
  readonly coSigners: number;
  readonly legs: number;
}

/** Rust `TransferAddresses::owner_signers`, a co-signer takes its record too. */
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

/** Rust `RowAuthorization`. */
export interface RowAuthorization {
  /** Rows outside the owner run, each takes its nullifier PDA alone. */
  readonly unsignedRows: number;
  /** Every withdrawal names one destination. */
  readonly hiddenExit: boolean;
  readonly enters: boolean;
}

const ROW_AUTHORIZATIONS: readonly RowAuthorization[] = Object.freeze([
  { unsignedRows: 0, hiddenExit: false, enters: true },
  { unsignedRows: 1, hiddenExit: false, enters: false },
  { unsignedRows: 1, hiddenExit: true, enters: true },
]);

/** Rust `TransferAddresses::owner_rows`, one bound for the catalog's pools and the owner check. */
export function ownerRows(authorization: RowAuthorization, addresses: TransferAddresses): number {
  return ownerSignerCapacity(addresses) + authorization.unsignedRows;
}

/** Rust `TransferShape::public_owners`, each row spends one note. */
function publicOwners(circuit: TransferKeyCircuit): number {
  let most = 0;
  for (const authorization of ROW_AUTHORIZATIONS) {
    if (circuit.entry && !authorization.enters) continue;
    for (let legs = 0; legs <= circuit.withdrawals; legs += 1) {
      let rows = circuit.owners;
      while (rows > 0 && rows > ownerRows(authorization, { nInputs: rows, coSigners: 0, legs }))
        rows -= 1;
      const legOwners = authorization.hiddenExit ? Math.min(legs, 1) : legs;
      most = Math.max(most, rows + legOwners);
    }
  }
  return most;
}

/** Withdrawal owners a wide key opens a tracking row for, Go `trackedWithdrawals`. */
function trackedWithdrawals(circuit: TransferKeyCircuit): number {
  return circuit.wide ? publicOwners(circuit) - circuit.owners : 0;
}

/** Go `saltedKeys`. */
function saltedKeys(circuit: TransferKeyCircuit): number {
  return circuit.wide
    ? 2 * publicOwners(circuit) + circuit.outputs - circuit.owners - circuit.withdrawals
    : 0;
}
