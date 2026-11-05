/**
 * The credential root selection a ring frame carries and the root table its statement binds, Rust
 * `custom_ring_interface::credential_read`. Transfer and deposit reads name an address root index and
 * the state root indexes, a merge read names one state root alone.
 * Read after `protocol/codec/audit-stream.ts`. Read before `protocol/transaction/transact.ts`.
 */
import { Reader, Writer } from "@heliuslabs/zolana/internal";
import { treeIdField, type Bytes32 } from "@heliuslabs/zolana/interface";

import { MAX_TRANSACTION_ADDRESSES } from "../proof/transfer-shapes.js";
import { RingError } from "../error.js";

/** Rust `MAX_CREDENTIAL_READS`, one state tree per transaction address at most. */
export const MAX_CREDENTIAL_READS = MAX_TRANSACTION_ADDRESSES;

/** Rust `CredentialStateRoot`. */
export interface CredentialStateRoot {
  readonly treeId: number;
  readonly root: Bytes32;
}

/** Rust `CredentialRead`, an empty state selection holds address index zero. */
export class CredentialRead {
  readonly addressRootIndex: number;
  readonly stateRootIndexes: readonly number[];

  private constructor(addressRootIndex: number, stateRootIndexes: readonly number[]) {
    this.addressRootIndex = addressRootIndex;
    this.stateRootIndexes = Object.freeze([...stateRootIndexes]);
  }

  /** Encodes `000000`, a merge state read `00`. */
  static empty(): CredentialRead {
    return new CredentialRead(0, []);
  }

  static create(addressRootIndex: number, stateRootIndexes: readonly number[]): CredentialRead {
    if (stateRootIndexes.length > MAX_CREDENTIAL_READS) throw invalidRead();
    const indexes = stateRootIndexes.map((index) => u16(index));
    if (indexes.length === 0 && u16(addressRootIndex) !== 0) throw invalidRead();
    return new CredentialRead(u16(addressRootIndex), indexes);
  }

  /** One state root and no address root, the merge read. */
  static state(rootIndex: number): CredentialRead {
    return new CredentialRead(0, [u16(rootIndex)]);
  }

  /** `u16le(address_root_index) ‖ count ‖ u16le(state_root_index)...`. */
  static read(reader: Reader): CredentialRead {
    const addressRootIndex = reader.u16("credentialRead.addressRootIndex");
    return CredentialRead.create(addressRootIndex, readIndexes(reader));
  }

  /** `count ‖ u16le(state_root_index)`, at most one index. */
  static readState(reader: Reader): CredentialRead {
    const read = CredentialRead.create(0, readIndexes(reader));
    read.checkState();
    return read;
  }

  get isEmpty(): boolean {
    return this.stateRootIndexes.length === 0;
  }

  get encodedLength(): number {
    return 3 + 2 * this.stateRootIndexes.length;
  }

  write(writer: Writer): Writer {
    writer.u16(this.addressRootIndex, "credentialRead.addressRootIndex");
    return this.#writeIndexes(writer);
  }

  writeState(writer: Writer): Writer {
    this.checkState();
    return this.#writeIndexes(writer);
  }

  /** A credential proof reads at least one state root, absence included. */
  checkCapacity(capacity: number): void {
    checkCapacity(capacity);
    if (this.isEmpty || this.stateRootIndexes.length > capacity) throw invalidRead();
  }

  /** A write or an owner signed merge proves no credential. */
  checkEmpty(): void {
    if (!this.isEmpty || this.addressRootIndex !== 0) throw invalidRead();
  }

  checkState(): void {
    if (this.addressRootIndex !== 0 || this.stateRootIndexes.length > 1) throw invalidRead();
  }

  #writeIndexes(writer: Writer): Writer {
    writer.u8(this.stateRootIndexes.length, "credentialRead.count");
    for (const index of this.stateRootIndexes) writer.u16(index, "credentialRead.stateRootIndex");
    return writer;
  }
}

/** Rust `CredentialRoots`, the statement elements of one credential read. */
export class CredentialRoots {
  readonly ownerHash: Bytes32;
  readonly addressRoot: Bytes32;
  readonly stateRoots: readonly CredentialStateRoot[];

  private constructor(
    ownerHash: Bytes32,
    addressRoot: Bytes32,
    stateRoots: readonly CredentialStateRoot[],
  ) {
    this.ownerHash = ownerHash;
    this.addressRoot = addressRoot;
    this.stateRoots = Object.freeze(stateRoots.map((entry) => Object.freeze({ ...entry })));
  }

  /** Zero owner, zero address root and `capacity` zero state pairs, a frame that reads no credential. */
  static empty(capacity: number): CredentialRoots {
    checkCapacity(capacity);
    return new CredentialRoots(
      zero(),
      zero(),
      Array.from({ length: capacity }, () => ({ treeId: 0, root: zero() })),
    );
  }

  /**
   * Rust `CredentialRootSelection::roots`. The program pads with the first selected root, a prover
   * padding with zeros states another table.
   */
  static selected(
    input: Readonly<{
      /** `credential_owner(ring_program)`, the ring's credential PDA owner hash. */
      ownerHash: Bytes32;
      addressRoot: Bytes32;
      stateRoots: readonly CredentialStateRoot[];
      capacity: number;
    }>,
  ): CredentialRoots {
    const { stateRoots, capacity } = input;
    checkRoots(stateRoots, capacity);
    const first = stateRoots[0] as CredentialStateRoot;
    return new CredentialRoots(input.ownerHash, input.addressRoot, [
      ...stateRoots,
      ...Array.from({ length: capacity - stateRoots.length }, () => first),
    ]);
  }

  /** Rust `CredentialRoots::state_only`, the merge table with a zero address root. */
  static stateOnly(ownerHash: Bytes32, stateRoot: CredentialStateRoot): CredentialRoots {
    checkRoots([stateRoot], 1);
    return new CredentialRoots(ownerHash, zero(), [stateRoot]);
  }

  get capacity(): number {
    return this.stateRoots.length;
  }

  /** `[owner, address_root, tree_id_0, root_0, ...]`. */
  elements(): readonly Bytes32[] {
    return Object.freeze([this.ownerHash, this.addressRoot, ...this.stateElements()]);
  }

  stateElements(): readonly Bytes32[] {
    return Object.freeze(
      this.stateRoots.flatMap(({ treeId, root }) => [treeIdField(treeId), root]),
    );
  }
}

function readIndexes(reader: Reader): readonly number[] {
  const count = reader.u8("credentialRead.count");
  if (count > MAX_CREDENTIAL_READS) throw invalidRead();
  return Array.from({ length: count }, () => reader.u16("credentialRead.stateRootIndex"));
}

function checkCapacity(capacity: number): void {
  if (!Number.isInteger(capacity) || capacity < 1 || capacity > MAX_CREDENTIAL_READS)
    throw invalidRead();
}

/** Distinct ascending tree ids, a zero root names no retained state. */
function checkRoots(roots: readonly CredentialStateRoot[], capacity: number): void {
  checkCapacity(capacity);
  if (
    roots.length === 0 ||
    roots.length > capacity ||
    roots.some((entry) => entry.root.every((byte) => byte === 0)) ||
    roots.some(
      (entry, index) =>
        index > 0 && (roots[index - 1] as CredentialStateRoot).treeId >= entry.treeId,
    )
  )
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "InvalidCredentialRoots" },
    });
}

function u16(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw invalidRead();
  return value;
}

function zero(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}

function invalidRead(): RingError {
  return new RingError("RING_TRANSACT_DATA_INVALID", {
    details: { reason: "InvalidCredentialRead" },
  });
}
