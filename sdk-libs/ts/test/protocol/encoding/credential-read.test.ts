// The layouts and refusals of Rust `program-libs/interface/src/proof/credential_read.rs`.
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { Reader, Writer } from "@heliuslabs/zolana/internal";
import { treeIdField, type Bytes32 } from "@heliuslabs/zolana/interface";

import {
  CredentialRead,
  CredentialRoots,
  MAX_CREDENTIAL_READS,
} from "../../../src/protocol/codec/credential-read.js";

const invalid = (reason: string) =>
  expect.objectContaining({ code: "RING_TRANSACT_DATA_INVALID", details: { reason } });
const encoded = (read: CredentialRead): string => bytesToHex(read.write(new Writer()).finish());
const encodedState = (read: CredentialRead): string =>
  bytesToHex(read.writeState(new Writer()).finish());
const fill = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;

describe("the credential read", () => {
  it("encodes the empty read as 000000 and its merge state form as 00", () => {
    expect(encoded(CredentialRead.empty())).toBe("000000");
    expect(encodedState(CredentialRead.empty())).toBe("00");
    expect(CredentialRead.empty().encodedLength).toBe(3);
  });

  it("writes the address index then the state indexes little endian", () => {
    expect(encoded(CredentialRead.create(3, [1, 0x0201]))).toBe("0300020100" + "0102");
    expect(encodedState(CredentialRead.state(5))).toBe("010500");
    const reader = new Reader(hexToBytes("0300020100010299"));
    expect(CredentialRead.read(reader).stateRootIndexes).toEqual([1, 0x0201]);
    expect(reader.u8("rest")).toBe(0x99);
  });

  it("refuses an address index without a state root and a count past the ceiling", () => {
    expect(() => CredentialRead.read(new Reader(hexToBytes("010000")))).toThrow(
      invalid("InvalidCredentialRead"),
    );
    expect(() => CredentialRead.create(1, [])).toThrow(invalid("InvalidCredentialRead"));
    const past = Uint8Array.of(0, 0, MAX_CREDENTIAL_READS + 1);
    expect(() => CredentialRead.read(new Reader(past))).toThrow(invalid("InvalidCredentialRead"));
  });

  it("holds a merge state read to one root and no address index", () => {
    expect(() => CredentialRead.readState(new Reader(hexToBytes("0201000200")))).toThrow(
      invalid("InvalidCredentialRead"),
    );
    expect(() => CredentialRead.create(2, [1]).writeState(new Writer())).toThrow(
      invalid("InvalidCredentialRead"),
    );
  });

  it("requires a state root under a credential proof and none on a write", () => {
    expect(() => CredentialRead.empty().checkCapacity(2)).toThrow(invalid("InvalidCredentialRead"));
    expect(() => CredentialRead.create(0, [1, 2, 3]).checkCapacity(2)).toThrow(
      invalid("InvalidCredentialRead"),
    );
    expect(CredentialRead.create(0, [1, 2]).checkCapacity(2)).toBe(undefined);
    expect(CredentialRead.empty().checkEmpty()).toBe(undefined);
    expect(() => CredentialRead.state(0).checkEmpty()).toThrow(invalid("InvalidCredentialRead"));
  });
});

describe("the credential roots", () => {
  const owner = fill(9);
  const address = fill(8);

  it("pads the selected table with its first root and binds owner, address root, then pairs", () => {
    const roots = CredentialRoots.selected({
      ownerHash: owner,
      addressRoot: address,
      stateRoots: [
        { treeId: 1, root: fill(1) },
        { treeId: 3, root: fill(3) },
      ],
      capacity: 3,
    });
    expect(roots.elements()).toEqual([
      owner,
      address,
      treeIdField(1),
      fill(1),
      treeIdField(3),
      fill(3),
      treeIdField(1),
      fill(1),
    ]);
  });

  it("states an empty table as zeros at the capacity and a merge table with a zero address root", () => {
    expect(CredentialRoots.empty(2).elements()).toEqual(Array<Bytes32>(6).fill(fill(0)));
    expect(CredentialRoots.stateOnly(owner, { treeId: 4, root: fill(4) }).elements()).toEqual([
      owner,
      fill(0),
      treeIdField(4),
      fill(4),
    ]);
  });

  it("refuses an unsorted or repeated tree, a zero root and a table past its capacity", () => {
    const select =
      (stateRoots: readonly { treeId: number; root: Bytes32 }[], capacity = 2) =>
      () =>
        CredentialRoots.selected({ ownerHash: owner, addressRoot: address, stateRoots, capacity });
    for (const stateRoots of [
      [
        { treeId: 3, root: fill(3) },
        { treeId: 1, root: fill(1) },
      ],
      [
        { treeId: 1, root: fill(1) },
        { treeId: 1, root: fill(2) },
      ],
      [{ treeId: 1, root: fill(0) }],
      [],
    ])
      expect(select(stateRoots)).toThrow(invalid("InvalidCredentialRoots"));
    expect(select([{ treeId: 1, root: fill(1) }], 0)).toThrow(invalid("InvalidCredentialRead"));
    expect(
      select(
        [
          { treeId: 1, root: fill(1) },
          { treeId: 2, root: fill(2) },
        ],
        1,
      ),
    ).toThrow(invalid("InvalidCredentialRoots"));
  });
});
