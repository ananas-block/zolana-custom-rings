import { describe, expect, it } from "vitest";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { ZERO_32 } from "@heliuslabs/zolana/internal";
import vector from "../../../../../test-vectors/registry/mint-records.json" with { type: "json" };
import {
  EMPTY_MINT_POLICY,
  mintPolicyField,
} from "../../../src/protocol/membership/mint-policy.js";
import {
  queueEntryHash,
  verifyRecordOpening,
} from "../../../src/protocol/membership/member-opening.js";
import { recordTree } from "../../helpers/member-registry.js";

const field = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex")) as Bytes32;
const records = vector.rows.map((row) => ({
  member: field(row.member),
  lists: 0n,
  mintPolicy: {
    threshold: BigInt(row.amount),
    cap: BigInt(row.amount),
    cosignAbove: BigInt(row.amount),
    withdrawalThreshold: BigInt(row.amount),
  },
}));
describe("mint records shared with Rust and Go", () => {
  it("authenticates twelve settings including u64 maximums", () => {
    const tree = recordTree(records);
    expect(Buffer.from(tree.root).toString("hex")).toBe(vector.root);
    for (const [i, record] of records.entries()) {
      expect(Buffer.from(mintPolicyField(record.mintPolicy)).toString("hex")).toBe(
        vector.rows[i]!.field,
      );
      expect(
        Buffer.from(
          queueEntryHash({ ...record, mask: 0n, value: 0n, escrowKey: ZERO_32 }),
        ).toString("hex"),
      ).toBe(vector.rows[i]!.entry_hash);
      expect(() =>
        verifyRecordOpening(tree.opening(record.member), tree.root, record.member),
      ).not.toThrow();
    }
    const opening = tree.opening(records[8]!.member);
    if (opening.kind !== "present") throw new Error("missing ninth mint");
    expect(() =>
      verifyRecordOpening(
        { ...opening, record: { ...opening.record, mintPolicy: EMPTY_MINT_POLICY } },
        tree.root,
        opening.record.member,
      ),
    ).toThrow();
  });
  it.each(["threshold", "cap", "cosignAbove", "withdrawalThreshold"] as const)(
    "rejects %s outside u64",
    (name) => {
      for (const amount of [-1n, 1n << 64n])
        expect(() => mintPolicyField({ ...EMPTY_MINT_POLICY, [name]: amount })).toThrow();
    },
  );
});
