import { beforeAll, describe, expect, it } from "vitest";

import empty from "../../../../../test-vectors/registry/empty_root.json" with { type: "json" };
import { initializePoseidon } from "@heliuslabs/zolana";
import { poseidon } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import {
  MEMBER_REGISTRY_EMPTY_ROOT,
  SENTINEL_RECORD,
  memberRecordHash,
  quadPathRoot,
} from "../../../src/protocol/membership/member-opening.js";
import { QUAD_HEIGHT } from "../../../src/protocol/membership/member-registry.js";
import { recordTree } from "../../helpers/member-registry.js";

function field(value: string): Bytes32 {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== 32) throw new RangeError("expected 32 bytes");
  return decoded as Bytes32;
}

function hex(value: Readonly<ArrayLike<number>> | undefined): string {
  return Buffer.from(Uint8Array.from(value ?? [])).toString("hex");
}

beforeAll(initializePoseidon);

describe("empty_root.json", () => {
  it("folds the sentinel over the zero subtrees to the registry's first root", () => {
    expect(hex(memberRecordHash(SENTINEL_RECORD))).toBe(empty.sentinel.leaf_hash);
    expect(empty.zero_subtrees.length).toBeGreaterThan(QUAD_HEIGHT);
    empty.zero_subtrees.slice(1).forEach((node, level) => {
      const below = field(empty.zero_subtrees[level] ?? "");
      expect(hex(poseidon([below, below, below, below]))).toBe(node);
    });
    const siblings = empty.zero_subtrees
      .slice(0, QUAD_HEIGHT)
      .map((node) => [field(node), field(node), field(node)]);
    const root = quadPathRoot({ index: 0, siblings }, memberRecordHash(SENTINEL_RECORD));
    expect(hex(root)).toBe(empty.empty_root);
    expect(hex(MEMBER_REGISTRY_EMPTY_ROOT)).toBe(empty.empty_root);
    expect(hex(recordTree().root)).toBe(empty.empty_root);
  });
});
