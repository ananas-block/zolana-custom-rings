import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import rulesVector from "../../../../../test-vectors/policy/ring-policy-rules.json" with { type: "json" };
import { EMPTY_MINT_POLICY } from "../../../src/protocol/membership/mint-policy.js";
import {
  admitTransfer,
  decodeRule,
  decodeRuleTable,
  policyTableFields,
  policyTableHash,
  type RecordLists,
} from "../../../src/protocol/membership/policy.js";

await initializePoseidon();

const field = (text: string): Bytes32 => hexToBytes(text) as Bytes32;

interface TableCase {
  readonly name: string;
  readonly sources: readonly Readonly<{ list_id: number; registry: string }>[];
  readonly salted: number;
  readonly rules: readonly string[];
  readonly fields: readonly string[];
  readonly policy_hash: string;
}

/** A u64 threshold passes a double, the rows carry it as hex and `rule_parts` is unread. */
const tableVector = JSON.parse(
  readFileSync(
    new URL("../../../../../test-vectors/policy/ring-policy-table.json", import.meta.url),
    "utf8",
  ),
) as Readonly<{ cases: readonly TableCase[] }>;

describe("ring-policy-table.json", () => {
  it.each(tableVector.cases.map((vector) => [vector.name, vector] as const))("%s", (_, vector) => {
    const table = { rules: vector.rules.map((row) => decodeRule(field(row))) };
    const sources = {
      slots: vector.sources.map((slot) => ({
        listId: slot.list_id,
        registry: field(slot.registry),
      })),
      salted: vector.salted,
    };
    expect(policyTableFields(table, sources).map((row) => bytesToHex(row))).toEqual(vector.fields);
    expect(bytesToHex(policyTableHash(table, sources))).toBe(vector.policy_hash);
  });
});

describe("ring-policy-rules.json", () => {
  type Case = (typeof rulesVector.cases)[number];
  const expected = (outcome: Case["outcome"]) =>
    outcome.kind === "pass"
      ? undefined
      : {
          kind: "lists",
          rule: outcome.rule,
          subject:
            outcome.subject === "sender"
              ? { kind: "sender" }
              : { kind: outcome.subject, output: outcome.output },
        };

  it.each(rulesVector.cases.map((vector) => [vector.name, vector] as const))("%s", (_, vector) => {
    const lookup = (list: readonly { member: string; lists: number }[], member: string): bigint =>
      BigInt(list.find((record) => record.member === member)?.lists ?? 0);
    const lists = (member: string): RecordLists => ({
      own: lookup(vector.own_records, member),
      curator: lookup(vector.curator_records, member),
    });
    const refusal = admitTransfer(
      decodeRuleTable({ rules: vector.rules.map(field) }),
      vector.sources.map((source) => ({
        listId: source.list_id,
        registry: field(source.registry),
      })),
      {
        sender: lists(vector.sender),
        ringInputs: (
          vector.ring_inputs as readonly { owner: string; asset: string; amount: number }[]
        ).map((input) => ({
          owner: field(input.owner),
          asset: field(input.asset),
          amount: BigInt(input.amount),
        })),
        outputs: vector.outputs.map((output) => ({
          ring: output.ring,
          owner: field(output.owner),
          asset: field(output.asset),
          amount: BigInt(output.amount),
          ownerLists: lists(output.owner),
          assetLists: lists(output.asset),
          mintPolicy: {
            ...EMPTY_MINT_POLICY,
            threshold: BigInt(
              vector.inline_limits[
                (vector.inline_assets as readonly string[]).indexOf(output.asset)
              ] ?? 0,
            ),
          },
        })),
      },
    );
    expect(refusal).toEqual(expected(vector.outcome));
  });
});
