import { readFileSync } from "node:fs";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { encodeBase58 } from "@heliuslabs/zolana/internal";
import { SPP_SUPPORTED_SHAPES } from "@heliuslabs/zolana/interface";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";

import expansion from "../../../../../test-vectors/proof/ring-transact-expansion-v4.json" with { type: "json" };
import keyed from "../../../../../test-vectors/proof/ring_keyed_shapes.json" with { type: "json" };
import statements from "../../../../../test-vectors/audit/transfer_statement_v4.json" with { type: "json" };
import tracking from "../../../../../test-vectors/registry/tracking-records.json" with { type: "json" };
import { encodeRingTransactInstructionData } from "../../../src/protocol/proof/circuit.js";
import {
  applyEnrollmentsStatementHash,
  signerBinding,
  transferStatementElements,
  transferStatementHash,
  type TransferStatement,
} from "../../../src/protocol/proof/statement.js";
import {
  TRANSFER_SHAPES,
  fittedSpend,
  ringTransferCircuit,
} from "../../../src/protocol/proof/transfer-shapes.js";
import {
  trackingEntryChained,
  trackingEntryHash,
  trackingRecordHash,
  type TrackingEntry,
  type TrackingRecord,
} from "../../../src/protocol/membership/tracking.js";
import {
  RingTransactData,
  railShapes,
  type RingRail,
} from "../../../src/protocol/transaction/transact.js";

const field = (value: string): Bytes32 => hexToBytes(value) as Bytes32;
const hex = (value: Uint8Array): string => bytesToHex(value);

const RAILS: Readonly<Record<string, RingRail>> = {
  confidential: "confidential",
  anonymous: "anonymous",
  delegate: "delegate",
  "anonymous delegate": "anonymousDelegate",
};

beforeAll(initializePoseidon);

describe("ring-transact-expansion-v4.json", () => {
  const config = { auditorPubkey: hexToBytes(expansion.auditor_pubkey) as Bytes33 };

  it.each(expansion.cases)("$name reads, writes and expands as Rust does", (vector) => {
    const rail = RAILS[vector.rail];
    if (rail === undefined) throw new Error(vector.rail);
    const data = RingTransactData.parse(hexToBytes(vector.compact), rail);
    expect(hex(RingTransactData.encode(data))).toBe(vector.compact);
    expect(hex(encodeRingTransactInstructionData(RingTransactData.expand(data, config)))).toBe(
      vector.transact_ix_data,
    );
    expect(hex(RingTransactData.sppInstructionData(data, config))).toBe(
      vector.spp_instruction_data,
    );
    const settlements = vector.settlements.map(([asset, user]) => ({
      asset: encodeBase58(hexToBytes(asset as string)),
      user: encodeBase58(hexToBytes(user as string)),
    }));
    expect(hex(RingTransactData.externalDataHash(data, config, settlements))).toBe(
      vector.external_data_hash,
    );
  });
});

describe("frame_v4.hex", () => {
  const lines = readFileSync(
    new URL("../../../../../test-vectors/settlement/frame_v4.hex", import.meta.url),
    "utf8",
  )
    .split("\n")
    .filter((line) => line.length > 0);

  it.each(lines.map((line, index) => [index, line] as const))(
    "line %i reads under a rail and writes the same bytes",
    (_, line) => {
      const bytes = hexToBytes(line);
      const written = Object.values(RAILS).flatMap((rail) => {
        try {
          return [hex(RingTransactData.encode(RingTransactData.parse(bytes, rail)))];
        } catch {
          return [];
        }
      });
      expect(written).toContain(line);
    },
  );
});

describe("transfer_statement_v4.json", () => {
  it.each(statements.cases)("$name rebuilds its elements and public input", (vector) => {
    const parties = vector.party_identities;
    const statement: TransferStatement = {
      head: {
        firstNullifier: field(vector.first_nullifier),
        ringId: field(vector.ring_id),
        txViewingU: field(vector.tx_viewing_u),
        auditorPubkey: hexToBytes(vector.auditor_pubkey) as Bytes33,
        ephU: field(vector.eph_u),
        envelope: hexToBytes(vector.envelope),
        salt: hexToBytes(vector.salt) as Bytes16,
        layout: { hasData: (vector.layout & 1) !== 0, entry: (vector.layout & 2) !== 0 },
      },
      family:
        vector.family === "confidential"
          ? {
              kind: "confidential",
              inProof: vector.in_proof,
              delegate: vector.delegate,
              sender: field(vector.sender ?? "00".repeat(32)),
            }
          : {
              kind: "anonymous",
              partyIdentities: (parties ?? []).map(field),
              publicOwners: vector.public_owners,
              delegate: vector.delegate,
            },
      approvalMask: vector.approval_mask,
      noSpend: vector.no_spend,
      outputs: vector.outputs.map((output) => ({
        hash: field(output.hash),
        record: hexToBytes(output.record),
        ...("tail" in output && typeof output.tail === "string"
          ? { tail: hexToBytes(output.tail) }
          : {}),
      })),
      capacity: vector.output_capacity,
      inputCount: vector.input_count,
      privateTxHash: field(vector.private_tx_hash),
      signers: signerBinding(vector.signers.map(field), vector.signer_slots),
      roots: {
        policyHash: field(vector.policy_hash),
        ownRoot: field(vector.own_root),
        curatorRoot: field(vector.curator_root),
        trackingRoot: field(vector.tracking_root),
      },
      publicAssets: vector.public_assets.map(field),
      publicAmounts: vector.public_amounts.map(field),
      publicGross: vector.public_gross.map(field),
      withdrawalHash: field(vector.withdrawal_hash),
    };
    expect(hex(statement.signers.chain)).toBe(vector.signer_chain);
    expect(transferStatementElements(statement).map(hex)).toEqual(vector.elements);
    expect(hex(transferStatementHash(statement))).toBe(vector.public_input_hash);
  });
});

describe("ring_keyed_shapes.json", () => {
  const served = (rail: RingRail, spendsDefaultRing: boolean) =>
    SPP_SUPPORTED_SHAPES.filter(
      (shape) =>
        railShapes(rail).some(
          (held) => held.inputs === shape.inputs && held.outputs === shape.outputs,
        ) &&
        ringTransferCircuit(
          fittedSpend({
            rail,
            inputs: shape.inputs,
            outputs: shape.outputs,
            spendsDefaultRing,
            legs: 0,
            owners: 0,
            pools: { own: 0, curator: 0, tracking: 0 },
            wide: false,
          }),
        ) !== undefined,
    ).map((shape) => [shape.inputs, shape.outputs]);

  it("lists the catalog's shapes", () => {
    expect(TRANSFER_SHAPES.map((shape) => ({ ...shape }))).toEqual(
      keyed.transfer_shapes.map((shape) => expect.objectContaining(shape)),
    );
  });

  it("serves the shapes of every rail", () => {
    expect(served("confidential", false)).toEqual(keyed.confidential_ring);
    expect(served("anonymous", false)).toEqual(keyed.anonymous_ring);
    expect(served("anonymous", true)).toEqual(keyed.anonymous_entry_ring);
    expect(served("delegate", false)).toEqual(keyed.ring_authority);
  });
});

describe("tracking-records.json", () => {
  const entryOf = (row: (typeof tracking.applications)[number]["writes"][number]["entry"]) =>
    ({
      member: field(row.member),
      nullifierPk: field(row.nullifier_pk),
      ctHash: field(row.ct_hash),
      viewingU: field(row.viewing_u),
      revision: BigInt(row.revision),
      listTag: field(row.list_tag),
    }) satisfies TrackingEntry;
  const recordOf = (row: (typeof tracking.applications)[number]["writes"][number]["old"]) =>
    ({
      member: field(row.member),
      next: field(row.next),
      nullifierPk: field(row.nullifier_pk),
      ctHash: field(row.ct_hash),
      viewingU: field(row.viewing_u),
      revision: BigInt(row.revision),
      listTag: field(row.list_tag),
    }) satisfies TrackingRecord;

  it.each(tracking.applications)("$name hashes, chains and states as Rust does", (application) => {
    let chain = field(application.chain_start);
    for (const write of application.writes) {
      expect(hex(trackingEntryHash(entryOf(write.entry)))).toBe(write.entry.entry_hash);
      expect(hex(trackingRecordHash(recordOf(write.old)))).toBe(write.old.leaf_hash);
      expect(hex(trackingRecordHash(recordOf(write.low)))).toBe(write.low.leaf_hash);
      chain = trackingEntryChained(chain, entryOf(write.entry));
    }
    expect(hex(chain)).toBe(application.chain_end);
    expect(
      hex(
        applyEnrollmentsStatementHash({
          oldRoot: field(application.old_root),
          newRoot: field(application.new_root),
          oldNextIndex: application.old_next_index,
          newNextIndex: application.new_next_index,
          chainStart: field(application.chain_start),
          chainEnd: field(application.chain_end),
          count: BigInt(application.count),
        }),
      ),
    ).toBe(application.statement_hash);
  });
});
