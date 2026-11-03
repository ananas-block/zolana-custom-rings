import { EMPTY_MINT_POLICY } from "../../../src/protocol/membership/mint-policy.js";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import keyedShapes from "../../../../../test-vectors/proof/ring_keyed_shapes.json" with { type: "json" };
import policyRules from "../../../../../test-vectors/policy/ring-policy-rules.json" with { type: "json" };
import records from "../../../../../test-vectors/registry/ring-records.json" with { type: "json" };
import ranges from "../../../../../test-vectors/audit/ring-disclosure-ranges.json" with { type: "json" };
import statements from "../../../../../test-vectors/proof/ring-statements.json" with { type: "json" };
import expansion from "../../../../../test-vectors/proof/ring-transact-expansion.json" with { type: "json" };
import { solanaOwnerIdentity, encodeBase58, hashChain } from "@heliuslabs/zolana/internal";
import { SPP_SUPPORTED_SHAPES } from "@heliuslabs/zolana/interface";
import { encodeRingTransactInstructionData } from "../../../src/protocol/proof/circuit.js";
import type { Address, Bytes16, Bytes32, Bytes33, Bytes96 } from "@heliuslabs/zolana/interface";
import { packDisclosure, unpackDisclosure } from "../../../src/crypto/audit/audit.js";
import {
  auditorMessageLen,
  ciphertextLen,
  envelopeRegion,
  exitRecordLen,
  firstRecordCounter,
  maxEvidenceBlocks,
  recordBlocks,
  recordLen,
  recordRegion,
  transferAuditKey,
  type AuditKey,
  type AuditLayout,
  type AuditStreamLayout,
} from "../../../src/protocol/codec/ring-disclosure-layout.js";
import {
  ANONYMOUS_TRANSFER_SHAPES,
  CONFIDENTIAL_TRANSFER_SHAPES,
  ENTRY_TRANSFER_SHAPES,
  ringTransferCircuit,
} from "../../../src/protocol/proof/transfer-shapes.js";
import { decodeDisclosure } from "../../../src/crypto/audit/ring-disclosure.js";
import {
  MIN_REPLY_LEN,
  RECIPIENT_BODY_LEN,
  senderBundleLen,
} from "../../../src/protocol/codec/anonymous-delivery.js";
import {
  APPLY_BATCH,
  QUAD_HEIGHT,
  type MemberRecord,
  type QuadPath,
  type QueueEntry,
  type RecordWriteProofInput,
} from "../../../src/protocol/membership/member-registry.js";
import {
  applyRecordsStatement,
  escrowEntry,
  queueChain,
  queueEntryHash,
  replayRecordWrites,
  verifyRecordOpening,
} from "../../../src/protocol/membership/member-opening.js";
import {
  admitTransfer,
  buildRuleTable,
  decodeRule,
  decodeRuleTable,
  policyTableFields,
  policyTableHash,
  type RecordLists,
  type RuleRefusal,
} from "../../../src/protocol/membership/policy.js";
import {
  applyRecordsStatementElements,
  applyRecordsStatementHash,
  registerKeyStatementElements,
  registerKeyStatementHash,
  ciphertextDigest,
  outputCiphertextChain,
  transferStatementElements,
  transferStatementHash,
  type TransferFamily,
} from "../../../src/protocol/proof/statement.js";
import {
  depositStatementElements,
  ringDepositContextHash,
} from "../../../src/proof/deposit-audit.js";
import { RingInstructionTag } from "../../../src/operations/management/admin.js";
import {
  RingTransactData,
  ringRail,
  ringRailOf,
  ringTransactOutput,
  type RingOutput,
  type RingRail,
  railShapes,
} from "../../../src/protocol/transaction/transact.js";
import {
  CONFIDENTIAL_DATA_FREE_BODY_LEN,
  encodeRingOutput,
  RingScheme,
} from "../../../src/protocol/transaction/output.js";
import {
  RING_AUTHORITY_MAX_INPUTS,
  RING_AUTHORITY_SHAPES,
  ringAuthorityShape,
} from "../../../src/protocol/transaction/spp.js";

function bytes<T extends Uint8Array>(value: string, length?: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (length !== undefined && decoded.length !== length)
    throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function hexes(values: readonly Uint8Array[]): string[] {
  return values.map(hex);
}

function field(value: string): Bytes32 {
  return bytes<Bytes32>(value, 32);
}

/** The last byte flipped, still below the modulus for every vector field. */
function flipped(value: Uint8Array): Bytes32 {
  const copy = Uint8Array.from(value);
  copy[31] = (copy[31] ?? 0) ^ 1;
  return field(hex(copy));
}

function railOf(name: string): RingRail {
  if (name !== "confidential" && name !== "anonymous" && name !== "delegate")
    throw new Error(`unknown rail ${name}`);
  return name;
}

function ringError(reason: string): unknown {
  return expect.objectContaining({ code: "RING_TRANSACT_DATA_INVALID", details: { reason } });
}

describe("ring-records.json", () => {
  type VectorPath = (typeof records.openings)[number]["path"];
  type VectorRecord = (typeof records.openings)[number]["record"];
  interface QueuedWrite {
    readonly kind: string;
    readonly signer: string | null;
    readonly member: string;
    readonly mask: number;
    readonly value: number;
    readonly nullifier_pk: string | null;
    readonly ciphertext: string | null;
    readonly escrow_key: string;
    readonly address_hash: string;
  }

  const path = (vector: VectorPath): QuadPath => ({
    index: vector.index,
    siblings: vector.siblings.map((level) => level.map(field)),
  });
  const record = (vector: VectorRecord): MemberRecord => ({
    mintPolicy: EMPTY_MINT_POLICY,
    member: field(vector.member),
    next: field(vector.next),
    lists: BigInt(vector.lists),
    escrowKey: field(vector.escrow_key),
    addressHash: field(vector.address_hash),
  });
  const entry = (queued: QueuedWrite): QueueEntry => {
    if (queued.kind === "register_key") {
      const { signer, nullifier_pk: nullifierPk, ciphertext } = queued;
      if (signer === null || nullifierPk === null || ciphertext === null)
        throw new Error("register key write without its key");
      return escrowEntry(solanaOwnerIdentity(field(signer)) as Bytes32, {
        nullifierPk: field(nullifierPk),
        ciphertext: field(ciphertext),
      });
    }
    const member =
      queued.signer === null
        ? field(queued.member)
        : (solanaOwnerIdentity(field(queued.signer)) as Bytes32);
    return {
      member,
      mask: BigInt(queued.mask),
      value: BigInt(queued.value),
      escrowKey: field(queued.escrow_key),
      addressHash: field(queued.address_hash),
    };
  };

  it("hashes every queued write and chains it from its position", () => {
    let chain = new Uint8Array(32) as Bytes32;
    for (const application of records.applications) {
      for (const queued of [...application.pending, ...application.authority_writes]) {
        const queuedEntry = entry(queued);
        expect(hex(queuedEntry.member)).toBe(queued.member);
        expect(hex(queuedEntry.escrowKey)).toBe(queued.escrow_key);
        expect(hex(queueEntryHash(queuedEntry))).toBe(queued.entry_hash);
        chain = queueChain(chain, queuedEntry);
        expect(hex(chain)).toBe(queued.chain);
      }
    }
  });

  it("replays every application to the root, next index and statement the apply proof binds", () => {
    for (const application of records.applications) {
      const writes: RecordWriteProofInput[] = application.writes.map((write) => ({
        oldMintPolicy: EMPTY_MINT_POLICY,
        entry: {
          member: field(write.member),
          mask: BigInt(write.mask),
          value: BigInt(write.value),
          escrowKey: field(write.escrow_key),
          addressHash: field(write.address_hash),
        },
        exists: write.exists,
        oldNext: field(write.old_next),
        oldLists: BigInt(write.old_lists),
        oldEscrow: field(write.old_escrow),
        oldAddressHash: field(write.old_address_hash),
        slot: path(write.slot),
        low: record(write.low),
        lowPath: path(write.low_path),
      }));
      expect(writes.length).toBeLessThanOrEqual(APPLY_BATCH);
      const inputs = replayRecordWrites({
        oldRoot: field(application.old_root),
        oldNextIndex: application.old_next_index,
        chainStart: field(application.chain_start),
        writes,
      });
      expect(hex(inputs.newRoot)).toBe(application.new_root);
      expect(inputs.newNextIndex).toBe(application.new_next_index);
      expect(hex(inputs.chainEnd)).toBe(application.chain_end);
      const statement = applyRecordsStatement(inputs);
      expect(statement.count).toBe(BigInt(application.count));
      expect(hex(applyRecordsStatementHash(statement))).toBe(application.statement_hash);
    }
  });

  it("verifies a present member and an absent member's low record under the root", () => {
    for (const opening of records.openings) {
      const member = field(opening.member);
      const opened = verifyRecordOpening(
        opening.present
          ? { kind: "present", record: record(opening.record), path: path(opening.path) }
          : { kind: "absent", low: record(opening.record), path: path(opening.path) },
        field(opening.root),
        member,
      );
      expect(opened === undefined).toBe(!opening.present);
      expect(path(opening.path).siblings).toHaveLength(QUAD_HEIGHT);
    }
  });

  it("refuses an opening whose path folds to another root", () => {
    const opening = records.openings[0];
    if (opening === undefined) throw new Error("vector has no opening");
    const honest = path(opening.path);
    const siblings = honest.siblings.map((entries, level) =>
      entries.map((sibling, at) => (level === 3 && at === 1 ? flipped(sibling) : sibling)),
    );
    expect(() =>
      verifyRecordOpening(
        { kind: "present", record: record(opening.record), path: { ...honest, siblings } },
        field(opening.root),
        field(opening.member),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "RING_MEMBER_REGISTRY_INVALID",
        details: { reason: "RootMismatch" },
      }),
    );
  });

  it("refuses a write whose value leaves its mask before the first write", () => {
    const application = records.applications[0];
    const write = application?.writes[0];
    if (application === undefined || write === undefined) throw new Error("vector has no write");
    expect(() =>
      replayRecordWrites({
        oldRoot: field(application.old_root),
        oldNextIndex: application.old_next_index,
        chainStart: field(application.chain_start),
        writes: [
          {
            oldMintPolicy: EMPTY_MINT_POLICY,
            entry: {
              member: field(write.member),
              mask: BigInt(write.mask),
              value: BigInt(write.value) | (1n << 7n),
              escrowKey: field(write.escrow_key),
              addressHash: field(write.address_hash),
            },
            exists: write.exists,
            oldNext: field(write.old_next),
            oldLists: BigInt(write.old_lists),
            oldEscrow: field(write.old_escrow),
            oldAddressHash: field(write.old_address_hash),
            slot: path(write.slot),
            low: record(write.low),
            lowPath: path(write.low_path),
          },
        ],
      }),
    ).toThrow(
      expect.objectContaining({
        code: "RING_MEMBER_REGISTRY_INVALID",
        details: { reason: "ValueOutsideMask" },
      }),
    );
  });
});

describe("ring-policy-table.json", () => {
  interface PolicyCase {
    readonly name: string;
    readonly sources: readonly Readonly<{ listId: number; registry: Bytes32 }>[];
    readonly rules: readonly Bytes32[];
    readonly fields: readonly string[];
    readonly policyHash: string;
  }

  /** u64 limits exceed the doubles `JSON.parse` returns, the reviver reads their source text. */
  function policyCases(): readonly PolicyCase[] {
    const text = readFileSync(
      new URL("../../../../../test-vectors/policy/ring-policy-table.json", import.meta.url),
      "utf8",
    );
    const parsed: unknown = JSON.parse(
      text,
      (_key, value: unknown, context?: { source?: string }) =>
        typeof value === "number" && context?.source !== undefined ? BigInt(context.source) : value,
    );
    const object = (value: unknown): Record<string, unknown> => {
      if (typeof value !== "object" || value === null) throw new Error("vector object");
      return value as Record<string, unknown>;
    };
    const list = (value: unknown): readonly unknown[] => {
      if (!Array.isArray(value)) throw new Error("vector array");
      return value;
    };
    const text32 = (value: unknown): string => {
      if (typeof value !== "string") throw new Error("vector string");
      return value;
    };
    const integer = (value: unknown): bigint => {
      if (typeof value !== "bigint") throw new Error("vector integer");
      return value;
    };
    return list(object(parsed)["cases"]).map((entry) => {
      const item = object(entry);
      return {
        name: text32(item["name"]),
        sources: list(item["sources"]).map((source) => ({
          listId: Number(integer(object(source)["list_id"])),
          registry: field(text32(object(source)["registry"])),
        })),
        rules: list(item["rules"]).map((row) => field(text32(row))),
        fields: list(item["fields"]).map(text32),
        policyHash: text32(item["policy_hash"]),
      };
    });
  }

  it("reproduces the 44 fields and the hash of every table", () => {
    const cases = policyCases();
    expect(cases.length).toBeGreaterThan(2);
    for (const vector of cases) {
      const table = buildRuleTable({
        rules: vector.rules.map(decodeRule),
      });
      const fields = policyTableFields(table, vector.sources);
      expect(fields).toHaveLength(44);
      expect(hexes(fields), vector.name).toEqual(vector.fields);
      expect(hex(policyTableHash(table, vector.sources)), vector.name).toBe(vector.policyHash);
    }
  });
});

describe("ring-statements.json", () => {
  type TransferCase = (typeof statements.transfer)[number];

  const output = (
    vector: TransferCase["outputs"][number],
    slot: number,
    change: number,
  ): RingOutput => {
    const hash = field(vector.hash);
    const zero = new Uint8Array(32) as Bytes32;
    switch (vector.kind) {
      case "delivered":
        return {
          kind: "delivered",
          hash,
          u: field(vector.u ?? ""),
          body: bytes(vector.body ?? ""),
        };
      case "anonymous":
        return ((change >> slot) & 1) === 1
          ? { kind: "change", hash, tag: zero }
          : {
              kind: "anonymous",
              hash,
              tag: field(vector.tag ?? ""),
              body: bytes(vector.recipient_body ?? ""),
            };
      default:
        return { kind: "exit", hash, ownerTag: zero, payload: new Uint8Array() };
    }
  };
  /** `key_escrow << 1 | full_openings << 3`. */
  const layout = (value: number): AuditLayout => ({
    keyEscrow: (value & 2) !== 0,
    fullOpenings: (value & 8) !== 0,
  });
  // A family's own values are null on the other family's vectors.
  const family = (vector: TransferCase): TransferFamily =>
    vector.family === "anonymous"
      ? {
          kind: "anonymous",
          partyIdentities: (vector.party_identities ?? []).map(field) as [
            Bytes32,
            Bytes32,
            Bytes32,
          ],
          senderBundle: bytes(vector.sender_bundle ?? ""),
          senderBundleTag: field(vector.sender_bundle_tag ?? ""),
          ...(vector.replies === null ? {} : { replies: bytes(vector.replies) }),
        }
      : {
          kind: "confidential",
          inProof: vector.in_proof === true,
          delegate: vector.delegate === true,
          sender: field(vector.sender ?? "00".repeat(32)),
          recipients: (vector.recipients ?? []).map(field),
        };

  it("rebuilds every transfer statement, its element count and its public input", () => {
    for (const vector of statements.transfer) {
      const outputCiphertexts = vector.outputs.map((slot) =>
        bytes(slot.kind === "delivered" ? (slot.body ?? "") : (slot.record ?? "")),
      );
      expect(hex(ciphertextDigest(bytes(vector.envelope))), vector.rail).toBe(
        vector.envelope_digest,
      );
      expect(
        hex(outputCiphertextChain(outputCiphertexts, vector.output_capacity)),
        vector.rail,
      ).toBe(vector.output_ciphertext_chain);
      const statement = {
        head: {
          firstNullifier: field(vector.first_nullifier),
          ringId: field(vector.ring_id),
          txViewingU: field(vector.tx_viewing_u),
          auditorPubkey: bytes<Bytes33>(vector.auditor_pubkey, 33),
          ephU: field(vector.eph_u),
          envelope: bytes(vector.envelope),
          salt: bytes<Bytes16>(vector.salt, 16),
          layout: layout(vector.layout),
        },
        family: family(vector),
        exempt: vector.exempt,
        approvalRequired: vector.approval_required,
        capacity: vector.output_capacity,
        outputs: vector.outputs.map((slot, index) =>
          output(slot, index, vector.change_bitmap ?? 0),
        ),
        outputCiphertexts,
        signers: { count: vector.signer_count, chain: field(vector.signer_chain) },
        inputCount: vector.input_count,
        privateTxHash: field(vector.private_tx_hash),
        roots: {
          policyHash: field(vector.policy_hash),
          ownRoot: field(vector.own_root),
          curatorRoot: field(vector.curator_root),
        },
        publicAssets: vector.public_assets.map(field),
        publicAmounts: vector.public_amounts.map(field),
        publicGross: vector.public_gross.map(field),
        withdrawalHash: field(vector.withdrawal_hash),
      };
      const elements = transferStatementElements(statement);
      expect(elements, vector.rail).toHaveLength(vector.elements.length);
      expect(hexes(elements), vector.rail).toEqual(vector.elements);
      expect(hex(transferStatementHash(statement))).toBe(vector.public_input_hash);
    }
  });

  it("rebuilds the apply records and register key statements", () => {
    const apply = statements.apply_records;
    const applyStatement = {
      oldRoot: field(apply.old_root),
      newRoot: field(apply.new_root),
      oldNextIndex: apply.old_next_index,
      newNextIndex: apply.new_next_index,
      chainStart: field(apply.chain_start),
      chainEnd: field(apply.chain_end),
      count: BigInt(apply.count),
    };
    expect(hexes(applyRecordsStatementElements(applyStatement))).toEqual(apply.elements);
    expect(hex(applyRecordsStatementHash(applyStatement))).toBe(apply.public_input_hash);
    const register = statements.register_key;
    const registerStatement = {
      member: field(register.member),
      nullifierPk: field(register.nullifier_pk),
      auditorPubkey: bytes<Bytes33>(register.auditor_pubkey, 33),
      ephU: field(register.eph_u),
      ciphertext: field(register.ciphertext),
    };
    expect(hexes(registerKeyStatementElements(registerStatement))).toEqual(register.elements);
    expect(hex(registerKeyStatementHash(registerStatement))).toBe(register.public_input_hash);
  });

  it("rebuilds the deposit statement over the context of its SPP data", () => {
    const deposit = statements.deposit;
    const contextHash = ringDepositContextHash(
      encodeBase58(bytes(deposit.program_id, 32)) as Address,
      encodeBase58(bytes(deposit.tree, 32)) as Address,
      bytes(deposit.spp_data),
    );
    expect(hex(contextHash)).toBe(deposit.context_hash);
    const elements = depositStatementElements({
      contextHash,
      anonymous: deposit.anonymous,
      ownerUtxoHashes: deposit.owner_utxo_hashes.map(field),
      ciphertexts: deposit.ciphertexts.map((value) => bytes<Bytes96>(value, 96)),
      assets: deposit.assets.map((asset, slot) => ({
        asset: field(asset),
        amount: BigInt(deposit.amounts[slot] ?? 0),
      })),
      auditorPk: bytes<Bytes33>(deposit.auditor_pubkey, 33),
      ephPk: bytes<Bytes33>(deposit.eph_pk, 33),
      registry: {
        ownRoot: field(deposit.member_registry_root),
        curatorRoot: field(deposit.curator_root),
        keyEscrow: deposit.key_escrow,
        policyHash: field(deposit.policy_hash),
      },
    });
    expect(hexes(elements)).toEqual(deposit.elements);
    expect(hex(hashChain(elements))).toBe(deposit.public_input_hash);
  });
});

describe("ring-transact-expansion.json", () => {
  const config = {
    auditorPubkey: bytes<Bytes33>(expansion.auditor_pubkey, 33),
  };

  it.each(expansion.cases)("$name expands to the SPP data and hash Rust forwards", (vector) => {
    const compact = bytes(vector.compact);
    const data = RingTransactData.parse(compact, railOf(vector.rail));
    expect(hex(RingTransactData.encode(data))).toBe(vector.compact);
    const expanded = RingTransactData.expand(data, config);
    expect(hex(encodeRingTransactInstructionData(expanded))).toBe(vector.transact_ix_data);
    // The auditor message stays last.
    expect(expanded.messages.at(-1)?.viewTag).toEqual(config.auditorPubkey.slice(1));
    expect(expanded.messages.slice(0, -1)).toEqual(
      data.sender === undefined
        ? []
        : [
            {
              viewTag: data.sender.tag,
              data: encodeRingOutput(RingScheme.ringSenderBundle, data.sender.body),
            },
          ],
    );
    expect(hex(RingTransactData.sppInstructionData(data, config))).toBe(
      vector.spp_instruction_data,
    );
    const settlements = vector.settlements.map(([asset = "", user = ""]) => ({
      asset: encodeBase58(bytes(asset, 32)),
      user: encodeBase58(bytes(user, 32)),
    }));
    expect(hex(RingTransactData.externalDataHash(data, config, settlements))).toBe(
      vector.external_data_hash,
    );
  });

  it("refuses a trailing byte and a missing byte", () => {
    for (const vector of expansion.cases) {
      const compact = bytes(vector.compact);
      const rail = railOf(vector.rail);
      expect(() => RingTransactData.parse(Uint8Array.of(...compact, 0), rail)).toThrow(
        ringError("RingTransactLength"),
      );
      expect(() => RingTransactData.parse(compact.subarray(0, compact.length - 1), rail)).toThrow(
        ringError("RingTransactLength"),
      );
    }
  });

  it("refuses a frame byte the rail or the shape does not admit", () => {
    const named = (name: string) => {
      const vector = expansion.cases.find((entry) => entry.name === name);
      if (vector === undefined) throw new Error(`vector has no ${name} case`);
      return { compact: bytes(vector.compact), rail: railOf(vector.rail) };
    };
    const refused = (name: string, at: number, set: (byte: number) => number) => {
      const { compact, rail } = named(name);
      const changed = compact.slice();
      changed[at] = set(changed[at] ?? 0);
      return () => RingTransactData.parse(changed, rail);
    };
    expect(refused("confidential_delivered_audit_only", 2, () => 16)).toThrow(
      ringError("RingTransactLength"),
    );
    expect(refused("confidential_delivered_audit_only", 1, (byte) => byte | (1 << 6))).toThrow(
      ringError("FlagNotAllowed"),
    );
    expect(refused("confidential_delivered_audit_only", 1, () => 63)).toThrow(
      ringError("RingShapeUnkeyed"),
    );
    for (const [at, bit] of [
      [0, 6],
      [0, 7],
      [1, 7],
    ] as const)
      expect(refused("confidential_delivered_audit_only", at, (byte) => byte | (1 << bit))).toThrow(
        ringError("FlagNotAllowed"),
      );
    const wide = SPP_SUPPORTED_SHAPES.findIndex(
      (shape) => shape.inputs > RING_AUTHORITY_MAX_INPUTS,
    );
    expect(refused("delegate_move", 1, () => wide)).toThrow(ringError("RingShapeUnkeyed"));
  });

  it("refuses the exempt bit on the delegate rail and the in-proof owner off the confidential rail", () => {
    for (const vector of expansion.cases)
      for (const bit of vector.rail === "confidential"
        ? []
        : vector.rail === "anonymous"
          ? [3]
          : [3, 4]) {
        const compact = bytes(vector.compact);
        compact[0] = (compact[0] ?? 0) | (1 << bit);
        expect(() => RingTransactData.parse(compact, railOf(vector.rail))).toThrow(
          ringError("FlagNotAllowed"),
        );
      }
  });

  it("reads the exempt bit with its own revision and refuses it without a withdrawal leg", () => {
    const exempt = expansion.cases.find((entry) => entry.name === "confidential_exempt_audit_only");
    if (exempt === undefined) throw new Error("vector has no exempt transfer");
    const data = RingTransactData.parse(bytes(exempt.compact), railOf(exempt.rail));
    expect([data.exempt, data.ownRevision !== undefined, data.policy]).toEqual([
      true,
      true,
      undefined,
    ]);
    expect(() => RingTransactData.encode({ ...data, interfaceTransfers: [] })).toThrow(
      ringError("ExemptionWithoutWithdrawal"),
    );
    const { ownRevision: _dropped, ...withoutRevision } = data;
    expect(() => RingTransactData.encode(withoutRevision)).toThrow(ringError("RingTransactLength"));
  });

  /** The anonymous policy frame and its first recipient slot. */
  const anonymousFrame = () => {
    const vector = expansion.cases.find((entry) => entry.name === "anonymous_policy");
    if (vector === undefined) throw new Error("vector has no anonymous policy transfer");
    const compact = bytes(vector.compact);
    const data = RingTransactData.parse(compact, "anonymous");
    const at = data.outputs.findIndex((output) => output.kind === "anonymous");
    const first = data.outputs[at];
    if (first?.kind !== "anonymous" || data.sender === undefined)
      throw new Error("anonymous transfer without a recipient body or a sender bundle");
    return { compact, data, at, first, bundle: data.sender };
  };

  it("frames a recipient body under scheme 11 and a change output with no data", () => {
    const { data } = anonymousFrame();
    expect(data.outputs[0]).toMatchObject({ kind: "change" });
    for (const output of data.outputs) {
      if (output.kind === "exit" || output.kind === "delivered") continue;
      const published = ringTransactOutput(output);
      expect(published.data).toEqual(
        output.kind === "change"
          ? undefined
          : encodeRingOutput(RingScheme.ringRecipientBody, output.body),
      );
      expect(published.ownerTag).toEqual({ kind: "inline", value: output.tag });
    }
  });

  it("carries no body length, the frame fixes each body and the bundle", () => {
    const { data, first, bundle } = anonymousFrame();
    expect(first.body).toHaveLength(RECIPIENT_BODY_LEN);
    expect(bundle.body).toHaveLength(senderBundleLen(data.outputs.length));
  });

  it("refuses an anonymous body or a sender bundle off its length at encoding", () => {
    const { data, at, first, bundle } = anonymousFrame();
    for (const body of [new Uint8Array(), new Uint8Array(RECIPIENT_BODY_LEN + 1)])
      expect(() =>
        RingTransactData.encode({ ...data, outputs: data.outputs.with(at, { ...first, body }) }),
      ).toThrow(ringError("RingTransactLength"));
    for (const body of [new Uint8Array(), new Uint8Array(bundle.body.length + 1)])
      expect(() => RingTransactData.encode({ ...data, sender: { ...bundle, body } })).toThrow(
        ringError("RingTransactLength"),
      );
  });

  it("frames one reply length per recipient body and refuses any other", () => {
    const vector = expansion.cases.find((entry) => entry.name === "anonymous_reply_metadata");
    if (vector === undefined) throw new Error("vector has no reply metadata transfer");
    const data = RingTransactData.parse(bytes(vector.compact), "anonymous");
    const { replies } = data;
    if (replies === undefined || replies.length === 0) throw new Error("frame without replies");
    expect(replies).toHaveLength(data.outputs.filter((slot) => slot.kind === "anonymous").length);
    expect(hex(RingTransactData.encode(data))).toBe(vector.compact);
    const short = new Uint8Array(MIN_REPLY_LEN - 1);
    const mixed = replies.map((reply, index) =>
      index === 0 ? new Uint8Array(reply.length + 1) : reply,
    );
    for (const refused of [
      replies.map(() => short),
      replies.slice(1),
      ...(replies.length > 1 ? [mixed] : []),
    ])
      expect(() => RingTransactData.encode({ ...data, replies: refused })).toThrow(
        ringError("ReplyLength"),
      );
  });

  it("carries the sender bundle exactly on the anonymous rail", () => {
    const { data, bundle } = anonymousFrame();
    const { sender: _, ...withoutSender } = data;
    expect(() => RingTransactData.encode(withoutSender)).toThrow(ringError("RingTransactLength"));
    const vector = expansion.cases.find((entry) => entry.name === "confidential_delivered_policy");
    if (vector === undefined) throw new Error("vector has no confidential policy transfer");
    const confidential = RingTransactData.parse(bytes(vector.compact), "confidential");
    expect(() => RingTransactData.encode({ ...confidential, sender: bundle })).toThrow(
      ringError("RingTransactLength"),
    );
  });

  it("frames an exit payload at its data-free length and refuses another", () => {
    const vector = expansion.cases.find((entry) => entry.name === "confidential_delivered_policy");
    if (vector === undefined) throw new Error("vector has no confidential policy transfer");
    const data = RingTransactData.parse(bytes(vector.compact), railOf(vector.rail));
    const at = data.outputs.findIndex((output) => output.kind === "exit");
    const exit = data.outputs[at];
    if (exit?.kind !== "exit") throw new Error("policy transfer without an exit");
    expect(exit.payload).toHaveLength(CONFIDENTIAL_DATA_FREE_BODY_LEN);
    const longer = { ...exit, payload: Uint8Array.of(...exit.payload, 0) };
    expect(() =>
      RingTransactData.encode({ ...data, outputs: data.outputs.with(at, longer) }),
    ).toThrow(ringError("DataFreeBodyLength"));
  });

  it("refuses an SPP point off the curve at expansion", () => {
    const vector = expansion.cases[0];
    if (vector === undefined) throw new Error("vector has no case");
    const data = RingTransactData.parse(bytes(vector.compact), railOf(vector.rail));
    const sppProof = data.sppProof.slice();
    sppProof.fill(0xff, 32, 96);
    sppProof[32] = 0x1f;
    expect(() => RingTransactData.expand({ ...data, sppProof }, config)).toThrow(
      ringError("InvalidSppProofPoint"),
    );
  });
});

describe("ring_keyed_shapes.json", () => {
  it.each([-1, 0, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "refuses an invalid published input count %s",
    (inputs) => {
      expect(
        ringTransferCircuit({
          rail: "confidential",
          inputs,
          outputs: 2,
          spendsDefaultRing: false,
          legs: 0,
        }),
      ).toBeUndefined();
    },
  );

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "refuses an invalid withdrawal count %s",
    (legs) => {
      expect(
        ringTransferCircuit({
          rail: "confidential",
          inputs: 1,
          outputs: 2,
          spendsDefaultRing: false,
          legs,
        }),
      ).toBeUndefined();
    },
  );

  it("keys the delegate rail at the pinned SPP's square authority shapes", () => {
    expect(RING_AUTHORITY_SHAPES.map((shape) => [shape.inputs, shape.outputs])).toEqual([
      [2, 2],
      [4, 4],
    ]);
    expect(ringAuthorityShape(3, 3)).toEqual({ inputs: 4, outputs: 4 });
    expect(ringAuthorityShape(3, 9)).toBeUndefined();
  });

  it("keys every transfer family at the pinned shapes and exactly the SPP shapes each rail serves", () => {
    expect({
      confidential: CONFIDENTIAL_TRANSFER_SHAPES,
      anonymous: ANONYMOUS_TRANSFER_SHAPES,
      entry: ENTRY_TRANSFER_SHAPES,
    }).toEqual(keyedShapes.transfer_shapes);
    const served = (rail: RingRail, spendsDefaultRing: boolean) =>
      SPP_SUPPORTED_SHAPES.filter(
        (shape) =>
          railShapes(rail).includes(shape) &&
          ringTransferCircuit({
            rail,
            inputs: shape.inputs,
            outputs: shape.outputs,
            spendsDefaultRing,
            legs: 0,
          }) !== undefined,
      ).map((shape) => [shape.inputs, shape.outputs]);
    expect(served("confidential", false)).toEqual(keyedShapes.confidential_ring);
    expect(served("delegate", false)).toEqual(keyedShapes.ring_authority);
    expect(served("anonymous", false)).toEqual(keyedShapes.anonymous_ring);
    expect(served("anonymous", true)).toEqual(keyedShapes.anonymous_entry_ring);
    expect(
      SPP_SUPPORTED_SHAPES.filter(
        (shape) =>
          transferAuditKey({
            rail: "anonymous",
            inputs: shape.inputs,
            capacity: shape.outputs,
            spendsDefaultRing: false,
          }) !== undefined,
      ).map((shape) => [shape.inputs, shape.outputs]),
    ).toEqual(keyedShapes.anonymous_ring);
  });
});

describe("ring rails", () => {
  it("picks the rail of a ring instruction under the mode and the delegate like Rust `RingRail::new`", () => {
    const { transfer, authorityTransfer, merge } = RingInstructionTag;
    const delegate = encodeBase58(new Uint8Array(32).fill(7));
    expect(ringRail(transfer, { mode: "confidential" })).toBe("confidential");
    expect(ringRail(transfer, { mode: "anonymous" })).toBe("anonymous");
    expect(ringRail(authorityTransfer, { mode: "confidentialEscrow", delegate })).toBe("delegate");
    expect(() => ringRail(authorityTransfer, { mode: "anonymous", delegate })).toThrow(
      ringError("AnonymousRingRefused"),
    );
    expect(() => ringRail(authorityTransfer, { mode: "confidential" })).toThrow(
      ringError("DelegateDisabled"),
    );
    expect(ringRailOf(authorityTransfer, "confidential")).toBe("delegate");
    expect(() => ringRailOf(merge, "confidential")).toThrow(ringError("InvalidInstructionData"));
  });
});

describe("disclosure packing", () => {
  it("left-aligns a short tail chunk and zero pads it", () => {
    const plaintext = Uint8Array.from({ length: 40 }, (_, index) => index + 1);
    const fields = packDisclosure(plaintext);
    expect(fields).toHaveLength(2);
    expect(hex(fields[0] ?? new Uint8Array())).toBe(`00${hex(plaintext.subarray(0, 31))}`);
    expect(hex(fields[1] ?? new Uint8Array())).toBe(
      `00${hex(plaintext.subarray(31))}${"00".repeat(22)}`,
    );
    expect(unpackDisclosure(fields, 40)).toEqual(plaintext);
    const padded = fields.map((entry, index) => (index === 1 ? flipped(entry) : entry));
    expect(() => unpackDisclosure(padded, 40)).toThrow("KEYPAIR_DISCLOSURE_PADDING");
  });

  it("refuses a layout no audit key serves", () => {
    const decode = (layout: AuditStreamLayout) => () =>
      decodeDisclosure(layout, {
        evidence: new Uint8Array(0),
        records: [],
      });
    const layoutOf = (
      kind: AuditKey["kind"],
      inputClass: number,
      inputs: number,
      outputs: number,
    ) =>
      decode({
        key: { kind, class: inputClass },
        keyEscrow: false,
        inputs,
        capacity: outputs,
        outputs,
        exits: 0n,
        change: 0n,
      });
    expect(layoutOf("commitment", 24, 2, 8)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(layoutOf("commitment", 28, 2, 2)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(layoutOf("commitment", 4, 5, 2)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(layoutOf("commitment", 1, 2, 16)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(layoutOf("entry", 8, 9, 2)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(layoutOf("entry", 8, 2, 16)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(layoutOf("entry", 2, 2, 2)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(layoutOf("confidential", 32, 1, 3)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
  });
});

describe("ring-disclosure-ranges.json", () => {
  type KeyRanges = (typeof ranges.keys)[number];

  const keyOf = (vector: KeyRanges): AuditKey => ({
    kind:
      vector.family === "confidential"
        ? "confidential"
        : vector.rail === "entry"
          ? "entry"
          : "commitment",
    class: vector.class,
  });

  it.each(ranges.keys)(
    "fixes every range of the $rail key of $outputs outputs and class $class, key escrow $key_escrow",
    (vector) => {
      const key = keyOf(vector);
      expect(maxEvidenceBlocks(key)).toBe(vector.max_evidence_blocks);
      expect(recordBlocks(key)).toBe(vector.record_blocks);
      expect(firstRecordCounter(key)).toBe(vector.first_record_counter);
      expect(exitRecordLen(vector.key_escrow)).toBe(vector.exit_record_len);
      const layoutAt = (inputs: number, exits: bigint): AuditStreamLayout => ({
        key,
        keyEscrow: vector.key_escrow,
        inputs,
        capacity: vector.outputs,
        outputs: vector.outputs,
        exits,
        change: 0n,
      });
      const everyExit = (1n << BigInt(vector.outputs)) - 1n;
      const free = layoutAt(1, 0n);
      expect(ciphertextLen(free, 0)).toBe(vector.ring_slot_ciphertext_len);
      expect(recordLen(free, 0)).toBe(vector.ring_slot_record_len);
      expect(
        Array.from({ length: vector.outputs }, (_, slot) => recordRegion(free, slot).startCounter),
      ).toEqual(vector.record_start_counters);
      expect(envelopeRegion(free).maxBlocks + vector.outputs * recordBlocks(key)).toBe(
        vector.capacity_blocks,
      );
      vector.envelope_len_by_input_count.forEach((length, index) => {
        const inputs = index + 1;
        expect(envelopeRegion(layoutAt(inputs, 0n)).length).toBe(length);
        expect(auditorMessageLen(layoutAt(inputs, 0n))).toBe(
          vector.message_len_no_exit_by_input_count[index],
        );
        expect(auditorMessageLen(layoutAt(inputs, everyExit))).toBe(
          vector.message_len_every_exit_by_input_count[index],
        );
      });
    },
  );
});

describe("ring-policy-rules.json", () => {
  type Case = (typeof policyRules.cases)[number];

  /** The refusal the vector names, `pass` none. */
  function outcome(expected: Case["outcome"]): RuleRefusal | undefined {
    const rule = expected.rule ?? -1;
    const output = expected.output ?? -1;
    switch (expected.kind) {
      case "pass":
        return undefined;
      case "lists":
        return {
          kind: "lists",
          rule,
          subject:
            expected.subject === "sender"
              ? { kind: "sender" }
              : { kind: expected.subject === "owner" ? "owner" : "asset", output },
        };
      case "no_asset_limit":
        return { kind: "noAssetLimit", rule, output };
      default:
        return { kind: "mixedAssets", rule, output };
    }
  }

  it.each(policyRules.cases.map((vector) => [vector.name, vector] as const))(
    "%s",
    (_name, vector) => {
      const table = decodeRuleTable({
        rules: vector.rules.map((row) => field(row)),
      });
      const lookup = (list: readonly { member: string; lists: number }[], member: string): bigint =>
        BigInt(list.find((record) => record.member === member)?.lists ?? 0);
      const lists = (member: string): RecordLists => ({
        own: lookup(vector.own_records, member),
        curator: lookup(vector.curator_records, member),
      });
      const refusal = admitTransfer(
        table,
        vector.sources.map((source) => ({
          listId: source.list_id,
          registry: field(source.registry),
        })),
        {
          sender: lists(vector.sender),
          outputs: vector.outputs.map((output) => ({
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
      expect(refusal).toEqual(outcome(vector.outcome));
    },
  );
});
