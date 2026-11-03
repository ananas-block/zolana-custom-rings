import { beforeAll, describe, expect, it } from "vitest";

import vector from "../../../../../test-vectors/registry/address_record.json" with { type: "json" };
import empty from "../../../../../test-vectors/registry/empty_root.json" with { type: "json" };
import { initializePoseidon } from "@heliuslabs/zolana";
import {
  SYSTEM_PROGRAM,
  ZERO_32,
  addressBytes,
  encodeBase58,
  hashBytes,
  poseidon,
  solanaOwnerIdentity,
} from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { X25519Keypair } from "@heliuslabs/zolana/keypair";
import {
  ENROLL_ADDRESS_TAG,
  authorizationAddressHash,
  decodeAddressAuthorization,
  enrollAddressInstruction,
} from "../../../src/operations/management/enroll-address.js";
import { RingDomain, domainField } from "../../../src/crypto/derivation/ring-domain.js";
import { packBytesBe } from "../../../src/crypto/derivation/hasher.js";
import { ringIdField } from "../../../src/crypto/derivation/ring-stream.js";
import {
  decodeStorageWrites,
  encodeStorageWrites,
  type StorageWrite,
} from "../../../src/protocol/codec/storage-writes.js";
import {
  MEMBER_REGISTRY_EMPTY_ROOT,
  SENTINEL_RECORD,
  addressRecordHash,
  applyRecordsStatement,
  checkedViewingU,
  escrowEntry,
  escrowKeyHash,
  memberRecordHash,
  quadPathRoot,
  queueEntryHash,
  replayRecordWrites,
  verifyRecordOpening,
} from "../../../src/protocol/membership/member-opening.js";
import {
  QUAD_HEIGHT,
  type MemberRecord,
  type QuadPath,
  type QueueEntry,
  type RecordWriteProofInput,
} from "../../../src/protocol/membership/member-registry.js";
import { EMPTY_MINT_POLICY } from "../../../src/protocol/membership/mint-policy.js";
import { memberOfTag } from "../../../src/protocol/membership/policy.js";
import { addressAuthorizationPda, STORAGE_PROGRAM_ID } from "../../../src/protocol/pda/index.js";
import { applyRecordsStatementHash } from "../../../src/protocol/proof/statement.js";
import { recordTree } from "../../helpers/member-registry.js";

type Step = (typeof vector.steps)[number];
type Update = Step["update"];
type VectorOpening = Update["openings"][number];
type VectorRecord = VectorOpening["record"];
type VectorPath = VectorOpening["path"];
type VectorEntry = Update["entries"][number];
type VectorWrite = Update["writes"][number];
type Enrollment = Step["enrollments"][number];

const CURVE25519_FIELD = 2n ** 255n - 19n;

function field(value: string): Bytes32 {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== 32) throw new RangeError("expected 32 bytes");
  return decoded as Bytes32;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function little(value: bigint): Bytes32 {
  const bytes = new Uint8Array(32);
  for (let at = 0; at < 32; at += 1) bytes[at] = Number((value >> BigInt(8 * at)) & 0xffn);
  return bytes as Bytes32;
}

function path(from: VectorPath): QuadPath {
  return { index: from.index, siblings: from.siblings.map((level) => level.map(field)) };
}

function record(from: VectorRecord): MemberRecord {
  return {
    member: field(from.member),
    next: field(from.next),
    lists: BigInt(from.lists),
    escrowKey: field(from.escrow_key),
    mintPolicy: EMPTY_MINT_POLICY,
    addressHash: field(from.address_hash),
  };
}

function entryOf(from: VectorEntry): QueueEntry {
  return {
    member: field(from.member),
    mask: BigInt(from.mask),
    value: BigInt(from.value),
    escrowKey: field(from.escrow_key),
    addressHash: field(from.address_hash),
  };
}

function writeOf(from: VectorWrite, entry: QueueEntry): RecordWriteProofInput {
  const { pair } = from;
  return {
    entry,
    exists: from.exists,
    oldNext: field(from.old_next),
    oldLists: BigInt(from.old_lists),
    oldEscrow: field(from.old_escrow),
    oldMintPolicy: EMPTY_MINT_POLICY,
    oldAddressHash: field(from.old_address_hash),
    slot: path(from.slot),
    low: record(from.low),
    lowPath: path(from.low_path),
    ...(pair === null
      ? {}
      : {
          pair: {
            nullifierPk: field(pair.nullifier_pk),
            addressRing: field(pair.address_ring),
            view0: field(pair.view0),
            view1: field(pair.view1),
            addressRevision: BigInt(pair.address_revision),
            escrowCiphertextHash: field(pair.escrow_ciphertext_hash),
          },
        }),
  };
}

function replay(update: Update) {
  return replayRecordWrites({
    oldRoot: field(update.old_root),
    oldNextIndex: update.old_next_index,
    chainStart: field(update.chain_start),
    writes: update.writes.map((write, at) => {
      const entry = update.entries[at];
      if (entry === undefined) throw new Error("write without its entry");
      return writeOf(write, entryOf(entry));
    }),
  });
}

function namedStep(name: string): Update {
  const step = vector.steps.find(({ update }) => update.name === name);
  if (step === undefined) throw new Error(`vector has no step ${name}`);
  return step.update;
}

/** `nullifier_pk` and `viewing_u` of an enrollment's data. */
function enrolledKeys(enrollment: Enrollment) {
  const data = Uint8Array.from(Buffer.from(enrollment.instruction_data, "hex"));
  return {
    nullifierPk: data.slice(1, 33) as Bytes32,
    viewingU: data.slice(33, 65) as Bytes32,
  };
}

function enrollmentOf(owner: string, revision: bigint): Enrollment {
  const found = vector.steps
    .flatMap((step) => step.enrollments)
    .find(
      (enrollment) =>
        enrollment.owner === owner && BigInt(enrollment.address_revision) === revision,
    );
  if (found === undefined) throw new Error("address write without its enrollment");
  return found;
}

/** The entry a write queues, an address hash read from the owner's enrollment alone. */
function queuedEntry(write: StorageWrite): QueueEntry {
  switch (write.kind) {
    case "record":
      return { member: write.member, mask: write.mask, value: write.value, escrowKey: ZERO_32 };
    case "escrow":
      return escrowEntry(memberOfTag(addressBytes(write.owner)), {
        nullifierPk: write.nullifierPk,
        ciphertext: write.ciphertext,
      });
    case "address": {
      const owner = addressBytes(write.owner);
      const member = memberOfTag(owner);
      return {
        member,
        mask: 0n,
        value: 0n,
        escrowKey: ZERO_32,
        addressHash: addressRecordHash({
          ringId: field(vector.ring_id),
          member,
          addressRevision: write.addressRevision,
          ...enrolledKeys(enrollmentOf(hex(owner), write.addressRevision)),
        }),
      };
    }
  }
}

beforeAll(initializePoseidon);

describe("empty_root.json", () => {
  it("folds the sentinel over the zero subtrees to the registry's first root", () => {
    expect(hex(memberRecordHash(SENTINEL_RECORD))).toBe(empty.sentinel.leaf_hash);
    expect(hex(memberRecordHash(record(empty.sentinel)))).toBe(empty.sentinel.leaf_hash);
    expect(empty.zero_subtrees).toHaveLength(QUAD_HEIGHT + 1);
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
    expect(vector.empty_root).toBe(empty.empty_root);
  });
});

describe("address_record.json", () => {
  it("names the ring id of its ring program", () => {
    expect(hex(ringIdField(encodeBase58(field(vector.ring_program))))).toBe(vector.ring_id);
  });

  it("replays every step to its root, next index, chain end and statement", () => {
    let root = vector.empty_root;
    let nextIndex = 1;
    for (const { update } of vector.steps) {
      expect(update.old_root, update.name).toBe(root);
      expect(update.old_next_index, update.name).toBe(nextIndex);
      const inputs = replay(update);
      expect(hex(inputs.newRoot), update.name).toBe(update.new_root);
      expect(inputs.newNextIndex, update.name).toBe(update.new_next_index);
      expect(hex(inputs.chainEnd), update.name).toBe(update.chain_end);
      const statement = applyRecordsStatement(inputs);
      expect(statement.count, update.name).toBe(BigInt(update.count));
      expect(hex(applyRecordsStatementHash(statement)), update.name).toBe(update.statement_hash);
      root = update.new_root;
      nextIndex = update.new_next_index;
    }
  });

  it("rebuilds every entry from its wire write, the hash of an address from the enrollment", () => {
    for (const { update } of vector.steps) {
      const wire = Uint8Array.from(Buffer.from(update.writes_wire, "hex"));
      const writes = decodeStorageWrites(wire);
      expect(hex(encodeStorageWrites(writes)), update.name).toBe(update.writes_wire);
      expect(writes, update.name).toHaveLength(update.entries.length);
      writes.forEach((write, at) => {
        const expected = update.entries[at];
        if (expected === undefined) throw new Error("wire write without its entry");
        const entry = queuedEntry(write);
        expect(hex(entry.member), update.name).toBe(expected.member);
        expect(hex(entry.addressHash ?? ZERO_32), update.name).toBe(expected.address_hash);
        expect(hex(queueEntryHash(entry)), update.name).toBe(expected.entry_hash);
      });
    }
  });

  it("opens each owner under its step's root with both preimages bound to the record", () => {
    const zero = hex(ZERO_32);
    for (const { update } of vector.steps) {
      expect(update.openings, update.name).toHaveLength(vector.owners.length);
      update.openings.forEach((opening, at) => {
        const owner = field(vector.owners[at] ?? "");
        const member = field(opening.member);
        expect(hex(member)).toBe(hex(solanaOwnerIdentity(owner)));
        expect(opening.root).toBe(update.new_root);
        const leaf = record(opening.record);
        expect(hex(memberRecordHash(leaf))).toBe(opening.record.leaf_hash);
        const opened = verifyRecordOpening(
          opening.present
            ? { kind: "present", record: leaf, path: path(opening.path) }
            : { kind: "absent", low: leaf, path: path(opening.path) },
          field(opening.root),
          member,
        );
        expect(opened === undefined, update.name).toBe(!opening.present);
        const { address, escrow } = opening;
        expect(address === null, update.name).toBe(opening.record.address_hash === zero);
        expect(escrow === null, update.name).toBe(opening.record.escrow_key === zero);
        if (address !== null) {
          expect(address.member).toBe(opening.record.member);
          expect(address.ring_id).toBe(vector.ring_id);
          expect(address.domain).toBe(hex(domainField(RingDomain.addressRecord)));
          expect(packBytesBe(field(address.viewing_u)).map(hex)).toEqual([
            address.view0,
            address.view1,
          ]);
          const hash = addressRecordHash({
            ringId: field(address.ring_id),
            member: field(address.member),
            nullifierPk: field(address.nullifier_pk),
            viewingU: field(address.viewing_u),
            addressRevision: BigInt(address.address_revision),
          });
          expect(hex(hash), update.name).toBe(opening.record.address_hash);
          expect(address.address_hash).toBe(opening.record.address_hash);
        }
        if (escrow !== null) {
          expect(escrow.ciphertext_hash).toBe(hex(hashBytes(field(escrow.ciphertext))));
          const key = escrowKeyHash({
            nullifierPk: field(escrow.nullifier_pk),
            ciphertext: field(escrow.ciphertext),
          });
          expect(hex(key), update.name).toBe(opening.record.escrow_key);
        }
        if (address !== null && escrow !== null)
          expect(address.nullifier_pk, update.name).toBe(escrow.nullifier_pk);
      });
    }
  });

  it("carries a pair exactly on a write that binds both preimages, each opening the written record", () => {
    const zero = hex(ZERO_32);
    let paired = 0;
    for (const { update } of vector.steps) {
      update.writes.forEach((write, at) => {
        const entry = update.entries[at];
        if (entry === undefined) throw new Error("write without its entry");
        const addressHash =
          entry.address_hash === zero ? write.old_address_hash : entry.address_hash;
        const escrowKey = write.old_escrow === zero ? entry.escrow_key : write.old_escrow;
        const changed =
          entry.address_hash !== zero || (write.old_escrow === zero && entry.escrow_key !== zero);
        const bound = addressHash !== zero && escrowKey !== zero && changed;
        const { pair } = write;
        expect(pair !== null, update.name).toBe(bound);
        if (pair === null) return;
        paired += 1;
        expect(pair.address_ring).toBe(vector.ring_id);
        expect(
          hex(
            poseidon([
              domainField(RingDomain.addressRecord),
              field(pair.address_ring),
              field(entry.member),
              field(pair.nullifier_pk),
              field(pair.view0),
              field(pair.view1),
              field(BigInt(pair.address_revision).toString(16).padStart(64, "0")),
            ]),
          ),
          update.name,
        ).toBe(addressHash);
        expect(hex(poseidon([field(pair.nullifier_pk), field(pair.escrow_ciphertext_hash)]))).toBe(
          escrowKey,
        );
      });
    }
    expect(paired).toBeGreaterThan(0);
  });

  it("keeps the nullifier key across a rotation and moves only the viewing key", () => {
    const [first, second] = [1n, 2n].map((revision) =>
      enrolledKeys(enrollmentOf(vector.owners[0] ?? "", revision)),
    );
    expect(first?.nullifierPk).toEqual(second?.nullifierPk);
    expect(first?.viewingU).not.toEqual(second?.viewingU);
  });
});

describe("enrollment", () => {
  const registry = encodeBase58(field(vector.registry));
  const enrollments = vector.steps.flatMap((step) => step.enrollments);

  it("lays out tag 5, the nullifier key and the viewing key, the ring id off the data", async () => {
    expect(enrollments.length).toBeGreaterThan(0);
    for (const enrollment of enrollments) {
      const owner = encodeBase58(field(enrollment.owner));
      const instruction = await enrollAddressInstruction({
        payer: encodeBase58(field(vector.creator)),
        owner,
        registry,
        ...enrolledKeys(enrollment),
      });
      const data = Uint8Array.from(instruction.data ?? []);
      expect(hex(data)).toBe(enrollment.instruction_data);
      expect(data).toHaveLength(65);
      expect(data[0]).toBe(ENROLL_ADDRESS_TAG);
      expect(instruction.programAddress).toBe(STORAGE_PROGRAM_ID);
      const [authorization] = await addressAuthorizationPda(registry, owner);
      expect(instruction.accounts?.map((account) => account.address)).toEqual([
        encodeBase58(field(vector.creator)),
        owner,
        registry,
        authorization,
        SYSTEM_PROGRAM,
      ]);
    }
  });

  it("refuses a viewing key off its encoding at building", async () => {
    await expect(
      enrollAddressInstruction({
        payer: encodeBase58(field(vector.creator)),
        owner: encodeBase58(field(vector.owners[0] ?? "")),
        registry,
        nullifierPk: field("11".repeat(32)),
        viewingU: ZERO_32,
      }),
    ).rejects.toMatchObject({ code: "RING_NONCANONICAL_VIEWING_KEY" });
  });

  it("decodes the authorization account to the hash a queued address write chains", () => {
    const enrollment = enrollmentOf(vector.owners[0] ?? "", 2n);
    const keys = enrolledKeys(enrollment);
    const data = new Uint8Array(178);
    data[0] = 2;
    data[1] = 254;
    data.set(field(vector.registry), 2);
    data.set(field(enrollment.owner), 34);
    data.set(field(vector.ring_id), 66);
    data.set(keys.nullifierPk, 98);
    data.set(keys.viewingU, 130);
    data[162] = 2;
    data[170] = 1;
    const decoded = decodeAddressAuthorization(data);
    expect(decoded).toMatchObject({
      bump: 254,
      registry,
      owner: encodeBase58(field(enrollment.owner)),
      addressRevision: 2n,
      appliedRevision: 1n,
    });
    const rotation = namedStep("rotation_moves_the_owner_revision_and_replaces_the_hash");
    expect(hex(authorizationAddressHash(decoded))).toBe(rotation.entries[0]?.address_hash);
    expect(() => decodeAddressAuthorization(data.subarray(1))).toThrow(
      expect.objectContaining({ code: "RING_ADDRESS_NOT_ENROLLED" }),
    );
    const other = data.slice();
    other[0] = 1;
    expect(() => decodeAddressAuthorization(other)).toThrow(
      expect.objectContaining({ code: "RING_ADDRESS_NOT_ENROLLED" }),
    );
  });
});

describe("address writes", () => {
  const MEMBER = field("00".repeat(31) + "07");
  const CIPHERTEXT = field("56".repeat(32));

  it("builds a zero address hash on an authority record and on an escrow write", () => {
    const escrow = escrowEntry(MEMBER, {
      nullifierPk: field("11".repeat(32)),
      ciphertext: CIPHERTEXT,
    });
    expect(escrow.addressHash).toBeUndefined();
    expect(queueEntryHash(escrow)).toEqual(queueEntryHash({ ...escrow, addressHash: ZERO_32 }));
    const authority = namedStep("authority_lists_a_neighbor").entries[0];
    expect(authority?.address_hash).toBe(hex(ZERO_32));
    const unrelated = namedStep("an_escrow_write_without_an_address_proves_no_preimage").entries[0];
    expect(unrelated?.address_hash).toBe(hex(ZERO_32));
    const entry: QueueEntry = { member: MEMBER, mask: 1n, value: 1n, escrowKey: ZERO_32 };
    expect(queueEntryHash(entry)).not.toEqual(
      queueEntryHash({ ...entry, addressHash: field("22".repeat(32)) }),
    );
  });

  it("keeps an existing address under a zero entry and replaces it under a nonzero one", () => {
    const update = namedStep("an_unrelated_write_and_a_predecessor_relink_keep_the_address");
    const write = update.writes.find((candidate) => candidate.exists);
    const vectorEntry = update.entries[update.writes.findIndex((candidate) => candidate.exists)];
    if (write === undefined || vectorEntry === undefined) throw new Error("no present write");
    expect(write.old_address_hash).not.toBe(hex(ZERO_32));
    const old: MemberRecord = {
      member: field(write.member),
      next: field(write.old_next),
      lists: BigInt(write.old_lists),
      escrowKey: field(write.old_escrow),
      mintPolicy: EMPTY_MINT_POLICY,
      addressHash: field(write.old_address_hash),
    };
    const slot = path(write.slot);
    const oldRoot = quadPathRoot(slot, memberRecordHash(old));
    const replayed = (addressHash?: Bytes32) =>
      replayRecordWrites({
        oldRoot,
        oldNextIndex: update.old_next_index,
        chainStart: ZERO_32,
        writes: [
          writeOf(write, {
            ...entryOf(vectorEntry),
            ...(addressHash === undefined ? { addressHash: ZERO_32 } : { addressHash }),
          }),
        ],
      }).newRoot;
    const lists = BigInt(vectorEntry.value);
    expect(replayed()).toEqual(quadPathRoot(slot, memberRecordHash({ ...old, lists })));
    const replacement = field("22".repeat(32));
    expect(replayed(replacement)).toEqual(
      quadPathRoot(slot, memberRecordHash({ ...old, lists, addressHash: replacement })),
    );
  });

  it("counts an address-only insert as nonempty and proves an empty write's absence alone", () => {
    const update = namedStep("an_address_only_write_inserts_the_record");
    const [write] = update.writes;
    const [entry] = update.entries;
    if (write === undefined || entry === undefined) throw new Error("no write");
    expect([entry.mask, entry.value, entry.escrow_key]).toEqual(["0", "0", hex(ZERO_32)]);
    expect(update.new_next_index).toBe(update.old_next_index + 1);
    expect(hex(replay(update).newRoot)).toBe(update.new_root);
    const unwritten = replayRecordWrites({
      oldRoot: field(update.old_root),
      oldNextIndex: update.old_next_index,
      chainStart: field(update.chain_start),
      writes: [writeOf(write, { ...entryOf(entry), addressHash: ZERO_32 })],
    });
    expect(hex(unwritten.newRoot)).toBe(update.old_root);
    expect(unwritten.newNextIndex).toBe(update.old_next_index);
  });

  it("hashes another ring, member or revision apart", () => {
    const base = {
      ringId: field(vector.ring_id),
      member: MEMBER,
      nullifierPk: field("11".repeat(32)),
      viewingU: field("51".repeat(32)),
      addressRevision: 1n,
    };
    const hashes = [
      base,
      { ...base, ringId: field("12".repeat(32)) },
      { ...base, member: field("00".repeat(31) + "08") },
      { ...base, nullifierPk: field("13".repeat(32)) },
      { ...base, viewingU: field("52".repeat(32)) },
      { ...base, addressRevision: 2n },
    ].map((input) => hex(addressRecordHash(input)));
    expect(new Set(hashes).size).toBe(hashes.length);
  });
});

describe("checkedViewingU", () => {
  const refused = expect.objectContaining({ code: "RING_NONCANONICAL_VIEWING_KEY" });

  it("refuses zero, `2^255 - 19` and every encoding at or past it", () => {
    for (const value of [
      ZERO_32,
      little(CURVE25519_FIELD),
      little(CURVE25519_FIELD + 1n),
      field("ff".repeat(32)),
    ])
      expect(() => checkedViewingU(value)).toThrow(refused);
  });

  it("reads the key little endian as X25519 and the Storage program do", () => {
    const largest = little(CURVE25519_FIELD - 1n);
    expect(checkedViewingU(largest)).toEqual(largest);
    const lowBytesHigh = little(0xffn);
    expect(checkedViewingU(lowBytesHigh)).toEqual(lowBytesHigh);
    for (let seed = 1; seed < 9; seed += 1) {
      const key = X25519Keypair.fromBytes(new Uint8Array(32).fill(seed)).publicKey().u();
      expect(checkedViewingU(key)).toEqual(key);
    }
  });

  it("leaves its input unchanged", () => {
    const value = little(0x0102n);
    checkedViewingU(value);
    expect(value).toEqual(little(0x0102n));
  });
});
