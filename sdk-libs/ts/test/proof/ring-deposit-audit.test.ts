import {
  AccountRole,
  address,
  generateKeyPairSigner,
  getAddressDecoder,
  getBase58Decoder,
  signTransactionWithSigners,
  type Address,
  type Signature,
} from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import {
  BN254_SCALAR_ORDER,
  poseidon,
  solanaOwnerIdentity,
  treeAddress,
  bigIntToBytes,
  checkedBytes,
  decodeRingDepositInstructionData,
  encodeRingDepositInstructionData,
} from "@heliuslabs/zolana/internal";
import { SHIELDED_POOL_PROGRAM_ID, initializePoseidon } from "@heliuslabs/zolana";
import {
  InstructionTag,
  DepositAsset,
  type Bytes16,
  type Bytes32,
  type Bytes33,
} from "@heliuslabs/zolana/interface";
import {
  ShieldedKeypair,
  ViewingKey,
  X25519Keypair,
} from "@heliuslabs/zolana/keypair";
import { SOL_MINT, ownerUtxoHash } from "@heliuslabs/zolana/transaction";
import depositVector from "../../../../test-vectors/deposit/deposit-v4.json" with { type: "json" };
import mergeVector from "../../../../test-vectors/merge/merge_v4.json" with { type: "json" };
import {
  encodeOpeningRecord,
  RecordKind,
  type AuditRecord,
} from "../../src/protocol/codec/audit-stream.js";
import { RingInstructionTag } from "../../src/protocol/transaction/instruction-tag.js";
import { LocalRingKeys } from "../../src/state/ring-keys.js";
import type { StorageRecordPool, StorageRecordPoolRequest } from "../../src/rpc/ports.js";
import type { RingProofRequest } from "../../src/rpc/prover/ring.js";
import { ringCoSignerAddress, ringPolicyPda } from "../../src/protocol/pda/index.js";
import { depositBlinding } from "../../src/crypto/derivation/ring-domain.js";
import {
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  type RingCoSigner,
  type RingMode,
} from "../../src/protocol/codec/ring-codecs.js";
import {
  PreparedRingDeposit,
  buildRingDepositTransaction,
  type RingDepositClient,
  type RingDepositParams,
} from "../../src/operations/payments/deposit.js";
import {
  openRingDepositOpening,
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "../../src/proof/deposit-audit.js";
import {
  encodeRingDepositCapsule,
  readRingDepositCapsule,
  RING_DEPOSIT_OPENING_LENGTH,
} from "../../src/protocol/codec/deposit-capsule.js";
import {
  AUDITED_DEPOSIT_PREFIX_LENGTH,
  ringDepositInstruction,
} from "../../src/protocol/transaction/deposit-instruction.js";
import { decryptRingDepositUtxo } from "../../src/protocol/transaction/deposit-payload.js";
import { encodeRingDepositPlaintext } from "../../src/protocol/codec/ring-deposit-plaintext.js";
import { ConfirmedDeposit } from "../../src/protocol/transaction/origin.js";
import {
  buildRuleTable,
  ListId,
  policySourceOwners,
  policyTableHash,
  recordBit,
  type RuleTable,
} from "../../src/protocol/membership/policy.js";
import type { TrackingEntry } from "../../src/protocol/membership/tracking.js";
import { BLOCKHASH } from "../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { confirmedDepositTransaction } from "../helpers/confirmed-deposits.js";
import { recordTree, trackingTree, type FixtureRecord } from "../helpers/member-registry.js";
import {
  ownedAccount,
  ownSources,
  ringCoSignerAccount,
  ringPolicyData,
  storageRegistryAccount,
  trackingRegistryAccount,
} from "../helpers/ring-accounts.js";
import { TRACKING_REVISION, trackingEntry } from "../helpers/ring-pipeline.js";
import { type RingKeys } from "../../src/state/ring-keys.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import { RingAddress, RingPaymentRequest } from "../../src/crypto/keys/ring-address.js";
import { RingProgramError, createRingDepositSubmission } from "../../src/index.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = treeAddress(0);
const PAYER = address("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T");
const CONTEXT = Object.freeze({ slot: 1n, blockTime: 1n });
const RECORDS = address("Stor111111111111111111111111111111111111111");
const RECORDS_REVISION = 3n;
const TRACKING = address("Cura111111111111111111111111111111111111111");
function field(value: bigint): Bytes32 {
  return bigIntToBytes(value) as Bytes32;
}
function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}
function vectorBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}
function u64le(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, true);
  return bytes;
}
function ringRecord(ownerKey: Bytes32, nullifierPk: Bytes32): AuditRecord {
  return { kind: RecordKind.ring, amount: 1n, ownerKey, mint: SOL_MINT, nullifierPk };
}
function recordOwnerHash(record: AuditRecord): Bytes32 {
  return poseidon([solanaOwnerIdentity(record.ownerKey), record.nullifierPk]) as Bytes32;
}
/** A confirmed wrapper of `tag` and its SPP self-CPI, each ciphertext one encoded capsule. */
function confirmedAudited(
  input: Readonly<{
    tag: number;
    prefixLength: number;
    ciphertexts: readonly Uint8Array[];
    ephemeralPublicKey: Bytes33;
    owners: readonly Bytes32[];
  }>,
): readonly ConfirmedDeposit[] {
  const signature = "1".repeat(87) as Signature;
  const wire = Uint8Array.of(
    InstructionTag.ringDeposit,
    ...encodeRingDepositInstructionData({
      assets: [{ kind: "sol" }],
      deposits: input.ciphertexts.map((ciphertext, slot) => ({
        assetIndex: 0,
        viewTag: new Uint8Array(32) as Bytes32,
        ownerUtxoHash: input.owners[slot] as Bytes32,
        amount: 1n,
        ringDataHash: new Uint8Array(32) as Bytes32,
        encrypted: {
          txViewingPublicKey: input.ephemeralPublicKey,
          salt: new Uint8Array(16) as Bytes16,
          ciphertext,
        },
      })),
    }),
  );
  const encode = getBase58Decoder();
  const wrapper = Uint8Array.of(input.tag, ...new Uint8Array(input.prefixLength - 1), ...wire);
  return ConfirmedDeposit.fromTransaction(
    {
      transaction: {
        signatures: [signature],
        message: {
          accountKeys: [RING, SHIELDED_POOL_PROGRAM_ID],
          instructions: [{ programIdIndex: 0, accounts: [], data: encode.decode(wrapper) }],
        },
      },
      meta: {
        err: null,
        innerInstructions: [
          {
            index: 0,
            instructions: [
              { programIdIndex: 1, accounts: [], data: encode.decode(wire), stackHeight: 2 },
              {
                programIdIndex: 1,
                accounts: [],
                data: encode.decode(Uint8Array.of(InstructionTag.emitEvent, 0)),
                stackHeight: 3,
              },
            ],
          },
        ],
      },
    },
    signature,
    0,
    RING,
  );
}
beforeAll(initializePoseidon);

describe("deposit disclosure", () => {
  it("hashes the deposit context over the SPP wire", () => {
    const contextHash = ringDepositContextHash(
      getAddressDecoder().decode(new Uint8Array(32).fill(0x33)),
      getAddressDecoder().decode(new Uint8Array(32).fill(0x44)),
      Uint8Array.of(18, 1, 0, 2),
    );
    expect(hex(contextHash)).toBe(
      "2cc6b9a5a2cb550702b5387ade744abee5e6eeb7c266415e59502e6f8acce56b",
    );
  });

  it.each(depositVector.cases.map((vector) => [vector.name, vector] as const))(
    "opens the %s record of deposit-v4.json and refuses another commitment",
    (_, vector) => {
      const auditor = X25519Keypair.fromBytes(
        Uint8Array.from(Buffer.from(mergeVector.auditor_sk.slice(2), "hex")) as Bytes32,
      );
      expect(hex(auditor.publicKey().toBytes())).toBe(vector.auditor_pubkey);
      const ephemeralPublicKey = vectorBytes(vector.eph_pk) as Bytes33;
      const owners = vector.owner_utxo_hashes.map((owner) => vectorBytes(owner) as Bytes32);
      const capsules = vector.ciphertexts.map((ciphertext, slotIndex) => ({
        slotIndex,
        ephemeralPublicKey,
        ciphertext: vectorBytes(ciphertext),
        recipientCiphertext: new Uint8Array(),
      }));
      const confirmed = confirmedAudited({
        tag: RingInstructionTag.deposit,
        prefixLength: AUDITED_DEPOSIT_PREFIX_LENGTH,
        ciphertexts: capsules.map(encodeRingDepositCapsule),
        ephemeralPublicKey,
        owners,
      });
      capsules.forEach((capsule, slot) => {
        const opened = openRingDepositOpening(
          capsule,
          auditor,
          owners[slot] as Bytes32,
          confirmed[slot] as ConfirmedDeposit,
        );
        expect(hex(encodeOpeningRecord({ record: opened.record, secret: opened.blinding }))).toBe(
          vector.records[slot],
        );
        expect(() =>
          openRingDepositOpening(capsule, auditor, field(1n), confirmed[slot] as ConfirmedDeposit),
        ).toThrow(expect.objectContaining({ code: "RING_AUDIT_MESSAGE" }));
      });
      auditor.destroy();
    },
  );

  it("opens every slot of one shared stream and preserves recipient ciphertext", () => {
    const auditor = X25519Keypair.generate();
    const openings = Array.from({ length: 8 }, (_, index) => ({
      record: ringRecord(new Uint8Array(32).fill(index + 1) as Bytes32, field(BigInt(index + 1))),
      blinding: field(BigInt(index + 11)),
      recipientCiphertext: Uint8Array.of(index, 9),
    }));
    const commitments = openings.map((opening) =>
      ownerUtxoHash(recordOwnerHash(opening.record), opening.blinding),
    );
    const sealed = sealRingDepositOpenings(openings, auditor.publicKey());
    const signature = "1".repeat(87) as Signature;
    const confirmed = ConfirmedDeposit.fromTransaction(
      confirmedDepositTransaction(RING, signature, sealed.capsules, commitments),
      signature,
      0,
      RING,
    );
    try {
      for (const [index, encoded] of sealed.payloads.entries()) {
        const capsule = readRingDepositCapsule(encoded);
        const opening = openings[index];
        const binding = confirmed[index];
        if (capsule === undefined || opening === undefined || binding === undefined)
          throw new Error("missing slot");
        expect(capsule.slotIndex).toBe(index);
        expect(capsule.ephemeralPublicKey).toEqual(sealed.capsules[0]?.ephemeralPublicKey);
        expect(capsule.recipientCiphertext).toEqual(opening.recipientCiphertext);
        const opened = openRingDepositOpening(
          capsule,
          auditor,
          commitments[index] as Bytes32,
          binding,
        );
        expect(opened.ownerHash).toEqual(recordOwnerHash(opening.record));
        expect(opened.blinding).toEqual(opening.blinding);
        expect(opened.ownerKey).toEqual(opening.record.ownerKey);
        expect(opened.record).toEqual(opening.record);
        expect(() => openRingDepositOpening(capsule, auditor, field(0n), binding)).toThrow(
          expect.objectContaining({ code: "RING_AUDIT_MESSAGE" }),
        );
      }
      const first = sealed.capsules[0];
      if (first === undefined) throw new Error("missing capsule");
      expect(() =>
        readRingDepositCapsule(
          sealed.payloads[0]?.slice(0, 41 + RING_DEPOSIT_OPENING_LENGTH) ?? new Uint8Array(),
        ),
      ).toThrow(
        expect.objectContaining({ code: "INTERFACE_CODEC", details: { field: "deposit capsule" } }),
      );
      expect(() => encodeRingDepositCapsule({ ...first, slotIndex: 8 })).toThrow(
        expect.objectContaining({ code: "INTERFACE_CODEC", details: { field: "deposit slot" } }),
      );
      expect(readRingDepositCapsule(Uint8Array.of(1, 2, 3))).toBeUndefined();
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("binds the SPP wire, both addresses, the anonymous flag, the commitments and the ciphertext", () => {
    const auditor = X25519Keypair.generate();
    const sealed = sealRingDepositOpenings(
      [
        {
          record: ringRecord(field(0n), field(1n)),
          blinding: field(2n),
          recipientCiphertext: Uint8Array.of(3),
        },
      ],
      auditor.publicKey(),
    );
    try {
      const contextHash = ringDepositContextHash(RING, TREE, Uint8Array.of(18, 1));
      expect(ringDepositContextHash(RING, TREE, Uint8Array.of(18, 2))).not.toEqual(contextHash);
      expect(ringDepositContextHash(TREE, RING, Uint8Array.of(18, 1))).not.toEqual(contextHash);
      const input = {
        contextHash,
        anonymous: false,
        ownerCommitments: [ownerUtxoHash(field(1n), field(2n))],
        capsules: sealed.capsules,
        assets: [{ asset: field(4n), amount: 5n }],
        auditorPublicKey: auditor.publicKey(),
        trackingRoot: field(8n),
      };
      const hash = ringDepositPublicInputHash(input);
      expect(ringDepositPublicInputHash({ ...input, trackingRoot: field(7n) })).not.toEqual(hash);
      expect(ringDepositPublicInputHash({ ...input, anonymous: true })).not.toEqual(hash);
      expect(ringDepositPublicInputHash({ ...input, ownerCommitments: [field(3n)] })).not.toEqual(
        hash,
      );
      expect(
        ringDepositPublicInputHash({ ...input, assets: [{ asset: field(4n), amount: 6n }] }),
      ).not.toEqual(hash);
      expect(
        ringDepositPublicInputHash({
          ...input,
          registry: { ownRoot: field(0n), policyHash: field(9n) },
        }),
      ).not.toEqual(hash);
      expect(() =>
        ringDepositPublicInputHash({ ...input, contextHash: field(BN254_SCALAR_ORDER) }),
      ).toThrow(expect.objectContaining({ code: "RING_BUILD_DEPOSIT" }));
      const capsule = sealed.capsules[0];
      if (capsule === undefined) throw new Error("missing capsule");
      capsule.ciphertext[0] = (capsule.ciphertext[0] ?? 0) ^ 1;
      expect(ringDepositPublicInputHash(input)).not.toEqual(hash);
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("unwraps the recipient ciphertext behind the auditor capsule", () => {
    const auditor = X25519Keypair.generate();
    const envelope = ViewingKey.generate();
    const recipient = ShieldedKeypair.generate();
    const blinding = field(15n);
    const salt = new Uint8Array(16) as Bytes16;
    const ciphertext = envelope.encryptRingDeposit(
      recipient.viewingPublicKey(),
      encodeRingDepositPlaintext({ blinding, ringData: Uint8Array.of(9) }),
      salt,
    );
    const sealed = sealRingDepositOpenings(
      [
        {
          record: ringRecord(
            recipient.signingPublicKey().confidentialViewTag(),
            recipient.nullifierPublicKey(),
          ),
          blinding,
          recipientCiphertext: ciphertext,
        },
      ],
      auditor.publicKey(),
    );
    try {
      const output = {
        ownerUtxoHash: ownerUtxoHash(recipient.shieldedAddress().ownerHash(), blinding),
        asset: SOL_MINT,
        amount: 7n,
        ringProgramId: RING,
        ringDataHash: field(0n),
        encrypted: { txViewingPublicKey: envelope.publicKey().toBytes(), salt, ciphertext },
      };
      const bare = decryptRingDepositUtxo(output, recipient, recipient.signingPublicKey());
      const capsule = sealed.payloads[0];
      if (capsule === undefined) throw new Error("missing capsule");
      const audited = decryptRingDepositUtxo(
        { ...output, encrypted: { ...output.encrypted, ciphertext: capsule } },
        recipient,
        recipient.signingPublicKey(),
      );
      expect(audited.blinding).toEqual(bare.blinding);
      expect(audited.data).toEqual(bare.data);
    } finally {
      sealed.ephemeralSecret.fill(0);
      envelope.destroy();
      auditor.destroy();
      recipient.destroy();
    }
  });
});

describe("audited deposit instruction", () => {
  it("prefixes the key capacity, the proof and three revisions, then the live registries, and keeps the SPP deposit bytes and accounts", async () => {
    const auditor = X25519Keypair.generate();
    const sealed = sealRingDepositOpenings(
      Array.from({ length: 8 }, () => ({
        record: ringRecord(field(0n), field(1n)),
        blinding: field(2n),
        recipientCiphertext: Uint8Array.of(3),
      })),
      auditor.publicKey(),
    );
    try {
      const deposits = sealed.payloads.map((ciphertext) => ({
        asset: DepositAsset.sol(),
        viewTag: field(1n),
        ownerUtxoHash: ownerUtxoHash(field(1n), field(2n)),
        amount: 1n,
        ringDataHash: field(0n),
        encrypted: {
          txViewingPublicKey: auditor.publicKey().toBytes(),
          salt: new Uint8Array(16) as Bytes16,
          ciphertext,
        },
      }));
      const input = {
        ringProgramId: RING,
        tree: TREE,
        depositor: PAYER,
        deposits,
        keyCapacity: 8,
        registries: [TRACKING],
        trackingRevision: 4n,
      };
      const proof = new Uint8Array(192).fill(7);
      const plain = await ringDepositInstruction({ ...input, proof });
      const curator = TREE;
      const registered = await ringDepositInstruction({
        ...input,
        proof,
        registries: [RECORDS, curator, TRACKING],
        ownRevision: 5n,
        curatorRevision: 6n,
        cosigner: RING,
      });
      const [ring] = await ringPolicyPda(RING);
      expect(AUDITED_DEPOSIT_PREFIX_LENGTH).toBe(218);
      expect(plain.data?.[0]).toBe(RingInstructionTag.deposit);
      expect(plain.data?.[1]).toBe(8);
      expect(plain.data?.slice(2, 194)).toEqual(proof);
      expect(plain.data?.slice(194, 202)).toEqual(u64le(4n));
      expect(plain.data?.slice(202, 218)).toEqual(new Uint8Array(16));
      expect(plain.data?.[218]).toBe(InstructionTag.ringDeposit);
      expect(registered.data?.slice(194, 202)).toEqual(u64le(4n));
      expect(registered.data?.slice(202, 210)).toEqual(u64le(5n));
      expect(registered.data?.slice(210, 218)).toEqual(u64le(6n));
      expect(registered.data?.slice(218)).toEqual(plain.data?.slice(218));
      expect(plain.accounts?.slice(0, 2)).toEqual([
        { address: ring, role: AccountRole.READONLY },
        { address: TRACKING, role: AccountRole.READONLY },
      ]);
      expect(registered.accounts?.slice(0, 6)).toEqual([
        { address: ring, role: AccountRole.READONLY },
        { address: RECORDS, role: AccountRole.READONLY },
        { address: curator, role: AccountRole.READONLY },
        { address: TRACKING, role: AccountRole.READONLY },
        { address: await ringCoSignerAddress(RING, RING), role: AccountRole.READONLY },
        { address: RING, role: AccountRole.READONLY_SIGNER },
      ]);
      expect(registered.accounts?.slice(6)).toEqual(plain.accounts?.slice(2));
      await expect(
        ringDepositInstruction({ ...input, proof, deposits: [...deposits, deposits[0]!] }),
      ).rejects.toMatchObject({ code: "INTERFACE_CODEC", details: { field: "deposit count" } });
      await expect(
        ringDepositInstruction({ ...input, proof: new Uint8Array(191) }),
      ).rejects.toMatchObject({
        code: "INTERFACE_INVALID_LENGTH",
        details: { name: "deposit proof", expected: 192, actual: 191 },
      });
      await expect(
        ringDepositInstruction({ ...input, proof, deposits: [...deposits].reverse() }),
      ).rejects.toMatchObject({ code: "INTERFACE_CODEC", details: { field: "deposit capsule" } });
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });
});

describe("ring deposit builder", () => {
  const auditor = X25519Keypair.generate();

  async function fixture(
    input: Readonly<{
      mode: RingMode;
      enrolled?: readonly TrackingEntry[];
      table?: RuleTable;
      members?: readonly FixtureRecord[];
      coSigner?: RingCoSigner;
    }>,
  ) {
    const records = recordTree(input.members ?? []);
    const tracked = trackingTree(input.enrolled ?? []);
    const [policy, policyBump] = await ringPolicyPda(RING);
    const requests: RingProofRequest[] = [];
    const proveRing = vi.fn(async (request: RingProofRequest) => {
      requests.push(request);
      return new Uint8Array(192).fill(9);
    });
    const sources = input.table === undefined ? undefined : ownSources(input.table);
    const client: RingDepositClient = {
      tree: TREE,
      treeId: 0,
      getLatestBlockhash: async () => BLOCKHASH,
      getAccount: async (account: Address) => {
        if (input.coSigner !== undefined) {
          const [record, stored] = await ringCoSignerAccount(RING, input.coSigner);
          if (account === record) return stored;
        }
        if (account === policy)
          return ownedAccount(
            RING,
            ringPolicyData({
              bump: policyBump,
              auditorPublicKey: auditor.publicKey().toBytes(),
              mode: input.mode,
              ...(input.coSigner === undefined ? {} : { coSigner: input.coSigner }),
              records: RECORDS,
              tracking: TRACKING,
              ...(input.table === undefined || sources === undefined
                ? {}
                : {
                    policyHash: policyTableHash(input.table, policySourceOwners(sources)),
                    sources,
                    table: input.table,
                    generation: 1,
                  }),
            }),
          );
        if (account === RECORDS)
          return storageRegistryAccount([
            { hash: records.root, revision: RECORDS_REVISION, expiresAt: 0n },
          ]);
        if (account === TRACKING)
          return trackingRegistryAccount({
            root: tracked.root,
            revision: TRACKING_REVISION,
            nextIndex: tracked.nextIndex,
            auditorPubkey: auditor.publicKey().toBytes(),
          });
        return undefined;
      },
      getStorageRecordPool: async (request: StorageRecordPoolRequest) =>
        ({
          context: CONTEXT,
          root: { root: records.root, revision: RECORDS_REVISION, nextIndex: records.nextIndex },
          ...records.pool(request.members, request.openings),
        }) satisfies StorageRecordPool,
      getTrackingRecordPool: async (request) => tracked.pool(request.members, request.openings),
      proveRing,
    };
    return { client, requests, proveRing };
  }

  function params(
    client: RingDepositClient,
    recipient: RingDepositParams["recipient"],
    overrides: Partial<RingDepositParams> = {},
  ): RingDepositParams {
    return { client, ringProgramId: RING, feePayer: PAYER, recipient, amount: 5n, ...overrides };
  }

  const enrolled = (member: ShieldedKeypair): TrackingEntry =>
    trackingEntry(member.shieldedAddress());

  /** A holder answering only what an anonymous deposit asks, every other call fails. */
  function remoteKeys(local: LocalRingKeys): RingKeys {
    const refused = (): never => {
      throw new Error("the deposit asked the key holder for more than its tags");
    };
    return {
      address: () => local.address(),
      viewTags: (requests) => local.viewTags(requests),
      ringTagMatches: refused,
      viewingPublicKeys: refused,
      decrypt: refused,
      derive: refused,
      transactionKeys: refused,
      ringDeliverySecrets: refused,
      mergeSeeds: refused,
    };
  }

  /** A history whose current key took `count` sender tags. */
  async function advancedHistory(keys: LocalRingKeys, count: number): Promise<ViewingHistory> {
    let history = ViewingHistory.create(keys.address().viewingPublicKey, 0n);
    for (let taken = 0; taken < count; taken++) history = (await history.senderTag(keys)).history;
    return history;
  }

  /** Whether the proven deposit's SPP data carries `tag`. */
  async function publishes(
    prepared: PreparedRingDeposit,
    client: RingDepositClient,
    tag: Uint8Array,
  ): Promise<boolean> {
    const proven = await prepared.prove(client);
    return hex(Uint8Array.from(proven.instruction.data ?? [])).includes(hex(tag));
  }

  it("binds a policy ring deposit to the recipient's tracking row under the newest roots", async () => {
    const recipient = ShieldedKeypair.generate();
    const member = recipient.signingPublicKey().ownerProofInputHash();
    const members = [{ member, lists: recordBit(ListId.allow) }];
    const row = enrolled(recipient);
    const { client, requests } = await fixture({
      mode: "confidential",
      enrolled: [row],
      table: buildRuleTable({
        rules: [
          {
            subject: "outputOwner",
            source: { kind: "lists", present: [], absent: [ListId.block] },
            guard: { kind: "always" },
          },
        ],
      }),
      members,
    });
    const prepared = await PreparedRingDeposit.prepare(
      params(client, { kind: "confidential", address: recipient.shieldedAddress() }),
    );
    try {
      const proven = await prepared.prove(client);
      const [request] = requests;
      if (request?.kind !== "deposit") throw new Error("expected one deposit request");
      expect(request.anonymous).toBe(false);
      expect(request.ownerKeys[0]).toEqual(recipient.signingPublicKey().confidentialViewTag());
      expect(request.nullifierPks[0]).toEqual(recipient.nullifierPublicKey());
      const trackingRoot = trackingTree([row]).root;
      expect(request.trackingRoot).toEqual(trackingRoot);
      const opened = request.trackingPool.records[request.outputEntries[0] ?? -1];
      expect(opened?.member).toEqual(member);
      expect(opened?.nullifierPk).toEqual(recipient.nullifierPublicKey());
      const ownRoot = recordTree(members).root;
      expect(request.ownRoot).toEqual(ownRoot);
      const owner = request.ownerEntries[0];
      expect(request.ownPool.subjects[owner?.own ?? -1]?.member).toEqual(member);
      expect(request.blindingSecrets).toHaveLength(request.capacity);
      expect(proven.roots).toEqual([
        {
          ringProgramId: RING,
          registry: RECORDS,
          revision: RECORDS_REVISION,
          root: ownRoot,
        },
      ]);
      expect(proven.trackingRoot).toEqual({
        ringProgramId: RING,
        registry: TRACKING,
        revision: TRACKING_REVISION,
        root: trackingRoot,
      });
      const data = proven.instruction.data ?? new Uint8Array();
      expect(data[1]).toBe(request.capacity);
      expect(data.slice(194, 202)).toEqual(u64le(TRACKING_REVISION));
      expect(data.slice(202, 210)).toEqual(u64le(RECORDS_REVISION));
      expect(data.slice(210, 218)).toEqual(new Uint8Array(8));
      const [registry] = await ringPolicyPda(RING);
      expect(proven.instruction.accounts?.slice(0, 3)).toEqual([
        { address: registry, role: AccountRole.READONLY },
        { address: RECORDS, role: AccountRole.READONLY },
        { address: TRACKING, role: AccountRole.READONLY },
      ]);
      // The recipient opens its note from the ciphertext behind the capsule.
      const spp = data.slice(AUDITED_DEPOSIT_PREFIX_LENGTH);
      expect(spp[0]).toBe(InstructionTag.ringDeposit);
      expect(prepared.utxo.blinding).toEqual(
        depositBlinding(request.blindingSecrets[0] ?? field(0n)),
      );
      expect(prepared.utxo.ringProgramId).toBe(RING);
    } finally {
      prepared.destroy();
      recipient.destroy();
    }
    expect(requests[0]?.kind === "deposit" && requests[0].blindingSecrets[0]).toEqual(field(0n));
  });

  it("seals a confidential recipient's owner key for the auditor", async () => {
    const recipient = ShieldedKeypair.generate();
    const { client } = await fixture({ mode: "confidential", enrolled: [enrolled(recipient)] });
    const prepared = await PreparedRingDeposit.prepare(
      params(client, { kind: "confidential", address: recipient.shieldedAddress() }),
    );
    try {
      const proven = await prepared.prove(client);
      const spp = (proven.instruction.data ?? new Uint8Array()).slice(
        AUDITED_DEPOSIT_PREFIX_LENGTH,
      );
      const [entry] = decodeRingDepositInstructionData(spp.slice(1)).deposits;
      const capsule = readRingDepositCapsule(entry?.encrypted.ciphertext ?? new Uint8Array());
      if (entry === undefined || capsule === undefined) throw new Error("missing capsule");
      const signature = "1".repeat(87) as Signature;
      const [binding] = ConfirmedDeposit.fromTransaction(
        confirmedDepositTransaction(RING, signature, [capsule], [entry.ownerUtxoHash]),
        signature,
        0,
        RING,
      );
      if (binding === undefined) throw new Error("missing confirmation");
      expect(
        openRingDepositOpening(capsule, auditor, entry.ownerUtxoHash, binding).ownerKey,
      ).toEqual(recipient.signingPublicKey().confidentialViewTag());
    } finally {
      prepared.destroy();
      recipient.destroy();
    }
  });

  it("refuses a recipient off its tracking row before any proof", async () => {
    const recipient = ShieldedKeypair.generate();
    for (const [rows, causeCode] of [
      [[{ ...enrolled(recipient), nullifierPk: field(77n) }], "RING_ADDRESS_MISMATCH"],
      [[], "RING_RECIPIENT_NOT_ENROLLED"],
    ] as const) {
      const { client, proveRing } = await fixture({ mode: "confidential", enrolled: rows });
      const prepared = await PreparedRingDeposit.prepare(
        params(client, { kind: "confidential", address: recipient.shieldedAddress() }),
      );
      try {
        await expect(prepared.prove(client)).rejects.toMatchObject({
          code: "RING_BUILD_DEPOSIT",
          causeCode,
        });
        expect(proveRing).not.toHaveBeenCalled();
      } finally {
        prepared.destroy();
      }
    }
    recipient.destroy();
  });

  it("funds the hidden owner's next sender tag through a remote key holder", async () => {
    const owner = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    const viewing = owner.viewingKey();
    const tags = [0n, 1n, 2n].map((count) => viewing.senderViewTag(count));
    viewing.destroy();
    const { client, requests } = await fixture({ mode: "anonymous", enrolled: [enrolled(owner)] });
    const history = await advancedHistory(local, 2);
    const prepared = await PreparedRingDeposit.prepare(
      params(client, { kind: "anonymous", keys: remoteKeys(local), history }),
    );
    try {
      const proven = await prepared.prove(client);
      const [request] = requests;
      if (request?.kind !== "deposit") throw new Error("expected one deposit request");
      expect(request.anonymous).toBe(true);
      expect(request.ownerKeys[0]).toEqual(owner.signingPublicKey().ed25519());
      expect(request.ownRoot).toEqual(field(0n));
      expect(request.policyHash).toEqual(field(0n));
      expect(proven.roots).toBeUndefined();
      const [ring] = await ringPolicyPda(RING);
      expect(
        proven.instruction.accounts?.filter((account) => account.address === ring),
      ).toHaveLength(1);
      const spp = (proven.instruction.data ?? new Uint8Array()).slice(
        AUDITED_DEPOSIT_PREFIX_LENGTH,
      );
      const [lowest, next, stored] = tags.map(hex);
      expect(hex(spp)).toContain(stored);
      expect(hex(spp)).not.toContain(lowest);
      expect(hex(spp)).not.toContain(next);
      expect(prepared.utxo.owner.equals(owner.signingPublicKey())).toBe(true);
      expect(prepared.viewingHistory?.current().txCount).toBe(3n);
    } finally {
      prepared.destroy();
      local.destroy();
      owner.destroy();
    }
  });

  it("takes the next sender tag from the stored history and refuses a plain anonymous build", async () => {
    const owner = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    const viewing = owner.viewingKey();
    const first = viewing.senderViewTag(0n);
    const second = viewing.senderViewTag(1n);
    viewing.destroy();
    const { client, proveRing } = await fixture({
      mode: "anonymous",
      enrolled: [enrolled(owner)],
    });
    const deposit = (history: ViewingHistory) =>
      params(client, { kind: "anonymous", keys: local, history });
    const prepared: PreparedRingDeposit[] = [];
    try {
      const history = ViewingHistory.create(owner.shieldedAddress().viewingPublicKey, 0n);
      await expect(buildRingDepositTransaction(deposit(history))).rejects.toMatchObject({
        code: "RING_BUILD_DEPOSIT",
        causeCode: "RING_ANONYMOUS_SUBMISSION_REQUIRED",
        cause: { details: { use: "createRingDepositSubmission" } },
      });
      expect(proveRing).not.toHaveBeenCalled();
      const initial = await PreparedRingDeposit.prepare(deposit(history));
      prepared.push(initial);
      expect(await publishes(initial, client, first)).toBe(true);
      const stored = initial.viewingHistory;
      if (stored === undefined) throw new Error("no history");
      const next = await PreparedRingDeposit.prepare(deposit(stored));
      prepared.push(next);
      const published = hex(Uint8Array.from((await next.prove(client)).instruction.data ?? []));
      expect(published.includes(hex(second))).toBe(true);
      expect(published.includes(hex(first))).toBe(false);
    } finally {
      for (const held of prepared) held.destroy();
      local.destroy();
      owner.destroy();
    }
  });

  it("sends an anonymous deposit as a submission that keeps its tag and proves again after a stale root", async () => {
    const owner = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    const viewing = owner.viewingKey();
    const first = viewing.senderViewTag(0n);
    viewing.destroy();
    const { client, proveRing } = await fixture({
      mode: "anonymous",
      enrolled: [enrolled(owner)],
    });
    const payer = await generateKeyPairSigner();
    try {
      const history = ViewingHistory.create(owner.shieldedAddress().viewingPublicKey, 0n);
      const submission = await createRingDepositSubmission(
        params(client, { kind: "anonymous", keys: local, history }, { feePayer: payer.address }),
      );
      expect(submission.viewingHistory?.current().txCount).toBe(1n);
      const signed: string[] = [];
      let polled = 0;
      const result = await submission.send({
        sign: async (transaction) => {
          signed.push(hex(new Uint8Array(transaction.messageBytes)));
          return signTransactionWithSigners([payer], transaction);
        },
        send: async () => undefined,
        status: async () =>
          ++polled === 1
            ? { kind: "failed", instructionIndex: 0, customCode: RingProgramError.rootNotServed }
            : { kind: "confirmed", slot: 4n },
      });

      expect(result).toMatchObject({ kind: "confirmed", attempts: 2 });
      expect(proveRing).toHaveBeenCalledTimes(2);
      expect(signed.map((message) => message.includes(hex(first)))).toEqual([true, true]);
    } finally {
      local.destroy();
      owner.destroy();
    }
  });

  it("pays another member under its request's tag and refuses the viewing key as a tag", async () => {
    const member = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(member);
    const { client } = await fixture({ mode: "anonymous", enrolled: [enrolled(recipient)] });
    const to = new RingAddress({
      recipient: recipient.shieldedAddress(),
      ringProgramId: RING,
      listSalt: new Uint8Array(32).fill(1) as Bytes32,
    });
    const depositTag = recipient.viewingKey().recipientRequestViewTag(0n);
    const paid = (target: RingAddress | RingPaymentRequest) =>
      PreparedRingDeposit.prepare(params(client, { kind: "anonymousPayment", to: target }));
    const refusal = { code: "RING_BUILD_DEPOSIT", causeCode: "RING_DEPOSIT_BOOTSTRAP_TAG" };
    try {
      const requested = await paid(new RingPaymentRequest({ address: to, depositTag }));
      expect(await publishes(requested, client, depositTag)).toBe(true);
      expect(requested.viewingHistory).toBeUndefined();
      requested.destroy();
      await expect(paid(to)).rejects.toMatchObject(refusal);
      await expect(paid(new RingPaymentRequest({ address: to }))).rejects.toMatchObject(refusal);
    } finally {
      local.destroy();
      member.destroy();
      recipient.destroy();
    }
  });

  it("proves one frame once, a retry prepares a new blinding", async () => {
    const recipient = ShieldedKeypair.generate();
    const { client } = await fixture({ mode: "confidential", enrolled: [enrolled(recipient)] });
    const recipientParams = params(client, {
      kind: "confidential",
      address: recipient.shieldedAddress(),
    });
    const first = await PreparedRingDeposit.prepare(recipientParams);
    const second = await PreparedRingDeposit.prepare(recipientParams);
    try {
      await first.prove(client);
      await expect(first.prove(client)).rejects.toMatchObject({
        code: "RING_DEPOSIT_FRAME_REUSED",
      });
      expect(second.utxo.blinding).not.toEqual(first.utxo.blinding);
    } finally {
      first.destroy();
      second.destroy();
      recipient.destroy();
    }
  });

  it("refuses an address of another ring before any proof", async () => {
    const owner = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    const { client, proveRing } = await fixture({ mode: "anonymous" });
    const other = address("SysvarRent111111111111111111111111111111111");
    try {
      await expect(
        PreparedRingDeposit.prepare(
          params(client, {
            kind: "anonymousPayment",
            to: new RingAddress({
              recipient: recipient.shieldedAddress(),
              ringProgramId: other,
              listSalt: new Uint8Array(32).fill(1) as Bytes32,
            }),
          }),
        ),
      ).rejects.toMatchObject({ code: "RING_BUILD_DEPOSIT", causeCode: "RING_FOREIGN_RING" });
      expect(proveRing).not.toHaveBeenCalled();
    } finally {
      local.destroy();
      owner.destroy();
      recipient.destroy();
    }
  });

  it("refuses a public signer that names the hidden owner", async () => {
    const owner = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    const { client, proveRing } = await fixture({ mode: "anonymous" });
    try {
      await expect(
        PreparedRingDeposit.prepare(
          params(
            client,
            {
              kind: "anonymous",
              keys: remoteKeys(local),
              history: ViewingHistory.create(owner.shieldedAddress().viewingPublicKey, 0n),
            },
            { feePayer: owner.shieldedAddress().solanaAddress() },
          ),
        ),
      ).rejects.toMatchObject({
        code: "RING_BUILD_DEPOSIT",
        causeCode: "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
      });
      expect(proveRing).not.toHaveBeenCalled();
    } finally {
      local.destroy();
      owner.destroy();
    }
  });

  it("refuses a recipient the ring mode does not admit", async () => {
    const owner = ShieldedKeypair.generate();
    const local = LocalRingKeys.fromKeypair(owner);
    try {
      const anonymous = await fixture({ mode: "anonymous" });
      await expect(
        PreparedRingDeposit.prepare(
          params(anonymous.client, { kind: "confidential", address: owner.shieldedAddress() }),
        ),
      ).rejects.toMatchObject({ causeCode: "RING_ANONYMOUS_REFUSED" });
      const registry = await fixture({ mode: "confidential" });
      await expect(
        PreparedRingDeposit.prepare(
          params(registry.client, {
            kind: "anonymous",
            keys: remoteKeys(local),
            history: ViewingHistory.create(owner.shieldedAddress().viewingPublicKey, 0n),
          }),
        ),
      ).rejects.toMatchObject({ causeCode: "RING_NOT_ANONYMOUS" });
    } finally {
      local.destroy();
      owner.destroy();
    }
  });

  it("carries the co-signer only when its scope covers deposits", async () => {
    const recipient = ShieldedKeypair.generate();
    const cosigner = getAddressDecoder().decode(new Uint8Array(32).fill(0x55));
    try {
      const covered = await fixture({
        mode: "confidential",
        enrolled: [enrolled(recipient)],
        coSigner: { signer: cosigner, scope: RING_COSIGN_DEPOSITS },
      });
      const deposit = { kind: "confidential", address: recipient.shieldedAddress() } as const;
      await expect(
        PreparedRingDeposit.prepare(params(covered.client, deposit)),
      ).rejects.toMatchObject({ causeCode: "RING_COSIGNER_REQUIRED" });
      const signed = await PreparedRingDeposit.prepare(
        params(covered.client, deposit, { cosigner }),
      );
      const outside = await fixture({
        mode: "confidential",
        enrolled: [enrolled(recipient)],
        coSigner: { signer: cosigner, scope: RING_COSIGN_TRANSFERS },
      });
      const unsigned = await PreparedRingDeposit.prepare(
        params(outside.client, deposit, { cosigner }),
      );
      try {
        const withCoSigner = await signed.prove(covered.client);
        const withoutCoSigner = await unsigned.prove(outside.client);
        expect(withCoSigner.instruction.accounts?.slice(2, 4)).toEqual([
          { address: await ringCoSignerAddress(RING, cosigner), role: AccountRole.READONLY },
          { address: cosigner, role: AccountRole.READONLY_SIGNER },
        ]);
        expect(
          withoutCoSigner.instruction.accounts?.map((account) => account.address),
        ).not.toContain(cosigner);
      } finally {
        signed.destroy();
        unsigned.destroy();
      }
    } finally {
      recipient.destroy();
    }
  });
});

describe("confirmed deposit attribution", () => {
  it("opens an unknown owner only with its confirmed capsule and rejects altered or swapped bytes", () => {
    const auditor = X25519Keypair.generate();
    const signature = "1".repeat(87) as Signature;
    const ownerKey = new Uint8Array(32).fill(7) as Bytes32;
    const records = [ringRecord(ownerKey, field(1n)), ringRecord(field(0n), field(3n))];
    const owners = [
      ownerUtxoHash(recordOwnerHash(records[0] as AuditRecord), field(2n)),
      ownerUtxoHash(recordOwnerHash(records[1] as AuditRecord), field(4n)),
    ];
    const sealed = sealRingDepositOpenings(
      [
        {
          record: records[0] as AuditRecord,
          blinding: field(2n),
          recipientCiphertext: Uint8Array.of(9),
        },
        {
          record: records[1] as AuditRecord,
          blinding: field(4n),
          recipientCiphertext: Uint8Array.of(8),
        },
      ],
      auditor.publicKey(),
    );
    try {
      const transaction = confirmedDepositTransaction(RING, signature, sealed.capsules, owners);
      const bindings = ConfirmedDeposit.fromTransaction(transaction, signature, 0, RING);
      const first = sealed.capsules[0];
      const binding = bindings[0];
      const other = bindings[1];
      if (
        first === undefined ||
        binding === undefined ||
        other === undefined ||
        owners[0] === undefined
      )
        throw new Error("missing confirmation");
      expect(openRingDepositOpening(first, auditor, owners[0], binding).ownerKey).toEqual(ownerKey);
      const forged: unknown = Object.create(ConfirmedDeposit.prototype);
      expect(ConfirmedDeposit.is(forged)).toBe(false);
      expect(ConfirmedDeposit.is(binding)).toBe(true);
      for (const offset of [0, 32, 64, 95, RING_DEPOSIT_OPENING_LENGTH - 1]) {
        const ciphertext = checkedBytes<Uint8Array>(
          first.ciphertext,
          RING_DEPOSIT_OPENING_LENGTH,
          "deposit ciphertext",
        );
        ciphertext[offset] = (ciphertext[offset] ?? 0) ^ 1;
        expect(() =>
          openRingDepositOpening({ ...first, ciphertext }, auditor, owners[0]!, binding),
        ).toThrow("RING_AUDIT_MESSAGE");
      }
      expect(() =>
        openRingDepositOpening(
          { ...first, recipientCiphertext: Uint8Array.of(10) },
          auditor,
          owners[0]!,
          binding,
        ),
      ).toThrow("RING_AUDIT_MESSAGE");
      expect(() => openRingDepositOpening(first, auditor, owners[0]!, other)).toThrow(
        "RING_AUDIT_MESSAGE",
      );
      expect(() => ConfirmedDeposit.fromTransaction(transaction, signature, 1, RING)).toThrow(
        "RING_ORIGIN_DECODE",
      );
      expect(() =>
        ConfirmedDeposit.fromTransaction(transaction, "2".repeat(87) as Signature, 0, RING),
      ).toThrow("RING_ORIGIN_DECODE");
      expect(() =>
        ConfirmedDeposit.fromTransaction(
          {
            ...transaction,
            meta: { ...transaction.meta, err: { InstructionError: [0, 1] } },
          },
          signature,
          0,
          RING,
        ),
      ).toThrow("RING_ORIGIN_DECODE");
      const source = transaction.meta.innerInstructions[0]?.instructions[0];
      if (source === undefined) throw new Error("missing source");
      const unaudited = {
        ...transaction,
        transaction: {
          ...transaction.transaction,
          message: {
            ...transaction.transaction.message,
            instructions: [{ ...source, programIdIndex: 0 }],
          },
        },
      };
      expect(ConfirmedDeposit.fromTransaction(unaudited, signature, 0, RING)).toEqual([]);
    } finally {
      sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });
});
