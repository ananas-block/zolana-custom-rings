import {
  AccountRole,
  generateKeyPairSigner,
  signTransactionWithSigners,
  type Address,
} from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import type { NonInclusionProof, RpcAccount } from "@heliuslabs/zolana/client";
import {
  addressBytes,
  bytesToBigInt,
  internalUserRecordPda,
  signerIdentity,
  treeAddress,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import {
  USER_REGISTRY_PROGRAM_ID,
  type Bytes32,
  type Bytes64,
  type TransactProof,
} from "@heliuslabs/zolana/interface";
import { ShieldedKeypair, X25519Keypair } from "@heliuslabs/zolana/keypair";
import { AssetRegistry, ProofInputUtxo, Wallet } from "@heliuslabs/zolana/transaction";
import { loadPersistedWallet, walletSnapshotCipher } from "@heliuslabs/zolana/wallet";

import { ringIdField } from "../../../src/crypto/derivation/ring-stream.js";
import {
  credentialWriteInputs,
  proveCredentialWrite,
} from "../../../src/operations/management/credential-write.js";
import {
  checkEnrolledCredential,
  credentialRegistration,
  enrollCredentialInstruction,
  enrollmentSubmission,
  prepareEnrollment,
  type CredentialEnrollmentClient,
  type PreparedEnrollment,
} from "../../../src/operations/management/enrollment.js";
import { RingDomain } from "../../../src/crypto/derivation/ring-domain.js";
import { prepareEnrollmentRelay } from "../../../src/operations/management/enroll-relay.js";
import { RingBufferLedger } from "../../../src/operations/workflow/buffer-ledger.js";
import { reconcileRingSubmissions } from "../../../src/operations/workflow/submission.js";
import {
  ADDRESS_TREE_ID,
  credentialAddress,
  credentialAddressInput,
  credentialElements,
  credentialPda,
  credentialSeed,
  credentialStateHash,
  credentialUtxoHash,
  registerKeyHash,
  type AuditCredential,
} from "../../../src/protocol/membership/credential.js";
import { memberOfTag } from "../../../src/protocol/membership/policy.js";
import { ringPolicyPda } from "../../../src/protocol/pda/index.js";
import { credentialAccounts } from "../../../src/protocol/ring-rpc/relay-enroll-inputs.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import { resolveCredential, type CredentialLookup } from "../../../src/rpc/credential-resolver.js";
import { BLOCKHASH } from "../../../../../zolana/sdk-libs/ts/test/helpers/clients.js";
import { ownedAccount, ringPolicyData } from "../../helpers/ring-accounts.js";
import { filled, randomAddress } from "../../helpers/ring-pipeline.js";

const OUTPUT_TREE_ID = 3;
const REGISTER_KEY = new Uint8Array(192).fill(9);
const TRANSACT: TransactProof = {
  a: filled(7),
  b: new Uint8Array(128).fill(8) as TransactProof["b"],
  c: filled(9),
};
const ZERO_ROOT = new Uint8Array(32) as Bytes32;

vi.mock("../../../src/rpc/credential-resolver.js", async (actual) => ({
  ...(await actual<typeof import("../../../src/rpc/credential-resolver.js")>()),
  resolveCredential: vi.fn(),
}));

beforeAll(initializePoseidon);

function credentialOf(ringProgramId: Address, owner: Address): AuditCredential {
  return Object.freeze({
    ringId: ringIdField(ringProgramId),
    member: memberOfTag(addressBytes(owner)),
    nullifierPk: filled(2),
    listTag: filled(3),
    auditorPubkey: X25519Keypair.generate().publicKey().toBytes(),
    ephU: filled(5),
    ciphertext: new Uint8Array(64).fill(6) as Bytes64,
  });
}

function nonInclusion(leaf: Bytes32, root = filled(0x11), rootIndex = 4): NonInclusionProof {
  return {
    leaf,
    merkleContext: { treeType: 1, tree: treeAddress(ADDRESS_TREE_ID) },
    path: Array.from({ length: 40 }, () => ZERO_ROOT),
    lowElement: ZERO_ROOT,
    lowElementIndex: 0n,
    highElement: filled(0x30),
    highElementIndex: 1n,
    root,
    rootSeq: 1n,
    rootIndex,
  };
}

async function writeProofs(ringProgramId: Address, credential: AuditCredential) {
  const pda = await credentialPda(ringProgramId);
  const address = credentialAddressInput(pda, credentialSeed(credential.ringId, credential.member));
  const padding = ProofInputUtxo.compact(ADDRESS_TREE_ID);
  return {
    pda,
    address,
    addressProof: nonInclusion(address.nullifier()),
    paddingProof: nonInclusion(padding.nullifier()),
  };
}

/** The user record zolana `REGISTER` writes, at the owner's canonical PDA. */
async function userRecord(owner: Address, nullifierPk: Bytes32): Promise<[Address, RpcAccount]> {
  const { address, bump } = await internalUserRecordPda(owner);
  const data = new Uint8Array(100);
  data[0] = 1;
  data.set(addressBytes(owner), 1);
  data[33] = bump;
  data.set(nullifierPk, 34);
  data.set(X25519Keypair.generate().publicKey().toBytes(), 66);
  return [address, { owner: USER_REGISTRY_PROGRAM_ID, lamports: 1n, data }];
}

describe("credential hashes", () => {
  it("moves only the domain between the RegisterKey input and the state hash", () => {
    const credential = credentialOf(randomAddress(), randomAddress());
    const [proofDomain, ...proofFields] = credentialElements(credential, RingDomain.registerKey);
    const [stateDomain, ...stateFields] = credentialElements(
      credential,
      RingDomain.credentialState,
    );
    expect(stateFields).toEqual(proofFields);
    expect(stateDomain).not.toEqual(proofDomain);
    expect(credentialStateHash(credential)).not.toEqual(registerKeyHash(credential));
  });
});

describe("Enroll instruction", () => {
  it("writes the tag, the four fields, both proofs and the root index in Rust order", async () => {
    const ringProgramId = randomAddress();
    const owner = await generateKeyPairSigner();
    const payer = randomAddress();
    const credential = credentialOf(ringProgramId, owner.address);
    const built = await enrollCredentialInstruction({
      ringProgramId,
      owner,
      payer,
      outputTreeId: OUTPUT_TREE_ID,
      proven: { credential, registerKey: REGISTER_KEY },
      write: { transact: TRANSACT, addressRootIndex: 0x0102 },
    });
    const data = new Uint8Array(built.data ?? []);
    // Core's `EnrollRequest` payload is 546 bytes behind the tag.
    expect(data.length).toBe(547);
    expect(data[0]).toBe(RingInstructionTag.enroll);
    expect(data.subarray(1, 33)).toEqual(credential.nullifierPk);
    expect(data.subarray(97, 161)).toEqual(credential.ciphertext);
    expect(data.subarray(161, 353)).toEqual(REGISTER_KEY);
    expect(data.subarray(353, 385)).toEqual(TRANSACT.a);
    expect(data.subarray(513, 545)).toEqual(TRANSACT.c);
    expect(data.subarray(545)).toEqual(Uint8Array.of(2, 1));
    const accounts = await credentialAccounts(ringProgramId, owner.address);
    const [policy] = await ringPolicyPda(ringProgramId);
    expect(built.programAddress).toBe(ringProgramId);
    expect(built.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [owner.address, AccountRole.READONLY_SIGNER],
      [policy, AccountRole.READONLY],
      [payer, AccountRole.WRITABLE_SIGNER],
      [treeAddress(OUTPUT_TREE_ID), AccountRole.WRITABLE],
      [expect.any(String), AccountRole.READONLY],
      [expect.any(String), AccountRole.READONLY],
      [treeAddress(ADDRESS_TREE_ID), AccountRole.WRITABLE],
      [accounts.nullifierPda, AccountRole.WRITABLE],
      [accounts.pda, AccountRole.READONLY],
    ]);
  });

  it("names a PDA owner as the signer its program's CPI supplies", async () => {
    const ringProgramId = randomAddress();
    const owner = randomAddress();
    const built = await enrollCredentialInstruction({
      ringProgramId,
      owner,
      payer: randomAddress(),
      outputTreeId: OUTPUT_TREE_ID,
      proven: {
        credential: credentialOf(ringProgramId, owner),
        registerKey: REGISTER_KEY,
      },
      write: { transact: TRANSACT, addressRootIndex: 1 },
    });
    expect(built.accounts?.[0]).toEqual({
      address: owner,
      role: AccountRole.READONLY_SIGNER,
    });
  });

  it("refuses a credential of another owner and the zero key", async () => {
    const ringProgramId = randomAddress();
    const owner = randomAddress();
    const enroll = (credential: AuditCredential) =>
      enrollCredentialInstruction({
        ringProgramId,
        owner,
        payer: randomAddress(),
        outputTreeId: OUTPUT_TREE_ID,
        proven: { credential, registerKey: REGISTER_KEY },
        write: { transact: TRANSACT, addressRootIndex: 1 },
      });
    await expect(enroll(credentialOf(ringProgramId, randomAddress()))).rejects.toMatchObject({
      code: "RING_ENROLLMENT_CREDENTIAL_MISMATCH",
    });
    const zeroKey = {
      ...credentialOf(ringProgramId, owner),
      nullifierPk: ZERO_NULLIFIER_PK as Bytes32,
    };
    await expect(enroll(zeroKey)).rejects.toMatchObject({
      code: "RING_ENROLLMENT_ZERO_KEY",
    });
  });
});

describe("credential SPP write", () => {
  it("proves the address as the first nullifier and the credential leaf the resolver opens", async () => {
    const ringProgramId = randomAddress();
    const credential = credentialOf(ringProgramId, randomAddress());
    const { pda, address, addressProof, paddingProof } = await writeProofs(
      ringProgramId,
      credential,
    );
    const inputs = credentialWriteInputs({
      credentialPda: pda,
      credential,
      outputTreeId: OUTPUT_TREE_ID,
      addressProof,
      paddingProof,
    });
    const owner = signerIdentity(pda);
    expect({
      nullifiers: inputs.inputs.map((input) => input.nullifier),
      owners: inputs.inputs.map((input) => input.ownerPublicKeyHash),
      outputHash: inputs.outputs[0]?.hash,
      padding: inputs.outputs[1]?.hash,
      signers: inputs.signerPublicKeyHashes,
      blindingSeed: inputs.blindingSeed,
    }).toEqual({
      nullifiers: [bytesToBigInt(address.nullifier()), 0n],
      owners: [owner, 0n],
      outputHash: bytesToBigInt(
        credentialUtxoHash({
          pda,
          address: credentialAddress(pda, credentialSeed(credential.ringId, credential.member)),
          credential,
          treeId: OUTPUT_TREE_ID,
        }),
      ),
      padding: 0n,
      signers: [owner, 0n, 0n],
      blindingSeed: 1n,
    });
  });

  it("moves the statement with any credential field", async () => {
    const ringProgramId = randomAddress();
    const credential = credentialOf(ringProgramId, randomAddress());
    const proofs = await writeProofs(ringProgramId, credential);
    const hash = (changed: AuditCredential) =>
      credentialWriteInputs({
        ...proofs,
        credentialPda: proofs.pda,
        credential: changed,
        outputTreeId: OUTPUT_TREE_ID,
      }).publicInputHash;
    expect(
      hash({
        ...credential,
        ciphertext: new Uint8Array(64).fill(7) as Bytes64,
      }),
    ).not.toBe(hash(credential));
    expect(hash({ ...credential, listTag: filled(4) })).not.toBe(hash(credential));
  });

  it.each([
    ["another root", { root: filled(0x12) }],
    ["another root index", { rootIndex: 5 }],
    ["another leaf", { leaf: filled(0x13) }],
    ["another tree", { merkleContext: { treeType: 1, tree: treeAddress(1) } }],
  ] as const)("refuses padding proven under %s before proving", async (_, change) => {
    const ringProgramId = randomAddress();
    const credential = credentialOf(ringProgramId, randomAddress());
    const { pda, addressProof, paddingProof } = await writeProofs(ringProgramId, credential);
    const prover = { proveTransferInputs: vi.fn(async () => TRANSACT) };
    await expect(
      proveCredentialWrite({
        credentialPda: pda,
        credential,
        outputTreeId: OUTPUT_TREE_ID,
        client: {
          getNonInclusionProofs: async () => ({
            context: { slot: 1n, blockTime: 1n },
            proofs: [addressProof, { ...paddingProof, ...change }],
          }),
        },
        prover,
      }),
    ).rejects.toMatchObject({ code: "RING_ENROLLMENT_ADDRESS_PROOF" });
    expect(prover.proveTransferInputs).not.toHaveBeenCalled();
  });

  it("carries the shared root index with the proof", async () => {
    const ringProgramId = randomAddress();
    const credential = credentialOf(ringProgramId, randomAddress());
    const { pda, address, addressProof, paddingProof } = await writeProofs(
      ringProgramId,
      credential,
    );
    const proven = await proveCredentialWrite({
      credentialPda: pda,
      credential,
      outputTreeId: OUTPUT_TREE_ID,
      client: {
        getNonInclusionProofs: async () => ({
          context: { slot: 1n, blockTime: 1n },
          proofs: [addressProof, paddingProof],
        }),
      },
      prover: { proveTransferInputs: async () => TRANSACT },
    });
    expect(proven).toEqual({
      address: address.nullifier(),
      transact: TRANSACT,
      addressRootIndex: 4,
    });
  });
});

describe("user record registration", () => {
  it("registers the credential key paid by the payer when the owner holds no record", async () => {
    const owner = randomAddress();
    const payer = randomAddress();
    const viewing = X25519Keypair.generate().publicKey();
    const register = await credentialRegistration(
      { owner, payer, nullifierPk: filled(2), viewingPublicKey: viewing },
      { getAccount: async () => undefined },
    );
    expect(register?.programAddress).toBe(USER_REGISTRY_PROGRAM_ID);
    expect(register?.accounts?.[2]).toEqual({
      address: payer,
      role: AccountRole.WRITABLE_SIGNER,
    });
    expect(new Uint8Array(register?.data ?? []).subarray(1, 33)).toEqual(filled(2));
  });

  it("adds nothing for a record of the same key and refuses one of another key", async () => {
    const owner = randomAddress();
    const [recordAddress, record] = await userRecord(owner, filled(2));
    const client = {
      getAccount: async (key: Address) => (key === recordAddress ? record : undefined),
    };
    const input = {
      owner,
      payer: randomAddress(),
      viewingPublicKey: X25519Keypair.generate().publicKey(),
    };
    await expect(
      credentialRegistration({ ...input, nullifierPk: filled(2) }, client),
    ).resolves.toBe(undefined);
    await expect(
      credentialRegistration({ ...input, nullifierPk: filled(4) }, client),
    ).rejects.toMatchObject({ code: "RING_ENROLLMENT_KEY_MISMATCH" });
  });
});

describe("prepared enrollment", () => {
  const PRESENT = {
    kind: "present",
    address: filled(1),
    credential: {},
  } as unknown as CredentialLookup;
  const ABSENT = { kind: "absent", address: filled(1), gap: {} } as unknown as CredentialLookup;
  const QUEUED: CredentialLookup = { kind: "unknown", reason: "queued" };

  async function setup(
    resolved: CredentialLookup,
    extra: ReadonlyMap<Address, RpcAccount> = new Map(),
  ) {
    vi.mocked(resolveCredential).mockResolvedValue(resolved);
    const ringProgramId = randomAddress();
    const [policy, bump] = await ringPolicyPda(ringProgramId);
    const accounts = new Map<Address, RpcAccount>([
      [policy, ownedAccount(ringProgramId, ringPolicyData({ bump }))],
      ...extra,
    ]);
    const prover = {
      proveRing: vi.fn(async () => REGISTER_KEY),
      proveTransferInputs: vi.fn(async () => TRANSACT),
    };
    const holder = ShieldedKeypair.generate();
    const client = {
      getAccount: async (key: Address) => accounts.get(key),
      getNonInclusionProofs: async (_tree: Address, leaves: readonly Bytes32[]) => ({
        context: { slot: 1n, blockTime: 1n },
        proofs: leaves.map((leaf) => nonInclusion(leaf)),
      }),
    } as unknown as CredentialEnrollmentClient;
    const input = {
      holder,
      owner: randomAddress(),
      payer: randomAddress(),
      ringProgramId,
      listSalt: filled(1),
      outputTreeId: OUTPUT_TREE_ID,
      client,
      prover: prover as never,
    };
    return { input, prover, holder };
  }

  it.each([
    ["an applied or queued credential", PRESENT, "RING_ALREADY_ENROLLED"],
    ["an enrollment Photon has not served", QUEUED, "RING_ENROLLMENT_STATUS_UNKNOWN"],
  ] as const)("refuses %s before any proof", async (_, resolved, code) => {
    const f = await setup(resolved);
    await expect(prepareEnrollment(f.input)).rejects.toMatchObject({ code });
    expect(f.prover.proveRing).not.toHaveBeenCalled();
    f.holder.destroy();
  });

  it("registers then enrolls one credential sealed to the ring's auditor once proven absent", async () => {
    const f = await setup(ABSENT);
    const prepared = await prepareEnrollment(f.input);
    const { credential } = prepared;
    expect(vi.mocked(resolveCredential)).toHaveBeenCalledWith(
      expect.objectContaining({
        ring: f.input.ringProgramId,
        owner: f.input.owner,
      }),
      undefined,
    );
    expect(credential.member).toEqual(memberOfTag(addressBytes(f.input.owner)));
    expect(credential.nullifierPk).toEqual(f.holder.nullifierPublicKey());
    expect(prepared.instructions.map((entry) => entry.programAddress)).toEqual([
      USER_REGISTRY_PROGRAM_ID,
      f.input.ringProgramId,
    ]);
    expect(f.prover.proveRing).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "registerKey",
        publicInputHash: registerKeyHash(credential),
      }),
      undefined,
    );
    f.holder.destroy();
  });

  it("relays only for an owner holding a user record, the relay funds no record", async () => {
    const owner = await generateKeyPairSigner();
    const quote = { feePayer: randomAddress(), validUntilSlot: 100n };
    const missing = await setup(ABSENT);
    await expect(prepareEnrollmentRelay({ ...missing.input, owner, quote })).rejects.toMatchObject({
      code: "RING_RELAY_NEEDS_USER_RECORD",
    });
    expect(missing.prover.proveRing).not.toHaveBeenCalled();
    const holder = ShieldedKeypair.generate();
    const registered = await setup(
      ABSENT,
      new Map([await userRecord(owner.address, holder.nullifierPublicKey())]),
    );
    const prepared = await prepareEnrollmentRelay({ ...registered.input, holder, owner, quote });
    expect(prepared.request.intent.operation).toBe("enroll");
    missing.holder.destroy();
    registered.holder.destroy();
    holder.destroy();
  });
});

describe("enrollment submission", () => {
  async function fixture() {
    const holder = ShieldedKeypair.generate();
    const payer = await generateKeyPairSigner();
    const ringProgramId = randomAddress();
    const enroll = await enrollCredentialInstruction({
      ringProgramId,
      owner: payer,
      payer,
      outputTreeId: OUTPUT_TREE_ID,
      proven: {
        credential: credentialOf(ringProgramId, payer.address),
        registerKey: REGISTER_KEY,
      },
      write: { transact: TRANSACT, addressRootIndex: 1 },
    });
    const prepared: PreparedEnrollment = {
      credential: credentialOf(ringProgramId, payer.address),
      address: filled(1),
      enroll,
      instructions: [enroll],
    };
    const wallet = new Wallet({
      identity: holder.shieldedAddress(),
      registry: new AssetRegistry(),
    });
    let stored: string | undefined;
    const store = {
      load: async () => stored,
      save: vi.fn(async (snapshot: string) => {
        stored = snapshot;
      }),
    };
    let ledger: string | undefined;
    const buffers = await RingBufferLedger.load({
      load: async () => ledger,
      save: async (document) => {
        ledger = document;
      },
    });
    const blockhashes = vi.fn(async () => BLOCKHASH);
    const submission = await enrollmentSubmission({
      prepared,
      feePayer: payer.address,
      chain: { getLatestBlockhash: blockhashes },
      wallet,
    });
    const transport = {
      sign: vi.fn(async (transaction: Parameters<typeof signTransactionWithSigners>[1]) =>
        signTransactionWithSigners([payer], transaction),
      ),
      send: vi.fn(async () => undefined),
      status: vi.fn(async () => ({ kind: "unknown" as const })),
    };
    const cipher = walletSnapshotCipher(holder);
    return {
      wallet,
      store,
      cipher,
      buffers,
      transport,
      submission,
      blockhashes,
      enroll,
    };
  }

  it("saves the attempt before its broadcast and settles it once confirmed", async () => {
    const f = await fixture();
    f.transport.send.mockImplementation(async () => {
      expect((await loadPersistedWallet(f))?.pendingSubmissions()).toHaveLength(1);
      return undefined;
    });
    const result = await f.submission.sendPersisted(f);
    expect(result.kind).toBe("unknown");
    expect(f.transport.send).toHaveBeenCalledOnce();
    await reconcileRingSubmissions({
      ...f,
      transport: { status: async () => ({ kind: "confirmed", slot: 5n }) },
    });
    expect((await loadPersistedWallet(f))?.pendingSubmissions()).toEqual([]);
  });

  it("re-signs the same Enroll under a fresh blockhash after expiry", async () => {
    const f = await fixture();
    f.transport.status
      .mockResolvedValueOnce({ kind: "expired" } as never)
      .mockResolvedValue({ kind: "confirmed", slot: 6n } as never);
    const result = await f.submission.sendPersisted(f);
    expect(result).toMatchObject({ kind: "confirmed", attempts: 2 });
    expect(f.blockhashes).toHaveBeenCalledTimes(2);
    const sent = f.transport.sign.mock.calls.map(([transaction]) =>
      Buffer.from(transaction.messageBytes).includes(Buffer.from(f.enroll.data ?? [])),
    );
    expect(sent).toEqual([true, true]);
  });
});

describe("stored credential", () => {
  it("refuses a present credential other than the proved one", () => {
    const credential = credentialOf(randomAddress(), randomAddress());
    const present = (stored: AuditCredential) =>
      ({
        kind: "present",
        address: filled(1),
        credential: stored,
      }) as unknown as CredentialLookup;
    expect(() => checkEnrolledCredential(present(credential), credential)).not.toThrow();
    expect(() =>
      checkEnrolledCredential(present({ ...credential, ephU: filled(8) }), credential),
    ).toThrow("RING_ENROLLMENT_CREDENTIAL_MISMATCH");
  });
});
