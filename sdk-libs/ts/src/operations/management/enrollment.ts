/**
 * Owner enrollment, Rust `custom_ring_sdk::enrollment`.
 *
 * The ring program's `Enroll` creates one immutable credential per ring and owner. It carries a
 * RegisterKey proof that seals the owner's nullifier key and list salt to the ring's auditor, and
 * the SPP proof of the credential output and its address reservation. The owner authorizes, a
 * separate payer only funds. Storage `OwnerGrant` records a PDA owner's reader consent.
 *
 * Read after `protocol/membership/credential.ts` and `operations/management/credential-write.ts`.
 * Read before `operations/management/enroll-relay.ts`.
 */
import type { Address, Instruction } from "@solana/kit";

import type {
  BlockhashProvider,
  ChainReader,
  Prover,
} from "@heliuslabs/zolana/client";
import {
  SYSTEM_PROGRAM,
  Writer,
  addressBytes,
  compileUnsignedTransaction,
  equalBytes,
  fetchUserRecord,
  instruction,
  meta,
  registerInstruction,
  rightAlign,
  sha256,
  signerAddress,
  treeAddress,
  ZERO_NULLIFIER_PK,
  type SignerAccount,
} from "@heliuslabs/zolana/internal";
import {
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type RequestContext,
} from "@heliuslabs/zolana/interface";
import { X25519PublicKey, type ShieldedKeypairLike } from "@heliuslabs/zolana/keypair";
import type { Wallet } from "@heliuslabs/zolana/transaction";

import { ringIdField } from "../../crypto/derivation/ring-stream.js";
import { listTagOf } from "../../crypto/keys/list-salt.js";
import { checkedCustomRingProof } from "../../protocol/codec/ring-codecs.js";
import { RingError } from "../../protocol/error.js";
import { fetchRingPolicy } from "../../protocol/membership/config.js";
import {
  encodeAuditCredential,
  registerKeyHash,
  type AuditCredential,
} from "../../protocol/membership/credential.js";
import { memberOfTag } from "../../protocol/membership/policy.js";
import { ownerGrantPda, STORAGE_PROGRAM_ID } from "../../protocol/pda/index.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../protocol/proof/custom-ring-proof.js";
import { credentialAccounts, enrollAccounts } from "../../protocol/ring-rpc/relay-enroll-inputs.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import type { RingProver } from "../../rpc/ports.js";
import { RingTransactionSubmission, type RingSubmissionBuild } from "../workflow/submission.js";
import { ringComputeUnitLimit } from "./admin.js";
import {
  resolveCredential,
  type CredentialClient,
  type CredentialLookup,
} from "../../rpc/credential-resolver.js";
import { proveCredentialWrite, type ProvenCredentialWrite } from "./credential-write.js";
import { readerKeyBytes, type ReaderKey } from "./reader-access.js";
import { sealNullifierKey } from "./register-key.js";

export const OWNER_GRANT_TAG = 8;

export type EnrollmentReadClient = Pick<ChainReader, "getAccount">;

export interface WriteOwnerGrant {
  readonly payer: SignerAccount;
  /** Program owners sign through CPI. */
  readonly owner: SignerAccount;
  /** The grant reads in this ring's namespace alone. */
  readonly ringProgramId: Address;
  readonly reader: ReaderKey;
  readonly active: boolean;
}

/** Storage tag 8, `ring_program ‖ reader ‖ active`. */
export async function ownerGrantInstruction(input: WriteOwnerGrant): Promise<Instruction> {
  const reader = readerKeyBytes(input.reader);
  const [grant] = await ownerGrantPda(input.ringProgramId, signerAddress(input.owner), reader);
  return instruction(
    new Writer()
      .u8(OWNER_GRANT_TAG, "tag")
      .bytes(addressBytes(input.ringProgramId, "ringProgramId"), 32, "ringProgramId")
      .bytes(reader, reader.length, "reader")
      .u8(input.active ? 1 : 0, "active")
      .finish(),
    [
      meta(input.payer, true, true),
      meta(input.owner, true, false),
      meta(grant, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
    STORAGE_PROGRAM_ID,
  );
}

/** The program rebuilds the credential, a field differing from its own fails RegisterKey. */
export interface ProvenCredential {
  readonly credential: AuditCredential;
  readonly registerKey: Uint8Array;
}

/** The ring policy fixes the auditor key and the ring program the ring id, as the program reads. */
export async function proveCredential(
  input: Readonly<{
    holder: Pick<ShieldedKeypairLike, "nullifierKey">;
    owner: Address;
    ringProgramId: Address;
    /** `RingKeys.listSalt` of the ring. */
    listSalt: Bytes32;
    client: EnrollmentReadClient;
    prover: RingProver;
  }>,
  context?: RequestContext,
): Promise<ProvenCredential> {
  const policy = await fetchRingPolicy(input.client, input.ringProgramId, context);
  return proveSealedKey(
    {
      ...input,
      ringId: ringIdField(input.ringProgramId),
      member: memberOfTag(addressBytes(input.owner, "owner")),
      auditorPubkey: policy.auditorPublicKey.toBytes(),
    },
    context,
  );
}

/** Rust `EnrollInstruction`, the ring instruction a PDA owner's program also issues through CPI. */
export interface EnrollCredential {
  readonly ringProgramId: Address;
  readonly owner: SignerAccount;
  /** Funds the address reservation and fees, authorizes nothing. */
  readonly payer: SignerAccount;
  readonly outputTreeId: number;
  readonly proven: ProvenCredential;
  readonly write: Pick<ProvenCredentialWrite, "transact" | "addressRootIndex">;
}

export async function enrollCredentialInstruction(input: EnrollCredential): Promise<Instruction> {
  const { credential, registerKey } = input.proven;
  const owner = signerAddress(input.owner);
  // The program derives the member from the signing owner, another owner's credential fails.
  if (!equalBytes(credential.member, memberOfTag(addressBytes(owner, "owner"))))
    throw new RingError("RING_ENROLLMENT_CREDENTIAL_MISMATCH", {
      details: { reason: "owner" },
    });
  if (equalBytes(credential.nullifierPk, ZERO_NULLIFIER_PK))
    throw new RingError("RING_ENROLLMENT_ZERO_KEY");
  const { transact, addressRootIndex } = input.write;
  return instruction(
    new Writer()
      .u8(RingInstructionTag.enroll, "tag")
      .bytes(credential.nullifierPk, 32, "nullifierPk")
      .bytes(credential.listTag, 32, "listTag")
      .bytes(credential.ephU, 32, "ephU")
      .bytes(credential.ciphertext, 64, "ciphertext")
      .bytes(checkedCustomRingProof(registerKey), CUSTOM_RING_PROOF_LENGTH, "registerKey")
      .bytes(transact.a, 32, "transact.a")
      .bytes(transact.b, 128, "transact.b")
      .bytes(transact.c, 32, "transact.c")
      .u16(addressRootIndex, "addressRootIndex")
      .finish(),
    await enrollAccounts({ ...input, outputTree: treeAddress(input.outputTreeId) }, owner),
    input.ringProgramId,
  );
}

/** A record of another nullifier key refuses, the registry never rotates it. */
export async function credentialRegistration(
  input: Readonly<{
    owner: SignerAccount;
    payer: SignerAccount;
    nullifierPk: Bytes32;
    /** The owner's current viewing key, readers resolve it from the record. */
    viewingPublicKey: X25519PublicKey;
  }>,
  client: EnrollmentReadClient,
  context?: RequestContext,
): Promise<Instruction | undefined> {
  const owner = signerAddress(input.owner);
  const record = await fetchUserRecord({ rpc: client, owner }, context);
  if (record === undefined)
    return registerInstruction({
      owner: input.owner,
      payer: input.payer,
      nullifierPublicKey: input.nullifierPk,
      viewingPublicKey: input.viewingPublicKey.toBytes(),
    });
  if (equalBytes(record.nullifierPublicKey, input.nullifierPk)) return undefined;
  throw new RingError("RING_ENROLLMENT_KEY_MISMATCH", {
    details: { reason: "userRecord", owner },
  });
}

export type CredentialEnrollmentClient = EnrollmentReadClient & CredentialClient;

export interface PreparedEnrollment {
  readonly credential: AuditCredential;
  readonly address: Bytes32;
  readonly registration?: Instruction;
  readonly enroll: Instruction;
  /** `registration` then `enroll`. */
  readonly instructions: readonly Instruction[];
}

/** Rust `Enroll`, one RegisterKey proof and one SPP proof for the credential the program builds. */
export async function prepareEnrollment(
  input: Readonly<{
    holder: Pick<ShieldedKeypairLike, "nullifierKey" | "viewingPublicKey">;
    owner: SignerAccount;
    payer: SignerAccount;
    ringProgramId: Address;
    listSalt: Bytes32;
    outputTreeId: number;
    client: CredentialEnrollmentClient;
    prover: RingProver & Pick<Prover, "proveTransferInputs">;
  }>,
  context?: RequestContext,
): Promise<PreparedEnrollment> {
  const { owner, payer, ringProgramId, outputTreeId, client } = input;
  // 1. A queued or applied credential refuses before any proof, a credential is never replaced.
  // Unknown is no absence, the owner retries once Photon serves the snapshot.
  const resolved = await resolveCredential(
    { client, ring: ringProgramId, owner: signerAddress(owner) },
    context,
  );
  if (resolved.kind === "present")
    throw new RingError("RING_ALREADY_ENROLLED", { details: { owner: signerAddress(owner) } });
  if (resolved.kind === "unknown")
    throw new RingError("RING_ENROLLMENT_STATUS_UNKNOWN", {
      details: { owner: signerAddress(owner), reason: resolved.reason },
    });
  const accounts = await credentialAccounts(ringProgramId, signerAddress(owner));
  // 2. RegisterKey seals the key and salt to the auditor, the credential carries that envelope.
  const proven = await proveCredential({ ...input, owner: signerAddress(owner) }, context);
  const { credential } = proven;
  // 3. The user record check runs first, a record of another key refuses before the SPP proof.
  const registration = await credentialRegistration(
    {
      owner,
      payer,
      nullifierPk: credential.nullifierPk,
      viewingPublicKey: await input.holder.viewingPublicKey(),
    },
    client,
    context,
  );
  // 4. The SPP proof reserves the fixed address, a racing second enrollment fails at SPP.
  const write = await proveCredentialWrite(
    {
      credentialPda: accounts.pda,
      credential,
      outputTreeId,
      client,
      prover: input.prover,
    },
    context,
  );
  const enroll = await enrollCredentialInstruction({
    ringProgramId,
    owner,
    payer,
    outputTreeId,
    proven,
    write,
  });
  return Object.freeze({
    credential,
    address: write.address,
    ...(registration === undefined ? {} : { registration }),
    enroll,
    instructions: Object.freeze(registration === undefined ? [enroll] : [registration, enroll]),
  });
}

/**
 * Rust `RingSubmission::send`, each retry re-signs the same instructions under a fresh blockhash
 * and the fixed address lets at most one land.
 */
export async function enrollmentSubmission(
  input: Readonly<{
    prepared: PreparedEnrollment;
    feePayer: Address;
    chain: BlockhashProvider;
    wallet: Wallet;
  }>,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const { instructions, enroll } = input.prepared;
  const intentHash = sha256(new Uint8Array(enroll.data ?? [])) as Bytes32;
  const build: RingSubmissionBuild = async (attempt) => {
    const lifetime = await input.chain.getLatestBlockhash(attempt);
    return Object.freeze({
      transaction: compileUnsignedTransaction({
        feePayer: input.feePayer,
        lifetime,
        computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.enroll),
        instructions,
      }),
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash,
      ringInstructionIndex: instructions.length - 1,
    });
  };
  return new RingTransactionSubmission({
    first: await build(context),
    build,
    wallet: input.wallet,
  });
}

/** The program never replaces a credential, a stored one other than `expected` refuses. */
export function checkEnrolledCredential(
  resolved: CredentialLookup,
  expected: AuditCredential,
): void {
  if (resolved.kind !== "present") return;
  if (!equalBytes(encodeAuditCredential(resolved.credential), encodeAuditCredential(expected)))
    throw new RingError("RING_ENROLLMENT_CREDENTIAL_MISMATCH", {
      details: { reason: "stored" },
    });
}

async function proveSealedKey(
  input: Readonly<{
    holder: Pick<ShieldedKeypairLike, "nullifierKey">;
    ringId: Bytes32;
    member: Bytes32;
    auditorPubkey: Bytes33;
    listSalt: Bytes32;
    prover: RingProver;
  }>,
  context: RequestContext | undefined,
): Promise<ProvenCredential> {
  const auditor = X25519PublicKey.fromBytes(input.auditorPubkey);
  const nullifierKey = await input.holder.nullifierKey();
  const secret = nullifierKey.secretBytes();
  const nullifierSecret = rightAlign(secret);
  secret.fill(0);
  const envelope = sealNullifierKey(nullifierKey, input.listSalt, auditor);
  try {
    const credential: AuditCredential = Object.freeze({
      ringId: input.ringId,
      member: input.member,
      nullifierPk: envelope.nullifierPublicKey,
      listTag: listTagOf(input.listSalt),
      auditorPubkey: input.auditorPubkey,
      ephU: envelope.sealed.ephemeralPublicKey.u(),
      ciphertext: envelope.sealed.ciphertext,
    });
    const registerKey = await input.prover.proveRing(
      {
        kind: "registerKey",
        publicInputHash: registerKeyHash(credential),
        ringId: input.ringId,
        member: input.member,
        nullifierSecret,
        listSalt: input.listSalt,
        ephSk: envelope.ephemeralSecret,
        auditorPk: auditor.u(),
      },
      context,
    );
    return Object.freeze({
      credential,
      registerKey: checkedCustomRingProof(registerKey),
    });
  } finally {
    nullifierSecret.fill(0);
    envelope.ephemeralSecret.fill(0);
    nullifierKey.destroy();
  }
}
