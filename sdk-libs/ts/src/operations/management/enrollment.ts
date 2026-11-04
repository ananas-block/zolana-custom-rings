/** A nonzero key enrolls in the ring's tracking registry, Rust `zolana_custom_ring_sdk::storage`. */
import type { Address, Instruction } from "@solana/kit";

import type { ChainReader } from "@heliuslabs/zolana/client";
import {
  SYSTEM_PROGRAM,
  Writer,
  addressBytes,
  equalBytes,
  instruction,
  meta,
  rightAlign,
  signerAddress,
  ZERO_NULLIFIER_PK,
  type SignerAccount,
} from "@heliuslabs/zolana/internal";
import type { Bytes32, Bytes33, RequestContext } from "@heliuslabs/zolana/interface";
import { X25519PublicKey, type ShieldedKeypairLike } from "@heliuslabs/zolana/keypair";

import { listSaltOf, listTagOf } from "../../crypto/keys/list-salt.js";
import { checkedCustomRingProof } from "../../protocol/codec/ring-codecs.js";
import { RingError } from "../../protocol/error.js";
import { checkedViewingU } from "../../protocol/membership/member-opening.js";
import { memberOfTag } from "../../protocol/membership/policy.js";
import {
  decodeTrackingAuthorization,
  decodeTrackingRegistry,
  type TrackingAuthorization,
} from "../../protocol/membership/tracking.js";
import {
  ownerGrantPda,
  STORAGE_PROGRAM_ID,
  trackingAuthorizationPda,
} from "../../protocol/pda/index.js";
import { registerKeyStatementHash } from "../../protocol/proof/statement.js";
import type { RingProver } from "../../rpc/ports.js";
import { readerKeyBytes, type ReaderKey } from "./reader-access.js";
import { sealNullifierKey } from "./register-key.js";

export const ENROLL_TAG = 6;
export const APPLY_ENROLLMENTS_TAG = 7;
export const OWNER_GRANT_TAG = 8;

/** The final fields a first enrollment proves and a rotation repeats. */
export interface EnrollmentSeal {
  readonly nullifierPk: Bytes32;
  readonly listTag: Bytes32;
  readonly ephU: Bytes32;
  readonly ciphertext: Bytes32;
}

export interface Enroll {
  readonly payer: SignerAccount;
  readonly owner: SignerAccount;
  readonly trackingRegistry: Address;
  readonly seal: EnrollmentSeal;
  readonly viewingU: Bytes32;
  /** The `RegisterKey` proof on a first enrollment, none on a rotation. */
  readonly proof?: Uint8Array;
}

/** An enrolled key is final. */
export async function enrollInstruction(
  input: Enroll,
  client: EnrollmentReadClient,
  context?: RequestContext,
): Promise<Instruction> {
  const owner = signerAddress(input.owner);
  const { seal, trackingRegistry } = input;
  checkEnrollment({
    seal,
    stored: await enrollmentState({ trackingRegistry, owner }, client, context),
  });
  const [authorization] = await trackingAuthorizationPda(trackingRegistry, owner);
  const writer = new Writer()
    .u8(ENROLL_TAG, "tag")
    .bytes(seal.nullifierPk, 32, "nullifierPk")
    .bytes(seal.listTag, 32, "listTag")
    .bytes(checkedViewingU(input.viewingU), 32, "viewingU")
    .bytes(seal.ephU, 32, "ephU")
    .bytes(seal.ciphertext, 32, "ciphertext");
  if (input.proof !== undefined)
    writer.bytes(checkedCustomRingProof(input.proof), input.proof.length, "proof");
  return instruction(
    writer.finish(),
    [
      meta(input.payer, true, true),
      meta(input.owner, true, false),
      meta(trackingRegistry, false, true),
      meta(authorization, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
    STORAGE_PROGRAM_ID,
  );
}

export type EnrollmentReadClient = Pick<ChainReader, "getAccount">;

/** `undefined` before the owner's first enrollment. */
export async function enrollmentState(
  input: Readonly<{ trackingRegistry: Address; owner: Address }>,
  client: EnrollmentReadClient,
  context?: RequestContext,
): Promise<TrackingAuthorization | undefined> {
  const [address] = await trackingAuthorizationPda(input.trackingRegistry, input.owner);
  const account = await client.getAccount(address, context);
  return account === undefined ? undefined : decodeTrackingAuthorization(account.data);
}

export function checkEnrollment(
  input: Readonly<{
    seal: EnrollmentSeal;
    stored: TrackingAuthorization | undefined;
  }>,
): void {
  const { seal, stored } = input;
  if (equalBytes(seal.nullifierPk, ZERO_NULLIFIER_PK))
    throw new RingError("RING_ENROLLMENT_ZERO_KEY");
  if (stored === undefined) return;
  if (
    !equalBytes(stored.nullifierPk, seal.nullifierPk) ||
    !equalBytes(stored.listTag, seal.listTag) ||
    !equalBytes(stored.ephU, seal.ephU) ||
    !equalBytes(stored.ciphertext, seal.ciphertext)
  )
    throw new RingError("RING_ENROLLMENT_KEY_MISMATCH");
}

/** Seals the nullifier key to the registry's auditor and proves it. */
export async function proveEnrollment(
  input: Readonly<{
    holder: Pick<ShieldedKeypairLike, "nullifierKey">;
    owner: Address;
    trackingRegistry: Address;
    client: EnrollmentReadClient;
    prover: RingProver;
  }>,
  context?: RequestContext,
): Promise<Readonly<{ seal: EnrollmentSeal; proof: Uint8Array }>> {
  const account = await input.client.getAccount(input.trackingRegistry, context);
  if (account === undefined)
    throw new RingError("RING_TRACKING_INVALID", { details: { reason: "registry" } });
  const registry = decodeTrackingRegistry(account.data);
  const auditor = X25519PublicKey.fromBytes(registry.auditorPubkey);
  const member = memberOfTag(addressBytes(input.owner, "owner"));
  const nullifierKey = await input.holder.nullifierKey();
  const secret = nullifierKey.secretBytes();
  const nullifierSecret = rightAlign(secret);
  secret.fill(0);
  const envelope = sealNullifierKey(nullifierKey, auditor);
  try {
    const seal: EnrollmentSeal = Object.freeze({
      nullifierPk: envelope.nullifierPublicKey,
      listTag: listTagOf(listSaltOf(nullifierKey)),
      ephU: envelope.sealed.ephemeralPublicKey.u(),
      ciphertext: envelope.sealed.ciphertext,
    });
    const proof = await input.prover.proveRing(
      {
        kind: "registerKey",
        publicInputHash: registerKeyStatementHash({
          ringId: registry.ringId,
          member,
          nullifierPk: seal.nullifierPk,
          listTag: seal.listTag,
          auditorPubkey: registry.auditorPubkey as Bytes33,
          ephU: seal.ephU,
          ciphertext: seal.ciphertext,
        }),
        ringId: registry.ringId,
        member,
        nullifierSecret,
        ephSk: envelope.ephemeralSecret,
        auditorPk: auditor.u(),
      },
      context,
    );
    return Object.freeze({ seal, proof: checkedCustomRingProof(proof) });
  } finally {
    nullifierSecret.fill(0);
    envelope.ephemeralSecret.fill(0);
    nullifierKey.destroy();
  }
}

export interface ApplyEnrollments {
  readonly trackingRegistry: Address;
  /** The revision the proof was made against. */
  readonly revision: bigint;
  readonly proof: Uint8Array;
  readonly newRoot: Bytes32;
  readonly newNextIndex: number;
  /** Chain order, the program computes each entry from the named account. */
  readonly owners: readonly Address[];
}

/** Permissionless. */
export async function applyEnrollmentsInstruction(input: ApplyEnrollments): Promise<Instruction> {
  if (input.owners.length === 0) throw new RingError("RING_ENROLLMENT_NONE_NAMED");
  const authorizations = await Promise.all(
    input.owners.map(
      async (owner) => (await trackingAuthorizationPda(input.trackingRegistry, owner))[0],
    ),
  );
  const { proof } = input;
  return instruction(
    new Writer()
      .u8(APPLY_ENROLLMENTS_TAG, "tag")
      .u64(input.revision, "revision")
      .bytes(checkedCustomRingProof(proof), proof.length, "proof")
      .bytes(input.newRoot, 32, "newRoot")
      .u32(input.newNextIndex, "newNextIndex")
      .finish(),
    [
      meta(input.trackingRegistry, false, true),
      ...authorizations.map((authorization) => meta(authorization, false, true)),
    ],
    STORAGE_PROGRAM_ID,
  );
}

export interface WriteOwnerGrant {
  readonly payer: SignerAccount;
  /** Program owners sign through CPI. */
  readonly owner: SignerAccount;
  readonly trackingRegistry: Address;
  readonly reader: ReaderKey;
  readonly active: boolean;
}

export async function ownerGrantInstruction(input: WriteOwnerGrant): Promise<Instruction> {
  const reader = readerKeyBytes(input.reader);
  const [grant] = await ownerGrantPda(input.trackingRegistry, signerAddress(input.owner), reader);
  return instruction(
    new Writer()
      .u8(OWNER_GRANT_TAG, "tag")
      .bytes(reader, reader.length, "reader")
      .u8(input.active ? 1 : 0, "active")
      .finish(),
    [
      meta(input.payer, true, true),
      meta(input.owner, true, false),
      meta(input.trackingRegistry, false, false),
      meta(grant, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
    STORAGE_PROGRAM_ID,
  );
}
