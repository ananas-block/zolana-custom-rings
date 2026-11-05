/** The deposit audit section, 144 B opening records in one stream and the statement, Rust `instructions::deposit`. */
import { X25519PublicKey, X25519Keypair } from "@heliuslabs/zolana/keypair";
import {
  hashBytes,
  addressBytes,
  isCanonicalField,
  bigIntBytes,
  equalBytes,
  hashChain,
  hashChain4,
  poseidon,
  readOutputData,
  solanaOwnerIdentity,
  U64_MAX,
} from "@heliuslabs/zolana/internal";
import { pack33 } from "@heliuslabs/zolana/interface";
import type { Address, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { EncryptedScheme, ownerUtxoHash } from "@heliuslabs/zolana/transaction";
import { ringIdField } from "../crypto/derivation/ring-stream.js";
import {
  decodeRingDepositOutput,
  type RingDepositOutput,
} from "../protocol/codec/ring-deposit-plaintext.js";
import {
  encodeRingDepositCapsule,
  readRingDepositCapsule,
  RING_DEPOSIT_AUDIT_SLOTS,
  RING_DEPOSIT_OPENING_BLOCKS,
  RING_DEPOSIT_OPENING_LENGTH,
  type RingDepositCapsule,
} from "../protocol/codec/ring-deposit-capsule.js";
import {
  decodeOpeningRecord,
  encodeOpeningRecord,
  type AuditRecord,
} from "../protocol/codec/audit-stream.js";
import { auditSharedSecret, DEPOSIT_ENC_INFO, symmetricAuditApply } from "../crypto/audit/audit.js";
import { STREAM_FIRST_COUNTER } from "../protocol/codec/ring-disclosure-layout.js";
import { RingError } from "../protocol/error.js";
import { domainField, RingDomain } from "../crypto/derivation/ring-domain.js";
import { ConfirmedDeposit } from "../protocol/transaction/origin.js";
import type { CredentialRoots } from "../protocol/codec/credential-read.js";
import { credentialCapacity } from "../protocol/proof/proving-keys.js";

const PAYLOAD_LENGTH = RING_DEPOSIT_OPENING_LENGTH * RING_DEPOSIT_AUDIT_SLOTS;
const ZERO = new Uint8Array(32) as Bytes32;

/** One deposit the auditor opens, the record's `secret` is its blinding. */
export interface RingDepositSealInput {
  readonly record: AuditRecord;
  readonly blinding: Bytes32;
  readonly recipientCiphertext: Uint8Array;
}

/** An opened deposit, `ownerHash` the owner commitment preimage. */
export interface RingDepositOpening extends RingDepositSealInput {
  readonly ownerHash: Bytes32;
  /** The proof binds its Solana owner identity into `ownerHash`. */
  readonly ownerKey: Bytes32;
}

/** One ephemeral key per batch, slot `i` at counter `2 + 9i`. */
export function sealRingDepositOpenings(
  openings: readonly RingDepositSealInput[],
  auditor: X25519PublicKey,
): Readonly<{
  capsules: readonly RingDepositCapsule[];
  payloads: readonly Uint8Array[];
  ephemeralSecret: Bytes32;
}> {
  if (openings.length < 1 || openings.length > RING_DEPOSIT_AUDIT_SLOTS)
    throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit count" } });
  const ephemeral = X25519Keypair.generate();
  const plaintext = new Uint8Array(PAYLOAD_LENGTH);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  let ciphertext: Uint8Array | undefined;
  try {
    for (const [index, opening] of openings.entries()) {
      if (!isCanonicalField(opening.blinding)) throw new RingError("RING_BUILD_DEPOSIT");
      const record = encodeOpeningRecord({ record: opening.record, secret: opening.blinding });
      plaintext.set(record, index * RING_DEPOSIT_OPENING_LENGTH);
      record.fill(0);
    }
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditor);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditor);
    ciphertext = symmetricAuditApply(
      shared,
      { label: DEPOSIT_ENC_INFO, counter: STREAM_FIRST_COUNTER },
      plaintext,
    );
    const encrypted = ciphertext;
    const capsules = openings.map((opening, index): RingDepositCapsule =>
      Object.freeze({
        slotIndex: index,
        ephemeralPublicKey: ephemeralPublicKey.toBytes(),
        ciphertext: encrypted.slice(
          index * RING_DEPOSIT_OPENING_LENGTH,
          (index + 1) * RING_DEPOSIT_OPENING_LENGTH,
        ),
        recipientCiphertext: new Uint8Array(opening.recipientCiphertext),
      }),
    );
    return Object.freeze({
      capsules: Object.freeze(capsules),
      payloads: Object.freeze(capsules.map(encodeRingDepositCapsule)),
      ephemeralSecret: ephemeral.secretBytes(),
    });
  } finally {
    ephemeral.destroy();
    plaintext.fill(0);
    dh?.fill(0);
    shared?.fill(0);
    ciphertext?.fill(0);
  }
}

/** @internal Rust `deposit_output`. */
export function ringDepositOutput(
  payload: Uint8Array,
  ring: Address,
): RingDepositOutput | undefined {
  try {
    const frame = readOutputData(payload);
    if (frame.encoding !== "encrypted" || frame.scheme !== EncryptedScheme.ringDeposit)
      return undefined;
    const deposit = decodeRingDepositOutput(frame.body);
    return deposit.ringProgramId === ring ? deposit : undefined;
  } catch {
    return undefined;
  }
}

/** Refuses a record whose opening misses the commitment SPP received. */
export function openRingDepositOpening(
  capsule: RingDepositCapsule,
  auditor: X25519Keypair,
  ownerCommitment: Bytes32,
  confirmed: ConfirmedDeposit,
): Omit<RingDepositOpening, "recipientCiphertext"> {
  if (!ConfirmedDeposit.is(confirmed)) throw new RingError("RING_AUDIT_MESSAGE");
  const snapshot = readRingDepositCapsule(encodeRingDepositCapsule(capsule));
  if (snapshot === undefined) throw new RingError("RING_AUDIT_MESSAGE");
  capsule = snapshot;
  confirmed.authenticate(capsule, ownerCommitment);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    const ephemeral = X25519PublicKey.fromBytes(capsule.ephemeralPublicKey);
    dh = auditor.ecdh(ephemeral);
    shared = auditSharedSecret(dh, ephemeral, auditor.publicKey());
    plaintext = symmetricAuditApply(
      shared,
      {
        label: DEPOSIT_ENC_INFO,
        counter: STREAM_FIRST_COUNTER + capsule.slotIndex * RING_DEPOSIT_OPENING_BLOCKS,
      },
      capsule.ciphertext,
    );
    const { record, secret: blinding } = decodeOpeningRecord(plaintext);
    const { ownerKey, nullifierPk } = record;
    const ownerHash = isCanonicalField(nullifierPk)
      ? (poseidon([solanaOwnerIdentity(ownerKey), nullifierPk]) as Bytes32)
      : undefined;
    if (
      ownerHash === undefined ||
      !isCanonicalField(blinding) ||
      !isCanonicalField(ownerCommitment) ||
      !equalBytes(ownerUtxoHash(ownerHash, blinding), ownerCommitment)
    ) {
      blinding.fill(0);
      throw new RingError("RING_AUDIT_MESSAGE");
    }
    return Object.freeze({ record, blinding, ownerHash, ownerKey });
  } finally {
    dh?.fill(0);
    shared?.fill(0);
    plaintext?.fill(0);
  }
}

export function ringDepositContextHash(ring: Address, tree: Address, sppWire: Uint8Array): Bytes32 {
  return hashChain([
    ringIdField(ring),
    hashBytes(addressBytes(tree)) as Bytes32,
    bigIntBytes(BigInt(sppWire.length)) as Bytes32,
    hashBytes(sppWire) as Bytes32,
  ]);
}

/** Rust `DepositedAsset`, `asset` is SPP's asset field of the entry's group. */
export interface DepositedAsset {
  readonly asset: Bytes32;
  readonly amount: bigint;
}

/** Rust `DepositRegistry`, absent off a policy ring. */
export interface DepositRegistry {
  readonly ownRoot: Bytes32;
  /** Absent without a curator source. */
  readonly curatorRoot?: Bytes32;
  /** Its table's asset rules screen every deposited asset. */
  readonly policyHash?: Bytes32;
}

/** Rust `DepositPublicInput`, the tagged keys as the statement packs them. */
export interface DepositStatement {
  readonly contextHash: Bytes32;
  /** `ringIdField` of the ring program, every credential address derives from it. */
  readonly ringId: Bytes32;
  readonly ownerUtxoHashes: readonly Bytes32[];
  readonly ciphertexts: readonly Uint8Array[];
  readonly assets: readonly DepositedAsset[];
  readonly auditorPk: Bytes33;
  readonly ephPk: Bytes33;
  /** Its capacity is the deposit key's, a key below the count cannot solve it. */
  readonly credentials: CredentialRoots;
  readonly registry?: DepositRegistry;
}

/** Rust `DepositPublicInput::elements`, every slot padded to the maximum. */
export function depositStatementElements(input: DepositStatement): readonly Bytes32[] {
  const count = input.ownerUtxoHashes.length;
  if (
    count < 1 ||
    count > RING_DEPOSIT_AUDIT_SLOTS ||
    count > input.credentials.capacity ||
    credentialCapacity({ family: "deposit", capacity: input.credentials.capacity }) === undefined ||
    input.ciphertexts.length !== count ||
    input.assets.length !== count ||
    input.ciphertexts.some((ciphertext) => ciphertext.length !== RING_DEPOSIT_OPENING_LENGTH)
  )
    throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit count" } });
  if (
    !isCanonicalField(input.contextHash) ||
    !isCanonicalField(input.ringId) ||
    !input.ownerUtxoHashes.every(isCanonicalField) ||
    !input.assets.every(
      ({ asset, amount }) => isCanonicalField(asset) && amount >= 0n && amount <= U64_MAX,
    )
  )
    throw new RingError("RING_BUILD_DEPOSIT");
  const registry = input.registry;
  return Object.freeze([
    domainField(RingDomain.depositStatement),
    input.contextHash,
    input.ringId,
    bigIntBytes(BigInt(count)) as Bytes32,
    ...Array.from({ length: RING_DEPOSIT_AUDIT_SLOTS }, (_, slot) => {
      const owner = input.ownerUtxoHashes[slot];
      const ciphertext = input.ciphertexts[slot];
      return owner === undefined || ciphertext === undefined
        ? [ZERO, ZERO]
        : [owner, hashBytes(ciphertext) as Bytes32];
    }).flat(),
    ...pack33(input.auditorPk),
    ...pack33(input.ephPk),
    ...input.credentials.elements(),
    registry?.ownRoot ?? ZERO,
    registry?.curatorRoot ?? ZERO,
    registry?.policyHash ?? ZERO,
    ...Array.from({ length: RING_DEPOSIT_AUDIT_SLOTS }, (_, slot) => {
      const deposited = input.assets[slot];
      return deposited === undefined
        ? [ZERO, ZERO]
        : [deposited.asset, bigIntBytes(deposited.amount) as Bytes32];
    }).flat(),
  ]);
}

/** Rust `DepositPublicInput::hash` over capsules that share one ephemeral key at their own slots. */
export function ringDepositPublicInputHash(
  input: Readonly<{
    contextHash: Bytes32;
    ownerCommitments: readonly Bytes32[];
    capsules: readonly RingDepositCapsule[];
    assets: readonly DepositedAsset[];
    auditorPublicKey: X25519PublicKey;
    ringId: Bytes32;
    credentials: CredentialRoots;
    registry?: DepositRegistry;
  }>,
): Bytes32 {
  const [first] = input.capsules;
  if (first === undefined || input.ownerCommitments.length !== input.capsules.length)
    throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit count" } });
  X25519PublicKey.fromBytes(first.ephemeralPublicKey);
  input.capsules.forEach((capsule, index) => {
    encodeRingDepositCapsule(capsule);
    if (
      capsule.slotIndex !== index ||
      !capsule.ephemeralPublicKey.every((byte, offset) => byte === first.ephemeralPublicKey[offset])
    )
      throw new RingError("RING_BUILD_DEPOSIT", { details: { reason: "deposit capsule" } });
  });
  return hashChain4(
    depositStatementElements({
      contextHash: input.contextHash,
      ringId: input.ringId,
      ownerUtxoHashes: input.ownerCommitments,
      ciphertexts: input.capsules.map((capsule) => capsule.ciphertext),
      assets: input.assets,
      auditorPk: input.auditorPublicKey.toBytes(),
      ephPk: first.ephemeralPublicKey,
      credentials: input.credentials,
      ...(input.registry === undefined ? {} : { registry: input.registry }),
    }),
  );
}
