import {
  hashBytes,
  hashChain4,
  randomBytes,
  Reader,
  Writer,
  isCanonicalField,
  rightAlign,
  ZERO_32,
  bigIntBytes,
  hashChain,
} from "@heliuslabs/zolana/internal";
import { symmetricApply, X25519Keypair, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import { pack33 } from "@heliuslabs/zolana/interface";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import type { PresentRecordOpening } from "../../../rpc/prover/types.js";
import { domainField, RingDomain } from "../../../crypto/derivation/ring-domain.js";
import {
  auditSharedSecret,
  openMergeDisclosureFields,
  sealMergeDisclosureFields,
} from "../../../crypto/audit/audit.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../proof/custom-ring-proof.js";
import { DISCLOSURE_CHUNK_BYTES, MERGE_WIDTHS, packedChunks } from "./layout.js";
import { RingError } from "../../error.js";

/** Rust `MERGE_DISCLOSURE_INFO`, the envelope of the disclosure key. */
const MERGE_DISCLOSURE_INFO = new TextEncoder().encode("CRING/mrg1");

export function mergeDisclosureFieldCount(width: number): number {
  return packedChunks(32 * width);
}

/** The auditor's half of a ring merge, Rust `MergeDisclosure`. */
export interface RingMergeDisclosure {
  readonly proof: Uint8Array;
  readonly ephemeralPublicKey: Bytes33;
  readonly ciphertext: Bytes32;
  readonly fields: readonly Bytes32[];
}

/** In slot order, a dummy reads zero. */
export type RingMergeOpening = readonly Bytes32[];

/** The zero nullifier key opens no record, the root and the flag stay bound. */
export interface RingMergeEscrow {
  readonly root: Bytes32;
  readonly record?: PresentRecordOpening;
  readonly ctHash: Bytes32;
}

/** Precedes the SPP merge body. */
export function writeRingMergeDisclosure(writer: Writer, disclosure: RingMergeDisclosure): Writer {
  writer
    .bytes(disclosure.proof, CUSTOM_RING_PROOF_LENGTH, "disclosure.proof")
    .bytes(disclosure.ephemeralPublicKey, 33, "disclosure.ephemeralPublicKey")
    .bytes(disclosure.ciphertext, 32, "disclosure.ciphertext")
    .u8(disclosure.fields.length, "disclosure.fields.length");
  for (const field of disclosure.fields) writer.bytes(field, 32, "disclosure.field");
  return writer;
}

export function readRingMergeDisclosure(reader: Reader): RingMergeDisclosure {
  const proof = reader.bytes(CUSTOM_RING_PROOF_LENGTH, "disclosure.proof");
  const ephemeralPublicKey = reader.bytes(33, "disclosure.ephemeralPublicKey") as Bytes33;
  const ciphertext = reader.bytes(32, "disclosure.ciphertext") as Bytes32;
  const count = reader.u8("disclosure.fields.length");
  const fields = Array.from(
    { length: count },
    () => reader.bytes(32, "disclosure.field") as Bytes32,
  );
  return Object.freeze({ proof, ephemeralPublicKey, ciphertext, fields: Object.freeze(fields) });
}

/** Only for a disclosure the ring program verified, the key fixes `width` and the proof the order. */
export function openRingMergeDisclosure(
  auditor: X25519Keypair,
  disclosure: RingMergeDisclosure,
  salt: Bytes16,
): RingMergeOpening {
  const width = MERGE_WIDTHS.find(
    (count) => mergeDisclosureFieldCount(count) === disclosure.fields.length,
  );
  if (width === undefined) throw invalid("disclosure width");
  const ephemeral = X25519PublicKey.fromBytes(disclosure.ephemeralPublicKey);
  const dh = auditor.ecdh(ephemeral);
  const shared = auditSharedSecret(dh, ephemeral, auditor.publicKey());
  const key = symmetricApply(shared, MERGE_DISCLOSURE_INFO, disclosure.ciphertext) as Bytes32;
  let plaintext: Uint8Array | undefined;
  try {
    const opened = openMergeDisclosureFields(key, salt, disclosure.fields);
    plaintext = opened;
    if (opened.subarray(32 * width).some((byte) => byte !== 0)) throw invalid("disclosure padding");
    return Object.freeze(
      Array.from({ length: width }, (_, index) => {
        const hash = opened.slice(32 * index, 32 * (index + 1)) as Bytes32;
        if (!isCanonicalField(hash)) throw invalid("disclosure input");
        return hash;
      }),
    );
  } finally {
    dh.fill(0);
    shared.fill(0);
    key.fill(0);
    plaintext?.fill(0);
  }
}

/** Binds in Rust `MergePublicInput::hash` order. */
export function ringMergePublicInputHash(
  input: Readonly<{
    partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
    privateTxHash: Bytes32;
    outputUtxoHash: Bytes32;
    firstNullifier: Bytes32;
    /** `hashBytes` of the ring program id, the value the merged notes commit. */
    ringId: Bytes32;
    auditorPublicKey: X25519PublicKey;
    disclosure: Omit<RingMergeDisclosure, "proof">;
    salt: Bytes16;
    /** Published nullifiers with a hidden dummy, never the real inputs. */
    inputCount: number;
    /** Key escrow rings only, the owner's record under the root escrows the merged nullifier key. */
    memberRegistryRoot?: Bytes32;
  }>,
): Bytes32 {
  return hashChain([
    domainField(RingDomain.mergeStatement),
    input.privateTxHash,
    input.outputUtxoHash,
    input.firstNullifier,
    input.ringId,
    ...pack33(input.auditorPublicKey.toBytes()),
    ...pack33(input.disclosure.ephemeralPublicKey),
    hashBytes(input.disclosure.ciphertext) as Bytes32,
    rightAlign(input.salt),
    hashChain4(input.disclosure.fields) as Bytes32,
    bigIntBytes(BigInt(input.inputCount)) as Bytes32,
    ...input.partyIdentities,
    bigIntBytes(input.memberRegistryRoot === undefined ? 0n : 1n) as Bytes32,
    input.memberRegistryRoot ?? ZERO_32,
  ]);
}

/** Rust `RingError::MergeTooWide`, refused before any proof. */
export function checkMergeWidth(width: number): void {
  if (!MERGE_WIDTHS.includes(width))
    throw new RingError("RING_MERGE_TOO_WIDE", { details: { width } });
}

/** The zeroed disclosure of `width` slots, sized exactly as the proved one. */
export function emptyRingMergeDisclosure(width: number): RingMergeDisclosure {
  checkMergeWidth(width);
  return Object.freeze({
    proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    ephemeralPublicKey: new Uint8Array(33) as Bytes33,
    ciphertext: new Uint8Array(32) as Bytes32,
    fields: Object.freeze(
      Array.from({ length: mergeDisclosureFieldCount(width) }, () => new Uint8Array(32) as Bytes32),
    ),
  });
}

/** The sealed half of a disclosure with the two secrets its proof witnesses. */
export interface SealedRingMergeDisclosure {
  readonly ephemeralSecret: Bytes32;
  readonly disclosureKey: Bytes32;
  readonly disclosure: Omit<RingMergeDisclosure, "proof">;
}

/** Rust `MergeDisclosureEncryption::new`, the ephemeral key and disclosure key are fresh per merge. */
export function sealRingMergeDisclosure(
  opening: RingMergeOpening,
  salt: Bytes16,
  auditor: X25519PublicKey,
): SealedRingMergeDisclosure {
  const ephemeral = X25519Keypair.generate();
  const disclosureKey = randomBytes(32) as Bytes32;
  try {
    return sealRingMergeDisclosureWith({ opening, salt, auditor, ephemeral, disclosureKey });
  } finally {
    ephemeral.destroy();
    disclosureKey.fill(0);
  }
}

/** @internal `salt` is the SPP merge output salt, the statement binds the pad to it. */
export function sealRingMergeDisclosureWith(
  input: Readonly<{
    opening: RingMergeOpening;
    salt: Bytes16;
    auditor: X25519PublicKey;
    ephemeral: X25519Keypair;
    disclosureKey: Bytes32;
  }>,
): SealedRingMergeDisclosure {
  checkMergeWidth(input.opening.length);
  const plaintext = encodeMergeOpening(input.opening);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = input.ephemeral.publicKey();
    dh = input.ephemeral.ecdh(input.auditor);
    shared = auditSharedSecret(dh, ephemeralPublicKey, input.auditor);
    const disclosure = Object.freeze({
      ephemeralPublicKey: ephemeralPublicKey.toBytes(),
      ciphertext: symmetricApply(shared, MERGE_DISCLOSURE_INFO, input.disclosureKey) as Bytes32,
      fields: sealMergeDisclosureFields(input.disclosureKey, input.salt, plaintext),
    });
    // The secrets are copied last, a refusal before them leaves no copy to wipe.
    return Object.freeze({
      ephemeralSecret: input.ephemeral.secretBytes(),
      disclosureKey: new Uint8Array(input.disclosureKey) as Bytes32,
      disclosure,
    });
  } finally {
    dh?.fill(0);
    shared?.fill(0);
    plaintext.fill(0);
  }
}

/** `be32(hash_0) ‖ .. ‖ be32(hash_{width-1})`, zero padded to whole 31-byte chunks. */
function encodeMergeOpening(opening: RingMergeOpening): Uint8Array {
  const plaintext = new Uint8Array(
    mergeDisclosureFieldCount(opening.length) * DISCLOSURE_CHUNK_BYTES,
  );
  try {
    opening.forEach((commitment, index) => plaintext.set(commitment, 32 * index));
    return plaintext;
  } catch (cause) {
    plaintext.fill(0);
    throw cause;
  }
}

function invalid(reason: string): RingError {
  return new RingError("RING_AUDIT_MESSAGE", { details: { reason } });
}
