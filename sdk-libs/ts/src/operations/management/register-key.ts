import type { Address } from "@solana/kit";

import {
  type RingSealedKey,
  type RingSealedNullifierKey as SealedNullifierKey,
} from "../../rpc/ports.js";
import { concatBytes, equalBytes, rightAlign } from "@heliuslabs/zolana/internal";
import type { Bytes31, Bytes32, Bytes64, RequestContext } from "@heliuslabs/zolana/interface";
import { NullifierKey, X25519Keypair, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  auditSharedSecret,
  NF_KEY_ENC_INFO,
  symmetricAuditApply,
} from "../../crypto/audit/audit.js";
import { STREAM_FIRST_COUNTER } from "../../protocol/codec/ring-disclosure-layout.js";

import { x25519FromU } from "../../crypto/keys/x25519.js";
import { RingError } from "../../protocol/error.js";
import {
  resolveCredential,
  type CredentialClient,
  type PresentCredential,
} from "../../rpc/credential-resolver.js";

const KEY_STREAM = Object.freeze({ label: NF_KEY_ENC_INFO, counter: STREAM_FIRST_COUNTER });

export type { SealedNullifierKey };

/** Rust `NullifierKeyEnvelope`, the sealed key and the ephemeral secret its proof witnesses. */
export interface NullifierKeyEnvelope {
  readonly ephemeralSecret: Bytes32;
  readonly sealed: SealedNullifierKey;
  readonly nullifierPublicKey: Bytes32;
}

export type RingSealedKeyClient = CredentialClient;

export interface RingSealedKeyEntry {
  readonly credential: PresentCredential;
  readonly sealed: RingSealedKey;
}

/** The key `owner` enrolled, an absent credential refuses and an unknown one never reads as absent. */
export async function fetchRingSealedKey(
  input: Readonly<{ client: RingSealedKeyClient; ringProgramId: Address; owner: Address }>,
  context?: RequestContext,
): Promise<RingSealedKeyEntry> {
  const { client, ringProgramId, owner } = input;
  const lookup = await resolveCredential({ client, ring: ringProgramId, owner }, context);
  if (lookup.kind === "unknown")
    throw new RingError("RING_CREDENTIAL_UNKNOWN", { details: { reason: lookup.reason } });
  if (lookup.kind === "absent") throw new RingError("RING_KEY_NOT_REGISTERED");
  const { nullifierPk, ephU, ciphertext } = lookup.credential;
  return Object.freeze({
    credential: lookup,
    sealed: Object.freeze({
      owner,
      nullifierPk,
      ephemeralPublicKey: ephemeralKey(ephU),
      ciphertext,
    }),
  });
}

/** The auditor's opening of a sealed key, the opened key must be the one the credential binds. */
export function openRingSealedKey(entry: RingSealedKeyEntry, auditor: X25519Keypair): NullifierKey {
  const key = openNullifierKey(entry.sealed, auditor);
  if (!equalBytes(key.publicKey(), entry.sealed.nullifierPk)) {
    key.destroy();
    throw new RingError("RING_KEY_ENVELOPE_INVALID");
  }
  return key;
}

/** `(ephemeral, auditor)` fixes the keystream, the ephemeral scalar is never taken from a caller. */
export function sealNullifierKey(
  nullifierKey: NullifierKey,
  listSalt: Bytes32,
  auditorPublicKey: X25519PublicKey,
): NullifierKeyEnvelope {
  const ephemeral = X25519Keypair.generate();
  try {
    return sealNullifierKeyWith(ephemeral, nullifierKey, listSalt, auditorPublicKey);
  } finally {
    ephemeral.destroy();
  }
}

/** @internal Bytes 0 and 32 of the plaintext are the pads the circuit pins. */
export function sealNullifierKeyWith(
  ephemeral: X25519Keypair,
  nullifierKey: NullifierKey,
  listSalt: Bytes32,
  auditorPublicKey: X25519PublicKey,
): NullifierKeyEnvelope {
  const secret = nullifierKey.secretBytes();
  const aligned = rightAlign(secret);
  const plaintext = concatBytes(aligned, listSalt);
  aligned.fill(0);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditorPublicKey);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
    const ciphertext = symmetricAuditApply(shared, KEY_STREAM, plaintext) as Bytes64;
    return Object.freeze({
      ephemeralSecret: ephemeral.secretBytes(),
      sealed: Object.freeze({ ephemeralPublicKey, ciphertext }),
      nullifierPublicKey: nullifierKey.publicKey(),
    });
  } finally {
    secret.fill(0);
    plaintext.fill(0);
    dh?.fill(0);
    shared?.fill(0);
  }
}

/** The pad alone does not authenticate the key against its credential. */
export function openNullifierKey(sealed: SealedNullifierKey, auditor: X25519Keypair): NullifierKey {
  const plaintext = openedPlaintext(sealed, auditor);
  try {
    return NullifierKey.fromSecret(plaintext.slice(1, 32) as Bytes31);
  } finally {
    plaintext.fill(0);
  }
}

export function openListSalt(sealed: SealedNullifierKey, auditor: X25519Keypair): Bytes32 {
  const plaintext = openedPlaintext(sealed, auditor);
  try {
    return plaintext.slice(32) as Bytes32;
  } finally {
    plaintext.fill(0);
  }
}

function openedPlaintext(sealed: SealedNullifierKey, auditor: X25519Keypair): Uint8Array {
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    dh = auditor.ecdh(sealed.ephemeralPublicKey);
    shared = auditSharedSecret(dh, sealed.ephemeralPublicKey, auditor.publicKey());
    const plaintext = symmetricAuditApply(shared, KEY_STREAM, sealed.ciphertext);
    if (plaintext[0] !== 0 || plaintext[32] !== 0) {
      plaintext.fill(0);
      throw new RingError("RING_KEY_ENVELOPE_INVALID");
    }
    return plaintext;
  } finally {
    dh?.fill(0);
    shared?.fill(0);
  }
}

function ephemeralKey(u: Bytes32): X25519PublicKey {
  try {
    return x25519FromU(u);
  } catch (cause) {
    throw new RingError("RING_KEY_ENVELOPE_INVALID", { cause });
  }
}
