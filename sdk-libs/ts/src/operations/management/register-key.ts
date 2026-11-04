import type { Address } from "@solana/kit";

import {
  type RingSealedKey,
  type RingSealedNullifierKey as SealedNullifierKey,
} from "../../rpc/ports.js";
import { equalBytes, rightAlign } from "@heliuslabs/zolana/internal";
import type { Bytes31, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import { NullifierKey, X25519Keypair, type X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { MemberRecord, QuadPath } from "../../protocol/membership/member-registry.js";
import {
  auditSharedSecret,
  NF_KEY_ENC_INFO,
  symmetricAuditApply,
} from "../../crypto/audit/audit.js";
import { STREAM_FIRST_COUNTER } from "../../protocol/codec/ring-disclosure-layout.js";

import { RingError } from "../../protocol/error.js";
import { readOwnRecords, type RingRecordReadClient } from "../../rpc/registered-record.js";

const KEY_STREAM = Object.freeze({ label: NF_KEY_ENC_INFO, counter: STREAM_FIRST_COUNTER });

export type { SealedNullifierKey };

/** Rust `NullifierKeyEnvelope`, the sealed key and the ephemeral secret its proof witnesses. */
export interface NullifierKeyEnvelope {
  readonly ephemeralSecret: Bytes32;
  readonly sealed: SealedNullifierKey;
  readonly nullifierPublicKey: Bytes32;
}

export type RingSealedKeyClient = RingRecordReadClient;

/** A member's record under the ring's newest own root, escrowing `sealed`. */
export interface RingSealedKeyEntry {
  readonly member: Bytes32;
  readonly root: Bytes32;
  readonly record: MemberRecord;
  readonly path: QuadPath;
  readonly sealed: RingSealedKey;
}

/** The key `member` escrowed, refused unless its record binds the served envelope. */
export async function fetchRingSealedKey(
  input: Readonly<{ client: RingSealedKeyClient; ringProgramId: Address; member: Bytes32 }>,
  context?: RequestContext,
): Promise<RingSealedKeyEntry> {
  const { root, reads } = await readOwnRecords(
    { client: input.client, ringProgramId: input.ringProgramId, members: [input.member] },
    context,
  );
  const [read] = reads;
  if (read === undefined)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", { details: { reason: "openings" } });
  const served = read.opening.sealedKey;
  const escrowed = served === undefined ? undefined : read.escrowed(served.nullifierPk);
  if (escrowed === undefined) throw new RingError("RING_KEY_NOT_REGISTERED");
  return Object.freeze({
    member: input.member,
    root: root.root,
    record: escrowed.record,
    path: escrowed.path,
    sealed: escrowed.sealed,
  });
}

/** The auditor's opening of an escrowed key, the opened key must be the one the record binds. */
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
  auditorPublicKey: X25519PublicKey,
): NullifierKeyEnvelope {
  const ephemeral = X25519Keypair.generate();
  try {
    return sealNullifierKeyWith(ephemeral, nullifierKey, auditorPublicKey);
  } finally {
    ephemeral.destroy();
  }
}

/** @internal Byte zero of the plaintext is the pad the circuit pins. */
export function sealNullifierKeyWith(
  ephemeral: X25519Keypair,
  nullifierKey: NullifierKey,
  auditorPublicKey: X25519PublicKey,
): NullifierKeyEnvelope {
  const secret = nullifierKey.secretBytes();
  const plaintext = rightAlign(secret);
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditorPublicKey);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
    const ciphertext = symmetricAuditApply(shared, KEY_STREAM, plaintext) as Bytes32;
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

/** The pad alone does not authenticate the key against its registry record. */
export function openNullifierKey(sealed: SealedNullifierKey, auditor: X25519Keypair): NullifierKey {
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    dh = auditor.ecdh(sealed.ephemeralPublicKey);
    shared = auditSharedSecret(dh, sealed.ephemeralPublicKey, auditor.publicKey());
    plaintext = symmetricAuditApply(shared, KEY_STREAM, sealed.ciphertext);
    if (plaintext[0] !== 0) throw new RingError("RING_KEY_ENVELOPE_INVALID");
    return NullifierKey.fromSecret(plaintext.subarray(1) as Bytes31);
  } finally {
    dh?.fill(0);
    shared?.fill(0);
    plaintext?.fill(0);
  }
}
