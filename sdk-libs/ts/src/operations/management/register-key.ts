import type { Address } from "@solana/kit";

import {
  type RingSealedKey,
  type RingSealedNullifierKey as SealedNullifierKey,
} from "../../rpc/ports.js";
import type { ChainReader } from "@heliuslabs/zolana/client";
import {
  addressBytes,
  equalBytes,
  hashBytes,
  rightAlign,
  waitForProjection,
} from "@heliuslabs/zolana/internal";
import type { Bytes31, Bytes32, Bytes33, RequestContext } from "@heliuslabs/zolana/interface";
import { NullifierKey, X25519Keypair, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { QuadPath } from "../../protocol/membership/member-registry.js";
import {
  auditSharedSecret,
  NF_KEY_ENC_INFO,
  symmetricAuditApply,
} from "../../crypto/audit/audit.js";
import { STREAM_FIRST_COUNTER } from "../../protocol/codec/ring-disclosure-layout.js";

import { RingError } from "../../protocol/error.js";
import { fetchRingPolicy } from "../../protocol/membership/config.js";
import { memberOfTag } from "../../protocol/membership/policy.js";
import { verifyTrackingOpening, type TrackingRecord } from "../../protocol/membership/tracking.js";
import type { TrackingSeal } from "../../protocol/indexer/tracking-codec.js";
import type { TrackingReader } from "../../rpc/ports.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "../../rpc/projection.js";
import { newestTrackingRoot } from "../../rpc/tracking-resolver.js";

const KEY_STREAM = Object.freeze({ label: NF_KEY_ENC_INFO, counter: STREAM_FIRST_COUNTER });

export type { SealedNullifierKey };

/** Rust `NullifierKeyEnvelope`, the sealed key and the ephemeral secret its proof witnesses. */
export interface NullifierKeyEnvelope {
  readonly ephemeralSecret: Bytes32;
  readonly sealed: SealedNullifierKey;
  readonly nullifierPublicKey: Bytes32;
}

export type RingSealedKeyClient = Pick<ChainReader, "getAccount"> &
  Pick<TrackingReader, "getTrackingOpenings">;

/** A member's tracking row under the ring's newest tracking root, sealing `sealed`. */
export interface RingSealedKeyEntry {
  readonly member: Bytes32;
  readonly root: Bytes32;
  readonly record: TrackingRecord;
  readonly path: QuadPath;
  readonly sealed: RingSealedKey;
}

/** The key `member` enrolled, refused unless its applied row binds the served seal. */
export function fetchRingSealedKey(
  input: Readonly<{ client: RingSealedKeyClient; ringProgramId: Address; member: Bytes32 }>,
  context?: RequestContext,
): Promise<RingSealedKeyEntry> {
  const { client, ringProgramId, member } = input;
  return waitForProjection(
    async (attempt) => {
      const { tracking } = await fetchRingPolicy(client, ringProgramId, attempt);
      const { root } = await newestTrackingRoot(
        { client, trackingRegistry: tracking, ring: ringProgramId },
        attempt,
      );
      const { openings } = await client.getTrackingOpenings(
        { registry: tracking, members: [member], expectedRoot: root },
        attempt,
      );
      const [opening] = openings;
      if (opening === undefined)
        throw new RingError("RING_TRACKING_INVALID", { details: { reason: "openings" } });
      const record = verifyTrackingOpening(opening, root, member);
      if (record === undefined || opening.kind !== "present" || opening.seal === undefined)
        throw new RingError("RING_KEY_NOT_REGISTERED");
      return Object.freeze({
        member,
        root,
        record,
        path: opening.path,
        sealed: boundSeal(opening.seal, record),
      });
    },
    MEMBER_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}

/** The auditor's opening of a sealed key, the opened key must be the one the row binds. */
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

/** The pad alone does not authenticate the key against its tracking row. */
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

/** The row binds the ciphertext by hash and the owner by member, the ephemeral key by neither. */
function boundSeal(seal: TrackingSeal, record: TrackingRecord): RingSealedKey {
  if (
    seal.ciphertext.length !== 32 ||
    !equalBytes(hashBytes(seal.ciphertext), record.ctHash) ||
    !equalBytes(memberOfTag(addressBytes(seal.owner, "owner")), record.member)
  )
    throw new RingError("RING_KEY_NOT_REGISTERED");
  return Object.freeze({
    owner: seal.owner,
    nullifierPk: record.nullifierPk,
    ephemeralPublicKey: ephemeralKey(seal.ephPk),
    ciphertext: seal.ciphertext as Bytes32,
  });
}

function ephemeralKey(bytes: Uint8Array): X25519PublicKey {
  try {
    return X25519PublicKey.fromBytes(bytes as Bytes33);
  } catch (cause) {
    throw new RingError("RING_KEY_ENVELOPE_INVALID", { cause });
  }
}
