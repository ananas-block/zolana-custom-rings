import { equalBytes, isCanonicalField } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { X25519PublicKey, type X25519Keypair } from "@heliuslabs/zolana/keypair";
import { ownerUtxoHash } from "@heliuslabs/zolana/transaction";

import {
  auditSharedSecret,
  DEPOSIT_ENC_INFO,
  symmetricAuditApply,
} from "../../../crypto/audit/audit.js";
import { RingError } from "../../error.js";
import { ConfirmedDeposit } from "../../transaction/origin.js";
import {
  HISTORICAL_DEPOSIT_OPENING_LENGTH,
  HISTORICAL_DEPOSIT_OWNER_KEY_OFFSET,
  type HistoricalDepositCapsule,
} from "./deposit-capsule.js";
import { STREAM_FIRST_COUNTER } from "./layout.js";

/** One opening's blocks of the batch's contiguous stream. */
const OPENING_BLOCKS = 6;

/** A tag 31 opening names the owner by its hash alone. */
export interface HistoricalDepositOpening {
  readonly ownerHash: Bytes32;
  readonly blinding: Bytes32;
  readonly ownerKey: Bytes32;
}

export function openHistoricalDepositOpening(
  capsule: HistoricalDepositCapsule,
  auditor: X25519Keypair,
  ownerCommitment: Bytes32,
  confirmed: ConfirmedDeposit,
): HistoricalDepositOpening {
  if (!ConfirmedDeposit.is(confirmed)) throw new RingError("RING_AUDIT_MESSAGE");
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
        counter: STREAM_FIRST_COUNTER + capsule.slotIndex * OPENING_BLOCKS,
      },
      capsule.ciphertext,
    );
    const ownerHash = plaintext.slice(0, 32) as Bytes32;
    const blinding = plaintext.slice(32, HISTORICAL_DEPOSIT_OWNER_KEY_OFFSET) as Bytes32;
    const ownerKey = plaintext.slice(
      HISTORICAL_DEPOSIT_OWNER_KEY_OFFSET,
      HISTORICAL_DEPOSIT_OPENING_LENGTH,
    ) as Bytes32;
    try {
      if (
        !isCanonicalField(ownerHash) ||
        !isCanonicalField(blinding) ||
        !isCanonicalField(ownerCommitment) ||
        !equalBytes(ownerUtxoHash(ownerHash, blinding), ownerCommitment)
      )
        throw new RingError("RING_AUDIT_MESSAGE");
    } catch (cause) {
      ownerHash.fill(0);
      blinding.fill(0);
      throw cause;
    }
    return Object.freeze({ ownerHash, blinding, ownerKey });
  } finally {
    dh?.fill(0);
    shared?.fill(0);
    plaintext?.fill(0);
  }
}
