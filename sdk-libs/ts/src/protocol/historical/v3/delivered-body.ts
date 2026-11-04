/** Scheme 10 bodies of frames before statement version 4, read and never written by a new frame. */
import type { Address, Bytes32 } from "@heliuslabs/zolana";
import {
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  equalBytes,
  isCanonicalField,
  u64be,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import { Data, Utxo, type AssetRegistry, type TreeId } from "@heliuslabs/zolana/transaction";

import type { RingNoteOwner } from "../../../crypto/derivation/blinding.js";

import { DELIVERED_BODY_ENC_INFO, symmetricAuditApply } from "../../../crypto/audit/audit.js";
import { checkedCounter } from "../../../crypto/error.js";
import {
  DELIVERED_BODY_LEN,
  ESCROWED_DELIVERED_BODY_LEN,
  STREAM_FIRST_COUNTER,
} from "./layout.js";

export interface DeliveredBodyOpening {
  readonly blinding: Bytes32;
  readonly amount: bigint;
  readonly ownerKey: Bytes32;
  /** `undefined` exactly under key escrow. */
  readonly nullifierPk: Bytes32 | undefined;
}

const BODY_STREAM = Object.freeze({
  label: DELIVERED_BODY_ENC_INFO,
  counter: STREAM_FIRST_COUNTER,
});

/** AES-256-CTR of `be32(blinding) ‖ u64be(amount) ‖ owner_key ‖ [be32(nullifier_pk)]` under the slot secret. */
export function sealDeliveredBody(slotSecret: Bytes32, opening: DeliveredBodyOpening): Uint8Array {
  const plaintext = concatBytes(
    checkedBytes<Bytes32>(opening.blinding, 32, "blinding"),
    u64be(checkedCounter(opening.amount, "amount")),
    checkedBytes<Bytes32>(opening.ownerKey, 32, "owner key"),
    ...(opening.nullifierPk === undefined
      ? []
      : [checkedBytes<Bytes32>(opening.nullifierPk, 32, "nullifier pk")]),
  );
  try {
    return symmetricAuditApply(
      checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
      BODY_STREAM,
      plaintext,
    );
  } finally {
    plaintext.fill(0);
  }
}

/** The length names the layout, the caller compares the keys, a commitment alone proves no ownership. */
export function openDeliveredBody(slotSecret: Bytes32, body: Uint8Array): DeliveredBodyOpening {
  const escrowed = body.length === ESCROWED_DELIVERED_BODY_LEN;
  const plaintext = symmetricAuditApply(
    checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
    BODY_STREAM,
    checkedBytes(
      body,
      escrowed ? ESCROWED_DELIVERED_BODY_LEN : DELIVERED_BODY_LEN,
      "delivered body",
    ),
  );
  try {
    return Object.freeze({
      blinding: checkedBytes<Bytes32>(plaintext.subarray(0, 32), 32, "blinding"),
      amount: bytesToBigInt(plaintext.subarray(32, 40)),
      ownerKey: checkedBytes<Bytes32>(plaintext.subarray(40, 72), 32, "owner key"),
      nullifierPk: escrowed
        ? undefined
        : checkedBytes<Bytes32>(plaintext.subarray(72), 32, "nullifier pk"),
    });
  } finally {
    plaintext.fill(0);
  }
}

/** Where a delivered ring output sits, Rust `RingDeliverySlot`. */
export interface RingDeliverySlot {
  readonly ring: Address;
}

/** One published delivered body and the secret its recipient agreed for it. */
export interface RingDeliveryOpening {
  readonly body: Uint8Array;
  readonly slotSecret: Bytes32;
  readonly owner: RingNoteOwner;
  /** The published commitment and the tree it was appended to. */
  readonly commitment: Bytes32;
  readonly treeId: TreeId;
}

/** A delivered output opened to the note its published commitment binds. */
export interface RingDeliveredNote {
  readonly utxo: Utxo;
  readonly utxoHash: Bytes32;
  readonly nullifierPublicKey: Bytes32;
}

/** Held back until a registered asset rebuilds the commitment. */
export const RING_DELIVERY_UNRESOLVED = "unresolved";

/** `undefined` for keys other than the owner's and zero, a blinding outside the field or a zero amount in no held asset, a commitment under a sender's choice of keys proves no ownership. */
export function openRingDelivery(
  slot: RingDeliverySlot,
  opening: RingDeliveryOpening,
  assets: AssetRegistry,
): RingDeliveredNote | typeof RING_DELIVERY_UNRESOLVED | undefined {
  const body = openDeliveredBody(opening.slotSecret, opening.body);
  const { signingPublicKey, nullifierPublicKey } = opening.owner;
  const named = body.nullifierPk;
  const foreign =
    !equalBytes(body.ownerKey, signingPublicKey.confidentialViewTag()) ||
    (named !== undefined &&
      !equalBytes(named, nullifierPublicKey) &&
      !equalBytes(named, ZERO_NULLIFIER_PK));
  // be32 below q is the only blinding a commitment binds.
  if (foreign || !isCanonicalField(body.blinding)) return undefined;
  // An old zero-key note stays readable after enrollment.
  const candidates: readonly Bytes32[] =
    named === undefined ? [nullifierPublicKey, ZERO_NULLIFIER_PK as Bytes32] : [named];
  for (const [, asset] of assets.entries()) {
    const utxo = new Utxo({
      owner: signingPublicKey,
      asset,
      amount: body.amount,
      blinding: body.blinding,
      data: new Data(),
      ringProgramId: slot.ring,
    });
    for (const candidate of candidates) {
      const utxoHash = utxo.hash(candidate, opening.treeId);
      if (equalBytes(utxoHash, opening.commitment))
        return Object.freeze({ utxo, utxoHash, nullifierPublicKey: candidate });
    }
  }
  return body.amount === 0n ? undefined : RING_DELIVERY_UNRESOLVED;
}
