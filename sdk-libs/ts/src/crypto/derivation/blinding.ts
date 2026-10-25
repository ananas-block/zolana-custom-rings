/** The ring side of SPP's output blinding, Rust `custom_ring_interface::blinding`. */
import type { Address, Bytes16, Bytes32 } from "@heliuslabs/zolana";
import {
  checkedBytes,
  equalBytes,
  isCanonicalField,
  rightAlign,
} from "@heliuslabs/zolana/internal";
import type { ShieldedPublicKey } from "@heliuslabs/zolana/keypair";
import {
  Data,
  outputBlindingSeed,
  transactOutputBlinding,
  Utxo,
  type AssetRegistry,
  type ProofOutputUtxo,
  type TreeId,
} from "@heliuslabs/zolana/transaction";

import { openDeliveredBody } from "../../protocol/transaction/output.js";
import { domainHash, RingDomain } from "./ring-domain.js";
import { packedSecret, ringTagField } from "./ring-stream.js";
import { withOutputFields } from "../../protocol/proof/proof-output.js";

/** SPP's `blinding_seed`, the seed of every ring output's TXOB blinding. */
export function ringBlindingSeed(txViewingSecret: Bytes32, salt: Bytes16): Bytes32 {
  return domainHash(RingDomain.blindingSeed, [
    ...packedSecret(txViewingSecret, "transaction viewing secret"),
    rightAlign(checkedBytes<Bytes16>(salt, 16, "salt")),
  ]);
}

/** SPP's TXOB blinding of slot `outputIndex` under the ring blinding seed. */
export function ringOutputBlinding(
  input: Readonly<{ firstNullifier: Bytes32; blindingSeed: Bytes32; outputIndex: number }>,
): Bytes32 {
  return transactOutputBlinding(
    input.firstNullifier,
    outputBlindingSeed(input.firstNullifier, input.blindingSeed),
    input.outputIndex,
  );
}

/** `Poseidon(CRAT, slot_secret, 0^16 ‖ tag)`, the `ring_data_hash` an anchor reads a first contact's tag back from. */
export function anonymousRingData(slotSecret: Bytes32, tag: Bytes16): Bytes32 {
  return domainHash(RingDomain.anonymousRingData, [
    checkedBytes<Bytes32>(slotSecret, 32, "slot secret"),
    ringTagField(tag),
  ]);
}

/** An `undefined` entry of `ringData` keeps the output's own ring data. */
export function ringBlindedOutputs(
  input: Readonly<{
    outputs: readonly ProofOutputUtxo[];
    firstNullifier: Bytes32;
    blindingSeed: Bytes32;
    ringData: readonly (Bytes32 | undefined)[];
  }>,
): readonly ProofOutputUtxo[] {
  const seedOut = outputBlindingSeed(input.firstNullifier, input.blindingSeed);
  return Object.freeze(
    input.outputs.map((output, index) => {
      const ringDataHash = input.ringData[index];
      return withOutputFields(output, {
        blinding: transactOutputBlinding(input.firstNullifier, seedOut, index),
        ...(ringDataHash === undefined ? {} : { ringDataHash }),
      });
    }),
  );
}

/** Where a delivered ring output sits, Rust `RingDeliverySlot`. */
export interface RingDeliverySlot {
  readonly ring: Address;
  /** The published tag on an anonymous ring, absent on a confidential one. */
  readonly tag?: Bytes16;
}

/** The keys of a delivered output's owner. */
export interface RingNoteOwner {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierPublicKey: Bytes32;
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
  /** CRAT on an anonymous ring. */
  readonly ringDataHash?: Bytes32;
}

/** The body names no mint, `undefined` when no registered asset rebuilds the commitment. */
export function openRingDelivery(
  slot: RingDeliverySlot,
  opening: RingDeliveryOpening,
  assets: AssetRegistry,
): RingDeliveredNote | undefined {
  const body = openDeliveredBody(opening.slotSecret, opening.body);
  // be32 below q is the only blinding a commitment binds.
  if (!isCanonicalField(body.blinding)) return undefined;
  const ringDataHash =
    slot.tag === undefined ? undefined : anonymousRingData(opening.slotSecret, slot.tag);
  for (const [, asset] of assets.entries()) {
    const utxo = new Utxo({
      owner: opening.owner.signingPublicKey,
      asset,
      amount: body.amount,
      blinding: body.blinding,
      data: new Data(),
      ringProgramId: slot.ring,
    });
    const utxoHash = utxo.hash(
      opening.owner.nullifierPublicKey,
      opening.treeId,
      undefined,
      ringDataHash,
    );
    if (equalBytes(utxoHash, opening.commitment))
      return Object.freeze({
        utxo,
        utxoHash,
        ...(ringDataHash === undefined ? {} : { ringDataHash }),
      });
  }
  return undefined;
}
