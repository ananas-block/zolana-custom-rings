/** Rust `zolana_ring_keys::RingNullifierKey`. */
import type { Address } from "@solana/kit";

import { poseidon, rightAlign } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import {
  ShieldedAddress,
  type NullifierKey,
  type ShieldedKeypairLike,
} from "@heliuslabs/zolana/keypair";

import { domainField, RingDomain } from "../derivation/ring-domain.js";
import { RingAddress } from "./ring-address.js";

/** `Poseidon(CRPT, list_salt)`, the tracking leaf's commitment to the owner's one salt. */
export function listTagOf(listSalt: Bytes32): Bytes32 {
  return poseidon([domainField(RingDomain.listTag), listSalt]) as Bytes32;
}

export class RingNullifierKey {
  readonly #key: NullifierKey;

  private constructor(key: NullifierKey) {
    this.#key = key;
  }

  static async derive(
    holder: Pick<ShieldedKeypairLike, "ringNullifierKey">,
    ringProgramId: Address,
  ): Promise<RingNullifierKey> {
    return new RingNullifierKey(await holder.ringNullifierKey(ringProgramId));
  }

  /** Owned copy. */
  nullifierKey(): NullifierKey {
    return this.#key.clone();
  }

  nullifierPublicKey(): Bytes32 {
    return this.#key.publicKey();
  }

  addressOf(wallet: ShieldedAddress): ShieldedAddress {
    return ShieldedAddress.fromPublicKeys(
      wallet.signingPublicKey,
      this.nullifierPublicKey(),
      wallet.viewingPublicKey,
    );
  }

  /** Reveals the owner's list status. */
  ringAddress(wallet: ShieldedAddress, ringProgramId: Address): RingAddress {
    return new RingAddress({
      recipient: this.addressOf(wallet),
      ringProgramId,
      listSalt: this.listSalt(),
    });
  }

  /** `Poseidon(CRPS, nullifier_secret)`. */
  listSalt(): Bytes32 {
    const secret = this.#key.secretBytes();
    const aligned = rightAlign(secret);
    try {
      return poseidon([domainField(RingDomain.listSalt), aligned]) as Bytes32;
    } finally {
      secret.fill(0);
      aligned.fill(0);
    }
  }

  listTag(): Bytes32 {
    return listTagOf(this.listSalt());
  }

  destroy(): void {
    this.#key.destroy();
  }
}
