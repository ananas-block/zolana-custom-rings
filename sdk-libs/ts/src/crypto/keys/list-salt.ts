/** Rust `zolana_ring_keys::list_salt`. */
import { poseidon, rightAlign } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import type { NullifierKey } from "@heliuslabs/zolana/keypair";

import { domainField, RingDomain } from "../derivation/ring-domain.js";

/** `Poseidon(CRPS, nullifier_secret, ring_id)`, valid in one ring. */
export function listSaltOf(key: NullifierKey, ringId: Bytes32): Bytes32 {
  const secret = key.secretBytes();
  const aligned = rightAlign(secret);
  try {
    return poseidon([domainField(RingDomain.listSalt), aligned, ringId]) as Bytes32;
  } finally {
    secret.fill(0);
    aligned.fill(0);
  }
}

/** `Poseidon(CRPT, list_salt)`, final in the tracking leaf. */
export function listTagOf(listSalt: Bytes32): Bytes32 {
  return poseidon([domainField(RingDomain.listTag), listSalt]) as Bytes32;
}
