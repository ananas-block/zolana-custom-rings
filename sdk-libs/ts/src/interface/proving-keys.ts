import type { ExpectedProvingKey } from "@heliuslabs/zolana/internal";

/** Keyed by the file name `GET /proving-keys` reports, mirrors Rust `PROVING_KEY_SHA256S`. */
export const RING_PROVING_KEY_SHA256S = Object.freeze({
  "custom_ring_base.key": "6a99eb09a8f5b5286c032f461550a894c2a8b522f246678f3987ee542e7c6f5c",
  "custom_ring_compressed_policy.key":
    "836c3d218a67d87d45a900fc8b45594ce9ef2fcc26122b26776e8c0e002995c8",
  "custom_ring_delegate_policy.key":
    "5cca9ae5ae6034b6f29e2b6c6506513fc1bd51ea979218fca54ee0f0b2a9e5af",
  "custom_ring_deposit.key": "248bf150c4717700d5c978a47d6b6b394bed00d8fb61f29c7ea2142261ca2c64",
  "custom_ring_policy.key": "506d4e70b89aa188c891ecd8c63ef74fc99edd605dbe40a2a1ffbee1fe3bfd1e",
  "custom_ring_register_key.key":
    "6f4ce5a730b7d61a8938ab9798ac3d520d1b8e818b337eeb9ff68ffb8d332bc1",
});

/** Go `ring.RingCircuits` key files, `custom-ring-<x>` proves with `custom_ring_<x>.key`. */
const KEY_FILES = Object.freeze({
  "custom-ring-base": "custom_ring_base.key",
  "custom-ring-policy": "custom_ring_policy.key",
  "custom-ring-compressed-policy": "custom_ring_compressed_policy.key",
  "custom-ring-delegate-policy": "custom_ring_delegate_policy.key",
  "custom-ring-deposit": "custom_ring_deposit.key",
  "custom-ring-register-key": "custom_ring_register_key.key",
} satisfies Record<string, keyof typeof RING_PROVING_KEY_SHA256S>);

export type RingCircuit = keyof typeof KEY_FILES;

export function ringProvingKey(circuit: RingCircuit): ExpectedProvingKey {
  const name = KEY_FILES[circuit];
  return Object.freeze({ name, sha256: RING_PROVING_KEY_SHA256S[name] });
}
