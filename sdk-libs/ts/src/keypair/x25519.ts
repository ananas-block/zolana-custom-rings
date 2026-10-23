import type { Bytes32 } from "@heliuslabs/zolana";
import { X25519PublicKey } from "@heliuslabs/zolana/keypair";

/** The tagged key of a bare u coordinate, the inverse of `X25519PublicKey.u`. */
export function x25519FromU(u: Bytes32): X25519PublicKey {
  return X25519PublicKey.fromBytes(
    new Uint8Array([4, ...u]) as Parameters<typeof X25519PublicKey.fromBytes>[0],
  );
}
