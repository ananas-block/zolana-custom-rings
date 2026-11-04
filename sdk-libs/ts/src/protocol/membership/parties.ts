import { addressBytes, ZERO_32 } from "@heliuslabs/zolana/internal";
import { solanaOwnerIdentity } from "@heliuslabs/zolana/keypair";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";

import { RingError } from "../error.js";
import { ANONYMOUS_PARTIES, MAX_CO_SIGNERS } from "../transaction/transact.js";

/** Ordered exactly as the verifier's `AnonymousParties`, zero for an absent party. */
export function anonymousPartyIdentities(
  input: Readonly<{
    payer: Address;
    coSigners: readonly Address[];
    exitDestination?: Address;
  }>,
): readonly Bytes32[] {
  if (input.coSigners.length > MAX_CO_SIGNERS)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "coSigners", expected: MAX_CO_SIGNERS, actual: input.coSigners.length },
    });
  const identity = (party: Address): Bytes32 => solanaOwnerIdentity(addressBytes(party)) as Bytes32;
  const identities = Array.from({ length: ANONYMOUS_PARTIES }, (): Bytes32 => ZERO_32);
  identities[0] = identity(input.payer);
  input.coSigners.forEach((coSigner, slot) => {
    identities[slot + 1] = identity(coSigner);
  });
  if (input.exitDestination !== undefined)
    identities[ANONYMOUS_PARTIES - 1] = identity(input.exitDestination);
  return Object.freeze(identities);
}
