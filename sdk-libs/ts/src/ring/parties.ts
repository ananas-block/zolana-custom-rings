import { addressBytes, ZERO_32 } from "@heliuslabs/zolana/internal";
import { solanaOwnerIdentity } from "@heliuslabs/zolana/keypair";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";

/** Ordered exactly as the verifier's AnonymousParties. */
export function anonymousPartyIdentities(
  payer: Address,
  cosigner?: Address,
  destination?: Address,
): readonly [Bytes32, Bytes32, Bytes32] {
  const identity = (party: Address | undefined): Bytes32 =>
    party === undefined ? ZERO_32 : (solanaOwnerIdentity(addressBytes(party)) as Bytes32);
  return [identity(payer), identity(cosigner), identity(destination)];
}
