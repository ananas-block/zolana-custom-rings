import { addressBytes, ZERO_32 } from "@heliuslabs/zolana/internal";
import { solanaOwnerIdentity } from "@heliuslabs/zolana/keypair";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";

import { ANONYMOUS_PARTIES } from "../transaction/transact.js";

/** Ordered exactly as the verifier's `AnonymousParties`, zero for an absent party. */
export function anonymousPartyIdentities(
  input: Readonly<{
    payer: Address;
    coSigner?: Address;
    exitDestination?: Address;
  }>,
): readonly Bytes32[] {
  const identity = (party: Address | undefined): Bytes32 =>
    party === undefined ? ZERO_32 : (solanaOwnerIdentity(addressBytes(party)) as Bytes32);
  return Object.freeze([
    identity(input.payer),
    identity(input.coSigner),
    ...new Array<Bytes32>(ANONYMOUS_PARTIES - 3).fill(ZERO_32),
    identity(input.exitDestination),
  ]);
}
