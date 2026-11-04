/** Rust `RelayEnrollInputs` in wincode. */
import { addressBytes, concatBytes, sha256, Writer } from "@heliuslabs/zolana/internal";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";

export interface RelayEnrollInputs {
  readonly ringProgramId: Address;
  readonly owner: Address;
  readonly trackingRegistry: Address;
  /** Tag 6 first, the program holds every field to the owner's signature and proof. */
  readonly instructionData: Uint8Array;
}

const ENROLL_REQUEST_DOMAIN = new TextEncoder().encode("zolana/ring-rpc-relay-enroll");

export function encodeRelayEnrollInputs(value: RelayEnrollInputs): Uint8Array {
  return new Writer()
    .bytes(addressBytes(value.ringProgramId), 32, "ringProgramId")
    .bytes(addressBytes(value.owner), 32, "owner")
    .bytes(addressBytes(value.trackingRegistry), 32, "trackingRegistry")
    .u64(BigInt(value.instructionData.length), "instructionData.length")
    .bytes(value.instructionData, undefined, "instructionData")
    .finish();
}

/** The owner's signature over it spends the relay's budget, it names no quote so a retry keeps it. */
export function enrollRequestDigest(value: RelayEnrollInputs): Bytes32 {
  return sha256(
    concatBytes(
      ENROLL_REQUEST_DOMAIN,
      addressBytes(value.ringProgramId),
      addressBytes(value.owner),
      addressBytes(value.trackingRegistry),
      value.instructionData,
    ),
  ) as Bytes32;
}
