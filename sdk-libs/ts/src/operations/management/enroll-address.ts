/** A PDA owner signs enrollment through CPI with the same flag. */
import type { Address, Instruction } from "@solana/kit";

import {
  SYSTEM_PROGRAM,
  Writer,
  addressBytes,
  encodeBase58,
  Reader,
  instruction,
  meta,
  signerAddress,
  type SignerAccount,
} from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import { RingError } from "../../protocol/error.js";
import { addressRecordHash, checkedViewingU } from "../../protocol/membership/member-opening.js";
import type { AuthorizedAddress } from "../../protocol/membership/member-registry.js";
import { memberOfTag } from "../../protocol/membership/policy.js";
import { addressAuthorizationPda, STORAGE_PROGRAM_ID } from "../../protocol/pda/index.js";

/** Rust `storage_instruction::tag::ENROLL_ADDRESS`. */
export const ENROLL_ADDRESS_TAG = 5;
/** Rust `AddressAuthorization::DISCRIMINATOR`. */
const ADDRESS_AUTHORIZATION_DISCRIMINATOR = 2;
const ADDRESS_AUTHORIZATION_SIZE = 178;

/** The first call opens revision 1, a later call rotates the viewing key alone. */
export interface EnrollAddress {
  readonly payer: SignerAccount;
  readonly owner: SignerAccount;
  /** The ring's `StorageRegistry`, its immutable `ring_id` fills the address hash. */
  readonly registry: Address;
  /** Fixed after the first enrollment, the program refuses a change. */
  readonly nullifierPk: Bytes32;
  readonly viewingU: Bytes32;
}

export async function enrollAddressInstruction(input: EnrollAddress): Promise<Instruction> {
  const owner = signerAddress(input.owner);
  const [authorization] = await addressAuthorizationPda(input.registry, owner);
  return instruction(
    new Writer()
      .u8(ENROLL_ADDRESS_TAG, "tag")
      .bytes(input.nullifierPk, 32, "nullifierPk")
      .bytes(checkedViewingU(input.viewingU), 32, "viewingU")
      .finish(),
    [
      meta(input.payer, true, true),
      meta(input.owner, true, false),
      meta(input.registry, false, false),
      meta(authorization, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ],
    STORAGE_PROGRAM_ID,
  );
}

/** The newest address an owner signed, an authority cannot roll it back. */
export interface AddressAuthorization extends AuthorizedAddress {
  readonly bump: number;
  readonly registry: Address;
  readonly owner: Address;
  readonly appliedRevision: bigint;
}

export function decodeAddressAuthorization(data: Uint8Array): AddressAuthorization {
  if (data.length !== ADDRESS_AUTHORIZATION_SIZE || data[0] !== ADDRESS_AUTHORIZATION_DISCRIMINATOR)
    throw new RingError("RING_ADDRESS_NOT_ENROLLED", { details: { reason: "account" } });
  const reader = new Reader(data.subarray(1));
  const bump = reader.u8("bump");
  const registry = encodeBase58(reader.bytes(32, "registry"));
  const owner = encodeBase58(reader.bytes(32, "owner"));
  const ringId = reader.bytes(32, "ringId") as Bytes32;
  const nullifierPk = reader.bytes(32, "nullifierPk") as Bytes32;
  const viewingU = reader.bytes(32, "viewingU") as Bytes32;
  const addressRevision = reader.u64("revision");
  const appliedRevision = reader.u64("appliedRevision");
  reader.done();
  return Object.freeze({
    bump,
    registry,
    owner,
    ringId,
    nullifierPk,
    viewingU,
    addressRevision,
    appliedRevision,
  });
}

/** The hash a queued `ADDRESS` write chains, the proof recomputes it under the statement's ring. */
export function authorizationAddressHash(authorization: AddressAuthorization): Bytes32 {
  return addressRecordHash({
    ...authorization,
    member: memberOfTag(addressBytes(authorization.owner, "owner")),
  });
}
