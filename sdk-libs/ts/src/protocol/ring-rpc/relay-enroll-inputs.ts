/**
 * Ring `Enroll` accounts and the relayed request an owner with no SOL signs, Rust `relay_enroll`.
 *
 * The credential PDA, its address and the address nullifier PDA derive from the ring program and
 * the owner alone. No caller names them, a wallet, the relay and the program agree on one identity.
 *
 * Read after `protocol/membership/credential.ts`.
 * Read before `operations/management/enrollment.ts`.
 */
import {
  addressBytes,
  concatBytes,
  instruction,
  meta,
  nullifierPdaAddress,
  sha256,
  SYSTEM_PROGRAM,
  treeAddress,
  Writer,
  type SignerAccount,
} from "@heliuslabs/zolana/internal";
import { SHIELDED_POOL_PROGRAM_ID, type Address, type Bytes32 } from "@heliuslabs/zolana/interface";
import type { AccountMeta, Instruction } from "@solana/kit";

import { ringIdField } from "../../crypto/derivation/ring-stream.js";
import {
  ADDRESS_TREE_ID,
  credentialAddress,
  credentialPda,
  credentialSeed,
} from "../membership/credential.js";
import { memberOfTag } from "../membership/policy.js";
import { ringPolicyAddress } from "../pda/index.js";

export interface RelayEnrollInputs {
  readonly ringProgramId: Address;
  readonly owner: Address;
  /** The SPP proof binds its id into the credential UTXO hash. */
  readonly outputTree: Address;
  /** The ring `Enroll` tag first, the program holds every field to both proofs. */
  readonly instructionData: Uint8Array;
}

const ENROLL_REQUEST_DOMAIN = new TextEncoder().encode("zolana/ring-rpc-relay-enroll");

/** Rust `CredentialAccounts`, the one credential identity of an owner in a ring. */
export interface CredentialAccounts {
  readonly pda: Address;
  /** The address slot nullifier, the key of the credential. */
  readonly address: Bytes32;
  /** SPP creates it with the reservation and closes it after the tree 0 batch applies. */
  readonly nullifierPda: Address;
}

export async function credentialAccounts(
  ringProgramId: Address,
  owner: Address,
): Promise<CredentialAccounts> {
  const pda = await credentialPda(ringProgramId);
  const address = credentialAddress(
    pda,
    credentialSeed(ringIdField(ringProgramId), memberOfTag(addressBytes(owner, "owner"))),
  );
  return Object.freeze({
    pda,
    address,
    nullifierPda: await nullifierPdaAddress(treeAddress(ADDRESS_TREE_ID), address),
  });
}

/** The program hands SPP every account from the payer on, a PDA owner signs through its CPI. */
export async function enrollAccounts(
  input: Readonly<{
    ringProgramId: Address;
    owner: SignerAccount;
    payer: SignerAccount;
    outputTree: Address;
  }>,
  owner: Address,
): Promise<readonly AccountMeta[]> {
  const [credential, ring] = await Promise.all([
    credentialAccounts(input.ringProgramId, owner),
    ringPolicyAddress(input.ringProgramId),
  ]);
  return [
    meta(input.owner, true, false),
    meta(ring, false, false),
    meta(input.payer, true, true),
    meta(input.outputTree, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    meta(SYSTEM_PROGRAM, false, false),
    meta(treeAddress(ADDRESS_TREE_ID), false, true),
    meta(credential.nullifierPda, false, true),
    meta(credential.pda, false, false),
  ];
}

export function encodeRelayEnrollInputs(value: RelayEnrollInputs): Uint8Array {
  return new Writer()
    .bytes(addressBytes(value.ringProgramId), 32, "ringProgramId")
    .bytes(addressBytes(value.owner), 32, "owner")
    .bytes(addressBytes(value.outputTree), 32, "outputTree")
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
      addressBytes(value.outputTree),
      value.instructionData,
    ),
  ) as Bytes32;
}

export async function relayEnrollInstruction(
  value: RelayEnrollInputs,
  feePayer: Address,
): Promise<Instruction> {
  return instruction(
    value.instructionData,
    await enrollAccounts(
      {
        ringProgramId: value.ringProgramId,
        owner: value.owner,
        payer: feePayer,
        outputTree: value.outputTree,
      },
      value.owner,
    ),
    value.ringProgramId,
  );
}
