/**
 * The audit credential `Enroll` stores once per ring and owner as an SPP unique data UTXO,
 * Rust `custom_ring_interface::credential`.
 *
 * The credential PDA owns every credential, and only `Enroll` signs for it, so a UTXO under
 * that owner can only be a verified enrollment. Its address enters the nullifier tree of
 * tree 0, and `rootSequence` orders those roots by their authenticated append count.
 *
 * Read after `crypto/derivation/ring-domain.ts` and `protocol/proof/statement.ts`.
 * Read before `rpc/credential-resolver.ts` and `operations/management/credential-write.ts`.
 */
import { getProgramDerivedAddress, type Address } from "@solana/kit";

import {
  concatBytes,
  decodeTreeId,
  hashChain4,
  isZero,
  poseidon,
  Reader,
  rightAlign,
  u32be,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import {
  NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET,
  NULLIFIER_ROOT_HISTORY_OFFSET,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
  type Bytes32,
  type Bytes33,
  type Bytes64,
} from "@heliuslabs/zolana/interface";
import {
  outputBlindingSeed,
  ownerHash,
  ShieldedPublicKey,
  transactOutputBlinding,
} from "@heliuslabs/zolana/keypair";
import { ProofInputUtxo, SOL_MINT, Utxo, type TreeId } from "@heliuslabs/zolana/transaction";

import { domainField, RingDomain } from "../../crypto/derivation/ring-domain.js";
import { RingError } from "../error.js";
import { registerKeyStatementElements } from "../proof/statement.js";

export const CREDENTIAL_PDA_SEED = new TextEncoder().encode("credential");
/** Rust `spr_instruction::ADDRESS_TREE_ID`, the only tree credential addresses enter. */
export const ADDRESS_TREE_ID: TreeId = 0;
export const AUDIT_CREDENTIAL_SIZE = 257;

/** `sequence_number` opens Rust `TreeAccountLayout::nullifier`, pinned by its layout test. */
export const NULLIFIER_SEQUENCE_OFFSET = 17_152;
/** Rust `ACCOUNT_BLINDING_SEED`, public as the state is, each derivation folds in the address. */
export const ACCOUNT_BLINDING_SEED = rightAlign(Uint8Array.of(1)) as Bytes32;
const UNIQUE_DATA_HASH_DOMAIN = 0x554e_4951; // "UNIQ"
const PLAINTEXT_TAG = 0;

/** Borsh order, the nullifier secret and list salt occur only inside `ciphertext`. */
export interface AuditCredential {
  /** `ringIdField` of the ring program. */
  readonly ringId: Bytes32;
  /** `solanaOwnerIdentity` of the owner. */
  readonly member: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly listTag: Bytes32;
  readonly auditorPubkey: Bytes33;
  readonly ephU: Bytes32;
  readonly ciphertext: Bytes64;
}

export interface AddressCheckpoint {
  readonly root: Bytes32;
  readonly rootIndex: number;
  /** Tree 0 append count when `root` was written. */
  readonly sequence: bigint;
}

export interface CredentialRead {
  readonly addressRootIndex: number;
  readonly stateRootIndexes: readonly number[];
}

/** A public only update reads no credential and passes no credential account. */
export const EMPTY_CREDENTIAL_READ: CredentialRead = Object.freeze({
  addressRootIndex: 0,
  stateRootIndexes: Object.freeze([]),
});

/** CRRG and CRCR share every field position, only the first element selects proof or state. */
export function credentialElements(
  credential: AuditCredential,
  domain: typeof RingDomain.registerKey | typeof RingDomain.credentialState,
): readonly Bytes32[] {
  const [, ...fields] = registerKeyStatementElements(credential);
  return [domainField(domain), ...fields];
}

/** The RegisterKey public input, the statement hash `Enroll` verifies. */
export function registerKeyHash(credential: AuditCredential): Bytes32 {
  return hashChain4(credentialElements(credential, RingDomain.registerKey)) as Bytes32;
}

export function credentialStateHash(credential: AuditCredential): Bytes32 {
  return hashChain4(credentialElements(credential, RingDomain.credentialState)) as Bytes32;
}

/** Binds the state to its one reserved address. */
export function credentialDataHash(credential: AuditCredential, address: Bytes32): Bytes32 {
  return poseidon([
    rightAlign(u32be(UNIQUE_DATA_HASH_DOMAIN)),
    address,
    credentialStateHash(credential),
  ]) as Bytes32;
}

/** A key or viewing key change keeps the same address. */
export function credentialSeed(ringId: Bytes32, member: Bytes32): Bytes32 {
  return poseidon([domainField(RingDomain.credentialSeed), ringId, member]) as Bytes32;
}

export async function credentialPda(ringProgramId: Address): Promise<Address> {
  const [pda] = await getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [CREDENTIAL_PDA_SEED],
  });
  return pda;
}

/** The owner hash every statement reading a credential carries, the circuit cannot derive a PDA. */
export function credentialOwnerHash(pda: Address): Bytes32 {
  return ownerHash(
    ShieldedPublicKey.fromPda(pda).ownerProofInputHash(),
    ZERO_NULLIFIER_PK,
  ) as Bytes32;
}

/** The address slot `Enroll` proves absent in tree 0, Rust `NewAddress::derive`. */
export function credentialAddressInput(pda: Address, seed: Bytes32): ProofInputUtxo {
  return ProofInputUtxo.address(ShieldedPublicKey.fromPda(pda), seed, ADDRESS_TREE_ID);
}

/** The address slot's zero key nullifier in tree 0. */
export function credentialAddress(pda: Address, seed: Bytes32): Bytes32 {
  return credentialAddressInput(pda, seed).nullifier();
}

/** Enroll writes one output, so its blinding derives from the address alone. */
export function credentialBlinding(address: Bytes32): Bytes32 {
  return transactOutputBlinding(address, outputBlindingSeed(address, ACCOUNT_BLINDING_SEED), 0);
}

/** SPP `DataUtxo::hash`, the tree id names the tree the credential lives in. */
export function credentialUtxoHash(
  input: Readonly<{ pda: Address; address: Bytes32; credential: AuditCredential; treeId: TreeId }>,
): Bytes32 {
  const utxo = new Utxo({
    owner: ShieldedPublicKey.fromPda(input.pda),
    asset: SOL_MINT,
    amount: 0n,
    blinding: credentialBlinding(input.address),
  });
  return utxo.hash(
    ZERO_NULLIFIER_PK,
    input.treeId,
    credentialDataHash(input.credential, input.address),
  );
}

export function encodeAuditCredential(credential: AuditCredential): Uint8Array {
  return concatBytes(
    credential.ringId,
    credential.member,
    credential.nullifierPk,
    credential.listTag,
    credential.auditorPubkey,
    credential.ephU,
    credential.ciphertext,
  );
}

export function decodeAuditCredential(data: Uint8Array): AuditCredential {
  if (data.length !== AUDIT_CREDENTIAL_SIZE) throw invalid("credentialLength");
  const reader = new Reader(data);
  const credential = Object.freeze({
    ringId: reader.bytes(32, "ringId") as Bytes32,
    member: reader.bytes(32, "member") as Bytes32,
    nullifierPk: reader.bytes(32, "nullifierPk") as Bytes32,
    listTag: reader.bytes(32, "listTag") as Bytes32,
    auditorPubkey: reader.bytes(33, "auditorPubkey") as Bytes33,
    ephU: reader.bytes(32, "ephU") as Bytes32,
    ciphertext: reader.bytes(64, "ciphertext") as Bytes64,
  });
  reader.done();
  return credential;
}

/** Rust `plaintext_output_data`, `tag || u32 LE length || address || Borsh(credential)`. */
export function encodeCredentialOutput(address: Bytes32, credential: AuditCredential): Uint8Array {
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, 32 + AUDIT_CREDENTIAL_SIZE, true);
  return concatBytes(
    Uint8Array.of(PLAINTEXT_TAG),
    length,
    address,
    encodeAuditCredential(credential),
  );
}

/** `Plaintext(address || Borsh(credential))`, the output data `Enroll` publishes. */
export function decodeCredentialOutput(
  payload: Uint8Array,
): Readonly<{ address: Bytes32; credential: AuditCredential }> {
  const body = 32 + AUDIT_CREDENTIAL_SIZE;
  if (payload.length !== 5 + body || payload[0] !== PLAINTEXT_TAG) throw invalid("outputFrame");
  if (new DataView(payload.buffer, payload.byteOffset + 1, 4).getUint32(0, true) !== body)
    throw invalid("outputFrame");
  return Object.freeze({
    address: payload.slice(5, 37) as Bytes32,
    credential: decodeAuditCredential(payload.slice(37)),
  });
}

/**
 * The append count of the tree 0 nullifier root at `rootIndex`. Init writes sequence 0 to
 * slot 0 and each apply adds one root and one count, so a slot's distance behind the newest
 * root is its distance behind `sequence_number`.
 */
export function rootSequence(tree: Uint8Array, rootIndex: number): AddressCheckpoint {
  // 1. Another tree carries roots no credential address entered.
  if (decodeTreeId(tree) !== ADDRESS_TREE_ID) throw invalid("addressTree");
  const capacity = BigInt(NULLIFIER_TREE_ROOT_HISTORY_CAPACITY);
  if (!Number.isInteger(rootIndex) || rootIndex < 0 || BigInt(rootIndex) >= capacity)
    throw invalid("rootIndex");
  const view = new DataView(tree.buffer, tree.byteOffset, tree.byteLength);
  const sequenceNumber = view.getBigUint64(NULLIFIER_SEQUENCE_OFFSET, true);
  const cursor = view.getBigUint64(NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET, true);
  if (cursor >= capacity) throw invalid("rootCursor");
  // 2. An unwritten slot is zero and names no root the program accepts.
  const start = NULLIFIER_ROOT_HISTORY_OFFSET + rootIndex * 32;
  const root = tree.slice(start, start + 32) as Bytes32;
  if (isZero(root)) throw invalid("emptyRoot");
  // 3. The cursor points past the newest root. A distance past the append count names a
  // slot the history never held at that position.
  const newest = (cursor + capacity - 1n) % capacity;
  const distance = (newest + capacity - BigInt(rootIndex)) % capacity;
  if (distance > sequenceNumber) throw invalid("rootSequence");
  return Object.freeze({ root, rootIndex, sequence: sequenceNumber - distance });
}

/** `address_root_index u16 LE || D u8 || D x u16 LE`, the empty read writes zero for all three. */
export function encodeCredentialRead(read: CredentialRead): Uint8Array {
  const { addressRootIndex, stateRootIndexes } = read;
  if (stateRootIndexes.length > 0xff) throw invalid("stateRootCount");
  if (stateRootIndexes.length === 0 && addressRootIndex !== 0) throw invalid("emptyRead");
  const bytes = new Uint8Array(3 + 2 * stateRootIndexes.length);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, u16(addressRootIndex), true);
  bytes[2] = stateRootIndexes.length;
  stateRootIndexes.forEach((index, at) => view.setUint16(3 + 2 * at, u16(index), true));
  return bytes;
}

function u16(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw invalid("rootIndex");
  return value;
}

function invalid(reason: string): RingError {
  return new RingError("RING_CREDENTIAL_INVALID", { details: { reason } });
}
