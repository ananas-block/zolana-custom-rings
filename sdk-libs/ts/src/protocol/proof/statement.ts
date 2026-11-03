import {
  hashBytes,
  hashChain4,
  checkedBytes,
  bigIntBytes,
  rightAlign,
} from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { packBytesBe } from "../../crypto/derivation/hasher.js";
import { auditLayoutValue, type AuditLayout } from "../codec/ring-disclosure-layout.js";

import {
  TRANSFER_STATEMENT_VERSION,
  RingDomain,
  domainField,
} from "../../crypto/derivation/ring-domain.js";
import { RingError } from "../error.js";
import {
  RingTransactData,
  outputBodyHash,
  outputRecipientKeyFields,
  taggedX25519,
  type RingOutput,
} from "../transaction/transact.js";
import { N_PUBLIC_SLOTS } from "../transaction/spp.js";

/** The values every transfer statement opens with, Rust `AuditHead`. */
export interface AuditHead {
  readonly firstNullifier: Bytes32;
  /** `hash_bytes` of the ring program id. */
  readonly ringId: Bytes32;
  readonly txViewingU: Bytes32;
  /** `0x04 ‖ u` as the ring config stores it. */
  readonly auditorPubkey: Bytes33;
  readonly ephU: Bytes32;
  readonly sealed: Bytes32;
  readonly salt: Bytes16;
  readonly layout: AuditLayout;
}

/** The rail's own statement values, Rust `TransferFamily`. */
export type TransferFamily =
  /** The signer, in-proof and authority rails. */
  | Readonly<{
      kind: "confidential";
      inProof: boolean;
      delegate: boolean;
      /** The in-proof owner's identity, the sole owner signer's under a policy, else zero. */
      sender: Bytes32;
      /** One owner identity per output slot, zero on a dummy and off a policy. */
      recipients: readonly Bytes32[];
    }>
  /** The anonymous rail, the head's layout picks the commitment or entry disclosure. */
  | Readonly<{
      kind: "anonymous";
      /** `solana_owner_identity` of the payer, the signing co-signer and the withdrawal destination, zero when absent. */
      partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
    }>;

/** The roots the transfer statement binds, zero where the program reads none, Rust `TransferRoots`. */
export interface TransferRoots {
  readonly policyHash: Bytes32;
  readonly ownRoot: Bytes32;
  readonly curatorRoot: Bytes32;
}

/** Every ring transfer's one proof, Rust `TransferStatement`. */
export interface TransferStatement {
  readonly head: AuditHead;
  readonly family: TransferFamily;
  readonly exempt: boolean;
  readonly approvalRequired: boolean;
  /** Published output order. */
  readonly outputs: readonly RingOutput[];
  /** Exactly the published disclosure fields. */
  readonly disclosure: readonly Bytes32[];
  readonly privateTxHash: Bytes32;
  readonly roots: TransferRoots;
  /** SPP's public asset fields, zero past the used slots. */
  readonly publicAssets: readonly Bytes32[];
  /** SPP's public amount fields, a withdrawal is `q - |amount|`. */
  readonly publicAmounts: readonly Bytes32[];
  /** Gross withdrawals per slot as right aligned u128. */
  readonly publicGross: readonly Bytes32[];
  readonly withdrawalHash: Bytes32;
}

/** An application of `count` queued writes, Rust `ApplyRecordsStatement`. */
export interface ApplyRecordsStatement {
  readonly oldRoot: Bytes32;
  readonly newRoot: Bytes32;
  readonly oldNextIndex: number;
  readonly newNextIndex: number;
  /** `chain(head - 1)`. */
  readonly chainStart: Bytes32;
  /** `chain(tail - 1)`. */
  readonly chainEnd: Bytes32;
  readonly count: bigint;
}

/** The auditor envelope of a registered nullifier key, Rust `RegisterKeyStatement`. */
export interface RegisterKeyStatement {
  /** The owner identity of the signing member. */
  readonly member: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly auditorPubkey: Bytes33;
  readonly ephU: Bytes32;
  readonly ciphertext: Bytes32;
}

/**
 * `head ‖ [in_proof, delegate] ‖ exempt, approval_required, output_chain ‖ [body_chain,
 * recipient_key_chain] ‖ disclosure_chain, private_tx_hash ‖ sender | party0, party1, party2 ‖
 * policy_hash, own_root, curator_root ‖ [recipient per output] ‖ (asset, net, gross) x 3 ‖
 * withdrawal_hash, length, version`, the bracketed runs on the confidential family alone.
 */
export function transferStatementElements(statement: TransferStatement): readonly Bytes32[] {
  const { outputs, family, publicAssets, publicAmounts, publicGross } = statement;
  if (
    publicAssets.length !== N_PUBLIC_SLOTS ||
    publicAmounts.length !== N_PUBLIC_SLOTS ||
    publicGross.length !== N_PUBLIC_SLOTS
  )
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "publicSlots", expected: N_PUBLIC_SLOTS },
    });
  const confidential = family.kind === "confidential";
  const elements: Bytes32[] = [
    ...auditHeadElements(statement.head),
    ...(confidential ? [bit(family.inProof), bit(family.delegate)] : []),
    bit(statement.exempt),
    bit(statement.approvalRequired),
    chain(outputs.map((output) => output.hash)),
    ...(confidential
      ? [chain(outputs.map(outputBodyHash)), chain(outputs.flatMap(outputRecipientKeyFields))]
      : []),
    chain(statement.disclosure),
    checkedBytes<Bytes32>(statement.privateTxHash, 32, "private tx hash"),
    ...(family.kind === "confidential"
      ? [checkedBytes<Bytes32>(family.sender, 32, "sender")]
      : family.partyIdentities.map((party) => checkedBytes<Bytes32>(party, 32, "party"))),
    checkedBytes<Bytes32>(statement.roots.policyHash, 32, "policy hash"),
    checkedBytes<Bytes32>(statement.roots.ownRoot, 32, "own root"),
    checkedBytes<Bytes32>(statement.roots.curatorRoot, 32, "curator root"),
    ...(family.kind === "confidential"
      ? family.recipients.map((recipient) => checkedBytes<Bytes32>(recipient, 32, "recipient"))
      : []),
    ...publicAssets.flatMap((asset, slot) => [
      checkedBytes<Bytes32>(asset, 32, "public asset"),
      checkedBytes<Bytes32>(publicAmounts[slot] as Bytes32, 32, "public amount"),
      checkedBytes<Bytes32>(publicGross[slot] as Bytes32, 32, "public gross"),
    ]),
    checkedBytes<Bytes32>(statement.withdrawalHash, 32, "withdrawal hash"),
  ];
  // The count then the version close the chain, another length or layout hashes apart.
  return [
    ...elements,
    bigIntBytes(BigInt(elements.length + 2)) as Bytes32,
    bigIntBytes(TRANSFER_STATEMENT_VERSION) as Bytes32,
  ];
}

export function transferStatementHash(statement: TransferStatement): Bytes32 {
  return chain(transferStatementElements(statement));
}

/** What the program supplies beside the data for the transfer statement, Rust `TransferBinding`. */
export interface TransferBinding {
  /** `hash_bytes` of the ring program id. */
  readonly ringId: Bytes32;
  readonly auditorPubkey: Bytes33;
  /** The ring mode escrows every output nullifier key, the frame flag has to agree. */
  readonly keyEscrow: boolean;
  /** The in-proof owner's identity, the sole owner signer's under a policy, zero otherwise. */
  readonly sender: Bytes32;
  /** Zeros off the anonymous rail. */
  readonly partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
  readonly roots: TransferRoots;
  readonly publicAssets: readonly Bytes32[];
  readonly publicAmounts: readonly Bytes32[];
  readonly publicGross: readonly Bytes32[];
  readonly withdrawalHash: Bytes32;
}

/** The statement the transfer proof is verified against, a key escrow flag off the ring mode refused. */
export function ringTransferStatement(
  data: RingTransactData,
  binding: TransferBinding,
): TransferStatement {
  if (binding.keyEscrow !== data.keyEscrow)
    throw new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason: "FlagNotAllowed" } });
  const layout = RingTransactData.disclosureLayout(data);
  const family: TransferFamily =
    layout.kind === "anonymous"
      ? { kind: "anonymous", partyIdentities: binding.partyIdentities }
      : {
          kind: "confidential",
          inProof: data.inProofOwner !== undefined,
          delegate: data.rail === "delegate",
          sender: binding.sender,
          recipients: RingTransactData.recipients(data),
        };
  return Object.freeze({
    head: Object.freeze({
      firstNullifier: RingTransactData.firstNullifier(data),
      ringId: binding.ringId,
      txViewingU: data.txViewingU,
      auditorPubkey: binding.auditorPubkey,
      ephU: data.ephU,
      sealed: data.sealed,
      salt: data.salt,
      layout: RingTransactData.auditLayout(data),
    }),
    family,
    exempt: data.exempt,
    approvalRequired: data.approvalRequired,
    outputs: data.outputs,
    disclosure: data.disclosure,
    privateTxHash: data.privateTxHash,
    roots: binding.roots,
    publicAssets: binding.publicAssets,
    publicAmounts: binding.publicAmounts,
    publicGross: binding.publicGross,
    withdrawalHash: binding.withdrawalHash,
  });
}

/** `[CRAP, old_root, new_root, old_next, new_next, chain_start, chain_end, count]`. */
export function applyRecordsStatementElements(
  statement: ApplyRecordsStatement,
): readonly Bytes32[] {
  return [
    domainField(RingDomain.applyRecords),
    checkedBytes<Bytes32>(statement.oldRoot, 32, "old root"),
    checkedBytes<Bytes32>(statement.newRoot, 32, "new root"),
    u64Field(BigInt(statement.oldNextIndex), "old next index", U32_MAX),
    u64Field(BigInt(statement.newNextIndex), "new next index", U32_MAX),
    checkedBytes<Bytes32>(statement.chainStart, 32, "chain start"),
    checkedBytes<Bytes32>(statement.chainEnd, 32, "chain end"),
    u64Field(statement.count, "count"),
  ];
}

export function applyRecordsStatementHash(statement: ApplyRecordsStatement): Bytes32 {
  return chain(applyRecordsStatementElements(statement));
}

/** `[CRRG, member, nullifier_pk, aud0, aud1, eph0, eph1, hash_bytes(ciphertext)]`. */
export function registerKeyStatementElements(statement: RegisterKeyStatement): readonly Bytes32[] {
  return [
    domainField(RingDomain.registerKey),
    checkedBytes<Bytes32>(statement.member, 32, "member"),
    checkedBytes<Bytes32>(statement.nullifierPk, 32, "nullifier pk"),
    ...packedKey(checkedBytes<Bytes33>(statement.auditorPubkey, 33, "auditor pubkey")),
    ...packedKey(taggedX25519(statement.ephU)),
    hashBytes(checkedBytes<Bytes32>(statement.ciphertext, 32, "ciphertext")) as Bytes32,
  ];
}

export function registerKeyStatementHash(statement: RegisterKeyStatement): Bytes32 {
  return chain(registerKeyStatementElements(statement));
}

const U32_MAX = 0xffff_ffffn;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** `[CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, sealed_hash, salt, layout]`. */
function auditHeadElements(head: AuditHead): readonly Bytes32[] {
  return [
    domainField(RingDomain.transferStatement),
    checkedBytes<Bytes32>(head.firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(head.ringId, 32, "ring id"),
    ...packedKey(taggedX25519(head.txViewingU)),
    ...packedKey(checkedBytes<Bytes33>(head.auditorPubkey, 33, "auditor pubkey")),
    ...packedKey(taggedX25519(head.ephU)),
    hashBytes(checkedBytes<Bytes32>(head.sealed, 32, "sealed")) as Bytes32,
    rightAlign(checkedBytes<Bytes16>(head.salt, 16, "salt")),
    rightAlign(Uint8Array.of(auditLayoutValue(head.layout))),
  ];
}

function packedKey(key: Bytes33): readonly Bytes32[] {
  return packBytesBe(key) as Bytes32[];
}

function chain(values: readonly Bytes32[]): Bytes32 {
  return hashChain4(values) as Bytes32;
}

function bit(value: boolean): Bytes32 {
  return rightAlign(Uint8Array.of(value ? 1 : 0));
}

function u64Field(value: bigint, name: string, maximum = U64_MAX): Bytes32 {
  if (typeof value !== "bigint" || value < 0n || value > maximum)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name, minimum: "0", maximum: maximum.toString() },
    });
  return bigIntBytes(value) as Bytes32;
}
