import {
  hashBytes,
  hashChain4,
  checkedBytes,
  bigIntBytes,
  rightAlign,
} from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import { poseidon } from "@heliuslabs/zolana/keypair";
import { packDisclosure } from "../../crypto/audit/audit.js";
import { u32Field } from "../../crypto/error.js";
import { packBytesBe } from "../../crypto/derivation/hasher.js";
import { auditLayoutValue, type AuditLayout } from "../codec/ring-disclosure-layout.js";

import {
  TRANSFER_STATEMENT_VERSION,
  RingDomain,
  domainField,
} from "../../crypto/derivation/ring-domain.js";
import { RingError } from "../error.js";
import { ListId, recordBit } from "../membership/policy.js";
import {
  RingTransactData,
  changeBitmap,
  exitsBitmap,
  outputRecipientKeyFields,
  replyRegion,
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
  /** `tx_viewing_sk ‖ evidence` under the auditor stream. */
  readonly envelope: Uint8Array;
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
      /** The in-proof owner's identity, zero on the signer and authority rails. */
      sender: Bytes32;
      /** One owner identity per published slot, zero on a dummy and off a policy. */
      recipients: readonly Bytes32[];
    }>
  /** The anonymous rail, the head's layout picks the commitment or entry disclosure. */
  | Readonly<{
      kind: "anonymous";
      /** `solana_owner_identity` of the payer, the signing co-signer and the withdrawal destination, zero when absent. */
      partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
      /** The transmitted scheme 12 ciphertext, its length follows `m`. */
      senderBundle: Uint8Array;
      senderBundleTag: Bytes32;
      /** Every reply in slot order, absent without the flag. */
      replies?: Uint8Array;
    }>;

export interface SignerBinding {
  readonly count: number;
  readonly chain: Bytes32;
}

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
  /** `N`, every per-slot chain is zero-filled to it. */
  readonly capacity: number;
  /** Published output order, `m` slots. */
  readonly outputs: readonly RingOutput[];
  /** One ring disclosure ciphertext per published slot, in output order. */
  readonly outputCiphertexts: readonly Uint8Array[];
  readonly signers: SignerBinding;
  /** `n`, the frame's nullifier count. */
  readonly inputCount: number;
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
  /** Set when any write restricts, `Update` then retires every earlier root. */
  readonly restrictive: boolean;
}

/** An application of named enrollments, Rust `ApplyEnrollmentsStatement`. */
export type ApplyEnrollmentsStatement = Omit<ApplyRecordsStatement, "restrictive">;

/** The auditor envelope of an enrolled nullifier key, Rust `RegisterKeyStatement`. */
export interface RegisterKeyStatement {
  /** The tracking registry's. */
  readonly ringId: Bytes32;
  /** The owner identity of the signing member. */
  readonly member: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly listTag: Bytes32;
  readonly auditorPubkey: Bytes33;
  readonly ephU: Bytes32;
  readonly ciphertext: Bytes32;
}

export function transferStatementElements(statement: TransferStatement): readonly Bytes32[] {
  const { outputs, family, publicAssets, publicAmounts, publicGross, capacity } = statement;
  if (
    publicAssets.length !== N_PUBLIC_SLOTS ||
    publicAmounts.length !== N_PUBLIC_SLOTS ||
    publicGross.length !== N_PUBLIC_SLOTS
  )
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "publicSlots", expected: N_PUBLIC_SLOTS },
    });
  if (outputs.length > capacity || statement.outputCiphertexts.length !== outputs.length)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "outputs", expected: capacity, actual: outputs.length },
    });
  const outputChain = filledChain(
    outputs.map((output) => output.hash),
    capacity,
  );
  const ciphertextChain = outputCiphertextChain(statement.outputCiphertexts, capacity);
  const counts = [
    u32Field(statement.inputCount, "input count"),
    bigIntBytes(exitsBitmap(outputs)) as Bytes32,
    checkedBytes<Bytes32>(statement.privateTxHash, 32, "private tx hash"),
  ];
  const signers = [
    u32Field(statement.signers.count, "signer count"),
    checkedBytes<Bytes32>(statement.signers.chain, 32, "signer chain"),
  ];
  const roots = [
    checkedBytes<Bytes32>(statement.roots.policyHash, 32, "policy hash"),
    checkedBytes<Bytes32>(statement.roots.ownRoot, 32, "own root"),
    checkedBytes<Bytes32>(statement.roots.curatorRoot, 32, "curator root"),
  ];
  const publicLegs = publicAssets.flatMap((asset, slot) => [
    checkedBytes<Bytes32>(asset, 32, "public asset"),
    checkedBytes<Bytes32>(publicAmounts[slot] as Bytes32, 32, "public amount"),
    checkedBytes<Bytes32>(publicGross[slot] as Bytes32, 32, "public gross"),
  ]);
  const withdrawalHash = checkedBytes<Bytes32>(statement.withdrawalHash, 32, "withdrawal hash");
  const head = auditHeadElements(statement.head);
  const outputCount = u32Field(outputs.length, "output count");
  const elements: Bytes32[] =
    family.kind === "confidential"
      ? [
          ...head,
          bit(family.inProof),
          bit(family.delegate),
          bit(statement.exempt),
          bit(statement.approvalRequired),
          outputCount,
          outputChain,
          ciphertextChain,
          filledChain(outputs.flatMap(outputRecipientKeyFields), 2 * capacity),
          ...counts,
          checkedBytes<Bytes32>(family.sender, 32, "sender"),
          ...signers,
          ...roots,
          ...filled(family.recipients, capacity).map((recipient) =>
            checkedBytes<Bytes32>(recipient, 32, "recipient"),
          ),
          ...publicLegs,
          withdrawalHash,
        ]
      : [
          ...head,
          bit(statement.exempt),
          bit(statement.approvalRequired),
          outputCount,
          outputChain,
          ciphertextChain,
          recipientBodyChain(outputs, capacity),
          recipientTagChain(outputs, capacity, family.senderBundleTag),
          bigIntBytes(changeBitmap(outputs)) as Bytes32,
          ciphertextDigest(family.senderBundle),
          ...counts,
          ...family.partyIdentities.map((party) => checkedBytes<Bytes32>(party, 32, "party")),
          ...signers,
          ...roots,
          ...publicLegs,
          withdrawalHash,
          family.replies === undefined ? ZERO_FIELD : ciphertextDigest(family.replies),
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
  /** The in-proof owner's identity, zero otherwise. */
  readonly sender: Bytes32;
  /** Zeros off the anonymous rail. */
  readonly partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
  /** The SPP owner signer run, first-occurrence dedup, each by its owner identity. */
  readonly signers: readonly Bytes32[];
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
  const replies = replyRegion(data);
  const family: TransferFamily =
    data.rail === "anonymous"
      ? {
          kind: "anonymous",
          partyIdentities: binding.partyIdentities,
          senderBundle: data.sender?.body ?? new Uint8Array(),
          senderBundleTag: data.sender?.tag ?? ZERO_FIELD,
          ...(replies === undefined ? {} : { replies }),
        }
      : {
          kind: "confidential",
          inProof: data.inProofOwner !== undefined,
          delegate: data.rail === "delegate",
          sender: binding.sender,
          recipients: RingTransactData.recipients(data),
        };
  const layout = RingTransactData.streamLayout(data);
  // In-proof, authority and entry bind no run, every other key one chain of its `S` slots.
  const unbound = data.inProofOwner !== undefined || data.rail === "delegate" || data.fullOpenings;
  return Object.freeze({
    head: Object.freeze({
      firstNullifier: RingTransactData.firstNullifier(data),
      ringId: binding.ringId,
      txViewingU: data.txViewingU,
      auditorPubkey: binding.auditorPubkey,
      ephU: data.ephU,
      envelope: data.envelope,
      salt: data.salt,
      layout: RingTransactData.auditLayout(data),
    }),
    family,
    exempt: data.exempt,
    approvalRequired: data.approvalRequired,
    capacity: data.nOut,
    outputs: data.outputs,
    outputCiphertexts: RingTransactData.outputCiphertexts(data),
    signers: unbound
      ? Object.freeze({ count: 0, chain: ZERO_FIELD })
      : signerBinding(binding.signers, layout.key.class),
    inputCount: data.nullifiers.length,
    privateTxHash: data.privateTxHash,
    roots: binding.roots,
    publicAssets: binding.publicAssets,
    publicAmounts: binding.publicAmounts,
    publicGross: binding.publicGross,
    withdrawalHash: binding.withdrawalHash,
  });
}

/** `HashChain4(identity_0 .. identity_{count-1}, 0 .. 0 up to slots)`, reorder or an extra signer hashes apart. */
export function signerBinding(identities: readonly Bytes32[], slots: number): SignerBinding {
  if (identities.length > slots)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "signers", expected: slots, actual: identities.length },
    });
  // An empty run binds zero on every rail, the program and the circuit agree on it.
  if (identities.length === 0) return Object.freeze({ count: 0, chain: ZERO_FIELD });
  return Object.freeze({ count: identities.length, chain: filledChain(identities, slots) });
}

/** A write clears a grant list, sets a deny list or replaces mint settings, mirror `registry.Restrictive`. */
export function restrictiveWrite(
  mask: bigint,
  value: bigint,
  replacesMintPolicy: boolean,
): boolean {
  const grant = recordBit(ListId.allow) | recordBit(ListId.approval);
  const deny = recordBit(ListId.block) | recordBit(ListId.frozen);
  return replacesMintPolicy || (mask & grant & ~value) !== 0n || (value & deny) !== 0n;
}

/** `[CRAP, old_root, new_root, old_next, new_next, chain_start, chain_end, count, restrictive]`. */
export function applyRecordsStatementElements(
  statement: ApplyRecordsStatement,
): readonly Bytes32[] {
  return [
    ...applyStatementHead(RingDomain.applyRecords, statement),
    u64Field(statement.restrictive ? 1n : 0n, "restrictive"),
  ];
}

/** `[CRTA, old_root, new_root, old_next, new_next, chain_start, chain_end, count]`. */
export function applyEnrollmentsStatementElements(
  statement: ApplyEnrollmentsStatement,
): readonly Bytes32[] {
  return applyStatementHead(RingDomain.applyEnrollments, statement);
}

export function applyEnrollmentsStatementHash(statement: ApplyEnrollmentsStatement): Bytes32 {
  return chain(applyEnrollmentsStatementElements(statement));
}

function applyStatementHead(
  domain: RingDomain,
  statement: ApplyEnrollmentsStatement,
): readonly Bytes32[] {
  return [
    domainField(domain),
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

/** `[CRRG, ring_id, member, nullifier_pk, list_tag, aud0, aud1, eph0, eph1, hash_bytes(ciphertext)]`. */
export function registerKeyStatementElements(statement: RegisterKeyStatement): readonly Bytes32[] {
  return [
    domainField(RingDomain.registerKey),
    checkedBytes<Bytes32>(statement.ringId, 32, "ring id"),
    checkedBytes<Bytes32>(statement.member, 32, "member"),
    checkedBytes<Bytes32>(statement.nullifierPk, 32, "nullifier pk"),
    checkedBytes<Bytes32>(statement.listTag, 32, "list tag"),
    ...packedKey(checkedBytes<Bytes33>(statement.auditorPubkey, 33, "auditor pubkey")),
    ...packedKey(taggedX25519(statement.ephU)),
    hashBytes(checkedBytes<Bytes32>(statement.ciphertext, 32, "ciphertext")) as Bytes32,
  ];
}

export function registerKeyStatementHash(statement: RegisterKeyStatement): Bytes32 {
  return chain(registerKeyStatementElements(statement));
}

const ZERO_FIELD = new Uint8Array(32) as Bytes32;
const U32_MAX = 0xffff_ffffn;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** `[CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, digest(envelope_ct), salt, layout]`. */
function auditHeadElements(head: AuditHead): readonly Bytes32[] {
  return [
    domainField(RingDomain.transferStatement),
    checkedBytes<Bytes32>(head.firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(head.ringId, 32, "ring id"),
    ...packedKey(taggedX25519(head.txViewingU)),
    ...packedKey(checkedBytes<Bytes33>(head.auditorPubkey, 33, "auditor pubkey")),
    ...packedKey(taggedX25519(head.ephU)),
    ciphertextDigest(head.envelope),
    rightAlign(checkedBytes<Bytes16>(head.salt, 16, "salt")),
    rightAlign(Uint8Array.of(auditLayoutValue(head.layout))),
  ];
}

/** The length tag closes the trailing zero ambiguity of `HashChain4`. */
export function ciphertextDigest(ciphertext: Uint8Array): Bytes32 {
  return poseidon([
    u32Field(ciphertext.length, "ciphertext length"),
    chain(packDisclosure(ciphertext)),
  ]) as Bytes32;
}

/** Every ciphertext has a fixed length under the layout, `hash_bytes` needs no tag. */
export function outputCiphertextChain(
  ciphertexts: readonly Uint8Array[],
  capacity: number,
): Bytes32 {
  return filledChain(
    ciphertexts.map((ciphertext) => hashBytes(ciphertext) as Bytes32),
    capacity,
  );
}

/** Zero on a change or exit slot and past `m`, a hidden dummy's body hashes as sent. */
export function recipientBodyChain(outputs: readonly RingOutput[], capacity: number): Bytes32 {
  return filledChain(
    outputs.map((output) =>
      output.kind === "anonymous" ? (hashBytes(output.body) as Bytes32) : ZERO_FIELD,
    ),
    capacity,
  );
}

/** `tag_i` on a recipient or dummy slot, zero on change, exit and past `m`, the bundle tag last. */
export function recipientTagChain(
  outputs: readonly RingOutput[],
  capacity: number,
  senderBundleTag: Bytes32,
): Bytes32 {
  return chain([
    ...filled(
      outputs.map((output) => (output.kind === "anonymous" ? output.tag : ZERO_FIELD)),
      capacity,
    ),
    checkedBytes<Bytes32>(senderBundleTag, 32, "sender bundle tag"),
  ]);
}

/** Zero past the published values, `output_count` keeps the length apart. */
function filled(values: readonly Bytes32[], width: number): readonly Bytes32[] {
  return [...values, ...Array.from({ length: width - values.length }, () => ZERO_FIELD)];
}

function filledChain(values: readonly Bytes32[], width: number): Bytes32 {
  return chain(filled(values, width));
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
