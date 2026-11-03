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
import { packBytesBe } from "../../crypto/derivation/hasher.js";
import { domainField, RingDomain } from "../../crypto/derivation/ring-domain.js";
import { u32Field } from "../../crypto/error.js";
import { RingError } from "../error.js";
import { N_PUBLIC_SLOTS } from "../transaction/spp.js";
import { exitsBitmap, HistoricalTransactData, type HistoricalOutput } from "./frame.js";
import { auditLayoutValue, type AuditLayout } from "./layout.js";

/** Closes every chain, a shared value would let a version 2 proof pass as version 3. */
export const HISTORICAL_TRANSFER_STATEMENT_VERSION = 2n;

export interface HistoricalAuditHead {
  readonly firstNullifier: Bytes32;
  readonly ringId: Bytes32;
  readonly txViewingU: Bytes32;
  readonly auditorPubkey: Bytes33;
  readonly ephU: Bytes32;
  readonly envelope: Uint8Array;
  readonly salt: Bytes16;
  readonly layout: AuditLayout;
}

export type HistoricalTransferFamily =
  | Readonly<{
      kind: "confidential";
      inProof: boolean;
      delegate: boolean;
      sender: Bytes32;
      recipients: readonly Bytes32[];
    }>
  | Readonly<{
      kind: "anonymous";
      partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
    }>;

export interface HistoricalTransferRoots {
  readonly policyHash: Bytes32;
  readonly ownRoot: Bytes32;
  readonly curatorRoot: Bytes32;
}

export interface HistoricalTransferStatement {
  readonly head: HistoricalAuditHead;
  readonly family: HistoricalTransferFamily;
  readonly exempt: boolean;
  readonly approvalRequired: boolean;
  readonly outputs: readonly HistoricalOutput[];
  readonly outputCiphertexts: readonly Uint8Array[];
  readonly inputCount: number;
  readonly privateTxHash: Bytes32;
  readonly roots: HistoricalTransferRoots;
  readonly publicAssets: readonly Bytes32[];
  readonly publicAmounts: readonly Bytes32[];
  readonly publicGross: readonly Bytes32[];
  readonly withdrawalHash: Bytes32;
}

export interface HistoricalTransferBinding {
  readonly ringId: Bytes32;
  readonly auditorPubkey: Bytes33;
  readonly keyEscrow: boolean;
  readonly sender: Bytes32;
  readonly partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
  readonly roots: HistoricalTransferRoots;
  readonly publicAssets: readonly Bytes32[];
  readonly publicAmounts: readonly Bytes32[];
  readonly publicGross: readonly Bytes32[];
  readonly withdrawalHash: Bytes32;
}

/** A key escrow flag off the ring mode refused. */
export function historicalTransferStatement(
  data: HistoricalTransactData,
  binding: HistoricalTransferBinding,
): HistoricalTransferStatement {
  if (binding.keyEscrow !== data.keyEscrow)
    throw new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason: "FlagNotAllowed" } });
  const family: HistoricalTransferFamily =
    data.rail === "anonymous"
      ? { kind: "anonymous", partyIdentities: binding.partyIdentities }
      : {
          kind: "confidential",
          inProof: data.inProofOwner !== undefined,
          delegate: data.rail === "delegate",
          sender: binding.sender,
          recipients: HistoricalTransactData.recipients(data),
        };
  return Object.freeze({
    head: Object.freeze({
      firstNullifier: HistoricalTransactData.firstNullifier(data),
      ringId: binding.ringId,
      txViewingU: data.txViewingU,
      auditorPubkey: binding.auditorPubkey,
      ephU: data.ephU,
      envelope: data.envelope,
      salt: data.salt,
      layout: HistoricalTransactData.auditLayout(data),
    }),
    family,
    exempt: data.exempt,
    approvalRequired: data.approvalRequired,
    outputs: data.outputs,
    outputCiphertexts: HistoricalTransactData.outputCiphertexts(data),
    inputCount: data.nullifiers.length,
    privateTxHash: data.privateTxHash,
    roots: binding.roots,
    publicAssets: binding.publicAssets,
    publicAmounts: binding.publicAmounts,
    publicGross: binding.publicGross,
    withdrawalHash: binding.withdrawalHash,
  });
}

export function historicalStatementElements(
  statement: HistoricalTransferStatement,
): readonly Bytes32[] {
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
    chain(statement.outputCiphertexts.map((ciphertext) => hashBytes(ciphertext) as Bytes32)),
    ...(confidential ? [chain(outputs.flatMap(outputRecipientKeyFields))] : []),
    u32Field(statement.inputCount, "input count"),
    bigIntBytes(exitsBitmap(outputs)) as Bytes32,
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
  return [
    ...elements,
    bigIntBytes(BigInt(elements.length + 2)) as Bytes32,
    bigIntBytes(HISTORICAL_TRANSFER_STATEMENT_VERSION) as Bytes32,
  ];
}

export function historicalStatementHash(statement: HistoricalTransferStatement): Bytes32 {
  return chain(historicalStatementElements(statement));
}

/** `[CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, digest(envelope_ct), salt, layout]`. */
function auditHeadElements(head: HistoricalAuditHead): readonly Bytes32[] {
  return [
    domainField(RingDomain.transferStatement),
    checkedBytes<Bytes32>(head.firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(head.ringId, 32, "ring id"),
    ...packedKey(taggedKey(head.txViewingU)),
    ...packedKey(checkedBytes<Bytes33>(head.auditorPubkey, 33, "auditor pubkey")),
    ...packedKey(taggedKey(head.ephU)),
    ciphertextDigest(head.envelope),
    rightAlign(checkedBytes<Bytes16>(head.salt, 16, "salt")),
    rightAlign(Uint8Array.of(auditLayoutValue(head.layout))),
  ];
}

/** The length tag closes the trailing zero ambiguity of `HashChain4`. */
function ciphertextDigest(ciphertext: Uint8Array): Bytes32 {
  return poseidon([
    u32Field(ciphertext.length, "ciphertext length"),
    chain(packDisclosure(ciphertext)),
  ]) as Bytes32;
}

/** `pack_be(u)` of a delivered slot, zeros for any other. */
function outputRecipientKeyFields(output: HistoricalOutput): readonly Bytes32[] {
  return output.kind === "delivered"
    ? (packBytesBe(checkedBytes<Bytes32>(output.u, 32, "u")) as Bytes32[])
    : [ZERO, ZERO];
}

/** `0x04 ‖ u`. */
function taggedKey(u: Bytes32): Bytes33 {
  const key = new Uint8Array(33);
  key[0] = VIEWING_PUBKEY_TAG;
  key.set(checkedBytes<Bytes32>(u, 32, "u"), 1);
  return key as Bytes33;
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

const VIEWING_PUBKEY_TAG = 4;
const ZERO = new Uint8Array(32) as Bytes32;
