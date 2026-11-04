/** The policy section of a ring transfer, every record read under a root the statement binds. */
import { EMPTY_MINT_POLICY, type MintPolicy } from "../protocol/membership/mint-policy.js";
import type { RecordPool } from "../protocol/membership/member-registry.js";
import {
  readPolicyWithdrawals,
  policyWithdrawalHash,
  type PolicyWithdrawal,
} from "./withdrawals.js";
import {
  ZERO_32,
  ZERO_NULLIFIER_PK,
  addressBytes,
  bytesKey,
  equalBytes,
  isZero,
} from "@heliuslabs/zolana/internal";
import { type RingRecordReader, type TrackingReader } from "../rpc/ports.js";
import type { ChainReader } from "@heliuslabs/zolana/client";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import {
  assetField,
  type ProofInputUtxo,
  type ProofOutputUtxo,
  type SettlementTransfer,
  type SppProofInputs,
} from "@heliuslabs/zolana/transaction";
import type {
  PolicyProofInputs,
  PolicySubjectEntry,
  PolicyTableProofInputs,
  TrackingProofInputs,
} from "../rpc/prover/ring.js";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "../rpc/prover/types.js";

import type { RingPolicy } from "../protocol/codec/ring-codecs.js";
import { RingError } from "../protocol/error.js";
import {
  unopenedRecordPool,
  type MemberOpeningRead,
} from "../protocol/membership/member-opening.js";
import {
  approvalMask,
  ownerDebits,
  type DebitInput,
  type DebitOutput,
  type PublicGross,
} from "../protocol/membership/owner-debits.js";
import {
  NO_PRIVATE_SOURCE,
  admitTransfer,
  memberOfAsset,
  pinnedPolicy,
  policyTableProofInputs,
  type RecordLists,
  type RuleRefusal,
} from "../protocol/membership/policy.js";
import { verifyTrackingPool, type TrackingRecord } from "../protocol/membership/tracking.js";
import { fetchBoundRoot, readRecordPool, type BoundRoot } from "../rpc/registered-record.js";
import { newestTrackingRoot } from "../rpc/tracking-resolver.js";
import type { TransferRoots } from "../protocol/proof/statement.js";
import {
  transferPoolCapacity,
  type TransferKeyCircuit,
} from "../protocol/proof/transfer-shapes.js";
import { isDelegateRail, type RingRail } from "../protocol/transaction/transact.js";
import {
  publicAmountFields,
  publicGrossFields,
  N_PUBLIC_SLOTS,
  type PublicSlots,
} from "../protocol/transaction/spp.js";

export type { BoundRoot } from "../rpc/registered-record.js";

/** The registry policy hash a statement binds, Rust `BoundPolicy`. */
export interface BoundPolicy {
  readonly ringProgramId: Address;
  readonly policyHash: Bytes32;
}

/** Rust `GetTrackingRecordPool`, the pool's canopy needs nodes no single opening's path holds. */
export type PolicyReadClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getStorageRecordPool"> &
  Pick<TrackingReader, "getTrackingRecordPool">;

/** The section's values read before the statement. */
export interface PolicyInputs {
  readonly circuit: TransferKeyCircuit;
  readonly withdrawals: readonly PolicyWithdrawal[];
  readonly splWithdrawalOwners: readonly Bytes32[];
  /** Zero rows off a policy. */
  readonly table: PolicyTableProofInputs;
  /** Zero off a policy, the gate of every rule. */
  readonly policyHash: Bytes32;
  /** Bound while thresholds are active. */
  readonly own?: BoundRoot;
  readonly curator?: BoundRoot;
  /** Absent is the unopened pool of a key whose queries are all off. */
  readonly ownPool?: RecordPool;
  readonly curatorPool?: RecordPool;
  /** At the key's owner rows, zero rows last. */
  readonly rows: readonly Bytes32[];
  readonly senderEntries: readonly PolicySubjectEntry[];
  /** The output slots then the withdrawals, the request pads them to the key. */
  readonly ownerEntries: readonly PolicySubjectEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
  readonly publicAssetEntries: readonly number[];
  /** Every rail reads it. */
  readonly trackingBound: BoundRoot;
  readonly tracking: TrackingProofInputs;
  /** The statement's proven bits, zero while thresholds are off. */
  readonly approvalMask: number;
}

/** What the request reads beside the section, Rust `PolicyProving`. */
export interface PolicyProving {
  readonly ringId: Bytes32;
  readonly publicSlots: PublicSlots;
}

export type PolicyReadInput = Readonly<{
  tokenOwnerHint?: Address;
  client: PolicyReadClient;
  ringProgramId: Address;
  config: RingPolicy;
  rail: RingRail;
  /** Clear on the hidden sender rail, its input 0 owner refuses a zero key. */
  publicOwners: boolean;
  circuit: TransferKeyCircuit;
  /** `ownerRows` at the key's rows. */
  rows: readonly Bytes32[];
  proofInputs: SppProofInputs;
  publicSlots: PublicSlots;
}>;

const ABSENT_ENTRY: PolicySubjectEntry = Object.freeze({ own: 0, curator: 0 });
/** A subject when nothing live opens a row, it brackets under the sentinel or holds its own leaf. */
const PADDING_SUBJECT = Uint8Array.from({ length: 32 }, (_, at) => (at === 31 ? 1 : 0)) as Bytes32;

/** Set on a ring with an own policy registry off the delegate rail, independent of `policy_hash`. */
export function thresholdsActive(config: Pick<RingPolicy, "records">, rail: RingRail): boolean {
  return !isDelegateRail(rail) && !equalBytes(addressBytes(config.records, "records"), ZERO_32);
}

/** The withdrawal rows a key must hold, the program reads none on a rail with no policy root. */
export function policyLegs(
  config: Pick<RingPolicy, "records" | "hasPolicy">,
  rail: RingRail,
  transfers: readonly Pick<SettlementTransfer, "isDeposit">[],
): number {
  return readsPolicyRoot(config, rail)
    ? transfers.filter((transfer) => !transfer.isDeposit).length
    : 0;
}

/** Rust `RootRead::transfer` is not `None`. */
function readsPolicyRoot(
  config: Pick<RingPolicy, "records" | "hasPolicy">,
  rail: RingRail,
): boolean {
  return !isDelegateRail(rail) && (config.hasPolicy || thresholdsActive(config, rail));
}

/** Every record the key opens, the rules admitted under a written policy, a delegate reads tracking alone. */
export async function readPolicy(
  input: PolicyReadInput,
  context?: RequestContext,
): Promise<PolicyInputs> {
  const { client, config, proofInputs, circuit, rail, ringProgramId } = input;
  const delegate = isDelegateRail(rail);
  const screening = config.hasPolicy && !delegate;
  // A private source reads through `-p` keys the TS catalog has not taken.
  if (screening && config.privateLists !== 0)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "RingShapeUnkeyed", rail, privateLists: config.privateLists },
    });
  const trackingSection = await readTracking(input, context);
  const base = {
    circuit,
    withdrawals: Object.freeze([]) as readonly PolicyWithdrawal[],
    splWithdrawalOwners: Object.freeze([]) as readonly Bytes32[],
    table: emptyTable(),
    policyHash: ZERO_32,
    rows: input.rows,
    senderEntries: Object.freeze(input.rows.map(() => ABSENT_ENTRY)),
    ownerEntries: Object.freeze([]) as readonly PolicySubjectEntry[],
    assetEntries: Object.freeze([]) as readonly PolicySubjectEntry[],
    publicAssetEntries: Object.freeze(Array.from({ length: N_PUBLIC_SLOTS }, () => 0)),
    ...trackingSection,
    approvalMask: 0,
  };
  if (!readsPolicyRoot(config, rail)) return Object.freeze(base);
  const read = await readPolicyWithdrawals(
    client,
    proofInputs.externalData.interfaceTransfers,
    input.tokenOwnerHint,
    context,
  );
  const pinned = screening ? pinnedPolicy(config) : undefined;
  const own = await fetchBoundRoot({ client, ringProgramId, registry: config.records }, context);
  const curatorRoot =
    pinned?.curator === undefined
      ? undefined
      : await fetchBoundRoot({ client, ringProgramId, registry: pinned.curator }, context);
  const { withdrawals } = read;
  const liveRows = input.rows.filter((row) => !isZero(row));
  const outputs = proofInputs.outputs;
  const owners = outputs.map((output) =>
    output.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  const assets = outputs.map((output) =>
    output.isDummy() ? undefined : memberOfAsset(output.asset),
  );
  const publicAssets = input.publicSlots.assets.filter((asset) => !isZero(asset));
  const capacity = transferPoolCapacity(circuit);
  // Owner subjects open only under a policy, a mint record serves the thresholds on every active ring.
  const curatorMembers = firstSeen(
    screening
      ? [
          ...liveRows,
          ...outputs.flatMap((_, slot) => [owners[slot], assets[slot]]),
          ...withdrawals.flatMap((leg) => [leg.owner, leg.asset]),
        ]
      : [...assets, ...withdrawals.map((leg) => leg.asset)],
  );
  const ownMembers = firstSeen([...curatorMembers, ...publicAssets]);
  const members = ownMembers.length === 0 ? [PADDING_SUBJECT] : ownMembers;
  const ownPool = await readRecordPool(
    { client, root: own, members, openings: capacity.own },
    context,
  );
  const curatorPool =
    curatorRoot === undefined
      ? undefined
      : await readRecordPool(
          {
            client,
            root: curatorRoot,
            members: curatorMembers.length === 0 ? [PADDING_SUBJECT] : curatorMembers,
            openings: capacity.curator,
          },
          context,
        );
  const ownReads = subjectReads(members, ownPool.reads);
  const curatorReads =
    curatorPool === undefined ? undefined : subjectReads(curatorMembers, curatorPool.reads);
  const subject = (pool: SubjectReads, member: Bytes32 | undefined): number =>
    member === undefined ? 0 : (pool.get(bytesKey(member))?.index ?? 0);
  // A curator query reads the subject at the same index, index 0 without a curator pool.
  const entry = (member: Bytes32 | undefined): PolicySubjectEntry => ({
    own: subject(ownReads, member),
    curator: curatorReads === undefined ? 0 : subject(curatorReads, member),
  });
  const lists = (member: Bytes32 | undefined): RecordLists =>
    member === undefined
      ? { own: 0n, curator: 0n }
      : Object.freeze({
          own: ownReads.get(bytesKey(member))?.read.record()?.lists ?? 0n,
          curator: curatorReads?.get(bytesKey(member))?.read.record()?.lists ?? 0n,
        });
  const policyOf = (asset: Bytes32): MintPolicy =>
    ownReads.get(bytesKey(asset))?.read.record()?.mintPolicy ?? EMPTY_MINT_POLICY;
  const spent = spentNotes(proofInputs);
  if (pinned !== undefined) {
    const live = outputs.flatMap((output, slot) => (output.isDummy() ? [] : [{ output, slot }]));
    const ringInputs = spent.filter((note) => note.ring);
    const payments = [
      ...live.map(({ output, slot }) => ({
        ring: output.ringProgramId !== undefined,
        owner: owners[slot] ?? ZERO_32,
        asset: memberOfAsset(output.asset),
        amount: output.amount,
        ownerLists: lists(owners[slot]),
        assetLists: lists(assets[slot]),
        mintPolicy: policyOf(memberOfAsset(output.asset)),
      })),
      ...withdrawals.map((leg) => ({
        ...leg,
        ring: false,
        ownerLists: lists(leg.owner),
        assetLists: lists(leg.asset),
        mintPolicy: policyOf(leg.asset),
      })),
    ];
    // A co-owner who receives nothing is screened, every row passes the sender rules.
    for (const sender of liveRows) {
      const refusal = admitTransfer(
        pinned.table,
        { slots: pinned.sources, private: pinned.privateSource },
        { sender: lists(sender), ringInputs, outputs: payments },
      );
      if (refusal !== undefined)
        throw ruleUnsatisfied(
          refusal,
          live.map(({ slot }) => slot),
        );
    }
  }
  return Object.freeze({
    ...base,
    withdrawals,
    splWithdrawalOwners: read.splWithdrawalOwners,
    ...(pinned === undefined
      ? {}
      : {
          table: policyTableProofInputs(pinned.table, {
            slots: pinned.sources,
            private: pinned.privateSource,
          }),
          policyHash: pinned.policyHash,
        }),
    own,
    ...(curatorRoot === undefined ? {} : { curator: curatorRoot }),
    ownPool: ownPool.pool,
    ...(curatorPool === undefined ? {} : { curatorPool: curatorPool.pool }),
    senderEntries: Object.freeze(
      input.rows.map((row) => (isZero(row) || !screening ? ABSENT_ENTRY : entry(row))),
    ),
    ownerEntries: Object.freeze([
      ...owners.map((owner) => (screening ? entry(owner) : ABSENT_ENTRY)),
      ...withdrawals.map((leg) => (screening ? entry(leg.owner) : ABSENT_ENTRY)),
    ]),
    assetEntries: Object.freeze([
      ...assets.map((asset) => entry(asset)),
      ...withdrawals.map((leg) => entry(leg.asset)),
    ]),
    publicAssetEntries: Object.freeze(
      input.publicSlots.assets.map((asset) => subject(ownReads, asset)),
    ),
    approvalMask: transferApprovalMask({
      rows: liveRows,
      proofInputs,
      publicSlots: input.publicSlots,
      policyOf,
    }),
  });
}

/** Opens every row and live ring output once under the newest root, refusing what the predicates refuse before proving. */
async function readTracking(
  input: PolicyReadInput,
  context: RequestContext | undefined,
): Promise<Pick<PolicyInputs, "trackingBound" | "tracking">> {
  const { client, config, circuit, proofInputs } = input;
  const trackingBound = await newestTrackingRoot(
    { client, trackingRegistry: config.tracking, ring: input.ringProgramId },
    context,
  );
  const liveRows = input.rows.filter((row) => !isZero(row));
  const ringOutputs = proofInputs.outputs.map((output) =>
    output.ringProgramId === undefined || output.ownerAddress === undefined ? undefined : output,
  );
  const outputOwners = ringOutputs.map((output) =>
    output?.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  const seen = firstSeen([...liveRows, ...outputOwners]);
  const members = seen.length === 0 ? [PADDING_SUBJECT] : seen;
  const openings = transferPoolCapacity(circuit).tracking;
  const served = await client.getTrackingRecordPool(
    { registry: config.tracking, members, expectedRoot: trackingBound.root, openings },
    context,
  );
  const pool = verifyTrackingPool({ pool: served, root: trackingBound.root, members, openings });
  const position = new Map(members.map((member, index) => [bytesKey(member), index]));
  const rowOf = (member: Bytes32): TrackingRecord | undefined =>
    pool.rows[position.get(bytesKey(member)) ?? -1];
  checkInputKeys({
    inputs: publishedNotes(proofInputs),
    rail: input.rail,
    publicOwners: input.publicOwners,
    rowOf,
  });
  checkOutputKeys(ringOutputs, rowOf);
  const entryOf = (member: Bytes32 | undefined): number =>
    member === undefined || isZero(member) ? 0 : (position.get(bytesKey(member)) ?? 0);
  return {
    trackingBound,
    tracking: Object.freeze({
      trackingRoot: trackingBound.root,
      trackingPool: Object.freeze({
        records: pool.records,
        canopy: pool.canopy,
        paths: pool.paths,
        subjects: pool.subjects,
      }),
      rowEntries: Object.freeze(input.rows.map(entryOf)),
      outputEntries: Object.freeze(outputOwners.map(entryOf)),
    }),
  };
}

/** Contract Output 4, a zero key waives only the key equality, a delegate moves it with no row and a hidden owner refuses it. */
export function checkInputKeys(
  input: Readonly<{
    inputs: readonly ProofInputUtxo[];
    rail: RingRail;
    publicOwners: boolean;
    rowOf: (member: Bytes32) => TrackingRecord | undefined;
  }>,
): void {
  const { inputs, rail, rowOf } = input;
  const hidden =
    rail === "anonymous" && !input.publicOwners
      ? inputs[0]?.utxo.owner.ownerProofInputHash()
      : undefined;
  for (const spent of inputs) {
    if (spent.isDummy()) continue;
    const owner = spent.utxo.owner.ownerProofInputHash();
    if (spent.utxo.ringProgramId === undefined) continue;
    if (equalBytes(spent.nullifierPublicKey, ZERO_NULLIFIER_PK)) {
      if (hidden !== undefined && equalBytes(owner, hidden))
        throw new RingError("RING_ZERO_KEY_INPUT_UNNAMED", {
          details: { owner: bytesKey(owner) },
        });
      continue;
    }
    const row = rowOf(owner);
    if (row === undefined)
      throw new RingError("RING_ADDRESS_NOT_ENROLLED", { details: { member: bytesKey(owner) } });
    if (!equalBytes(row.nullifierPk, spent.nullifierPublicKey))
      throw new RingError("RING_ADDRESS_MISMATCH", {
        details: { field: "nullifierPk", member: bytesKey(owner) },
      });
  }
}

/** Contract Output 3, a nonzero key needs its row, a zero key needs none under the frame's root. */
export function checkOutputKeys(
  outputs: readonly (ProofOutputUtxo | undefined)[],
  rowOf: (member: Bytes32) => TrackingRecord | undefined,
): void {
  for (const output of outputs) {
    const owner = output?.ownerAddress;
    if (owner === undefined) continue;
    const member = owner.signingPublicKey.ownerProofInputHash();
    const row = rowOf(member);
    if (equalBytes(owner.nullifierPublicKey, ZERO_NULLIFIER_PK)) {
      if (row !== undefined) throw new RingError("RING_RECIPIENT_ENROLLED");
      continue;
    }
    if (row === undefined) throw new RingError("RING_RECIPIENT_NOT_ENROLLED");
    if (!equalBytes(row.nullifierPk, owner.nullifierPublicKey))
      throw new RingError("RING_ADDRESS_MISMATCH", { details: { field: "nullifierPk" } });
  }
}

/** The roots the statement binds, zero where the program reads none, Rust `PolicyInputs::roots`. */
export function policyRoots(policy: PolicyInputs): TransferRoots {
  return Object.freeze({
    policyHash: policy.policyHash,
    ownRoot: policy.own?.root ?? ZERO_32,
    curatorRoot: policy.curator?.root ?? ZERO_32,
    trackingRoot: policy.tracking.trackingRoot,
    privateRoot: ZERO_32,
  });
}

export function screened(policy: PolicyInputs): boolean {
  return !isZero(policy.policyHash);
}

/** The section at the key's capacities, an unopened pool where no root is bound, Rust `PolicyInputs::params`. */
export function policyParams(policy: PolicyInputs, proving: PolicyProving): PolicyProofInputs {
  const capacity = transferPoolCapacity(policy.circuit);
  const withdrawalSlots = policy.circuit.withdrawals;
  const slots = policy.circuit.outputs + withdrawalSlots;
  const pad = <T>(values: readonly T[], length: number, zero: T): readonly T[] =>
    Object.freeze([...values, ...Array.from({ length: length - values.length }, () => zero)]);
  const roots = policyRoots(policy);
  return Object.freeze({
    withdrawalCount: policy.withdrawals.length,
    withdrawalHash: policyWithdrawalHash(policy.withdrawals),
    withdrawals: pad(policy.withdrawals, withdrawalSlots, {
      owner: ZERO_32,
      asset: ZERO_32,
      amount: 0n,
    }),
    policyHash: roots.policyHash,
    ringId: proving.ringId,
    ownRoot: roots.ownRoot,
    curatorRoot: roots.curatorRoot,
    privateRoot: roots.privateRoot,
    publicAssets: proving.publicSlots.assets,
    publicAmounts: publicAmountFields(proving.publicSlots),
    publicGross: publicGrossFields(proving.publicSlots),
    ...policy.table,
    ownPool: policy.ownPool ?? unopenedRecordPool(capacity.own),
    curatorPool: policy.curatorPool ?? unopenedRecordPool(capacity.curator),
    senderEntries: policy.senderEntries,
    ownerEntries: pad(policy.ownerEntries, slots, ABSENT_ENTRY),
    assetEntries: pad(policy.assetEntries, slots, ABSENT_ENTRY),
    publicAssetEntries: policy.publicAssetEntries,
  });
}

/** The proven mask, a nonzero cap refuses a larger `outflow`, no record reads no threshold. */
export function transferApprovalMask(
  input: Readonly<{
    rows: readonly Bytes32[];
    proofInputs: SppProofInputs;
    publicSlots: PublicSlots;
    policyOf: (asset: Bytes32) => MintPolicy;
  }>,
): number {
  const { proofInputs, publicSlots, policyOf } = input;
  const debitOutputs = slotOutputs(proofInputs);
  const publicGross = grossOf(publicSlots);
  const flows = ownerDebits({
    senders: input.rows,
    assets: [
      ...debitOutputs.map((output) => output.asset),
      ...publicGross.map((slot) => slot.asset),
      ...publicSlots.assets.filter((asset) => !isZero(asset)),
    ],
    inputs: spentNotes(proofInputs),
    outputs: debitOutputs,
    publicGross,
  });
  for (const flow of flows) {
    const { cap } = policyOf(flow.asset);
    if (cap !== 0n && flow.outflow > cap)
      throw new RingError("RING_OUTFLOW_CAP_EXCEEDED", {
        details: { cap: cap.toString(), outflow: flow.outflow.toString() },
      });
  }
  return approvalMask({ flows, publicGross, policyOf });
}

function grossOf(slots: PublicSlots): readonly PublicGross[] {
  return slots.assets.flatMap((asset, slot) => {
    const gross = slots.gross[slot] ?? 0n;
    return gross === 0n ? [] : [{ asset, gross }];
  });
}

/** The published input slots, compact padding left out. */
export function publishedNotes(proofInputs: SppProofInputs): readonly ProofInputUtxo[] {
  return proofInputs.inputUtxos.filter((input) => !input.isCompact());
}

/** Live notes, `ring` clear on a default-ring note, held for debit and no same-ring input. */
function spentNotes(proofInputs: SppProofInputs): readonly (DebitInput & { ring: boolean })[] {
  return publishedNotes(proofInputs)
    .filter((input) => !input.isDummy())
    .map((input) => ({
      owner: input.utxo.owner.ownerProofInputHash(),
      asset: assetField(input.utxo.asset),
      amount: input.utxo.amount,
      ring: input.utxo.ringProgramId !== undefined,
    }));
}

/** An exit carries no ring id, it counts as leaving. */
function slotOutputs(proofInputs: SppProofInputs): readonly DebitOutput[] {
  return proofInputs.outputs.flatMap((output) => {
    const owner = output.ownerAddress;
    return owner === undefined
      ? []
      : [
          {
            owner: owner.signingPublicKey.ownerProofInputHash(),
            asset: assetField(output.asset),
            amount: output.amount,
            ring: output.ringProgramId !== undefined,
          },
        ];
  });
}

/** The zero table, every gate reads it switched off. */
function emptyTable(): PolicyTableProofInputs {
  return Object.freeze({
    sources: Object.freeze(
      Array.from({ length: RING_SOURCE_SLOTS }, () =>
        Object.freeze({ listId: 0, registry: ZERO_32 }),
      ),
    ),
    source: NO_PRIVATE_SOURCE,
    policyLen: 0,
    rules: Object.freeze(Array.from({ length: RING_RULE_SLOTS }, () => ZERO_32)),
  });
}

/** The rule and the subject a refusal names, outputs by their SPP slot. */
function ruleUnsatisfied(refusal: RuleRefusal, live: readonly number[]): RingError {
  const { subject } = refusal;
  return new RingError("RING_POLICY_RULE_UNSATISFIED", {
    details:
      subject.kind === "sender"
        ? { reason: refusal.kind, ruleIndex: refusal.rule, subject: "sender" }
        : {
            reason: refusal.kind,
            ruleIndex: refusal.rule,
            subject: subject.kind,
            slotIndex: live[subject.output] ?? -1,
          },
  });
}

type SubjectReads = ReadonlyMap<string, Readonly<{ index: number; read: MemberOpeningRead }>>;

/** Every subject's pool index and verified read, keyed by member. */
function subjectReads(
  members: readonly Bytes32[],
  reads: readonly MemberOpeningRead[],
): SubjectReads {
  return new Map(
    members.flatMap((member, index) => {
      const read = reads[index];
      return read === undefined ? [] : [[bytesKey(member), { index, read }] as const];
    }),
  );
}

/** Distinct members in first-seen order, padding dropped. */
function firstSeen(members: readonly (Bytes32 | undefined)[]): readonly Bytes32[] {
  const unique = new Map<string, Bytes32>();
  for (const member of members)
    if (member !== undefined && !unique.has(bytesKey(member))) unique.set(bytesKey(member), member);
  return [...unique.values()];
}
