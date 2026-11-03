/**
 * The policy section of a ring transfer, every record read under a root the statement binds, Rust
 * `pipeline::policy`.
 */
import { EMPTY_MINT_POLICY } from "../protocol/membership/mint-policy.js";
import type { RecordPool } from "../protocol/membership/member-registry.js";
import {
  readPolicyWithdrawals,
  policyWithdrawalHash,
  type PolicyWithdrawal,
} from "./withdrawals.js";
import { thresholdsCover, waivesCoSigner } from "./withdrawal-exemption.js";
import { ZERO_32, addressBytes, bytesKey, equalBytes, isZero } from "@heliuslabs/zolana/internal";
import { type RingRecordReader } from "../rpc/ports.js";
import type { ChainReader } from "@heliuslabs/zolana/client";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import { assetField, type SppProofInputs } from "@heliuslabs/zolana/transaction";
import type {
  PolicyProofInputs,
  PolicySubjectEntry,
  PolicyTableProofInputs,
} from "../rpc/prover/ring.js";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "../rpc/prover/types.js";

import type { RingPolicy } from "../protocol/codec/ring-codecs.js";
import { RingError } from "../protocol/error.js";
import {
  ownerEscrowed,
  unopenedRecordPool,
  type MemberOpeningRead,
} from "../protocol/membership/member-opening.js";
import {
  admitTransfer,
  memberOfAsset,
  pinnedPolicy,
  policyTableProofInputs,
  type OutflowLimit,
  type RecordLists,
  type RuleRefusal,
} from "../protocol/membership/policy.js";
import { fetchBoundRoot, readRecordPool, type BoundRoot } from "../rpc/registered-record.js";
import type { TransferRoots } from "../protocol/proof/statement.js";
import {
  ringTransferCircuit,
  transferPoolCapacity,
  type TransferKeyCircuit,
} from "../protocol/proof/transfer-shapes.js";
import { publishesRecipients, type RingRail } from "../protocol/transaction/transact.js";
import {
  N_PUBLIC_SLOTS,
  publicAmountFields,
  publicGrossFields,
  type PublicSlots,
} from "../protocol/transaction/spp.js";
import type { CoSignDemand } from "./cosign.js";

export type { BoundRoot } from "../rpc/registered-record.js";

/** The registry policy hash a statement binds, Rust `BoundPolicy`. */
export interface BoundPolicy {
  readonly ringProgramId: Address;
  readonly policyHash: Bytes32;
}

export type PolicyReadClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getStorageMemberOpenings" | "getStorageRecordPool">;

/** The section's values read before the statement, Rust `PolicyInputs`. */
export interface PolicyInputs {
  readonly circuit: TransferKeyCircuit;
  readonly withdrawals: readonly PolicyWithdrawal[];
  readonly splWithdrawalOwners: readonly Bytes32[];
  /** Zero rows off a policy. */
  readonly table: PolicyTableProofInputs;
  /** Zero off a policy, the gate of every rule. */
  readonly policyHash: Bytes32;
  /** Bound under a policy or an exemption. */
  readonly own?: BoundRoot;
  readonly curator?: BoundRoot;
  /** Absent is the unopened pool of a key whose queries are all off. */
  readonly ownPool?: RecordPool;
  readonly curatorPool?: RecordPool;
  readonly senderEntry: PolicySubjectEntry;
  /** The live outputs then the withdrawals, the request pads them to the key. */
  readonly ownerEntries: readonly PolicySubjectEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
  readonly publicAssetEntries: readonly number[];
  /** One per output slot, zero without key escrow. */
  readonly ctHashes: readonly Bytes32[];
  /** One per output slot, zero on a dummy, off a policy and on the anonymous rail. */
  readonly recipients: readonly Bytes32[];
  readonly approvalRequired: boolean;
  readonly keyEscrow: boolean;
  readonly exempt: boolean;
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
  proofInputs: SppProofInputs;
  /** The spent notes, every input but the compact ones. */
  publishedInputs: number;
  spendsDefaultRing: boolean;
  /** The owner identity the rules read as the sender. */
  sender: Bytes32;
  publicSlots: PublicSlots;
}>;

const ABSENT_ENTRY: PolicySubjectEntry = Object.freeze({ own: 0, curator: 0 });

/** The key and its section, screened under a written policy alone, Rust `PolicyRead::read`. */
export async function readPolicy(
  input: PolicyReadInput,
  context?: RequestContext,
): Promise<PolicyInputs> {
  const { client, config, proofInputs } = input;
  const outputs = proofInputs.outputs.length;
  const { withdrawals, splWithdrawalOwners } = config.hasPolicy
    ? await readPolicyWithdrawals(
        client,
        proofInputs.externalData.interfaceTransfers,
        input.tokenOwnerHint,
        context,
      )
    : { withdrawals: [], splWithdrawalOwners: [] };
  const circuit = ringTransferCircuit({
    rail: input.rail,
    inputs: input.publishedInputs,
    outputs,
    spendsDefaultRing: input.spendsDefaultRing,
    legs: withdrawals.length,
  });
  if (circuit === undefined)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "RingShapeUnkeyed", rail: input.rail },
    });
  const unscreened: PolicyInputs = Object.freeze({
    circuit,
    withdrawals,
    splWithdrawalOwners,
    table: emptyTable(),
    policyHash: ZERO_32,
    senderEntry: ABSENT_ENTRY,
    ownerEntries: Object.freeze([]),
    assetEntries: Object.freeze([]),
    publicAssetEntries: Object.freeze(Array.from({ length: N_PUBLIC_SLOTS }, () => 0)),
    ctHashes: Object.freeze(Array.from({ length: outputs }, zeroField)),
    recipients: Object.freeze(Array.from({ length: outputs }, zeroField)),
    approvalRequired: false,
    keyEscrow: config.keyEscrow,
    exempt: false,
  });
  return config.hasPolicy ? screen(input, unscreened, context) : unscreened;
}

/** Opens every subject once under the bound roots and admits the transfer under the rules. */
async function screen(
  input: PolicyReadInput,
  inputs: PolicyInputs,
  context: RequestContext | undefined,
): Promise<PolicyInputs> {
  const { client, ringProgramId, proofInputs, config: policy } = input;
  const pinned = pinnedPolicy(policy);
  const own = await fetchBoundRoot({ client, ringProgramId, registry: policy.records }, context);
  const curatorRoot =
    pinned.curator === undefined
      ? undefined
      : await fetchBoundRoot({ client, ringProgramId, registry: pinned.curator }, context);
  const { withdrawals } = inputs;
  const outputs = proofInputs.outputs;
  const owners = outputs.map((output) =>
    output.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  const assets = outputs.map((output) =>
    !output.isDummy() ? memberOfAsset(output.asset) : undefined,
  );
  const publicAssets = input.publicSlots.assets.filter((asset) => !equalBytes(asset, ZERO_32));
  const capacity = transferPoolCapacity(inputs.circuit);
  // Rust builds the same subject order, public assets resolve in the own pool alone.
  const curatorMembers = firstSeen([
    input.sender,
    ...outputs.flatMap((_, slotIndex) => [owners[slotIndex], assets[slotIndex]]),
    ...withdrawals.flatMap((w) => [w.owner, w.asset]),
  ]);
  const ownMembers = firstSeen([...curatorMembers, ...publicAssets]);
  const ownPool = await readRecordPool(
    { client, root: own, members: ownMembers, openings: capacity.own },
    context,
  );
  const curatorPool =
    curatorRoot === undefined
      ? undefined
      : await readRecordPool(
          { client, root: curatorRoot, members: curatorMembers, openings: capacity.curator },
          context,
        );
  const ownReads = subjectReads(ownMembers, ownPool.reads);
  const curatorReads =
    curatorPool === undefined ? undefined : subjectReads(curatorMembers, curatorPool.reads);
  const reads = (member: Bytes32 | undefined) =>
    member === undefined
      ? { own: undefined, curator: undefined }
      : {
          own: ownReads.get(bytesKey(member))?.read,
          curator: curatorReads?.get(bytesKey(member))?.read,
        };
  const subject = (pool: SubjectReads, member: Bytes32 | undefined): number =>
    member === undefined ? 0 : (pool.get(bytesKey(member))?.index ?? 0);
  // A curator query reads the subject at the same index, index 0 without a curator pool.
  const entry = (member: Bytes32 | undefined): PolicySubjectEntry => ({
    own: subject(ownReads, member),
    curator: curatorReads === undefined ? 0 : subject(curatorReads, member),
  });
  const lists = (member: Bytes32 | undefined): RecordLists => {
    const { own: ownRead, curator } = reads(member);
    return Object.freeze({
      own: ownRead?.record()?.lists ?? 0n,
      curator: curator?.record()?.lists ?? 0n,
    });
  };
  const mintPolicy = (asset: Bytes32 | undefined) =>
    reads(asset).own?.record()?.mintPolicy ?? EMPTY_MINT_POLICY;
  const live = outputs.flatMap((output, slotIndex) =>
    output.isDummy() ? [] : [{ output, slotIndex }],
  );
  const refusal = admitTransfer(pinned.table, pinned.sources, {
    sender: lists(input.sender),
    outputs: [
      ...live.map(({ output, slotIndex }) => ({
        owner: owners[slotIndex] ?? ZERO_32,
        asset: memberOfAsset(output.asset),
        amount: output.amount,
        ownerLists: lists(owners[slotIndex]),
        assetLists: lists(assets[slotIndex]),
        mintPolicy: mintPolicy(assets[slotIndex]),
      })),
      ...withdrawals.map((w) => ({
        ...w,
        ownerLists: lists(w.owner),
        assetLists: lists(w.asset),
        mintPolicy: mintPolicy(w.asset),
      })),
    ],
  });
  if (refusal !== undefined)
    throw ruleUnsatisfied(
      refusal,
      live.map(({ slotIndex }) => slotIndex),
    );
  const ctHashes = outputs.map((output, slotIndex) => {
    const owner = owners[slotIndex];
    const address = output.ownerAddress;
    if (!inputs.keyEscrow || owner === undefined || address === undefined) return zeroField();
    return ownerEscrowed(owner, reads(owner).own, address.nullifierPublicKey).ctHash;
  });
  const approvalRequired =
    input.rail === "delegate"
      ? false
      : outflowApproval({
          sender: input.sender,
          ringProgramId,
          proofInputs,
          publicSlots: input.publicSlots,
          limits: uniqueMembers([...assets, ...publicAssets]).flatMap((asset) => {
            const mint = mintPolicy(asset);
            return mint.cap === 0n && mint.cosignAbove === 0n
              ? []
              : [
                  {
                    asset: asset as OutflowLimit["asset"],
                    cap: mint.cap,
                    cosignAbove: mint.cosignAbove,
                  },
                ];
          }),
        });
  return Object.freeze({
    ...inputs,
    table: policyTableProofInputs(pinned.table, pinned.sources),
    policyHash: pinned.policyHash,
    own,
    ...(curatorRoot === undefined ? {} : { curator: curatorRoot }),
    ownPool: ownPool.pool,
    ...(curatorPool === undefined ? {} : { curatorPool: curatorPool.pool }),
    senderEntry: entry(input.sender),
    ownerEntries: Object.freeze([
      ...owners.map((owner) => entry(owner)),
      ...withdrawals.map((w) => entry(w.owner)),
    ]),
    assetEntries: Object.freeze([
      ...assets.map((asset) => entry(asset)),
      ...withdrawals.map((w) => entry(w.asset)),
    ]),
    publicAssetEntries: Object.freeze(
      input.publicSlots.assets.map((asset) => subject(ownReads, asset)),
    ),
    ctHashes: Object.freeze(ctHashes),
    recipients: Object.freeze(
      owners.map((owner) =>
        publishesRecipients(input.rail) && owner !== undefined ? owner : zeroField(),
      ),
    ),
    approvalRequired,
  });
}

/**
 * Sets the exempt bit when the waiver removes the co-signer and every withdrawn mint's threshold
 * covers its gross, an audit-only ring opens its own pool for the public assets, Rust
 * `PolicyInputs::exempt_withdrawals`.
 */
export async function exemptWithdrawals(
  policy: PolicyInputs,
  input: Readonly<{
    client: PolicyReadClient;
    ringProgramId: Address;
    config: RingPolicy;
    demand: CoSignDemand;
    publicSlots: PublicSlots;
  }>,
  context?: RequestContext,
): Promise<PolicyInputs> {
  const { config, demand } = input;
  if (
    !waivesCoSigner({
      ringProgramId: input.ringProgramId,
      config,
      demand,
      approvalRequired: policy.approvalRequired,
    })
  )
    return policy;
  const { assets, gross } = input.publicSlots;
  if (policy.ownPool !== undefined)
    return thresholdsCover(policy.ownPool, assets, gross)
      ? Object.freeze({ ...policy, exempt: true })
      : policy;
  if (equalBytes(addressBytes(config.records, "records"), ZERO_32)) return policy;
  const own = await fetchBoundRoot(
    { client: input.client, ringProgramId: input.ringProgramId, registry: config.records },
    context,
  );
  const members = assets.filter((asset) => !equalBytes(asset, ZERO_32));
  const { pool } = await readRecordPool(
    {
      client: input.client,
      root: own,
      members,
      openings: transferPoolCapacity(policy.circuit).own,
    },
    context,
  );
  if (!thresholdsCover(pool, assets, gross)) return policy;
  return Object.freeze({
    ...policy,
    own,
    ownPool: pool,
    exempt: true,
    publicAssetEntries: Object.freeze(
      assets.map((asset) =>
        Math.max(
          0,
          members.findIndex((member) => equalBytes(member, asset)),
        ),
      ),
    ),
  });
}

export function screened(policy: PolicyInputs): boolean {
  return !isZero(policy.policyHash);
}

/** The roots the statement binds, zero where the program reads none, Rust `PolicyInputs::roots`. */
export function policyRoots(policy: PolicyInputs): TransferRoots {
  return Object.freeze({
    policyHash: policy.policyHash,
    ownRoot: policy.own?.root ?? zeroField(),
    curatorRoot: policy.curator?.root ?? zeroField(),
  });
}

/** The section at the key's capacities, an unopened pool where no root is bound, Rust `PolicyInputs::params`. */
export function policyParams(policy: PolicyInputs, proving: PolicyProving): PolicyProofInputs {
  const capacity = transferPoolCapacity(policy.circuit);
  const withdrawalSlots = policy.circuit.withdrawals;
  const slots = policy.recipients.length + withdrawalSlots;
  const pad = <T>(values: readonly T[], length: number, zero: T): readonly T[] =>
    Object.freeze([...values, ...Array.from({ length: length - values.length }, () => zero)]);
  const roots = policyRoots(policy);
  return Object.freeze({
    withdrawalCount: policy.withdrawals.length,
    withdrawalHash: policyWithdrawalHash(policy.withdrawals),
    withdrawals: pad(policy.withdrawals, withdrawalSlots, {
      owner: zeroField(),
      asset: zeroField(),
      amount: 0n,
    }),
    policyHash: roots.policyHash,
    ringId: proving.ringId,
    ownRoot: roots.ownRoot,
    curatorRoot: roots.curatorRoot,
    publicAssets: proving.publicSlots.assets,
    publicAmounts: publicAmountFields(proving.publicSlots),
    publicGross: publicGrossFields(proving.publicSlots),
    ...policy.table,
    ctHashes: policy.ctHashes,
    recipients: policy.recipients,
    ownPool: policy.ownPool ?? unopenedRecordPool(capacity.own),
    curatorPool: policy.curatorPool ?? unopenedRecordPool(capacity.curator),
    senderEntry: policy.senderEntry,
    ownerEntries: pad(policy.ownerEntries, slots, ABSENT_ENTRY),
    assetEntries: pad(policy.assetEntries, slots, ABSENT_ENTRY),
    publicAssetEntries: policy.publicAssetEntries,
  });
}

/**
 * Rust `Outflows::approval_required`. Every UTXO output but the sender's change inside the ring
 * leaves it, less the asset's public net, a nonzero cap refuses more and a nonzero co-sign bound sets
 * the approval bit.
 */
export function outflowApproval(
  input: Readonly<{
    sender: Bytes32;
    ringProgramId: Address;
    proofInputs: SppProofInputs;
    publicSlots: PublicSlots;
    limits: readonly OutflowLimit[];
  }>,
): boolean {
  let approval = false;
  for (const limit of input.limits) {
    const outflow = assetOutflow(input, limit.asset);
    const over = (bound: bigint): boolean => bound !== 0n && outflow > bound;
    if (over(limit.cap))
      throw new RingError("RING_OUTFLOW_CAP_EXCEEDED", {
        details: { cap: limit.cap.toString(), outflow: outflow.toString() },
      });
    approval ||= over(limit.cosignAbove);
  }
  return approval;
}

function assetOutflow(
  input: Readonly<{
    sender: Bytes32;
    ringProgramId: Address;
    proofInputs: SppProofInputs;
    publicSlots: PublicSlots;
  }>,
  asset: Bytes32,
): bigint {
  let others = 0n;
  for (const output of input.proofInputs.outputs) {
    const owner = output.ownerAddress;
    if (owner === undefined) continue;
    const change =
      equalBytes(owner.signingPublicKey.ownerProofInputHash(), input.sender) &&
      output.ringProgramId === input.ringProgramId;
    if (!change && equalBytes(assetField(output.asset), asset)) others += output.amount;
  }
  const net = input.publicSlots.assets.reduce(
    (sum, publicAsset, index) =>
      equalBytes(publicAsset, asset) ? sum + (input.publicSlots.nets[index] ?? 0n) : sum,
    0n,
  );
  if (net > others) throw new RingError("RING_DEPOSIT_ABOVE_OUTFLOW");
  return others - net;
}

/** The zero table, every gate reads it switched off. */
function emptyTable(): PolicyTableProofInputs {
  return Object.freeze({
    sources: Object.freeze(
      Array.from({ length: RING_SOURCE_SLOTS }, () =>
        Object.freeze({ listId: 0, registry: ZERO_32 }),
      ),
    ),
    policyLen: 0,
    rules: Object.freeze(Array.from({ length: RING_RULE_SLOTS }, () => ZERO_32)),
  });
}

/** The rule and the subject a refusal names, outputs by their SPP slot. */
function ruleUnsatisfied(refusal: RuleRefusal, live: readonly number[]): RingError {
  const slot = (output: number): number => live[output] ?? -1;
  return new RingError("RING_POLICY_RULE_UNSATISFIED", {
    details:
      refusal.kind !== "lists"
        ? { reason: refusal.kind, ruleIndex: refusal.rule, slotIndex: slot(refusal.output) }
        : refusal.subject.kind === "sender"
          ? { reason: refusal.kind, ruleIndex: refusal.rule, subject: "sender" }
          : {
              reason: refusal.kind,
              ruleIndex: refusal.rule,
              subject: refusal.subject.kind,
              slotIndex: slot(refusal.subject.output),
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

/** Sorted by bytes like Rust's `BTreeSet`, padding and duplicates dropped. */
function uniqueMembers(members: readonly (Bytes32 | undefined)[]): readonly Bytes32[] {
  const unique = new Map<string, Bytes32>();
  for (const member of members) if (member !== undefined) unique.set(bytesKey(member), member);
  return [...unique.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([, member]) => member);
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}
