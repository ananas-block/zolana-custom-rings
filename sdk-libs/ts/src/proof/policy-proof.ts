/** The policy section of a ring transfer, every record read under a root the statement binds. */
import type { ShieldedPublicKey } from "@heliuslabs/zolana/keypair";
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
import { type RingRecordReader } from "../rpc/ports.js";
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
  PolicyOwnerEntry,
  PolicyProofInputs,
  PolicySubjectEntry,
  PolicyTableProofInputs,
  CredentialProofInputs,
} from "../rpc/prover/ring.js";
import { RING_RULE_SLOTS, RING_SOURCE_SLOTS } from "../rpc/prover/types.js";

import type { RingPolicy } from "../protocol/codec/ring-codecs.js";
import { RingError } from "../protocol/error.js";
import { InputClass } from "../protocol/codec/audit-stream.js";
import { inputClassOf } from "./audit-proof.js";
import {
  unopenedRecordPool,
  type MemberOpeningRead,
} from "../protocol/membership/member-opening.js";
import { ApprovalTotals } from "../protocol/membership/approval-totals.js";
import {
  approvalMask,
  ownerDebits,
  type DebitInput,
  type DebitOutput,
  type PublicGross,
} from "../protocol/membership/owner-debits.js";
import { listTagOf } from "../crypto/keys/list-salt.js";
import { privateListKey } from "../protocol/membership/private-list.js";
import {
  evaluateInputAssets,
  evaluatePayments,
  evaluateSenders,
  memberOfAsset,
  pinnedPolicy,
  policySourceView,
  policyTableProofInputs,
  type PinnedPolicy,
  type RecordLists,
  type RuleRefusal,
  type SourceView,
} from "../protocol/membership/policy.js";
import { fetchBoundRoot, readRecordPool, type BoundRoot } from "../rpc/registered-record.js";
import { fetchStorageRegistry } from "../protocol/membership/config.js";
import type { AuditCredential } from "../protocol/membership/credential.js";
import type { CredentialClient } from "../rpc/credential-resolver.js";
import {
  credentialSubject,
  readCredentials,
  type CredentialSection,
  type CredentialSubject,
} from "./credential-proof.js";
import type { TransferRoots } from "../protocol/proof/statement.js";
import {
  depositKeyCapacity,
  depositPoolWidth,
  transferPoolCapacity,
  type PolicyPoolCapacity,
  type TransferKeyCircuit,
} from "../protocol/proof/transfer-shapes.js";
import { isDelegateRail, type RingRail } from "../protocol/transaction/transact.js";
import {
  publicAmountFields,
  publicGrossFields,
  publicSlots,
  N_PUBLIC_SLOTS,
  type PublicSlots,
} from "../protocol/transaction/spp.js";

export type { BoundRoot } from "../rpc/registered-record.js";

/** The registry policy hash a statement binds, Rust `BoundPolicy`. */
export interface BoundPolicy {
  readonly ringProgramId: Address;
  readonly policyHash: Bytes32;
}

/** Policy records come from the ring indexer, credentials from Photon and the SPP trees. */
export type PolicyReadClient = Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getStorageRecordPool"> &
  CredentialClient;

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
  readonly senderEntries: readonly PolicyOwnerEntry[];
  /** The output slots then the withdrawals, the request pads them to the key. */
  readonly ownerEntries: readonly PolicyOwnerEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
  /** One per published input slot, the request pads them to the key's input class past the payments. */
  readonly inputAssetEntries: readonly PolicySubjectEntry[];
  readonly publicAssetEntries: readonly number[];
  /** Every rail reads it. */
  readonly credentials: CredentialSection;
  /** The statement's proven bits, zero while thresholds are off. */
  readonly approvalMask: number;
}

/** What the request reads beside the section, Rust `PolicyProving`. */
export interface PolicyProving {
  readonly ringId: Bytes32;
  readonly publicSlots: PublicSlots;
}

/** From the owner's `RingAddress` or `RingKeys.listSalt`. */
export interface RingListSalt {
  readonly owner: Bytes32;
  readonly salt: Bytes32;
}

/** Read before any record opens. */
export interface PolicyDemand {
  readonly withdrawals: readonly PolicyWithdrawal[];
  readonly splWithdrawalOwners: readonly Bytes32[];
  /** Taken at every subject's own record, a salted owner counts its key. */
  readonly pools: PolicyPoolCapacity;
}

export type PolicyDemandInput = Readonly<{
  tokenOwnerHint?: Address;
  client: PolicyReadClient;
  config: RingPolicy;
  rail: RingRail;
  /** Live and padded rows alike, a zero row opens nothing. */
  rows: readonly Bytes32[];
  proofInputs: SppProofInputs;
  publicSlots: PublicSlots;
  listSalts: readonly RingListSalt[];
}>;

export type PolicyReadInput = PolicyDemandInput &
  Readonly<{
    ringProgramId: Address;
    /** Clear on the hidden sender rail, its input 0 owner refuses a zero key. */
    publicOwners: boolean;
    circuit: TransferKeyCircuit;
    demand: PolicyDemand;
  }>;

const ABSENT_ENTRY: PolicySubjectEntry = Object.freeze({ own: 0, curator: 0 });
const ABSENT_OWNER: PolicyOwnerEntry = Object.freeze({
  ...ABSENT_ENTRY,
  credential: 0,
  listSalt: ZERO_32,
  ownSalted: 0,
  curatorSalted: 0,
});
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
export function readsPolicyRoot(
  config: Pick<RingPolicy, "records" | "hasPolicy">,
  rail: RingRail,
): boolean {
  return !isDelegateRail(rail) && (config.hasPolicy || thresholdsActive(config, rail));
}

interface PolicySubjects {
  readonly pinned?: PinnedPolicy;
  readonly view?: SourceView;
  readonly liveRows: readonly Bytes32[];
  /** By output slot, undefined on a dummy. */
  readonly owners: readonly (Bytes32 | undefined)[];
  readonly assets: readonly (Bytes32 | undefined)[];
  /** By published input slot, undefined on a dummy or an address slot and off a policy. */
  readonly inputAssets: readonly (Bytes32 | undefined)[];
  /** Screened owners, empty off a policy. */
  readonly ownerMembers: readonly Bytes32[];
  readonly assetMembers: readonly Bytes32[];
  readonly publicAssets: readonly Bytes32[];
  /** Live rows and ring output owners, any other owner only under a salted list, Go `resolveOwner`. */
  readonly credentialMembers: readonly Bytes32[];
  /** Every owner key the transfer names, by member. */
  readonly subjectOf: ReadonlyMap<string, CredentialSubject>;
}

function policySubjects(
  input: PolicyDemandInput,
  withdrawals: readonly PolicyWithdrawal[],
): PolicySubjects {
  const { config, rail, proofInputs } = input;
  const pinned = config.hasPolicy && !isDelegateRail(rail) ? pinnedPolicy(config) : undefined;
  const view = pinned === undefined ? undefined : policySourceView(pinned.sources);
  const liveRows = input.rows.filter((row) => !isZero(row));
  const { outputs } = proofInputs;
  const owners = outputs.map((output) =>
    output.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  const assets = outputs.map((output) =>
    output.isDummy() ? undefined : memberOfAsset(output.asset),
  );
  // Only the rules read an input's asset, so the thresholds alone open none.
  const inputAssets = publishedNotes(proofInputs).map((spent) =>
    pinned === undefined || inputClassOf(spent) !== InputClass.note
      ? undefined
      : memberOfAsset(spent.utxo.asset),
  );
  const ownerMembers =
    pinned === undefined
      ? []
      : firstSeen([...liveRows, ...owners, ...withdrawals.map((leg) => leg.owner)]);
  const ringOwners = outputs.map((output) =>
    output.ringProgramId === undefined
      ? undefined
      : output.ownerAddress?.signingPublicKey.ownerProofInputHash(),
  );
  return {
    ...(pinned === undefined ? {} : { pinned }),
    ...(view === undefined ? {} : { view }),
    liveRows,
    owners,
    assets,
    inputAssets,
    ownerMembers,
    assetMembers: firstSeen([...assets, ...withdrawals.map((leg) => leg.asset), ...inputAssets]),
    publicAssets: input.publicSlots.assets.filter((asset) => !isZero(asset)),
    credentialMembers: firstSeen([
      ...liveRows,
      ...ringOwners,
      ...(view !== undefined && view.salted !== 0 ? ownerMembers : []),
    ]),
    subjectOf: new Map(
      [
        ...publishedNotes(proofInputs).map((spent) => credentialSubject(spent.utxo.owner)),
        ...outputs.flatMap((output) =>
          output.ownerAddress === undefined
            ? []
            : [credentialSubject(output.ownerAddress.signingPublicKey)],
        ),
        ...withdrawals.map((leg) => ({ member: leg.owner, owner: leg.holder })),
      ].map((subject) => [bytesKey(subject.member), subject] as const),
    ),
  };
}

/** The members each pool opens, Go `resolveSubjects`. */
function poolMembers(
  subjects: PolicySubjects,
  saltedKeys: readonly Bytes32[],
): Readonly<{ own: readonly Bytes32[]; curator: readonly Bytes32[] }> {
  const { view, ownerMembers, assetMembers, publicAssets, pinned } = subjects;
  return {
    own: firstSeen([
      ...ownerMembers,
      ...assetMembers,
      ...publicAssets,
      ...(view?.saltedOwn === true ? saltedKeys : []),
    ]),
    curator:
      pinned?.curator === undefined
        ? []
        : firstSeen([
            ...(view?.publicForeign === true ? ownerMembers : []),
            ...assetMembers,
            ...(view?.saltedCurated === true ? saltedKeys : []),
          ]),
  };
}

/** A ring reading no salted list discloses no salt to a relay. */
export function relayListSalts(
  config: RingPolicy,
  salts: readonly RingListSalt[],
): readonly RingListSalt[] {
  if (!config.hasPolicy) return [];
  return policySourceView(pinnedPolicy(config).sources).salted === 0 ? [] : salts;
}

function saltsByOwner(salts: readonly RingListSalt[]): ReadonlyMap<string, Bytes32> {
  return new Map(salts.map(({ owner, salt }) => [bytesKey(owner), salt]));
}

/** The withdrawals and the pools a key must hold, a salted read takes a row beside the public one. */
export async function policyDemand(
  input: PolicyDemandInput,
  context?: RequestContext,
): Promise<PolicyDemand> {
  const { client, config, rail, proofInputs } = input;
  const read = readsPolicyRoot(config, rail)
    ? await readPolicyWithdrawals(
        client,
        proofInputs.externalData.interfaceTransfers,
        input.tokenOwnerHint,
        context,
      )
    : { withdrawals: [], splWithdrawalOwners: [] };
  const subjects = policySubjects(input, read.withdrawals);
  const salts = saltsByOwner(input.listSalts);
  const saltedKeys =
    subjects.view === undefined || subjects.view.salted === 0
      ? []
      : subjects.ownerMembers.flatMap((member) => {
          const salt = salts.get(bytesKey(member));
          return salt === undefined ? [] : [privateListKey(member, salt)];
        });
  const members = poolMembers(subjects, saltedKeys);
  return Object.freeze({
    withdrawals: read.withdrawals,
    splWithdrawalOwners: read.splWithdrawalOwners,
    pools: Object.freeze({
      own: members.own.length,
      curator: members.curator.length,
      credentials: subjects.credentialMembers.length,
    }),
  });
}

/** Every record the key opens, the rules admitted under a written policy, a delegate reads credentials alone. */
export async function readPolicy(
  input: PolicyReadInput,
  context?: RequestContext,
): Promise<PolicyInputs> {
  const { client, config, proofInputs, circuit, rail, ringProgramId, demand } = input;
  const { withdrawals } = demand;
  const subjects = policySubjects(input, withdrawals);
  const { pinned, view, liveRows, owners, assets, inputAssets } = subjects;
  const screening = pinned !== undefined;
  const { credentials, rowOf, credentialEntry } = await readOwnerCredentials(
    input,
    subjects,
    context,
  );
  const base = {
    circuit,
    withdrawals: Object.freeze([]) as readonly PolicyWithdrawal[],
    splWithdrawalOwners: Object.freeze([]) as readonly Bytes32[],
    table: emptyTable(),
    policyHash: ZERO_32,
    rows: input.rows,
    senderEntries: Object.freeze(input.rows.map(() => ABSENT_OWNER)),
    ownerEntries: Object.freeze([]) as readonly PolicyOwnerEntry[],
    assetEntries: Object.freeze([]) as readonly PolicySubjectEntry[],
    inputAssetEntries: Object.freeze([]) as readonly PolicySubjectEntry[],
    publicAssetEntries: Object.freeze(Array.from({ length: N_PUBLIC_SLOTS }, () => 0)),
    credentials,
    approvalMask: 0,
  };
  if (!readsPolicyRoot(config, rail)) return Object.freeze(base);
  const own = await fetchBoundRoot({ client, ringProgramId, registry: config.records }, context);
  const curatorRoot =
    pinned?.curator === undefined
      ? undefined
      : await fetchBoundRoot({ client, ringProgramId, registry: pinned.curator }, context);
  const salts = saltsByOwner(input.listSalts);
  const anySalted = view !== undefined && view.salted !== 0;
  const saltOf = new Map(
    (anySalted ? subjects.ownerMembers : []).flatMap((member) => {
      const salt = enrolledSalt(member, rowOf(member), salts);
      return salt === undefined ? [] : [[bytesKey(member), salt] as const];
    }),
  );
  const keyOf = new Map(
    [...saltOf].map(([owner, salt]) => {
      const member = subjects.ownerMembers.find((candidate) => bytesKey(candidate) === owner);
      return [owner, privateListKey(member as Bytes32, salt)] as const;
    }),
  );
  const members = poolMembers(subjects, [...keyOf.values()]);
  const capacity = transferPoolCapacity(circuit);
  const ownMembers = members.own.length === 0 ? [PADDING_SUBJECT] : members.own;
  const ownPool = await readRecordPool(
    { client, root: own, members: ownMembers, openings: capacity.own },
    context,
  );
  const curatorPool =
    curatorRoot === undefined
      ? undefined
      : await readRecordPool(
          {
            client,
            root: curatorRoot,
            members: members.curator.length === 0 ? [PADDING_SUBJECT] : members.curator,
            openings: capacity.curator,
          },
          context,
        );
  const ownReads = subjectReads(ownMembers, ownPool.reads);
  const curatorReads =
    curatorPool === undefined ? undefined : subjectReads(members.curator, curatorPool.reads);
  const subject = (pool: SubjectReads, member: Bytes32 | undefined): number =>
    member === undefined ? 0 : (pool.get(bytesKey(member))?.index ?? 0);
  // A curator query reads the subject at the same index, index 0 without a curator pool.
  const entry = (member: Bytes32 | undefined): PolicySubjectEntry => ({
    own: subject(ownReads, member),
    curator: curatorReads === undefined ? 0 : subject(curatorReads, member),
  });
  const ownerEntry = (member: Bytes32 | undefined): PolicyOwnerEntry => {
    if (member === undefined || !screening) return ABSENT_OWNER;
    const key = keyOf.get(bytesKey(member));
    return {
      ...entry(member),
      credential: credentialEntry(member),
      listSalt: saltOf.get(bytesKey(member)) ?? ZERO_32,
      ownSalted: subject(ownReads, key),
      curatorSalted: curatorReads === undefined ? 0 : subject(curatorReads, key),
    };
  };
  const recordLists = (member: Bytes32 | undefined): RecordLists => {
    const on = (reads: SubjectReads | undefined, read: Bytes32 | undefined): bigint =>
      read === undefined ? 0n : (reads?.get(bytesKey(read))?.read.record()?.lists ?? 0n);
    const key = member === undefined ? undefined : keyOf.get(bytesKey(member));
    const foreign = BigInt(view?.foreign ?? 0);
    return Object.freeze({
      own: on(ownReads, member),
      curator: on(curatorReads, member),
      salted: (on(ownReads, key) & ~foreign) | (on(curatorReads, key) & foreign),
    });
  };
  const policyOf = (asset: Bytes32): MintPolicy =>
    ownReads.get(bytesKey(asset))?.read.record()?.mintPolicy ?? EMPTY_MINT_POLICY;
  const padding = <T>(zero: T): readonly T[] =>
    Array.from({ length: circuit.outputs - owners.length }, () => zero);
  const spent = spentNotes(proofInputs);
  if (pinned !== undefined) {
    const sources = pinned.sources;
    const live = proofInputs.outputs.flatMap((output, slot) =>
      output.isDummy() ? [] : [{ output, slot }],
    );
    const ringInputs = spent.filter((note) => note.ring);
    const payments = [
      ...live.map(({ output, slot }) => ({
        ring: output.ringProgramId !== undefined,
        owner: owners[slot] ?? ZERO_32,
        asset: memberOfAsset(output.asset),
        amount: output.amount,
        ownerLists: recordLists(owners[slot]),
        assetLists: recordLists(assets[slot]),
        mintPolicy: policyOf(memberOfAsset(output.asset)),
      })),
      ...withdrawals.map((leg) => ({
        ...leg,
        ring: false,
        ownerLists: recordLists(leg.owner),
        assetLists: recordLists(leg.asset),
        mintPolicy: policyOf(leg.asset),
      })),
    ];
    // A co-owner who receives nothing is screened, every row passes the sender rules. Payments
    // read once with or without a row, a dummy sender would hold a deposit to sender rules.
    const refusal =
      evaluateSenders(pinned.table, sources, liveRows.map(recordLists)) ??
      evaluatePayments(pinned.table, sources, { ringInputs, outputs: payments }) ??
      evaluateInputAssets(
        pinned.table,
        sources,
        inputAssets.flatMap((asset, input) =>
          asset === undefined ? [] : [{ input, lists: recordLists(asset) }],
        ),
      );
    if (refusal !== undefined)
      throw ruleUnsatisfied(
        refusal,
        live.map(({ slot }) => slot),
      );
  }
  return Object.freeze({
    ...base,
    withdrawals,
    splWithdrawalOwners: demand.splWithdrawalOwners,
    ...(pinned === undefined
      ? {}
      : {
          table: policyTableProofInputs(pinned.table, pinned.sources),
          policyHash: pinned.policyHash,
        }),
    own,
    ...(curatorRoot === undefined ? {} : { curator: curatorRoot }),
    ownPool: ownPool.pool,
    ...(curatorPool === undefined ? {} : { curatorPool: curatorPool.pool }),
    senderEntries: Object.freeze(
      input.rows.map((row) => (isZero(row) ? ABSENT_OWNER : ownerEntry(row))),
    ),
    ownerEntries: Object.freeze([
      ...owners.map(ownerEntry),
      ...padding(ABSENT_OWNER),
      ...withdrawals.map((leg) => ownerEntry(leg.owner)),
    ]),
    assetEntries: Object.freeze([
      ...assets.map((asset) => entry(asset)),
      ...padding(ABSENT_ENTRY),
      ...withdrawals.map((leg) => entry(leg.asset)),
    ]),
    inputAssetEntries: Object.freeze(inputAssets.map((asset) => entry(asset))),
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

/** A proven absence is the one skip, a present credential forces its salt, Go `resolveOwner`. */
export function enrolledSalt(
  member: Bytes32,
  row: AuditCredential | undefined,
  salts: ReadonlyMap<string, Bytes32>,
): Bytes32 | undefined {
  if (row === undefined) return undefined;
  const salt = salts.get(bytesKey(member));
  if (salt === undefined)
    throw new RingError("RING_LIST_SALT_MISSING", { details: { member: bytesKey(member) } });
  if (!equalBytes(listTagOf(salt), row.listTag))
    throw new RingError("RING_ADDRESS_MISMATCH", {
      details: { field: "listSalt", member: bytesKey(member) },
    });
  return salt;
}

/** Opens every credential member once in one snapshot, refusing what the predicates refuse. */
async function readOwnerCredentials(
  input: PolicyReadInput,
  subjects: PolicySubjects,
  context: RequestContext | undefined,
): Promise<
  Pick<PolicyInputs, "credentials"> &
    Readonly<{
      rowOf: (member: Bytes32) => AuditCredential | undefined;
      credentialEntry: (member: Bytes32 | undefined) => number;
    }>
> {
  const { client, config, circuit, proofInputs } = input;
  const ringOutputs = proofInputs.outputs.map((output) =>
    output.ringProgramId === undefined || output.ownerAddress === undefined ? undefined : output,
  );
  const credentials = await readCredentials(
    {
      client,
      ringProgramId: input.ringProgramId,
      subjects: subjects.credentialMembers.map((member) => {
        const subject = subjects.subjectOf.get(bytesKey(member));
        if (subject === undefined)
          throw new RingError("RING_TRANSACT_DATA_INVALID", {
            details: { reason: "credentialSubject" },
          });
        return subject;
      }),
      capacity: transferPoolCapacity(circuit).credentials,
      absenceFloor: readsPolicyRoot(config, input.rail)
        ? await saltedAbsenceFloor(client, config, context)
        : 0n,
      rows: input.rows,
      outputs: [
        ...ringOutputs.map((output) =>
          output?.ownerAddress?.signingPublicKey.ownerProofInputHash(),
        ),
        ...Array.from({ length: circuit.outputs - ringOutputs.length }, () => undefined),
      ],
    },
    context,
  );
  const rowOf = credentials.credentialOf;
  checkInputKeys({
    inputs: publishedNotes(proofInputs),
    rail: input.rail,
    publicOwners: input.publicOwners,
    rowOf,
  });
  checkOutputKeys({ outputs: ringOutputs, rowOf });
  const position = new Map(
    subjects.credentialMembers.map((member, index) => [bytesKey(member), index]),
  );
  return {
    credentials,
    rowOf,
    credentialEntry: (member: Bytes32 | undefined): number =>
      member === undefined || isZero(member) ? 0 : (position.get(bytesKey(member)) ?? 0),
  };
}

/** Rust `RingPolicy::absence_floor` over the registries the frame reads, zero with no salted read. */
async function saltedAbsenceFloor(
  client: Pick<ChainReader, "getAccount">,
  config: RingPolicy,
  context: RequestContext | undefined,
): Promise<bigint> {
  if (!config.hasPolicy) return 0n;
  const pinned = pinnedPolicy(config);
  const view = policySourceView(pinned.sources);
  const sources = [
    ...(view.saltedOwn ? [config.records] : []),
    ...(view.saltedCurated && pinned.curator !== undefined ? [pinned.curator] : []),
  ];
  const floors = await Promise.all(
    sources.map(
      async (source) => (await fetchStorageRegistry(client, source, context)).absenceFloor,
    ),
  );
  return floors.reduce((max, floor) => (floor > max ? floor : max), 0n);
}

/** The credential and policy sections of one deposit and the key holding them, Go `ScreenDeposit`. */
export async function readDepositSection(
  input: Readonly<{
    client: PolicyReadClient;
    ringProgramId: Address;
    ringId: Bytes32;
    config: RingPolicy;
    /** The recipient's signing key, its credential binds the output key. */
    recipient: ShieldedPublicKey;
    nullifierPk: Bytes32;
    asset: Bytes32;
    listSalts: readonly RingListSalt[];
  }>,
  context?: RequestContext,
): Promise<
  CredentialProofInputs &
    PolicyProofInputs &
    Readonly<{
      capacity: number;
      credentials: CredentialSection;
      own?: BoundRoot;
      curator?: BoundRoot;
    }>
> {
  const { client, config, ringProgramId, asset } = input;
  const subject = credentialSubject(input.recipient);
  const owner = subject.member;
  const pinned = config.hasPolicy ? pinnedPolicy(config) : undefined;
  const view = pinned === undefined ? undefined : policySourceView(pinned.sources);
  const anySalted = view !== undefined && view.salted !== 0;
  const enrolled = !equalBytes(input.nullifierPk, ZERO_NULLIFIER_PK);
  const capacity = depositKeyCapacity({
    slots: 1,
    recipients: 1,
    assets: 1,
    saltedKeys: anySalted && enrolled ? 1 : 0,
  });
  if (capacity === undefined) throw new RingError("RING_BUILD_DEPOSIT");
  const credentials = await readCredentials(
    {
      client,
      ringProgramId,
      subjects: [subject],
      capacity,
      absenceFloor: pinned === undefined ? 0n : await saltedAbsenceFloor(client, config, context),
      rows: [],
      outputs: Array.from({ length: capacity }, (_, slot) => (slot === 0 ? owner : undefined)),
    },
    context,
  );
  const row = credentials.credentialOf(owner);
  checkOutputKey(owner, input.nullifierPk, row);
  const pad = <T>(values: readonly T[], zero: T): readonly T[] =>
    Object.freeze([...values, ...Array.from({ length: capacity - values.length }, () => zero)]);
  const width = depositPoolWidth(capacity);
  const zeroSlots = Object.freeze(Array.from({ length: N_PUBLIC_SLOTS }, () => ZERO_32));
  const section = {
    capacity,
    credentials,
    ...credentials.inputs,
    withdrawalCount: 0,
    withdrawalHash: policyWithdrawalHash([]),
    withdrawals: Object.freeze([]),
    ringId: input.ringId,
    publicAssets: zeroSlots,
    publicAmounts: zeroSlots,
    publicGross: zeroSlots,
    senderEntries: Object.freeze([]),
    publicAssetEntries: Object.freeze([]),
  };
  if (pinned === undefined)
    return Object.freeze({
      ...section,
      ...emptyTable(),
      policyHash: ZERO_32,
      ownRoot: ZERO_32,
      curatorRoot: ZERO_32,
      ownPool: unopenedRecordPool(width),
      curatorPool: unopenedRecordPool(width),
      ownerEntries: pad([], ABSENT_OWNER),
      assetEntries: pad([], ABSENT_ENTRY),
    });
  const salt = anySalted ? enrolledSalt(owner, row, saltsByOwner(input.listSalts)) : undefined;
  const key = salt === undefined ? undefined : privateListKey(owner, salt);
  const own = await fetchBoundRoot({ client, ringProgramId, registry: config.records }, context);
  const curator =
    pinned.curator === undefined
      ? undefined
      : await fetchBoundRoot({ client, ringProgramId, registry: pinned.curator }, context);
  const saltedIn = (read: boolean | undefined): readonly Bytes32[] =>
    read === true && key !== undefined ? [key] : [];
  const ownMembers = [asset, owner, ...saltedIn(view?.saltedOwn)];
  const curatorMembers = [
    asset,
    ...(view?.publicForeign === true ? [owner] : []),
    ...saltedIn(view?.saltedCurated),
  ];
  const ownPool = await readRecordPool(
    { client, root: own, members: ownMembers, openings: width },
    context,
  );
  const curatorPool =
    curator === undefined
      ? undefined
      : await readRecordPool(
          { client, root: curator, members: curatorMembers, openings: width },
          context,
        );
  const ownReads = subjectReads(ownMembers, ownPool.reads);
  const curatorReads =
    curatorPool === undefined ? undefined : subjectReads(curatorMembers, curatorPool.reads);
  const index = (reads: SubjectReads | undefined, member: Bytes32 | undefined): number =>
    member === undefined ? 0 : (reads?.get(bytesKey(member))?.index ?? 0);
  return Object.freeze({
    ...section,
    ...policyTableProofInputs(pinned.table, pinned.sources),
    policyHash: pinned.policyHash,
    ownRoot: own.root,
    curatorRoot: curator?.root ?? ZERO_32,
    own,
    ...(curator === undefined ? {} : { curator }),
    ownPool: ownPool.pool,
    curatorPool: curatorPool?.pool ?? unopenedRecordPool(width),
    ownerEntries: pad(
      [
        {
          own: index(ownReads, owner),
          curator: index(curatorReads, owner),
          credential: 0,
          listSalt: salt ?? ZERO_32,
          ownSalted: index(ownReads, key),
          curatorSalted: index(curatorReads, key),
        },
      ],
      ABSENT_OWNER,
    ),
    assetEntries: pad(
      [{ own: index(ownReads, asset), curator: index(curatorReads, asset) }],
      ABSENT_ENTRY,
    ),
  });
}

/** A zero key waives only the key equality, a delegate moves it with no row and a hidden owner refuses it. */
export function checkInputKeys(
  input: Readonly<{
    inputs: readonly ProofInputUtxo[];
    rail: RingRail;
    publicOwners: boolean;
    rowOf: (member: Bytes32) => AuditCredential | undefined;
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

/** A nonzero key needs its credential, a zero key a proven absence, Go `outputs.go`. */
export function checkOutputKeys(
  input: Readonly<{
    outputs: readonly (ProofOutputUtxo | undefined)[];
    rowOf: (member: Bytes32) => AuditCredential | undefined;
  }>,
): void {
  for (const output of input.outputs) {
    const owner = output?.ownerAddress;
    if (owner === undefined) continue;
    const member = owner.signingPublicKey.ownerProofInputHash();
    checkOutputKey(member, owner.nullifierPublicKey, input.rowOf(member));
  }
}

function checkOutputKey(
  member: Bytes32,
  nullifierPk: Bytes32,
  row: AuditCredential | undefined,
): void {
  if (equalBytes(nullifierPk, ZERO_NULLIFIER_PK)) {
    if (row !== undefined) throw new RingError("RING_RECIPIENT_ENROLLED");
    return;
  }
  if (row === undefined) throw new RingError("RING_RECIPIENT_NOT_ENROLLED");
  if (!equalBytes(row.nullifierPk, nullifierPk))
    throw new RingError("RING_ADDRESS_MISMATCH", {
      details: { field: "nullifierPk", member: bytesKey(member) },
    });
}

/** The roots the statement binds, zero where the program reads none, Rust `PolicyInputs::roots`. */
export function policyRoots(policy: PolicyInputs): TransferRoots {
  return Object.freeze({
    policyHash: policy.policyHash,
    ownRoot: policy.own?.root ?? ZERO_32,
    curatorRoot: policy.curator?.root ?? ZERO_32,
    credentials: policy.credentials.inputs.credentialRoots,
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
    withdrawals: pad(
      policy.withdrawals.map(({ owner, asset, amount }) => ({ owner, asset, amount })),
      withdrawalSlots,
      { owner: ZERO_32, asset: ZERO_32, amount: 0n },
    ),
    policyHash: roots.policyHash,
    ringId: proving.ringId,
    ownRoot: roots.ownRoot,
    curatorRoot: roots.curatorRoot,
    publicAssets: proving.publicSlots.assets,
    publicAmounts: publicAmountFields(proving.publicSlots),
    publicGross: publicGrossFields(proving.publicSlots),
    ...policy.table,
    ownPool: policy.ownPool ?? unopenedRecordPool(capacity.own),
    curatorPool: policy.curatorPool ?? unopenedRecordPool(capacity.curator),
    senderEntries: policy.senderEntries,
    ownerEntries: pad(policy.ownerEntries, slots, ABSENT_OWNER),
    assetEntries: [
      ...pad(policy.assetEntries, slots, ABSENT_ENTRY),
      ...pad(policy.inputAssetEntries, policy.circuit.class, ABSENT_ENTRY),
    ],
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

/**
 * The wallet and the relay read one layout, one slot per output of the key and every public slot in
 * statement order, rows are the inputs' owners whatever their padding, Rust `approval_totals_of`.
 */
export function approvalTotalsOf(proofInputs: SppProofInputs, outputSlots: number): ApprovalTotals {
  const slots = publicSlots(proofInputs.externalData.interfaceTransfers);
  const inputs = spentNotes(proofInputs);
  const outputs = slotOutputs(proofInputs);
  return ApprovalTotals.new({
    transfer: {
      senders: inputs.map((note) => note.owner),
      assets: [],
      inputs,
      outputs,
      publicGross: grossOf(slots),
    },
    slotAssets: Array.from({ length: outputSlots }, (_, slot) => {
      const output = proofInputs.outputs[slot];
      return output === undefined || output.isDummy() ? undefined : assetField(output.asset);
    }),
    publicSlots: slots.assets.map((asset, slot) => ({ asset, gross: slots.gross[slot] ?? 0n })),
  });
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
    .filter((input) => inputClassOf(input) === InputClass.note)
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
    salted: 0,
    policyLen: 0,
    rules: Object.freeze(Array.from({ length: RING_RULE_SLOTS }, () => ZERO_32)),
  });
}

/** The rule and the subject a refusal names, outputs by their SPP slot. */
function ruleUnsatisfied(refusal: RuleRefusal, live: readonly number[]): RingError {
  const { subject } = refusal;
  const reason = { reason: refusal.kind, ruleIndex: refusal.rule, subject: subject.kind };
  return new RingError("RING_POLICY_RULE_UNSATISFIED", {
    details:
      subject.kind === "sender"
        ? reason
        : subject.kind === "inputAsset"
          ? { ...reason, inputIndex: subject.input }
          : { ...reason, slotIndex: live[subject.output] ?? -1 },
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
