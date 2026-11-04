/**
 * One transfer pipeline for every rail, Rust `pipeline`. The rail seals the outputs, the ring proof
 * opens them to the auditor and screens the ring's table, the SPP proof spends.
 */
import type { AccountMeta, Instruction } from "@solana/kit";

import {
  addressBytes,
  bytesKey,
  compressG2,
  concatBytes,
  encodeBase58,
  equalBytes,
  meta,
  solanaOwnerIdentity,
  treeAddress,
} from "@heliuslabs/zolana/internal";
import { type RingProver } from "../../rpc/ports.js";
import type { ChainReader, ProvenRingTransact, TreeContext } from "@heliuslabs/zolana/client";
import { ringTransactAccounts, type Shape } from "@heliuslabs/zolana/interface";
import type {
  Address,
  Bytes32,
  RequestContext,
  TransactWithdrawal,
} from "@heliuslabs/zolana/interface";
import type { RingTransactInstructionData } from "../../protocol/proof/circuit.js";
import type { ProvenAnonymousRingTransact } from "../../rpc/ports.js";
import type { ShieldedAddress, ViewingKey } from "@heliuslabs/zolana/keypair";
import { encodeAuditRecord, encodeDataTail } from "../../protocol/codec/audit-stream.js";
import {
  interfaceTransferBytes,
  type RelayTransferTerms,
  type TokenAccountCreate,
} from "../../rpc/relay-message.js";
import { SppProofInputs, createExternalData } from "@heliuslabs/zolana/transaction";
import type { ProofInputUtxo, ProofOutputUtxo } from "@heliuslabs/zolana/transaction";
import { CUSTOM_RING_PROOF_LENGTH } from "../../protocol/proof/custom-ring-proof.js";
import { ringAuthAddress, ringCoSignerMetas, ringPolicyAddress } from "../../protocol/pda/index.js";
import type { AuditStreamLayout } from "../../protocol/codec/ring-disclosure-layout.js";
import { ringIdField } from "../../crypto/derivation/ring-stream.js";

import { RingInstructionTag, ringComputeUnitLimit } from "../management/admin.js";
import {
  ownerRows,
  realInputCount,
  sealAudit,
  sealedAuditMessage,
  type SealedAudit,
  outputRecord,
  outputTail,
} from "../../proof/audit-proof.js";
import { type RingPolicy } from "../../protocol/codec/ring-codecs.js";
import {
  NO_DEMAND,
  operationDemand,
  publicLegClasses,
  resolveRingCoSigners,
} from "../../proof/cosign.js";
import { RingError } from "../../protocol/error.js";
import {
  policyLegs,
  policyDemand,
  readsPolicyRoot,
  policyRoots,
  publishedNotes,
  readPolicy,
  screened,
  type BoundPolicy,
  type BoundRoot,
  type PolicyInputs,
  type PolicyReadClient,
  type RingListSalt,
} from "../../proof/policy-proof.js";
import { selectTransferKey, transferProofRequest } from "../../proof/transfer-proof.js";
import { fittedSpend } from "../../protocol/proof/transfer-shapes.js";
import { policyWithdrawalHash } from "../../proof/withdrawals.js";
import { framesData, type PublishedSlot, type RingOutputRail } from "../payments/output-rail.js";
import {
  ringTransferStatement,
  signerBinding,
  transferStatementHash,
} from "../../protocol/proof/statement.js";
import {
  ANONYMOUS_PARTIES,
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  isDelegateRail,
  ringStreamLayout,
  ringSppInputs,
  type FrameExtensions,
  type InputTrees,
  type PolicyProof,
  type PublishedSenderBundle,
  type RingRail,
} from "../../protocol/transaction/transact.js";
import {
  MAX_SPP_CPI_ACCOUNTS,
  publicAmountFields,
  publicGrossFields,
  publicSlots,
  type PublicSlots,
  interfaceTransferOf,
  settlementAccounts,
} from "../../protocol/transaction/spp.js";
import { decideAddressCeiling } from "./address-ceiling.js";
import { checkTransferFits } from "./compile.js";
import { BufferedFrame } from "../payments/buffered-frame.js";
import { ringRegistrySlots, transferRootRead } from "./ring-reads.js";

/** The client a ring transfer reads the ring and proves with, every rail adds its SPP prover. */
export type RingProvingClient = TreeContext &
  Pick<ChainReader, "getAccount"> &
  PolicyReadClient &
  RingProver;

/** What an anonymous frame adds to a staged transfer, Rust `AnonymousSpend`. */
export interface AnonymousSpendValues {
  readonly tokenOwner?: Address;
  /** Binds the signing co-signers, each of `ANONYMOUS_PARTIES` zero when absent. */
  partyIdentities(coSigners: readonly Address[]): readonly Bytes32[];
}

/** How the SPP proof authorizes the spends of one rail, Rust `Spend`. */
export interface RailSpend {
  readonly rail: RingRail;
  /** The rail's SPP proof over the final inputs, the hidden owner signs them inside it. */
  prove(
    proofInputs: SppProofInputs,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransact | ProvenAnonymousRingTransact>;
  /** Signs the transaction beside the payer on the delegate rails. */
  readonly delegate?: Address;
  readonly anonymous?: AnonymousSpendValues;
  /** The confidential rail's owner key when it signs inside the SPP proof. */
  readonly inProofOwner?: Bytes32;
  /** The anonymous rail with every live owner a published signer. */
  readonly publicOwners?: true;
}

/** A transfer past its outputs' sealing, ready for its statements, Rust `Staged`. */
export interface StagedTransfer {
  /** Sealed by the rail, before the auditor message joins the external data. */
  readonly proofInputs: SppProofInputs;
  readonly rail: RingOutputRail;
  readonly sender: ShieldedAddress;
  /** SPP's owner signer run, empty on the authority rails. */
  readonly ownerSigners: readonly Address[];
  readonly withdrawal?: TransactWithdrawal;
  /** Empty unless the caller sets them. */
  readonly extensions?: FrameExtensions;
  readonly spend: RailSpend;
}

/** The accounts a ring transfer names besides its data, Rust `TransactAccounts`. */
export interface RingTransactAccounts {
  /** SPP's fee payer. */
  readonly payer: Address;
  /** One per tree context, in the data's order. */
  readonly inputTrees: readonly Address[];
  readonly outputTree: Address;
  readonly ownerSigners: readonly Address[];
  readonly withdrawal?: TransactWithdrawal;
  /** Read only, right after the ring account, tracking last. */
  readonly registries: readonly Address[];
  readonly coSigners: readonly Address[];
  readonly delegate?: Address;
}

/** Every value a transfer's proofs bind that the chain can move before it lands, Rust `BoundState`. */
export interface RingBoundState {
  /** The live roots the proofs bind by revision, the own root first. */
  readonly roots?: readonly BoundRoot[];
  /** Read from the tracking registry, a separate account layout. */
  readonly trackingRoot?: BoundRoot;
  readonly policy?: BoundPolicy;
}

/** A proven transfer, its compact data, accounts and the chain values its proofs bind, Rust `ProvenRingTransfer`. */
export class ProvenRingTransfer {
  readonly ringProgramId: Address;
  readonly data: RingTransactData;
  readonly accounts: RingTransactAccounts;
  /** Padding included, final slot order. */
  readonly outputs: readonly ProofOutputUtxo[];
  readonly coSigners: readonly Address[];
  /** The live roots the proofs bind, a submission proves again once one leaves its registry. */
  readonly roots: readonly BoundRoot[];
  readonly trackingRoot: BoundRoot;
  readonly policy?: BoundPolicy;

  /** @internal */
  constructor(fields: Omit<ProvenRingTransfer, "instruction" | "buffered">) {
    this.ringProgramId = fields.ringProgramId;
    this.data = fields.data;
    this.accounts = fields.accounts;
    this.outputs = fields.outputs;
    this.coSigners = fields.coSigners;
    this.roots = fields.roots;
    this.trackingRoot = fields.trackingRoot;
    if (fields.policy !== undefined) this.policy = fields.policy;
    Object.freeze(this);
  }

  instruction(): Promise<Instruction> {
    return ringTransactInstruction(this.ringProgramId, this.accounts, this.data);
  }

  /** `nonce` names the buffer, the payer writes it and pays the settlement. */
  async buffered(nonce: bigint): Promise<BufferedFrame> {
    return BufferedFrame.of(await this.instruction(), this.accounts.payer, nonce);
  }
}

/** What a staged transfer's proofs read, valid inside the `assembleStagedTransfer` callback. */
interface AssembledTransfer {
  readonly sealed: SealedAudit;
  readonly published: readonly PublishedSlot[];
  readonly inputs: readonly ProofInputUtxo[];
  readonly proofInputs: SppProofInputs;
  readonly slots: PublicSlots;
  readonly policy: PolicyInputs;
  readonly coSigners: readonly Address[];
  /** Zeros off the anonymous frame. */
  readonly partyIdentities: readonly Bytes32[];
  /** The in-proof owner's identity, zero on every other rail. */
  readonly sender: Bytes32;
  /** SPP's owner signer run by owner identity, empty on the authority rails. */
  readonly signers: readonly Bytes32[];
  readonly privateTxHash: Bytes32;
  /** The one ring statement, hashed as the program rebuilds it. */
  readonly publicInputHash: Bytes32;
  readonly accounts: RingTransactAccounts;
  readonly ringId: Bytes32;
  readonly preview: RingTransactData;
}

export interface RingTransactionFrame {
  readonly priorityFeeLamports?: bigint;
  readonly setupInstructions?: readonly Instruction[];
}

export type StagedTransferInput = Readonly<{
  client: RingProvingClient;
  ringProgramId: Address;
  config: RingPolicy;
  staged: StagedTransfer;
  coSigners?: readonly Address[];
  /** An enrolled subject on a ring reading a salted list needs its salt here. */
  listSalts?: readonly RingListSalt[];
  transaction?: RingTransactionFrame;
  /** Past one transaction the frame settles from a buffer its payer writes. */
  bufferedSettlement?: boolean;
  approve?: (coSigners: readonly Address[]) => Promise<void>;
}>;

/** Rust `Pipeline::assemble` and `Assembled::prove`, neither proof is an input to the other. */
export function proveStagedTransfer(
  input: StagedTransferInput,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return assembleStagedTransfer(input, context, async (assembled) => {
    await input.approve?.(assembled.coSigners);
    return proveAssembled(input, assembled, context);
  });
}

/** A staged transfer whose external data is final, Rust `Sealed`. */
export interface SealedTransfer {
  readonly sealed: SealedAudit;
  readonly layout: AuditStreamLayout;
  readonly published: readonly PublishedSlot[];
  /** The spent notes in SPP order, compact padding left out. */
  readonly inputs: readonly ProofInputUtxo[];
  readonly senderBundle: PublishedSenderBundle | undefined;
  readonly shape: Shape;
  /** The owner signs its `messageHash`. */
  readonly proofInputs: SppProofInputs;
}

export function sealedTransferTerms(
  input: Readonly<{
    ringProgramId: Address;
    feePayer: Address;
    sealed: SealedTransfer;
    ownerSigners: readonly Address[];
    coSigners: readonly Address[];
    txViewingKey: ViewingKey;
    setup: readonly TokenAccountCreate[];
  }>,
): RelayTransferTerms {
  const { sealed } = input;
  const outputs = sealed.published.map((slot) => slot.output);
  return Object.freeze({
    ring: input.ringProgramId,
    feePayer: input.feePayer,
    txViewingKey: input.txViewingKey.secretBytes(),
    signers: Object.freeze([...input.ownerSigners, ...input.coSigners]),
    records: Object.freeze(outputs.map((output) => encodeAuditRecord(outputRecord(output)))),
    tails: Object.freeze(
      framesData(outputs) ? outputs.map((output) => encodeDataTail(outputTail(output))) : [],
    ),
    nullifiers: Object.freeze(sealed.inputs.map((spent) => spent.nullifier())),
    legs: Object.freeze(
      sealed.proofInputs.externalData.interfaceTransfers.map((leg) =>
        interfaceTransferBytes(interfaceTransferOf(leg)),
      ),
    ),
    setup: input.setup,
  });
}

/** The key a staged transfer selects, every stream counter follows it. */
async function selectStagedKey(input: StagedTransferInput, context: RequestContext | undefined) {
  const { client, config, staged } = input;
  const { spend } = staged;
  const delegate = isDelegateRail(spend.rail);
  const inputs = publishedNotes(staged.proofInputs);
  const transfers = staged.proofInputs.externalData.interfaceTransfers;
  const liveRows = ownerRows({ inputs, delegate });
  const demandInput = {
    client,
    config,
    rail: spend.rail,
    proofInputs: staged.proofInputs,
    publicSlots: publicSlots(transfers),
    listSalts: input.listSalts ?? [],
    ...(spend.anonymous?.tokenOwner === undefined
      ? {}
      : { tokenOwnerHint: spend.anonymous.tokenOwner }),
  };
  const demand = await policyDemand({ ...demandInput, rows: liveRows }, context);
  const shape = staged.proofInputs.checkShape();
  const keySpend = {
    rail: spend.rail,
    inputs: inputs.length,
    outputs: shape.outputs,
    spendsDefaultRing: spendsDefaultRing(staged.proofInputs),
    legs: policyLegs(config, spend.rail, transfers),
    owners: liveRows.length,
    pools: demand.pools,
    wide: false,
  };
  const addresses = { nInputs: shape.inputs, legs: transfers.length };
  const { circuit, wideOwners } = selectTransferKey({
    spend: keySpend,
    addresses: { ...addresses, coSigners: input.coSigners?.length ?? 0 },
    ownerSigners: staged.ownerSigners.length,
  });
  return { demandInput, demand, keySpend, addresses, circuit, wideOwners };
}

/** Rust `Prepared::unread_wide`. */
function unreadWide(
  input: Readonly<{
    config: RingPolicy;
    staged: Pick<StagedTransfer, "proofInputs"> & Readonly<{ spend: Pick<RailSpend, "rail"> }>;
  }>,
): boolean {
  const { config, staged } = input;
  const { proofInputs, spend } = staged;
  const inputs = publishedNotes(proofInputs);
  const entry = spendsDefaultRing(proofInputs);
  const { wide } = fittedSpend({
    rail: spend.rail,
    inputs: inputs.length,
    outputs: proofInputs.checkShape().outputs,
    spendsDefaultRing: entry,
    legs: proofInputs.externalData.interfaceTransfers.length,
    owners: ownerRows({ inputs, delegate: isDelegateRail(spend.rail) }).length,
    pools: { own: 0, curator: 0, tracking: 0 },
    wide: false,
  });
  const reads = readsPolicyRoot(config, spend.rail);
  const data = framesData(proofInputs.outputs.filter((output) => !output.isDummy()));
  return wide || (reads && (data || entry));
}

/** A relayed owner's seal, the caller wipes `sealed.ephemeralSecret`. */
export function sealRelayedTransfer(
  input: Readonly<{
    ringProgramId: Address;
    config: RingPolicy;
    staged: Omit<StagedTransfer, "spend"> &
      Readonly<{ spend: Pick<RailSpend, "rail" | "inProofOwner" | "publicOwners"> }>;
  }>,
): SealedTransfer & Readonly<{ wideOwners: boolean }> {
  const wideOwners = unreadWide(input);
  return Object.freeze({ ...sealStagedTransfer({ ...input, wideOwners }), wideOwners });
}

/** The caller wipes `sealed.ephemeralSecret`. */
function sealStagedTransfer(
  input: Readonly<{
    ringProgramId: Address;
    config: RingPolicy;
    wideOwners: boolean;
    staged: Omit<StagedTransfer, "spend"> &
      Readonly<{ spend: Pick<RailSpend, "rail" | "inProofOwner" | "publicOwners"> }>;
  }>,
): SealedTransfer {
  const { ringProgramId, config, staged } = input;
  const { rail, sender, spend } = staged;
  checkDistinctInputs(staged.proofInputs);
  checkMembership(ringProgramId, staged.proofInputs);
  checkDelegateLegs(spend.rail, staged.proofInputs);
  const shape = staged.proofInputs.checkShape();
  const inputs = publishedNotes(staged.proofInputs);
  const published = rail.publishedSlots(staged.proofInputs, sender);
  const senderBundle = rail.publishedSender(staged.proofInputs, sender.viewingPublicKey);
  const layout = ringStreamLayout({
    rail: spend.rail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    inputs: inputs.length,
    outputs: published.length,
    entry: spendsDefaultRing(staged.proofInputs),
    hasData: framesData(published.map((slot) => slot.output)),
    publicOwners: spend.publicOwners === true,
    wideOwners: input.wideOwners,
  });
  const auditor = config.auditorPublicKey;
  // The auditor message precedes every hash over the external data.
  const sealed = sealAudit({ rail, layout, published, inputs, auditor });
  try {
    return Object.freeze({
      sealed,
      layout,
      published,
      inputs,
      senderBundle,
      shape,
      proofInputs: withAuditorMessage(
        staged.proofInputs,
        sealedAuditMessage(sealed, auditor),
        staged.extensions ?? NO_EXTENSIONS,
      ),
    });
  } catch (cause) {
    sealed.ephemeralSecret.fill(0);
    throw cause;
  }
}

/** Every chain value is read once, the audit secret lives until `use` settles. */
async function assembleStagedTransfer<T>(
  input: StagedTransferInput,
  context: RequestContext | undefined,
  use: (assembled: AssembledTransfer) => Promise<T>,
): Promise<T> {
  const { client, ringProgramId, config, staged } = input;
  const { rail, spend } = staged;
  const ringRail = spend.rail;
  const delegate = isDelegateRail(ringRail);
  const selected = await selectStagedKey(input, context);
  const { demandInput, demand, keySpend, addresses, circuit, wideOwners } = selected;
  const { sealed, layout, published, inputs, senderBundle, shape, proofInputs } =
    sealStagedTransfer({ ...input, wideOwners });
  const auditor = config.auditorPublicKey;
  try {
    const transfers = proofInputs.externalData.interfaceTransfers;
    const slots = publicSlots(transfers);
    const entry = layout.key.entry;
    const listSalts = input.listSalts ?? [];
    const policy = await readPolicy(
      {
        ...demandInput,
        proofInputs,
        ringProgramId,
        publicOwners: spend.publicOwners === true,
        circuit,
        rows: ownerRows({ inputs, delegate, slots: circuit.owners }),
        demand,
      },
      context,
    );
    const noSpend = realInputCount(inputs) === 0;
    const coSignDemand = delegate
      ? NO_DEMAND
      : operationDemand({
          spendsNote: !noSpend,
          publicLegs: publicLegClasses(transfers),
          approval: policy.approvalMask,
        });
    const coSigners = (
      await resolveRingCoSigners(
        {
          client,
          ringProgramId,
          config,
          demand: coSignDemand,
          supplied: input.coSigners ?? [],
          ownerSigners:
            spend.inProofOwner === undefined
              ? staged.ownerSigners
              : [...staged.ownerSigners, encodeBase58(spend.inProofOwner)],
        },
        context,
      )
    ).map(({ signer }) => signer);
    // The final co-signer count moves the account bound.
    selectTransferKey({
      spend: keySpend,
      addresses: { ...addresses, coSigners: coSigners.length },
      ownerSigners: staged.ownerSigners.length,
    });
    const partyIdentities =
      spend.anonymous?.partyIdentities(coSigners) ??
      Array.from({ length: ANONYMOUS_PARTIES }, () => zeroField());
    const privateTxHash = proofInputs.privateTxHash();
    const statementSender =
      spend.inProofOwner === undefined
        ? zeroField()
        : (solanaOwnerIdentity(spend.inProofOwner) as Bytes32);
    const signers = staged.ownerSigners.map(
      (signer) => solanaOwnerIdentity(addressBytes(signer)) as Bytes32,
    );
    const accounts: RingTransactAccounts = Object.freeze({
      payer: proofInputs.payer,
      inputTrees: Object.freeze(proofInputs.inputTreeIds().map(treeAddress)),
      outputTree: treeAddress(proofInputs.outputTreeId),
      ownerSigners: staged.ownerSigners,
      ...(staged.withdrawal === undefined ? {} : { withdrawal: staged.withdrawal }),
      registries: ringRegistrySlots(config, transferRootRead(config, delegate)),
      coSigners,
      ...(spend.delegate === undefined ? {} : { delegate: spend.delegate }),
    });
    const ringId = ringIdField(ringProgramId);
    const preview = previewData({
      rail: ringRail,
      shape,
      proofInputs,
      inputs,
      published,
      sealed,
      ...(senderBundle === undefined ? {} : { sender: senderBundle }),
      txViewingU: rail.txViewingKey.publicKey().u(),
      privateTxHash,
      policy,
      noSpend,
      wideOwners,
      publicOwners: spend.publicOwners === true,
      extensions: staged.extensions ?? NO_EXTENSIONS,
      ...(spend.inProofOwner === undefined ? {} : { inProofOwner: spend.inProofOwner }),
    });
    const publicInputHash = transferStatementHash(
      ringTransferStatement(preview, {
        ringId,
        auditorPubkey: auditor.toBytes(),
        sender: statementSender,
        partyIdentities,
        signers: signerBinding(signers, circuit.class),
        roots: policyRoots(policy),
        publicAssets: slots.assets,
        publicAmounts: publicAmountFields(slots),
        publicGross: publicGrossFields(slots),
        withdrawalHash: policyWithdrawalHash(policy.withdrawals),
      }),
    );
    // The program's expansion must reproduce the external data the SPP proof binds.
    if (
      !equalBytes(
        RingTransactData.externalDataHash(
          preview,
          { auditorPubkey: auditor.toBytes() },
          transfers.map(settlementAccounts),
        ),
        proofInputs.externalData.hash(),
      )
    )
      throw new RingError("RING_EXTERNAL_DATA_MISMATCH");
    const inline = await ringTransactInstruction(ringProgramId, accounts, preview);
    const computeUnitLimit = ringComputeUnitLimit(transactTag(ringRail));
    if (input.bufferedSettlement === true)
      await decideAddressCeiling({
        ...input.transaction,
        payer: proofInputs.payer,
        instruction: inline,
        computeUnitLimit,
        inputs: [],
        mergeCapacity: { keyed: 0, zeroKey: 0 },
      });
    else
      checkTransferFits(shape, {
        ...input.transaction,
        feePayer: proofInputs.payer,
        instructions: [inline],
        computeUnitLimit,
      });
    return await use(
      Object.freeze({
        sealed,
        published,
        inputs,
        proofInputs,
        slots,
        policy,
        coSigners,
        partyIdentities,
        sender: statementSender,
        signers,
        privateTxHash,
        publicInputHash,
        accounts,
        ringId,
        preview,
      }),
    );
  } finally {
    sealed.ephemeralSecret.fill(0);
  }
}

async function proveAssembled(
  input: StagedTransferInput,
  assembled: AssembledTransfer,
  context: RequestContext | undefined,
): Promise<ProvenRingTransfer> {
  const { client, ringProgramId, config, staged } = input;
  const { rail, spend } = staged;
  const { proofInputs, policy, coSigners, privateTxHash, ringId, preview, inputs } = assembled;
  const request = transferProofRequest({
    rail,
    ringRail: spend.rail,
    sealed: assembled.sealed,
    outputCount: assembled.published.length,
    inputs,
    proofInputs,
    auditor: config.auditorPublicKey,
    policy,
    proving: { ringId, publicSlots: assembled.slots },
    publicInputHash: assembled.publicInputHash,
    privateTxHash,
    sender: assembled.sender,
    inProof: spend.inProofOwner !== undefined,
    publicOwners: spend.publicOwners === true,
    partyIdentities: assembled.partyIdentities,
    signers: assembled.signers,
  });
  let proofs: readonly [ProvenRingTransact | ProvenAnonymousRingTransact, Uint8Array];
  try {
    // Each request runs in its own async call, a synchronous throw never strands the other proof.
    proofs = await Promise.all([
      (async () => spend.prove(proofInputs, context))(),
      (async () => client.proveRing(request, context))(),
    ]);
  } finally {
    wipeAuditRequest(request);
  }
  const [spp, proof] = proofs;
  const data = provenData({
    preview,
    spp: spp.data,
    privateTxHash,
    publishedInputs: inputs.length,
    proof,
  });
  return new ProvenRingTransfer({
    ringProgramId,
    data,
    accounts: assembled.accounts,
    outputs: proofInputs.outputs,
    coSigners,
    roots: boundRoots(policy),
    trackingRoot: policy.trackingBound,
    ...(screened(policy)
      ? { policy: Object.freeze({ ringProgramId, policyHash: policy.policyHash }) }
      : {}),
  });
}

/** The ring prefix, then SPP's own accounts, the data's tag by its rail, Rust `TransactAccounts::instruction`. */
export async function ringTransactInstruction(
  ringProgramId: Address,
  accounts: RingTransactAccounts,
  data: RingTransactData,
): Promise<Instruction> {
  const spp = ringSppInputs(data);
  const [ring, ringAuth] = await Promise.all([
    ringPolicyAddress(ringProgramId),
    ringAuthAddress(ringProgramId),
  ]);
  const sppAccounts = await ringTransactAccounts({
    payer: accounts.payer,
    inputTrees: accounts.inputTrees,
    outputTree: accounts.outputTree,
    ringAuth,
    inputs: spp.inputs,
    treeContexts: spp.treeContexts,
    ...(!isDelegateRail(data.rail) && accounts.ownerSigners.length > 0
      ? { ownerSigners: accounts.ownerSigners }
      : {}),
    ...(accounts.withdrawal === undefined ? {} : { withdrawal: accounts.withdrawal }),
  });
  if (sppAccounts.length > MAX_SPP_CPI_ACCOUNTS)
    throw new RingError("RING_TOO_MANY_SETTLEMENT_ACCOUNTS", {
      details: { accounts: sppAccounts.length, limit: MAX_SPP_CPI_ACCOUNTS },
    });
  const prefix: AccountMeta[] = [
    meta(ring, false, false),
    ...accounts.registries.map((registry) => meta(registry, false, false)),
  ];
  for (const coSigner of accounts.coSigners)
    prefix.push(...(await ringCoSignerMetas(ringProgramId, coSigner)));
  if (accounts.delegate !== undefined) prefix.push(meta(accounts.delegate, true, false));
  const encoded = RingTransactData.encode(data);
  const bytes = new Uint8Array(1 + encoded.length);
  bytes[0] = transactTag(data.rail);
  bytes.set(encoded, 1);
  return Object.freeze({
    programAddress: ringProgramId,
    accounts: Object.freeze([...prefix, ...sppAccounts]),
    data: bytes,
  });
}

/** The auditor message joins the external data last, the expiry the compact data carries as a u32. */
function withAuditorMessage(
  proofInputs: SppProofInputs,
  message: Readonly<{ viewTag: Bytes32; data: Uint8Array }>,
  extensions: FrameExtensions,
): SppProofInputs {
  const external = proofInputs.externalData;
  return new SppProofInputs({
    payer: proofInputs.payer,
    inputUtxos: proofInputs.inputUtxos,
    outputs: proofInputs.outputs,
    externalData: createExternalData({
      instructionDiscriminator: external.instructionDiscriminator,
      expiryUnixTs: U32_MAX,
      interfaceTransfers: external.interfaceTransfers,
      ...(extensions.dataHash === undefined ? {} : { dataHash: extensions.dataHash }),
      ...(extensions.ringDataHash === undefined ? {} : { ringDataHash: extensions.ringDataHash }),
      txViewingPublicKey: external.txViewingPublicKey,
      salt: external.salt,
      outputs: external.outputs,
      resolvedOwnerTags: external.resolvedOwnerTags,
      messages: [...external.messages, ...(extensions.messages ?? []), message],
    }),
    blindingSeed: proofInputs.blindingSeed,
    outputTreeId: proofInputs.outputTreeId,
  });
}

/** The compact data before any proof, sized and hashed as the proven one, Rust `preview_parts`. */
function previewData(
  input: Readonly<{
    rail: RingRail;
    shape: Readonly<{ inputs: number; outputs: number }>;
    proofInputs: SppProofInputs;
    inputs: readonly ProofInputUtxo[];
    published: readonly PublishedSlot[];
    sealed: SealedAudit;
    sender?: PublishedSenderBundle;
    txViewingU: Bytes32;
    privateTxHash: Bytes32;
    policy: PolicyInputs;
    noSpend: boolean;
    wideOwners: boolean;
    publicOwners: boolean;
    extensions: FrameExtensions;
    inProofOwner?: Bytes32;
  }>,
): RingTransactData {
  const { policy, sealed, published } = input;
  const external = input.proofInputs.externalData;
  const zeroContext = { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 };
  const trees = input.proofInputs.inputTreeIds().length;
  const inputTrees: InputTrees =
    trees === 1
      ? { kind: "one", context: zeroContext }
      : { kind: "two", first: zeroContext, second: zeroContext, secondInputs: 0n };
  const replies = published.flatMap((slot) => (slot.reply === undefined ? [] : [slot.reply]));
  const policySection: PolicyProof | undefined = screened(policy)
    ? Object.freeze(
        policy.curator === undefined ? {} : { curatorRevision: policy.curator.revision },
      )
    : undefined;
  const { entry, hasData } = sealed.audit;
  return Object.freeze({
    rail: input.rail,
    nIn: input.shape.inputs,
    nOut: input.shape.outputs,
    proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    trackingRevision: policy.trackingBound.revision,
    ...(policy.own === undefined ? {} : { ownRevision: policy.own.revision }),
    ...(policySection === undefined ? {} : { policy: policySection }),
    splWithdrawalOwners: policy.own === undefined ? [] : policy.splWithdrawalOwners,
    approval: policy.approvalMask,
    noSpend: input.noSpend,
    publicOwners: input.publicOwners,
    expiryUnixTs: Number(U32_MAX),
    txViewingU: input.txViewingU,
    salt: external.salt,
    extensions: input.extensions,
    interfaceTransfers: external.interfaceTransfers.map(interfaceTransferOf),
    hasData,
    entry,
    wideOwners: input.wideOwners,
    outputs: Object.freeze(
      published.map((slot, index) => {
        const tail = sealed.tails?.[index];
        return Object.freeze({
          ...slot.wire,
          record: sealed.records[index] as Uint8Array,
          ...(tail === undefined ? {} : { tail }),
        });
      }),
    ),
    ...(replies[0] === undefined
      ? {}
      : {
          replies: Object.freeze({
            length: replies[0].length,
            region: concatBytes(...replies),
          }),
        }),
    ...(input.sender === undefined ? {} : { sender: input.sender }),
    envelope: sealed.envelope,
    privateTxHash: input.privateTxHash,
    ...(input.rail === "anonymous" && !input.publicOwners
      ? {
          anonymous: {
            commitment: zeroField(),
            commitmentPok: zeroField(),
            // SPP names the hidden owner's key exactly when a default-ring note is spent.
            ...(entry ? { defaultOwnerTag: zeroField() } : {}),
          },
        }
      : {}),
    ...(input.inProofOwner === undefined
      ? {}
      : {
          inProofOwner: {
            owner: input.inProofOwner,
            commitment: zeroField(),
            commitmentPok: zeroField(),
          },
        }),
    sppProof: new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH),
    nullifiers: Object.freeze(input.inputs.map((spent) => spent.nullifier())),
    inputTrees,
  });
}

/** The preview with every proof in place, refused unless SPP published the preview's values. */
function provenData(
  input: Readonly<{
    preview: RingTransactData;
    spp: RingTransactInstructionData;
    privateTxHash: Bytes32;
    publishedInputs: number;
    proof: Uint8Array;
  }>,
): RingTransactData {
  const { preview, spp } = input;
  // SPP publishes the nullifier of every input slot but compact padding.
  const inputs = spp.inputs.slice(0, input.publishedInputs);
  const nullifiers = inputs.map((spent) => spent.nullifierHash);
  if (
    inputs.length !== input.publishedInputs ||
    !equalBytes(spp.privateTxHash, input.privateTxHash) ||
    nullifiers.some(
      (nullifier, index) => !equalBytes(nullifier, preview.nullifiers[index] ?? zeroField()),
    )
  )
    throw new RingError("RING_SPP_PROOF_MISMATCH");
  const [first, second, ...rest] = spp.treeContexts;
  if (first === undefined || rest.length > 0) throw new RingError("RING_SPP_PROOF_MISMATCH");
  const inputTrees: InputTrees =
    second === undefined
      ? { kind: "one", context: first }
      : {
          kind: "two",
          first,
          second,
          secondInputs: inputs.reduce(
            (bits, spent, index) => (spent.treeIndex === 1 ? bits | (1n << BigInt(index)) : bits),
            0n,
          ),
        };
  const circuit = spp.circuit;
  // The anonymous ring's hidden owner and a confidential ring's in-proof owner both prove on SPP's anonymous rail.
  const proofData =
    circuit.kind === "anonymousRingEddsa" || circuit.kind === "anonymousRingEddsaCached"
      ? circuit.proofData
      : undefined;
  const commitment =
    proofData === undefined
      ? undefined
      : {
          commitment: proofData.bsb22Commitment.commitment,
          commitmentPok: proofData.bsb22Commitment.commitmentPok,
        };
  const anonymous =
    commitment !== undefined && preview.anonymous !== undefined
      ? {
          ...commitment,
          ...(proofData?.defaultOwnerTag === undefined
            ? {}
            : { defaultOwnerTag: proofData.defaultOwnerTag }),
        }
      : undefined;
  const inProofOwner =
    commitment !== undefined && preview.inProofOwner !== undefined
      ? { owner: preview.inProofOwner.owner, ...commitment }
      : undefined;
  if (
    (commitment !== undefined) !==
      (preview.anonymous !== undefined || preview.inProofOwner !== undefined) ||
    // A default owner tag would publish the in-proof owner SPP hides.
    (inProofOwner !== undefined && proofData?.defaultOwnerTag !== undefined)
  )
    throw new RingError("RING_SPP_PROOF_MISMATCH");
  const sppProof = new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH);
  sppProof.set(spp.proof.a, 0);
  sppProof.set(compressG2(spp.proof.b), 32);
  sppProof.set(spp.proof.c, 96);
  return Object.freeze({
    ...preview,
    proof: input.proof,
    ...(anonymous === undefined ? {} : { anonymous }),
    ...(inProofOwner === undefined ? {} : { inProofOwner }),
    sppProof,
    nullifiers: Object.freeze(nullifiers),
    inputTrees,
  });
}

export function spendsDefaultRing(proofInputs: SppProofInputs): boolean {
  return proofInputs.inputUtxos.some(
    (spent) => !spent.isCompact() && !spent.isDummy() && spent.utxo.ringProgramId === undefined,
  );
}

/** A deposit leg would bring an unlisted asset in, a delegate withdraws alone. */
function checkDelegateLegs(rail: RingRail, proofInputs: SppProofInputs): void {
  if (
    isDelegateRail(rail) &&
    proofInputs.externalData.interfaceTransfers.some((transfer) => transfer.isDeposit)
  )
    throw new RingError("RING_DELEGATE_DEPOSIT_LEG");
}

/** Each real input spends once, a repeated nullifier fails on chain after proving. */
function checkDistinctInputs(proofInputs: SppProofInputs): void {
  const seen = new Set<string>();
  proofInputs.inputUtxos.forEach((spent, index) => {
    if (spent.isDummy()) return;
    const key = bytesKey(spent.nullifier());
    if (seen.has(key)) throw new RingError("RING_DUPLICATE_INPUT", { details: { index } });
    seen.add(key);
  });
}

/** Every ring field names the transfer's ring, and only a ring note carries ring data. */
function checkMembership(ringProgramId: Address, proofInputs: SppProofInputs): void {
  const slots = [
    ...proofInputs.inputUtxos.map((spent) => ({
      ring: spent.utxo.ringProgramId,
      data: spent.ringDataHash,
    })),
    ...proofInputs.outputs.map((output) => ({
      ring: output.ringProgramId,
      data: output.ringDataHash,
    })),
  ];
  for (const { ring, data } of slots) {
    if (ring !== undefined && ring !== ringProgramId)
      throw new RingError("RING_FOREIGN_RING", { details: { ring } });
    if (ring === undefined && data !== undefined) throw new RingError("RING_DATA_OUTSIDE_RING");
  }
}

/** @internal What a submission attempt of `proven` checks before it proves again. */
export function boundState(proven: ProvenRingTransfer): RingBoundState {
  return Object.freeze({
    ...(proven.roots.length === 0 ? {} : { roots: proven.roots }),
    trackingRoot: proven.trackingRoot,
    ...(proven.policy === undefined ? {} : { policy: proven.policy }),
  });
}

function boundRoots(policy: PolicyInputs): readonly BoundRoot[] {
  return Object.freeze(
    [policy.own, policy.curator].filter((root): root is BoundRoot => root !== undefined),
  );
}

function transactTag(rail: RingRail): RingInstructionTag {
  return isDelegateRail(rail) ? RingInstructionTag.authorityTransfer : RingInstructionTag.transfer;
}

function wipeAuditRequest(request: Readonly<{ txViewingSk: Bytes32 }>): void {
  request.txViewingSk.fill(0);
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}

const U32_MAX = 0xffff_ffffn;
const NO_EXTENSIONS: FrameExtensions = Object.freeze({});
