/**
 * One transfer pipeline for every rail, Rust `pipeline`. The rail seals the outputs, the ring proof
 * opens them to the auditor and screens the ring's table, the SPP proof spends.
 */
import type { AccountMeta, Instruction } from "@solana/kit";

import {
  compressG2,
  encodeBase58,
  meta,
  treeAddress,
  bytesKey,
  equalBytes,
} from "@heliuslabs/zolana/internal";
import { type RingProver, type RingRecordReader } from "../../rpc/ports.js";
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
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";
import { SppProofInputs, createExternalData } from "@heliuslabs/zolana/transaction";
import type { ProofOutputUtxo } from "@heliuslabs/zolana/transaction";
import { CUSTOM_RING_PROOF_LENGTH } from "../../protocol/proof/custom-ring-proof.js";
import { ringAuthAddress, ringCoSignerMetas, ringPolicyAddress } from "../../protocol/pda/index.js";
import type { AuditLayout } from "../../protocol/codec/ring-disclosure-layout.js";
import { ringIdField } from "../../crypto/derivation/ring-stream.js";

import { RingInstructionTag, ringComputeUnitLimit } from "../management/admin.js";
import { sealAudit, sealedAuditMessage, type SealedAudit } from "../../proof/audit-proof.js";
import { ringRootRegistries, type RingPolicy } from "../../protocol/codec/ring-codecs.js";
import { demandedCoSigner, transactDemand } from "../../proof/cosign.js";
import { RingError } from "../../protocol/error.js";
import {
  exemptWithdrawals,
  policyRoots,
  readPolicy,
  screened,
  type BoundPolicy,
  type BoundRoot,
  type PolicyInputs,
} from "../../proof/policy-proof.js";
import { transferProofRequest } from "../../proof/transfer-proof.js";
import { policyWithdrawalHash } from "../../proof/withdrawals.js";
import type { PublishedSlot, RingOutputRail } from "../payments/output-rail.js";
import { ringTransferStatement, transferStatementHash } from "../../protocol/proof/statement.js";
import {
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  exitsBitmap,
  publishesRecipients,
  ringStreamLayout,
  ringSppInputs,
  type InputTrees,
  type PolicyProof,
  type PolicyRecipients,
  type RingRail,
  type SenderBundle,
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
import { checkTransferFits } from "./compile.js";
import type { ViewingHistory } from "../../state/viewing-history.js";

/** The client a ring transfer reads the ring and proves with, every rail adds its SPP prover. */
export type RingProvingClient = TreeContext &
  Pick<ChainReader, "getAccount"> &
  Pick<RingRecordReader, "getStorageMemberOpenings" | "getStorageRecordPool"> &
  RingProver;

/** What the anonymous rail adds to a staged transfer, Rust `AnonymousSpend`. */
export interface AnonymousSpendValues {
  readonly tokenOwner?: Address;
  /** Binds the signing co-signer, zero when none signs. */
  partyIdentities(coSigner: Address | undefined): readonly [Bytes32, Bytes32, Bytes32];
  /** Past the transfer's tags. */
  readonly viewingHistory: ViewingHistory;
}

/** How the SPP proof authorizes the spends of one rail, Rust `Spend`. */
export interface RailSpend {
  readonly rail: RingRail;
  /** The rail's SPP proof over the final inputs, the anonymous rail signs them inside it. */
  prove(
    proofInputs: SppProofInputs,
    coSigner: Address | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransact | ProvenAnonymousRingTransact>;
  /** Signs the transaction beside the payer on the delegate rail. */
  readonly delegate?: Address;
  readonly anonymous?: AnonymousSpendValues;
  /** The confidential rail's owner key when it signs inside the SPP proof. */
  readonly inProofOwner?: Bytes32;
}

/** A transfer past its outputs' sealing, ready for its statements, Rust `Staged`. */
export interface StagedTransfer {
  /** Sealed by the rail, before the auditor message joins the external data. */
  readonly proofInputs: SppProofInputs;
  readonly rail: RingOutputRail;
  readonly sender: ShieldedAddress;
  /** The confidential rail's owner signer run, empty on the other rails. */
  readonly ownerSigners: readonly Address[];
  readonly withdrawal?: TransactWithdrawal;
  readonly spend: RailSpend;
}

/** The accounts a ring transfer names besides its data, Rust `TransactAccounts`. */
export interface RingTransactAccounts {
  /** SPP's fee payer, the only signer an anonymous transfer takes. */
  readonly payer: Address;
  /** One per tree context, in the data's order. */
  readonly inputTrees: readonly Address[];
  readonly outputTree: Address;
  readonly ownerSigners: readonly Address[];
  readonly withdrawal?: TransactWithdrawal;
  /** Read only, right after the ring account, the records first. */
  readonly registries: readonly Address[];
  /** The supplied co-signer when the ring demands one, it signs beside its record. */
  readonly coSigner?: Address;
  readonly delegate?: Address;
}

/** Every value a transfer's proofs bind that the chain can move before it lands, Rust `BoundState`. */
export interface RingBoundState {
  /** The live roots the proofs bind by revision, the own root first. */
  readonly roots?: readonly BoundRoot[];
  readonly policy?: BoundPolicy;
}

/** A proven transfer, its compact data, accounts and the chain values its proofs bind, Rust `ProvenRingTransfer`. */
export class ProvenRingTransfer {
  readonly ringProgramId: Address;
  readonly data: RingTransactData;
  readonly accounts: RingTransactAccounts;
  /** Padding included, final slot order. */
  readonly outputs: readonly ProofOutputUtxo[];
  /** The supplied co-signer when the ring demands one, it signs the transaction. */
  readonly coSigner?: Address;
  readonly approvalRequired: boolean;
  /** The live roots the proofs bind, a submission proves again once one leaves its registry. */
  readonly roots: readonly BoundRoot[];
  readonly policy?: BoundPolicy;
  /** The anonymous sender's viewing history past the transfer's tags, stored before it is sent. */
  readonly viewingHistory?: ViewingHistory;

  /** @internal */
  constructor(fields: Omit<ProvenRingTransfer, "instruction">) {
    this.ringProgramId = fields.ringProgramId;
    this.data = fields.data;
    this.accounts = fields.accounts;
    this.outputs = fields.outputs;
    if (fields.coSigner !== undefined) this.coSigner = fields.coSigner;
    this.approvalRequired = fields.approvalRequired;
    this.roots = fields.roots;
    if (fields.policy !== undefined) this.policy = fields.policy;
    if (fields.viewingHistory !== undefined) this.viewingHistory = fields.viewingHistory;
    Object.freeze(this);
  }

  instruction(): Promise<Instruction> {
    return ringTransactInstruction(this.ringProgramId, this.accounts, this.data);
  }
}

/** What a staged transfer's proofs read, valid inside the `assembleStagedTransfer` callback. */
interface AssembledTransfer {
  readonly sealed: SealedAudit;
  readonly published: readonly PublishedSlot[];
  readonly publishedInputs: number;
  readonly proofInputs: SppProofInputs;
  readonly slots: PublicSlots;
  readonly senderPkHash: Bytes32;
  readonly policy: PolicyInputs;
  readonly coSigner: Address | undefined;
  /** Zeros off the anonymous rail. */
  readonly partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
  /** The statement's sender identity, zero where the rail names none. */
  readonly sender: Bytes32;
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
  /** Read only when the ring demands a co-signer, its record must cover the demand. */
  coSigner?: Address;
  transaction?: RingTransactionFrame;
  approve?: (coSigner: Address | undefined) => Promise<void>;
}>;

/** Rust `Pipeline::assemble` and `Assembled::prove`, neither proof is an input to the other. */
export function proveStagedTransfer(
  input: StagedTransferInput,
  context?: RequestContext,
): Promise<ProvenRingTransfer> {
  return assembleStagedTransfer(input, context, async (assembled) => {
    await input.approve?.(assembled.coSigner);
    return proveAssembled(input, assembled, context);
  });
}

/** A staged transfer whose external data is final, Rust `Sealed`, before any record read. */
export interface SealedTransfer {
  readonly sealed: SealedAudit;
  readonly audit: AuditLayout;
  readonly published: readonly PublishedSlot[];
  readonly publishedInputs: number;
  readonly senderBundle: SenderBundle | undefined;
  readonly shape: Shape;
  /** The owner signs its `messageHash`. */
  readonly proofInputs: SppProofInputs;
}

/** Rust `Pipeline::seal`, the caller wipes `sealed.ephemeralSecret`. */
export function sealStagedTransfer(
  input: Readonly<{
    ringProgramId: Address;
    config: RingPolicy;
    staged: Omit<StagedTransfer, "spend"> &
      Readonly<{ spend: Pick<RailSpend, "rail" | "inProofOwner"> }>;
  }>,
): SealedTransfer {
  const { ringProgramId, config, staged } = input;
  const { rail, sender, spend } = staged;
  const ringRail = spend.rail;
  checkDistinctInputs(staged.proofInputs);
  checkMembership(ringProgramId, staged.proofInputs);
  const shape = staged.proofInputs.checkShape();
  const publishedInputs = staged.proofInputs.inputUtxos.filter((spent) => !spent.isCompact());
  const published = rail.publishedSlots(staged.proofInputs, sender);
  const senderBundle = rail.publishedSender(staged.proofInputs);
  const audit: AuditLayout = Object.freeze({
    keyEscrow: config.keyEscrow,
    // A default-ring input takes the entry key, every commitment key refuses ring id zero.
    fullOpenings: ringRail === "anonymous" && spendsDefaultRing(staged.proofInputs),
  });
  const layout = ringStreamLayout({
    rail: ringRail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    inputs: publishedInputs.length,
    outputs: published.length,
    keyEscrow: audit.keyEscrow,
    fullOpenings: audit.fullOpenings,
    exits: exitsBitmap(published.map((slot) => slot.wire)),
    ownerInProof: spend.inProofOwner !== undefined,
  });
  const auditor = config.auditorPublicKey;
  // The auditor message precedes every hash over the external data.
  const sealed = sealAudit({
    rail,
    audit,
    layout,
    published,
    proofInputs: staged.proofInputs,
    sender,
    auditor,
  });
  try {
    return Object.freeze({
      sealed,
      audit,
      published,
      publishedInputs: publishedInputs.length,
      senderBundle,
      shape,
      proofInputs: withAuditorMessage(staged.proofInputs, sealedAuditMessage(sealed, auditor)),
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
  const { rail, sender, spend } = staged;
  const ringRail = spend.rail;
  const { sealed, audit, published, publishedInputs, senderBundle, shape, proofInputs } =
    sealStagedTransfer(input);
  const auditor = config.auditorPublicKey;
  try {
    const slots = publicSlots(proofInputs.externalData.interfaceTransfers);
    const senderPkHash = sender.signingPublicKey.ownerProofInputHash();
    const read = await readPolicy(
      {
        ...(spend.anonymous?.tokenOwner === undefined
          ? {}
          : { tokenOwnerHint: spend.anonymous.tokenOwner }),
        client,
        ringProgramId,
        config,
        rail: ringRail,
        proofInputs,
        publishedInputs,
        // The entry layout is the anonymous rail's, a confidential ring spends default-ring notes as any other.
        spendsDefaultRing: ringRail === "anonymous" && spendsDefaultRing(proofInputs),
        sender: senderPkHash,
        publicSlots: slots,
      },
      context,
    );
    const policy = await exemptWithdrawals(
      read,
      {
        client,
        ringProgramId,
        config,
        demand: transactDemand(proofInputs.externalData.interfaceTransfers),
        publicSlots: slots,
      },
      context,
    );
    const coSigner = await demandedCoSigner(
      {
        client,
        withdrawalExempt: policy.exempt,
        ringProgramId,
        config,
        approvalRequired: policy.approvalRequired,
        supplied: input.coSigner,
        transfers: proofInputs.externalData.interfaceTransfers,
        ownerSigners:
          spend.inProofOwner === undefined
            ? staged.ownerSigners
            : [...staged.ownerSigners, encodeBase58(spend.inProofOwner)],
        ...(spend.delegate === undefined ? {} : { delegate: spend.delegate }),
      },
      context,
    );
    const partyIdentities = spend.anonymous?.partyIdentities(coSigner) ?? [
      zeroField(),
      zeroField(),
      zeroField(),
    ];
    const privateTxHash = proofInputs.privateTxHash();
    // The signer rail names its sole owner under a policy alone, the in-proof owner is public in the frame.
    const statementSender =
      ringRail === "confidential" && (spend.inProofOwner !== undefined || screened(policy))
        ? senderPkHash
        : zeroField();
    const accounts: RingTransactAccounts = Object.freeze({
      payer: proofInputs.payer,
      inputTrees: Object.freeze(proofInputs.inputTreeIds().map(treeAddress)),
      outputTree: treeAddress(proofInputs.outputTreeId),
      ownerSigners: staged.ownerSigners,
      ...(staged.withdrawal === undefined ? {} : { withdrawal: staged.withdrawal }),
      registries: ringRootRegistries(config, policy.exempt ? "exemptTransfer" : "transfer"),
      ...(coSigner === undefined ? {} : { coSigner }),
      ...(spend.delegate === undefined ? {} : { delegate: spend.delegate }),
    });
    const ringId = ringIdField(ringProgramId);
    const preview = previewData({
      rail: ringRail,
      shape,
      audit,
      proofInputs,
      published,
      ...(senderBundle === undefined ? {} : { sender: senderBundle }),
      txViewingU: rail.txViewingKey.publicKey().u(),
      ephemeralU: sealed.ephemeralPublicKey.u(),
      envelope: sealed.envelope,
      records: sealed.records,
      privateTxHash,
      approvalRequired: policy.approvalRequired,
      exempt: policy.exempt,
      ...(policy.own === undefined ? {} : { ownRevision: policy.own.revision }),
      ...(screened(policy)
        ? {
            policy: {
              splWithdrawalOwners: policy.splWithdrawalOwners,
              ...(policy.curator === undefined ? {} : { curatorRevision: policy.curator.revision }),
              recipients: policyRecipients(ringRail, policy),
            },
          }
        : {}),
      ...(spend.inProofOwner === undefined ? {} : { inProofOwner: spend.inProofOwner }),
    });
    const publicInputHash = transferStatementHash(
      ringTransferStatement(preview, {
        ringId,
        auditorPubkey: auditor.toBytes(),
        keyEscrow: config.keyEscrow,
        sender: statementSender,
        partyIdentities,
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
          proofInputs.externalData.interfaceTransfers.map(settlementAccounts),
        ),
        proofInputs.externalData.hash(),
      )
    )
      throw new RingError("RING_EXTERNAL_DATA_MISMATCH");
    checkTransferFits(shape, {
      ...input.transaction,
      feePayer: proofInputs.payer,
      instructions: [await ringTransactInstruction(ringProgramId, accounts, preview)],
      computeUnitLimit: ringComputeUnitLimit(transactTag(ringRail)),
    });
    return await use(
      Object.freeze({
        sealed,
        published,
        publishedInputs,
        proofInputs,
        slots,
        senderPkHash,
        policy,
        coSigner,
        partyIdentities,
        sender: statementSender,
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
  const { rail, sender, spend } = staged;
  const { proofInputs, policy, coSigner, privateTxHash, ringId, preview } = assembled;
  const request = transferProofRequest({
    rail,
    ringRail: spend.rail,
    sealed: assembled.sealed,
    published: assembled.published,
    publishedInputs: assembled.publishedInputs,
    proofInputs,
    sender,
    auditor: config.auditorPublicKey,
    policy,
    proving: { ringId, publicSlots: assembled.slots },
    privateTxHash,
    publicInputHash: assembled.publicInputHash,
    statementSender: assembled.sender,
    senderPkHash: assembled.senderPkHash,
    inProof: spend.inProofOwner !== undefined,
    partyIdentities: assembled.partyIdentities,
  });
  let proofs: readonly [ProvenRingTransact | ProvenAnonymousRingTransact, Uint8Array];
  try {
    // Each request runs in its own async call, a synchronous throw never strands the other proof.
    proofs = await Promise.all([
      (async () => spend.prove(proofInputs, coSigner, context))(),
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
    publishedInputs: assembled.publishedInputs,
    proof,
  });
  return new ProvenRingTransfer({
    ringProgramId,
    data,
    accounts: assembled.accounts,
    outputs: proofInputs.outputs,
    ...(coSigner === undefined ? {} : { coSigner }),
    approvalRequired: policy.approvalRequired,
    roots: boundRoots(policy),
    ...(screened(policy)
      ? { policy: Object.freeze({ ringProgramId, policyHash: policy.policyHash }) }
      : {}),
    ...(spend.anonymous === undefined ? {} : { viewingHistory: spend.anonymous.viewingHistory }),
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
    ...(data.rail === "confidential" && accounts.ownerSigners.length > 0
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
  if (accounts.coSigner !== undefined)
    prefix.push(...(await ringCoSignerMetas(ringProgramId, accounts.coSigner)));
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
      txViewingPublicKey: external.txViewingPublicKey,
      salt: external.salt,
      outputs: external.outputs,
      resolvedOwnerTags: external.resolvedOwnerTags,
      messages: [...external.messages, message],
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
    audit: AuditLayout;
    proofInputs: SppProofInputs;
    published: readonly Readonly<{ wire: RingTransactData["outputs"][number] }>[];
    sender?: SenderBundle;
    txViewingU: Bytes32;
    ephemeralU: Bytes32;
    envelope: Uint8Array;
    records: readonly Uint8Array[];
    privateTxHash: Bytes32;
    approvalRequired: boolean;
    exempt: boolean;
    ownRevision?: bigint;
    policy?: PolicyProof;
    inProofOwner?: Bytes32;
  }>,
): RingTransactData {
  const external = input.proofInputs.externalData;
  const outputs = input.published.map((slot) => slot.wire);
  const zeroContext = { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 };
  const trees = input.proofInputs.inputTreeIds().length;
  const inputTrees: InputTrees =
    trees === 1
      ? { kind: "one", context: zeroContext }
      : { kind: "two", first: zeroContext, second: zeroContext, secondInputs: 0n };
  return Object.freeze({
    rail: input.rail,
    nIn: input.shape.inputs,
    nOut: input.shape.outputs,
    proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    ...(input.ownRevision === undefined ? {} : { ownRevision: input.ownRevision }),
    ...(input.policy === undefined ? {} : { policy: input.policy }),
    exempt: input.exempt,
    approvalRequired: input.approvalRequired,
    expiryUnixTs: Number(U32_MAX),
    txViewingU: input.txViewingU,
    salt: external.salt,
    interfaceTransfers: external.interfaceTransfers.map(interfaceTransferOf),
    keyEscrow: input.audit.keyEscrow,
    fullOpenings: input.audit.fullOpenings,
    outputs: Object.freeze(outputs),
    ...(input.sender === undefined ? {} : { sender: input.sender }),
    ephU: input.ephemeralU,
    envelope: input.envelope,
    records: input.records,
    privateTxHash: input.privateTxHash,
    ...(input.rail === "anonymous"
      ? {
          anonymous: {
            commitment: zeroField(),
            commitmentPok: zeroField(),
            // SPP names the hidden owner's key exactly when a default-ring note is spent.
            ...(input.audit.fullOpenings ? { defaultOwnerTag: zeroField() } : {}),
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
    nullifiers: Object.freeze(
      input.proofInputs.inputUtxos
        .filter((spent) => !spent.isCompact())
        .map((spent) => spent.nullifier()),
    ),
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
  const proofData = circuit.kind === "anonymousRingEddsa" ? circuit.proofData : undefined;
  const commitment =
    proofData === undefined
      ? undefined
      : {
          commitment: proofData.bsb22Commitment.commitment,
          commitmentPok: proofData.bsb22Commitment.commitmentPok,
        };
  const anonymous =
    commitment !== undefined && preview.rail === "anonymous"
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
      (preview.rail === "anonymous" || preview.inProofOwner !== undefined) ||
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

function policyRecipients(rail: RingRail, policy: PolicyInputs): PolicyRecipients {
  return publishesRecipients(rail)
    ? { kind: "framed", recipients: policy.recipients }
    : { kind: "hidden" };
}

export function spendsDefaultRing(proofInputs: SppProofInputs): boolean {
  return proofInputs.inputUtxos.some(
    (spent) => !spent.isCompact() && !spent.isDummy() && spent.utxo.ringProgramId === undefined,
  );
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
    ...(proven.policy === undefined ? {} : { policy: proven.policy }),
  });
}

function boundRoots(policy: PolicyInputs): readonly BoundRoot[] {
  return Object.freeze(
    [policy.own, policy.curator].filter((root): root is BoundRoot => root !== undefined),
  );
}

function transactTag(rail: RingRail): RingInstructionTag {
  return rail === "delegate" ? RingInstructionTag.authorityTransfer : RingInstructionTag.transfer;
}

function wipeAuditRequest(request: Readonly<{ txViewingSk: Bytes32; ephSk: Bytes32 }>): void {
  request.txViewingSk.fill(0);
  request.ephSk.fill(0);
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}

const U32_MAX = 0xffff_ffffn;
