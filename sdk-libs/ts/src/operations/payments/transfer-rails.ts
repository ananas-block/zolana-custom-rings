/** The rails of a ring transfer, Rust `RingTransfer<Owner>`, `<Anonymous>`, `<PublicOwners>` and `<Delegated>`. */
import { getBase58Decoder, getBase64Decoder, type Signature } from "@solana/kit";

import {
  encodeBase58,
  equalBytes,
  ownerSignerAddresses,
  prepareRingAuthorityTransfer,
  addressBytes,
} from "@heliuslabs/zolana/internal";
import type { AnonymousRingTransactProver } from "../../rpc/ports.js";
import type {
  PreparedOwnerSignature,
  ProofAuthority,
  Prover,
  WalletKeys,
} from "@heliuslabs/zolana/client";
import { type Shape, InstructionTag } from "@heliuslabs/zolana/interface";
import type {
  Address,
  Bytes32,
  RequestContext,
  TransactWithdrawal,
} from "@heliuslabs/zolana/interface";
import { associatedTokenAddress } from "@heliuslabs/zolana/internal";
import type { NullifierKey, ShieldedAddress } from "@heliuslabs/zolana/keypair";
import type { TokenAccountCreate } from "../../rpc/relay-message.js";
import { ShieldedPublicKey, ViewingKey } from "@heliuslabs/zolana/keypair";
import type {
  AssetRegistry,
  ProofInputUtxo,
  ProofOutputUtxo,
  SettlementTransfer,
  SppProofInputs,
  WalletUtxo,
} from "@heliuslabs/zolana/transaction";
import {
  createProofOutput,
  SOL_MINT,
  type ConfidentialTransfer,
  type PreparedTransfer,
  type WithdrawalTarget,
} from "@heliuslabs/zolana/transaction";
import { encodeRelayProofInputs } from "../../protocol/ring-rpc/relay-proof-inputs.js";
import type {
  RelayIntent,
  RelayQuote,
  TokenAccountSetup,
} from "../../protocol/ring-rpc/ring-rpc-types.js";
import { PreparedRelay } from "../../rpc/relay.js";

import {
  anonymousExitTokenOwner,
  checkAnonymousSigner,
  checkHiddenParties,
  checkHiddenOwnerSpends,
  checkEntryInputs,
  type AnonymousPayment,
  type AnonymousSpendSigner,
} from "./anonymous.js";
import type { RingPolicy } from "../../protocol/codec/ring-codecs.js";
import { fetchRingPolicy, requireActiveRing } from "../../protocol/membership/config.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import {
  isAnonymousFrame,
  ringRail,
  type FrameExtensions,
} from "../../protocol/transaction/transact.js";
import { RingError } from "../../protocol/error.js";
import { relayListSalts, type RingListSalt } from "../../proof/policy-proof.js";
import { anonymousPartyIdentities } from "../../protocol/membership/parties.js";
import {
  proveStagedTransfer,
  sealRelayedTransfer,
  sealedTransferTerms,
  type AnonymousSpendValues,
  type ProvenRingTransfer,
  type RailSpend,
  type RingProvingClient,
  type RingTransactionFrame,
  type StagedTransfer,
  type StagedTransferInput,
} from "../workflow/pipeline.js";
import { isSmallOrder } from "../../crypto/keys/x25519.js";
import { AnonymousPlan, RingOutputRail } from "./output-rail.js";
import {
  checkCoOwnerKeys,
  checkZeroKeyInputs,
  ringSpendAuthority,
  standIn,
  type CoOwner,
} from "./ring-spend.js";

const base58 = getBase58Decoder();
const base64 = getBase64Decoder();

/** @internal */
export interface RingTransferApproval {
  readonly transaction: RingTransactionFrame;
  /** Runs once the transfer fits its transaction, before any proof. */
  approve(
    transfer: Readonly<{ prepared: PreparedTransfer; coSigners: readonly Address[] }>,
  ): Promise<void>;
}

export type CustomRingTransferClient = RingProvingClient &
  Pick<Prover, "proveRingTransact"> &
  AnonymousRingTransactProver;

export type AnonymousTransferClient = RingProvingClient & AnonymousRingTransactProver;

export type DelegateTransferClient = RingProvingClient &
  Pick<Prover, "proveRingAuthorityTransact" | "proveRingAuthorityExitTransact">;

/** Public owners settle on SPP's confidential rail on either ring mode. */
export type PublicOwnerTransferClient = RingProvingClient & Pick<Prover, "proveRingTransact">;

/** Rust `CustomRingTransferInput`. */
export interface CustomRingTransferInput {
  readonly ringProgramId: Address;
  /** Reads the sender's address and transaction keys and completes its inputs, no secret leaves it. */
  readonly keys: WalletKeys;
  /** Prepared by the rail, every output it already holds keeps its slot. */
  readonly transfer: ConfidentialTransfer;
  readonly assets: AssetRegistry;
  /** Read in order while a demanded class stays uncovered. */
  readonly coSigners?: readonly Address[];
  /** Every enrolled owner a salted list reads, the sender and the recipients alike. */
  readonly listSalts?: readonly RingListSalt[];
  /** SPP's optional fields the frame carries through. */
  readonly extensions?: FrameExtensions;
  /** Past one transaction the frame settles from a buffer its payer writes. */
  readonly bufferedSettlement?: boolean;
}

/** The confidential rail, the owner signs its spends in public or inside the proof, Rust `RingTransfer<Owner>`. */
export class CustomRingTransfer {
  readonly #input: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;
  readonly #inProofOwner: AnonymousSpendSigner | undefined;
  readonly #coOwners: readonly CoOwner[];

  private constructor(
    input: CustomRingTransferInput,
    withdrawal: TransactWithdrawal | undefined,
    inProofOwner: AnonymousSpendSigner | undefined,
    coOwners: readonly CoOwner[] = [],
  ) {
    this.#input = input;
    this.#withdrawal = withdrawal;
    this.#inProofOwner = inProofOwner;
    this.#coOwners = coOwners;
    Object.freeze(this);
  }

  static new(input: CustomRingTransferInput): CustomRingTransfer {
    input.transfer.withRingProgramId(input.ringProgramId);
    return new CustomRingTransfer(input, undefined, undefined);
  }

  withBufferedSettlement(): CustomRingTransfer {
    return new CustomRingTransfer(
      { ...this.#input, bufferedSettlement: true },
      this.#withdrawal,
      this.#inProofOwner,
      this.#coOwners,
    );
  }

  /** The settlement accounts of the transfer's public withdrawal, Rust `with_interface_transfer_accounts`. */
  withWithdrawalAccounts(withdrawal: TransactWithdrawal): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, withdrawal, this.#inProofOwner, this.#coOwners);
  }

  /** The sender's signing key signs inside the proof, any fee payer sends the transaction, Rust `with_in_proof_owner`. */
  withInProofOwner(signer: AnonymousSpendSigner): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, this.#withdrawal, signer, this.#coOwners);
  }

  /** A co-owner of `ringSpendTransfer` inputs signs the transaction. */
  withCoOwner(coOwner: CoOwner): CustomRingTransfer {
    return new CustomRingTransfer(this.#input, this.#withdrawal, this.#inProofOwner, [
      ...this.#coOwners,
      Object.freeze({ ...coOwner }),
    ]);
  }

  /** `wallet` signs in public and may spend its zero-key notes, nothing selects them for it, Rust `spend_public`. */
  spendPublic(wallet: Address): PublicOwnerTransfer {
    return PublicOwnerTransfer.of({
      owner: this.#input,
      ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
      wallet,
      inProofOwner: this.#inProofOwner !== undefined,
      coOwners: this.#coOwners,
    });
  }

  /** The hidden Ed25519 owner an anonymous ring proves, it must be the sender's signing key. */
  withAnonymousSigner(signer: AnonymousSpendSigner): AnonymousTransfer {
    return AnonymousTransfer.of({
      owner: this.#input,
      ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
      signer,
      coOwners: this.#coOwners,
    });
  }

  prove(client: CustomRingTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: CustomRingTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  /** Rust `prepare_relay`, the in-proof owner signs the message hash, the wallet reads no Merkle path and no record. */
  prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    context?: RequestContext,
  ): Promise<PreparedRelay> {
    return this.#prepareRelay(client, input, undefined, context);
  }

  /** @internal */
  prepareRelayApproved(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<PreparedRelay> {
    return this.#prepareRelay(client, input, approval, context);
  }

  async #prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<PreparedRelay> {
    const { ringProgramId, keys } = this.#input;
    const signer = this.#inProofOwner;
    if (signer === undefined) throw new RingError("RING_IN_PROOF_OWNER_MISMATCH");
    const { quote } = input;
    const { config, staged, prepared, owner } = await this.#stage(client, context);
    try {
      if (owner === undefined) throw new RingError("RING_IN_PROOF_OWNER_MISMATCH");
      if (prepared.payer !== quote.feePayer)
        throw new RingError("RING_RELAY_PAYER_MISMATCH", {
          details: { payer: prepared.payer, feePayer: quote.feePayer },
        });
      await approval?.approve({ prepared, coSigners: [] });
      const sealed = sealRelayedTransfer({
        ringProgramId,
        config,
        staged: { ...staged, spend: { rail: "confidential", inProofOwner: owner } },
      });
      let payload: Uint8Array | undefined;
      try {
        const { proofInputs } = sealed;
        const ownerSignature = await signer.sign(proofInputs.messageHash(), context);
        payload = encodeRelayProofInputs({
          rail: { kind: "confidential" },
          ringProgramId,
          sender: keys.address(),
          nullifierKey: input.nullifierKey,
          txViewingKey: staged.rail.txViewingKey,
          inputs: proofInputs.inputUtxos,
          leafIndexes: proofInputs.inputUtxos.map((spent) => leafIndexOf(spent, input.notes)),
          outputs: proofInputs.outputs,
          externalData: proofInputs.externalData,
          ...(staged.withdrawal === undefined ? {} : { withdrawal: staged.withdrawal }),
          blindingSeed: proofInputs.blindingSeed,
          outputTreeId: proofInputs.outputTreeId,
          wideOwners: sealed.wideOwners,
          assets: this.#input.assets,
          listSalts: relayListSalts(config, this.#input.listSalts ?? []),
          coOwners: this.#coOwners,
        });
        const coSigners = this.#input.coSigners ?? [];
        const terms = sealedTransferTerms({
          ringProgramId,
          feePayer: quote.feePayer,
          sealed,
          ownerSigners: staged.ownerSigners,
          setup: await tokenAccountCreates(input.tokenAccountSetup, staged.withdrawal),
        });
        return new PreparedRelay(
          {
            ring: ringProgramId,
            quote,
            ...(coSigners.length === 0 ? {} : { coSigners }),
            intent: {
              operation: "confidential",
              proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
              ownerSignature: base58.decode(ownerSignature) as Signature,
              ...(input.tokenAccountSetup === undefined
                ? {}
                : { tokenAccountSetup: input.tokenAccountSetup }),
            },
          },
          Object.freeze({ kind: "sealed", terms }),
        );
      } finally {
        payload?.fill(0);
        sealed.sealed.ephemeralSecret.fill(0);
      }
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  async #prove(
    client: CustomRingTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const { ringProgramId } = this.#input;
    const { config, staged, prepared, owner } = await this.#stage(client, context);
    try {
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: { ...staged, spend: this.#spend(client, owner) },
          bufferedSettlement: this.#input.bufferedSettlement === true,
          ...suppliedCoSigners(this.#input.coSigners),
          listSalts: this.#input.listSalts ?? [],
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  /** The confidential rail's SPP proof, the in-proof owner signs the final inputs inside it. */
  #spend(client: CustomRingTransferClient, owner: Bytes32 | undefined): RailSpend {
    const { ringProgramId, keys } = this.#input;
    const signer = this.#inProofOwner;
    if (signer === undefined || owner === undefined)
      return {
        rail: "confidential",
        prove: (inputs, proveContext) =>
          client.proveRingTransact(
            inputs,
            ringProgramId,
            ringSpendAuthority({
              keys,
              coOwners: this.#coOwners,
              proofInputs: inputs,
              sender: keys.address(),
            }),
            { outputTree: client },
            proveContext,
          ),
      };
    return {
      rail: "confidential",
      inProofOwner: owner,
      // SPP's anonymous rail hides the owner, the statement publishes it.
      prove: async (inputs, proveContext) =>
        client.proveAnonymousRingTransact(
          {
            proofInputs: inputs,
            ringProgramId,
            owner: await preparedOwnerSignature(signer, owner, inputs, proveContext),
            keys: ringSpendAuthority({
              keys,
              coOwners: this.#coOwners,
              proofInputs: inputs,
              sender: keys.address(),
            }),
            config: { outputTree: client },
          },
          proveContext,
        ),
    };
  }

  /** The caller destroys `staged.rail.txViewingKey`. */
  async #stage(
    client: Pick<RingProvingClient, "getAccount">,
    context: RequestContext | undefined,
  ): Promise<
    Readonly<{
      config: RingPolicy;
      staged: Omit<StagedTransfer, "spend">;
      prepared: PreparedTransfer;
      owner: Bytes32 | undefined;
    }>
  > {
    const { ringProgramId, keys } = this.#input;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.mode === "anonymous")
      throw new RingError("RING_ANONYMOUS_SIGNER_REQUIRED", { details: { ringProgramId } });
    const sender = keys.address();
    const owner = inProofOwnerKey(this.#inProofOwner, sender);
    const prepared = this.#input.transfer.prepare();
    checkWithdrawalAccounts(prepared, this.#withdrawal);
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      { kind: "delivered" },
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#input.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      checkZeroKeyInputs(proofInputs.inputUtxos, sender.signingPublicKey);
      if (owner !== undefined) checkRingNotes(proofInputs);
      checkSlotsOpenable(proofInputs);
      // An in-proof owner may sit beside signing co-owners, the run names them alone.
      const ownerSigners = ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.outputs, owner);
      if (!spendsNothing(proofInputs) && owner === undefined && ownerSigners.length === 0)
        throw new RingError("RING_NO_SIGNING_OWNER");
      checkCoOwnerKeys(proofInputs, sender, this.#coOwners);
      return {
        config,
        prepared,
        owner,
        staged: {
          proofInputs,
          rail,
          sender,
          ownerSigners,
          ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
          ...(this.#input.extensions === undefined ? {} : { extensions: this.#input.extensions }),
        },
      };
    } catch (cause) {
      rail.txViewingKey.destroy();
      throw cause;
    }
  }
}

async function preparedOwnerSignature(
  signer: AnonymousSpendSigner,
  owner: Bytes32,
  proofInputs: SppProofInputs,
  context: RequestContext | undefined,
): Promise<PreparedOwnerSignature> {
  return {
    ownerPublicKey: owner,
    ownerSignature: await signer.sign(proofInputs.messageHash(), context),
  };
}

/** SPP's anonymous rail publishes the owner of a default-ring input, Rust `RingError::InProofDefaultRingInput`. */
function checkRingNotes(proofInputs: SppProofInputs): void {
  checkSlotsOpenable(proofInputs);
  const index = proofInputs.inputUtxos.findIndex(
    (spent) => !spent.isCompact() && !spent.isDummy() && spent.utxo.ringProgramId === undefined,
  );
  if (index >= 0) throw new RingError("RING_IN_PROOF_DEFAULT_RING_INPUT", { details: { index } });
}

/** Every rail opens its inputs, no address input and no cached slot opens. */
function checkSlotsOpenable(proofInputs: SppProofInputs): void {
  const index = proofInputs.inputUtxos.findIndex(
    (spent) => spent.isAddress() || spent.cacheSlot !== undefined,
  );
  if (index >= 0)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "UnopenableInput", index },
    });
}

/** `R` is zero, the transfer takes public funds alone. */
function spendsNothing(proofInputs: SppProofInputs): boolean {
  return proofInputs.inputUtxos.every((spent) => spent.isDummy() || spent.isCompact());
}

/** The signer must hold the sender's signing key. */
function inProofOwnerKey(
  signer: AnonymousSpendSigner | undefined,
  sender: ShieldedAddress,
): Bytes32 | undefined {
  if (signer === undefined) return undefined;
  const signing = signer.publicKey();
  if (!(signing instanceof ShieldedPublicKey) || !signing.equals(sender.signingPublicKey))
    throw new RingError("RING_IN_PROOF_OWNER_MISMATCH");
  return signing.ed25519();
}

/** The hidden owner's spends on an anonymous ring, no transaction signer names the owner, Rust `RingTransfer<Anonymous>`. */
export class AnonymousTransfer {
  readonly #owner: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;
  readonly #signer: AnonymousSpendSigner;
  /** In declared order, the order of their ring outputs. */
  readonly #payments: readonly AnonymousPayment[];
  readonly #shape: Shape | undefined;
  readonly #exitTokenOwner: Address | undefined;
  readonly #coOwners: readonly CoOwner[];

  private constructor(fields: AnonymousFields) {
    this.#owner = fields.owner;
    this.#withdrawal = fields.withdrawal;
    this.#signer = fields.signer;
    this.#payments = fields.payments;
    this.#shape = fields.shape;
    this.#exitTokenOwner = fields.exitTokenOwner;
    this.#coOwners = fields.coOwners;
    Object.freeze(this);
  }

  /** @internal */
  static of(
    input: Readonly<{
      owner: CustomRingTransferInput;
      withdrawal?: TransactWithdrawal;
      signer: AnonymousSpendSigner;
      coOwners?: readonly CoOwner[];
    }>,
  ): AnonymousTransfer {
    return new AnonymousTransfer({
      owner: input.owner,
      withdrawal: input.withdrawal,
      signer: input.signer,
      payments: Object.freeze([]),
      shape: undefined,
      exitTokenOwner: undefined,
      coOwners: input.coOwners ?? [],
    });
  }

  /** A public co-owner of later `ringSpendTransfer` inputs signs the transaction. */
  withCoOwner(coOwner: CoOwner): AnonymousTransfer {
    return new AnonymousTransfer({
      ...this.#fields(),
      coOwners: [...this.#coOwners, Object.freeze({ ...coOwner })],
    });
  }

  /** Every ring output owner other than the sender is paid here, Rust `with_payment`. */
  withPayment(payment: AnonymousPayment): AnonymousTransfer {
    if (payment.to.ringProgramId !== this.#owner.ringProgramId)
      throw new RingError("RING_FOREIGN_RING", {
        details: { address: payment.to.ringProgramId, ring: this.#owner.ringProgramId },
      });
    this.#owner.transfer.sendToRing(
      payment.to.recipient,
      payment.asset,
      payment.amount,
      payment.to.ringProgramId,
    );
    return new AnonymousTransfer({
      ...this.#fields(),
      payments: Object.freeze([...this.#payments, Object.freeze({ ...payment })]),
    });
  }

  withBufferedSettlement(): AnonymousTransfer {
    return new AnonymousTransfer({
      ...this.#fields(),
      owner: { ...this.#owner, bufferedSettlement: true },
    });
  }

  /** Pads to `shape`, else the transfer takes the smallest supported shape. */
  withShape(shape: Shape): AnonymousTransfer {
    this.#owner.transfer.withShape(shape);
    return new AnonymousTransfer({ ...this.#fields(), shape });
  }

  /** A missing exit token account must be the owner's associated token account. */
  withExitTokenOwner(owner: Address): AnonymousTransfer {
    return new AnonymousTransfer({ ...this.#fields(), exitTokenOwner: owner });
  }

  prove(client: AnonymousTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: AnonymousTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: AnonymousTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const { ringProgramId, keys } = this.#owner;
    const { config, staged, prepared, owner } = await this.#stage(client, context);
    try {
      const spend: StagedTransfer["spend"] = {
        rail: "anonymous",
        anonymous: staged.anonymous,
        prove: async (inputs, proveContext) =>
          client.proveAnonymousRingTransact(
            {
              proofInputs: inputs,
              ringProgramId,
              owner: await preparedOwnerSignature(this.#signer, owner, inputs, proveContext),
              keys: ringSpendAuthority({
                keys,
                coOwners: this.#coOwners,
                proofInputs: inputs,
                sender: keys.address(),
              }),
              config: { outputTree: client },
            },
            proveContext,
          ),
      };
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          staged: { ...staged, spend },
          ...suppliedCoSigners(this.#owner.coSigners),
          listSalts: this.#owner.listSalts ?? [],
          bufferedSettlement: this.#owner.bufferedSettlement === true,
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  /** Rust `prepare_relay`, the wallet reads no Merkle path and no record. */
  async prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    context?: RequestContext,
  ): Promise<PreparedRingRelay> {
    return this.#prepareRelay(client, input, undefined, context);
  }

  /** @internal */
  prepareRelayApproved(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<PreparedRingRelay> {
    return this.#prepareRelay(client, input, approval, context);
  }

  async #prepareRelay(
    client: Pick<RingProvingClient, "getAccount">,
    input: RingRelayInput,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<PreparedRingRelay> {
    const { ringProgramId, keys } = this.#owner;
    const { quote } = input;
    const { config, staged, prepared } = await this.#stage(client, context);
    try {
      if (prepared.payer !== quote.feePayer)
        throw new RingError("RING_RELAY_PAYER_MISMATCH", {
          details: { payer: prepared.payer, feePayer: quote.feePayer },
        });
      await approval?.approve({ prepared, coSigners: [] });
      const sealed = sealRelayedTransfer({
        ringProgramId,
        config,
        staged: { ...staged, spend: { rail: "anonymous" } },
      });
      let payload: Uint8Array | undefined;
      try {
        const { proofInputs } = sealed;
        const ownerSignature = await this.#signer.sign(proofInputs.messageHash(), context);
        const plan = staged.rail.delivery;
        if (plan.kind !== "anonymous") throw new RingError("RING_NOT_ANONYMOUS");
        payload = encodeRelayProofInputs({
          rail: {
            kind: "anonymous",
            plan: plan.plan,
            ...(this.#exitTokenOwner === undefined ? {} : { exitTokenOwner: this.#exitTokenOwner }),
          },
          ringProgramId,
          sender: keys.address(),
          nullifierKey: input.nullifierKey,
          txViewingKey: staged.rail.txViewingKey,
          inputs: proofInputs.inputUtxos,
          leafIndexes: proofInputs.inputUtxos.map((spent) => leafIndexOf(spent, input.notes)),
          outputs: proofInputs.outputs,
          externalData: proofInputs.externalData,
          ...(staged.withdrawal === undefined ? {} : { withdrawal: staged.withdrawal }),
          blindingSeed: proofInputs.blindingSeed,
          outputTreeId: proofInputs.outputTreeId,
          wideOwners: sealed.wideOwners,
          assets: this.#owner.assets,
          listSalts: relayListSalts(config, this.#owner.listSalts ?? []),
          coOwners: spendingCoOwners(staged.ownerSigners, proofInputs.inputUtxos, this.#coOwners),
        });
        const coSigners = this.#owner.coSigners ?? [];
        const terms = sealedTransferTerms({
          ringProgramId,
          feePayer: quote.feePayer,
          sealed,
          ownerSigners: staged.ownerSigners,
          setup: await tokenAccountCreates(input.tokenAccountSetup, staged.withdrawal),
        });
        return Object.freeze({
          relay: new PreparedRelay(
            {
              ring: ringProgramId,
              quote,
              ...(coSigners.length === 0 ? {} : { coSigners }),
              intent: {
                operation: "anonymous",
                proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
                ownerSignature: base58.decode(ownerSignature) as Signature,
                ...(input.tokenAccountSetup === undefined
                  ? {}
                  : { tokenAccountSetup: input.tokenAccountSetup }),
              },
            },
            Object.freeze({ kind: "sealed", terms }),
          ),
        });
      } finally {
        payload?.fill(0);
        sealed.sealed.ephemeralSecret.fill(0);
      }
    } finally {
      staged.rail.txViewingKey.destroy();
    }
  }

  /** The caller destroys `staged.rail.txViewingKey`. */
  async #stage(
    client: Pick<RingProvingClient, "getAccount">,
    context: RequestContext | undefined,
  ): Promise<
    Readonly<{
      config: RingPolicy;
      staged: Omit<StagedTransfer, "spend"> & Readonly<{ anonymous: AnonymousSpendValues }>;
      prepared: PreparedTransfer;
      owner: Bytes32;
      exitTokenOwner: Address | undefined;
    }>
  > {
    const { ringProgramId, keys } = this.#owner;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.mode !== "anonymous")
      throw new RingError("RING_NOT_ANONYMOUS", { details: { ringProgramId } });
    const sender = keys.address();
    const prepared = this.#owner.transfer.prepare();
    checkWithdrawalAccounts(prepared, this.#withdrawal);
    const owner = checkAnonymousSigner({
      signer: this.#signer,
      sender,
      payer: prepared.payer,
    });
    const exitTokenOwner = await anonymousExitTokenOwner(
      {
        client,
        transfers: prepared.interfaceTransfers,
        hiddenOwner: owner,
        ...(this.#exitTokenOwner === undefined ? {} : { tokenOwner: this.#exitTokenOwner }),
      },
      context,
    );
    const solExit = prepared.interfaceTransfers.find((t) => t.kind === "sol" && !t.isDeposit);
    const destination = solExit?.kind === "sol" ? solExit.userSolAccount : exitTokenOwner;
    if (destination !== undefined && exitTokenOwner !== undefined && destination !== exitTokenOwner)
      throw new RingError("RING_ANONYMOUS_EXIT_DESTINATIONS_DIFFER");
    if (this.#payments.some((payment) => isSmallOrder(payment.to.recipient.viewingPublicKey)))
      throw new RingError("RING_RECIPIENT_KEY_NOT_CONTRIBUTORY");
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      { kind: "anonymous", plan: anonymousPlan(this.#payments) },
      this.#payments.map((payment) => payment.data),
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#owner.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      checkSlotsOpenable(proofInputs);
      checkZeroKeyInputs(proofInputs.inputUtxos, sender.signingPublicKey);
      const coOwners = ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.outputs, owner);
      checkHiddenOwnerSpends(proofInputs, sender);
      checkEntryInputs(proofInputs, ownerSignerAddresses(proofInputs.inputUtxos, [], owner));
      checkCoOwnerKeys(proofInputs, sender, this.#coOwners);
      const staged = {
        proofInputs,
        rail,
        sender,
        ownerSigners: coOwners,
        ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
        ...(this.#owner.extensions === undefined ? {} : { extensions: this.#owner.extensions }),
        anonymous: {
          ...(exitTokenOwner === undefined ? {} : { tokenOwner: exitTokenOwner }),
          partyIdentities: (coSigners: readonly Address[]) => {
            checkHiddenParties(owner, [prepared.payer, ...coSigners]);
            return anonymousPartyIdentities({
              payer: prepared.payer,
              coSigners,
              ...(destination === undefined ? {} : { exitDestination: destination }),
            });
          },
        },
      };
      return Object.freeze({ config, staged, prepared, owner, exitTokenOwner });
    } catch (cause) {
      rail.txViewingKey.destroy();
      throw cause;
    }
  }

  #fields(): AnonymousFields {
    return {
      owner: this.#owner,
      withdrawal: this.#withdrawal,
      signer: this.#signer,
      payments: this.#payments,
      shape: this.#shape,
      exitTokenOwner: this.#exitTokenOwner,
      coOwners: this.#coOwners,
    };
  }
}

interface AnonymousFields {
  readonly owner: CustomRingTransferInput;
  readonly withdrawal: TransactWithdrawal | undefined;
  readonly signer: AnonymousSpendSigner;
  readonly payments: readonly AnonymousPayment[];
  readonly shape: Shape | undefined;
  readonly exitTokenOwner: Address | undefined;
  readonly coOwners: readonly CoOwner[];
}

/** Every live owner signs in public, recipients stay hidden on an anonymous ring, Rust `RingTransfer<PublicOwners>`. */
export class PublicOwnerTransfer {
  readonly #owner: CustomRingTransferInput;
  readonly #withdrawal: TransactWithdrawal | undefined;
  readonly #wallet: Address;
  readonly #inProofOwner: boolean;
  readonly #coOwners: readonly CoOwner[];
  /** In declared order, the order of their ring outputs. */
  readonly #payments: readonly AnonymousPayment[];

  private constructor(fields: PublicOwnerFields) {
    this.#owner = fields.owner;
    this.#withdrawal = fields.withdrawal;
    this.#wallet = fields.wallet;
    this.#inProofOwner = fields.inProofOwner;
    this.#coOwners = fields.coOwners;
    this.#payments = fields.payments;
    Object.freeze(this);
  }

  /** @internal */
  static of(
    input: Readonly<{
      owner: CustomRingTransferInput;
      withdrawal?: TransactWithdrawal;
      wallet: Address;
      inProofOwner: boolean;
      coOwners: readonly CoOwner[];
    }>,
  ): PublicOwnerTransfer {
    return new PublicOwnerTransfer({
      ...input,
      withdrawal: input.withdrawal,
      payments: Object.freeze([]),
    });
  }

  /** Every ring output owner other than the wallet is paid here, Rust `with_payment`. */
  withPayment(payment: AnonymousPayment): PublicOwnerTransfer {
    checkPaymentRing(payment, this.#owner.ringProgramId);
    this.#owner.transfer.sendToRing(
      payment.to.recipient,
      payment.asset,
      payment.amount,
      payment.to.ringProgramId,
    );
    return new PublicOwnerTransfer({
      owner: this.#owner,
      withdrawal: this.#withdrawal,
      wallet: this.#wallet,
      inProofOwner: this.#inProofOwner,
      coOwners: this.#coOwners,
      payments: Object.freeze([...this.#payments, Object.freeze({ ...payment })]),
    });
  }

  withBufferedSettlement(): PublicOwnerTransfer {
    return new PublicOwnerTransfer({
      owner: { ...this.#owner, bufferedSettlement: true },
      withdrawal: this.#withdrawal,
      wallet: this.#wallet,
      inProofOwner: this.#inProofOwner,
      coOwners: this.#coOwners,
      payments: this.#payments,
    });
  }

  prove(client: PublicOwnerTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: PublicOwnerTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: PublicOwnerTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const { ringProgramId, keys } = this.#owner;
    const sender = keys.address();
    if (encodeBase58(sender.signingPublicKey.ed25519()) !== this.#wallet)
      throw new RingError("RING_PUBLIC_SPEND_WALLET_MISMATCH", {
        details: { named: this.#wallet, sender: encodeBase58(sender.signingPublicKey.ed25519()) },
      });
    if (this.#inProofOwner) throw new RingError("RING_PUBLIC_SPEND_IN_PROOF_OWNER");
    const config = await activeConfig(client, ringProgramId, context);
    const anonymous = config.mode === "anonymous";
    const prepared = this.#owner.transfer.prepare();
    checkWithdrawalAccounts(prepared, this.#withdrawal);
    if (
      anonymous &&
      this.#payments.some((payment) => isSmallOrder(payment.to.recipient.viewingPublicKey))
    )
      throw new RingError("RING_RECIPIENT_KEY_NOT_CONTRIBUTORY");
    const rail = new RingOutputRail(
      await transactionKey(keys, sender, prepared, context),
      prepared.firstNullifier,
      anonymous
        ? { kind: "anonymous", plan: anonymousPlan(this.#payments) }
        : { kind: "delivered" },
      this.#payments.map((payment) => payment.data),
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender,
        assets: this.#owner.assets,
        instructionDiscriminator: InstructionTag.ringTransact,
      });
      checkSlotsOpenable(proofInputs);
      checkCoOwnerKeys(proofInputs, sender, this.#coOwners);
      const ownerSigners = ownerSignerAddresses(proofInputs.inputUtxos, proofInputs.outputs);
      const prove: RailSpend["prove"] = (inputs, proveContext) =>
        client.proveRingTransact(
          inputs,
          ringProgramId,
          ringSpendAuthority({
            keys,
            coOwners: this.#coOwners,
            proofInputs: inputs,
            sender,
          }),
          { outputTree: client },
          proveContext,
        );
      const spend: RailSpend = anonymous
        ? {
            rail: "anonymous",
            publicOwners: true,
            prove,
            anonymous: {
              partyIdentities: (coSigners) =>
                anonymousPartyIdentities({ payer: prepared.payer, coSigners }),
            },
          }
        : { rail: "confidential", prove };
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          bufferedSettlement: this.#owner.bufferedSettlement === true,
          staged: {
            proofInputs,
            rail,
            sender,
            ownerSigners,
            ...(this.#withdrawal === undefined ? {} : { withdrawal: this.#withdrawal }),
            ...(this.#owner.extensions === undefined ? {} : { extensions: this.#owner.extensions }),
            spend,
          },
          ...suppliedCoSigners(this.#owner.coSigners),
          listSalts: this.#owner.listSalts ?? [],
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      rail.txViewingKey.destroy();
    }
  }
}

interface PublicOwnerFields {
  readonly owner: CustomRingTransferInput;
  readonly withdrawal: TransactWithdrawal | undefined;
  readonly wallet: Address;
  readonly inProofOwner: boolean;
  readonly coOwners: readonly CoOwner[];
  readonly payments: readonly AnonymousPayment[];
}

function checkPaymentRing(payment: AnonymousPayment, ringProgramId: Address): void {
  if (payment.to.ringProgramId !== ringProgramId)
    throw new RingError("RING_FOREIGN_RING", {
      details: { address: payment.to.ringProgramId, ring: ringProgramId },
    });
}

function anonymousPlan(payments: readonly AnonymousPayment[]): AnonymousPlan {
  return payments.reduce(
    (planned, payment) =>
      planned.withPayment({
        recipient: payment.to.recipient.viewingPublicKey,
        reply: payment.reply,
      }),
    AnonymousPlan.create(),
  );
}

/** One output of a delegate move. */
export interface DelegateOutput {
  readonly recipient: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  /** Pays a default-ring note under SPP's `ring_authority_exit` circuit. */
  readonly exit?: boolean;
}

/** A delegate's public withdrawal, its settlement accounts named. */
export interface DelegateWithdrawal {
  readonly asset: Address;
  readonly amount: bigint;
  readonly target: WithdrawalTarget;
  readonly accounts: TransactWithdrawal;
}

/** Rust `DelegateTransferInput`. */
export interface DelegateTransferInput {
  readonly ringProgramId: Address;
  /** Signs the transaction beside the payer. */
  readonly delegate: Address;
  readonly payer: Address;
  /** The member whose notes move, its change returns to it. */
  readonly source: ShieldedAddress;
  /** Completes the source's inputs with the key the delegate recovered. */
  readonly sourceProofs: ProofAuthority;
  readonly inputs: readonly ProofInputUtxo[];
  /** Owners of the inputs `source` does not own. */
  readonly coSources?: readonly CoOwner[];
  /** The key the signed request names, fresh unless named. */
  readonly txViewingKey?: Bytes32;
  readonly outputs: readonly DelegateOutput[];
  readonly withdrawal?: DelegateWithdrawal;
  readonly assets: AssetRegistry;
  /** The outputs land in the first input's tree unless named. */
  readonly outputTreeId?: number;
  /** Past one transaction the frame settles from a buffer its payer writes. */
  readonly bufferedSettlement?: boolean;
}

/** The delegate moves one member's notes with the member's key, the member does not sign, Rust `RingTransfer<Delegated>`. */
export class DelegateTransfer {
  readonly #input: DelegateTransferInput;

  private constructor(input: DelegateTransferInput) {
    this.#input = input;
    Object.freeze(this);
  }

  static new(input: DelegateTransferInput): DelegateTransfer {
    return new DelegateTransfer(input);
  }

  withBufferedSettlement(): DelegateTransfer {
    return new DelegateTransfer({ ...this.#input, bufferedSettlement: true });
  }

  withTxViewingKey(txViewingKey: Bytes32): DelegateTransfer {
    return new DelegateTransfer({ ...this.#input, txViewingKey });
  }

  withCoSource(coSource: CoOwner): DelegateTransfer {
    return new DelegateTransfer({
      ...this.#input,
      coSources: [...(this.#input.coSources ?? []), Object.freeze({ ...coSource })],
    });
  }

  prove(client: DelegateTransferClient, context?: RequestContext): Promise<ProvenRingTransfer> {
    return this.#prove(client, undefined, context);
  }

  /** @internal */
  proveApproved(
    client: DelegateTransferClient,
    approval: RingTransferApproval,
    context?: RequestContext,
  ): Promise<ProvenRingTransfer> {
    return this.#prove(client, approval, context);
  }

  async #prove(
    client: DelegateTransferClient,
    approval: RingTransferApproval | undefined,
    context: RequestContext | undefined,
  ): Promise<ProvenRingTransfer> {
    const input = this.#input;
    const { ringProgramId } = input;
    const config = await activeConfig(client, ringProgramId, context);
    if (config.delegate === undefined)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "missing" } });
    if (config.delegate !== input.delegate)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "unauthorized" } });
    const railKind = ringRail(RingInstructionTag.authorityTransfer, config);
    const coSources = input.coSources ?? [];
    const named = coSources.map((coSource) =>
      ShieldedPublicKey.fromEd25519(addressBytes(coSource.owner) as Bytes32),
    );
    if (
      input.inputs.some(
        (spent) =>
          !spent.utxo.owner.equals(input.source.signingPublicKey) &&
          !named.some((owner) => spent.utxo.owner.equals(owner)),
      )
    )
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "mixedOwners" } });
    const first = input.inputs[0];
    if (first === undefined)
      throw new RingError("RING_DELEGATE_INVALID", { details: { reason: "inputs" } });
    const prepared = prepareDelegateTransfer({
      input,
      outputTreeId: input.outputTreeId ?? first.treeId,
    });
    checkWithdrawalAccounts(prepared, input.withdrawal?.accounts);
    const hasExit = input.outputs.some((output) => output.exit === true);
    // The member never signs, the transaction key seals the move to the auditor.
    const rail = new RingOutputRail(
      input.txViewingKey === undefined
        ? ViewingKey.generate()
        : ViewingKey.fromBytes(input.txViewingKey.slice() as Bytes32),
      prepared.firstNullifier,
      isAnonymousFrame(railKind)
        ? { kind: "anonymous", plan: delegatePlan(input.outputs) }
        : { kind: "delivered" },
    );
    try {
      const proofInputs = rail.encrypt({
        prepared,
        sender: input.source,
        assets: input.assets,
        instructionDiscriminator: InstructionTag.ringAuthorityTransact,
      });
      checkCoOwnerKeys(proofInputs, input.source, coSources);
      return await proveStagedTransfer(
        {
          client,
          ringProgramId,
          config,
          bufferedSettlement: input.bufferedSettlement === true,
          staged: {
            proofInputs,
            rail,
            sender: input.source,
            ownerSigners: [],
            ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal.accounts }),
            spend: {
              rail: railKind,
              delegate: input.delegate,
              ...(isAnonymousFrame(railKind)
                ? {
                    anonymous: {
                      partyIdentities: (coSigners: readonly Address[]) =>
                        anonymousPartyIdentities({ payer: prepared.payer, coSigners }),
                    },
                  }
                : {}),
              prove: (inputs, proveContext) =>
                (hasExit
                  ? client.proveRingAuthorityExitTransact
                  : client.proveRingAuthorityTransact
                ).call(
                  client,
                  inputs,
                  ringProgramId,
                  ringSpendAuthority({
                    keys: input.sourceProofs,
                    coOwners: coSources,
                    proofInputs: inputs,
                    sender: input.source,
                  }),
                  proveContext,
                  client,
                ),
            },
          },
          ...approvedStage(approval, prepared),
        },
        context,
      );
    } finally {
      rail.txViewingKey.destroy();
    }
  }
}

/** Ring outputs in declared order, an exit carries no payment. */
function delegatePlan(outputs: readonly DelegateOutput[]): AnonymousPlan {
  return outputs
    .filter((output) => output.exit !== true)
    .reduce(
      (planned, output) =>
        planned.withPayment({ recipient: output.recipient.viewingPublicKey, reply: null }),
      AnonymousPlan.create(),
    );
}

/** SPP's authority builder takes no leg, the withdrawal holds a slot through its change sum and leaves padding. */
function prepareDelegateTransfer(
  params: Readonly<{ input: DelegateTransferInput; outputTreeId: number }>,
): PreparedTransfer {
  const { input, outputTreeId } = params;
  const { withdrawal } = input;
  const planned = {
    owner: input.source,
    inputs: input.inputs.map((spent) => standIn(spent, input.source)),
    payer: input.payer,
    ringProgramId: input.ringProgramId,
    outputTreeId,
  };
  const spendingReal = (prepared: PreparedTransfer): PreparedTransfer =>
    Object.freeze({ ...prepared, inputs: Object.freeze([...input.inputs]) });
  if (withdrawal === undefined)
    return spendingReal(prepareRingAuthorityTransfer({ ...planned, outputs: input.outputs }));
  const prepared = prepareRingAuthorityTransfer({
    ...planned,
    outputs: [
      ...input.outputs,
      { recipient: input.source, asset: withdrawal.asset, amount: withdrawal.amount },
    ],
  });
  const leg = prepared.outputs.length - 1;
  return spendingReal({
    ...prepared,
    interfaceTransfers: Object.freeze([settlementLeg(withdrawal)]),
    outputs: Object.freeze(prepared.outputs.slice(0, leg)),
    proofOutputs: () =>
      Object.freeze(
        prepared
          .proofOutputs()
          .map((output, slot) =>
            slot === leg ? delegatePadding(input.ringProgramId, output.blinding) : output,
          ),
      ),
  });
}

function delegatePadding(ringProgramId: Address, blinding: Bytes32): ProofOutputUtxo {
  return createProofOutput({ asset: SOL_MINT, amount: 0n, blinding, ringProgramId });
}

function settlementLeg(withdrawal: DelegateWithdrawal): SettlementTransfer {
  const { target, amount, asset } = withdrawal;
  return target.kind === "sol"
    ? { kind: "sol", isDeposit: false, amount, userSolAccount: target.recipient }
    : {
        kind: "spl",
        mint: asset,
        isDeposit: false,
        amount,
        tokenAccount: target.recipientTokenAccount,
        splInterfaceBump: target.splInterfaceBump,
      };
}

function suppliedCoSigners(
  coSigners: readonly Address[] | undefined,
): Pick<StagedTransferInput, "coSigners"> {
  return coSigners === undefined ? {} : { coSigners };
}

/** A held co-owner spending nothing keeps its secret from Ring RPC. */
function spendingCoOwners(
  ownerSigners: readonly Address[],
  inputs: readonly ProofInputUtxo[],
  coOwners: readonly CoOwner[],
): readonly CoOwner[] {
  return ownerSigners.flatMap((owner) => {
    const key = ShieldedPublicKey.fromEd25519(addressBytes(owner) as Bytes32);
    const held = coOwners.find((coOwner) => coOwner.owner === owner);
    const spends = inputs.some((spent) => !spent.isDummy() && spent.utxo.owner.equals(key));
    return held !== undefined && spends ? [held] : [];
  });
}

/** Rust `RelayProofInputs::token_account_setup`, each account the withdrawal pays. */
async function tokenAccountCreates(
  setup: readonly TokenAccountSetup[] | undefined,
  withdrawal: TransactWithdrawal | undefined,
): Promise<readonly TokenAccountCreate[]> {
  const created = new Set<Address>();
  return Promise.all(
    (setup ?? []).map(async (entry, index) => {
      const refused = (): RingError =>
        new RingError("RING_RELAY_PROOF_INPUTS", {
          details: { reason: "tokenAccountSetup", index },
        });
      if (withdrawal?.kind !== "spl" || withdrawal.mint !== entry.mint) throw refused();
      const { tokenProgram } = withdrawal;
      const account = await associatedTokenAddress(entry.owner, entry.mint, tokenProgram);
      if (account !== withdrawal.recipientTokenAccount || created.has(account)) throw refused();
      created.add(account);
      return Object.freeze({ owner: entry.owner, mint: entry.mint, tokenProgram });
    }),
  );
}

/** The approval a pipeline runs, bound to the prepared transfer the rail proves. */
function approvedStage(
  approval: RingTransferApproval | undefined,
  prepared: PreparedTransfer,
): Pick<StagedTransferInput, "transaction" | "approve"> {
  if (approval === undefined) return {};
  return {
    transaction: approval.transaction,
    approve: (coSigners) => approval.approve({ prepared, coSigners }),
  };
}

/** The ring's config once SPP's registration admits it, Rust `require_config` and `require_active`. */
async function activeConfig(
  client: Pick<RingProvingClient, "getAccount">,
  ringProgramId: Address,
  context: RequestContext | undefined,
): Promise<RingPolicy> {
  const [config] = await Promise.all([
    fetchRingPolicy(client, ringProgramId, context),
    requireActiveRing(client, ringProgramId, context),
  ]);
  return config;
}

/** The sender's transaction key, derived by its key holder from the first nullifier. */
async function transactionKey(
  keys: WalletKeys,
  sender: ShieldedAddress,
  prepared: PreparedTransfer,
  context: RequestContext | undefined,
): Promise<ViewingKey> {
  const derived = await keys.transactionKeys(
    [{ viewingPublicKey: sender.viewingPublicKey, firstNullifier: prepared.firstNullifier }],
    context,
  );
  const [key, ...extra] = derived;
  for (const surplus of extra) surplus.destroy();
  if (key === undefined)
    throw new RingError("RING_KEYS_REQUIRED", { details: { reason: "transactionKey" } });
  return key;
}

/** A public withdrawal names its settlement accounts, a transfer without one names none. */
function checkWithdrawalAccounts(
  prepared: PreparedTransfer,
  withdrawal: TransactWithdrawal | undefined,
): void {
  const leg = prepared.interfaceTransfers.find((transfer) => !transfer.isDeposit);
  const matches =
    leg === undefined
      ? withdrawal === undefined
      : withdrawal !== undefined &&
        (leg.kind === "sol"
          ? withdrawal.kind === "sol" && withdrawal.recipient === leg.userSolAccount
          : withdrawal.kind === "spl" &&
            withdrawal.mint === leg.mint &&
            withdrawal.recipientTokenAccount === leg.tokenAccount);
  if (!matches) throw new RingError("RING_SETTLEMENT_ACCOUNTS_INVALID");
}

export interface RingRelayInput {
  /** Names the fee payer the transfer pays from. */
  readonly quote: RelayQuote;
  /** Ring RPC proves with it and so links every spend of the owner. */
  readonly nullifierKey: NullifierKey;
  /** The wallet notes the transfer spends, each names its leaf. */
  readonly notes: readonly WalletUtxo[];
  /** Ring RPC creates each account before the withdrawal pays it. */
  readonly tokenAccountSetup?: readonly TokenAccountSetup[];
}

export interface PreparedRingRelay {
  readonly relay: PreparedRelay;
}

/** A padding slot names no leaf. */
function leafIndexOf(input: ProofInputUtxo, notes: readonly WalletUtxo[]): bigint {
  if (input.isDummy()) return 0n;
  const note = notes.find((entry) => equalBytes(entry.nullifier, input.nullifier()));
  if (note === undefined)
    throw new RingError("RING_RELAY_PROOF_INPUTS", { details: { reason: "leafIndex" } });
  return note.outputContext.leafIndex;
}
