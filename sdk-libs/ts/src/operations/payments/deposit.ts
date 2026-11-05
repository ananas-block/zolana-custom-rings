import {
  getBase58Decoder,
  getBase64Decoder,
  type Instruction,
  type MessagePartialSigner,
} from "@solana/kit";

import { type RingProver } from "../../rpc/ports.js";
import { encodeRingDepositPlaintext } from "../../protocol/codec/ring-deposit-plaintext.js";
import {
  bigIntBytes,
  compileUnsignedTransaction,
  mergeMintChunks,
  resolveDepositSettlement,
  signerAddress,
  waitForProjection,
  ZERO_32,
  resolveShieldedRecipient,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import { checkIntentApproval, type SignerAccount } from "@heliuslabs/zolana/internal";
import type {
  Address,
  Bytes32,
  RequestContext,
  RingAssetDeposit,
  Signature,
  Transaction,
} from "@heliuslabs/zolana/interface";
import {
  randomBlinding,
  randomSalt,
  ShieldedAddress,
  ViewingKey,
} from "@heliuslabs/zolana/keypair";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  assetField,
  SOL_MINT,
  Data,
  Utxo,
  ownerUtxoHash,
  approveUnattended,
  intentHash,
  type ApprovalHandler,
  type TransactionIntent,
} from "@heliuslabs/zolana/transaction";
import type { DepositClient } from "@heliuslabs/zolana/wallet";
import type { DepositProofRequest } from "../../rpc/prover/ring.js";
import { depositBlinding } from "../../crypto/derivation/ring-domain.js";

import { checkHiddenParties } from "./anonymous.js";
import { type RingPolicy } from "../../protocol/codec/ring-codecs.js";
import { RecordKind } from "../../protocol/codec/audit-stream.js";
import { fetchRingPolicy } from "../../protocol/membership/config.js";
import {
  readDepositSection,
  relayListSalts,
  type PolicyReadClient,
} from "../../proof/policy-proof.js";
import { ringIdField } from "../../crypto/derivation/ring-stream.js";
import { DEPOSIT_DEMAND, demandRequirement, resolveRingCoSigners } from "../../proof/cosign.js";
import { type RingDepositCapsule } from "../../protocol/codec/deposit-capsule.js";
import {
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
  type DepositedAsset,
} from "../../proof/deposit-audit.js";
import {
  ringDepositInstruction,
  ringDepositSpp,
} from "../../protocol/transaction/deposit-instruction.js";
import { RingError, wrapRingError } from "../../protocol/error.js";
import type { BoundRoot } from "../../rpc/registered-record.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "../../rpc/projection.js";
import { type RingKeys } from "../../state/ring-keys.js";
import { RingAddress, type RingPaymentRequest } from "../../crypto/keys/ring-address.js";
import { isSmallOrder } from "../../crypto/keys/x25519.js";
import type { ViewingHistory } from "../../state/viewing-history.js";
import {
  depositRequestDigest,
  encodeRelayDepositInputs,
} from "../../protocol/ring-rpc/relay-deposit-inputs.js";
import type { RelayIntent, RelayQuote } from "../../protocol/ring-rpc/ring-rpc-types.js";
import { PreparedRelay } from "../../rpc/relay.js";
import { expectedDeposit, mismatch } from "../../rpc/relay-message.js";
import { signMessage } from "../../rpc/ring-rpc.js";
import { ringIntentMismatch } from "../workflow/selection.js";
import { depositRootRead, ringRegistrySlots } from "../workflow/ring-reads.js";
import { boundCredentialRoots, type BoundCredentialRoot } from "../../proof/credential-proof.js";
import { RingTransactionSubmission, type RingSubmissionAttempt } from "../workflow/submission.js";
import { assetLabel } from "./transfer.js";

const base64 = getBase64Decoder();

/** Rust `compute_unit_limit(Deposit)`. */
export const RING_DEPOSIT_COMPUTE_UNIT_LIMIT = 1_400_000;

/** Who a deposit pays, Rust `DepositRecipient`. */
export type RingDepositRecipient =
  /** A confidential ring member, found under its viewing key's tag. */
  | Readonly<{ kind: "confidential"; address: Address | ShieldedAddress; listSalt?: Bytes32 }>
  /** The depositor's own hidden identity on an anonymous ring, under its next sender tag. */
  | Readonly<{ kind: "anonymous"; keys: RingKeys; history: ViewingHistory; listSalt?: Bytes32 }>
  /** Another member of an anonymous ring, under a request's deposit tag. */
  | Readonly<{ kind: "anonymousPayment"; to: RingAddress | RingPaymentRequest }>;

type TaggedRecipient = Readonly<{
  address: ShieldedAddress;
  viewTag: Bytes32;
  history?: ViewingHistory;
  /** An enrolled recipient on a ring reading a salted list needs it. */
  listSalt?: Bytes32;
}>;

export type RingDepositClient = DepositClient & PolicyReadClient & RingProver;

export interface RingDepositParams {
  readonly client: RingDepositClient;
  readonly ringProgramId: Address;
  readonly feePayer: Address;
  /** Funds the deposit, the fee payer when absent. */
  readonly depositor?: SignerAccount;
  readonly tree?: Address;
  readonly recipient: RingDepositRecipient;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
  /** Signs when a record covers deposits, the record must be its own. */
  readonly cosigner?: SignerAccount;
}

/** Rust `RingDeposit::prepare_relay`. */
export interface RingDepositRelayParams extends DepositSealingParams {
  /** The depositor's key, Ring RPC proves nothing for an unsigned request. */
  readonly depositorSigner: MessagePartialSigner;
  readonly quote: RelayQuote;
  readonly approve?: ApprovalHandler;
}

/** Store `viewingHistory` in place of the old one before `relay.send`. */
export interface PreparedRingDepositRelay {
  readonly relay: PreparedRelay;
  readonly viewingHistory?: ViewingHistory;
}

type DepositSealingParams = Omit<
  RingDepositParams,
  "client" | "feePayer" | "depositor" | "cosigner"
> &
  Readonly<{
    client: DepositClient;
    /** Funds the deposit and signs its message. */
    depositor: SignerAccount;
  }>;

/** The proof binds the key's Solana owner identity into the owner hash. */
type DisclosedOwner = Readonly<{ kind: "confidential" | "anonymous"; key: Bytes32 }>;

type DepositSealing = Readonly<{
  config: RingPolicy;
  recipient: TaggedRecipient;
  owner: DisclosedOwner;
  asset: Address;
  settlement: RingAssetDeposit["asset"];
}>;

/** A proven deposit with the registry roots its proof binds. */
export interface ProvenRingDeposit {
  readonly instruction: Instruction;
  /** The own root a policy ring's proof binds by revision, then any curator root. */
  readonly roots?: readonly BoundRoot[];
  /** The credential roots the proof binds, reread from their tree accounts. */
  readonly credentialRoots: readonly BoundCredentialRoot[];
}

/** Rust `DepositRecords`. */
type DepositRecords = Awaited<ReturnType<typeof readDepositSection>> &
  Readonly<{
    /** The live registries the deposit passes after the ring account. */
    registries: readonly Address[];
  }>;

/** A deposit whose note and auditor ciphertext every proof reuses, Rust `PreparedRingDeposit`. */
export class PreparedRingDeposit {
  /** The note the deposit creates. */
  readonly utxo: Utxo;
  /** The depositor's viewing history past the deposit's tag, stored before it is sent. */
  readonly viewingHistory?: ViewingHistory;
  readonly #ringProgramId: Address;
  readonly #tree: Address;
  readonly #recipient: ShieldedAddress;
  readonly #depositor: SignerAccount;
  readonly #cosigner: SignerAccount | undefined;
  readonly #deposit: RingAssetDeposit;
  readonly #capsule: RingDepositCapsule;
  readonly #contextHash: Bytes32;
  readonly #ownerPkHash: Bytes32;
  readonly #nullifierPk: Bytes32;
  readonly #owner: DisclosedOwner;
  readonly #auditor: X25519PublicKey;
  readonly #mint: Address;
  readonly #asset: DepositedAsset;
  readonly #blindingSecret: Bytes32;
  readonly #ephemeralSecret: Bytes32;
  readonly #listSalt: Bytes32 | undefined;
  #proved = false;

  private constructor(state: {
    utxo: Utxo;
    viewingHistory: ViewingHistory | undefined;
    ringProgramId: Address;
    tree: Address;
    recipient: ShieldedAddress;
    depositor: SignerAccount;
    cosigner: SignerAccount | undefined;
    deposit: RingAssetDeposit;
    capsule: RingDepositCapsule;
    contextHash: Bytes32;
    ownerPkHash: Bytes32;
    nullifierPk: Bytes32;
    owner: DisclosedOwner;
    auditor: X25519PublicKey;
    mint: Address;
    asset: DepositedAsset;
    blindingSecret: Bytes32;
    ephemeralSecret: Bytes32;
    listSalt: Bytes32 | undefined;
  }) {
    this.utxo = state.utxo;
    if (state.viewingHistory !== undefined) this.viewingHistory = state.viewingHistory;
    this.#ringProgramId = state.ringProgramId;
    this.#tree = state.tree;
    this.#recipient = state.recipient;
    this.#depositor = state.depositor;
    this.#cosigner = state.cosigner;
    this.#deposit = state.deposit;
    this.#capsule = state.capsule;
    this.#contextHash = state.contextHash;
    this.#ownerPkHash = state.ownerPkHash;
    this.#nullifierPk = state.nullifierPk;
    this.#owner = state.owner;
    this.#auditor = state.auditor;
    this.#mint = state.mint;
    this.#asset = state.asset;
    this.#blindingSecret = state.blindingSecret;
    this.#ephemeralSecret = state.ephemeralSecret;
    this.#listSalt = state.listSalt;
  }

  /** Fixes the note against the ring's mode, co-signer and auditor. */
  static async prepare(
    params: RingDepositParams,
    context?: RequestContext,
  ): Promise<PreparedRingDeposit> {
    try {
      const depositor = params.depositor ?? params.feePayer;
      const sealingParams = { ...params, depositor };
      const sealing = await depositSealing(sealingParams, context);
      checkDepositSigners(sealing, [params.feePayer, depositor, params.cosigner]);
      // An optional class with no configured record demands nothing.
      const demanded = demandRequirement(DEPOSIT_DEMAND, sealing.config) !== undefined;
      if (demanded)
        await resolveRingCoSigners(
          {
            client: params.client,
            ringProgramId: params.ringProgramId,
            config: sealing.config,
            demand: DEPOSIT_DEMAND,
            supplied: params.cosigner === undefined ? [] : [signerAddress(params.cosigner)],
            ownerSigners: [],
          },
          context,
        );
      return PreparedRingDeposit.#seal({
        params: sealingParams,
        sealing,
        cosigner: demanded ? params.cosigner : undefined,
        tree: params.tree ?? params.client.tree,
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  }

  /** Reads no record, Ring RPC answers with the message the depositor signs. */
  static async prepareRelay(
    params: RingDepositRelayParams,
    context?: RequestContext,
  ): Promise<PreparedRingDepositRelay> {
    let prepared: PreparedRingDeposit | undefined;
    let payload: Uint8Array | undefined;
    try {
      if (params.depositorSigner.address !== signerAddress(params.depositor))
        throw mismatch("Signer");
      const sealing = await depositSealing(params, context);
      checkDepositSigners(sealing, [params.quote.feePayer, params.depositor]);
      prepared = await PreparedRingDeposit.#seal({
        params,
        sealing,
        cosigner: undefined,
        tree: params.tree ?? params.client.tree,
      });
      const intent = prepared.intent();
      const approval = await (params.approve ?? approveUnattended)({
        solanaPublicKey: signerAddress(params.depositor),
        intent,
        summary: `ring deposit of ${String(params.amount)} ${assetLabel(sealing.asset)} into ring ${params.ringProgramId}`,
      });
      checkIntentApproval(approval, intent, ringIntentMismatch);
      payload = encodeRelayDepositInputs({
        ringProgramId: prepared.#ringProgramId,
        tree: prepared.#tree,
        depositor: signerAddress(prepared.#depositor),
        recipient: prepared.#recipient,
        listSalt:
          prepared.#listSalt === undefined
            ? ZERO_32
            : (relayListSalts(sealing.config, [
                { owner: prepared.#ownerPkHash, salt: prepared.#listSalt },
              ])[0]?.salt ?? ZERO_32),
        deposit: prepared.#deposit,
        blindingSecret: prepared.#blindingSecret,
        auditEphemeralKey: prepared.#ephemeralSecret,
      });
      const depositorSignature = getBase58Decoder().decode(
        await signMessage(params.depositorSigner, depositRequestDigest(payload)),
      ) as Signature;
      const expected = await expectedDeposit({
        ringProgramId: prepared.#ringProgramId,
        feePayer: params.quote.feePayer,
        tree: prepared.#tree,
        depositor: signerAddress(prepared.#depositor),
        deposit: prepared.#deposit,
      });
      return Object.freeze({
        relay: new PreparedRelay(
          {
            ring: params.ringProgramId,
            quote: params.quote,
            intent: {
              operation: "deposit",
              proofInputs: base64.decode(payload) as RelayIntent["proofInputs"],
              depositorSignature,
            },
          },
          expected,
        ),
        ...(prepared.viewingHistory === undefined
          ? {}
          : { viewingHistory: prepared.viewingHistory }),
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    } finally {
      payload?.fill(0);
      prepared?.destroy();
    }
  }

  /** A second proof is refused, a resent note would stay unspendable, a retry prepares a new one. */
  async prove(client: RingDepositClient, context?: RequestContext): Promise<ProvenRingDeposit> {
    if (this.#proved) throw new RingError("RING_DEPOSIT_FRAME_REUSED");
    this.#proved = true;
    try {
      const records = await this.#records(client, context);
      const { capacity, own, curator, credentials } = records;
      const commitment = this.#deposit.ownerUtxoHash;
      const pad = (values: readonly Bytes32[]): readonly Bytes32[] => [
        ...values,
        ...Array.from({ length: capacity - values.length }, () => ZERO_32),
      ];
      const {
        registries,
        credentials: _credentials,
        own: _own,
        curator: _curator,
        ...sections
      } = records;
      const request: DepositProofRequest = {
        ...sections,
        kind: "deposit",
        publicInputHash: ringDepositPublicInputHash({
          contextHash: this.#contextHash,
          ownerCommitments: [commitment],
          capsules: [this.#capsule],
          assets: [this.#asset],
          auditorPublicKey: this.#auditor,
          ringId: ringIdField(this.#ringProgramId),
          credentials: credentials.inputs.credentialRoots,
          ...(own === undefined
            ? {}
            : {
                registry: {
                  ownRoot: own.root,
                  ...(curator === undefined ? {} : { curatorRoot: curator.root }),
                  policyHash: records.policyHash,
                },
              }),
        }),
        contextHash: this.#contextHash,
        count: 1,
        ownerPkHashes: pad([this.#ownerPkHash]),
        ownerKeys: pad([this.#owner.key]),
        nullifierPks: pad([this.#nullifierPk]),
        blindingSecrets: pad([this.#blindingSecret]),
        ephSk: this.#ephemeralSecret,
        auditorPk: this.#auditor.u(),
        assets: pad([this.#asset.asset]),
        amounts: pad([bigIntBytes(this.#asset.amount, 32) as Bytes32]),
        mintChunks: [
          mergeMintChunks(this.#mint).map((chunk) => bigIntBytes(chunk, 32) as Bytes32),
          ...Array.from({ length: capacity - 1 }, () => [ZERO_32, ZERO_32]),
        ],
      };
      const proof = await client.proveRing(request, context);
      return Object.freeze({
        instruction: await ringDepositInstruction({
          ringProgramId: this.#ringProgramId,
          tree: this.#tree,
          depositor: this.#depositor,
          deposits: [this.#deposit],
          keyCapacity: capacity,
          proof,
          registries,
          credentialRead: credentials.read,
          credentialTrees: credentials.trees.metas(),
          ...(own === undefined ? {} : { ownRevision: own.revision }),
          ...(curator === undefined ? {} : { curatorRevision: curator.revision }),
          ...(this.#cosigner === undefined ? {} : { cosigner: this.#cosigner }),
        }),
        credentialRoots: boundCredentialRoots(credentials),
        ...(own === undefined
          ? {}
          : { roots: Object.freeze(curator === undefined ? [own] : [own, curator]) }),
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  }

  /** @internal */
  intent(): TransactionIntent {
    return {
      kind: "ringDeposit",
      ringProgramId: this.#ringProgramId,
      asset: this.utxo.asset,
      amount: this.utxo.amount,
      recipient: this.#recipient,
    };
  }

  /** Wipes the blinding secret and the auditor sealing key. */
  destroy(): void {
    this.#blindingSecret.fill(0);
    this.#ephemeralSecret.fill(0);
  }

  #records(
    client: RingDepositClient,
    context: RequestContext | undefined,
  ): Promise<DepositRecords> {
    return waitForProjection(
      async (attempt) => {
        const config = await fetchRingPolicy(client, this.#ringProgramId, attempt);
        const section = await readDepositSection(
          {
            client,
            ringProgramId: this.#ringProgramId,
            ringId: ringIdField(this.#ringProgramId),
            config,
            recipient: this.#recipient.signingPublicKey,
            nullifierPk: this.#nullifierPk,
            asset: this.#asset.asset,
            listSalts:
              this.#listSalt === undefined
                ? []
                : [{ owner: this.#ownerPkHash, salt: this.#listSalt }],
          },
          attempt,
        );
        return Object.freeze({
          ...section,
          registries: ringRegistrySlots(config, depositRootRead(config)),
        });
      },
      MEMBER_REGISTRY_PROJECTION_ERRORS,
      context,
    );
  }

  /** The note, its recipient ciphertext and the auditor capsule, sealed under fresh secrets. */
  static async #seal(
    input: Readonly<{
      params: DepositSealingParams;
      sealing: DepositSealing;
      cosigner: SignerAccount | undefined;
      tree: Address;
    }>,
  ): Promise<PreparedRingDeposit> {
    const { params, sealing } = input;
    const { recipient } = sealing;
    const blindingSecret = randomBlinding();
    const blinding = depositBlinding(blindingSecret);
    const ownerHash = recipient.address.ownerHash();
    const envelope = ViewingKey.generate();
    const plaintext = encodeRingDepositPlaintext({
      blinding,
      ...(params.memo === undefined ? {} : { memo: params.memo }),
      ringData: new Uint8Array(),
    });
    let ephemeralSecret: Bytes32 | undefined;
    try {
      const salt = randomSalt();
      const sealed = sealRingDepositOpenings(
        [
          {
            record: {
              kind: RecordKind.ring,
              amount: params.amount,
              ownerKey: sealing.owner.key,
              mint: sealing.asset,
              nullifierPk: recipient.address.nullifierPublicKey,
            },
            blinding,
            recipientCiphertext: envelope.encryptRingDeposit(
              recipient.address.viewingPublicKey,
              plaintext,
              salt,
            ),
          },
        ],
        sealing.config.auditorPublicKey,
      );
      ephemeralSecret = sealed.ephemeralSecret;
      const [capsule] = sealed.capsules;
      const [payload] = sealed.payloads;
      if (capsule === undefined || payload === undefined) throw new RingError("RING_BUILD_DEPOSIT");
      const deposit: RingAssetDeposit = Object.freeze({
        asset: sealing.settlement,
        viewTag: recipient.viewTag,
        ownerUtxoHash: ownerUtxoHash(ownerHash, blinding),
        amount: params.amount,
        ringDataHash: ZERO_32,
        encrypted: Object.freeze({
          txViewingPublicKey: envelope.publicKey().toBytes(),
          salt,
          ciphertext: payload,
        }),
      });
      const spp = await ringDepositSpp({
        ringProgramId: params.ringProgramId,
        tree: input.tree,
        depositor: params.depositor,
        deposits: [deposit],
      });
      const prepared = new PreparedRingDeposit({
        utxo: new Utxo({
          owner: recipient.address.signingPublicKey,
          asset: sealing.asset,
          amount: params.amount,
          blinding,
          data: new Data(),
          ringProgramId: params.ringProgramId,
        }),
        viewingHistory: recipient.history,
        ringProgramId: params.ringProgramId,
        tree: input.tree,
        recipient: recipient.address,
        depositor: params.depositor,
        cosigner: input.cosigner,
        deposit,
        capsule,
        contextHash: ringDepositContextHash(params.ringProgramId, input.tree, spp.data),
        ownerPkHash: recipient.address.signingPublicKey.ownerProofInputHash(),
        nullifierPk: recipient.address.nullifierPublicKey,
        owner: sealing.owner,
        auditor: sealing.config.auditorPublicKey,
        mint: sealing.asset,
        asset: Object.freeze({ asset: assetField(sealing.asset), amount: params.amount }),
        blindingSecret,
        ephemeralSecret,
        listSalt: recipient.listSalt,
      });
      ephemeralSecret = undefined;
      return prepared;
    } catch (cause) {
      blindingSecret.fill(0);
      throw cause;
    } finally {
      envelope.destroy();
      ownerHash.fill(0);
      plaintext.fill(0);
      ephemeralSecret?.fill(0);
    }
  }
}

/** Prepares, proves and compiles one audited deposit, Rust `RingDeposit::send`. */
export async function buildRingDepositTransaction(
  params: RingDepositParams,
  context?: RequestContext,
): Promise<Transaction> {
  const prepared = await PreparedRingDeposit.prepare(params, context);
  try {
    // A plain build drops the history past its tag.
    if (prepared.viewingHistory !== undefined)
      throw new RingError("RING_ANONYMOUS_SUBMISSION_REQUIRED", {
        details: { ringProgramId: params.ringProgramId, use: "createRingDepositSubmission" },
      });
    return (await depositAttempt(prepared, params, context)).transaction;
  } catch (cause) {
    throw wrapRingError("RING_BUILD_DEPOSIT", cause);
  } finally {
    prepared.destroy();
  }
}

/** Each attempt seals a fresh note under the same viewing history. */
export async function createRingDepositSubmission(
  params: RingDepositParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const build = async (attemptContext?: RequestContext): Promise<RingSubmissionAttempt> => {
    const prepared = await PreparedRingDeposit.prepare(params, attemptContext);
    try {
      return await depositAttempt(prepared, params, attemptContext);
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    } finally {
      prepared.destroy();
    }
  };
  return new RingTransactionSubmission({
    first: await build(context),
    build,
    registry: params.client,
  });
}

async function depositAttempt(
  prepared: PreparedRingDeposit,
  params: RingDepositParams,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { instruction, roots, credentialRoots } = await prepared.prove(params.client, context);
  const lifetime = await params.client.getLatestBlockhash(context);
  return Object.freeze({
    transaction: await compileUnsignedTransaction({
      feePayer: params.feePayer,
      lifetime,
      computeUnitLimit: RING_DEPOSIT_COMPUTE_UNIT_LIMIT,
      instructions: [instruction],
    }),
    lastValidBlockHeight: lifetime.lastValidBlockHeight,
    intentHash: intentHash(prepared.intent()),
    ringInstructionIndex: 0,
    ...(roots === undefined ? {} : { roots }),
    credentialRoots,
    ...(prepared.viewingHistory === undefined ? {} : { viewingHistory: prepared.viewingHistory }),
  });
}

async function depositSealing(
  params: DepositSealingParams,
  context: RequestContext | undefined,
): Promise<DepositSealing> {
  await initializePoseidon();
  const config = await fetchRingPolicy(params.client, params.ringProgramId, context);
  const anonymous = config.mode === "anonymous";
  const recipient = await depositRecipient(params, anonymous, context);
  const asset = params.asset ?? SOL_MINT;
  const settlement = await resolveDepositSettlement(
    {
      asset,
      depositor: signerAddress(params.depositor),
      ...(params.splTokenAccount === undefined ? {} : { splTokenAccount: params.splTokenAccount }),
      ...(params.splTokenProgram === undefined ? {} : { splTokenProgram: params.splTokenProgram }),
    },
    () => new RingError("RING_BUILD_DEPOSIT", { details: { reason: "missing token account" } }),
  );
  return Object.freeze({
    config,
    recipient,
    owner: Object.freeze({
      kind: anonymous ? "anonymous" : "confidential",
      key: recipient.address.signingPublicKey.confidentialViewTag(),
    }),
    asset,
    settlement,
  });
}

/** No transaction signer may name an anonymous ring's owner. */
function checkDepositSigners(
  sealing: DepositSealing,
  signers: readonly (Address | SignerAccount | undefined)[],
): void {
  if (sealing.owner.kind !== "anonymous") return;
  checkHiddenParties(
    sealing.owner.key,
    signers.map((party) => (party === undefined ? undefined : signerAddress(party))),
  );
}

/** The recipient's address and the tag its scan reads, refused when the ring mode disagrees. */
async function depositRecipient(
  params: DepositSealingParams,
  anonymous: boolean,
  context: RequestContext | undefined,
): Promise<TaggedRecipient> {
  const recipient = params.recipient;
  if (recipient.kind === "confidential") {
    if (anonymous)
      throw new RingError("RING_ANONYMOUS_REFUSED", { details: { operation: "deposit" } });
    const address = await resolveShieldedRecipient(
      { rpc: params.client, recipient: recipient.address },
      (unregistered) =>
        new RingError("RING_BUILD_DEPOSIT", {
          details: { reason: "recipient not registered", recipient: unregistered },
        }),
      context,
    );
    return {
      address,
      viewTag: address.viewingPublicKey.u(),
      ...(recipient.listSalt === undefined ? {} : { listSalt: recipient.listSalt }),
    };
  }
  if (!anonymous) throw new RingError("RING_NOT_ANONYMOUS", { details: { operation: "deposit" } });
  // The recipient signs nothing in a deposit, a PDA owner is valid.
  return anonymousRecipient(recipient, params.ringProgramId, context);
}

async function anonymousRecipient(
  recipient: Exclude<RingDepositRecipient, { kind: "confidential" }>,
  ringProgramId: Address,
  context: RequestContext | undefined,
): Promise<TaggedRecipient> {
  if (recipient.kind === "anonymous") {
    const { tag, history } = await recipient.history.senderTag(recipient.keys, context);
    return {
      address: recipient.keys.address(),
      viewTag: tag,
      history,
      ...(recipient.listSalt === undefined ? {} : { listSalt: recipient.listSalt }),
    };
  }
  const ringAddress = recipient.to instanceof RingAddress ? recipient.to : recipient.to.address;
  if (ringAddress.ringProgramId !== ringProgramId)
    throw new RingError("RING_FOREIGN_RING", {
      details: { address: ringAddress.ringProgramId, ring: ringProgramId },
    });
  const { viewingPublicKey } = ringAddress.recipient;
  if (isSmallOrder(viewingPublicKey)) throw new RingError("RING_RECIPIENT_KEY_NOT_CONTRIBUTORY");
  const depositTag = recipient.to instanceof RingAddress ? undefined : recipient.to.depositTag;
  // The viewing key as a tag would link every deposit to one recipient.
  if (depositTag === undefined) throw new RingError("RING_DEPOSIT_BOOTSTRAP_TAG");
  return { address: ringAddress.recipient, viewTag: depositTag, listSalt: ringAddress.listSalt };
}
