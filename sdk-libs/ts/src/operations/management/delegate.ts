/** Delegate moves from a wallet, the configured delegate signs and the member does not. */
import { NullifierKeyProofAuthority } from "@heliuslabs/zolana/client";
import type {
  BlockhashProvider,
  KitRpcAccess,
  ProofAuthority,
  ProofService,
  WalletKeys,
} from "@heliuslabs/zolana/client";
import {
  compileUnsignedTransaction,
  reserveEntries,
  reservedUtxoKeys,
  unreserved,
  selectUtxos,
  signerAddress,
  type SignerAccount,
  ZERO_32,
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactionIntent,
  ownerSolanaAccount,
  type UtxoReservation,
  equalBytes,
  fetchSplAssetRegistrations,
} from "@heliuslabs/zolana/internal";
import type { Address, RequestContext, Transaction } from "@heliuslabs/zolana/interface";
import type { NullifierKey, ShieldedAddress } from "@heliuslabs/zolana/keypair";
import {
  approveUnattended,
  intentHash,
  type ApprovalHandler,
  type TransactionIntent,
  Wallet,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";

import { RingInstructionTag, ringComputeUnitLimit } from "./admin.js";
import { wrapRingError } from "../../protocol/error.js";
import { boundState } from "../workflow/pipeline.js";
import {
  DelegateTransfer,
  type DelegateOutput,
  type DelegateTransferClient,
  type DelegateWithdrawal,
  type RingTransferApproval,
} from "../payments/transfer-rails.js";
import { ringIntentMismatch, ringProofInput, ringSelectionErrors } from "../workflow/selection.js";
import {
  RingTransactionSubmission,
  checkRetainedEntries,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "../workflow/submission.js";
import { RING_AUTHORITY_SHAPES } from "../../protocol/transaction/spp.js";

export type RingDelegateTransferClient = DelegateTransferClient & BlockhashProvider & KitRpcAccess;

/** Builds a move authorized by the configured Solana delegate. */
export interface RingDelegateTransferParams {
  readonly client: RingDelegateTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  /** The source is not a required Solana signer. */
  readonly source: WalletKeys;
  readonly approve?: ApprovalHandler;
  readonly delegate: SignerAccount;
  readonly feePayer: Address;
  readonly outputs: readonly DelegateOutput[];
  /** A public withdrawal, a delegate takes no deposit leg. */
  readonly withdrawal?: DelegateWithdrawal;
  readonly priorityFeeLamports?: bigint;
}

/** The opened member key proves through the client's proof service. */
export type RingDelegateRecoveredClient = RingDelegateTransferClient &
  Readonly<{ proofService: ProofService }>;

/** Recovered openings still require the configured delegate's signature. */
export type RingDelegateRecoveredParams = Omit<
  RingDelegateTransferParams,
  "wallet" | "source" | "approve" | "client"
> &
  Readonly<{
    client: RingDelegateRecoveredClient;
    source: ShieldedAddress;
    nullifierKey: NullifierKey;
    notes: readonly WalletUtxo[];
  }>;

type DelegateMove = Omit<RingDelegateTransferParams, "wallet" | "source" | "approve">;

type DelegateSource =
  | Readonly<{ kind: "keys"; keys: WalletKeys; approve: ApprovalHandler }>
  | Readonly<{
      kind: "recovered";
      address: ShieldedAddress;
      nullifierKey: NullifierKey;
      proofs: ProofService;
    }>;

export function createRingDelegateSubmission(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const source = keysSource(input);
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      build: (retry, buildContext) =>
        buildDelegateTransaction(
          { move: input, wallet: input.wallet, source, retry },
          buildContext,
        ),
    },
    context,
  );
}

export async function buildRingDelegateTransferTransaction(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (
    await buildDelegateTransaction(
      { move: input, wallet: input.wallet, source: keysSource(input), retry: {} },
      context,
    )
  ).transaction;
}

export function createRingDelegateRecoveredSubmission(
  input: RingDelegateRecoveredParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const wallet = recoveredWallet(input);
  const source = recoveredSource(input);
  return RingTransactionSubmission.fromBuilder(
    {
      wallet,
      registry: input.client,
      build: (retry, buildContext) =>
        buildDelegateTransaction({ move: input, wallet, source, retry }, buildContext),
    },
    context,
  );
}

export async function buildRingDelegateRecoveredTransaction(
  input: RingDelegateRecoveredParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (
    await buildDelegateTransaction(
      { move: input, wallet: recoveredWallet(input), source: recoveredSource(input), retry: {} },
      context,
    )
  ).transaction;
}

function keysSource(input: RingDelegateTransferParams): DelegateSource {
  return { kind: "keys", keys: input.source, approve: input.approve ?? approveUnattended };
}

function recoveredWallet(input: RingDelegateRecoveredParams): Wallet {
  const wallet = new Wallet({ identity: input.source });
  wallet._replace({ utxos: input.notes, transactions: [], nullifiers: new Set() });
  return wallet;
}

function recoveredSource(input: RingDelegateRecoveredParams): DelegateSource {
  return {
    kind: "recovered",
    address: input.source,
    nullifierKey: input.nullifierKey,
    proofs: input.client.proofService,
  };
}

/** The source's address and the authority completing its inputs, released when the attempt settles. */
function delegateProofs(
  source: DelegateSource,
): Readonly<{ address: ShieldedAddress; proofs: ProofAuthority; release(): void }> {
  if (source.kind === "keys")
    return { address: source.keys.address(), proofs: source.keys, release: () => {} };
  const proofs = new NullifierKeyProofAuthority(source.nullifierKey, source.proofs);
  return { address: source.address, proofs, release: () => proofs.destroy() };
}

async function buildDelegateTransaction(
  input: Readonly<{
    move: DelegateMove;
    wallet: Wallet;
    source: DelegateSource;
    retry: RingSubmissionBuildState;
  }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { move, wallet, source, retry } = input;
  const outputs = Object.freeze(move.outputs.map((output) => Object.freeze({ ...output })));
  const spender = delegateProofs(source);
  let reservation: UtxoReservation | undefined;
  try {
    const owner = spender.address;
    if (!equalBytes(owner.toBytes(), wallet.identity.toBytes())) throw ringIntentMismatch("source");
    const intent: TransactionIntent = Object.freeze({
      kind: "ringDelegate",
      ringProgramId: move.ringProgramId,
      delegate: signerAddress(move.delegate),
      source: owner,
      outputs: outputs.map(({ recipient, asset, amount }) =>
        Object.freeze({ recipient, asset, amount }),
      ),
    });
    checkTransactionIntent(intent, ringIntentMismatch);
    const planned = intentHash(intent);
    if (retry.intent !== undefined && !equalBytes(retry.intent, planned))
      throw ringIntentMismatch("retryIntent");
    retry.intent = planned;
    const assets = wallet.registry.clone();
    for (const { assetId, mint } of await fetchSplAssetRegistrations(move.client, context))
      assets.register(assetId, mint);
    const amounts = new Map<Address, bigint>();
    for (const output of outputs) {
      assets.assetId(output.asset);
      amounts.set(output.asset, (amounts.get(output.asset) ?? 0n) + output.amount);
    }
    const { withdrawal } = move;
    if (withdrawal !== undefined)
      amounts.set(withdrawal.asset, (amounts.get(withdrawal.asset) ?? 0n) + withdrawal.amount);
    if (retry.entries !== undefined) checkRetainedEntries(wallet, retry.entries);
    const selected = retry.entries ?? selectSourceNotes(move, wallet, owner, amounts);
    reservation = retry.reservation ?? reserveEntries(wallet, selected, retry.lifetime);
    retry.entries = selected;
    retry.reservation = reservation;
    const transfer = DelegateTransfer.new({
      ringProgramId: move.ringProgramId,
      delegate: intent.delegate,
      payer: move.feePayer,
      source: owner,
      sourceProofs: spender.proofs,
      inputs: selected.map((entry) => ringProofInput(entry, owner, move.client)),
      outputs,
      assets,
      outputTreeId: move.client.treeId,
      ...(withdrawal === undefined ? {} : { withdrawal }),
    });
    const approval: RingTransferApproval = {
      transaction:
        move.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: move.priorityFeeLamports },
      approve: async ({ prepared }) => {
        if (source.kind === "keys") {
          const approved = await source.approve({
            solanaPublicKey: ownerSolanaAccount(owner, move.feePayer),
            intent,
            summary: `Delegate ${intent.delegate} moves ${String(outputs.length)} payment(s)${withdrawal === undefined ? "" : " and a public withdrawal"}, change stays with the source.`,
          });
          checkIntentApproval(approved, intent, ringIntentMismatch);
        }
        // SPP's delegate intent names ring outputs alone.
        if (withdrawal === undefined && outputs.every((output) => output.exit !== true))
          checkPreparedTransfer(prepared, intent, ringIntentMismatch);
      },
    };
    const proven = await transfer.proveApproved(move.client, approval, context);
    const [instruction, lifetime] = await Promise.all([
      proven.instruction(),
      move.client.getLatestBlockhash(context),
    ]);
    const transaction = compileUnsignedTransaction({
      ...approval.transaction,
      feePayer: move.feePayer,
      lifetime,
      instructions: [instruction],
      computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.authorityTransfer),
    });
    return Object.freeze({
      transaction,
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: planned,
      ringInstructionIndex: 0,
      ...boundState(proven),
    });
  } catch (cause) {
    if (reservation !== undefined) wallet._releaseReservation(reservation.id);
    throw wrapRingError("RING_BUILD_TRANSFER", cause);
  } finally {
    spender.release();
  }
}

/** Plain ring notes of the source, one cover per mint inside the widest authority shape holding the outputs. */
function selectSourceNotes(
  move: DelegateMove,
  wallet: Wallet,
  owner: ShieldedAddress,
  amounts: ReadonlyMap<Address, bigint>,
): readonly WalletUtxo[] {
  // Every mint may return change, a withdrawal holds a slot of SPP's authority builder.
  const outputs = move.outputs.length + amounts.size + (move.withdrawal === undefined ? 0 : 1);
  const maxInputs = Math.max(
    0,
    ...RING_AUTHORITY_SHAPES.filter((shape) => shape.outputs >= outputs).map(
      (shape) => shape.inputs,
    ),
  );
  const reserved = reservedUtxoKeys(wallet);
  const selected: WalletUtxo[] = [];
  for (const [asset, amount] of amounts) {
    selected.push(
      ...selectUtxos({
        wallet,
        asset,
        target: { kind: "cover", amount },
        policy: {
          eligible: (entry) =>
            unreserved(reserved)(entry) &&
            entry.utxo.ringProgramId === move.ringProgramId &&
            entry.dataHash === undefined &&
            (entry.ringDataHash === undefined || equalBytes(entry.ringDataHash, ZERO_32)) &&
            entry.utxo.data.utxoData() === undefined &&
            entry.utxo.data.memo() === undefined &&
            (entry.utxo.data.ringData()?.length ?? 0) === 0 &&
            equalBytes(
              entry.utxo.owner.ownerProofInputHash(),
              owner.signingPublicKey.ownerProofInputHash(),
            ),
          ordering: "largestFirst",
          allowWideBalance: true,
          maxInputs: maxInputs - selected.length,
          tree: { kind: "fixed", tree: move.client.tree },
          errors: ringSelectionErrors,
        },
      }).entries,
    );
  }
  return selected;
}
