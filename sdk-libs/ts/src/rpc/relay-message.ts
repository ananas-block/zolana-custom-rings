/** The message a wallet signs for Ring RPC, checked against the request the wallet made, Rust `relay_message`. */
import {
  type AccountMeta,
  type Address,
  decompileTransactionMessage,
  getBase58Decoder,
  getCompiledTransactionMessageDecoder,
  getCompiledTransactionMessageEncoder,
  isSignerRole,
  isWritableRole,
  type TransactionMessageBytes,
  type TransactionPartialSigner,
} from "@solana/kit";

import type {
  Bytes32,
  RequestContext,
  RingAssetDeposit,
  Signature,
} from "@heliuslabs/zolana/interface";
import { slotTag } from "../crypto/derivation/ring-stream.js";
import {
  equalBytes,
  isCanonicalField,
  LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
} from "@heliuslabs/zolana/internal";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/zolana/keypair";

import { ringComputeUnitLimit } from "../operations/management/admin.js";
import {
  bufferedFrame,
  frameDigest,
  settleBufferedData,
} from "../protocol/transaction/frame-buffer.js";
import { RingError } from "../protocol/error.js";
import { ringPolicyAddress } from "../protocol/pda/index.js";
import type {
  PrepareAuthorityTransferRequest,
  RelayQuote,
} from "../protocol/ring-rpc/ring-rpc-types.js";
import {
  AUDITED_DEPOSIT_PREFIX_LENGTH,
  ringDepositSpp,
  type RingDepositSpp,
} from "../protocol/transaction/deposit-instruction.js";
import { RingInstructionTag } from "../protocol/transaction/instruction-tag.js";
import {
  isAnonymousFrame,
  RingTransactData,
  ringRailOf,
  type RingRail,
} from "../protocol/transaction/transact.js";
import type { RingPolicy } from "../protocol/codec/ring-codecs.js";
import { RecordKind, type AuditRecord } from "../protocol/codec/audit-stream.js";
import { canonicalViewingKey, openSealedDisclosure } from "../crypto/audit/ring-disclosure.js";
import { x25519FromU } from "../crypto/keys/x25519.js";

const base58 = getBase58Decoder();
const VERIFIED = Symbol("verified relay message");
const MAX_SIGNATURES = 12;
const MAX_INSTRUCTIONS = 64;

/** Rust `MessageMismatch`, the variant names the shared vectors carry. */
export type RelayMessageMismatch =
  | "Undecodable"
  | "NotV1"
  | "FeePayer"
  | "Budget"
  | "Instructions"
  | "Program"
  | "Data"
  | "Accounts"
  | "Recipients"
  | "TransactionKey"
  | "SettlesBuffer"
  | "Unrequested"
  | "Signer";

/** Rust `ExpectedDeposit`, built from the depositor's own request. */
export interface ExpectedDeposit {
  readonly kind: "deposit";
  readonly ring: Address;
  readonly policy: Address;
  readonly feePayer: Address;
  readonly depositor: Address;
  /** The SPP deposit the ring forwards unchanged. */
  readonly spp: RingDepositSpp;
}

export type DelegateRingConfig = Pick<RingPolicy, "mode" | "auditorPublicKey">;

interface ExpectedOwner {
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly viewingU: Bytes32;
}

interface ExpectedPayment {
  readonly owner: ExpectedOwner;
  readonly amount: bigint;
}

/** Rust `ExpectedDelegate`. */
export interface ExpectedDelegate {
  readonly kind: "delegate";
  readonly ring: Address;
  readonly policy: Address;
  readonly feePayer: Address;
  readonly delegate: Address;
  /** The frame the ring's mode fixes. */
  readonly rail: RingRail;
  readonly auditor: X25519PublicKey;
  readonly txViewingKey: Bytes32;
  readonly source: ExpectedOwner;
  readonly mint: Address;
  readonly payments: readonly ExpectedPayment[];
}

export type ExpectedRelayMessage = ExpectedDeposit | ExpectedDelegate;

/** Rust `VerifiedMessage`, only a check builds one. */
export class VerifiedRelayMessage {
  readonly signer: Address;
  readonly #bytes: Uint8Array;

  /** @internal */
  constructor(token: typeof VERIFIED, signer: Address, bytes: Uint8Array) {
    if (token !== VERIFIED) throw mismatch("Unrequested");
    this.signer = signer;
    this.#bytes = bytes;
    Object.freeze(this);
  }

  async sign(signer: TransactionPartialSigner, context?: RequestContext): Promise<Signature> {
    if (signer.address !== this.signer) throw mismatch("Signer");
    const transaction = {
      messageBytes: this.#bytes as unknown as TransactionMessageBytes,
      signatures: {},
    } as unknown as Parameters<TransactionPartialSigner["signTransactions"]>[0][number];
    const [signatures] = await signer.signTransactions(
      [transaction],
      context?.signal === undefined ? undefined : { abortSignal: context.signal },
    );
    const signature = signatures?.[signer.address];
    if (signature === undefined) throw mismatch("Signer");
    return base58.decode(signature) as Signature;
  }
}

export async function expectedDeposit(
  input: Readonly<{
    ringProgramId: Address;
    feePayer: Address;
    tree: Address;
    depositor: Address;
    deposit: RingAssetDeposit;
  }>,
): Promise<ExpectedDeposit> {
  const [policy, spp] = await Promise.all([
    ringPolicyAddress(input.ringProgramId),
    ringDepositSpp({
      ringProgramId: input.ringProgramId,
      tree: input.tree,
      depositor: input.depositor,
      deposits: [input.deposit],
    }),
  ]);
  return Object.freeze({
    kind: "deposit",
    ring: input.ringProgramId,
    policy,
    feePayer: input.feePayer,
    depositor: input.depositor,
    spp,
  });
}

export async function expectedDelegate(
  request: PrepareAuthorityTransferRequest,
  quote: RelayQuote,
  config: DelegateRingConfig,
): Promise<ExpectedDelegate> {
  const { transfer } = request;
  return Object.freeze({
    kind: "delegate",
    ring: request.ring,
    policy: await ringPolicyAddress(request.ring),
    feePayer: quote.feePayer,
    delegate: request.delegate,
    rail: ringRailOf(RingInstructionTag.authorityTransfer, config.mode),
    auditor: config.auditorPublicKey,
    txViewingKey: request.txViewingKey,
    source: expectedOwner(transfer.source),
    mint: transfer.mint,
    payments: Object.freeze(
      transfer.payments.map((payment) =>
        Object.freeze({ owner: expectedOwner(payment.recipient), amount: payment.amount }),
      ),
    ),
  });
}

function expectedOwner(address: ShieldedAddress): ExpectedOwner {
  return Object.freeze({
    ownerKey: address.signingPublicKey.confidentialViewTag(),
    nullifierPk: address.nullifierPublicKey,
    viewingU: address.viewingPublicKey.u(),
  });
}

export function checkRelayMessage(
  expected: ExpectedRelayMessage,
  message: Uint8Array,
): VerifiedRelayMessage {
  return expected.kind === "deposit"
    ? checkDepositMessage(expected, message)
    : checkDelegateMessage(expected, message);
}

/** Rust `ExpectedDeposit::check`, every SPP byte and account is the depositor's. */
export function checkDepositMessage(
  expected: ExpectedDeposit,
  message: Uint8Array,
): VerifiedRelayMessage {
  const envelope: Envelope = {
    ...expected,
    signer: expected.depositor,
    tag: RingInstructionTag.deposit,
  };
  const instruction = open(envelope, message);
  const { data, accounts } = instruction;
  if (
    data[0] !== RingInstructionTag.deposit ||
    !equalBytes(data.subarray(AUDITED_DEPOSIT_PREFIX_LENGTH), expected.spp.data)
  )
    throw mismatch("Data");
  const split = accounts.length - expected.spp.accounts.length;
  if (
    split < 0 ||
    !sameAccounts(accounts.slice(split), expected.spp.accounts) ||
    !readsOnly(envelope, accounts.slice(0, split))
  )
    throw mismatch("Accounts");
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
}

/** Owner tags alone, the message holds no blinding, so no commitment rebuilds and a hidden frame's tags bind nothing. */
export function checkDelegateMessage(
  expected: ExpectedDelegate,
  message: Uint8Array,
): VerifiedRelayMessage {
  const envelope = delegateEnvelope(expected, RingInstructionTag.authorityTransfer);
  const { data, accounts } = open(envelope, message);
  if (data[0] === RingInstructionTag.settleBuffered) throw mismatch("SettlesBuffer");
  checkDelegateFrame(expected, data, accounts);
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
}

/** The account a settling message reads its frame from, `undefined` on an inline message. */
export function settledBufferOf(
  expected: ExpectedDelegate,
  message: Uint8Array,
): Address | undefined {
  const { data, accounts } = open(
    delegateEnvelope(expected, RingInstructionTag.settleBuffered),
    message,
  );
  return data[0] === RingInstructionTag.settleBuffered ? accounts[0]?.address : undefined;
}

/** The digest binds the buffer's frame, every check of an inline message then reads it. */
export function checkSettledDelegateMessage(
  expected: ExpectedDelegate,
  message: Uint8Array,
  buffer: Uint8Array,
): VerifiedRelayMessage {
  const envelope = delegateEnvelope(expected, RingInstructionTag.settleBuffered);
  const { data, accounts } = open(envelope, message);
  const inner = accounts.slice(2);
  if (accounts.length < 2) throw mismatch("Accounts");
  const frame = bufferedFrame(buffer);
  if (frame === undefined || !equalBytes(data, settleBufferedData(frameDigest(frame))))
    throw mismatch("Data");
  checkDelegateFrame(expected, frame, inner);
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
}

function delegateEnvelope(expected: ExpectedDelegate, tag: RingInstructionTag): Envelope {
  return { ...expected, signer: expected.delegate, tag };
}

function checkDelegateFrame(
  expected: ExpectedDelegate,
  data: Uint8Array,
  accounts: readonly AccountMeta[],
): void {
  const envelope = delegateEnvelope(expected, RingInstructionTag.authorityTransfer);
  if (data[0] !== RingInstructionTag.authorityTransfer) throw mismatch("Data");
  const parsed = withMismatch("Data", () =>
    RingTransactData.parse(data.subarray(1), expected.rail),
  );
  checkMoved(expected, parsed);
  const named = accounts.filter((meta) => meta.address === expected.delegate);
  const signsOnce =
    named.length === 1 &&
    named.every((meta) => isSignerRole(meta.role) && !isWritableRole(meta.role));
  if (!signsOnce || !readsOnly(envelope, accounts.slice(0, 1))) throw mismatch("Accounts");
}

/** The proof binds each record to its slot under the key the frame publishes. */
function checkMoved(expected: ExpectedDelegate, frame: RingTransactData): void {
  const key = withMismatch("TransactionKey", () =>
    canonicalViewingKey(expected.txViewingKey.slice() as Bytes32),
  );
  const published = key.publicKey().u();
  key.destroy();
  if (!equalBytes(frame.txViewingU, published)) throw mismatch("TransactionKey");
  // The request names ring payments alone, a leg or a data commitment moves what no one asked.
  if (frame.interfaceTransfers.length !== 0 || frame.hasData) throw mismatch("Data");
  const { records } = withMismatch("Data", () => {
    const opened = openSealedDisclosure(expected.txViewingKey, expected.auditor, {
      layout: RingTransactData.streamLayout(frame),
      salt: frame.salt,
      message: {
        ephemeralPublicKey: x25519FromU(frame.txViewingU),
        envelope: frame.envelope,
        records: frame.outputs.map((output) => output.record),
      },
    });
    const { envelope } = opened;
    canonicalViewingKey(envelope.txViewingSecret.slice() as Bytes32).destroy();
    envelope.txViewingSecret.fill(0);
    if (
      envelope.evidence.kind === "entry" &&
      !envelope.evidence.inputs.every(
        (input) =>
          isCanonicalField(input.nullifierPk) &&
          isCanonicalField(input.blinding) &&
          isCanonicalField(input.dataHash) &&
          isCanonicalField(input.ringDataHash),
      )
    )
      throw mismatch("Data");
    return opened;
  });
  const owns = (owner: ExpectedOwner, record: AuditRecord): boolean =>
    equalBytes(record.ownerKey, owner.ownerKey) &&
    equalBytes(record.nullifierPk, owner.nullifierPk);
  const unpaid = [...expected.payments];
  records.forEach((record, slot) => {
    if (record.kind === RecordKind.dummy) return;
    if (record.kind === RecordKind.exit) throw mismatch("Recipients");
    const paid = unpaid.findIndex(
      (payment) =>
        record.mint === expected.mint &&
        record.amount === payment.amount &&
        owns(payment.owner, record),
    );
    if (paid < 0) {
      if (!owns(expected.source, record)) throw mismatch("Recipients");
      return;
    }
    const payment = unpaid[paid];
    // Rust `swap_remove`, the order decides which equal payment a later record takes.
    unpaid[paid] = unpaid[unpaid.length - 1] as ExpectedPayment;
    unpaid.pop();
    // A wrong hint strands the note with no scan reaching it.
    const tag = frame.outputs[slot]?.ownerTag;
    if (
      !isAnonymousFrame(frame.rail) &&
      (payment === undefined ||
        tag === undefined ||
        !equalBytes(tag, slotTag(payment.owner.viewingU)))
    )
      throw mismatch("Recipients");
  });
  if (unpaid.length !== 0) throw mismatch("Recipients");
}

export function mismatch(reason: RelayMessageMismatch): RingError {
  return new RingError("RING_RELAY_MESSAGE_INVALID", { details: { mismatch: reason } });
}

interface Envelope {
  readonly ring: Address;
  readonly policy: Address;
  readonly feePayer: Address;
  readonly signer: Address;
  readonly tag: RingInstructionTag;
}

interface RingInstruction {
  readonly data: Uint8Array;
  readonly accounts: readonly AccountMeta[];
}

/** One canonical v1 message the quoted fee payer pays, holding only the ring instruction. */
function open(envelope: Envelope, bytes: Uint8Array): RingInstruction {
  const compiled = withMismatch("Undecodable", () =>
    getCompiledTransactionMessageDecoder().decode(bytes),
  );
  if (compiled.version !== 1) throw mismatch("NotV1");
  const canonical = withMismatch(
    "Undecodable",
    () => new Uint8Array(getCompiledTransactionMessageEncoder().encode(compiled)),
  );
  // Mirrors Rust `v1::Message::validate`, the vectors pin both on the same verdict.
  const { header, staticAccounts, instructionHeaders } = compiled;
  if (
    !equalBytes(canonical, bytes) ||
    new Set(staticAccounts).size !== staticAccounts.length ||
    header.numSignerAccounts > MAX_SIGNATURES ||
    header.numReadonlySignerAccounts >= header.numSignerAccounts ||
    instructionHeaders.length > MAX_INSTRUCTIONS ||
    instructionHeaders.some((instruction) => instruction.programAccountIndex === 0)
  )
    throw mismatch("Undecodable");
  const message = withMismatch("Undecodable", () =>
    decompileTransactionMessage(
      compiled as Parameters<typeof decompileTransactionMessage>[0] & { version: 1 },
    ),
  );
  if (message.feePayer.address !== envelope.feePayer || envelope.feePayer === envelope.signer)
    throw mismatch("FeePayer");
  const config = message.config ?? {};
  const withinBudget =
    config.computeUnitLimit !== undefined &&
    config.computeUnitLimit <= ringComputeUnitLimit(envelope.tag) &&
    config.loadedAccountsDataSizeLimit !== undefined &&
    config.loadedAccountsDataSizeLimit <= LOADED_ACCOUNTS_DATA_SIZE_LIMIT &&
    config.heapSize === undefined;
  if (!withinBudget) throw mismatch("Budget");
  const [instruction, ...rest] = message.instructions;
  if (instruction === undefined || rest.length !== 0) throw mismatch("Instructions");
  if (instruction.programAddress !== envelope.ring) throw mismatch("Program");
  return {
    data: new Uint8Array(instruction.data ?? []),
    accounts: instruction.accounts ?? [],
  };
}

/** The ring account first, then read only accounts that never name the signer. */
function readsOnly(envelope: Envelope, prefix: readonly AccountMeta[]): boolean {
  const [ring, ...rest] = prefix;
  return (
    ring !== undefined &&
    ring.address === envelope.policy &&
    !isSignerRole(ring.role) &&
    !isWritableRole(ring.role) &&
    rest.every((meta) => !isWritableRole(meta.role) && meta.address !== envelope.signer)
  );
}

function sameAccounts(found: readonly AccountMeta[], expected: readonly AccountMeta[]): boolean {
  return (
    found.length === expected.length &&
    found.every(
      (meta, index) =>
        meta.address === expected[index]?.address && meta.role === expected[index]?.role,
    )
  );
}

function withMismatch<T>(reason: RelayMessageMismatch, run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (error instanceof RingError && error.code === "RING_RELAY_MESSAGE_INVALID") throw error;
    throw mismatch(reason);
  }
}
