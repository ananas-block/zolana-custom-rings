/** The message a wallet signs for Ring RPC, checked against the request the wallet made, Rust `relay_message`. */
import {
  type AccountMeta,
  type Address,
  address,
  decompileTransactionMessage,
  getBase58Decoder,
  getBase64Decoder,
  getBase64Encoder,
  getCompiledTransactionMessageDecoder,
  getCompiledTransactionMessageEncoder,
  type Instruction,
  isSignerRole,
  isWritableRole,
  type TransactionMessageBytes,
  type TransactionPartialSigner,
} from "@solana/kit";

import { getCreateAssociatedTokenAccountInstructionAsync } from "@heliuslabs/zolana/instructions";
import type {
  Bytes32,
  InterfaceTransfer,
  RequestContext,
  RingAssetDeposit,
  Signature,
} from "@heliuslabs/zolana/interface";
import { slotTag } from "../crypto/derivation/ring-stream.js";
import {
  equalBytes,
  isCanonicalField,
  LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
  Writer,
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
import {
  encodeAuditRecord,
  encodeDataTail,
  RecordKind,
  type AuditRecord,
} from "../protocol/codec/audit-stream.js";
import { writeInterfaceTransfer } from "../protocol/codec/codecs.js";
import {
  canonicalViewingKey,
  openSealedDisclosure,
  type RingDisclosure,
} from "../crypto/audit/ring-disclosure.js";
import { x25519FromU } from "../crypto/keys/x25519.js";

const base58 = getBase58Decoder();
const base64Text = getBase64Decoder();
const base64Bytes = getBase64Encoder();
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

/** Rust `RelayTransferTerms`, a public signer refuses a frame differing by a byte. */
export interface RelayTransferTerms {
  readonly ring: Address;
  readonly feePayer: Address;
  readonly txViewingKey: Bytes32;
  /** Every public owner and co-signer the frame names, no other key signs. */
  readonly signers: readonly Address[];
  /** One `AuditRecord` encoding per published slot. */
  readonly records: readonly Uint8Array[];
  /** One `DataTail` encoding per published slot, empty on a frame with no data. */
  readonly tails: readonly Uint8Array[];
  readonly nullifiers: readonly Uint8Array[];
  /** One wincode `InterfaceTransfer` per leg. */
  readonly legs: readonly Uint8Array[];
  /** The token accounts the fee payer creates ahead of the ring instruction. */
  readonly setup: readonly TokenAccountCreate[];
}

export interface TokenAccountCreate {
  readonly owner: Address;
  readonly mint: Address;
  readonly tokenProgram: Address;
}

export interface ExpectedTransfer {
  readonly kind: "transfer";
  readonly terms: RelayTransferTerms;
  readonly policy: Address;
  /** From the ring account, a frame read under the wrong rail or auditor proves nothing. */
  readonly rail: RingRail;
  readonly auditor: X25519PublicKey;
  readonly setup: readonly Instruction[];
}

export type ExpectedRelayMessage = ExpectedDeposit | ExpectedDelegate | ExpectedTransfer;

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

const TERMS_FIELDS = [
  "ring",
  "feePayer",
  "txViewingKey",
  "signers",
  "records",
  "tails",
  "nullifiers",
  "legs",
  "setup",
];

/** Rust's serde JSON byte for byte. */
export function encodeRelayTransferTerms(terms: RelayTransferTerms): string {
  const text = (bytes: Uint8Array): string => base64Text.decode(bytes);
  return JSON.stringify({
    ring: terms.ring,
    feePayer: terms.feePayer,
    txViewingKey: text(terms.txViewingKey),
    signers: terms.signers,
    records: terms.records.map(text),
    tails: terms.tails.map(text),
    nullifiers: terms.nullifiers.map(text),
    legs: terms.legs.map(text),
    setup: terms.setup,
  });
}

export function decodeRelayTransferTerms(json: string): RelayTransferTerms {
  return withMismatch("Undecodable", () => {
    const wire = JSON.parse(json) as Record<string, unknown>;
    if (Object.keys(wire).some((name) => !TERMS_FIELDS.includes(name)))
      throw mismatch("Undecodable");
    const bytes = (value: unknown): Uint8Array => {
      const decoded = new Uint8Array(base64Bytes.encode(value as string));
      if (base64Text.decode(decoded) !== value) throw mismatch("Undecodable");
      return decoded;
    };
    const list = (name: string): readonly unknown[] => wire[name] as readonly unknown[];
    const txViewingKey = bytes(wire["txViewingKey"]);
    if (txViewingKey.length !== 32) throw mismatch("Undecodable");
    return Object.freeze({
      ring: address(wire["ring"] as string),
      feePayer: address(wire["feePayer"] as string),
      txViewingKey: txViewingKey as Bytes32,
      signers: list("signers").map((signer) => address(signer as string)),
      records: list("records").map(bytes),
      tails: list("tails").map(bytes),
      nullifiers: list("nullifiers").map(bytes),
      legs: list("legs").map(bytes),
      setup: list("setup").map((entry) => {
        const { owner, mint, tokenProgram, ...unknown } = entry as Record<string, string>;
        if (Object.keys(unknown).length !== 0) throw mismatch("Undecodable");
        return Object.freeze({
          owner: address(owner as string),
          mint: address(mint as string),
          tokenProgram: address(tokenProgram as string),
        });
      }),
    });
  });
}

export async function expectedTransfer(
  terms: RelayTransferTerms,
  config: DelegateRingConfig,
): Promise<ExpectedTransfer> {
  withMismatch("TransactionKey", () =>
    canonicalViewingKey(terms.txViewingKey.slice() as Bytes32),
  ).destroy();
  const [policy, setup] = await Promise.all([
    ringPolicyAddress(terms.ring),
    Promise.all(
      terms.setup.map((create) =>
        getCreateAssociatedTokenAccountInstructionAsync({
          payer: terms.feePayer,
          owner: create.owner,
          mint: create.mint,
          tokenProgram: create.tokenProgram,
        }),
      ),
    ),
  ]);
  return Object.freeze({
    kind: "transfer",
    terms,
    policy,
    rail: ringRailOf(RingInstructionTag.transfer, config.mode),
    auditor: config.auditorPublicKey,
    setup: Object.freeze(setup),
  });
}

export function checkRelayMessage(
  expected: ExpectedRelayMessage,
  message: Uint8Array,
  signer: Address,
): VerifiedRelayMessage {
  if (expected.kind === "deposit") return checkDepositMessage(expected, message);
  const envelope = frameEnvelope(expected, signer, frameTag(expected));
  const { data, accounts } = open(envelope, message);
  if (data[0] === RingInstructionTag.settleBuffered) throw mismatch("SettlesBuffer");
  checkFrame(expected, signer, data, accounts);
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
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
    setup: [],
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

/** The account a settling message reads its frame from, `undefined` on an inline message. */
export function settledBufferOf(
  expected: ExpectedRelayMessage,
  message: Uint8Array,
  signer: Address,
): Address | undefined {
  if (expected.kind === "deposit") return undefined;
  const { data, accounts } = open(
    frameEnvelope(expected, signer, RingInstructionTag.settleBuffered),
    message,
  );
  return data[0] === RingInstructionTag.settleBuffered ? accounts[0]?.address : undefined;
}

/** The digest binds the buffer's frame, every check of an inline message then reads it. */
export function checkSettledMessage(
  expected: ExpectedRelayMessage,
  message: Uint8Array,
  buffer: Uint8Array,
  signer: Address,
): VerifiedRelayMessage {
  if (expected.kind === "deposit") throw mismatch("Data");
  const envelope = frameEnvelope(expected, signer, RingInstructionTag.settleBuffered);
  const { data, accounts } = open(envelope, message);
  if (accounts.length < 2) throw mismatch("Accounts");
  const frame = bufferedFrame(buffer);
  if (frame === undefined || !equalBytes(data, settleBufferedData(frameDigest(frame))))
    throw mismatch("Data");
  checkFrame(expected, signer, frame, accounts.slice(2));
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
}

function frameTag(expected: ExpectedDelegate | ExpectedTransfer): RingInstructionTag {
  return expected.kind === "delegate"
    ? RingInstructionTag.authorityTransfer
    : RingInstructionTag.transfer;
}

function frameEnvelope(
  expected: ExpectedDelegate | ExpectedTransfer,
  signer: Address,
  tag: RingInstructionTag,
): Envelope {
  if (expected.kind === "delegate")
    return {
      ring: expected.ring,
      policy: expected.policy,
      feePayer: expected.feePayer,
      signer: expected.delegate,
      tag,
      setup: [],
    };
  if (!expected.terms.signers.includes(signer)) throw mismatch("Unrequested");
  return {
    ring: expected.terms.ring,
    policy: expected.policy,
    feePayer: expected.terms.feePayer,
    signer,
    tag,
    setup: expected.setup,
  };
}

function checkFrame(
  expected: ExpectedDelegate | ExpectedTransfer,
  signer: Address,
  data: Uint8Array,
  accounts: readonly AccountMeta[],
): void {
  const tag = frameTag(expected);
  if (data[0] !== tag) throw mismatch("Data");
  const frame = withMismatch("Data", () => RingTransactData.parse(data.subarray(1), expected.rail));
  if (expected.kind === "delegate") checkMoved(expected, frame);
  else checkTerms(expected, frame);
  const envelope = frameEnvelope(expected, signer, tag);
  const named = accounts.filter((meta) => meta.address === envelope.signer);
  const signsOnce =
    named.length === 1 &&
    named.every((meta) => isSignerRole(meta.role) && !isWritableRole(meta.role));
  if (!signsOnce || !readsOnly(envelope, accounts.slice(0, 1))) throw mismatch("Accounts");
}

/** The proof binds each record to its slot under the key the frame publishes. */
function checkMoved(expected: ExpectedDelegate, frame: RingTransactData): void {
  // Owner tags alone, the message holds no blinding, a hidden frame's tags bind nothing.
  checkTransactionKey(expected.txViewingKey, frame);
  // The request names ring payments alone, a leg or a data commitment moves what no one asked.
  if (frame.interfaceTransfers.length !== 0 || frame.hasData) throw mismatch("Data");
  const { records } = openStream(expected.txViewingKey, expected.auditor, frame);
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

function checkTransactionKey(txViewingKey: Bytes32, frame: RingTransactData): void {
  const key = withMismatch("TransactionKey", () =>
    canonicalViewingKey(txViewingKey.slice() as Bytes32),
  );
  const published = key.publicKey().u();
  key.destroy();
  if (!equalBytes(frame.txViewingU, published)) throw mismatch("TransactionKey");
}

function openStream(
  txViewingKey: Bytes32,
  auditor: X25519PublicKey,
  frame: RingTransactData,
): RingDisclosure {
  return withMismatch("Data", () => {
    const tails = frame.outputs.flatMap((output) =>
      output.tail === undefined ? [] : [output.tail],
    );
    const opened = openSealedDisclosure(txViewingKey, auditor, {
      layout: RingTransactData.streamLayout(frame),
      salt: frame.salt,
      message: {
        ephemeralPublicKey: x25519FromU(frame.txViewingU),
        envelope: frame.envelope,
        records: frame.outputs.map((output) => output.record),
        ...(frame.hasData ? { tails } : {}),
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
}

function checkTerms(expected: ExpectedTransfer, frame: RingTransactData): void {
  const { terms } = expected;
  checkTransactionKey(terms.txViewingKey, frame);
  const { records, tails } = openStream(terms.txViewingKey, expected.auditor, frame);
  if (frame.outputs.length !== terms.records.length) throw mismatch("Recipients");
  records.forEach((record, slot) => {
    const named = terms.records[slot];
    if (named === undefined || !equalBytes(encodeAuditRecord(record), named))
      throw mismatch("Recipients");
    const tail = tails?.[slot];
    if (tail === undefined) return;
    const namedTail = terms.tails[slot];
    if (namedTail === undefined || !equalBytes(encodeDataTail(tail), namedTail))
      throw mismatch("Data");
  });
  const sameBytes = (found: readonly Uint8Array[], named: readonly Uint8Array[]): boolean =>
    found.length === named.length &&
    found.every((bytes, index) => {
      const other = named[index];
      return other !== undefined && equalBytes(bytes, other);
    });
  if (
    frame.hasData === (terms.tails.length === 0) ||
    !sameBytes(frame.nullifiers, terms.nullifiers) ||
    !sameBytes(frame.interfaceTransfers.map(interfaceTransferBytes), terms.legs)
  )
    throw mismatch("Data");
}

export function interfaceTransferBytes(transfer: InterfaceTransfer): Uint8Array {
  const writer = new Writer();
  writeInterfaceTransfer(writer, transfer);
  return writer.finish();
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
  /** Ahead of the ring instruction, exactly these. */
  readonly setup: readonly Instruction[];
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
  const instruction = message.instructions.at(-1);
  const leading = message.instructions.slice(0, -1);
  if (instruction === undefined || leading.length !== envelope.setup.length)
    throw mismatch("Instructions");
  const sameSetup = leading.every((found, index) => {
    const named = envelope.setup[index];
    const accounts = found.accounts ?? [];
    const namedAccounts = named?.accounts ?? [];
    return (
      named !== undefined &&
      found.programAddress === named.programAddress &&
      equalBytes(new Uint8Array(found.data ?? []), new Uint8Array(named.data ?? [])) &&
      accounts.length === namedAccounts.length &&
      accounts.every((meta, at) => meta.address === namedAccounts[at]?.address)
    );
  });
  if (!sameSetup) throw mismatch("Instructions");
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
