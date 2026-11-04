/** The message a wallet signs for Ring RPC, checked against the request the wallet made, Rust `relay_message`. */
import {
  type AccountMeta,
  type Address,
  address,
  decompileTransactionMessage,
  getBase58Decoder,
  getBase58Encoder,
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
  RequestContext,
  RingAssetDeposit,
  Signature,
} from "@heliuslabs/zolana/interface";
import { slotTag } from "../crypto/derivation/ring-stream.js";
import {
  addressBytes,
  encodeBase58,
  equalBytes,
  isCanonicalField,
  U64_MAX,
  LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
} from "@heliuslabs/zolana/internal";
import {
  ShieldedPublicKey,
  type ShieldedAddress,
  type X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import { Utxo, type WalletUtxo } from "@heliuslabs/zolana/transaction";

import { ringComputeUnitLimit } from "../operations/management/admin.js";
import {
  bufferedFrame,
  frameDigest,
  settleBufferedData,
} from "../protocol/transaction/frame-buffer.js";
import { RingError } from "../protocol/error.js";
import { ringPolicyAddress, STORAGE_PROGRAM_ID } from "../protocol/pda/index.js";
import {
  ENROLL_COMPUTE_UNITS,
  enrollRequestDigest,
  relayEnrollInstruction,
  type RelayEnrollInputs,
} from "../protocol/ring-rpc/relay-enroll-inputs.js";
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
import {
  canonicalViewingKey,
  openSealedDisclosure,
  type RingDisclosure,
} from "../crypto/audit/ring-disclosure.js";
import { x25519FromU } from "../crypto/keys/x25519.js";

const base58 = getBase58Decoder();
/** The engine floor holds `JSON.rawJSON`, the TS lib does not type it. */
const rawJson = (JSON as unknown as { rawJSON(text: string): unknown }).rawJSON;
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
  | "SpendsUnnamedNote"
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
  readonly mint: Address;
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
  /** Change returns to an input's owner. */
  readonly sources: readonly ExpectedOwner[];
  readonly payments: readonly ExpectedPayment[];
}

/** Holds no transaction key, no other slot opens to the signer. */
export interface RelayTransferTerms {
  readonly ring: Address;
  readonly feePayer: Address;
  readonly signer: Address;
  readonly slots: readonly SlotOpening[];
  /** The signer's notes the transfer spends. */
  readonly nullifiers: readonly Bytes32[];
  /** The token accounts the fee payer creates ahead of the ring instruction. */
  readonly setup: readonly TokenAccountCreate[];
}

export interface SlotOpening {
  readonly slot: number;
  readonly owner: Address;
  readonly nullifierPk: Bytes32;
  readonly mint: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly treeId: number;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
}

export interface TokenAccountCreate {
  readonly owner: Address;
  readonly mint: Address;
  readonly tokenProgram: Address;
}

export interface ExpectedPublicOwner {
  readonly kind: "publicOwner";
  readonly terms: RelayTransferTerms;
  readonly policy: Address;
  readonly setup: readonly Instruction[];
  /** From the ring account, a frame read under the wrong rail proves nothing. */
  readonly rail: RingRail;
  readonly knownNullifiers: readonly Bytes32[];
}

/** The sealing wallet hands each owner its terms and signs nothing itself. */
export interface ExpectedSealed {
  readonly kind: "sealed";
  readonly terms: readonly RelayTransferTerms[];
}

export interface ExpectedEnroll {
  readonly kind: "enroll";
  readonly feePayer: Address;
  readonly policy: Address;
  readonly inputs: RelayEnrollInputs;
  readonly accounts: readonly AccountMeta[];
}

export type ExpectedRelayMessage =
  | ExpectedDeposit
  | ExpectedDelegate
  | ExpectedSealed
  | ExpectedPublicOwner
  | ExpectedEnroll;

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
      // A kit keypair signs only an address the transaction lists.
      signatures: { [signer.address]: null },
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
    sources: Object.freeze(transfer.sources.map(expectedOwner)),
    payments: Object.freeze(
      transfer.payments.map((payment) =>
        Object.freeze({
          owner: expectedOwner(payment.recipient),
          mint: payment.mint,
          amount: payment.amount,
        }),
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

/** Rust's serde JSON byte for byte, an amount past the safe integers stays exact. */
export function encodeRelayTransferTerms(terms: RelayTransferTerms): string {
  return JSON.stringify({
    ring: terms.ring,
    feePayer: terms.feePayer,
    signer: terms.signer,
    slots: terms.slots.map((opening) => ({
      slot: opening.slot,
      owner: opening.owner,
      nullifierPk: encodeBase58(opening.nullifierPk),
      mint: opening.mint,
      amount: rawJson(opening.amount.toString()),
      blinding: encodeBase58(opening.blinding),
      treeId: opening.treeId,
      dataHash: encodeBase58(opening.dataHash),
      ringDataHash: encodeBase58(opening.ringDataHash),
    })),
    nullifiers: terms.nullifiers.map(encodeBase58),
    setup: terms.setup,
  });
}

export function decodeRelayTransferTerms(json: string): RelayTransferTerms {
  return withMismatch("Undecodable", () => {
    const wire = JSON.parse(json, (key: string, value: unknown, context?: { source?: string }) => {
      if (typeof value !== "number") return value;
      // Serde refuses `7.0` and `-0` for an integer.
      if (!/^(0|[1-9][0-9]*)$/.test(context?.source ?? "")) throw mismatch("Undecodable");
      return key === "amount" ? BigInt(context?.source ?? "") : value;
    }) as unknown;
    const row = fields(wire, ["ring", "feePayer", "signer", "slots", "nullifiers", "setup"]);
    return Object.freeze({
      ring: address(row["ring"] as string),
      feePayer: address(row["feePayer"] as string),
      signer: address(row["signer"] as string),
      slots: (row["slots"] as readonly unknown[]).map(decodeSlotOpening),
      nullifiers: (row["nullifiers"] as readonly unknown[]).map(hash32),
      setup: (row["setup"] as readonly unknown[]).map((entry) => {
        const create = fields(entry, ["owner", "mint", "tokenProgram"]);
        return Object.freeze({
          owner: address(create["owner"] as string),
          mint: address(create["mint"] as string),
          tokenProgram: address(create["tokenProgram"] as string),
        });
      }),
    });
  });
}

function decodeSlotOpening(value: unknown): SlotOpening {
  const row = fields(value, [
    "slot",
    "owner",
    "nullifierPk",
    "mint",
    "amount",
    "blinding",
    "treeId",
    "dataHash",
    "ringDataHash",
  ]);
  return Object.freeze({
    slot: integer(row["slot"], 0xffff_ffff),
    owner: address(row["owner"] as string),
    nullifierPk: hash32(row["nullifierPk"]),
    mint: address(row["mint"] as string),
    amount: u64Amount(row["amount"]),
    blinding: hash32(row["blinding"]),
    treeId: integer(row["treeId"], 0xffff),
    dataHash: hash32(row["dataHash"]),
    ringDataHash: hash32(row["ringDataHash"]),
  });
}

/** Rust `deny_unknown_fields` with every field required. */
function fields(value: unknown, names: readonly string[]): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null) throw mismatch("Undecodable");
  const present = Object.keys(value);
  if (present.length !== names.length || !names.every((name) => present.includes(name)))
    throw mismatch("Undecodable");
  return value as Readonly<Record<string, unknown>>;
}

function hash32(value: unknown): Bytes32 {
  const bytes = new Uint8Array(getBase58Encoder().encode(value as string));
  if (bytes.length !== 32) throw mismatch("Undecodable");
  return bytes as Bytes32;
}

function integer(value: unknown, limit: number): number {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > limit)
    throw mismatch("Undecodable");
  return value as number;
}

function u64Amount(value: unknown): bigint {
  if (typeof value !== "bigint" || value < 0n || value > U64_MAX) throw mismatch("Undecodable");
  return value;
}

export async function expectedPublicOwner(
  input: Readonly<{
    terms: RelayTransferTerms;
    config: DelegateRingConfig;
    knownNotes: readonly Pick<WalletUtxo, "nullifier">[];
  }>,
): Promise<ExpectedPublicOwner> {
  const { terms, config } = input;
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
    kind: "publicOwner",
    terms,
    policy,
    setup: Object.freeze(setup),
    rail: ringRailOf(RingInstructionTag.transfer, config.mode),
    knownNullifiers: Object.freeze(input.knownNotes.map((note) => note.nullifier)),
  });
}

export function checkRelayMessage(
  expected: ExpectedRelayMessage,
  message: Uint8Array,
  signer: Address,
): VerifiedRelayMessage {
  if (expected.kind === "deposit") return checkDepositMessage(expected, message);
  if (expected.kind === "enroll") return checkEnrollMessage(expected, message);
  if (expected.kind === "sealed") throw mismatch("Unrequested");
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
    program: expected.ring,
    policy: expected.policy,
    units: ringComputeUnitLimit(RingInstructionTag.deposit),
    feePayer: expected.feePayer,
    signer: expected.depositor,
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

export async function expectedEnroll(
  inputs: RelayEnrollInputs,
  feePayer: Address,
): Promise<ExpectedEnroll> {
  const [policy, proved] = await Promise.all([
    ringPolicyAddress(inputs.ringProgramId),
    relayEnrollInstruction(inputs, feePayer),
  ]);
  return Object.freeze({
    kind: "enroll",
    feePayer,
    policy,
    inputs,
    accounts: proved.accounts ?? [],
  });
}

function checkEnrollMessage(expected: ExpectedEnroll, message: Uint8Array): VerifiedRelayMessage {
  const envelope: Envelope = {
    program: STORAGE_PROGRAM_ID,
    policy: expected.policy,
    units: ENROLL_COMPUTE_UNITS,
    feePayer: expected.feePayer,
    signer: expected.inputs.owner,
    setup: [],
  };
  const { data, accounts } = open(envelope, message);
  if (!sameAccounts(accounts, expected.accounts)) throw mismatch("Accounts");
  const signed = enrollRequestDigest({ ...expected.inputs, instructionData: data });
  if (!equalBytes(signed, enrollRequestDigest(expected.inputs))) throw mismatch("Data");
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
}

/** The account a settling message reads its frame from, `undefined` on an inline message. */
export function settledBufferOf(
  expected: ExpectedRelayMessage,
  message: Uint8Array,
  signer: Address,
): Address | undefined {
  if (expected.kind === "deposit" || expected.kind === "enroll" || expected.kind === "sealed")
    return undefined;
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
  if (expected.kind === "sealed") throw mismatch("Unrequested");
  if (expected.kind === "deposit" || expected.kind === "enroll") throw mismatch("Data");
  const envelope = frameEnvelope(expected, signer, RingInstructionTag.settleBuffered);
  const { data, accounts } = open(envelope, message);
  if (accounts.length < 2) throw mismatch("Accounts");
  const frame = bufferedFrame(buffer);
  if (frame === undefined || !equalBytes(data, settleBufferedData(frameDigest(frame))))
    throw mismatch("Data");
  checkFrame(expected, signer, frame, accounts.slice(2));
  return new VerifiedRelayMessage(VERIFIED, envelope.signer, message);
}

function frameTag(expected: ExpectedDelegate | ExpectedPublicOwner): RingInstructionTag {
  return expected.kind === "delegate"
    ? RingInstructionTag.authorityTransfer
    : RingInstructionTag.transfer;
}

function frameEnvelope(
  expected: ExpectedDelegate | ExpectedPublicOwner,
  signer: Address,
  tag: RingInstructionTag,
): Envelope {
  if (expected.kind === "delegate")
    return {
      program: expected.ring,
      policy: expected.policy,
      units: ringComputeUnitLimit(tag),
      feePayer: expected.feePayer,
      signer: expected.delegate,
      setup: [],
    };
  const { terms, policy, setup } = expected;
  if (terms.signer !== signer) throw mismatch("Unrequested");
  return {
    program: terms.ring,
    policy,
    units: ringComputeUnitLimit(tag),
    feePayer: terms.feePayer,
    signer,
    setup,
  };
}

function checkFrame(
  expected: ExpectedDelegate | ExpectedPublicOwner,
  signer: Address,
  data: Uint8Array,
  accounts: readonly AccountMeta[],
): void {
  const tag = frameTag(expected);
  if (data[0] !== tag) throw mismatch("Data");
  const frame = withMismatch("Data", () => RingTransactData.parse(data.subarray(1), expected.rail));
  if (expected.kind === "delegate") checkMoved(expected, frame);
  else checkOpenings(expected, frame);
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
        record.mint === payment.mint &&
        record.amount === payment.amount &&
        owns(payment.owner, record),
    );
    if (paid < 0) {
      if (!expected.sources.some((source) => owns(source, record))) throw mismatch("Recipients");
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
    const opened = openSealedDisclosure(txViewingKey, auditor, {
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
}

function checkOpenings(expected: ExpectedPublicOwner, frame: RingTransactData): void {
  const { terms, knownNullifiers } = expected;
  if (terms.slots.length === 0 && terms.nullifiers.length === 0) throw mismatch("Unrequested");
  for (const opening of terms.slots) {
    const published = frame.outputs[opening.slot];
    if (
      published === undefined ||
      opening.owner !== terms.signer ||
      !equalBytes(
        withMismatch("Recipients", () => openingHash(opening, terms.ring)),
        published.hash,
      )
    )
      throw mismatch("Recipients");
  }
  const among = (list: readonly Uint8Array[], nullifier: Uint8Array): boolean =>
    list.some((held) => equalBytes(held, nullifier));
  // A named note the wallet cannot place means no list stood behind the check.
  if (
    !terms.nullifiers.every(
      (named) => among(frame.nullifiers, named) && among(knownNullifiers, named),
    )
  )
    throw mismatch("Data");
  if (
    frame.nullifiers.some(
      (spent) => among(knownNullifiers, spent) && !among(terms.nullifiers, spent),
    )
  )
    throw mismatch("SpendsUnnamedNote");
}

export function openingHash(opening: SlotOpening, ring: Address): Bytes32 {
  return new Utxo({
    owner: ShieldedPublicKey.fromEd25519(addressBytes(opening.owner) as Bytes32),
    asset: opening.mint,
    amount: opening.amount,
    blinding: opening.blinding,
    ringProgramId: ring,
  })
    .proofInput(opening.nullifierPk, opening.treeId, opening.dataHash, opening.ringDataHash)
    .hash();
}

export function mismatch(reason: RelayMessageMismatch): RingError {
  return new RingError("RING_RELAY_MESSAGE_INVALID", { details: { mismatch: reason } });
}

interface Envelope {
  readonly program: Address;
  readonly policy: Address;
  readonly units: number;
  readonly feePayer: Address;
  readonly signer: Address;
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
    config.computeUnitLimit <= envelope.units &&
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
  if (instruction.programAddress !== envelope.program) throw mismatch("Program");
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
