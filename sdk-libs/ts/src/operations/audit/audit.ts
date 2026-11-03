import { historyCursor, historyCursorToken, nextHistoryToken } from "../../rpc/history.js";
import type { IndexerReader, KitRpcAccess } from "@heliuslabs/zolana/client";
import {
  addressBytes,
  hashBytes,
  solanaOwnerIdentity,
  ZERO_32,
  ZERO_NULLIFIER_PK,
  equalBytes,
  bytesKey,
  isCanonicalField,
  fetchSplAssetRegistrations,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type {
  Address,
  Bytes16,
  Bytes32,
  RequestContext,
  Signature,
} from "@heliuslabs/zolana/interface";
import {
  KeypairError,
  ownerHash,
  ViewingKey,
  X25519PublicKey,
  type X25519Keypair,
} from "@heliuslabs/zolana/keypair";
import type {
  AssetRegistry,
  IndexedShieldedTransaction,
  OutputContext,
  OutputSlot,
} from "@heliuslabs/zolana/transaction";
import {
  openDeliveredBody,
  readRingOutput,
  RingScheme,
} from "../../protocol/transaction/output.js";
import {
  deliveredBodyLen,
  type AuditStreamLayout,
} from "../../protocol/codec/ring-disclosure-layout.js";
import {
  auditorViewTag,
  openTransactionViewingSecret,
  parseAuditorMessage,
  type AuditorMessage,
} from "../../crypto/audit/audit.js";
import {
  canonicalViewingKey,
  openAuditEnvelope,
  type AnonymousOutputOpening,
  type DeliveredOutputOpening,
  type RingDisclosure,
} from "../../crypto/audit/ring-disclosure.js";
import { deliveredSlotSecret, ringIdField } from "../../crypto/derivation/ring-stream.js";

import { RingError } from "../../protocol/error.js";
import type { MergeInput } from "../../state/merge-ledger.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";
import { RpcTransactionOrigin, type TransactionOrigin } from "../../protocol/transaction/origin.js";
import { RowOrigins } from "./row-origins.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../crypto/derivation/blinding.js";
import { dummyUtxoHash, fieldUtxoHash } from "../../protocol/membership/utxo-hash.js";
import { outputTreeId } from "../../protocol/membership/trees.js";
import { x25519FromU } from "../../crypto/keys/x25519.js";

/** Rust `AuditedUtxo`, an opening whose UTXO hash the audit rebuilt. */
export interface AuditedUtxo {
  /** The raw Solana key whose owner identity the commitment binds. */
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  /** `hashBytes(mint)`. */
  readonly asset: Bytes32;
  /** Absent until the asset registry knows the asset. */
  readonly mint?: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
}

/** The owner tag a ring output was published under, Rust `RingOwnerTag`. */
export type RingOwnerTag =
  /** The recipient key's u on the delivered rails. */
  | Readonly<{ kind: "recipient"; u: Bytes32 }>
  /** A view tag the anonymous proof leaves free. */
  | Readonly<{ kind: "view"; tag: Bytes32 }>;

/** Rust `OutputOpening`. */
export type OutputOpening =
  | Readonly<{ kind: "ring"; utxo: AuditedUtxo; ownerTag: RingOwnerTag }>
  /** A default-ring UTXO, its owner the published owner tag. */
  | Readonly<{ kind: "exit"; utxo: AuditedUtxo }>
  | Readonly<{ kind: "dummy" }>
  /** A key escrow slot before its owner's record is read, its proof fixes the fields and no hash rebuilds. */
  | (Readonly<{ kind: "escrowPending" }> & EscrowPendingOutput);

/** Rust `EscrowPendingOutput`. */
export interface EscrowPendingOutput {
  readonly ownerKey: Bytes32;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly slot: EscrowPendingSlot;
}

/** Rust `EscrowPendingSlot`. */
export type EscrowPendingSlot =
  /** A delivered body omits the asset, only the nullifier key finds it. */
  | Readonly<{ kind: "ring"; recipientU: Bytes32 }>
  | Readonly<{ kind: "exit"; asset: Bytes32; mint?: Address }>;

type RebuiltOpening = Exclude<OutputOpening, { kind: "escrowPending" }>;

/** Rust `AuditedOutput`, one published slot whose rebuilt commitment is the published one. */
export interface AuditedRingOutput {
  readonly slotIndex: number;
  readonly outputContext: OutputContext;
  readonly opening: OutputOpening;
}

/** Rust `OutputPayloadErrorKind`, why a published slot did not open. */
export type OutputPayloadErrorKind =
  | "frame"
  | "disclosure"
  | "recipientKey"
  | "commitment"
  /** No registered asset rebuilds the commitment. */
  | "unknownAsset";

export interface OutputPayloadError {
  readonly slotIndex: number;
  readonly kind: OutputPayloadErrorKind;
}

/** Rust `AuditedSender`, the owner of every UTXO an anonymous transfer spends. */
export interface AuditedSender {
  readonly ownerKey: Bytes32;
  /** Spent UTXO 0's key, absent when that UTXO is a deposit. */
  readonly nullifierPk?: Bytes32;
}

/** Rust `InputRing`, SPP spends a UTXO of the ring or of the default ring and the disclosure names neither. */
export type InputRing =
  | Readonly<{ kind: "ring"; commitment: Bytes32 }>
  | Readonly<{ kind: "default"; commitment: Bytes32 }>
  /** No known commitment told the candidates apart. */
  | Readonly<{ kind: "unresolved"; ring: Bytes32; default: Bytes32 }>;

export interface AuditedInputOpening {
  readonly asset: Bytes32;
  readonly mint?: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  /** Absent without the input's tree id, every commitment binds it. */
  readonly ring?: InputRing;
}

/** Rust `InputOpening`. */
export type InputOpening =
  | Readonly<{ kind: "dummy" }>
  | (Readonly<{ kind: "opened" }> & AuditedInputOpening)
  /** A merge output's audit record with no blinding, a wallet cannot spend from it. */
  | Readonly<{
      kind: "merged";
      ownerKey: Bytes32;
      asset: Bytes32;
      mint?: Address;
      amount: bigint;
    }>
  /** The evidence names a note the auditor lacks, the outputs still open. */
  | Readonly<{ kind: "unseenHash"; hash: Bytes32 }>;

export interface AuditedInput {
  readonly nullifier: Bytes32;
  /** The commitment the evidence names, absent at a dummy. */
  readonly hash?: Bytes32;
  readonly opening: InputOpening;
}

/** @internal One audited frame, its input opening per frame format. */
export type AuditedTransferOf<Input> = Omit<AuditedRingTransaction, "inputs"> &
  Readonly<{
    inputs: readonly Readonly<{
      nullifier: Bytes32;
      hash?: Bytes32;
      opening: Input;
    }>[];
  }>;

/** Rust `AuditedTransaction`. */
export interface AuditedRingTransaction {
  readonly signature: Signature;
  readonly slot: bigint;
  /** Checked against the key the auditor envelope seals. */
  readonly txViewingPublicKey: X25519PublicKey;
  /** Published order, a slot that did not open sits in `payloadErrors` instead. */
  readonly outputs: readonly AuditedRingOutput[];
  readonly payloadErrors: readonly OutputPayloadError[];
  /** One per published slot, a payload error names its slot here. */
  readonly outputCommitments: readonly Bytes32[];
  /** The hidden sender of an anonymous transfer, absent while `hash_0` names a note the auditor lacks. */
  readonly sender?: AuditedSender;
  /** One per published nullifier. */
  readonly inputs: readonly AuditedInput[];
}

/** Rust `UtxoOwner`. */
export type UtxoOwner =
  | Readonly<{ kind: "keyed"; nullifierPk: Bytes32 }>
  /** A deposit capsule discloses the owner hash alone. */
  | Readonly<{ kind: "deposited"; ownerHash: Bytes32 }>;

/** A UTXO an earlier audit opened, a later disclosure names it by its hash. */
export interface KnownUtxo extends Omit<AuditedUtxo, "nullifierPk"> {
  readonly owner: UtxoOwner;
  readonly treeId: number;
}

/** Rust `CreatedUtxo`. */
export interface CreatedRingUtxo {
  readonly commitment: Bytes32;
  readonly slotIndex: number;
  readonly utxo: KnownUtxo;
}

/** Rust `KnownUtxos`, UTXOs the auditor opened before. */
export interface KnownUtxos {
  utxo(commitment: Bytes32): KnownUtxo | undefined;
  /** The inherited fields of a merge output the ledger resolved. */
  merged?(commitment: Bytes32): MergeInput | undefined;
}

export class KnownUtxoIndex implements KnownUtxos {
  readonly #utxos = new Map<string, KnownUtxo>();

  constructor(utxos: Iterable<Readonly<{ commitment: Bytes32; utxo: KnownUtxo }>> = []) {
    for (const { commitment, utxo } of utxos) this.insert(commitment, utxo);
  }

  /** A later opening of a known commitment replaces it only to name its mint. */
  insert(commitment: Bytes32, utxo: KnownUtxo): void {
    const key = bytesKey(commitment);
    const kept = this.#utxos.get(key);
    if (kept !== undefined && (kept.mint !== undefined || utxo.mint === undefined)) return;
    this.#utxos.set(key, utxo);
  }

  utxo(commitment: Bytes32): KnownUtxo | undefined {
    return this.#utxos.get(bytesKey(commitment));
  }
}

/** By raw Solana key, the audit tries the zero key after it. */
export interface EscrowedKeys {
  nullifierPk(ownerKey: Bytes32): Bytes32 | undefined;
}

export interface RingAuditPage {
  readonly transactions: readonly AuditedRingTransaction[];
  /** Landed rows that fail to decode or fail their audit, each opens nothing. */
  readonly skipped: readonly SkippedRingTransaction[];
  /** Set only when the page cap stopped the scan. */
  readonly nextCursor?: string;
}

export type RingAuditReader = KitRpcAccess & Pick<IndexerReader, "getShieldedTransactionsByTags">;

const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 32;

/** The program keeps the auditor's message last, a sender bundle before it may carry any tag. */
export function auditorMessage(
  transaction: IndexedShieldedTransaction,
  auditorPublicKey: X25519PublicKey,
): Uint8Array {
  const message = transaction.messages.at(-1);
  if (message === undefined || !equalBytes(message.viewTag, auditorViewTag(auditorPublicKey)))
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "missing" },
    });
  return message.data;
}

/** The envelope's key alone, a full audit reads it from `openAuditEnvelope`. */
export function recoverTransactionViewingKey(
  auditor: X25519Keypair,
  message: AuditorMessage,
): ViewingKey {
  return canonicalViewingKey(openTransactionViewingSecret(auditor, message));
}

interface TransactionAuditInput {
  readonly auditor: X25519Keypair;
  readonly transaction: IndexedShieldedTransaction;
  readonly assets: AssetRegistry;
  /** The layout the ring program verified the audit proof under, `ConfirmedRingTransaction` reads it. */
  readonly layout: AuditStreamLayout;
  /** One per published nullifier, the tree the input was spent from. */
  readonly inputTreeIds?: readonly (number | undefined)[];
  /** Opens a commitment-layout input. */
  readonly knownUtxos?: KnownUtxos;
  /** The output nullifier keys a key-escrow ring leaves out of its disclosure. */
  readonly escrowedKeys?: EscrowedKeys;
}

/** Mirrors Rust `TransactionAudit::run`, every published commitment rebuilt from the disclosure. */
export function auditRingTransaction(input: TransactionAuditInput): AuditedRingTransaction {
  return openRingTransfer(input).audited;
}

/** @internal `auditRingTransaction` with its opening kept for a later asset lookup. */
export function openRingTransfer(input: TransactionAuditInput): OpenedRingTransfer {
  const { layout, auditor, transaction } = input;
  return auditTransferWith<RingDisclosure, InputOpening>(
    {
      transaction,
      assets: input.assets,
      ...(input.inputTreeIds === undefined ? {} : { inputTreeIds: input.inputTreeIds }),
      ...(input.escrowedKeys === undefined ? {} : { escrowedKeys: input.escrowedKeys }),
      counts: layout,
      open: () =>
        openAuditEnvelope(auditor, {
          layout,
          message: parsedMessage(auditorMessage(transaction, auditor.publicKey()), layout),
        }),
    },
    (transfer, disclosure, spent) =>
      transfer.inputs({
        evidence: disclosure,
        ...spent,
        ...(input.knownUtxos === undefined ? {} : { known: input.knownUtxos }),
      }),
  );
}

/** @internal What a stream opens to, shared with the historical reader. */
export interface OpenedEnvelope<Disclosure> {
  readonly txViewingKey: ViewingKey;
  disclosure(): Disclosure;
  destroy(): void;
}

/** @internal The published slots a disclosure must fit. */
export interface SlotDisclosure {
  readonly kind: "delivered" | "anonymous";
  readonly layout: Readonly<{ keyEscrow: boolean }>;
  readonly outputs: readonly (DeliveredOutputOpening | AnonymousOutputOpening)[];
}

/** @internal The slot audit every frame format shares, `readInputs` decodes its own evidence. */
export function auditTransferWith<Disclosure extends SlotDisclosure, Input>(
  input: Readonly<{
    transaction: IndexedShieldedTransaction;
    assets: AssetRegistry;
    inputTreeIds?: readonly (number | undefined)[];
    escrowedKeys?: EscrowedKeys;
    /** The counts and exits the program bound the layout to. */
    counts: Readonly<{ outputs: number; exits: bigint; inputs: number }>;
    open: (message: Uint8Array) => OpenedEnvelope<Disclosure>;
    auditor?: never;
  }>,
  readInputs: (
    transfer: TransferSlots,
    disclosure: Disclosure,
    spent: Readonly<{
      nullifiers: readonly Bytes32[];
      trees?: readonly (number | undefined)[];
    }>,
  ) => SpentInputs<Input>,
): OpenedRingTransfer<Input> {
  const { transaction, counts } = input;
  const unsealed = (reason: string): RingError =>
    new RingError("RING_AUDIT_UNSEALED", {
      details: { reason, signature: transaction.txSignature },
    });
  const txViewingPublicKey = transaction.txViewingPublicKey;
  if (txViewingPublicKey === undefined) throw unsealed("txViewingPk");
  const salt = transaction.salt;
  if (salt === undefined) throw unsealed("salt");
  const ring = transaction.ringProgramId;
  if (ring === undefined) throw unsealed("ringProgramId");
  const firstNullifier = transaction.nullifiers[0];
  if (firstNullifier === undefined) throw unsealed("nullifier");
  if (
    input.inputTreeIds !== undefined &&
    input.inputTreeIds.length !== transaction.nullifiers.length
  )
    throw new RingError("RING_INVALID_LENGTH", {
      details: {
        name: "inputTreeIds",
        expected: transaction.nullifiers.length,
        actual: input.inputTreeIds.length,
      },
    });
  const exits = transaction.outputSlots.reduce(
    (bits, slot, index) => (isExit(slot) ? bits | (1n << BigInt(index)) : bits),
    0n,
  );
  // The program bound the layout to these counts and exits, the message length checks the rest.
  if (
    counts.outputs !== transaction.outputSlots.length ||
    counts.exits !== exits ||
    counts.inputs !== transaction.nullifiers.length
  )
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "layout" },
    });
  const opened = input.open(lastAuditorMessage(transaction));
  const txKey = opened.txViewingKey;
  const txViewingSecret = txKey.secretBytes();
  try {
    // The proof binds the envelope to the published key, a mismatch is a forged message.
    if (!txKey.publicKey().equals(txViewingPublicKey))
      throw new RingError("RING_AUDIT_KEY_MISMATCH", {
        details: { signature: transaction.txSignature },
      });
    const disclosure = opened.disclosure();
    const transfer = new TransferSlots({
      ring,
      txKey,
      txViewingSecret,
      txViewingPublicKey,
      salt,
      firstNullifier,
      blindingSeed: ringBlindingSeed(txViewingSecret, salt),
      assets: input.assets,
      ...(input.escrowedKeys === undefined ? {} : { escrowed: input.escrowedKeys }),
    });
    const audited = new AuditRecord();
    transaction.outputSlots.forEach((output, index) => {
      const slot = { index, output };
      audited.record(slot, transfer.open(slot, disclosure));
    });
    const spent = readInputs(transfer, disclosure, {
      nullifiers: transaction.nullifiers,
      ...(input.inputTreeIds === undefined ? {} : { trees: input.inputTreeIds }),
    });
    return new OpenedRingTransfer<Input>(
      Object.freeze({
        signature: transaction.txSignature,
        slot: transaction.slot,
        txViewingPublicKey,
        outputs: Object.freeze(audited.outputs),
        payloadErrors: Object.freeze(audited.payloadErrors),
        outputCommitments: Object.freeze(
          transaction.outputSlots.map((slot) => slot.outputContext.hash),
        ),
        ...(spent.sender === undefined ? {} : { sender: spent.sender }),
        inputs: spent.inputs,
      }),
      { ring, bodies: audited.bodies },
    );
  } finally {
    txViewingSecret.fill(0);
    opened.destroy();
  }
}

/** The program keeps the auditor's message last, its tag checked by the stream's key. */
function lastAuditorMessage(transaction: IndexedShieldedTransaction): Uint8Array {
  const message = transaction.messages.at(-1);
  if (message === undefined)
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "missing" },
    });
  return message.data;
}

/** @internal An audited transfer, a registry refresh repeats no check its opening passed. */
export class OpenedRingTransfer<Input = InputOpening> {
  constructor(
    readonly audited: AuditedTransferOf<Input>,
    private readonly opening: Readonly<{
      ring: Address;
      /** The bodies no registered asset rebuilt, by slot. */
      bodies: ReadonlyMap<number, DeliveredBody>;
    }>,
  ) {}

  /** Rust `AuditedTransaction::resolve`, each asset lookup retried without the auditor stream. */
  withAssets(assets: AssetRegistry): AuditedTransferOf<Input> {
    const { audited, opening } = this;
    const record = new AuditRecord();
    record.outputs.push(...audited.outputs.map((output) => namedOutput(output, assets)));
    for (const error of audited.payloadErrors) {
      const body = opening.bodies.get(error.slotIndex);
      if (body === undefined) record.payloadErrors.push(error);
      else record.record(body.slot, deliveredOpening(opening.ring, body, assets));
    }
    return Object.freeze({
      ...audited,
      outputs: Object.freeze(record.outputs.sort((a, b) => a.slotIndex - b.slotIndex)),
      payloadErrors: Object.freeze(record.payloadErrors),
      inputs: Object.freeze(audited.inputs.map((spent) => namedInput(spent, assets))),
    }) as AuditedTransferOf<Input>;
  }
}

/** Every opened UTXO by its hash, Rust `AuditedTransaction::utxos`. */
export function auditedUtxos(transaction: AuditedRingTransaction): readonly CreatedRingUtxo[] {
  return transaction.outputs.flatMap((output) =>
    output.opening.kind === "dummy" || output.opening.kind === "escrowPending"
      ? []
      : [
          Object.freeze({
            commitment: output.outputContext.hash,
            slotIndex: output.slotIndex,
            utxo: openedUtxo(output.opening.utxo, outputTreeId(output.outputContext)),
          }),
        ],
  );
}

/** Rust `KnownUtxo::opened`. */
export function openedUtxo(utxo: AuditedUtxo, treeId: number): KnownUtxo {
  const { nullifierPk, ...fields } = utxo;
  return Object.freeze({
    ...fields,
    owner: Object.freeze({ kind: "keyed", nullifierPk }),
    treeId,
  });
}

/** Rust `KnownUtxo::commitment`, `ringId` zero for a default-ring UTXO. */
export function knownUtxoHash(utxo: KnownUtxo, ringId: Bytes32): Bytes32 {
  return fieldUtxoHash({
    owner: knownUtxoOwnerHash(utxo),
    assetField: utxo.asset,
    amount: utxo.amount,
    blinding: utxo.blinding,
    treeId: utxo.treeId,
    dataHash: utxo.dataHash,
    ringDataHash: utxo.ringDataHash,
    ringId,
  });
}

export function knownUtxoOwnerHash(utxo: Pick<KnownUtxo, "ownerKey" | "owner">): Bytes32 {
  return utxo.owner.kind === "keyed"
    ? (ownerHash(solanaOwnerIdentity(utxo.ownerKey), utxo.owner.nullifierPk) as Bytes32)
    : utxo.owner.ownerHash;
}

/** Rust `AuditedTransaction::has_unknown_assets`, a registry refresh may name the mint, a delivered slot opens only after it. */
export function hasUnknownAssets(transaction: AuditedRingTransaction): boolean {
  return (
    auditedUtxos(transaction).some(({ utxo }) => utxo.mint === undefined) ||
    transaction.payloadErrors.some(({ kind }) => kind === "unknownAsset") ||
    transaction.inputs.some(
      (input) => input.opening.kind === "opened" && input.opening.mint === undefined,
    )
  );
}

/** Mirrors Rust `RingScan::audit`, each tagged event attributed through its confirmed call stack. */
export async function auditRing(
  input: Readonly<{
    client: RingAuditReader;
    auditor: X25519Keypair;
    ringProgramId: Address;
    assets: AssetRegistry;
    /** The output nullifier keys a key-escrow ring leaves out of its disclosure. */
    escrowedKeys?: EscrowedKeys;
    /** UTXOs opened outside the scan, earlier pages and `createdRingUtxos` among them. */
    knownUtxos?: KnownUtxos;
    origin?: TransactionOrigin;
    cursor?: string;
    pageSize?: number;
    maxPages?: number;
  }>,
  context?: RequestContext,
): Promise<RingAuditPage> {
  await initializePoseidon();
  const viewTag = auditorViewTag(input.auditor.publicKey());
  const pageSize = input.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxPages = input.maxPages ?? DEFAULT_MAX_PAGES;
  for (const [name, value] of [
    ["pageSize", pageSize],
    ["maxPages", maxPages],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1)
      throw new RingError("RING_RPC", {
        details: { reason: "invalid scan limit", name, value },
      });
  }
  const origin = input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc);
  const rows = new RowOrigins(origin, input.ringProgramId, context);
  const known = new ScanUtxos(input.knownUtxos);
  const transactions: AuditedRingTransaction[] = [];
  let assetsRefreshed = false;
  let token = historyCursorToken(input.cursor, input.ringProgramId, "tags");
  for (let page = 0; page < maxPages; page++) {
    const response = await input.client.getShieldedTransactionsByTags(
      {
        tags: [viewTag],
        limit: pageSize,
        ...(token === undefined ? {} : { paginationToken: token }),
      },
      undefined,
      context,
    );
    for (const indexed of response.data.flatMap((item) => item.events)) {
      if (indexed.ringProgramId !== input.ringProgramId) continue;
      const confirmed = await rows.read(indexed);
      if (confirmed?.kind !== "transfer") continue;
      const opened = rows.attempt(indexed, () =>
        openRingTransfer({
          auditor: input.auditor,
          transaction: confirmed.transaction,
          assets: input.assets,
          layout: confirmed.layout,
          inputTreeIds: confirmed.inputTreeIds,
          knownUtxos: known,
          ...(input.escrowedKeys === undefined ? {} : { escrowedKeys: input.escrowedKeys }),
        }),
      );
      if (opened === undefined) continue;
      let audited: AuditedRingTransaction | undefined = opened.audited;
      if (!assetsRefreshed && hasUnknownAssets(audited)) {
        assetsRefreshed = true;
        for (const { assetId, mint } of await fetchSplAssetRegistrations(input.client, context))
          input.assets.register(assetId, mint);
        audited = rows.attempt(indexed, () => opened.withAssets(input.assets));
        if (audited === undefined) continue;
      }
      known.add(audited);
      transactions.push(audited);
    }
    const next = nextHistoryToken(token, response);
    if (next === undefined)
      return Object.freeze({
        transactions: Object.freeze(transactions),
        skipped: Object.freeze(rows.skipped),
      });
    token = next;
  }
  return Object.freeze({
    transactions: Object.freeze(transactions),
    skipped: Object.freeze(rows.skipped),
    ...(token === undefined
      ? {}
      : { nextCursor: historyCursor(input.ringProgramId, "tags", token) }),
  });
}

/** The ring program encodes every exit under scheme 3, every other slot under its rail's scheme. */
function isExit(slot: OutputSlot): boolean {
  return encryptedBody(slot.payload, RingScheme.confidential) !== undefined;
}

/** The body of an encrypted payload of `scheme`, `undefined` for any other frame. */
function encryptedBody(payload: Uint8Array, scheme: RingScheme): Uint8Array | undefined {
  try {
    const frame = readRingOutput(payload);
    return frame.encoding === "encrypted" && frame.scheme === scheme ? frame.body : undefined;
  } catch {
    return undefined;
  }
}

function parsedMessage(data: Uint8Array, layout: AuditStreamLayout): AuditorMessage {
  try {
    return parseAuditorMessage(data, layout);
  } catch (cause) {
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "malformed", length: data.length },
      cause,
    });
  }
}

interface Slot {
  readonly index: number;
  readonly output: OutputSlot;
}

type SlotOpening =
  | Readonly<{ ok: true; opening: OutputOpening }>
  | Readonly<{
      ok: false;
      kind: Exclude<OutputPayloadErrorKind, "unknownAsset">;
    }>
  | Readonly<{ ok: false; kind: "unknownAsset"; body: DeliveredBody }>;

/** A delivered body under a known nullifier key, only its asset is left to find. */
interface DeliveredBody {
  readonly slot: Slot;
  readonly recipientU: Bytes32;
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly amount: bigint;
  readonly blinding: Bytes32;
}

/** An exit of a delivered rail, its owner key published as its owner tag. */
interface DeliveredExit {
  readonly nullifierPk: Bytes32 | undefined;
  readonly asset: Bytes32;
  readonly amount: bigint;
}

/** @internal */
export interface SpentInputs<Input> {
  /** Absent outside the anonymous rail. */
  readonly sender?: AuditedSender;
  readonly inputs: readonly Readonly<{
    nullifier: Bytes32;
    hash?: Bytes32;
    opening: Input;
  }>[];
}

/** @internal The slot audit, the auditor stream reads its evidence apart. */
export class TransferSlots {
  constructor(
    private readonly keys: Readonly<{
      ring: Address;
      txKey: ViewingKey;
      txViewingSecret: Bytes32;
      txViewingPublicKey: X25519PublicKey;
      salt: Bytes16;
      firstNullifier: Bytes32;
      blindingSeed: Bytes32;
      assets: AssetRegistry;
      escrowed?: EscrowedKeys;
    }>,
  ) {}

  open(slot: Slot, disclosure: SlotDisclosure): SlotOpening {
    switch (disclosure.kind) {
      case "delivered":
        return this.delivered(
          slot,
          disclosureSlot(disclosure.outputs as readonly DeliveredOutputOpening[], slot),
          disclosure.layout.keyEscrow,
        );
      case "anonymous":
        return this.anonymous(
          slot,
          disclosureSlot(disclosure.outputs as readonly AnonymousOutputOpening[], slot),
        );
    }
  }

  /** Each evidence entry is an opened commitment the proof binds, an unknown one reads unseen. */
  inputs(
    spent: Readonly<{
      evidence: RingDisclosure;
      nullifiers: readonly Bytes32[];
      trees?: readonly (number | undefined)[];
      known?: KnownUtxos;
    }>,
  ): SpentInputs<InputOpening> {
    const { nullifiers, known } = spent;
    const published = spent.evidence.inputs;
    if (published.kind === "commitments") {
      const openings = published.hashes.map((hash): InputOpening => {
        if (hash === undefined) return DUMMY_INPUT;
        const utxo = known?.utxo(hash);
        if (utxo !== undefined) return ringInput(hash, utxo);
        const merged = known?.merged?.(hash);
        return merged === undefined
          ? Object.freeze({ kind: "unseenHash", hash })
          : Object.freeze({
              kind: "merged",
              ownerKey: merged.ownerKey,
              asset: merged.asset,
              ...(merged.mint === undefined ? {} : { mint: merged.mint }),
              amount: merged.amount,
            });
      });
      const first = published.hashes[0];
      const zero = first === undefined ? undefined : (known?.utxo(first) ?? known?.merged?.(first));
      // Spent UTXO 0 is the hidden owner's, its record names the sender on the anonymous rail alone.
      const sender =
        spent.evidence.kind === "anonymous" && zero !== undefined
          ? Object.freeze({
              ownerKey: zero.ownerKey,
              ...(zero.owner.kind === "keyed" ? { nullifierPk: zero.owner.nullifierPk } : {}),
            })
          : undefined;
      return Object.freeze({
        ...(sender === undefined ? {} : { sender }),
        inputs: withHashes(spentInputs(nullifiers, openings), published.hashes),
      });
    }
    const openings = published.inputs.map((opening, index): InputOpening => {
      if (opening === undefined) return DUMMY_INPUT;
      const utxo = this.opened({
        ownerKey: published.senderKey,
        nullifierPk: published.senderNullifierPk,
        asset: opening.asset,
        amount: opening.amount,
        blinding: opening.blinding,
      });
      const tree = spent.trees?.[index];
      const ring = tree === undefined ? undefined : this.inputRing(utxo, tree, opening.hash);
      return Object.freeze({
        kind: "opened",
        asset: utxo.asset,
        ...(utxo.mint === undefined ? {} : { mint: utxo.mint }),
        amount: utxo.amount,
        blinding: utxo.blinding,
        ...(ring === undefined ? {} : { ring }),
      });
    });
    return Object.freeze({
      sender: Object.freeze({
        ownerKey: published.senderKey,
        nullifierPk: published.senderNullifierPk,
      }),
      inputs: withHashes(
        spentInputs(nullifiers, openings),
        published.inputs.map((input) => input?.hash),
      ),
    });
  }

  private delivered(slot: Slot, opening: DeliveredOutputOpening, keyEscrow: boolean): SlotOpening {
    return opening.kind === "exit"
      ? this.exit(slot, opening)
      : this.deliver(slot, deliveredBodyLen(keyEscrow));
  }

  private anonymous(slot: Slot, opening: AnonymousOutputOpening): SlotOpening {
    switch (opening.kind) {
      case "ring": {
        const utxo = this.opened({
          ownerKey: opening.ownerKey,
          nullifierPk: opening.nullifierPk,
          asset: opening.asset,
          amount: opening.amount,
          blinding: this.blinding(slot),
        });
        return this.verify(
          slot,
          Object.freeze({
            kind: "ring",
            utxo,
            ownerTag: Object.freeze({ kind: "view", tag: slot.output.viewTag }),
          }),
        );
      }
      case "exit":
        return this.exit(slot, opening);
      case "dummy":
        return this.verify(slot, DUMMY);
    }
  }

  /** A hidden dummy publishes random bytes under a random key, only its commitment names it. */
  private deliver(slot: Slot, bodyLength: number): SlotOpening {
    const dummy = this.verify(slot, DUMMY);
    if (dummy.ok) return dummy;
    const recipientU = slot.output.viewTag;
    const body = encryptedBody(slot.output.payload, RingScheme.ringConfidentialDelivered);
    if (body?.length !== bodyLength) return FRAME;
    const secret = this.deliveredSecret(slot, recipientU);
    if (secret === undefined) return Object.freeze({ ok: false, kind: "recipientKey" });
    try {
      const opened = openDeliveredBody(secret, body);
      const { ownerKey, amount } = opened;
      const blinding = this.blinding(slot);
      if (!equalBytes(opened.blinding, blinding)) return COMMITMENT;
      const registered = this.nullifierPk(ownerKey, opened.nullifierPk);
      if (registered !== undefined && !isCanonicalField(registered)) return COMMITMENT;
      let held: SlotOpening | undefined;
      for (const nullifierPk of nullifierKeys(registered)) {
        const body = Object.freeze({
          slot,
          recipientU,
          ownerKey,
          nullifierPk,
          amount,
          blinding,
        });
        const attempt = deliveredOpening(this.keys.ring, body, this.keys.assets);
        if (attempt.ok) return attempt;
        if (equalBytes(nullifierPk, registered ?? ZERO_NULLIFIER_PK)) held = attempt;
      }
      return registered === undefined
        ? escrowPending({
            ownerKey,
            amount,
            blinding,
            slot: Object.freeze({ kind: "ring", recipientU }),
          })
        : (held ?? COMMITMENT);
    } finally {
      secret.fill(0);
    }
  }

  private exit(slot: Slot, exit: DeliveredExit): SlotOpening {
    const registered = this.nullifierPk(slot.output.viewTag, exit.nullifierPk);
    for (const nullifierPk of nullifierKeys(registered)) {
      const utxo = this.opened({
        ownerKey: slot.output.viewTag,
        nullifierPk,
        asset: exit.asset,
        amount: exit.amount,
        blinding: this.blinding(slot),
      });
      const opening = this.verify(slot, Object.freeze({ kind: "exit", utxo }));
      if (opening.ok || exit.nullifierPk !== undefined) return opening;
    }
    if (registered !== undefined) return COMMITMENT;
    const mint = this.keys.assets.addressForField(exit.asset);
    return escrowPending({
      ownerKey: slot.output.viewTag,
      amount: exit.amount,
      blinding: this.blinding(slot),
      slot: Object.freeze({
        kind: "exit",
        asset: exit.asset,
        ...(mint === undefined ? {} : { mint }),
      }),
    });
  }

  /** The opening of `slot` when it rebuilds the published commitment. */
  private verify(slot: Slot, opening: RebuiltOpening): SlotOpening {
    const rebuilt =
      opening.kind === "dummy"
        ? equalBytes(
            dummyUtxoHash(outputTreeId(slot.output.outputContext), this.blinding(slot)),
            slot.output.outputContext.hash,
          )
        : rebuildsCommitment(this.keys.ring, slot, opening);
    return rebuilt ? Object.freeze({ ok: true, opening }) : COMMITMENT;
  }

  /** `undefined` when `recipientU` admits no agreement with the transaction key. */
  private deliveredSecret(slot: Slot, recipientU: Bytes32): Bytes32 | undefined {
    let agreement: Bytes32 | undefined;
    try {
      const recipient = x25519FromU(recipientU);
      agreement = this.keys.txKey.ecdh(recipient);
      return deliveredSlotSecret({
        agreement,
        txViewingKey: this.keys.txViewingPublicKey,
        recipientViewingKey: recipient,
        salt: this.keys.salt,
        outputIndex: slot.index,
        firstNullifier: this.keys.firstNullifier,
      });
    } catch (error) {
      if (error instanceof KeypairError) return undefined;
      throw error;
    } finally {
      agreement?.fill(0);
    }
  }

  /** SPP's TXOB blinding of the slot under the seed the transaction key fixes. */
  private blinding(slot: Slot): Bytes32 {
    return ringOutputBlinding({
      firstNullifier: this.keys.firstNullifier,
      blindingSeed: this.keys.blindingSeed,
      outputIndex: slot.index,
    });
  }

  /** The disclosed key, else the one the owner's record escrows. */
  private nullifierPk(ownerKey: Bytes32, disclosed: Bytes32 | undefined): Bytes32 | undefined {
    return disclosed ?? this.keys.escrowed?.nullifierPk(ownerKey);
  }

  private opened(
    fields: Readonly<{
      ownerKey: Bytes32;
      nullifierPk: Bytes32;
      asset: Bytes32;
      amount: bigint;
      blinding: Bytes32;
    }>,
  ): AuditedUtxo {
    const mint = this.keys.assets.addressForField(fields.asset);
    return Object.freeze({
      ownerKey: fields.ownerKey,
      nullifierPk: fields.nullifierPk,
      asset: fields.asset,
      ...(mint === undefined ? {} : { mint }),
      amount: fields.amount,
      blinding: fields.blinding,
      dataHash: ZERO_32,
      ringDataHash: ZERO_32,
    });
  }

  /** SPP spends a note of the ring or of the default ring, the disclosed hash tells them apart. */
  private inputRing(utxo: AuditedUtxo, treeId: number, hash: Bytes32): InputRing {
    const opened = openedUtxo(utxo, treeId);
    const ring = knownUtxoHash(opened, ringIdField(this.keys.ring));
    const fallback = knownUtxoHash(opened, ZERO_32);
    if (equalBytes(ring, hash)) return Object.freeze({ kind: "ring", commitment: ring });
    if (equalBytes(fallback, hash)) return Object.freeze({ kind: "default", commitment: fallback });
    return Object.freeze({ kind: "unresolved", ring, default: fallback });
  }
}

/** The disclosed or registered key then the zero key, every other key opens nothing. */
function nullifierKeys(registered: Bytes32 | undefined): readonly Bytes32[] {
  if (registered === undefined) return [ZERO_NULLIFIER_PK];
  return equalBytes(registered, ZERO_NULLIFIER_PK) ? [registered] : [registered, ZERO_NULLIFIER_PK];
}

function rebuildsCommitment(
  ring: Address,
  slot: Slot,
  opening: Extract<RebuiltOpening, { utxo: AuditedUtxo }>,
): boolean {
  const { outputContext } = slot.output;
  return equalBytes(
    knownUtxoHash(
      openedUtxo(opening.utxo, outputTreeId(outputContext)),
      opening.kind === "ring" ? ringIdField(ring) : ZERO_32,
    ),
    outputContext.hash,
  );
}

/** The body names no mint, the first registered asset that rebuilds the commitment is it. */
function deliveredOpening(ring: Address, body: DeliveredBody, assets: AssetRegistry): SlotOpening {
  const { slot, recipientU, ownerKey, nullifierPk, amount, blinding } = body;
  for (const [, mint] of assets.entries()) {
    const opening: RebuiltOpening = Object.freeze({
      kind: "ring",
      utxo: Object.freeze({
        ownerKey,
        nullifierPk,
        asset: hashBytes(addressBytes(mint, "mint")) as Bytes32,
        mint,
        amount,
        blinding,
        dataHash: ZERO_32,
        ringDataHash: ZERO_32,
      }),
      ownerTag: Object.freeze({ kind: "recipient", u: recipientU }),
    });
    if (rebuildsCommitment(ring, slot, opening)) return Object.freeze({ ok: true, opening });
  }
  return Object.freeze({ ok: false, kind: "unknownAsset", body });
}

function namedOutput(output: AuditedRingOutput, assets: AssetRegistry): AuditedRingOutput {
  const { opening } = output;
  if (opening.kind === "ring" || opening.kind === "exit")
    return Object.freeze({
      ...output,
      opening: Object.freeze({
        ...opening,
        utxo: withMint(opening.utxo, assets),
      }),
    });
  if (opening.kind === "escrowPending" && opening.slot.kind === "exit")
    return Object.freeze({
      ...output,
      opening: Object.freeze({
        ...opening,
        slot: withMint(opening.slot, assets),
      }),
    });
  return output;
}

function namedInput<Input>(
  spent: Readonly<{ nullifier: Bytes32; hash?: Bytes32; opening: Input }>,
  assets: AssetRegistry,
): Readonly<{ nullifier: Bytes32; hash?: Bytes32; opening: Input }> {
  const opening = spent.opening as InputOpening;
  return opening.kind === "opened"
    ? Object.freeze({ ...spent, opening: withMint(opening, assets) as Input })
    : spent;
}

function withMint<T extends Readonly<{ asset: Bytes32; mint?: Address }>>(
  named: T,
  assets: AssetRegistry,
): T {
  const mint = named.mint ?? assets.addressForField(named.asset);
  return mint === undefined ? named : Object.freeze({ ...named, mint });
}

/** The layout fixes one disclosed slot per published output. */
function disclosureSlot<T>(outputs: readonly T[], slot: Slot): T {
  const opening = outputs[slot.index];
  if (opening === undefined)
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "disclosure", slotIndex: slot.index },
    });
  return opening;
}

/** @internal Shared with the historical reader. */
export function ringInput(commitment: Bytes32, utxo: KnownUtxo): InputOpening {
  return Object.freeze({
    kind: "opened",
    asset: utxo.asset,
    ...(utxo.mint === undefined ? {} : { mint: utxo.mint }),
    amount: utxo.amount,
    blinding: utxo.blinding,
    ring: Object.freeze({ kind: "ring", commitment }),
  });
}

function withHashes<Input>(
  rows: readonly Readonly<{ nullifier: Bytes32; opening: Input }>[],
  hashes: readonly (Bytes32 | undefined)[],
): readonly Readonly<{ nullifier: Bytes32; hash?: Bytes32; opening: Input }>[] {
  return Object.freeze(
    rows.map((row, index) => {
      const hash = hashes[index];
      return hash === undefined ? row : Object.freeze({ ...row, hash });
    }),
  );
}

/** @internal Every key with evidence keeps dummies last as SPP does, opening k belongs to nullifier k. */
export function spentInputs<Input>(
  nullifiers: readonly Bytes32[],
  openings: readonly Input[],
): readonly Readonly<{ nullifier: Bytes32; opening: Input }>[] {
  return Object.freeze(
    openings.map((opening, index) => {
      const nullifier = nullifiers[index];
      if (nullifier === undefined)
        throw new RingError("RING_AUDIT_MESSAGE", {
          details: { reason: "layout" },
        });
      return Object.freeze({ nullifier, opening });
    }),
  );
}

export const DUMMY_INPUT: InputOpening = Object.freeze({ kind: "dummy" });
const DUMMY: RebuiltOpening = Object.freeze({ kind: "dummy" });
const FRAME: SlotOpening = Object.freeze({ ok: false, kind: "frame" });
const COMMITMENT: SlotOpening = Object.freeze({
  ok: false,
  kind: "commitment",
});

function escrowPending(fields: EscrowPendingOutput): SlotOpening {
  return Object.freeze({
    ok: true,
    opening: Object.freeze({ kind: "escrowPending", ...fields }),
  });
}

/** The outputs and payload errors of one audit, in published order. */
class AuditRecord {
  readonly outputs: AuditedRingOutput[] = [];
  readonly payloadErrors: OutputPayloadError[] = [];
  readonly bodies = new Map<number, DeliveredBody>();

  record(slot: Slot, opened: SlotOpening): void {
    if (opened.ok)
      this.outputs.push(
        Object.freeze({
          slotIndex: slot.index,
          outputContext: slot.output.outputContext,
          opening: opened.opening,
        }),
      );
    else {
      this.payloadErrors.push(Object.freeze({ slotIndex: slot.index, kind: opened.kind }));
      if (opened.kind === "unknownAsset") this.bodies.set(slot.index, opened.body);
    }
  }
}

class ScanUtxos implements KnownUtxos {
  readonly #opened = new KnownUtxoIndex();
  readonly #known: KnownUtxos | undefined;

  constructor(known: KnownUtxos | undefined) {
    this.#known = known;
  }

  add(transaction: AuditedRingTransaction): void {
    for (const { commitment, utxo } of auditedUtxos(transaction))
      this.#opened.insert(commitment, utxo);
  }

  utxo(commitment: Bytes32): KnownUtxo | undefined {
    return this.#opened.utxo(commitment) ?? this.#known?.utxo(commitment);
  }

  merged(commitment: Bytes32): MergeInput | undefined {
    return this.#known?.merged?.(commitment);
  }
}
