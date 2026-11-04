/** The slot audit of frames before statement version 4, tags 43 to 47. */
import type { IndexerReader, KitRpcAccess } from "@heliuslabs/zolana/client";
import { initializePoseidon } from "@heliuslabs/zolana";
import {
  addressBytes,
  equalBytes,
  fetchSplAssetRegistrations,
  hashBytes,
  isCanonicalField,
  mergePaddedInputCount,
  MERGE_OUTPUT_BODY_LENGTH,
  readMergeOutputBody,
  ZERO_32,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import type { Address, Bytes16, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import {
  KeypairError,
  type ViewingKey,
  type X25519Keypair,
  type X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import type {
  AssetRegistry,
  IndexedShieldedTransaction,
  OutputSlot,
} from "@heliuslabs/zolana/transaction";

import type { AuditorMessage } from "../../../crypto/audit/audit.js";
import { ringBlindingSeed, ringOutputBlinding } from "../../../crypto/derivation/blinding.js";
import { deliveredSlotSecret, ringIdField } from "../../../crypto/derivation/ring-stream.js";
import { x25519FromU } from "../../../crypto/keys/x25519.js";
import {
  auditorMessage,
  auditedUtxos,
  DUMMY_INPUT,
  hasUnknownAssets,
  knownUtxoHash,
  KnownUtxoIndex,
  openedUtxo,
  ringInput,
  spentInputs,
  type AuditedRingOutput,
  type AuditedRingTransaction,
  type AuditedSender,
  type AuditedTransferOf,
  type AuditedUtxo,
  type EscrowedKeys,
  type EscrowPendingOutput,
  type InputOpening,
  type InputRing,
  type KnownUtxos,
  type OutputOpening,
  type OutputPayloadError,
  type OutputPayloadErrorKind,
  type RingAuditReader,
  type SpentInputs,
} from "../../../operations/audit/audit.js";
import { RowOrigins, rowEventIndex } from "../../../operations/audit/row-origins.js";
import { createdRingUtxos } from "../../../operations/workflow/created-utxos.js";
import { readRingHistory, scanLimits } from "../../../rpc/history.js";
import type { SkippedRingTransaction } from "../../../rpc/ring-rpc.js";
import {
  MergeLedger,
  mergeInputOf,
  realMergeInputs,
  type AuditedMergeOutput,
  type ConfirmedMerge,
  type KnownMergeInput,
} from "../../../state/merge-ledger.js";
import { RingError } from "../../error.js";
import { dummyUtxoHash } from "../../membership/utxo-hash.js";
import { outputTreeId } from "../../membership/trees.js";
import {
  RpcTransactionOrigin,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../../transaction/origin.js";
import { readRingOutput, RingScheme } from "../../transaction/output.js";
import { openDeliveredBody } from "./delivered-body.js";
import {
  openAuditEnvelope,
  parseAuditorMessage,
  type AnonymousOutputOpening,
  type DeliveredOutputOpening,
  type RingDisclosure,
} from "./disclosure.js";
import { deliveredBodyLen, type AuditStreamLayout } from "./layout.js";
import { openRingMergeDisclosure, type RingMergeDisclosure } from "./merge-disclosure.js";

type RebuiltOpening = Exclude<OutputOpening, { kind: "escrowPending" }>;

interface TransactionAuditInputV3 {
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

/** Every published commitment of a tag 45 or 46 frame rebuilt from its disclosure. */
export function auditRingTransactionV3(input: TransactionAuditInputV3): AuditedRingTransaction {
  return openRingTransferV3(input).audited;
}

/** @internal `auditRingTransactionV3` with its opening kept for a later asset lookup. */
export function openRingTransferV3(input: TransactionAuditInputV3): OpenedRingTransfer {
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

/** The tag 45 and 46 rows of one history, an input a later row opens resolves on the last pass. */
export async function auditHistoryV3(
  input: Readonly<{
    client: RingAuditReader;
    auditor: X25519Keypair;
    ringProgramId: Address;
    assets: AssetRegistry;
    escrowedKeys?: EscrowedKeys;
    history: readonly ConfirmedRingTransaction[];
    rows: RowOrigins;
    known: KnownUtxoIndex;
  }>,
  context?: RequestContext,
): Promise<readonly AuditedRingTransaction[]> {
  const { known, rows } = input;
  for (const confirmed of input.history) {
    rows.attempt(confirmed.transaction, () => {
      if (confirmed.kind === "deposit") {
        for (const { commitment, utxo } of createdRingUtxos({
          confirmed,
          ringProgramId: input.ringProgramId,
          auditor: input.auditor,
        }))
          known.insert(commitment, utxo);
      } else if (confirmed.kind === "historicalMergeV3") {
        known.applyMerge(
          confirmedMergeV3({
            transaction: confirmed.transaction,
            eventIndex: rowEventIndex(confirmed.transaction),
            disclosure: confirmed.disclosure,
            auditor: input.auditor,
          }),
        );
      }
    });
  }
  const transactions: { audited: AuditedRingTransaction; anonymous: boolean }[] = [];
  let assetsRefreshed = false;
  for (const confirmed of input.history) {
    if (confirmed.kind !== "historicalTransferV3") continue;
    const opened = rows.attempt(confirmed.transaction, () =>
      openRingTransferV3({
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
      audited = rows.attempt(confirmed.transaction, () => opened.withAssets(input.assets));
      if (audited === undefined) continue;
    }
    for (const { commitment, utxo } of auditedUtxos(audited)) known.insert(commitment, utxo);
    transactions.push({ audited, anonymous: confirmed.layout.key.kind === "commitment" });
  }
  return Object.freeze(
    transactions.map(({ audited, anonymous }) => {
      const first = audited.inputs[0]?.hash;
      const sender = anonymous && first !== undefined ? knownSender(first, known) : audited.sender;
      return Object.freeze({
        ...audited,
        ...(sender === undefined ? {} : { sender }),
        inputs: Object.freeze(
          audited.inputs.map((spent) =>
            spent.hash === undefined ||
            (spent.opening.kind !== "unseenHash" && spent.opening.kind !== "merged")
              ? spent
              : Object.freeze({ ...spent, opening: commitmentInput(spent.hash, known) }),
          ),
        ),
      });
    }),
  );
}

export type RingMergeAuditReaderV3 = KitRpcAccess &
  Pick<IndexerReader, "getShieldedTransactionsByTags">;

export interface RingMergeAuditPageV3 {
  /** Every nonzero list entry the page applied, known to the auditor or not. */
  readonly spent: readonly Bytes32[];
  /** Audit records the page resolved, descendants included. */
  readonly outputs: readonly AuditedMergeOutput[];
  /** Every merge the ledger holds on an unknown input. */
  readonly unresolved: readonly ConfirmedMerge[];
  /** Rows that do not decode or fail their disclosure, each opens nothing. */
  readonly skipped: readonly SkippedRingTransaction[];
  /** Set only when the page cap stopped the history scan. */
  readonly nextCursor?: string;
}

/** The tag 47 rows of a ring's history, a later page's opening resolves what the ledger held. */
export async function auditRingMergesV3(
  input: Readonly<{
    client: RingMergeAuditReaderV3;
    ringProgramId: Address;
    auditor: X25519Keypair;
    origin?: TransactionOrigin;
    cursor?: string;
    pageSize?: number;
    maxPages?: number;
    knownUtxos?: Pick<KnownUtxos, "utxo">;
    ledger?: MergeLedger;
  }>,
  context?: RequestContext,
): Promise<RingMergeAuditPageV3> {
  await initializePoseidon();
  const rows = new RowOrigins(
    input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
    input.ringProgramId,
    context,
  );
  const merges: ConfirmedMerge[] = [];
  const seen = new Set<string>();
  const { nextCursor } = await readRingHistory(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      rows,
      ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
      limits: scanLimits(input),
    },
    (confirmed, eventIndex) => {
      if (confirmed.kind !== "historicalMergeV3") return;
      const { transaction, disclosure } = confirmed;
      const event = `${transaction.txSignature}:${String(eventIndex)}`;
      if (seen.has(event))
        throw new RingError("RING_RPC", {
          details: { reason: "duplicate merge" },
        });
      seen.add(event);
      merges.push(
        confirmedMergeV3({ transaction, eventIndex, disclosure, auditor: input.auditor }),
      );
    },
    context,
  );
  const ledger = input.ledger ?? new MergeLedger();
  const known: KnownMergeInput = (commitment) => {
    const utxo = input.knownUtxos?.utxo(commitment);
    return utxo === undefined ? undefined : mergeInputOf(utxo);
  };
  const spent: Bytes32[] = [];
  const outputs: AuditedMergeOutput[] = [];
  for (const merge of merges) {
    // Listed ahead of the ledger, a retried page over a carried ledger still names its inputs.
    spent.push(...merge.inputs);
    outputs.push(...ledger.apply(merge, known).resolved);
  }
  outputs.push(...ledger.resolve(known));
  return Object.freeze({
    spent: Object.freeze(spent),
    outputs: Object.freeze(outputs),
    unresolved: ledger.unresolved(),
    skipped: Object.freeze(rows.skipped),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  });
}

export function confirmedMergeV3(
  input: Readonly<{
    transaction: IndexedShieldedTransaction;
    eventIndex: number;
    disclosure: RingMergeDisclosure;
    auditor: X25519Keypair;
  }>,
): ConfirmedMerge {
  const { transaction, eventIndex } = input;
  const slot = transaction.outputSlots[0];
  const firstNullifier = transaction.nullifiers[0];
  const width = mergePaddedInputCount(transaction.nullifiers.length);
  const body = slot === undefined ? undefined : readMergeOutputBody(slot.payload);
  const ringDataHash = body?.ringDataHash;
  if (
    slot === undefined ||
    firstNullifier === undefined ||
    transaction.outputSlots.length !== 1 ||
    width === undefined ||
    body === undefined ||
    ringDataHash === undefined ||
    body.encrypted.length !== MERGE_OUTPUT_BODY_LENGTH ||
    !isCanonicalField(firstNullifier) ||
    !isCanonicalField(slot.outputContext.hash) ||
    !isCanonicalField(ringDataHash)
  )
    throw new RingError("RING_ORIGIN_DECODE", {
      details: { reason: "ring merge output" },
    });
  const salt = body.encrypted.slice(0, 16) as Bytes16;
  const list = openRingMergeDisclosure(input.auditor, input.disclosure, salt);
  if (list.length !== width)
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "merge disclosure width" },
    });
  return Object.freeze({
    slot: transaction.slot,
    signature: transaction.txSignature,
    eventIndex,
    outputCommitment: slot.outputContext.hash,
    treeId: outputTreeId(slot.outputContext),
    leafIndex: slot.outputContext.leafIndex,
    firstNullifier,
    ringDataHash,
    inputs: realMergeInputs(list, transaction.nullifiers.length),
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
        return commitmentInput(hash, known);
      });
      const first = published.hashes[0];
      const sender =
        spent.evidence.kind === "anonymous" && first !== undefined
          ? knownSender(first, known)
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

function commitmentInput(hash: Bytes32, known: KnownUtxos | undefined): InputOpening {
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
}

function knownSender(hash: Bytes32, known: KnownUtxos | undefined): AuditedSender | undefined {
  const utxo = known?.utxo(hash) ?? known?.merged?.(hash);
  return utxo === undefined
    ? undefined
    : Object.freeze({
        ownerKey: utxo.ownerKey,
        ...(utxo.owner.kind === "keyed" ? { nullifierPk: utxo.owner.nullifierPk } : {}),
      });
}
