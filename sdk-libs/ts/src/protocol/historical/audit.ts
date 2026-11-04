import { ZERO_32 } from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32, Signature } from "@heliuslabs/zolana/interface";
import type { X25519Keypair } from "@heliuslabs/zolana/keypair";
import type { AssetRegistry, IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";

import type { AuditorMessage } from "../../crypto/audit/audit.js";
import { ringIdField } from "../../crypto/derivation/ring-stream.js";
import { auditTransferWith } from "./v3/audit.js";
import {
  DUMMY_INPUT,
  knownUtxoHash,
  openedUtxo,
  ringInput,
  spentInputs,
  type AuditedSender,
  type AuditedTransferOf,
  type AuditedUtxo,
  type EscrowedKeys,
  type InputRing,
  type KnownUtxos,
  type SpentInputs,
} from "../../operations/audit/audit.js";
import { rowEventIndex } from "../../operations/audit/row-origins.js";
import { RingError } from "../error.js";
import {
  openAuditEnvelope,
  parseAuditorMessage,
  type AnonymousInputOpening,
  type InputPrefix,
  type RingDisclosure,
} from "./disclosure.js";
import { HistoricalTransactData, landedHistoricalRail } from "./frame.js";
import {
  anyOwnerNotes,
  assignPrefixedInputs,
  ringNotes,
  type HistoricalInputOpening,
  type PrefixedKnownUtxos,
} from "./known-prefixes.js";
import type { AuditStreamLayout } from "./layout.js";
import {
  openHistoricalMergeDisclosure,
  readHistoricalMergeDisclosure,
  type HistoricalMergeOpening,
} from "./merge-disclosure.js";

export interface HistoricalTransferInput {
  readonly auditor: X25519Keypair;
  readonly transaction: IndexedShieldedTransaction;
  readonly assets: AssetRegistry;
  /** The ring wrapper's data, its first byte the tag. */
  readonly instruction: Uint8Array;
  readonly sppAnonymous: boolean;
  readonly inputTreeIds?: readonly (number | undefined)[];
  readonly known?: PrefixedKnownUtxos;
  readonly escrowedKeys?: EscrowedKeys;
}

export type HistoricalTransfer = AuditedTransferOf<HistoricalInputOpening>;

export interface HistoricalCoverageRow {
  readonly slot: bigint;
  readonly txSignature: Signature;
  readonly eventIndex: number;
  readonly reason: "historicalPrefix";
  readonly inputs: readonly Bytes32[];
}

export function openHistoricalRingTransfer(input: HistoricalTransferInput): HistoricalTransfer {
  const { auditor, transaction, assets, instruction, known } = input;
  const frame = HistoricalTransactData.parse(
    instruction.subarray(1),
    landedHistoricalRail(instruction, input.sppAnonymous),
  );
  const layout = HistoricalTransactData.streamLayout(frame);
  const ring = transaction.ringProgramId;
  if (ring === undefined)
    throw new RingError("RING_AUDIT_UNSEALED", {
      details: { reason: "ringProgramId", signature: transaction.txSignature },
    });
  const ringId = ringIdField(ring);
  return auditTransferWith<RingDisclosure, HistoricalInputOpening>(
    {
      transaction,
      assets,
      ...(input.inputTreeIds === undefined ? {} : { inputTreeIds: input.inputTreeIds }),
      ...(input.escrowedKeys === undefined ? {} : { escrowedKeys: input.escrowedKeys }),
      counts: layout,
      open: (message) =>
        openAuditEnvelope(auditor, { layout, message: parsedMessage(message, layout) }),
    },
    (_, disclosure, spent) =>
      historicalInputs({
        disclosure,
        ringId,
        assets,
        nullifiers: spent.nullifiers,
        ...(spent.trees === undefined ? {} : { trees: spent.trees }),
        ...(known === undefined ? {} : { known }),
      }),
  ).audited;
}

export function openHistoricalMerge(
  auditor: X25519Keypair,
  instruction: Uint8Array,
  salt: Bytes16,
): HistoricalMergeOpening {
  return openHistoricalMergeDisclosure(auditor, readHistoricalMergeDisclosure(instruction), salt);
}

/** A prefix names no input alone, a row with an unassigned one leaves coverage incomplete. */
export function historicalCoverageRow(
  transaction: IndexedShieldedTransaction,
  opened: Pick<HistoricalTransfer, "inputs">,
): HistoricalCoverageRow | undefined {
  const unresolved = opened.inputs.some(
    ({ opening }) => opening.kind === "ambiguous" || opening.kind === "unseen",
  );
  if (!unresolved) return undefined;
  return Object.freeze({
    slot: transaction.slot,
    txSignature: transaction.txSignature,
    eventIndex: rowEventIndex(transaction),
    reason: "historicalPrefix",
    inputs: Object.freeze([]),
  });
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

function historicalInputs(
  spent: Readonly<{
    disclosure: RingDisclosure;
    ringId: Bytes32;
    assets: AssetRegistry;
    nullifiers: readonly Bytes32[];
    trees?: readonly (number | undefined)[];
    known?: PrefixedKnownUtxos;
  }>,
): SpentInputs<HistoricalInputOpening> {
  const { nullifiers, known, ringId } = spent;
  const published = spent.disclosure.inputs;
  const anyOwner = (prefixes: readonly (InputPrefix | undefined)[]) =>
    assignPrefixedInputs(prefixes, (prefix) =>
      known === undefined ? [] : anyOwnerNotes({ known, ringId }, prefix),
    );
  switch (published.kind) {
    case "none":
      return Object.freeze({ inputs: Object.freeze([]) });
    case "prefixes":
      return Object.freeze({ inputs: spentInputs(nullifiers, anyOwner(published.prefixes)) });
    case "commitments": {
      const { first, prefixes } = published;
      const zero = known?.utxo(first);
      if (known === undefined || zero === undefined) {
        const unseen: HistoricalInputOpening = Object.freeze({ kind: "unseenHash", hash: first });
        return Object.freeze({
          inputs: spentInputs(nullifiers, [unseen, ...anyOwner(prefixes)]),
        });
      }
      const source = { known, sender: zero.ownerKey, first, ringId };
      const later = assignPrefixedInputs(prefixes, (prefix) => ringNotes(source, prefix));
      const sender: AuditedSender = Object.freeze({
        ownerKey: zero.ownerKey,
        ...(zero.owner.kind === "keyed" ? { nullifierPk: zero.owner.nullifierPk } : {}),
      });
      return Object.freeze({
        sender,
        inputs: spentInputs(nullifiers, [ringInput(first, zero), ...later]),
      });
    }
    case "openings": {
      const { senderKey, senderNullifierPk } = published;
      const openings = published.inputs.map((opening, index) =>
        opening === undefined
          ? DUMMY_INPUT
          : openedEntryInput(spent, { senderKey, senderNullifierPk, opening, index }),
      );
      return Object.freeze({
        sender: Object.freeze({ ownerKey: senderKey, nullifierPk: senderNullifierPk }),
        inputs: spentInputs(nullifiers, openings),
      });
    }
  }
}

function openedEntryInput(
  spent: Readonly<{
    ringId: Bytes32;
    assets: AssetRegistry;
    trees?: readonly (number | undefined)[];
    known?: KnownUtxos;
  }>,
  input: Readonly<{
    senderKey: Bytes32;
    senderNullifierPk: Bytes32;
    opening: AnonymousInputOpening;
    index: number;
  }>,
): HistoricalInputOpening {
  const { asset, amount, blinding } = input.opening;
  const mint = spent.assets.addressForField(asset);
  const utxo: AuditedUtxo = Object.freeze({
    ownerKey: input.senderKey,
    nullifierPk: input.senderNullifierPk,
    asset,
    ...(mint === undefined ? {} : { mint }),
    amount,
    blinding,
    dataHash: ZERO_32,
    ringDataHash: ZERO_32,
  });
  const tree = spent.trees?.[input.index];
  const ring = tree === undefined ? undefined : inputRing(utxo, tree, spent);
  return Object.freeze({
    kind: "opened",
    asset,
    ...(mint === undefined ? {} : { mint }),
    amount,
    blinding,
    ...(ring === undefined ? {} : { ring }),
  });
}

/** Version 2 evidence names no entry hash, a known commitment alone tells the rings apart. */
function inputRing(
  utxo: AuditedUtxo,
  treeId: number,
  spent: Readonly<{ ringId: Bytes32; known?: KnownUtxos }>,
): InputRing {
  const opened = openedUtxo(utxo, treeId);
  const ring = knownUtxoHash(opened, spent.ringId);
  const fallback = knownUtxoHash(opened, ZERO_32);
  const found = (commitment: Bytes32): boolean => spent.known?.utxo(commitment) !== undefined;
  if (found(ring) && !found(fallback)) return Object.freeze({ kind: "ring", commitment: ring });
  if (found(fallback) && !found(ring))
    return Object.freeze({ kind: "default", commitment: fallback });
  return Object.freeze({ kind: "unresolved", ring, default: fallback });
}
