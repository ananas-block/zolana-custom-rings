/** A spend names deposit UTXOs by hash. */
import { hashBytes, addressBytes, equalBytes } from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import type { X25519Keypair } from "@heliuslabs/zolana/keypair";
import type { OutputSlot } from "@heliuslabs/zolana/transaction";
import { ringIdField } from "../../crypto/derivation/ring-stream.js";
import { RecordKind } from "../../protocol/codec/audit-stream.js";
import { readRingDepositCapsule } from "../../protocol/codec/deposit-capsule.js";
import type { RingDepositOutput } from "../../protocol/codec/ring-deposit-plaintext.js";

import {
  knownUtxoHash,
  type CreatedRingUtxo,
  type KnownUtxo,
  type RingAuditReader,
} from "../audit/audit.js";
import {
  openRingDepositOpening,
  ringDepositOutput,
  type RingDepositOpening,
} from "../../proof/deposit-audit.js";
import { RingError } from "../../protocol/error.js";
import { RowOrigins, rowEventIndex } from "../audit/row-origins.js";
import { readRingHistory, scanLimits } from "../../rpc/history.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";
import {
  RpcTransactionOrigin,
  type ConfirmedDeposit,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../../protocol/transaction/origin.js";
import { outputTreeId } from "../../protocol/membership/trees.js";
import { openRingMerge, type OpenedRingMerge } from "../audit/audit-merge.js";

/** Rust `CreatedUtxoPage`. */
export interface CreatedRingUtxosPage {
  readonly utxos: readonly CreatedRingUtxo[];
  readonly merges: readonly OpenedRingMerge[];
  /** Rows that do not decode or fail to open, their notes stay out of `utxos`. */
  readonly skipped: readonly SkippedRingTransaction[];
  /** Set only when the page cap stopped the read. */
  readonly nextCursor?: string;
}

/** Rust `CreatedUtxoScan::run`. */
export async function scanCreatedRingUtxos(
  input: Readonly<{
    client: RingAuditReader;
    ringProgramId: Address;
    auditor: X25519Keypair;
    origin?: TransactionOrigin;
    cursor?: string;
    pageSize?: number;
    maxPages?: number;
  }>,
  context?: RequestContext,
): Promise<CreatedRingUtxosPage> {
  await initializePoseidon();
  const utxos: CreatedRingUtxo[] = [];
  const merges: OpenedRingMerge[] = [];
  const rows = new RowOrigins(
    input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
    input.ringProgramId,
    context,
  );
  const { nextCursor } = await readRingHistory(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      rows,
      ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
      limits: scanLimits(input),
    },
    (confirmed) => {
      if (confirmed.kind === "merge") {
        const merge = rows.attempt(confirmed.transaction, () =>
          openRingMerge({
            confirmed,
            eventIndex: rowEventIndex(confirmed.transaction),
            auditor: input.auditor,
          }),
        );
        if (merge !== undefined) merges.push(merge);
      }
      utxos.push(
        ...createdRingUtxos({
          confirmed,
          ringProgramId: input.ringProgramId,
          auditor: input.auditor,
        }),
      );
    },
    context,
  );
  return Object.freeze({
    utxos: Object.freeze(utxos),
    merges: Object.freeze(merges),
    skipped: Object.freeze(rows.skipped),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  });
}

/** A merge or a transfer creates none. */
export function createdRingUtxos(
  input: Readonly<{
    confirmed: ConfirmedRingTransaction;
    ringProgramId: Address;
    auditor: X25519Keypair;
  }>,
): readonly CreatedRingUtxo[] {
  const { confirmed } = input;
  return confirmed.kind === "deposit" ? depositUtxos(input, confirmed) : Object.freeze([]);
}

function depositUtxos(
  input: Readonly<{ ringProgramId: Address; auditor: X25519Keypair }>,
  confirmed: Extract<ConfirmedRingTransaction, { kind: "deposit" }>,
): readonly CreatedRingUtxo[] {
  const utxos: CreatedRingUtxo[] = [];
  for (const [slotIndex, slot] of confirmed.transaction.outputSlots.entries()) {
    const output = ringDepositOutput(slot.payload, input.ringProgramId);
    const binding = confirmed.deposits.find((deposit) => deposit.slotIndex === slotIndex);
    if (output === undefined || binding === undefined) continue;
    const opening = openConfirmedDeposit({ output, auditor: input.auditor, binding });
    try {
      utxos.push(
        createdDepositUtxo({
          ringProgramId: input.ringProgramId,
          slotIndex,
          slot,
          output,
          opening,
        }),
      );
    } finally {
      opening.ownerHash.fill(0);
      opening.blinding.fill(0);
    }
  }
  return Object.freeze(utxos);
}

export type OpenedDeposit = Omit<RingDepositOpening, "recipientCiphertext">;

/** Refuses a capsule the confirmed binding does not name and a record off the published owner hash. */
export function openConfirmedDeposit(
  input: Readonly<{
    output: RingDepositOutput;
    auditor: X25519Keypair;
    binding: ConfirmedDeposit;
  }>,
): OpenedDeposit {
  const { output, auditor, binding } = input;
  const { ciphertext } = output.encrypted;
  const capsule = readRingDepositCapsule(ciphertext);
  if (capsule === undefined) throw depositRefusal();
  const opening = openRingDepositOpening(capsule, auditor, output.ownerUtxoHash, binding);
  if (opening.record.kind !== RecordKind.ring) {
    opening.blinding.fill(0);
    throw depositRefusal();
  }
  return Object.freeze(opening);
}

/** @internal Rebuilds the full commitment, the record names the mint and amount the event publishes. */
export function createdDepositUtxo(
  input: Readonly<{
    ringProgramId: Address;
    slotIndex: number;
    slot: OutputSlot;
    output: RingDepositOutput;
    opening: OpenedDeposit;
  }>,
): CreatedRingUtxo {
  const { output, opening, slot } = input;
  if (opening.record.mint !== output.asset || opening.record.amount !== output.amount)
    throw depositRefusal();
  const utxo: KnownUtxo = Object.freeze({
    ownerKey: opening.ownerKey,
    owner: Object.freeze({ kind: "keyed", nullifierPk: opening.record.nullifierPk }),
    asset: hashBytes(addressBytes(output.asset)) as Bytes32,
    mint: output.asset,
    amount: output.amount,
    blinding: opening.blinding.slice() as Bytes32,
    dataHash: output.dataHash ?? (new Uint8Array(32) as Bytes32),
    ringDataHash: output.ringDataHash,
    treeId: outputTreeId(slot.outputContext),
  });
  const commitment = knownUtxoHash(utxo, ringIdField(input.ringProgramId));
  if (!equalBytes(commitment, slot.outputContext.hash)) throw depositRefusal();
  return Object.freeze({ commitment, slotIndex: input.slotIndex, utxo });
}

function depositRefusal(): RingError {
  return new RingError("RING_AUDIT_MESSAGE", { details: { reason: "deposit opening" } });
}
