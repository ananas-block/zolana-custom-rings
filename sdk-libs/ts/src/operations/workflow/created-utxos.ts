/** A spend names deposit UTXOs by hash. */
import { hashBytes, addressBytes, equalBytes } from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import type { Address, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import type { X25519Keypair } from "@heliuslabs/zolana/keypair";
import type { OutputSlot } from "@heliuslabs/zolana/transaction";
import { ringIdField } from "../../crypto/derivation/ring-stream.js";
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
import { readRingDepositCapsule } from "../../protocol/codec/deposit-capsule.js";
import { RingError } from "../../protocol/error.js";
import { RowOrigins } from "../audit/row-origins.js";
import { readRingHistory, scanLimits } from "../../rpc/history.js";
import type { SkippedRingTransaction } from "../../rpc/ring-rpc.js";
import {
  RpcTransactionOrigin,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../../protocol/transaction/origin.js";
import { outputTreeId } from "../../protocol/membership/trees.js";

/** Rust `CreatedUtxoPage`. */
export interface CreatedRingUtxosPage {
  readonly utxos: readonly CreatedRingUtxo[];
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
    const capsule = readRingDepositCapsule(output.encrypted.ciphertext);
    if (capsule === undefined)
      throw new RingError("RING_AUDIT_MESSAGE", {
        details: { reason: "deposit opening" },
      });
    const opening = openRingDepositOpening(capsule, input.auditor, output.ownerUtxoHash, binding);
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

/** @internal */
export function createdDepositUtxo(
  input: Readonly<{
    ringProgramId: Address;
    slotIndex: number;
    slot: OutputSlot;
    output: RingDepositOutput;
    opening: Omit<RingDepositOpening, "recipientCiphertext">;
  }>,
): CreatedRingUtxo {
  const { output, opening, slot } = input;
  const utxo: KnownUtxo = Object.freeze({
    ownerKey: opening.ownerKey,
    owner: Object.freeze({
      kind: "deposited",
      ownerHash: opening.ownerHash.slice() as Bytes32,
    }),
    asset: hashBytes(addressBytes(output.asset)) as Bytes32,
    mint: output.asset,
    amount: output.amount,
    blinding: opening.blinding.slice() as Bytes32,
    dataHash: output.dataHash ?? (new Uint8Array(32) as Bytes32),
    ringDataHash: output.ringDataHash,
    treeId: outputTreeId(slot.outputContext),
  });
  const commitment = knownUtxoHash(utxo, ringIdField(input.ringProgramId));
  if (!equalBytes(commitment, slot.outputContext.hash))
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "deposit opening" },
    });
  return Object.freeze({ commitment, slotIndex: input.slotIndex, utxo });
}
