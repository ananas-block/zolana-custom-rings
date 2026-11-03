/** The rebuild of a published anonymous output from its plaintext, Rust `anonymous_body`. */
import type { Address, Bytes32 } from "@heliuslabs/zolana";
import { equalBytes } from "@heliuslabs/zolana/internal";
import { X25519PublicKey, type ShieldedAddress } from "@heliuslabs/zolana/keypair";
import { Utxo, type IndexedShieldedTransaction, type TreeId } from "@heliuslabs/zolana/transaction";

import { readRingOutput } from "../transaction/output.js";
import {
  anonymousRecipientUtxo,
  anonymousSenderUtxos,
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  type AnonymousRecipientPlaintext,
  type AnonymousSenderPlaintext,
} from "./anonymous-plaintext.js";

export { RECIPIENT_BODY_LEN } from "./anonymous-plaintext.js";

/** `0x04 ‖ 0^32`, the sender bundle's entry for an output no anonymous recipient reads. */
export const DUMMY_RECIPIENT_VIEWING_PK = X25519PublicKey.fromBytes(
  Uint8Array.of(4, ...new Uint8Array(32)),
);

export interface AnonymousOutput {
  readonly owner: ShieldedAddress;
  readonly ring: Address;
  readonly treeId: TreeId;
  readonly utxoHash: Bytes32;
}

/** `undefined` unless the plaintext names the reader as owner and rebuilds the hash. */
export function openRecipient(
  output: AnonymousOutput,
  plaintext: AnonymousRecipientPlaintext,
): Utxo | undefined {
  if (!plaintext.committed.ownerPublicKey.equals(output.owner.signingPublicKey)) return undefined;
  const utxo = inRing(output.ring, anonymousRecipientUtxo(plaintext));
  return rebuilds(output, utxo) ? utxo : undefined;
}

/** The bundle's change in output order, the change leading at output 0. */
export function senderChange(
  output: Pick<AnonymousOutput, "ring">,
  plaintext: AnonymousSenderPlaintext,
  firstNullifier: Bytes32,
): readonly Utxo[] {
  return anonymousSenderUtxos(plaintext, firstNullifier).map((utxo) => inRing(output.ring, utxo));
}

/** Ring outputs commit to no data, a hashed record rebuilds nothing. */
export function rebuilds(output: AnonymousOutput, utxo: Utxo): boolean {
  if (utxo.data.ringData() !== undefined || utxo.data.utxoData() !== undefined) return false;
  try {
    return equalBytes(utxo.hash(output.owner.nullifierPublicKey, output.treeId), output.utxoHash);
  } catch {
    return false;
  }
}

/** Dummy entries left out. */
export function listedRecipients(plaintext: AnonymousSenderPlaintext): readonly X25519PublicKey[] {
  return plaintext.uncommitted.recipientViewingPublicKeys.filter((key) => !isDummyRecipient(key));
}

export function isDummyRecipient(key: X25519PublicKey): boolean {
  return key.equals(DUMMY_RECIPIENT_VIEWING_PK);
}

/** Every anonymous output is the ring's, its plaintext names no ring. */
function inRing(ring: Address, utxo: Utxo): Utxo {
  return new Utxo({
    owner: utxo.owner,
    asset: utxo.asset,
    amount: utxo.amount,
    blinding: utxo.blinding,
    data: utxo.data,
    ringProgramId: ring,
  });
}

export const HistoricalScheme = Object.freeze({
  anonymousRecipient: 1,
  anonymousSender: 2,
} as const);
export type HistoricalScheme = (typeof HistoricalScheme)[keyof typeof HistoricalScheme];

export function anonymousRecipientOutputBody(data: Uint8Array): Uint8Array | undefined {
  return encryptedOutputBody(data, HistoricalScheme.anonymousRecipient);
}

export function anonymousSenderOutputBody(data: Uint8Array): Uint8Array | undefined {
  return encryptedOutputBody(data, HistoricalScheme.anonymousSender);
}

function encryptedOutputBody(data: Uint8Array, scheme: HistoricalScheme): Uint8Array | undefined {
  try {
    const frame = readRingOutput(data);
    return frame.encoding === "encrypted" && frame.scheme === scheme ? frame.body : undefined;
  } catch {
    return undefined;
  }
}

/** A scheme 1 output or scheme 2 message of a row. */
export type HistoricalSite =
  | Readonly<{ kind: "output"; position: number }>
  | Readonly<{ kind: "message"; message: number }>;

export interface HistoricalBody {
  readonly ciphertext: Uint8Array;
  readonly slotIndex: number;
}

/** `undefined` on another scheme, a message's stream reads past the outputs. */
export function historicalBody(
  tx: IndexedShieldedTransaction,
  site: HistoricalSite,
): HistoricalBody | undefined {
  const output = site.kind === "output";
  const data = output ? tx.outputSlots[site.position]?.payload : tx.messages[site.message]?.data;
  if (data === undefined) return undefined;
  const ciphertext = output ? anonymousRecipientOutputBody(data) : anonymousSenderOutputBody(data);
  if (ciphertext === undefined) return undefined;
  return { ciphertext, slotIndex: output ? site.position : tx.outputSlots.length + site.message };
}

export interface HistoricalReader {
  readonly owner: ShieldedAddress;
  readonly ring: Address;
  readonly firstNullifier: Bytes32;
}

export interface HistoricalNote {
  readonly position: number;
  readonly utxo: Utxo;
}

/** Only a rebuilt commitment proves a note the reader's, any other plaintext stays silent. */
export function historicalNotes(
  reader: HistoricalReader,
  tx: IndexedShieldedTransaction,
  site: HistoricalSite,
  plaintext: Uint8Array,
): readonly HistoricalNote[] {
  try {
    return site.kind === "output"
      ? recipientNotes(reader, tx, site.position, plaintext)
      : changeNotes(reader, tx, plaintext);
  } catch {
    return [];
  }
}

function recipientNotes(
  reader: HistoricalReader,
  tx: IndexedShieldedTransaction,
  position: number,
  plaintext: Uint8Array,
): readonly HistoricalNote[] {
  const output = outputAt(reader, tx, position);
  const utxo = output && openRecipient(output, decodeAnonymousRecipient(plaintext));
  return utxo === undefined ? [] : [{ position, utxo }];
}

function changeNotes(
  reader: HistoricalReader,
  tx: IndexedShieldedTransaction,
  plaintext: Uint8Array,
): readonly HistoricalNote[] {
  const bundle = decodeAnonymousSender(plaintext);
  if (!bundle.committed.ownerPublicKey.equals(reader.owner.signingPublicKey)) return [];
  return senderChange(reader, bundle, reader.firstNullifier).flatMap((utxo, position) => {
    const output = outputAt(reader, tx, position);
    return output !== undefined && rebuilds(output, utxo) ? [{ position, utxo }] : [];
  });
}

function outputAt(
  reader: HistoricalReader,
  tx: IndexedShieldedTransaction,
  position: number,
): AnonymousOutput | undefined {
  const context = tx.outputSlots[position]?.outputContext;
  if (context?.treeId === undefined) return undefined;
  return {
    owner: reader.owner,
    ring: reader.ring,
    treeId: context.treeId,
    utxoHash: context.hash,
  };
}
