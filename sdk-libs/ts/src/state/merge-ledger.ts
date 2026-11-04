import { RingError } from "../protocol/error.js";
import { getBase58Encoder, type Address } from "@solana/kit";

import {
  U64_MAX,
  ZERO_32,
  bytesKey,
  equalBytes,
  isZero,
  mergeOutputBlinding,
  solanaOwnerIdentity,
  addressBytes,
  hashBytes,
} from "@heliuslabs/zolana/internal";
import type { Bytes32, Signature } from "@heliuslabs/zolana/interface";

import { ownerHash, type NullifierKey } from "@heliuslabs/zolana/keypair";

import { ringIdField } from "../crypto/derivation/ring-stream.js";
import {
  knownUtxoHash,
  knownUtxoOwnerHash,
  type KnownUtxo,
  type UtxoOwner,
} from "../operations/audit/audit.js";

const base58Encoder = getBase58Encoder();

/** The published count never reads as a count of real inputs. */
export interface ConfirmedMerge {
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly outputCommitment: Bytes32;
  readonly treeId: number;
  readonly leafIndex: bigint;
  readonly firstNullifier: Bytes32;
  readonly ringDataHash: Bytes32;
  /** The output of {@link realMergeInputs}. */
  readonly inputs: readonly Bytes32[];
}

/** The fields of one spent commitment. */
export interface MergeInput {
  readonly ownerKey: Bytes32;
  readonly owner: UtxoOwner;
  readonly asset: Bytes32;
  readonly mint?: Address;
  readonly amount: bigint;
}

/** An audit record and no wallet opening. */
export interface AuditedMergeOutput extends MergeInput {
  readonly commitment: Bytes32;
  readonly slot: bigint;
  readonly signature: Signature;
  readonly eventIndex: number;
  readonly treeId: number;
  readonly leafIndex: bigint;
  readonly inputs: readonly Bytes32[];
  readonly firstNullifier: Bytes32;
  readonly ringDataHash: Bytes32;
}

export interface MergeTransition {
  /** Empty on a repeat. */
  readonly spent: readonly Bytes32[];
  /** Descendants included. */
  readonly resolved: readonly AuditedMergeOutput[];
}

/** Reads the auditor's openings. */
export type KnownMergeInput = (commitment: Bytes32) => MergeInput | undefined;

/** A zero entry is a dummy and never spent, slot 0 stays real and a slot past the published count holds nothing. */
export function realMergeInputs(
  list: readonly Bytes32[],
  publishedInputs: number,
): readonly Bytes32[] {
  const [first] = list;
  if (
    first === undefined ||
    isZero(first) ||
    list.slice(publishedInputs).some((entry) => !isZero(entry))
  )
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "merge disclosure list" } });
  return Object.freeze(list.filter((entry) => !isZero(entry)));
}

export function mergeInputOf(utxo: KnownUtxo): MergeInput {
  return Object.freeze({
    ownerKey: utxo.ownerKey,
    owner: utxo.owner,
    asset: utxo.asset,
    ...(utxo.mint === undefined ? {} : { mint: utxo.mint }),
    amount: utxo.amount,
  });
}

const EMPTY_TRANSITION: MergeTransition = Object.freeze({
  spent: Object.freeze([]),
  resolved: Object.freeze([]),
});

/** Requires `await initializePoseidon()` before owner verification. */
export class MergeLedger {
  readonly #applied = new Set<string>();
  readonly #outputs = new Map<string, AuditedMergeOutput>();
  readonly #unresolved = new Map<string, ConfirmedMerge>();

  /** A repeated `(signature, eventIndex)` changes nothing, a persisting caller writes `merge.inputs` first to keep a failed write unapplied. */
  apply(merge: ConfirmedMerge, known: KnownMergeInput): MergeTransition {
    const id = mergeId(merge);
    if (this.#applied.has(id)) return EMPTY_TRANSITION;
    const inputs = Object.freeze([...merge.inputs]);
    const pending = Object.freeze({ ...merge, inputs });
    const resolved = this.#resolve([...this.unresolved(), pending], known);
    this.#applied.add(id);
    this.#unresolved.set(id, pending);
    this.#commit(resolved);
    return Object.freeze({ spent: inputs, resolved });
  }

  /** A tag 57 record names the output, no input opening resolves it. */
  applyRecord(output: AuditedMergeOutput): void {
    const id = mergeId(output);
    if (this.#applied.has(id)) return;
    this.#applied.add(id);
    this.#outputs.set(bytesKey(output.commitment), Object.freeze(output));
  }

  /** Runs after every new opening, a resolved output can complete its descendant. */
  resolve(known: KnownMergeInput): readonly AuditedMergeOutput[] {
    const resolved = this.#resolve(this.unresolved(), known);
    this.#commit(resolved);
    return resolved;
  }

  output(commitment: Bytes32): AuditedMergeOutput | undefined {
    return this.#outputs.get(bytesKey(commitment));
  }

  outputs(): readonly AuditedMergeOutput[] {
    return Object.freeze([...this.#outputs.values()]);
  }

  /** Oldest first, a descendant follows the merge it spends. */
  unresolved(): readonly ConfirmedMerge[] {
    return Object.freeze([...this.#unresolved.values()].sort(oldestFirst));
  }

  #resolve(
    merges: readonly ConfirmedMerge[],
    known: KnownMergeInput,
  ): readonly AuditedMergeOutput[] {
    const pending = new Map([...merges].sort(oldestFirst).map((merge) => [mergeId(merge), merge]));
    const staged = new Map<string, AuditedMergeOutput>();
    const input: KnownMergeInput = (commitment) =>
      known(commitment) ?? staged.get(bytesKey(commitment)) ?? this.output(commitment);
    for (;;) {
      const opened = [...pending.values()].flatMap((merge) => resolvedOutput(merge, input) ?? []);
      if (opened.length === 0) return Object.freeze([...staged.values()]);
      for (const output of opened) {
        pending.delete(mergeId(output));
        staged.set(bytesKey(output.commitment), output);
      }
    }
  }

  #commit(outputs: readonly AuditedMergeOutput[]): void {
    for (const output of outputs) {
      this.#unresolved.delete(mergeId(output));
      this.#outputs.set(bytesKey(output.commitment), output);
    }
  }
}

function mergeId(merge: Readonly<{ signature: Signature; eventIndex: number }>): string {
  return `${merge.signature}:${String(merge.eventIndex)}`;
}

/** `undefined` while an input is unknown, on inputs of two owners or assets and on an overflow. */
function resolvedOutput(
  merge: ConfirmedMerge,
  known: KnownMergeInput,
): AuditedMergeOutput | undefined {
  const inputs: MergeInput[] = [];
  let amount = 0n;
  for (const commitment of merge.inputs) {
    const input = known(commitment);
    if (input === undefined) return undefined;
    inputs.push(input);
    amount += input.amount;
  }
  const first = inputs[0];
  if (first === undefined || amount > U64_MAX) return undefined;
  const ownerHash = knownUtxoOwnerHash(first);
  const sameNoteKind = inputs.every(
    (input) =>
      equalBytes(input.ownerKey, first.ownerKey) &&
      equalBytes(knownUtxoOwnerHash(input), ownerHash) &&
      equalBytes(input.asset, first.asset),
  );
  if (!sameNoteKind) return undefined;
  const owner = inputs.find((input) => input.owner.kind === "keyed")?.owner ?? first.owner;
  const mint = inputs.find((input) => input.mint !== undefined)?.mint;
  return Object.freeze({
    commitment: merge.outputCommitment,
    slot: merge.slot,
    signature: merge.signature,
    eventIndex: merge.eventIndex,
    treeId: merge.treeId,
    leafIndex: merge.leafIndex,
    ownerKey: first.ownerKey,
    owner,
    asset: first.asset,
    ...(mint === undefined ? {} : { mint }),
    amount,
    inputs: merge.inputs,
    firstNullifier: merge.firstNullifier,
    ringDataHash: merge.ringDataHash,
  });
}

/** Rust `(slot, signature, event_index)` order. */
function oldestFirst(left: ConfirmedMerge, right: ConfirmedMerge): number {
  if (left.slot !== right.slot) return left.slot < right.slot ? -1 : 1;
  const leftBytes = base58Encoder.encode(left.signature);
  const rightBytes = base58Encoder.encode(right.signature);
  const differing = leftBytes.findIndex((byte, index) => byte !== rightBytes[index]);
  if (differing === -1) return left.eventIndex - right.eventIndex;
  return (leftBytes[differing] ?? 0) - (rightBytes[differing] ?? 0);
}

export function reconstructMergeOutput(
  input: Readonly<{
    output: AuditedMergeOutput;
    nullifierKey: NullifierKey;
    ringProgramId: Address;
  }>,
): KnownUtxo | undefined {
  const { output, nullifierKey } = input;
  const nullifierPk = nullifierKey.publicKey();
  if (output.mint !== undefined && !equalBytes(hashBytes(addressBytes(output.mint)), output.asset))
    return undefined;
  if (
    !equalBytes(
      knownUtxoOwnerHash(output),
      ownerHash(solanaOwnerIdentity(output.ownerKey), nullifierPk),
    )
  )
    return undefined;
  const utxo: KnownUtxo = Object.freeze({
    ownerKey: output.ownerKey,
    owner: Object.freeze({ kind: "keyed", nullifierPk }),
    asset: output.asset,
    ...(output.mint === undefined ? {} : { mint: output.mint }),
    amount: output.amount,
    blinding: mergeOutputBlinding(nullifierKey, output.firstNullifier),
    dataHash: ZERO_32,
    ringDataHash: output.ringDataHash,
    treeId: output.treeId,
  });
  return equalBytes(knownUtxoHash(utxo, ringIdField(input.ringProgramId)), output.commitment)
    ? utxo
    : undefined;
}
