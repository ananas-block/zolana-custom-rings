import { bytesKey, equalBytes } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import {
  DUMMY_INPUT,
  KnownUtxoIndex,
  knownUtxoHash,
  ringInput,
  type InputOpening,
  type KnownUtxo,
  type KnownUtxos,
} from "../../operations/audit/audit.js";
import { inputPrefix, type InputPrefix } from "./disclosure.js";

export type HistoricalInputOpening =
  | InputOpening
  /** More known ring notes carry the disclosed prefix than inputs name it. */
  | Readonly<{ kind: "ambiguous"; candidates: readonly Bytes32[] }>
  /** Too few opened notes carry the disclosed prefix, the outputs still open. */
  | Readonly<{ kind: "unseen"; prefix: InputPrefix }>;

export interface PrefixedKnownUtxos extends KnownUtxos {
  /** Every opened note of `ownerKey` whose hash carries `prefix`. */
  withPrefix(ownerKey: Bytes32, prefix: InputPrefix): readonly Bytes32[];
  /** The authority rail names no owner. */
  withPrefixOfAnyone(prefix: InputPrefix): readonly Bytes32[];
}

export class PrefixedUtxoIndex implements PrefixedKnownUtxos {
  readonly #utxos = new KnownUtxoIndex();
  readonly #owned = new Map<string, Bytes32[]>();
  readonly #prefixes = new Map<InputPrefix, Bytes32[]>();

  constructor(utxos: Iterable<Readonly<{ commitment: Bytes32; utxo: KnownUtxo }>> = []) {
    for (const { commitment, utxo } of utxos) this.insert(commitment, utxo);
  }

  insert(commitment: Bytes32, utxo: KnownUtxo): void {
    const prefix = this.#utxos.utxo(commitment) === undefined ? inputPrefix(commitment) : undefined;
    if (prefix !== undefined) {
      const owner = ownedKey(utxo.ownerKey, prefix);
      this.#owned.set(owner, [...(this.#owned.get(owner) ?? []), commitment]);
      this.#prefixes.set(prefix, [...(this.#prefixes.get(prefix) ?? []), commitment]);
    }
    this.#utxos.insert(commitment, utxo);
  }

  utxo(commitment: Bytes32): KnownUtxo | undefined {
    return this.#utxos.utxo(commitment);
  }

  withPrefix(ownerKey: Bytes32, prefix: InputPrefix): readonly Bytes32[] {
    return Object.freeze([...(this.#owned.get(ownedKey(ownerKey, prefix)) ?? [])]);
  }

  withPrefixOfAnyone(prefix: InputPrefix): readonly Bytes32[] {
    return Object.freeze([...(this.#prefixes.get(prefix) ?? [])]);
  }
}

export type PrefixNote = Readonly<{ commitment: Bytes32; utxo: KnownUtxo }>;

/** Exact only for one note in one position, notes sharing a prefix fit any of its positions. */
export function assignPrefixedInputs(
  prefixes: readonly (InputPrefix | undefined)[],
  notesOf: (prefix: InputPrefix) => readonly PrefixNote[],
): HistoricalInputOpening[] {
  const positions = new Map<InputPrefix, number[]>();
  prefixes.forEach((prefix, position) => {
    if (prefix !== undefined) positions.set(prefix, [...(positions.get(prefix) ?? []), position]);
  });
  const openings: HistoricalInputOpening[] = prefixes.map(() => DUMMY_INPUT);
  for (const [prefix, inputs] of positions) {
    const notes = notesOf(prefix);
    if (notes.length < inputs.length) {
      const unseen: HistoricalInputOpening = Object.freeze({ kind: "unseen", prefix });
      for (const position of inputs) openings[position] = unseen;
      continue;
    }
    const ambiguous: HistoricalInputOpening | undefined =
      notes.length > 1
        ? Object.freeze({
            kind: "ambiguous",
            candidates: Object.freeze(notes.map(({ commitment }) => commitment)),
          })
        : undefined;
    notes.forEach((note, rank) => {
      const position = inputs[rank];
      if (position !== undefined)
        openings[position] = ambiguous ?? ringInput(note.commitment, note.utxo);
    });
  }
  return openings;
}

/** A note of `sender` other than spent UTXO 0, the circuit binds every spent UTXO to its owner key. */
export function ringNotes(
  source: Readonly<{ known: PrefixedKnownUtxos; sender: Bytes32; first: Bytes32; ringId: Bytes32 }>,
  prefix: InputPrefix,
): readonly PrefixNote[] {
  const { known, sender, first, ringId } = source;
  return notesWithPrefix(
    known.withPrefix(sender, prefix),
    { known, ringId, prefix },
    (commitment, utxo) => !equalBytes(commitment, first) && equalBytes(utxo.ownerKey, sender),
  );
}

export function anyOwnerNotes(
  source: Readonly<{ known: PrefixedKnownUtxos; ringId: Bytes32 }>,
  prefix: InputPrefix,
): readonly PrefixNote[] {
  return notesWithPrefix(
    source.known.withPrefixOfAnyone(prefix),
    { ...source, prefix },
    () => true,
  );
}

/** A named note whose hash carries the prefix and rebuilds under the ring, each counted once. */
export function notesWithPrefix(
  candidates: readonly Bytes32[],
  source: Readonly<{ known: KnownUtxos; ringId: Bytes32; prefix: InputPrefix }>,
  inScope: (commitment: Bytes32, utxo: KnownUtxo) => boolean,
): readonly PrefixNote[] {
  const { known, ringId, prefix } = source;
  const seen = new Set<string>();
  return candidates.flatMap((commitment) => {
    const utxo = known.utxo(commitment);
    if (
      utxo === undefined ||
      !inScope(commitment, utxo) ||
      inputPrefix(commitment) !== prefix ||
      !equalBytes(knownUtxoHash(utxo, ringId), commitment) ||
      seen.has(bytesKey(commitment))
    )
      return [];
    seen.add(bytesKey(commitment));
    return [Object.freeze({ commitment, utxo })];
  });
}

function ownedKey(ownerKey: Bytes32, prefix: InputPrefix): string {
  return `${bytesKey(ownerKey)}:${prefix.toString(16)}`;
}
