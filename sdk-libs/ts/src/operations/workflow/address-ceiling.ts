/** The address ceiling of one compiled transaction, Rust `validation::address_ceiling`. */
import type { Address, Bytes32, Instruction } from "@heliuslabs/zolana/interface";
import {
  equalBytes,
  isZero,
  nullifierPdaAddress,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import type { ShieldedPublicKey } from "@heliuslabs/zolana/keypair";
import type { ProofInputUtxo } from "@heliuslabs/zolana/transaction";

import { RingError } from "../../protocol/error.js";

/** Rust `v1::MAX_ADDRESSES`. */
export const MAX_TRANSACTION_ADDRESSES = 64;

/** One real input of the transaction, as SPP merge groups it. */
export interface SpentInput {
  readonly owner: ShieldedPublicKey;
  readonly asset: Address;
  readonly nullifierPublicKey: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ringProgramId?: Address;
  readonly treeId: number;
  readonly nullifierPda: Address;
}

/** `FittedMerge`'s published inputs per kind of merge, a zero-key merge adds its signer. */
export interface MergeCapacity {
  readonly keyed: number;
  readonly zeroKey: number;
}

export interface MergeGroup {
  readonly owner: ShieldedPublicKey;
  readonly asset: Address;
  readonly nullifierPublicKey: Bytes32;
  readonly ringProgramId?: Address;
  readonly treeId: number;
  /** Positions in `inputs`. */
  readonly inputs: readonly number[];
}

export type CeilingDecision =
  | Readonly<{ kind: "underCeiling"; addresses: number }>
  /** The fewest merges under the ceiling. */
  | Readonly<{ kind: "mergeFirst"; groups: readonly MergeGroup[]; addresses: number }>;

export async function spentInputOf(input: ProofInputUtxo, tree: Address): Promise<SpentInput> {
  const { utxo } = input;
  return Object.freeze({
    owner: utxo.owner,
    asset: utxo.asset,
    nullifierPublicKey: input.nullifierPublicKey,
    ...(input.dataHash === undefined ? {} : { dataHash: input.dataHash }),
    ...(utxo.ringProgramId === undefined ? {} : { ringProgramId: utxo.ringProgramId }),
    treeId: input.treeId,
    nullifierPda: await nullifierPdaAddress(tree, input.nullifier()),
  });
}

/** Rust `AddressCeiling::decide`, `RING_ADDRESS_CEILING` when merging every valid group falls short. */
export function decideAddressCeiling(
  input: Readonly<{
    payer: Address;
    instruction: Instruction;
    inputs: readonly SpentInput[];
    mergeCapacity: MergeCapacity;
  }>,
): CeilingDecision {
  const { inputs } = input;
  const addresses = (mergedAway: ReadonlySet<Address>): number =>
    new Set([
      input.payer,
      input.instruction.programAddress,
      ...(input.instruction.accounts ?? [])
        .map((account) => account.address)
        .filter((address) => !mergedAway.has(address)),
    ]).size;
  const compiled = addresses(new Set());
  if (compiled <= MAX_TRANSACTION_ADDRESSES)
    return Object.freeze({ kind: "underCeiling", addresses: compiled });
  const mergedAway = new Set<Address>();
  const chosen: MergeGroup[] = [];
  let afterMerging = compiled;
  for (const group of mergeGroups(inputs, input.mergeCapacity)) {
    // The merged note's own nullifier PDA replaces one of the group's.
    for (const position of group.inputs.slice(1))
      mergedAway.add((inputs[position] as SpentInput).nullifierPda);
    chosen.push(group);
    afterMerging = addresses(mergedAway);
    if (afterMerging <= MAX_TRANSACTION_ADDRESSES)
      return Object.freeze({
        kind: "mergeFirst",
        groups: Object.freeze(chosen),
        addresses: afterMerging,
      });
  }
  throw new RingError("RING_ADDRESS_CEILING", {
    details: {
      compiled,
      limit: MAX_TRANSACTION_ADDRESSES,
      afterMerging,
      dataNotes: inputs.filter(carriesData).length,
    },
  });
}

function mergeGroups(
  inputs: readonly SpentInput[],
  capacity: MergeCapacity,
): readonly MergeGroup[] {
  const groups: { head: SpentInput; positions: number[] }[] = [];
  inputs.forEach((input, position) => {
    if (carriesData(input)) return;
    const held = groups.find((group) => mergesWith(input, group.head));
    if (held === undefined) groups.push({ head: input, positions: [position] });
    else held.positions.push(position);
  });
  const merges = groups.flatMap(({ head, positions }) => {
    const width = Math.max(
      1,
      equalBytes(head.nullifierPublicKey, ZERO_NULLIFIER_PK) ? capacity.zeroKey : capacity.keyed,
    );
    return Array.from({ length: Math.ceil(positions.length / width) }, (_, run) =>
      positions.slice(run * width, (run + 1) * width),
    )
      .filter((run) => run.length > 1)
      .map(
        (run): MergeGroup =>
          Object.freeze({
            owner: head.owner,
            asset: head.asset,
            nullifierPublicKey: head.nullifierPublicKey,
            ...(head.ringProgramId === undefined ? {} : { ringProgramId: head.ringProgramId }),
            treeId: head.treeId,
            inputs: Object.freeze(run),
          }),
      );
  });
  return merges.sort((left, right) => right.inputs.length - left.inputs.length);
}

/** SPP merge refuses a note with a data hash. */
function carriesData(input: SpentInput): boolean {
  return input.dataHash !== undefined && !isZero(input.dataHash);
}

function mergesWith(input: SpentInput, other: SpentInput): boolean {
  return (
    input.owner.equals(other.owner) &&
    input.asset === other.asset &&
    equalBytes(input.nullifierPublicKey, other.nullifierPublicKey) &&
    input.ringProgramId === other.ringProgramId &&
    input.treeId === other.treeId
  );
}
