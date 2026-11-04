/** The address ceiling of one compiled transaction, Rust `validation::address_ceiling`. */
import {
  TRANSACTION_SIZE_LIMIT,
  type Address,
  type Bytes32,
  type Instruction,
} from "@heliuslabs/zolana/interface";
import {
  equalBytes,
  isZero,
  nullifierPdaAddress,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import type { ShieldedPublicKey } from "@heliuslabs/zolana/keypair";
import type { ProofInputUtxo } from "@heliuslabs/zolana/transaction";

import { RingError } from "../../protocol/error.js";
import { MAX_FRAME_LEN } from "../../protocol/transaction/frame-buffer.js";
import { BufferedFrame } from "../payments/buffered-frame.js";
import {
  fitsOneTransaction,
  MAX_TRANSACTION_ADDRESSES,
  transactionSize,
  type TransactionSize,
} from "./compile.js";

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
  | Readonly<{ kind: "inline"; size: TransactionSize }>
  /** The frame settles from a buffer, the size is the settlement's. */
  | Readonly<{ kind: "buffered"; size: TransactionSize }>
  /** `addresses` counts one nullifier PDA left per merged note. */
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
export async function decideAddressCeiling(
  input: Readonly<{
    payer: Address;
    instruction: Instruction;
    computeUnitLimit: number;
    priorityFeeLamports?: bigint;
    setupInstructions?: readonly Instruction[];
    inputs: readonly SpentInput[];
    mergeCapacity: MergeCapacity;
  }>,
): Promise<CeilingDecision> {
  const { inputs, instruction, payer } = input;
  const frame = instruction.data?.length ?? 0;
  // Runs before the compile, the kit refuses a frame past its u16 length.
  if (frame > MAX_FRAME_LEN)
    throw new RingError("RING_FRAME_TOO_LARGE", {
      details: { bytes: frame, limit: MAX_FRAME_LEN },
    });
  const sized = (form: Instruction, mergedAway: ReadonlySet<Address>): TransactionSize =>
    transactionSize({
      feePayer: payer,
      computeUnitLimit: input.computeUnitLimit,
      ...(input.priorityFeeLamports === undefined
        ? {}
        : { priorityFeeLamports: input.priorityFeeLamports }),
      ...(input.setupInstructions === undefined
        ? {}
        : { setupInstructions: input.setupInstructions }),
      instructions: [
        {
          ...form,
          accounts: (form.accounts ?? []).filter((account) => !mergedAway.has(account.address)),
        },
      ],
    });
  const none = new Set<Address>();
  const inline = sized(instruction, none);
  if (fitsOneTransaction(inline)) return Object.freeze({ kind: "inline", size: inline });
  // Past the byte ceiling only the settlement's own compiled count decides.
  const form =
    inline.bytes > TRANSACTION_SIZE_LIMIT
      ? (await BufferedFrame.of(instruction, payer, 0n)).settle()
      : instruction;
  const compiled = sized(form, none);
  if (compiled.addresses <= MAX_TRANSACTION_ADDRESSES)
    return Object.freeze({ kind: "buffered", size: compiled });
  const mergedAway = new Set<Address>();
  const chosen: MergeGroup[] = [];
  let afterMerging = compiled.addresses;
  for (const group of mergeGroups(inputs, input.mergeCapacity)) {
    // The merged note's own nullifier PDA replaces one of the group's.
    for (const position of group.inputs.slice(1))
      mergedAway.add((inputs[position] as SpentInput).nullifierPda);
    chosen.push(group);
    afterMerging = sized(form, mergedAway).addresses;
    if (afterMerging <= MAX_TRANSACTION_ADDRESSES)
      return Object.freeze({
        kind: "mergeFirst",
        groups: Object.freeze(chosen),
        addresses: afterMerging,
      });
  }
  throw new RingError("RING_ADDRESS_CEILING", {
    details: {
      compiled: compiled.addresses,
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
