/** The address ceiling of one compiled transaction, Rust `validation::address_ceiling`. */
import {
  TRANSACTION_SIZE_LIMIT as LIMIT_BYTES,
  type Address,
  type Bytes32,
  type Bytes33,
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
import { MAX_CPI_DATA_LEN, MAX_FRAME_LEN } from "../../protocol/transaction/frame-buffer.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import {
  ringRailOf,
  RingTransactData,
  type RingTransactConfig,
} from "../../protocol/transaction/transact.js";
import { BufferedFrame } from "../payments/buffered-frame.js";
import {
  MAX_TRANSACTION_ADDRESSES,
  MAX_TRANSACTION_INSTRUCTIONS,
  MAX_TRANSACTION_SIGNATURES,
  transactionSignatures,
  transactionSize,
  type TransactionSize,
} from "./compile.js";

const ZERO_POLICY: RingTransactConfig = Object.freeze({
  auditorPubkey: new Uint8Array(33) as Bytes33,
});

/** The message around the operation, setup compiles ahead of it in one transaction. */
export interface FitSigners {
  readonly payer: Address;
  /** Its signers and addresses join the count. */
  readonly setupInstructions?: readonly Instruction[];
}

export interface FitBudget {
  readonly computeUnitLimit: number;
  readonly priorityFeeLamports?: bigint;
}

/** `buffered` figures are the settlement's, each upload write fits by its own chunking. */
export type FitTransport = "inline" | "buffered";

/** What setup adds to the transaction it shares with the operation. */
export interface SetupEffect {
  readonly instructions: number;
  readonly signatures: number;
  readonly bytes: number;
  readonly addresses: number;
}

/** What the transaction costs against each ceiling, setup included. */
export interface Fit {
  readonly transport: FitTransport;
  readonly signatures: number;
  readonly bytes: number;
  readonly addresses: number;
  /** The data SPP receives on the transfer tags, absent on any other tag. */
  readonly cpiBytes?: number;
  readonly setup: SetupEffect;
}

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

/** Rust `TransactionFit`, the one acceptance rule of a final transaction, refusing CPI bytes, then signatures, instructions, bytes, addresses. */
export const TransactionFit = Object.freeze({
  /** A transfer past the byte ceiling settles from a buffer, nothing else changes transport. */
  async of(instruction: Instruction, signers: FitSigners, budget: FitBudget): Promise<Fit> {
    const cpiBytes = sppCpiBytes(instruction);
    // Runs before the compile, the kit refuses a frame past its u16 length.
    const frame = instruction.data?.length ?? 0;
    if (takesBuffer(instruction) && frame > MAX_FRAME_LEN)
      throw new RingError("RING_FRAME_TOO_LARGE", {
        details: { bytes: frame, limit: MAX_FRAME_LEN },
      });
    checkCounts(instruction, signers);
    const settlement = await settlementOf(instruction, signers, budget);
    return settlement === undefined
      ? accept({ form: instruction, transport: "inline", signers, budget, cpiBytes })
      : accept({ form: settlement, transport: "buffered", signers, budget, cpiBytes });
  },

  /** The operation refuses a buffer, a deposit, a merge or a transfer sent in one transaction. */
  inline(instruction: Instruction, signers: FitSigners, budget: FitBudget): Fit {
    const cpiBytes = sppCpiBytes(instruction);
    checkCounts(instruction, signers);
    return accept({ form: instruction, transport: "inline", signers, budget, cpiBytes });
  },
});

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
  const signers: FitSigners = {
    payer,
    ...(input.setupInstructions === undefined
      ? {}
      : { setupInstructions: input.setupInstructions }),
  };
  const budget: FitBudget = {
    computeUnitLimit: input.computeUnitLimit,
    ...(input.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: input.priorityFeeLamports }),
  };
  try {
    const fit = await TransactionFit.of(instruction, signers, budget);
    return Object.freeze({
      kind: fit.transport,
      size: Object.freeze({ bytes: fit.bytes, addresses: fit.addresses }),
    });
  } catch (cause) {
    // Only the address count leaves a route, merging first narrows the spend.
    if (!(cause instanceof RingError) || cause.code !== "RING_FIT_ADDRESSES") throw cause;
  }
  // Past the byte ceiling only the settlement's own compiled count decides.
  const form = (await settlementOf(instruction, signers, budget)) ?? instruction;
  const sized = (mergedAway: ReadonlySet<Address>): TransactionSize =>
    compiled(
      {
        ...form,
        accounts: (form.accounts ?? []).filter((account) => !mergedAway.has(account.address)),
      },
      signers,
      budget,
    );
  const mergedAway = new Set<Address>();
  const before = sized(mergedAway);
  const chosen: MergeGroup[] = [];
  let afterMerging = before.addresses;
  for (const group of mergeGroups(inputs, input.mergeCapacity)) {
    // The merged note's own nullifier PDA replaces one of the group's.
    for (const position of group.inputs.slice(1))
      mergedAway.add((inputs[position] as SpentInput).nullifierPda);
    chosen.push(group);
    afterMerging = sized(mergedAway).addresses;
    if (afterMerging <= MAX_TRANSACTION_ADDRESSES)
      return Object.freeze({
        kind: "mergeFirst",
        groups: Object.freeze(chosen),
        addresses: afterMerging,
      });
  }
  throw new RingError("RING_ADDRESS_CEILING", {
    details: {
      compiled: before.addresses,
      limit: MAX_TRANSACTION_ADDRESSES,
      afterMerging,
      dataNotes: inputs.filter(carriesData).length,
    },
  });
}

function takesBuffer(instruction: Instruction): boolean {
  const tag = instruction.data?.[0];
  return tag === RingInstructionTag.transfer || tag === RingInstructionTag.authorityTransfer;
}

function compiled(form: Instruction, signers: FitSigners, budget: FitBudget): TransactionSize {
  return transactionSize({
    ...budget,
    feePayer: signers.payer,
    ...(signers.setupInstructions === undefined
      ? {}
      : { setupInstructions: signers.setupInstructions }),
    instructions: [form],
  });
}

/**
 * The counts read the metas with no compile, so the kit's own ceilings never name the refusal. A
 * settlement keeps every signer of the transfer and the instruction count, the verdict holds for
 * either transport.
 */
function checkCounts(form: Instruction, signers: FitSigners): void {
  const setup = signers.setupInstructions ?? [];
  const signatures = transactionSignatures({
    feePayer: signers.payer,
    setupInstructions: setup,
    instructions: [form],
  });
  if (signatures > MAX_TRANSACTION_SIGNATURES)
    throw new RingError("RING_FIT_SIGNATURES", {
      details: { signatures, limit: MAX_TRANSACTION_SIGNATURES },
    });
  const instructions = setup.length + 1;
  if (instructions > MAX_TRANSACTION_INSTRUCTIONS)
    throw new RingError("RING_FIT_INSTRUCTIONS", {
      details: { instructions, limit: MAX_TRANSACTION_INSTRUCTIONS },
    });
}

/** Set past the byte ceiling on a tag the buffer takes, a buffer relieves bytes and nothing else. */
async function settlementOf(
  instruction: Instruction,
  signers: FitSigners,
  budget: FitBudget,
): Promise<Instruction | undefined> {
  if (!takesBuffer(instruction) || compiled(instruction, signers, budget).bytes <= LIMIT_BYTES)
    return undefined;
  return (await BufferedFrame.of(instruction, signers.payer, 0n)).settle();
}

function accept(
  input: Readonly<{
    form: Instruction;
    transport: FitTransport;
    signers: FitSigners;
    budget: FitBudget;
    cpiBytes: number | undefined;
  }>,
): Fit {
  const { form, transport, signers, budget, cpiBytes } = input;
  const size = compiled(form, signers, budget);
  if (size.bytes > LIMIT_BYTES)
    throw new RingError("RING_FIT_BYTES", {
      details: { bytes: size.bytes, limit: LIMIT_BYTES },
    });
  if (size.addresses > MAX_TRANSACTION_ADDRESSES)
    throw new RingError("RING_FIT_ADDRESSES", {
      details: { addresses: size.addresses, limit: MAX_TRANSACTION_ADDRESSES },
    });
  const signatures = transactionSignatures({
    feePayer: signers.payer,
    setupInstructions: signers.setupInstructions ?? [],
    instructions: [form],
  });
  return Object.freeze({
    transport,
    signatures,
    bytes: size.bytes,
    addresses: size.addresses,
    ...(cpiBytes === undefined ? {} : { cpiBytes }),
    setup: setupEffect({ form, signers, budget, size, signatures }),
  });
}

function setupEffect(
  input: Readonly<{
    form: Instruction;
    signers: FitSigners;
    budget: FitBudget;
    size: TransactionSize;
    signatures: number;
  }>,
): SetupEffect {
  const { form, signers, budget, size, signatures } = input;
  const instructions = signers.setupInstructions?.length ?? 0;
  if (instructions === 0)
    return Object.freeze({ instructions: 0, signatures: 0, bytes: 0, addresses: 0 });
  const alone = compiled(form, { payer: signers.payer }, budget);
  return Object.freeze({
    instructions,
    signatures:
      signatures - transactionSignatures({ feePayer: signers.payer, instructions: [form] }),
    bytes: Math.max(size.bytes - alone.bytes, 0),
    addresses: Math.max(size.addresses - alone.addresses, 0),
  });
}

/**
 * The exact data the program forwards to SPP, undefined off the transfer tags, refused past the CPI
 * limit under either transport, since the program forwards one expansion. A frame can clear
 * `MAX_FRAME_LEN` and still pass it, because the expansion widens outputs and messages. The ring's
 * mode decides the rail and the compact frame does not name it, so the strict parser reads the frame
 * under both rails of its tag and the longer expansion counts. The zero auditor key changes no
 * length, the expansion reads it only as a view tag of fixed width.
 */
function sppCpiBytes(instruction: Instruction): number | undefined {
  if (!takesBuffer(instruction)) return undefined;
  const data = Uint8Array.from(instruction.data ?? []);
  const lengths = (["confidential", "anonymous"] as const).flatMap((mode) => {
    try {
      const rail = ringRailOf(data[0] as number, mode);
      const parsed = RingTransactData.parse(data.subarray(1), rail);
      return [RingTransactData.sppDataLength(parsed, ZERO_POLICY)];
    } catch (cause) {
      if (!(cause instanceof RingError)) throw cause;
      return [];
    }
  });
  if (lengths.length === 0) throw new RingError("RING_FIT_UNPARSED_FRAME");
  const bytes = Math.max(...lengths);
  if (bytes > MAX_CPI_DATA_LEN)
    throw new RingError("RING_FIT_CPI_BYTES", {
      details: { bytes, limit: MAX_CPI_DATA_LEN },
    });
  return bytes;
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
      .map((run): MergeGroup =>
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
