import { DUMMY_DOMAIN, UTXO_DOMAIN, treeIdField } from "@heliuslabs/zolana/interface";
import { type Bytes32, ClientError } from "@heliuslabs/zolana";
import {
  SppProofInputs,
  type ProofInputUtxo,
  type ProofOutputUtxo,
} from "@heliuslabs/zolana/transaction";
import { bigintToBytes, inputCircuitUtxo, outputCircuitUtxo } from "@heliuslabs/zolana/internal";
import { RING_INPUT_SLOTS, RING_OUTPUT_SLOTS, type CustomRingOpening } from "./types.js";

export interface RingOpenings {
  readonly nIn: number;
  readonly nOut: number;
  readonly inputs: readonly CustomRingOpening[];
  readonly outputs: readonly CustomRingOpening[];
}

/** A dummy output retains the tree and blinding bound by its SPP commitment and auditor disclosure. */
export function ringOpenings(proofInputs: SppProofInputs): RingOpenings {
  if (!(proofInputs instanceof SppProofInputs)) {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  if (
    proofInputs.inputUtxos.length > RING_INPUT_SLOTS ||
    proofInputs.outputs.length > RING_OUTPUT_SLOTS
  ) {
    throw new ClientError("CLIENT_PROVER_INPUT");
  }
  const outputTreeId = treeIdField(proofInputs.outputTreeId);
  const inputs = Array.from({ length: RING_INPUT_SLOTS }, (_, index) => {
    const input = proofInputs.inputUtxos[index];
    return input === undefined ? zeroOpening(0) : inputOpening(input);
  });
  const outputs = Array.from({ length: RING_OUTPUT_SLOTS }, (_, index) => {
    const output = proofInputs.outputs[index];
    return output === undefined ? zeroOpening(0) : outputOpening(output, outputTreeId);
  });
  return Object.freeze({
    nIn: proofInputs.inputUtxos.length,
    nOut: proofInputs.outputs.filter((output) => !output.isCompact()).length,
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
  });
}

/** Mirrors Rust `input_opening`, each slot opens under its own tree. */
function inputOpening(input: ProofInputUtxo): CustomRingOpening {
  if (input.isDummy()) return zeroOpening(DUMMY_DOMAIN);
  const utxo = inputCircuitUtxo(input);
  return Object.freeze({
    domain: openingField(BigInt(UTXO_DOMAIN)),
    treeId: treeIdField(input.treeId),
    ownerPkHash: input.utxo.owner.ownerProofInputHash(),
    nullifierPk: input.nullifierPublicKey,
    asset: openingField(utxo.asset),
    amount: openingField(utxo.amount),
    blinding: openingField(utxo.blinding),
    dataHash: openingField(utxo.dataHash),
    ringDataHash: openingField(utxo.ringDataHash),
    ringProgramId: openingField(utxo.ringProgramId),
  });
}

/** Owner address presence determines the dummy domain independently of the public owner tag. */
function outputOpening(output: ProofOutputUtxo, treeId: Bytes32): CustomRingOpening {
  const owner = output.ownerAddress;
  if (owner === undefined) {
    return Object.freeze({
      ...zeroOpening(DUMMY_DOMAIN),
      treeId,
      blinding: output.blinding,
    });
  }
  const utxo = outputCircuitUtxo(output);
  return Object.freeze({
    domain: openingField(BigInt(UTXO_DOMAIN)),
    treeId,
    ownerPkHash: owner.signingPublicKey.ownerProofInputHash(),
    nullifierPk: owner.nullifierPublicKey,
    asset: openingField(utxo.asset),
    amount: openingField(utxo.amount),
    blinding: openingField(utxo.blinding),
    dataHash: openingField(utxo.dataHash),
    ringDataHash: openingField(utxo.ringDataHash),
    ringProgramId: openingField(utxo.ringProgramId),
  });
}

function zeroOpening(domain: number): CustomRingOpening {
  return Object.freeze({
    domain: openingField(BigInt(domain)),
    treeId: openingField(0n),
    ownerPkHash: openingField(0n),
    nullifierPk: openingField(0n),
    asset: openingField(0n),
    amount: openingField(0n),
    blinding: openingField(0n),
    dataHash: openingField(0n),
    ringDataHash: openingField(0n),
    ringProgramId: openingField(0n),
  });
}

function openingField(value: bigint): Bytes32 {
  return bigintToBytes(value, "opening") as Bytes32;
}
