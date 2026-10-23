import { getBase58Decoder } from "@solana/kit";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  wireDecoder,
  treeAddress,
  equal as equalBytes,
  checkedClientBytes as checkedBytes,
  bytesField,
  bindResolution,
  contextSlotJson,
  opensAt,
  bytesToBigInt,
  hashChain,
} from "@heliuslabs/zolana/internal";
import {
  STATE_ROOT_HISTORY_CAPACITY,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
  inputTreeSlots,
  treeSlotsHashChain,
} from "@heliuslabs/zolana/interface";
import { ClientError, type Bytes32 } from "@heliuslabs/zolana";
import type { ProofResolution } from "@heliuslabs/zolana/client";
import type { IndexedPolicyInputs, IndexedDepositInputs, IndexedRegistry } from "../ports.js";

const invalid = (): ClientError => new ClientError("CLIENT_INVALID_PROOF_INPUTS");
const unparsable = (): ClientError => new ClientError("CLIENT_PROOF_PARSE", { details: {} });
const decoder = wireDecoder(invalid);
const hex = (value: Uint8Array): string => {
  const bytes = checkedBytes(value, 32, "field");
  bytesField(bytes, "field");
  return `0x${bytesToHex(bytes)}`;
};
const base58 = (value: Uint8Array): string => {
  hex(value);
  return getBase58Decoder().decode(value);
};
const omit = (value: unknown, names: readonly string[]): Record<string, unknown> =>
  Object.fromEntries(
    Object.entries(decoder.record(value, "prepared")).filter(([key]) => !names.includes(key)),
  );

export function indexedPolicyEnvelope(
  inputs: IndexedPolicyInputs,
  serialized: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  const compressed = inputs.circuit === "custom-ring-compressed-policy";
  if (
    ![
      "custom-ring-policy",
      "custom-ring-compressed-policy",
      "custom-ring-delegate-policy",
    ].includes(inputs.circuit) ||
    inputs.trees.length < 1 ||
    inputs.trees.length > 5 ||
    inputs.lookups.length !== 10 ||
    inputs.publicInputs.length !== (compressed ? 20 : 19)
  )
    throw invalid();
  if (
    inputs.circuit === "custom-ring-delegate-policy" &&
    (inputs.policy.velocity.windowIndex !== 0n || inputs.policy.velocity.approvalRequired)
  )
    throw invalid();
  if (compressed !== (inputs.transactionSalt !== undefined)) throw invalid();
  const prepared = omit(serialized, ["treeSlots", "publicInputHash"]);
  prepared["answers"] = decoder.list(prepared["answers"], "answers").map((answer, index) => {
    const fact = decoder.record(answer, "answer");
    const lookup = inputs.lookups[index];
    if (
      lookup === undefined ||
      !Number.isInteger(lookup.treeSlot) ||
      lookup.treeSlot < 0 ||
      lookup.treeSlot >= inputs.trees.length ||
      fact["enabled"] !== (lookup.nullifier !== null) ||
      fact["treeSlot"] !== lookup.treeSlot ||
      (lookup.nullifier !== null &&
        (fact["absentBranch"] === 2) !== (lookup.commitment !== null)) ||
      (lookup.nullifier === null && lookup.commitment !== null)
    )
      throw invalid();
    return omit(fact, [
      "statePathElements",
      "statePathIndex",
      "nfPathElements",
      "nfPathIndex",
      "low",
      "next",
    ]);
  });
  prepared["outputs"] = decoder
    .list(prepared["outputs"], "outputs")
    .map((output) => omit(output, ["key"]));
  const trees = inputs.trees.map((tree, index) => {
    if (
      tree.tree !== treeAddress(tree.id) ||
      inputs.trees.slice(0, index).some((known) => known.id === tree.id) ||
      !Number.isInteger(tree.utxoRootIndex) ||
      tree.utxoRootIndex < 0 ||
      tree.utxoRootIndex >= STATE_ROOT_HISTORY_CAPACITY ||
      !Number.isInteger(tree.nullifierRootIndex) ||
      tree.nullifierRootIndex < 0 ||
      tree.nullifierRootIndex >= NULLIFIER_TREE_ROOT_HISTORY_CAPACITY ||
      bytesField(tree.utxoRoot, "state root") === 0n
    )
      throw invalid();
    return {
      tree: tree.tree,
      id: tree.id,
      fallback: { ...tree, utxoRoot: hex(tree.utxoRoot), nullifierRoot: hex(tree.nullifierRoot) },
    };
  });
  if ((inputs.registry === undefined) !== (inputs.policy.keyRegistryRoot === undefined))
    throw invalid();
  const registry = inputs.registry;
  const wrapped =
    inputs.circuit === "custom-ring-policy"
      ? prepared
      : {
          circuitType: inputs.circuit,
          policy: prepared,
          ...(inputs.transactionSalt === undefined
            ? {}
            : {
                transactionSalt: `0x${bytesToHex(checkedBytes(inputs.transactionSalt, 16, "transaction salt"))}`,
              }),
        };
  return {
    ...contextSlotJson(inputs.minContextSlot),
    circuitType: inputs.circuit,
    prepared: wrapped,
    trees,
    inputs: inputs.lookups.map((lookup) => ({
      treeSlot: lookup.treeSlot,
      commitment: lookup.commitment === null ? null : base58(lookup.commitment),
      nullifier: lookup.nullifier === null ? null : base58(lookup.nullifier),
    })),
    publicInputs: inputs.publicInputs.map(hex),
    ...(registry === undefined
      ? {}
      : {
          registry: registryEnvelope(registry, inputs.policy.keyRegistryRoot),
        }),
  };
}

function registryEnvelope(
  registry: IndexedRegistry,
  root?: Bytes32,
): Readonly<Record<string, unknown>> {
  if (
    root === undefined ||
    typeof registry.nextIndex !== "bigint" ||
    registry.nextIndex < 1n ||
    registry.nextIndex > 1n << 40n ||
    !equalBytes(registry.root, root)
  )
    throw invalid();
  return {
    ringProgramId: decoder.address(registry.ringProgramId, "ring"),
    root: base58(registry.root),
    nextIndex: Number(registry.nextIndex),
  };
}

export function indexedDepositEnvelope(
  inputs: IndexedDepositInputs,
  serialized: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  return {
    circuitType: "custom-ring-deposit",
    prepared: omit(serialized, ["keys"]),
    publicInputs: [hex(inputs.deposit.publicInputHash)],
    registry: registryEnvelope(inputs.registry, inputs.deposit.keyRegistryRoot),
    ...contextSlotJson(inputs.minContextSlot),
  };
}

export function snapshotPolicyInputs(inputs: IndexedPolicyInputs): IndexedPolicyInputs {
  return {
    ...inputs,
    trees: inputs.trees.map((tree) => ({
      ...tree,
      utxoRoot: checkedBytes(tree.utxoRoot, 32, "state root"),
      nullifierRoot: checkedBytes(tree.nullifierRoot, 32, "nullifier root"),
    })),
    lookups: inputs.lookups.map((lookup) => ({
      ...lookup,
      commitment:
        lookup.commitment === null ? null : checkedBytes(lookup.commitment, 32, "commitment"),
      nullifier: lookup.nullifier === null ? null : checkedBytes(lookup.nullifier, 32, "nullifier"),
    })),
    publicInputs: inputs.publicInputs.map((value) => checkedBytes(value, 32, "public input")),
  };
}

/** A tree without a state or nullifier lookup keeps the root and position the client sent for it. */
export function checkPolicyResolution(
  inputs: IndexedPolicyInputs,
  resolution: ProofResolution,
): void {
  bindResolution(resolution, inputs.trees, (slots) =>
    bytesToBigInt(
      hashChain([
        ...inputs.publicInputs.slice(0, 1),
        treeSlotsHashChain(inputTreeSlots(slots)),
        ...inputs.publicInputs.slice(1),
      ]),
    ),
  );
  resolution.trees.forEach((tree, index) => {
    const sent = inputs.trees[index];
    if (
      sent === undefined ||
      tree.utxoRootIndex >= STATE_ROOT_HISTORY_CAPACITY ||
      (!opensAt(inputs.lookups, index, "commitment") &&
        (bytesToBigInt(tree.utxoRoot) !== bytesToBigInt(sent.utxoRoot) ||
          tree.utxoRootIndex !== sent.utxoRootIndex)) ||
      (!opensAt(inputs.lookups, index, "nullifier") &&
        (bytesToBigInt(tree.nullifierRoot) !== bytesToBigInt(sent.nullifierRoot) ||
          tree.nullifierRootIndex !== sent.nullifierRootIndex))
    )
      throw unparsable();
  });
}

/** A deposit resolves no tree, its statement is the hash the request carries. */
export function checkDepositResolution(
  publicInputHash: Bytes32,
  resolution: ProofResolution,
): void {
  bindResolution(resolution, [], () => bytesToBigInt(publicInputHash));
}
