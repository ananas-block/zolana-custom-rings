/**
 * The SPP proof of the one write `Enroll` makes, the client side of Rust
 * `SppTransactCpi::into_ix_data`.
 *
 * The ring program rebuilds the output, its data, the private transaction hash and the external
 * data hash on chain from the credential and the address root index, and SPP verifies the proof
 * against them. A value built here that differs from the program's construction fails SPP and
 * settles nothing. The fee payer enters no hash, a sponsor signs without a new proof.
 *
 * Read after `protocol/membership/credential.ts`.
 * Read before `operations/management/enrollment.ts`.
 */
import type { Address } from "@solana/kit";

import type {
  NonInclusionProof,
  ProofReader,
  Prover,
  TransferInputs,
} from "@heliuslabs/zolana/client";
import {
  asField,
  bytesToBigInt,
  cacheProverFields,
  createDummyTransferInput,
  createOutput,
  emptyCachedInputs,
  equalBytes,
  inputFlags,
  InstructionTag,
  addressBytes,
  signerIdentity,
  signerWidth,
  transferPublicInputHash,
  treeAddress,
  treeSlotFields,
} from "@heliuslabs/zolana/internal";
import {
  externalDataHash,
  inputTreeSlots,
  treeIdField,
  type Bytes32,
  type Bytes33,
  type RequestContext,
  type TransactProof,
} from "@heliuslabs/zolana/interface";
import { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  createProofOutput,
  outputBlindingSeed,
  privateTxBlinding,
  privateTxHash,
  ProgramOwner,
  ProofInputUtxo,
  SOL_MINT,
  transactOutputBlinding,
} from "@heliuslabs/zolana/transaction";

import { RingError } from "../../protocol/error.js";
import {
  ACCOUNT_BLINDING_SEED,
  ADDRESS_TREE_ID,
  credentialAddressInput,
  credentialBlinding,
  credentialDataHash,
  credentialSeed,
  encodeCredentialOutput,
  type AuditCredential,
} from "../../protocol/membership/credential.js";

const U64_MAX = (1n << 64n) - 1n;
const ZERO_32 = new Uint8Array(32) as Bytes32;
/** One write proves at the 2x2 shape, the second slot of each side is compact padding. */
const SHAPE = Object.freeze({ inputs: 2, outputs: 2 });
/** Rust `pda_shielded_address` uses a fixed viewing key, it enters no hash the proof binds. */
const UNUSED_VIEWING_KEY = X25519PublicKey.fromBytes(
  Uint8Array.of(4, 9, ...new Uint8Array(31)) as Bytes33,
);

export interface CredentialWrite {
  readonly credentialPda: Address;
  readonly credential: AuditCredential;
  /** The credential output hash binds its id. */
  readonly outputTreeId: number;
}

export interface ProvenCredentialWrite {
  readonly address: Bytes32;
  readonly transact: TransactProof;
  /** The tree 0 nullifier root both non-inclusion proofs open against. */
  readonly addressRootIndex: number;
}

/** The address and the padding nullifier prove absent under one tree 0 root. */
export async function proveCredentialWrite(
  input: CredentialWrite &
    Readonly<{
      client: Pick<ProofReader, "getNonInclusionProofs">;
      prover: Pick<Prover, "proveTransferInputs">;
    }>,
  context?: RequestContext,
): Promise<ProvenCredentialWrite> {
  const address = addressInputOf(input);
  const padding = ProofInputUtxo.compact(ADDRESS_TREE_ID);
  const { proofs } = await input.client.getNonInclusionProofs(
    treeAddress(ADDRESS_TREE_ID),
    [address.nullifier(), padding.nullifier()],
    undefined,
    context,
  );
  const { addressProof, paddingProof } = checkedProofs(address, padding, proofs);
  const transferInputs = credentialWriteInputs({
    ...input,
    addressProof,
    paddingProof,
  });
  return Object.freeze({
    address: address.nullifier(),
    transact: await input.prover.proveTransferInputs(transferInputs, context),
    addressRootIndex: addressProof.rootIndex,
  });
}

/** @internal Rust `CreateProofInputParams::to_proof_inputs` for the credential PDA. */
export function credentialWriteInputs(
  input: CredentialWrite &
    Readonly<{
      addressProof: NonInclusionProof;
      paddingProof: NonInclusionProof;
    }>,
): TransferInputs {
  const { credentialPda, credential, outputTreeId, addressProof, paddingProof } = input;
  const address = addressInputOf(input);
  const padding = ProofInputUtxo.compact(ADDRESS_TREE_ID);
  // 1. The address is the first nullifier, every blinding derives from it and the account seed.
  const first = address.nullifier();
  const outputSeed = outputBlindingSeed(first, ACCOUNT_BLINDING_SEED);
  const output = createProofOutput({
    ownerAddress: new ProgramOwner(credentialPda).address(UNUSED_VIEWING_KEY),
    asset: SOL_MINT,
    amount: 0n,
    blinding: credentialBlinding(first),
    dataHash: credentialDataHash(credential, first),
  });
  const compact = createProofOutput({
    asset: SOL_MINT,
    amount: 0n,
    blinding: transactOutputBlinding(first, outputSeed, 1),
    compact: true,
  });
  const outputHash = output.hash(outputTreeId);
  // 2. The program hashes only its write, an address input hashes as zero, padding enters no chain.
  const privateHash = privateTxHash({
    inputHashes: [ZERO_32],
    outputHashes: [outputHash],
    addressNullifiers: [first],
    blinding: privateTxBlinding(first, ACCOUNT_BLINDING_SEED),
  });
  // 3. Rust `TransactExternalData::from_outputs`, one plaintext output under the PDA's inline tag.
  const ownerTag = addressBytes(credentialPda, "credential PDA") as Bytes32;
  const externalHash = externalDataHash({
    instructionDiscriminator: InstructionTag.transact,
    expiryUnixTs: U64_MAX,
    txViewingPk: new Uint8Array(33) as Bytes33,
    salt: new Uint8Array(16) as never,
    interfaceTransfers: [],
    outputs: [
      {
        utxoHash: outputHash,
        ownerTag: { kind: "inline", value: ownerTag },
        data: encodeCredentialOutput(first, credential),
      },
    ],
    messages: [],
    settlementAccounts: [],
    resolvedOwnerTags: [ownerTag],
  });
  // 4. The PDA is the one signer, the ring program signs for it, the fee payer holds no slot.
  const owner = signerIdentity(credentialPda);
  const signers = [owner, ...Array<bigint>(signerWidth(SHAPE) - 1).fill(0n)];
  const flags = inputFlags(true, [0, 0]);
  const treeSlots = inputTreeSlots([
    {
      id: ADDRESS_TREE_ID,
      utxoRoot: ZERO_32,
      nullifierRoot: addressProof.root,
    },
  ]);
  const cached = emptyCachedInputs(SHAPE.inputs);
  const outputs = [createOutput(output, outputTreeId), createOutput(compact, outputTreeId)];
  const publicInputHash = transferPublicInputHash({
    nullifiers: [bytesToBigInt(first), 0n],
    outputHashes: outputs.map((entry) => entry.hash as bigint),
    outputTreeId,
    privateTxHash: bytesToBigInt(privateHash),
    externalDataHash: bytesToBigInt(externalHash),
    publicSlots: Array<bigint>(6).fill(0n),
    ringProgramId: 0n,
    signerPublicKeyHashes: signers,
    inputFlags: flags,
    publishedOutputOwnerPublicKeyHashes: outputs.map((entry) => entry.ownerPublicKeyHash as bigint),
    ...cached,
    treeSlots,
  });
  return Object.freeze({
    inputs: Object.freeze([
      Object.freeze({
        ...createDummyTransferInput(address, addressProof),
        ownerPublicKeyHash: asField(owner),
      }),
      createDummyTransferInput(padding, paddingProof),
    ]),
    outputs: Object.freeze(outputs),
    treeSlots: Object.freeze(treeSlots.map(treeSlotFields)),
    outputTreeId: asField(bytesToBigInt(treeIdField(outputTreeId))),
    externalDataHash: asField(bytesToBigInt(externalHash)),
    privateTxHash: asField(bytesToBigInt(privateHash)),
    blindingSeed: asField(bytesToBigInt(ACCOUNT_BLINDING_SEED)),
    publicAssets: Object.freeze([asField(0n), asField(0n), asField(0n)]),
    publicAmounts: Object.freeze([asField(0n), asField(0n), asField(0n)]),
    ringProgramId: asField(0n),
    signerPublicKeyHashes: Object.freeze(signers.map(asField)),
    inputFlags: asField(flags),
    publishedOutputOwnerPublicKeyHashes: Object.freeze(
      outputs.map((entry) => entry.ownerPublicKeyHash),
    ),
    ...cacheProverFields(cached),
    publicInputHash: asField(publicInputHash),
  });
}

function addressInputOf(input: CredentialWrite): ProofInputUtxo {
  const { credentialPda, credential } = input;
  return credentialAddressInput(
    credentialPda,
    credentialSeed(credential.ringId, credential.member),
  );
}

/** Both proofs name their leaf and one tree 0 root, `Enroll` carries a single root index. */
function checkedProofs(
  address: ProofInputUtxo,
  padding: ProofInputUtxo,
  proofs: readonly NonInclusionProof[],
): Readonly<{
  addressProof: NonInclusionProof;
  paddingProof: NonInclusionProof;
}> {
  const [addressProof, paddingProof] = proofs;
  const tree = treeAddress(ADDRESS_TREE_ID);
  if (
    proofs.length !== 2 ||
    addressProof === undefined ||
    paddingProof === undefined ||
    !equalBytes(addressProof.leaf, address.nullifier()) ||
    !equalBytes(paddingProof.leaf, padding.nullifier()) ||
    !equalBytes(addressProof.root, paddingProof.root) ||
    addressProof.rootIndex !== paddingProof.rootIndex ||
    addressProof.merkleContext.tree !== tree ||
    paddingProof.merkleContext.tree !== tree
  )
    throw new RingError("RING_ENROLLMENT_ADDRESS_PROOF");
  return { addressProof, paddingProof };
}
