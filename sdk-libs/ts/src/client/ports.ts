import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { RequestContext, Bytes32 } from "@heliuslabs/zolana";
import type { Transaction } from "@heliuslabs/zolana/interface";
import type { IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";
import type {
  BlockhashProvider,
  ChainReader,
  MergeAssembler,
  ProofDataSourceContext,
  ProofResolution,
  ResolvedProofTree,
  TreeContext,
} from "@heliuslabs/zolana/client";
import type { Address, Signature } from "@solana/kit";
import type {
  CustomRingBaseProofRequest,
  CustomRingCompressedPolicyProofRequest,
  CustomRingDepositProofRequest,
  CustomRingPolicyProofRequest,
  CustomRingRegisterKeyProofRequest,
} from "./prover/types.js";

export interface RingMemberRequest {
  readonly ringProgramId: Address;
  readonly member: Bytes32;
}

export interface RingMemberProofRequest extends RingMemberRequest {
  readonly expectedRoot: Bytes32;
  readonly expectedNextIndex: bigint;
}

/** Correlates a member proof with its indexed root and cursor. */
export interface RingMemberProofContext {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly root: Bytes32;
  readonly nextIndex: bigint;
  readonly member: Bytes32;
}

/** `record` is `null` until the member registers. */
export interface RingSpendRecordLookup {
  readonly context: Readonly<{ slot: bigint; blockTime: bigint }>;
  readonly record: Readonly<{
    transaction: IndexedShieldedTransaction;
    outputIndex: number;
  }> | null;
}

export interface RingSpendRecordReader {
  getRingSpendRecord(
    request: RingMemberRequest,
    context?: RequestContext,
  ): Promise<RingSpendRecordLookup>;
}

/** Authenticates insertion of a member's encrypted nullifier key. */
export interface RingKeyRegistryRegisterProof extends RingMemberProofContext {
  readonly lowMember: Bytes32;
  readonly lowNext: Bytes32;
  readonly lowKeyHash: Bytes32;
  readonly lowIndex: bigint;
  readonly lowProof: readonly Bytes32[];
  readonly newProof: readonly Bytes32[];
}

/** Carries an encrypted key and the path needed to authenticate its opening. */
export interface RingKeyRegistryEntry extends RingMemberProofContext {
  readonly next: Bytes32;
  readonly index: bigint;
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly ciphertext: Bytes32;
  readonly proof: readonly Bytes32[];
}

/** Reads encrypted member keys and their registry paths. */
export interface RingKeyRegistryReader {
  getRingKeyRegistryEntry(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryEntry>;
  getRingKeyRegistryRegisterProof(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryRegisterProof>;
}

export type RingSubmissionStatus =
  | Readonly<{ kind: "unknown" }>
  | Readonly<{ kind: "confirmed"; slot: bigint }>
  | Readonly<{ kind: "failed"; instructionIndex?: number; customCode?: number }>
  | Readonly<{ kind: "expired" }>;

/** Identifies a broadcast awaiting confirmation or expiry. */
export interface RingSubmissionPending {
  readonly signature: Signature;
  readonly lastValidBlockHeight: bigint;
}

/** Separates signing and broadcast from submission status resolution. */
export interface RingSubmissionTransport {
  sign(transaction: Transaction, context?: RequestContext): Promise<Transaction>;
  /** A refusal before broadcast returns `failed`, a throw leaves the signature pending. */
  send(
    transaction: Transaction,
    context?: RequestContext,
  ): Promise<RingSubmissionStatus | undefined>;
  status(pending: RingSubmissionPending, context?: RequestContext): Promise<RingSubmissionStatus>;
}

export interface IndexedPolicyLookup {
  readonly treeSlot: number;
  readonly commitment: Bytes32 | null;
  readonly nullifier: Bytes32 | null;
}

export interface IndexedRegistry {
  readonly ringProgramId: Address;
  readonly root: Bytes32;
  readonly nextIndex: bigint;
}

export interface IndexedDepositInputs {
  readonly deposit: CustomRingDepositProofRequest;
  readonly registry: IndexedRegistry;
  readonly minContextSlot?: bigint;
}

export interface IndexedDepositClient extends ProofDataSourceContext {
  proveIndexedRingDeposit?(
    inputs: IndexedDepositInputs,
    context?: RequestContext,
  ): Promise<Uint8Array>;
}

export interface IndexedPolicyInputs {
  readonly minContextSlot?: bigint;
  readonly circuit:
    | "custom-ring-policy"
    | "custom-ring-compressed-policy"
    | "custom-ring-delegate-policy";
  readonly policy: CustomRingPolicyProofRequest;
  readonly transactionSalt?: Uint8Array;
  readonly trees: readonly ResolvedProofTree[];
  readonly lookups: readonly IndexedPolicyLookup[];
  readonly publicInputs: readonly Bytes32[];
  readonly registry?: IndexedRegistry;
}

export interface IndexedPolicyClient extends ProofDataSourceContext {
  proveIndexedRingPolicy?(
    inputs: IndexedPolicyInputs,
    context?: RequestContext,
  ): Promise<Readonly<{ proof: Uint8Array; resolution: ProofResolution }>>;
}

/** Returns proofs in the `CUSTOM_RING_PROOF_LENGTH` layout the ring program verifies. */
export interface RingProver {
  proveCustomRingBase(
    inputs: CustomRingBaseProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  proveCustomRingPolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  proveCustomRingCompressedPolicy(
    inputs: CustomRingCompressedPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  proveCustomRingDelegatePolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  proveCustomRingDeposit(
    inputs: CustomRingDepositProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
  proveCustomRingRegisterKey(
    inputs: CustomRingRegisterKeyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array>;
}

export type RingMergeClient = TreeContext &
  BlockhashProvider &
  Pick<ChainReader, "getAccount"> &
  Pick<MergeAssembler, "proveMerge"> &
  ProofDataSourceContext;
