import type { Bytes16, Bytes32 } from "@heliuslabs/zolana";
import type { TreeSlot } from "@heliuslabs/zolana/interface";

/** Rust `POLICY_INPUT_SLOTS` and `POLICY_OUTPUT_SLOTS`, the ring circuit's slot counts. */
export const RING_INPUT_SLOTS = 5;
export const RING_OUTPUT_SLOTS = 4;
/** Rust `MAX_RULES` and `MAX_INLINE_ASSETS`, the fixed rule table width. */
export const RING_RULE_SLOTS = 16;
export const RING_INLINE_ASSET_SLOTS = 8;
/** Rust `ANSWER_SLOTS`, the server rejects any other answers length. */
export const RING_ANSWER_SLOTS = 10;
/** Rust `MAX_SOURCES`, the positional source map width. */
export const RING_SOURCE_SLOTS = 8;
/** Rust `MAX_VELOCITY_ASSETS`, one counter per mint a spend record carries. */
export const RING_VELOCITY_SLOTS = 8;
export const RING_STATE_PATH_LENGTH = 32;
export const RING_NULLIFIER_PATH_LENGTH = 40;

/** Mirrors Rust `CustomRingOpening`, one opened UTXO slot in circuit hash order. */
export interface CustomRingOpening {
  readonly domain: Bytes32;
  /** Raw id of the tree the slot hashes under, right aligned. */
  readonly treeId: Bytes32;
  readonly ownerPkHash: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly asset: Bytes32;
  readonly amount: Bytes32;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly ringProgramId: Bytes32;
  /** Outputs only, absent with escrow off, in padding or on a namespace-owned record. */
  readonly key?: CustomRingRegistryKey;
}

/** Mirrors Go `RegistryKey`, an owner's escrowed nullifier key opened in the ring key registry. */
export interface CustomRingRegistryKey {
  readonly next: Bytes32;
  /** `hashBytes` of the sealed key ciphertext. */
  readonly ctHash: Bytes32;
  readonly index: bigint;
  readonly path: readonly Bytes32[];
}

/** Mirrors Rust `RuleAnswer`, one entry fact proven against the roots. */
export interface CustomRingRuleAnswer {
  readonly enabled: boolean;
  /** Index into the proof's `treeSlots` of the tree the fact is read in. */
  readonly treeSlot: number;
  readonly mode: number;
  readonly listId: number;
  readonly state: number;
  readonly absentBranch: number;
  readonly member: Bytes32;
  readonly contentHash: Bytes32;
  readonly version: bigint;
  readonly blinding: Bytes32;
  readonly low: Bytes32;
  readonly next: Bytes32;
  readonly nullifierPath: readonly Bytes32[];
  readonly nullifierPathIndex: bigint;
  readonly statePath: readonly Bytes32[];
  readonly statePathIndex: bigint;
}

/** Mirrors Rust `RuleAnswer::default`. */
export function disabledRuleAnswer(): CustomRingRuleAnswer {
  const zero = (): Bytes32 => new Uint8Array(32) as Bytes32;
  return Object.freeze({
    enabled: false,
    treeSlot: 0,
    mode: 1,
    listId: 1,
    state: 1,
    absentBranch: 1,
    member: zero(),
    contentHash: zero(),
    version: 0n,
    blinding: zero(),
    low: zero(),
    next: zero(),
    nullifierPath: Object.freeze(Array.from({ length: RING_NULLIFIER_PATH_LENGTH }, () => zero())),
    nullifierPathIndex: 0n,
    statePath: Object.freeze(Array.from({ length: RING_STATE_PATH_LENGTH }, () => zero())),
    statePathIndex: 0n,
  });
}

/** Mirrors Rust `SourceOwner`, slot `i` is empty or serves list `i + 1`. */
export interface CustomRingSourceOwner {
  readonly listId: number;
  readonly ownerHash: Bytes32;
}

/** Sets outflow and approval bounds for one asset. */
export interface CustomRingVelocityRow {
  readonly asset: Bytes32;
  readonly cap: bigint;
  readonly cosignAbove: bigint;
}

/** Opens the previous counters and salts their successor commitment. */
export interface CustomRingSpendRecordProofInput {
  readonly version: bigint;
  readonly window: bigint;
  readonly commitment: Bytes32;
  readonly salt: Bytes32;
  readonly assets: readonly Bytes32[];
  readonly spent: readonly bigint[];
  readonly nextSalt: Bytes32;
}

/** Binds outflow accounting to a ring and its current window. */
export interface CustomRingVelocityProofInput {
  readonly windowSlots: bigint;
  readonly rows: readonly CustomRingVelocityRow[];
  readonly ringId: Bytes32;
  readonly namespaceOwnerHash: Bytes32;
  readonly windowIndex: bigint;
  readonly approvalRequired: boolean;
  readonly record: CustomRingSpendRecordProofInput;
}

const zeroField = (): Bytes32 => new Uint8Array(32) as Bytes32;

export function velocityProofInputOff(
  identity: Readonly<{ ringId: Bytes32; namespaceOwnerHash: Bytes32 }>,
): CustomRingVelocityProofInput {
  return Object.freeze({
    windowSlots: 0n,
    rows: Object.freeze([]),
    ringId: identity.ringId,
    namespaceOwnerHash: identity.namespaceOwnerHash,
    windowIndex: 0n,
    approvalRequired: false,
    record: Object.freeze({
      version: 0n,
      window: 0n,
      commitment: zeroField(),
      salt: zeroField(),
      assets: Object.freeze(Array.from({ length: RING_VELOCITY_SLOTS }, zeroField)),
      spent: Object.freeze(Array.from({ length: RING_VELOCITY_SLOTS }, () => 0n)),
      nextSalt: zeroField(),
    }),
  });
}

/** Mirrors Rust `CustomRingPolicyProofRequest`, `auditorPublicKey` is the canonical 32-byte X25519 coordinate. */
export interface CustomRingPolicyProofRequest {
  readonly publicInputHash: Bytes32;
  readonly privateTxHash: Bytes32;
  readonly txViewingSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
  readonly salt: Bytes16;
  readonly nIn: number;
  readonly nOut: number;
  readonly inputs: readonly CustomRingOpening[];
  readonly outputs: readonly CustomRingOpening[];
  readonly addressChain: Bytes32;
  readonly privateTxBlinding: Bytes32;
  readonly sources: readonly CustomRingSourceOwner[];
  readonly policyLen: number;
  readonly rules: readonly Bytes32[];
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineLimits: readonly bigint[];
  readonly inlineCount: number;
  /** The populated prefix, one to `INPUT_TREES` policy trees. */
  readonly treeSlots: readonly TreeSlot[];
  readonly addressTreeId: number;
  readonly velocity: CustomRingVelocityProofInput;
  /** Present exactly when the ring escrows nullifier keys, every output key opens under it. */
  readonly keyRegistryRoot?: Bytes32;
  readonly answers: readonly CustomRingRuleAnswer[];
}

export interface CustomRingBaseProofRequest {
  readonly publicInputHash: Bytes32;
  readonly privateTxHash: Bytes32;
  readonly txViewingSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
  readonly salt: Bytes16;
  readonly nOut: number;
  readonly outputs: readonly CustomRingOpening[];
}

/** Proves one batch of deposit openings encrypted to the ring auditor. */
export interface CustomRingDepositProofRequest {
  readonly publicInputHash: Bytes32;
  readonly contextHash: Bytes32;
  readonly count: number;
  /** `ownerHash = Poseidon(ownerPkHash, nullifierPk)` per slot, zero past `count`. */
  readonly ownerPkHashes: readonly Bytes32[];
  readonly nullifierPks: readonly Bytes32[];
  readonly blindings: readonly Bytes32[];
  /** Per slot, absent with escrow off or past `count`. */
  readonly keys: readonly (CustomRingRegistryKey | undefined)[];
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
  /** Present exactly when the ring escrows nullifier keys. */
  readonly keyRegistryRoot?: Bytes32;
}

export interface CustomRingCompressedPolicyProofRequest {
  readonly transactionSalt: Bytes16;
  readonly policy: CustomRingPolicyProofRequest;
}

/** Mirrors Go `registryInsertion`, the append the key registration circuit proves. */
export interface CustomRingRegistryInsertion {
  readonly registryOldRoot: Bytes32;
  readonly registryNewRoot: Bytes32;
  readonly member: Bytes32;
  readonly newIndex: bigint;
  readonly lowMember: Bytes32;
  readonly lowNext: Bytes32;
  readonly lowKey: Bytes32;
  readonly lowIndex: bigint;
  readonly lowProof: readonly Bytes32[];
  readonly newProof: readonly Bytes32[];
}

/** Proves disclosure of a member nullifier key to the auditor. */
export interface CustomRingRegisterKeyProofRequest extends CustomRingRegistryInsertion {
  readonly publicInputHash: Bytes32;
  readonly nullifierSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
  readonly auditorPublicKey: Uint8Array;
}
