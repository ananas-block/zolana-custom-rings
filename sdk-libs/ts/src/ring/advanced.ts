/** Circuit-facing codecs, registry proofs, and policy primitives. */
export {
  AUDIT_ENC_INFO,
  AUDITOR_MESSAGE_PREFIX_LENGTH,
  auditSharedSecret,
  auditorMessageData,
  auditorViewTag,
  maskDisclosure,
  packDisclosure,
  parseAuditorMessage,
  unmaskDisclosure,
  unpackDisclosure,
} from "../crypto/audit.js";
export type { AuditorMessage, DisclosurePad } from "../crypto/audit.js";
export {
  ANONYMOUS_AUDIT_CLASSES,
  ANONYMOUS_ENTRY_CLASS,
  ANONYMOUS_ENTRY_OUTPUTS,
  ANONYMOUS_MAX_INPUTS,
  ANONYMOUS_SLOT_BYTES,
  DELIVERED_AUDIT_CAPACITIES,
  DELIVERED_SLOT_BYTES,
  DENSE_DELIVERED_SLOT_BYTES,
  DISCLOSURE_CHUNK_BYTES,
  DISCLOSURE_INPUT_AMOUNT_BYTES,
  DISCLOSURE_SENDER_KEY_BYTES,
  INPUT_PREFIX_BITS,
  INPUT_PREFIX_BYTES,
  PACKED_AUDIT_CAPACITIES,
  anonymousAuditClass,
  anonymousAuditKey,
  anonymousFields,
  anonymousKeyClass,
  auditLayoutValue,
  deliveredFields,
  disclosureFieldCount,
  packedChunks,
  packedFields,
} from "../protocol/codec/ring-disclosure-layout.js";
export type {
  AnonymousAuditKey,
  AnonymousFields,
  AnonymousInputFields,
  AnonymousLayout,
  AnonymousSpend,
  AuditLayout,
  DeliveredFields,
  DeliveredLayout,
  DisclosureLayout,
  FieldRange,
  PackedFields,
  PackedLayout,
} from "../protocol/codec/ring-disclosure-layout.js";
export {
  anonymousCommitments,
  decodeDisclosure,
  disclosureFields,
  disclosureLayout,
  inputPrefixPair,
  openRingDisclosure,
  sealRingDisclosure,
  splitInputPrefixPair,
} from "../crypto/ring-disclosure.js";
export type {
  AnonymousInputOpening,
  AnonymousInputs,
  AnonymousOutputOpening,
  DeliveredOutputOpening,
  DisclosureKey,
  DummySlot,
  PackedOutputOpening,
  PublishedOutputs,
  RingDisclosure,
} from "../crypto/ring-disclosure.js";
export {
  EPOCH_SLOTS,
  J_INBOX,
  J_PAIR,
  K_PAIR_EPOCHS,
  TAG_LEN,
  deliveredSlotSecret,
  inboxKey,
  inboxTag,
  pairKey,
  pairTag,
  ringIdField,
  ringTag,
  ringTagField,
  ringTagFromOwnerTag,
  senderCommitment,
  tagEpoch,
  tagIndex,
} from "../crypto/ring-stream.js";
export type { DeliveredSlot, TagIndex } from "../crypto/ring-stream.js";
export {
  RING_DELIVERED_BODY_LEN,
  openDeliveredBody,
  sealDeliveredBody,
  type DeliveredBodyOpening,
} from "../protocol/transaction/output.js";
export {
  anonymousRingData,
  openRingDelivery,
  ringBlindingSeed,
  ringOutputBlinding,
  type RingDeliveredNote,
  type RingDeliveryOpening,
  type RingDeliverySlot,
  type RingNoteOwner,
} from "../crypto/blinding.js";

export {
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  isDataFreeOutput,
  outputBodyHash,
  outputRecipientKeyFields,
  outputTagField,
  ringDisclosureLayout,
  ringRail,
  ringRailOf,
  ringSppInputs,
  ringTransactOutput,
  taggedX25519,
} from "../protocol/transaction/transact.js";
export {
  encodeRingTransactInstructionData,
  type AnonymousRingEddsaCircuit,
  type RingCircuitId,
  type RingTransactInstructionData,
} from "../protocol/proof/circuit.js";
export type {
  AnchorRoot,
  AnonymousProofData,
  InputTrees,
  PolicyProof,
  RingOutput,
  RingRail,
  RingTransactConfig,
} from "../protocol/transaction/transact.js";
export {
  applyRecordsStatementElements,
  applyRecordsStatementHash,
  auditStatementElements,
  auditStatementHash,
  policyStatementElements,
  policyStatementHash,
  registerKeyStatementElements,
  registerKeyStatementHash,
  ringAuditStatement,
} from "../protocol/proof/statement.js";
export type {
  ApplyRecordsStatement,
  AuditBinding,
  AuditHead,
  AuditKind,
  AuditStatement,
  PolicyKey,
  PolicyStatement,
  RegisterKeyStatement,
} from "../protocol/proof/statement.js";
export { depositStatementElements } from "../proof/deposit-audit.js";
export type { DepositStatement } from "../proof/deposit-audit.js";
export type { EncodedRuleTable } from "../protocol/codec/ring-codecs.js";

export {
  FIELD_MAX,
  MEMBER_REGISTRY_EMPTY_ROOT,
  SENTINEL_RECORD,
  applyRecordsStatement,
  checkMember,
  escrowEntry,
  escrowKeyHash,
  memberRecordHash,
  queueChain,
  queueEntryHash,
  quadPathRoot,
  replayRecordWrites,
  verifyRecordOpening,
} from "../protocol/membership/member-opening.js";
export type { EscrowKey } from "../protocol/membership/member-opening.js";
export { readRegisteredRecord, type RegisteredRecord } from "../rpc/registered-record.js";
export { nextScanCursor } from "../operations/audit/audit.js";
export { openDisclosedMerge } from "../operations/audit/audit-merge.js";
export { recoverMergeOpening, type MergeAuditorOpening } from "../operations/audit/audit-merge.js";

export {
  AUDITED_RING_DEPOSIT_TAG,
  RING_DEPOSIT_AUDIT_SLOTS,
  RING_DEPOSIT_OPENING_LENGTH,
  RING_DEPOSIT_OPENING_OWNER_KEY_OFFSET,
  encodeRingDepositCapsule,
  readRingDepositCapsule,
  type RingDepositCapsule,
} from "../protocol/codec/deposit-capsule.js";
export {
  ringDepositSpp,
  type RingDepositSpp,
} from "../protocol/transaction/deposit-instruction.js";

export {
  LIST_IDS,
  ListId,
  POLICY_TABLE_VERSION,
  admitTransfer,
  buildRuleTable,
  checkedListId,
  decodeRule,
  decodeRuleTable,
  encodeRule,
  encodeRuleTable,
  listIdFromByte,
  listSet,
  listWriter,
  memberOfAsset,
  memberOfIdentity,
  memberOfTag,
  pinnedPolicy,
  policySourceOwners,
  policyTableFields,
  policyTableHash,
  policyTableProofInputs,
  recordBit,
  referencedLists,
  ruleAlternatives,
} from "../protocol/membership/policy.js";
export type {
  ListWriter,
  Member,
  OutflowLimit,
  OutputSubjects,
  PinnedPolicy,
  PolicySource,
  RecordLists,
  Rule,
  RuleAlternative,
  RuleGuard,
  RuleMode,
  RuleRefusal,
  RuleSource,
  RuleSubject,
  RuleTable,
  RuleTableInput,
  TransferSubject,
  TransferSubjects,
} from "../protocol/membership/policy.js";
