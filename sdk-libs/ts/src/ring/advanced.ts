/** Circuit-facing codecs, registry proofs, and policy primitives. */
export {
  AUDIT_ENC_INFO,
  DELIVERED_BODY_ENC_INFO,
  DEPOSIT_ENC_INFO,
  auditSharedSecret,
  auditorMessageData,
  auditorViewTag,
  openAuditorRegions,
  packDisclosure,
  parseAuditorMessage,
  sealAuditorStream,
  symmetricAuditApply,
  unpackDisclosure,
} from "../crypto/audit/audit.js";
export type {
  AuditorEnvelope,
  AuditorMessage,
  AuditorRegion,
  StreamPosition,
} from "../crypto/audit/audit.js";
export {
  ANONYMOUS_RECORD_LEN,
  DELIVERED_AUDIT_CAPACITIES,
  DELIVERED_BODY_LEN,
  DISCLOSURE_CHUNK_BYTES,
  ENTRY_EVIDENCE_HEAD_LEN,
  ENTRY_INPUT_LEN,
  ENVELOPE_KEY_LEN,
  ESCROWED_DELIVERED_BODY_LEN,
  ESCROWED_EXIT_RECORD_LEN,
  EXIT_RECORD_LEN,
  INPUT_HASH_LEN,
  MERGE_WIDTHS,
  STREAM_BLOCK_LEN,
  STREAM_FIRST_COUNTER,
  auditLayoutValue,
  auditorMessageLen,
  checkedStreamLayout,
  ciphertextLen,
  transferAuditKey,
  deliveredBodyLen,
  envelopeRegion,
  evidenceBytes,
  exitRecordLen,
  firstRecordCounter,
  isExitSlot,
  maxEvidenceBlocks,
  packedChunks,
  recordBlocks,
  recordLen,
  recordRegion,
  recordSlots,
} from "../protocol/codec/ring-disclosure-layout.js";
export type {
  AuditKeySpend,
  AuditKey,
  AuditLayout,
  AuditStreamLayout,
  AuditStreamRegion,
} from "../protocol/codec/ring-disclosure-layout.js";
export {
  decodeDisclosure,
  disclosurePlaintext,
  openRingDisclosure,
  sealRingDisclosure,
} from "../crypto/audit/ring-disclosure.js";
export type {
  AnonymousInputOpening,
  AnonymousOutputOpening,
  InputCommitments,
  InputOpenings,
  DeliveredOutputOpening,
  DisclosurePlaintext,
  DummySlot,
  RingDisclosure,
} from "../crypto/audit/ring-disclosure.js";
export { deliveredSlotSecret, ringIdField } from "../crypto/derivation/ring-stream.js";
export type { DeliveredSlot } from "../crypto/derivation/ring-stream.js";
export {
  openDeliveredBody,
  recipientOutputBody,
  senderBundleOutputBody,
  RingScheme,
  sealDeliveredBody,
  type DeliveredBodyOpening,
} from "../protocol/transaction/output.js";
export {
  MIN_REPLY_LEN,
  RECIPIENT_BODY_LEN,
  openRecipientBody,
  openReply,
  openSenderBundle,
  replyLength,
  sealRecipientBody,
  sealReply,
  sealSenderBundle,
  senderBundleLen,
  type RecipientBody,
  type ReplyMetadata,
  type SenderBundle,
} from "../protocol/codec/anonymous-delivery.js";
export {
  ownerDebits,
  type DebitInput,
  type DebitOutput,
  type OwnerDebit,
} from "../protocol/membership/owner-debits.js";
export {
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  type AnonymousRecipientPlaintext,
  type AnonymousSenderPlaintext,
  type CommittedRecipientPlaintext,
  type CommittedSenderPlaintext,
  type UncommittedRecipientPlaintext,
  type UncommittedSenderPlaintext,
} from "../protocol/historical/anonymous-plaintext.js";
export {
  OutputBlindings,
  openRingDelivery,
  RING_DELIVERY_UNRESOLVED,
  ringBlindingSeed,
  ringOutputBlinding,
  type RingDeliveredNote,
  type RingDeliveryOpening,
  type RingDeliverySlot,
  type RingNoteOwner,
} from "../crypto/derivation/blinding.js";

export {
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  exitsBitmap,
  outputRecipientKeyFields,
  ringStreamLayout,
  ringRail,
  ringRailOf,
  ringSppInputs,
  outputOwnerTag,
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
  AnonymousProofData,
  InProofOwner,
  InputTrees,
  PolicyProof,
  PolicyRecipients,
  RingOutput,
  RingRail,
  RingTransactConfig,
  PublishedSenderBundle,
} from "../protocol/transaction/transact.js";
export {
  applyRecordsStatementElements,
  applyRecordsStatementHash,
  ciphertextDigest,
  outputCiphertextChain,
  registerKeyStatementElements,
  registerKeyStatementHash,
  ringTransferStatement,
  transferStatementElements,
  transferStatementHash,
} from "../protocol/proof/statement.js";
export type {
  ApplyRecordsStatement,
  AuditHead,
  RegisterKeyStatement,
  TransferBinding,
  TransferFamily,
  TransferRoots,
  TransferStatement,
} from "../protocol/proof/statement.js";
export { depositStatementElements } from "../proof/deposit-audit.js";
export type { DepositedAsset, DepositRegistry, DepositStatement } from "../proof/deposit-audit.js";
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
export { historyCursor, historyCursorToken, type HistoryStream } from "../rpc/history.js";
export { recoverMergeOpening, type MergeAuditorOpening } from "../operations/audit/audit-merge.js";

export {
  RING_DEPOSIT_AUDIT_SLOTS,
  RING_DEPOSIT_OPENING_LENGTH,
  RING_DEPOSIT_OPENING_OWNER_KEY_OFFSET,
  encodeRingDepositCapsule,
  readRingDepositCapsule,
  type RingDepositCapsule,
} from "../protocol/codec/deposit-capsule.js";
export {
  decodeStorageWrites,
  encodeStorageWrites,
  type StorageWrite,
} from "../protocol/codec/storage-writes.js";
export {
  ringDepositSpp,
  type RingDepositSpp,
} from "../protocol/transaction/deposit-instruction.js";

export {
  LIST_IDS,
  ListId,
  POLICY_LISTS,
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
  walletGrantMember,
} from "../protocol/membership/policy.js";
export {
  ENROLMENT_LISTS,
  recordUpdateQueueEntry,
  recordUpdateStatementHash,
  signRecordUpdate,
  verifyRecordUpdate,
} from "../protocol/ring-rpc/record-update.js";
export type { UnsignedRecordUpdate } from "../protocol/ring-rpc/record-update.js";
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

export {
  EMPTY_ASSET_LIMITS,
  EMPTY_MINT_POLICY,
  type AssetLimits,
  type MintPolicy,
} from "../protocol/membership/mint-policy.js";
export {
  historicalCoverageRow,
  openHistoricalMerge,
  openHistoricalRingTransfer,
  type HistoricalCoverageRow,
  type HistoricalInputOpening,
  type HistoricalTransfer,
  type HistoricalTransferInput,
} from "../protocol/historical/index.js";
