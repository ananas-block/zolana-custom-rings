/** Circuit-facing codecs, registry proofs, and policy primitives. */
export {
  AUDIT_ENC_INFO,
  DEPOSIT_ENC_INFO,
  auditSharedSecret,
  auditorMessageData,
  auditorViewTag,
  openAuditorRegions,
  packDisclosure,
  parseAuditorMessage,
  sealSaltedAuditorStream,
  symmetricAuditApply,
} from "../crypto/audit/audit.js";
export type {
  AuditorEnvelope,
  AuditorMessage,
  AuditorRegion,
  StreamPosition,
} from "../crypto/audit/audit.js";
export {
  AUDIT_RECORD_LEN,
  DATA_TAIL_LEN,
  DEFAULT_INPUT_BITS_LEN,
  DELIVERED_AUDIT_CAPACITIES,
  DISCLOSURE_CHUNK_BYTES,
  ENTRY_INPUT_LEN,
  ENVELOPE_KEY_LEN,
  OPENING_RECORD_LEN,
  REAL_INPUT_COUNT_LEN,
  RECORD_BLOCKS,
  STREAM_BLOCK_LEN,
  STREAM_FIRST_COUNTER,
  TAIL_BLOCKS,
  auditLayoutValue,
  auditorMessageLen,
  capacityBlocks,
  checkedStreamLayout,
  envelopeBlocks,
  envelopeRegion,
  firstRecordCounter,
  firstTailCounter,
  packedChunks,
  recordLen,
  recordRegion,
  recordsLen,
  tailLen,
  tailRegion,
  tailsLen,
} from "../protocol/codec/ring-disclosure-layout.js";
export type {
  AuditKey,
  AuditLayout,
  AuditStreamLayout,
  AuditStreamRegion,
} from "../protocol/codec/ring-disclosure-layout.js";
export {
  DUMMY_RECORD,
  EMPTY_ENTRY_INPUT,
  EMPTY_TAIL,
  RecordKind,
  decodeAuditEnvelope,
  decodeAuditRecord,
  decodeDataTail,
  decodeOpeningRecord,
  encodeAuditEnvelope,
  encodeAuditRecord,
  encodeDataTail,
  encodeOpeningRecord,
  isEmptyEntryInput,
} from "../protocol/codec/audit-stream.js";
export type {
  AuditEnvelope,
  AuditEvidence,
  AuditRecord,
  DataTail,
  EntryInput,
  OpeningRecord,
} from "../protocol/codec/audit-stream.js";
export {
  canonicalViewingKey,
  disclosurePlaintext,
  openRingDisclosure,
  sealRingDisclosure,
} from "../crypto/audit/ring-disclosure.js";
export type { PublishedAudit, RingDisclosure } from "../crypto/audit/ring-disclosure.js";
export { deliveredSlotSecret, ringIdField } from "../crypto/derivation/ring-stream.js";
export type { DeliveredSlot } from "../crypto/derivation/ring-stream.js";
export {
  encodeRingBodyOutput,
  ringBodyOutput,
  senderBundleOutputBody,
  RingScheme,
} from "../protocol/transaction/output.js";
export {
  MIN_REPLY_LEN,
  RECIPIENT_BODY_LEN,
  decodeRecipientBody,
  encodeRecipientBody,
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
  OutputBlindings,
  openRecipientNote,
  ringBlindingSeed,
  ringOutputBlinding,
  type OpenedRingNote,
  type RingNoteOwner,
  type RingOutputReader,
} from "../crypto/derivation/blinding.js";

export {
  ANONYMOUS_PARTIES,
  MAX_CO_SIGNERS,
  ApprovalMask,
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  bodilessBitmap,
  exitsBitmap,
  isAnonymousFrame,
  isDelegateRail,
  landedRingRail,
  ringStreamLayout,
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
  AnonymousProofData,
  AppMessage,
  FrameExtensions,
  InProofOwner,
  InputTrees,
  PolicyProof,
  Replies,
  RingOutput,
  RingRail,
  RingTransactConfig,
  PublishedSenderBundle,
  SlotBody,
} from "../protocol/transaction/transact.js";
export {
  applyRecordsStatementElements,
  applyRecordsStatementHash,
  ciphertextDigest,
  recordChain,
  registerKeyStatementElements,
  registerKeyStatementHash,
  ringTransferStatement,
  signerBinding,
  tailChain,
  transferStatementElements,
  transferStatementHash,
} from "../protocol/proof/statement.js";
export type {
  ApplyRecordsStatement,
  AuditHead,
  RegisterKeyStatement,
  SignerBinding,
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
  memberRecordHash,
  queueChain,
  queueEntryHash,
  quadPathRoot,
  replayRecordWrites,
  verifyRecordOpening,
} from "../protocol/membership/member-opening.js";
export { readRegisteredRecord, type RegisteredRecord } from "../rpc/registered-record.js";
export { historyCursor, historyCursorToken, type HistoryStream } from "../rpc/history.js";
export { recoverMergeOpening, type MergeAuditorOpening } from "../operations/audit/audit-merge.js";

export {
  RING_DEPOSIT_AUDIT_SLOTS,
  RING_DEPOSIT_OPENING_BLOCKS,
  RING_DEPOSIT_OPENING_LENGTH,
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
  closeFrameBufferData,
  FRAME_BUFFER_HEADER_LEN,
  FRAME_BUFFER_PDA_SEED,
  frameDigest,
  MAX_FRAME_LEN,
  settleBufferedData,
  settledFrame,
  writeFrameData,
  type WriteFrame,
} from "../protocol/transaction/frame-buffer.js";
