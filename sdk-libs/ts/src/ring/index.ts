export type { ErrorEnvelope } from "@heliuslabs/zolana";
export {
  decodeRingDepositOutput,
  decodeRingDepositPlaintext,
  encodeRingDepositPlaintext,
} from "@heliuslabs/zolana/internal";
export type { RingDepositOutput, RingDepositPlaintext } from "@heliuslabs/zolana/internal";
export { ringTransactAccounts } from "@heliuslabs/zolana/interface";
export { RING_ERROR_CODES, RingError, RingProgramError, wrapRingError } from "../protocol/error.js";
export type { RingErrorCode, RingProgramErrorName } from "../protocol/error.js";

export {
  ringAuthAddress,
  ringConfigAddress,
  ringMemberRegistryAddress,
  ringRecordQueueAddress,
} from "../protocol/pda/index.js";
export {
  APPLY_DELAY_SLOTS,
  AUTHORITY_RESERVED_LEAVES,
  CUSTOM_RING_PROOF_LENGTH,
  DEFAULT_INSERT_FEE,
  GRACE_SLOTS,
  MEMBER_QUEUE_LIMIT,
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_SCOPE_MASK,
  RING_COSIGN_THRESHOLD_SLOTS,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  checkedCustomRingProof,
  decodeRingMemberRegistry,
  decodeRingProgramConfig,
  decodeRingRecordQueue,
  queueAdmitsMemberWrite,
  queueApplyDue,
  queueChainTail,
  queuePending,
  registryCurator,
  registryCuratorRoot,
  registryCurrentRoot,
  registryOwnRoot,
} from "../protocol/ring-codecs.js";
export type {
  RingCoSignThreshold,
  RingCoSigner,
  RingMemberRegistry,
  RingMode,
  RingProgramConfig,
  RingQueueCheckpoint,
  RingRecordQueue,
  RingRootEntry,
  RingSourceSlot,
} from "../protocol/ring-codecs.js";
export {
  BPF_LOADER_UPGRADEABLE_ID,
  fetchCuratorRegistry,
  fetchRingMemberRegistry,
  fetchRingProgramConfig,
  fetchRingRecordQueue,
  requireActiveRing,
  ringProgramDataAddress,
} from "../protocol/config.js";
export { ringRole, type RingRole } from "../protocol/role.js";
export { listRegisteredRings, type RegisteredRing } from "../rpc/ring-directory.js";
export { ringTreeIdResolver } from "../protocol/trees.js";

export {
  RingInstructionTag,
  clearRingCoSignerInstruction,
  createMemberRegistryInstruction,
  createRingConfigInstruction,
  createRingPolicyInstruction,
  initSppRingConfigInstruction,
  ringComputeUnitLimit,
  setRingAuthorityInstruction,
  setRingCoSignerInstruction,
  setRingDelegateInstruction,
  setRingInsertFeeInstruction,
  setRingPausedInstruction,
  setRingPolicyRulesInstruction,
  setRingPolicySourceInstruction,
} from "../operations/admin.js";
export type {
  RingKind,
  RingPolicySourceOwner,
  RingPolicyTableInput,
  RingSharedSource,
} from "../operations/admin.js";
export {
  buildRingCreatePolicyTransaction,
  buildRingSetPolicyRulesTransaction,
  buildRingSetPolicySourceTransaction,
} from "../operations/policy-admin.js";
export type {
  RingCreatePolicyTransactionParams,
  RingPolicyAdminClient,
  RingSetPolicyRulesTransactionParams,
  RingSetPolicySourceTransactionParams,
} from "../operations/policy-admin.js";
export {
  CLOCK_SYSVAR,
  RENT_SYSVAR,
  RingProgramBinary,
  closeBufferInstruction,
  decodeRingProgramData,
  deployRingProgram,
  deployWithMaxDataLenInstruction,
  extendProgramInstruction,
  fetchRingProgramData,
  initializeBufferInstruction,
  setUpgradeAuthorityInstruction,
  upgradeInstruction,
  verifyRingProgram,
  writeBufferInstruction,
} from "../protocol/program.js";
export type {
  RingProgramData,
  RingProgramDeployClient,
  RingProgramDeployOutcome,
  RingProgramDeployParams,
} from "../protocol/program.js";

export {
  AUTHORITY_WRITABLE_LISTS,
  AuthorityListWrite,
  MEMBER_WRITABLE_LISTS,
  RecordApplication,
  feeAccounts,
  listWrite,
  memberListWriteInstruction,
} from "../operations/record-writes.js";
export type {
  ListWrite,
  ProvenRecordWrite,
  RecordQueueBinding,
  RingRecordApplicationClient,
  RingRecordWriteClient,
} from "../operations/record-writes.js";
export { MemberOpeningRead } from "../protocol/member-opening.js";
export type { EscrowedRecord } from "../protocol/member-opening.js";
export { checkEscrowedRecipients, readMemberRecords } from "../rpc/registered-record.js";
export type { RingRecordReadClient } from "../rpc/registered-record.js";
export {
  NF_KEY_ENC_INFO,
  NullifierKeyEscrow,
  RegisterKey,
  fetchRingSealedKey,
  openNullifierKey,
  openRingSealedKey,
  sealNullifierKey,
} from "../operations/register-key.js";
export type {
  KeyEscrowAuthority,
  KeyEscrowRequest,
  NullifierKeyEnvelope,
  ProvenEscrow,
  ProvenKeyRegistration,
  RingKeyRegistrationClient,
  RingSealedKeyClient,
  RingSealedKeyEntry,
  SealedNullifierKey,
} from "../operations/register-key.js";

export {
  PreparedRingDeposit,
  RING_DEPOSIT_COMPUTE_UNIT_LIMIT,
  buildRingDepositTransaction,
} from "../operations/deposit.js";
export type {
  ProvenRingDeposit,
  RingDepositClient,
  RingDepositParams,
  RingDepositRecipient,
} from "../operations/deposit.js";
export { ringDepositInstruction } from "../protocol/deposit-instruction.js";
export { customRingDepositPayload, decryptRingDepositUtxo } from "../protocol/deposit-payload.js";
export {
  openRingDepositOpening,
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "../proof/deposit-audit.js";
export type { RingDepositOpening } from "../proof/deposit-audit.js";

export {
  ANCHOR_DECOYS,
  messageSignerSpendSigner,
  signingKeySpendSigner,
} from "../operations/anonymous.js";
export { ANONYMOUS_RING_STATE_VERSION, AnonymousRingState } from "../state/anonymous-state.js";
export type {
  DecoyLeaf,
  IndexedSpend,
  IssuedAddress,
  PairAnchor,
  ReceivedAnchor,
  SentFirstContact,
  SerializedAnonymousRingState,
} from "../state/anonymous-state.js";
export { issueRingAddress, ringAddressOf } from "../state/anonymous.js";
export { openRingNotes, syncRingWallet } from "../state/ring-sync.js";
export type { RingNotes, RingSyncClient } from "../state/ring-sync.js";
export { LocalRingKeys, isRingKeys, ringWalletKeys } from "../state/ring-keys.js";
export type { RingDeliveryRequest, RingKeys, RingRecipientKey } from "../state/ring-keys.js";
export { approveRingUnattended, ringIntentHash } from "../protocol/intent.js";
export type {
  RingAnonymousTransferIntent,
  RingApprovalHandler,
  RingApprovalRequest,
  RingTransactionIntent,
} from "../protocol/intent.js";
export type { AnonymousPayment, AnonymousSpendSigner } from "../operations/anonymous.js";
export {
  AnonymousTransfer,
  CustomRingTransfer,
  DelegateTransfer,
} from "../operations/transfer-rails.js";
export type {
  AnonymousTransferClient,
  CustomRingTransferClient,
  CustomRingTransferInput,
  DelegateOutput,
  DelegateTransferClient,
  DelegateTransferInput,
} from "../operations/transfer-rails.js";
export { ProvenRingTransfer, ringTransactInstruction } from "../operations/pipeline.js";
export type {
  PendingFirstContact,
  RingBoundState,
  RingProvingClient,
  RingTransactAccounts,
} from "../operations/pipeline.js";
export type { BoundPolicy, BoundRoot } from "../proof/policy-proof.js";
export type { BoundAnchor } from "../protocol/trees.js";
export {
  buildRingEntryTransaction,
  buildRingExitTransaction,
  buildRingTransferTransaction,
  buildRingWithdrawalTransaction,
  createRingExitSubmission,
  createRingTransferSubmission,
  createRingWithdrawalSubmission,
} from "../operations/transfer.js";
export type {
  AnonymousRingSpend,
  RingEntryTransactionParams,
  RingExitTransactionParams,
  RingSpendParams,
  RingTransferClient,
  RingTransferTransactionParams,
  RingWithdrawalTransactionParams,
} from "../operations/transfer.js";
export {
  buildRingDelegateRecoveredTransaction,
  buildRingDelegateTransferTransaction,
  createRingDelegateRecoveredSubmission,
  createRingDelegateSubmission,
} from "../operations/delegate.js";
export type {
  RingDelegateRecoveredClient,
  RingDelegateRecoveredParams,
  RingDelegateTransferClient,
  RingDelegateTransferParams,
} from "../operations/delegate.js";
export {
  MAX_RING_MERGE_INPUTS,
  RING_MERGE_COMPUTE_UNIT_LIMIT,
  buildRingMergeTransaction,
  createRingMergeSubmission,
  ringMergeInstruction,
} from "../operations/merge.js";
export type { RingMergeTransactionParams } from "../operations/merge.js";
export type { RingMergeClient } from "../rpc/ports.js";
export {
  RingTransactionSubmission,
  createKitRingSubmissionTransport,
  reconcileRingSubmissions,
} from "../operations/submission.js";
export type {
  ReservationHold,
  RingSubmissionAttempt,
  RingSubmissionBuild,
  RingSubmissionResult,
} from "../operations/submission.js";

export {
  KnownUtxoIndex,
  auditRing,
  auditRingTransaction,
  auditedUtxos,
  auditorMessage,
  hasUnknownAssets,
  knownUtxoHash,
  openedUtxo,
  recoverTransactionViewingKey,
} from "../operations/audit.js";
export { inputPrefix } from "../crypto/ring-disclosure.js";
export type { InputPrefix } from "../crypto/ring-disclosure.js";
export type {
  AuditedInput,
  AuditedInputOpening,
  AuditedRingOutput,
  AuditedRingTransaction,
  AuditedSender,
  AuditedUtxo,
  CreatedRingUtxo,
  EscrowedKeys,
  InputOpening,
  InputRing,
  KnownUtxo,
  KnownUtxos,
  OutputOpening,
  OutputPayloadError,
  OutputPayloadErrorKind,
  RingAuditPage,
  RingAuditReader,
  UtxoOwner,
} from "../operations/audit.js";
export { auditRingMerges } from "../operations/audit-merge.js";
export { createdRingUtxos, scanCreatedRingUtxos } from "../operations/created-utxos.js";
export type { CreatedRingUtxosPage } from "../operations/created-utxos.js";
export type {
  AuditedRingMerge,
  MergeKeys,
  RingMergeAuditPage,
  RingMergeAuditReader,
  UnresolvedRingMerge,
} from "../operations/audit-merge.js";
export {
  mergeDisclosureFieldCount,
  openRingMergeDisclosure,
  ringMergeAnonymousPublicInputHash,
} from "../crypto/merge-disclosure.js";
export type { RingMergeDisclosure, RingMergeOpening } from "../crypto/merge-disclosure.js";
export { recoverRingMemberNotes } from "../operations/recover.js";
export type {
  RecoveredRingNotes,
  RingRecoveryClient,
  RingRecoveryParams,
} from "../operations/recover.js";
export {
  ConfirmedDeposit,
  ORIGIN_TRANSACTION_CONFIG,
  RpcTransactionOrigin,
  confirmedInstructionGroups,
  confirmedRingWithdrawals,
  ringInstructionsIn,
  ringInvokedIn,
  ringWithdrawalsOf,
  senderOf,
} from "../protocol/origin.js";
export type {
  ConfirmedEventKind,
  ConfirmedRingTransaction,
  OriginInstruction,
  OriginInstructionGroup,
  RingWithdrawal,
  TransactionOrigin,
} from "../protocol/origin.js";
export {
  RING_AUDITED_UTXOS_LIMIT,
  RING_PAYLOAD_ERROR_KINDS,
  RING_READ_CURSOR_LIMIT,
  RING_READ_PAGE_LIMIT,
  RingAuditedUtxosRequest,
  RingAuditorKeyRequest,
  RingReadRequest,
  RingRpc,
  auditedUtxosAttestation,
  auditorKeyStatement,
  auditorKeyRequestAttestation,
  messageSignerReader,
  ringReadAttestation,
} from "../rpc/ring-rpc.js";
export type {
  AuditedMergesPage,
  DecryptedOutputContext,
  DecryptedRingOutput,
  DecryptedRingTransaction,
  DecryptedRingTransactionsPage,
  DecryptedRingWithdrawal,
  RingActivation,
  RingAuditedUtxo,
  RingAuditedUtxosPage,
  RingAuditorKey,
  RingDeposit,
  RingDepositsPage,
  RingKeyMode,
  RingPagedRead,
  RingReadSigner,
  RingReadTarget,
  RingRegistryStatus,
  RingRpcHealth,
  RingRpcOptions,
  RingState,
  RingStatus,
  SignedAuditedUtxosRead,
  SignedAuditorKeyRequest,
  SignedRingRead,
  SkippedReason,
  SkippedRingTransaction,
  WebAuthnSignature,
} from "../rpc/ring-rpc.js";
export {
  P256ReaderKey,
  checkedReaderKey,
  decodeReadAccessRecord,
  fetchReaderGrant,
  grantReadAccessInstruction,
  parseReaderKey,
  readAccessRecordAddress,
  readerKeyBytes,
  readerKeyEquals,
  readerKeyFromBytes,
  readerKeyToString,
  revokeReadAccessInstruction,
} from "../operations/reader-access.js";
export type { ReadAccessRecord, ReaderKey } from "../operations/reader-access.js";
export { createPasskey, passkeyReader, type Passkey } from "../crypto/passkey.js";
