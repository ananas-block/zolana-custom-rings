//! Instruction builders, proofs and submission for the custom ring program, a blocking caller
//! wraps an operation in `zolana.block_on(op.prove(zolana.as_async()))`.

#[path = "state/account.rs"]
mod account;
#[path = "validation/address_ceiling.rs"]
mod address_ceiling;
#[path = "operations/admin.rs"]
mod admin;
#[path = "operations/buffered.rs"]
mod buffered;
#[path = "rpc/client.rs"]
mod client;
#[path = "validation/co_signer.rs"]
mod co_signer;
#[path = "operations/deposit.rs"]
mod deposit;
mod error;
#[path = "state/heap.rs"]
mod heap;
#[path = "validation/limits.rs"]
mod limits;
#[path = "operations/merge.rs"]
mod merge;
#[path = "operations/pipeline/mod.rs"]
mod pipeline;
#[path = "rpc/projection.rs"]
mod projection;
#[path = "rpc/prover.rs"]
mod prover;
#[path = "operations/records.rs"]
mod records;
#[path = "operations/register_key.rs"]
mod register_key;
#[path = "rpc/relay.rs"]
mod relay;
#[path = "validation/relay_message.rs"]
mod relay_message;
#[path = "codec/request.rs"]
mod request;
#[path = "operations/utxo_selection.rs"]
mod select;
#[path = "operations/storage.rs"]
mod storage;
#[path = "operations/submission.rs"]
mod submission;
#[cfg(test)]
mod tests;
#[path = "state/trees.rs"]
mod trees;

pub(crate) const REDACTED: &str = "<redacted>";

pub use custom_ring_interface::{
    compute_unit_limit, tag, CoSignScope, CustomRingProof, InstructionTag, ListRegistry, RingKind,
    RingMode,
};
pub use spr_program::instruction::{DepositAsset, DepositSplAccounts};

pub use crate::prover::secret_json_body;
pub use crate::{
    account::{
        CustomRing, CustomRingCoSigner, CustomRingConfig, PinnedPolicy, RingRegistration,
        RingStatus,
    },
    address_ceiling::{
        AddressCeiling, AddressCeilingError, CeilingDecision, MergeCapacity, MergeGroup, SpentInput,
    },
    admin::{
        ClearCoSigner, InitialPolicy, Initialize, PolicyTable, PolicyUpdate, SetCoSigner,
        SetDelegate, SourceOwner, UpdateAuthority, UpdatePolicy,
    },
    buffered::{close_frame_buffer, BufferedFrame},
    client::{RingClient, RingIndexerBackend},
    deposit::{
        fetch_asset_id_async, DepositRecipient, PreparedRingDeposit, RelayedDeposit, RingDeposit,
        RingDepositReceipt,
    },
    error::RingError,
    merge::{
        CustomRingMerge, CustomRingMergeInstruction, FittedMerge, MergeProofInput, MergeRelay,
        PreparedCustomRingMerge, ProvenCustomRingMerge, RingMergeOperation, MAX_RING_MERGE_INPUTS,
        MERGE_DEFAULT_INPUT_COUNT,
    },
    pipeline::{
        entry_shape_keyed, shape_keyed, transfer_key, Anonymous, AnonymousMove, AnonymousPayment,
        AnonymousTransfer, ApplicationData, CoOwner, CustomRingTransfer, CustomRingTransferInput,
        DelegateMove, DelegateOutput, DelegatePayment, DelegateTransfer, DelegateTransferInput,
        DelegateWithdrawal, Delegated, EntrySpend, NoteData, Owner, ProvenRingTransfer,
        PublicOwnerTransfer, PublicOwners, Rail, RailKind, Relayed, RelayedTransfer,
        RelayedTransferInput, RingPayment, RingSender, RingTransfer, TransferKey, WideFrames,
    },
    records::{
        AuthorityRecordUpdate, MemberRecords, OwnerSaltCheck, RecordUpdateService,
        RecordUpdateTarget, SaltedOwnerCheck, WalletRecordUpdate,
    },
    register_key::{Enroll, EnrollInstruction, WriteOwnerGrant},
    relay::{PendingSignature, PreparedAuthorityTransfer, PreparedRelay, RelaySent, RingRelay},
    relay_message::{MessageMismatch, RelayTransferTerms, TokenAccountCreate, VerifiedMessage},
    select::{select_merge_where, select_spend_where},
    storage::{
        tracking_apply_inputs, ApplyEnrollments, EnrollPending, InitializeStorage,
        StorageApplyProof, UpdateStorage, UpdateStorageAuthority,
    },
    submission::{
        live_registry, RingOperation, RingSubmission, SettledSubmission, SubmissionStatus,
    },
    trees::tree_id,
};
