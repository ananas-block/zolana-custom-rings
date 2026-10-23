//! The custom ring auditor client, free of test utilities so the end-to-end test runs its path.

pub mod anonymous;
mod created;
mod decrypt;
pub mod delivered;
mod deposit;
mod deposit_payload;
mod disclosure;
mod encryption;
mod error;
mod indexer;
mod known;
mod merge_audit;
mod origin;
mod paging;
mod program_data;
mod reader;
pub mod records;
mod recover;
#[cfg(feature = "rpc")]
pub mod rpc;
mod scan;
pub mod tags;
mod types;

pub use crate::anonymous::{
    AnonymousRingScan, AnonymousRingState, AnonymousRingSync, AnonymousRingUtxo, AnonymousStream,
    DecoyLeaf, IssuedAddress, PairAnchor, PaymentStream, PaymentTag, ReceivedAnchor,
    SentFirstContact, TagAllocation, ADDRESS_GAP, ANCHOR_DECOYS, ANONYMOUS_RING_STATE_VERSION,
    DECOYS_PER_TREE, DEPOSIT_GAP, MAX_FETCH_EPOCHS, MAX_ISSUED_ADDRESSES, PAIR_IDLE_EPOCHS,
};
#[cfg(feature = "solana-rpc")]
pub use crate::origin::{confirmed_origin, ORIGIN_TRANSACTION_CONFIG};
pub use crate::tags::{IndexerReads, TagWindow, DEFAULT_TAG_WINDOW, TAGS_PER_REQUEST};
pub use crate::{
    created::{CreatedUtxoPage, CreatedUtxoScan, CreatedUtxos},
    decrypt::{EscrowedKeys, KnownUtxos, TransactionAudit},
    deposit::{ring_deposits_in, RingDeposit},
    deposit_payload::deposit_payload,
    disclosure::{
        AnonymousDisclosure, AnonymousInputOpening, AnonymousInputs, AnonymousOutputOpening,
        AuditDisclosure, AuditEnvelope, DeliveredOutputOpening, DisclosurePad, PackedOutputOpening,
        PublishedOutputs, SealedAuditEnvelope,
    },
    encryption::{
        auditor_view_tag, open_deposit, open_merge_disclosure, seal_deposits, DepositEncryption,
        DepositOpening, MergeDisclosureEncryption, MergeOpening, NullifierKeyEnvelope,
        SealedNullifierKey,
    },
    error::{AnonymousError, AuditError},
    indexer::{AsyncRingIndexer, RingIndexer, RingIndexerError},
    known::KnownUtxoIndex,
    merge_audit::{
        AuditedMerge, MergeAudit, MergeAuditPage, MergeAuditResult, MergeKeys, UnresolvedMerge,
    },
    origin::{
        ring_event_origin_in, ConfirmedDeposit, ConfirmedEvent, ConfirmedEventKind,
        ConfirmedMergeDisclosure, RingOrigin, RingWithdrawal, TransactionOrigin,
    },
    reader::{
        Ed25519ReaderKey, P256ReaderKey, ReaderKey, ReaderKeyError, READ_ACCESS_RECORD_PDA_SEED,
    },
    records::{apply_proof_inputs, member_record, quad_path, MemberOpeningRead, RegistryTip},
    recover::{MemberRecovery, RecoveredNotes, RingRecovery, SourceMember},
    scan::{AuditedPage, RingScan, RingScanPage, ScanPage},
    types::{
        AuditedInput, AuditedInputOpening, AuditedOutput, AuditedSender, AuditedTransaction,
        AuditedUtxo, CreatedUtxo, InputOpening, InputRing, KnownUtxo, OutputOpening,
        OutputPayloadError, OutputPayloadErrorKind, UtxoOwner,
    },
};
pub use program_data::{program_data, ProgramData, PROGRAM_DATA_METADATA_LEN};
pub use zolana_ring_indexer::rpc::RingRpcError;

/// The answer to a one-item request, a holder that answers more or less is refused.
pub fn exactly_one<T>(answers: Vec<T>) -> Result<T, zolana_transaction::TransactionError> {
    let got = answers.len();
    <[T; 1]>::try_from(answers)
        .map(|[answer]| answer)
        .map_err(|_| zolana_transaction::TransactionError::IncompleteDerivation { got, want: 1 })
}

/// One answer per request, a holder that answers more or less is refused.
pub(crate) fn exactly_one_each<T>(
    answers: Vec<T>,
    want: usize,
) -> Result<Vec<T>, zolana_transaction::TransactionError> {
    match answers.len() {
        got if got == want => Ok(answers),
        got => Err(zolana_transaction::TransactionError::IncompleteDerivation { got, want }),
    }
}
