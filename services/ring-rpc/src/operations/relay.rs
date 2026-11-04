use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use custom_ring_interface::{
    storage_instruction, tracking::TrackingAuthorization, STORAGE_PROGRAM_ID,
};
use custom_ring_sdk::RingError;
use jsonrpsee::types::ErrorObjectOwned;
use log::warn;
use sea_orm::{
    sqlx::error::{Error as SqlxError, ErrorKind},
    DatabaseConnection, DbErr, RuntimeErr, TransactionTrait,
};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{compile_message, ComputeBudgetConfig};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, RelayDepositInputs,
    RelayEnrollInputs, RelayId, RelayIntent, RelayMergeInputs, RelayProofInputs,
    RelayProofInputsError, RelayQuote, RelayStatus, RelayStep, SubmitRelayRequest,
    TokenAccountSetupError,
};
use zolana_ring_policy::Member;

use crate::{
    cosign::{
        AssetFlow, CoSignDecision, CoSignFlows, CoSignPolicy, CoSignRefusal, CoSignRequest,
        CoSignSettlement, OwnerFlow, RefusingCoSigner,
    },
    database::Store,
    error::{redacted, RingRpcError},
    landing::{Attempt, ChainOutcome, ChainSubmit, Landing, LatestBlockhash},
    merge_inputs::{HoldInputs, MergeInputs},
    relay_prover::{DelegateSeal, ProvenRelay, RelayParties, RelayProofRequest, RelayProver},
    relay_submit::{presigned_transaction, CollectedSignature},
    relays::{PendingCoSign, RelayRecord, RelayState, RelayStore},
};

/// Longest quote window, one blockhash lifetime.
pub const QUOTE_SLOTS: u64 = 150;
pub const RELAY_TRACK_INTERVAL: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_PROOFS: usize = 4;
const EXPIRED: &str = "the relay message expired before it landed";
const MANAGED_MERGE_DOMAIN: &[u8] = b"zolana/ring-rpc-managed-merge/v1";
/// Modelled, the first enrollment verifies a proof in its instruction.
const ENROLL_COMPUTE_UNITS: u32 = 400_000;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("the ring is not relayed here")]
    RingNotServed,
    #[error("the quote names another fee payer")]
    QuoteFeePayer,
    #[error("the quote expired")]
    QuoteExpired,
    #[error("the quote outlasts the relay window")]
    QuoteWindow,
    #[error("the proof inputs are invalid because {0}")]
    ProofInputs(#[from] RelayProofInputsError),
    #[error("the proof inputs name another ring")]
    RingMismatch,
    #[error("the proof inputs name another rail")]
    RailMismatch,
    #[error("the owner signature does not sign the proof inputs")]
    OwnerSignature,
    #[error("the transfer is refused because {0}")]
    Proof(String),
    #[error("the co-signer refused the transfer")]
    CoSignRefused,
    #[error("the relay is unknown")]
    UnknownRelay,
    #[error("the relay message awaits no signature from the signer")]
    UnexpectedSigner,
    #[error("the signature does not sign the relay message")]
    SignerSignature,
    #[error("the cluster refused the transaction because {reason}")]
    SendRefused { reason: String },
    #[error(transparent)]
    TokenAccountSetup(#[from] TokenAccountSetupError),
    #[error("the depositor is the relay fee payer")]
    DepositorIsFeePayer,
    #[error("the enrollment is no tag 6 of a ring's tracking registry under its own owner")]
    InvalidEnrollment,
}

pub enum RelayPayload {
    Transfer(RelayProofInputs),
    Deposit(RelayDepositInputs),
    Merge(RelayMergeInputs),
    Enroll(RelayEnrollInputs),
}

/// Admits a ring only while its config names an auditor key the service holds.
#[async_trait]
pub trait ServedRings: Send + Sync {
    async fn check(&self, ring: Address) -> Result<(), RingRpcError>;

    /// The tracking registry the ring pins, the relay pays for no other enrollment.
    async fn tracking_registry(&self, ring: Address) -> Result<Address, RingRpcError>;
}

struct NoRings;

#[must_use]
pub struct RelayParts {
    pub store: Store,
    pub prover: Arc<dyn RelayProver>,
    /// The SPP payer every relayed message names.
    pub fee_payer: Keypair,
    pub chain: Arc<dyn ChainSubmit>,
}

/// One stored record per `relayId`.
pub struct Relay {
    store: Store,
    prover: Arc<dyn RelayProver>,
    fee_payer: Keypair,
    chain: Arc<dyn ChainSubmit>,
    rings: Arc<dyn ServedRings>,
    co_signer: Arc<dyn CoSignPolicy>,
    proofs: Semaphore,
    /// Every record write after the proofs, one relay state at a time.
    transitions: Mutex<()>,
}

/// Every signature except the fee payer's is collected.
#[must_use]
pub(crate) struct HeldMerge {
    pub ring: Address,
    pub message: VersionedMessage,
    pub last_valid_block_height: u64,
    pub co_signature: Option<CollectedSignature>,
    pub nullifiers: Vec<[u8; 32]>,
}

#[must_use]
struct PrepareCheck<'a> {
    request: &'a PrepareRelayRequest,
    payload: &'a RelayPayload,
    fee_payer: Address,
    slot: u64,
}

struct Checked {
    owner_signature: Option<[u8; 64]>,
    setup: Vec<Instruction>,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationAfterWrite {
    Keep,
    Free(Signature),
}

enum WriteError {
    /// The commit was never sent.
    Uncommitted(DbErr),
    /// The write may have committed unless the store refused it.
    Committing(DbErr),
}

enum UnstoredWrite<'a> {
    /// Another record holds the relay id.
    Existing,
    Failed(&'a WriteError),
}

#[must_use]
struct FailedWrite<'a> {
    write: UnstoredWrite<'a>,
    co_signature: Option<Signature>,
    stored: Result<Option<&'a RelayRecord>, &'a DbErr>,
}

impl RelayError {
    pub const fn code(&self) -> i32 {
        match self {
            Self::RingNotServed => -32100,
            Self::QuoteFeePayer => -32101,
            Self::QuoteExpired => -32102,
            Self::QuoteWindow => -32103,
            Self::ProofInputs(_) => -32104,
            Self::RingMismatch => -32105,
            Self::RailMismatch => -32106,
            Self::OwnerSignature => -32107,
            Self::Proof(_) => -32108,
            Self::CoSignRefused => -32109,
            Self::UnknownRelay => -32110,
            Self::UnexpectedSigner => -32111,
            Self::SignerSignature => -32112,
            Self::SendRefused { .. } => -32113,
            Self::TokenAccountSetup(_) => -32200,
            Self::DepositorIsFeePayer => -32201,
            Self::InvalidEnrollment => -32202,
        }
    }

    /// A refused transfer is the caller's, an unreachable chain or prover is the service's.
    pub(crate) fn proof(error: RingError) -> RingRpcError {
        match error {
            RingError::Client(error) => RingRpcError::Upstream(error),
            RingError::Indexer(refused) => RingRpcError::Refused(refused),
            refused => Self::Proof(refused.to_string()).into(),
        }
    }
}

impl From<&RelayError> for ErrorObjectOwned {
    fn from(error: &RelayError) -> Self {
        Self::owned(error.code(), error.to_string(), None::<()>)
    }
}

#[async_trait]
impl ServedRings for NoRings {
    async fn check(&self, _ring: Address) -> Result<(), RingRpcError> {
        Err(RelayError::RingNotServed.into())
    }

    async fn tracking_registry(&self, _ring: Address) -> Result<Address, RingRpcError> {
        Err(RelayError::RingNotServed.into())
    }
}

impl Relay {
    pub fn new(parts: RelayParts) -> Self {
        Self {
            store: parts.store,
            prover: parts.prover,
            fee_payer: parts.fee_payer,
            chain: parts.chain,
            rings: Arc::new(NoRings),
            co_signer: Arc::new(RefusingCoSigner),
            proofs: Semaphore::new(MAX_CONCURRENT_PROOFS),
            transitions: Mutex::new(()),
        }
    }

    #[must_use = "use the updated relay"]
    pub fn with_co_signer(mut self, co_signer: Arc<dyn CoSignPolicy>) -> Self {
        self.co_signer = co_signer;
        self
    }

    /// Without it the relay refuses every ring.
    #[must_use = "use the updated relay"]
    pub fn with_rings(mut self, rings: Arc<dyn ServedRings>) -> Self {
        self.rings = rings;
        self
    }

    pub fn fee_payer(&self) -> Address {
        self.fee_payer.pubkey()
    }

    fn parties(&self) -> RelayParties {
        RelayParties {
            fee_payer: self.fee_payer(),
            co_signer: self.co_signer.signer(),
        }
    }

    pub async fn quote(&self, request: &GetRelayQuoteRequest) -> Result<RelayQuote, RingRpcError> {
        self.rings.check(request.ring.0).await?;
        Ok(RelayQuote {
            fee_payer: self.fee_payer().into(),
            valid_until_slot: self.chain.slot().await? + QUOTE_SLOTS,
        })
    }

    /// A repeated request returns the stored relay, it proves nothing again.
    pub async fn prepare(&self, request: &PrepareRelayRequest) -> Result<RelayStep, RingRpcError> {
        let relay_id = request
            .relay_id()
            .map_err(|_| RingRpcError::StateUnavailable)?;
        if let Some(step) = self.stored(&relay_id).await? {
            return Ok(step);
        }
        let ring = request.ring.0;
        self.rings.check(ring).await?;
        let payload = RelayPayload::decode(&request.intent).map_err(RelayError::from)?;
        if let RelayPayload::Enroll(enrollment) = &payload {
            if enrollment.tracking_registry != self.rings.tracking_registry(ring).await? {
                return Err(RelayError::InvalidEnrollment.into());
            }
        }
        let parties = self.parties();
        let Checked {
            owner_signature,
            setup,
        } = PrepareCheck {
            request,
            payload: &payload,
            fee_payer: parties.fee_payer,
            slot: self.chain.slot().await?,
        }
        .check()?;
        let proven = match &payload {
            // The wallet proved its seal, the relay only pays.
            RelayPayload::Enroll(enrollment) => enrollment_step(enrollment, parties.fee_payer),
            _ => {
                let _proof = self
                    .proofs
                    .try_acquire()
                    .map_err(|_| RingRpcError::RelayProverBusy)?;
                self.prover
                    .prove(RelayProofRequest {
                        ring,
                        parties,
                        payload: &payload,
                        owner_signature,
                    })
                    .await?
            }
        };
        self.stage(ProvenStep {
            relay_id,
            payload,
            setup,
            proven,
        })
        .await
    }

    pub(crate) async fn stored(
        &self,
        relay_id: &RelayId,
    ) -> Result<Option<RelayStep>, RingRpcError> {
        Ok(self
            .relays()
            .get(relay_id)
            .await?
            .map(|record| step(relay_id.clone(), &record)))
    }

    /// The source signs nothing, the delegate signs the returned message.
    pub(crate) async fn prepare_delegated(
        &self,
        relay_id: RelayId,
        seal: DelegateSeal<'_>,
    ) -> Result<RelayStep, RingRpcError> {
        let ring = seal.ring;
        self.rings.check(ring).await?;
        let parties = self.parties();
        let (payload, proven) = {
            let _proof = self
                .proofs
                .try_acquire()
                .map_err(|_| RingRpcError::RelayProverBusy)?;
            let payload = RelayPayload::Transfer(self.prover.seal_delegate(seal, parties).await?);
            let proven = self
                .prover
                .prove(RelayProofRequest {
                    ring,
                    parties,
                    payload: &payload,
                    owner_signature: None,
                })
                .await?;
            (payload, proven)
        };
        self.stage(ProvenStep {
            relay_id,
            payload,
            setup: Vec::new(),
            proven,
        })
        .await
    }

    /// A relay awaiting no signer is co-signed before the record lands.
    async fn stage(&self, proven: ProvenStep) -> Result<RelayStep, RingRpcError> {
        let ProvenStep {
            relay_id,
            payload,
            mut setup,
            proven,
        } = proven;
        let fee_payer = self.fee_payer();
        let LatestBlockhash {
            blockhash,
            last_valid_block_height,
        } = self.chain.latest_blockhash().await?;
        setup.push(proven.instruction.clone());
        let message = compile_message(&fee_payer, &setup, blockhash, proven.budget)?;
        let awaited = CoSignStep {
            payload: &payload,
            proven,
        }
        .plan(self.co_signer.as_ref())?;
        // The decoded secrets zeroize before the store and send awaits.
        drop(payload);
        let mut record = RelayRecord {
            message,
            signatures: Vec::new(),
            co_signature: None,
            state: RelayState::AwaitingSignature,
            awaiting: awaited.signers,
            co_sign: awaited.co_sign,
            last_valid_block_height,
        };
        self.sign_when_complete(&mut record).await?;
        let _transition = self.transitions.lock().await;
        let inserted = self
            .relays()
            .insert(&relay_id, &record)
            .await
            .map_err(WriteError::Committing);
        let write = match &inserted {
            Ok(true) => None,
            Ok(false) => Some(UnstoredWrite::Existing),
            Err(error) => Some(UnstoredWrite::Failed(error)),
        };
        if let Some(write) = write {
            let stored = self.relays().get(&relay_id).await;
            self.free_unless_stored(FailedWrite {
                write,
                co_signature: record.co_signature,
                stored: stored.as_ref().map(Option::as_ref),
            })
            .await?;
            inserted?;
            return Ok(step(
                relay_id,
                &stored?.ok_or(RingRpcError::StateUnavailable)?,
            ));
        }
        self.first_send(&relay_id, &mut record).await?;
        Ok(step(relay_id, &record))
    }

    /// The record and its held inputs commit together before the send.
    pub(crate) async fn send_merge(&self, merge: HeldMerge) -> Result<RelayId, RingRpcError> {
        let relay_id = RelayId(
            <[u8; 32]>::from(
                Sha256::new()
                    .chain_update(MANAGED_MERGE_DOMAIN)
                    .chain_update(merge.message.serialize())
                    .finalize(),
            )
            .into(),
        );
        let mut record = RelayRecord {
            message: merge.message,
            signatures: merge.co_signature.into_iter().collect(),
            awaiting: Vec::new(),
            co_sign: None,
            co_signature: merge.co_signature.map(|collected| collected.signature),
            last_valid_block_height: merge.last_valid_block_height,
            state: RelayState::AwaitingSignature,
        };
        self.sign_when_complete(&mut record).await?;
        let _transition = self.transitions.lock().await;
        let hold = HoldInputs {
            ring: &merge.ring,
            relay_id: &relay_id,
            nullifiers: &merge.nullifiers,
        };
        match self.store_merge(&record, hold).await {
            Ok(true) => {}
            // The stored relay keeps the co-signer reservation.
            Ok(false) => return Ok(relay_id),
            Err(error) => {
                let stored = self.relays().get(&relay_id).await;
                self.free_unless_stored(FailedWrite {
                    write: UnstoredWrite::Failed(&error),
                    co_signature: record.co_signature,
                    stored: stored.as_ref().map(Option::as_ref),
                })
                .await?;
                return Err(error.into());
            }
        }
        self.first_send(&relay_id, &mut record).await?;
        Ok(relay_id)
    }

    /// `false` when the relay is stored already.
    async fn store_merge(
        &self,
        record: &RelayRecord,
        hold: HoldInputs<'_>,
    ) -> Result<bool, WriteError> {
        let transaction = self
            .store
            .connection()
            .begin()
            .await
            .map_err(WriteError::Uncommitted)?;
        let staged = async {
            if !RelayStore::new(&transaction)
                .insert(hold.relay_id, record)
                .await?
            {
                return Ok(false);
            }
            MergeInputs { conn: &transaction }.hold(hold).await?;
            Ok(true)
        }
        .await
        .map_err(WriteError::Uncommitted)?;
        if staged {
            transaction.commit().await.map_err(WriteError::Committing)?;
        }
        Ok(staged)
    }

    pub(crate) fn merge_inputs(&self) -> MergeInputs<'_, DatabaseConnection> {
        MergeInputs {
            conn: self.store.connection(),
        }
    }

    /// A signature already collected leaves the relay as it is.
    pub async fn submit(&self, request: &SubmitRelayRequest) -> Result<RelayStatus, RingRpcError> {
        let _transition = self.transitions.lock().await;
        let mut record = self.record(&request.relay_id).await?;
        let (signer, signature) = (request.signer.0, request.signature.0);
        if record.state == RelayState::AwaitingSignature
            && !record
                .signatures
                .iter()
                .any(|collected| collected.signer == signer)
        {
            let index = record
                .awaiting
                .iter()
                .position(|awaited| *awaited == signer)
                .ok_or(RelayError::UnexpectedSigner)?;
            if !signature.verify(signer.as_ref(), &record.message.serialize()) {
                return Err(RelayError::SignerSignature.into());
            }
            record.awaiting.remove(index);
            record
                .signatures
                .push(CollectedSignature { signer, signature });
            self.sign_when_complete(&mut record).await?;
            if let Err(error) = self.relays().update(&request.relay_id, &record).await {
                let error = WriteError::Committing(error);
                let stored = self.relays().get(&request.relay_id).await;
                self.free_unless_stored(FailedWrite {
                    write: UnstoredWrite::Failed(&error),
                    co_signature: record.co_signature,
                    stored: stored.as_ref().map(Option::as_ref),
                })
                .await?;
                return Err(error.into());
            }
            self.first_send(&request.relay_id, &mut record).await?;
        }
        self.advance(&request.relay_id, &mut record).await?;
        Ok(relay_status(&record.state))
    }

    pub async fn status(
        &self,
        request: &GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingRpcError> {
        let _transition = self.transitions.lock().await;
        let mut record = self.record(&request.relay_id).await?;
        self.advance(&request.relay_id, &mut record).await?;
        Ok(relay_status(&record.state))
    }

    /// A restart resumes every relay it left pending.
    pub async fn run(self: Arc<Self>, interval: Duration) {
        loop {
            if let Err(error) = self.track().await {
                warn!("relay tracking failed {}", redacted(&error));
            }
            tokio::time::sleep(interval).await;
        }
    }

    pub(crate) async fn track(&self) -> Result<(), RingRpcError> {
        for relay_id in self.relays().pending().await? {
            let _transition = self.transitions.lock().await;
            let tracked = async {
                let mut record = self.record(&relay_id).await?;
                self.advance(&relay_id, &mut record).await?;
                self.resend(&record).await
            }
            .await;
            if let Err(error) = tracked {
                warn!("relay {} did not advance {}", relay_id.0, redacted(&error));
            }
        }
        Ok(())
    }

    /// Runs once every other signer signed, a refusal stores nothing.
    async fn co_sign(&self, record: &mut RelayRecord) -> Result<(), RingRpcError> {
        if let Some(pending) = record.co_sign.take() {
            let request = CoSignRequest {
                ring: pending.ring,
                message: record.message.clone(),
                flows: pending.flows,
            };
            match self.co_signer.decide(&request).await? {
                CoSignDecision::Signed(signature) => {
                    record.signatures.push(CollectedSignature {
                        signer: pending.signer,
                        signature,
                    });
                    record.co_signature = Some(signature);
                }
                CoSignDecision::Refused(
                    CoSignRefusal::Disabled | CoSignRefusal::OverLimit | CoSignRefusal::NotApproved,
                ) => return Err(RelayError::CoSignRefused.into()),
            }
        }
        Ok(())
    }

    fn relays(&self) -> RelayStore<'_, DatabaseConnection> {
        RelayStore::new(self.store.connection())
    }

    async fn record(&self, relay_id: &RelayId) -> Result<RelayRecord, RingRpcError> {
        self.relays()
            .get(relay_id)
            .await?
            .ok_or_else(|| RelayError::UnknownRelay.into())
    }

    /// The fee payer signs only after the co-sign decision, every later send repeats its signature.
    async fn sign_when_complete(&self, record: &mut RelayRecord) -> Result<(), RingRpcError> {
        if record.state != RelayState::AwaitingSignature || !record.awaiting.is_empty() {
            return Ok(());
        }
        self.co_sign(record).await?;
        let signature = self.fee_payer.sign_message(&record.message.serialize());
        record.signatures.push(CollectedSignature {
            signer: self.fee_payer(),
            signature,
        });
        record.state = RelayState::Sent {
            signature: signature.into(),
        };
        Ok(())
    }

    /// A refused preflight forwards nothing and ends the relay.
    async fn first_send(
        &self,
        relay_id: &RelayId,
        record: &mut RelayRecord,
    ) -> Result<(), RingRpcError> {
        if !matches!(record.state, RelayState::Sent { .. }) {
            return Ok(());
        }
        let transaction = presigned_transaction(&record.message, &record.signatures)?;
        match self.chain.send(&transaction).await {
            Err(RingRpcError::Relay(RelayError::SendRefused { reason })) => {
                record.state = RelayState::Failed { reason };
                self.close(relay_id, record).await
            }
            sent => sent,
        }
    }

    /// A refusal leaves the relay open, an earlier send can still land.
    async fn resend(&self, record: &RelayRecord) -> Result<(), RingRpcError> {
        match record.state {
            RelayState::Sent { .. } => {
                let transaction = presigned_transaction(&record.message, &record.signatures)?;
                self.chain.send(&transaction).await
            }
            _ => Ok(()),
        }
    }

    async fn advance(
        &self,
        relay_id: &RelayId,
        record: &mut RelayRecord,
    ) -> Result<(), RingRpcError> {
        let last_valid_block_height = record.last_valid_block_height;
        record.state = match record.state.clone() {
            RelayState::AwaitingSignature
                if self.chain.block_height().await? > last_valid_block_height =>
            {
                RelayState::Failed {
                    reason: EXPIRED.to_owned(),
                }
            }
            RelayState::Sent { signature } => {
                let attempt = Attempt {
                    signature: signature.0,
                    last_valid_block_height,
                };
                match attempt.landing(self.chain.as_ref()).await? {
                    Landing::Pending => return Ok(()),
                    Landing::Landed(ChainOutcome::Confirmed { slot }) => {
                        RelayState::Confirmed { signature, slot }
                    }
                    Landing::Landed(ChainOutcome::Failed { reason }) => {
                        RelayState::Failed { reason }
                    }
                    Landing::Expired => RelayState::Failed {
                        reason: EXPIRED.to_owned(),
                    },
                }
            }
            RelayState::Failed { .. } => {
                return self
                    .settle(record.co_signature, CoSignSettlement::Failed)
                    .await;
            }
            RelayState::AwaitingSignature | RelayState::Confirmed { .. } => return Ok(()),
        };
        self.close(relay_id, record).await
    }

    /// A freed row must never outlive a stored `Sent`, a resend that landed would escape the cap.
    async fn close(&self, relay_id: &RelayId, record: &RelayRecord) -> Result<(), RingRpcError> {
        match record.state {
            RelayState::Confirmed { .. } => {
                self.settle(record.co_signature, CoSignSettlement::Confirmed)
                    .await?;
                Ok(self.relays().update(relay_id, record).await?)
            }
            _ => {
                self.relays().update(relay_id, record).await?;
                self.settle(record.co_signature, CoSignSettlement::Failed)
                    .await
            }
        }
    }

    async fn free_unless_stored(&self, failed: FailedWrite<'_>) -> Result<(), RingRpcError> {
        match failed.reservation() {
            ReservationAfterWrite::Free(co_signature) => {
                self.co_signer
                    .settle(CoSignSettlement::Failed(co_signature))
                    .await
            }
            ReservationAfterWrite::Keep => Ok(()),
        }
    }

    async fn settle(
        &self,
        co_signature: Option<Signature>,
        settlement: fn(Signature) -> CoSignSettlement,
    ) -> Result<(), RingRpcError> {
        match co_signature {
            Some(signature) => self.co_signer.settle(settlement(signature)).await,
            None => Ok(()),
        }
    }
}

struct ProvenStep {
    relay_id: RelayId,
    payload: RelayPayload,
    setup: Vec<Instruction>,
    proven: ProvenRelay,
}

struct CoSignStep<'a> {
    payload: &'a RelayPayload,
    proven: ProvenRelay,
}

struct Awaited {
    co_sign: Option<PendingCoSign>,
    signers: Vec<Address>,
}

impl CoSignStep<'_> {
    fn plan(self, co_signer: &dyn CoSignPolicy) -> Result<Awaited, RingRpcError> {
        let Self { payload, proven } = self;
        let Some(named) = proven.co_signer else {
            return Ok(Awaited {
                co_sign: None,
                signers: proven.signers,
            });
        };
        let signer = co_signer
            .signer_named(named)
            .ok_or(RelayError::CoSignRefused)?;
        Ok(Awaited {
            co_sign: Some(PendingCoSign {
                signer,
                ring: payload.ring_program_id(),
                flows: payload.flows()?,
            }),
            signers: proven.signers,
        })
    }
}

impl FailedWrite<'_> {
    /// An unknown commit outcome or an unreadable store keeps the reservation, a stored relay can still land.
    fn reservation(self) -> ReservationAfterWrite {
        let Some(co_signature) = self.co_signature else {
            return ReservationAfterWrite::Keep;
        };
        if let UnstoredWrite::Failed(WriteError::Committing(error)) = self.write {
            if !refused(error) {
                return ReservationAfterWrite::Keep;
            }
        }
        match self.stored {
            Ok(Some(record)) if record.co_signature == Some(co_signature) => {
                ReservationAfterWrite::Keep
            }
            Ok(_) => ReservationAfterWrite::Free(co_signature),
            Err(_) => ReservationAfterWrite::Keep,
        }
    }
}

impl From<WriteError> for RingRpcError {
    fn from(error: WriteError) -> Self {
        match error {
            WriteError::Uncommitted(error) | WriteError::Committing(error) => error.into(),
        }
    }
}

impl PrepareCheck<'_> {
    fn check(self) -> Result<Checked, RingRpcError> {
        let Self {
            request,
            payload,
            fee_payer,
            slot,
        } = self;
        let quote = &request.quote;
        if quote.fee_payer.0 != fee_payer {
            return Err(RelayError::QuoteFeePayer.into());
        }
        if quote.valid_until_slot < slot {
            return Err(RelayError::QuoteExpired.into());
        }
        if quote.valid_until_slot > slot.saturating_add(QUOTE_SLOTS) {
            return Err(RelayError::QuoteWindow.into());
        }
        if payload.ring_program_id() != request.ring.0 {
            return Err(RelayError::RingMismatch.into());
        }
        let unsigned = Checked {
            owner_signature: None,
            setup: Vec::new(),
        };
        let proof_inputs = match payload {
            RelayPayload::Transfer(proof_inputs) => proof_inputs,
            RelayPayload::Deposit(deposit) if deposit.depositor == fee_payer => {
                return Err(RelayError::DepositorIsFeePayer.into())
            }
            RelayPayload::Deposit(_) | RelayPayload::Merge(_) => return Ok(unsigned),
            RelayPayload::Enroll(enrollment) => {
                check_enrollment(enrollment, fee_payer)?;
                return Ok(unsigned);
            }
        };
        if proof_inputs.rail.operation() != request.intent.operation() {
            return Err(RelayError::RailMismatch.into());
        }
        let setup = proof_inputs
            .token_account_setup(fee_payer, request.intent.token_account_setup())
            .map_err(RelayError::from)?
            .iter()
            .map(|create| create.instruction())
            .collect();
        let signature = match &request.intent {
            RelayIntent::Anonymous {
                owner_signature, ..
            }
            | RelayIntent::Confidential {
                owner_signature, ..
            } => <[u8; 64]>::from(owner_signature.0),
            RelayIntent::Delegate { .. }
            | RelayIntent::Deposit { .. }
            | RelayIntent::Merge { .. }
            | RelayIntent::Enroll { .. } => return Ok(Checked { setup, ..unsigned }),
        };
        let digest = proof_inputs
            .spp_proof_inputs(fee_payer)
            .message_hash()
            .map_err(RelayProofInputsError::from)
            .map_err(RelayError::from)?;
        match proof_inputs
            .sender
            .signing_pubkey
            .verify_message(&digest, &signature)
        {
            true => Ok(Checked {
                owner_signature: Some(signature),
                setup,
            }),
            false => Err(RelayError::OwnerSignature.into()),
        }
    }
}

impl RelayPayload {
    fn decode(intent: &RelayIntent) -> Result<Self, RelayProofInputsError> {
        let bytes = intent.proof_inputs().as_bytes();
        Ok(match intent {
            RelayIntent::Deposit { .. } => Self::Deposit(RelayDepositInputs::decode(bytes)?),
            RelayIntent::Merge { .. } => Self::Merge(RelayMergeInputs::decode(bytes)?),
            RelayIntent::Enroll { .. } => Self::Enroll(RelayEnrollInputs::decode(bytes)?),
            RelayIntent::Anonymous { .. }
            | RelayIntent::Confidential { .. }
            | RelayIntent::Delegate { .. } => Self::Transfer(RelayProofInputs::decode(bytes)?),
        })
    }

    pub fn ring_program_id(&self) -> Address {
        match self {
            Self::Transfer(inputs) => inputs.ring_program_id,
            Self::Deposit(inputs) => inputs.ring_program_id,
            Self::Merge(inputs) => inputs.ring_program_id,
            Self::Enroll(inputs) => inputs.ring_program_id,
        }
    }

    /// A transfer's debits come from the frame the co-signer signs.
    fn flows(&self) -> Result<CoSignFlows, RelayError> {
        Ok(match self {
            Self::Transfer(_) => CoSignFlows::Frame,
            Self::Deposit(inputs) => {
                let owner_hash = inputs
                    .recipient
                    .signing_pubkey
                    .owner_proof_input_hash()
                    .map_err(RelayProofInputsError::from)?;
                CoSignFlows::Published(vec![OwnerFlow {
                    owner: Member::from_bytes(owner_hash)
                        .map_err(|error| RelayError::Proof(error.to_string()))?,
                    flow: AssetFlow {
                        asset: inputs.asset.mint(),
                        outflow: 0,
                        deposited: inputs.amount,
                        withdrawn: 0,
                    },
                }])
            }
            Self::Merge(_) | Self::Enroll(_) => CoSignFlows::Published(Vec::new()),
        })
    }
}

/// The relay pays for no owner's account but the owner's own, and for no other storage instruction.
fn check_enrollment(enrollment: &RelayEnrollInputs, fee_payer: Address) -> Result<(), RelayError> {
    let refused = enrollment.owner == fee_payer
        || enrollment.instruction_data.first() != Some(&storage_instruction::tag::ENROLL)
        || enrollment.instruction_data.len() > solana_message::v1::MAX_TRANSACTION_SIZE;
    match refused {
        true => Err(RelayError::InvalidEnrollment),
        false => Ok(()),
    }
}

/// `payer, owner, tracking_registry, authorization, system_program`.
fn enrollment_step(enrollment: &RelayEnrollInputs, fee_payer: Address) -> ProvenRelay {
    let (authorization, _) =
        TrackingAuthorization::find_address(&enrollment.tracking_registry, &enrollment.owner);
    ProvenRelay {
        instruction: Instruction {
            program_id: STORAGE_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(fee_payer, true),
                AccountMeta::new_readonly(enrollment.owner, true),
                AccountMeta::new(enrollment.tracking_registry, false),
                AccountMeta::new(authorization, false),
                AccountMeta::new_readonly(Address::default(), false),
            ],
            data: enrollment.instruction_data.clone(),
        },
        budget: ComputeBudgetConfig::new(ENROLL_COMPUTE_UNITS),
        co_signer: None,
        signers: vec![enrollment.owner],
    }
}

/// A constraint violation or a failed pool acquire proves the store never committed the write.
fn refused(error: &DbErr) -> bool {
    match error {
        DbErr::ConnectionAcquire(_) => true,
        DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(error)))
        | DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(error))) => matches!(
            error.kind(),
            ErrorKind::UniqueViolation
                | ErrorKind::ForeignKeyViolation
                | ErrorKind::NotNullViolation
                | ErrorKind::CheckViolation
        ),
        _ => false,
    }
}

fn step(relay_id: RelayId, record: &RelayRecord) -> RelayStep {
    match record.state {
        RelayState::AwaitingSignature => RelayStep::SignMessage {
            relay_id,
            message: record.message.serialize().into(),
        },
        _ => RelayStep::Submitted { relay_id },
    }
}

fn relay_status(state: &RelayState) -> RelayStatus {
    match state {
        RelayState::AwaitingSignature => RelayStatus::AwaitingSignature,
        RelayState::Sent { signature } => RelayStatus::Sent {
            signature: *signature,
        },
        RelayState::Confirmed { signature, slot } => RelayStatus::Confirmed {
            signature: *signature,
            slot: *slot,
        },
        RelayState::Failed { reason } => RelayStatus::Failed {
            reason: reason.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_in_doubt_commit_keeps_the_reservation_with_no_stored_relay() {
        let lost = WriteError::Committing(DbErr::Query(RuntimeErr::SqlxError(SqlxError::Io(
            std::io::ErrorKind::ConnectionReset.into(),
        ))));

        let reservation = FailedWrite {
            write: UnstoredWrite::Failed(&lost),
            co_signature: Some(Signature::from([1; 64])),
            stored: Ok(None),
        }
        .reservation();

        assert_eq!(reservation, ReservationAfterWrite::Keep);
    }
}
