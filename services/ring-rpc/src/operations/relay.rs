use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use custom_ring_interface::{
    compute_unit_limit, storage_instruction, tag as ring_tag, tracking::TrackingAuthorization,
    InstructionTag, FRAME_BUFFER_HEADER_LEN, STORAGE_PROGRAM_ID,
};
use custom_ring_sdk::{
    close_frame_buffer, AddressCeiling, BufferedFrame, CeilingDecision, MergeCapacity, RingError,
};
use jsonrpsee::types::ErrorObjectOwned;
use log::warn;
use sea_orm::{
    sqlx::error::{Error as SqlxError, ErrorKind},
    DatabaseConnection, DbErr, RuntimeErr, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::Signer;
use spl_token_2022_interface::{
    extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions},
    state::{Account, Mint},
};
use spr_client::{compile_message, sign_transaction, ComputeBudgetConfig};
use spr_indexer_api::{Base64String, SerializablePubkey};
use spr_instruction::instruction::CreateAssociatedTokenAccount;
use spr_interface::{SPL_TOKEN_ACCOUNT_LEN, SPL_TOKEN_PROGRAM_ID};
use thiserror::Error;
use tokio::sync::{Mutex, Semaphore};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, RelayDepositInputs,
    RelayEnrollInputs, RelayId, RelayIntent, RelayMergeInputs, RelayProofInputs,
    RelayProofInputsError, RelayQuote, RelayRail, RelayStatus, RelayStep, SubmitRelayRequest,
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
    relay_reservations::{
        RelayBudget, RelayReservations, Reservation, Reserve, ReserveOutcome, ReservedBuffer,
    },
    relay_submit::{presigned_transaction, CollectedSignature},
    relays::{PendingCoSign, RelayRecord, RelayState, RelayStore},
};

/// Longest quote window, one blockhash lifetime.
pub const QUOTE_SLOTS: u64 = 150;
pub const RELAY_TRACK_INTERVAL: Duration = Duration::from_secs(2);
const MAX_CONCURRENT_PROOFS: usize = 4;
const EXPIRED: &str = "the relay message expired before it landed";

const LANDING_POLL: Duration = Duration::from_millis(500);
const MANAGED_MERGE_DOMAIN: &[u8] = b"zolana/ring-rpc-managed-merge/v1";
/// Modelled, the first enrollment verifies a proof in its instruction.
const ENROLL_COMPUTE_UNITS: u32 = 400_000;
/// One blockhash lifetime for the last write to land and one for the wallet to sign.
pub const ABANDONED_AFTER_SLOTS: u64 = 2 * QUOTE_SLOTS;
const SWEEP_PAGE: u64 = 16;
const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
const FRAME_KEY_DOMAIN: &[u8] = b"zolana/ring-rpc-reserve-frame/v1";
const ENROLL_KEY_DOMAIN: &[u8] = b"zolana/ring-rpc-reserve-enroll/v1";
const SETUP_KEY_DOMAIN: &[u8] = b"zolana/ring-rpc-reserve-setup/v1";

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
    #[error("the relay budget has no room for the request")]
    Budget,
    #[error("the signer holds its whole share of the relay budget")]
    SignerBudget,
    #[error("the enrollment request does not carry the owner's signature")]
    EnrollmentSignature,
    #[error("the request does not carry the ring delegate's signature")]
    DelegateSignature,
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

    async fn delegate(&self, ring: Address) -> Result<Option<Address>, RingRpcError>;
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
    budget: RelayBudget,
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
    signer: Option<Address>,
    setup: Vec<CreateAssociatedTokenAccount>,
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
            Self::Budget => -32203,
            Self::SignerBudget => -32204,
            Self::EnrollmentSignature => -32205,
            Self::DelegateSignature => -32206,
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
    async fn delegate(&self, _ring: Address) -> Result<Option<Address>, RingRpcError> {
        Ok(None)
    }

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
            budget: RelayBudget::default(),
        }
    }

    /// Without it the relay funds no enrollment and no buffer.
    #[must_use = "use the updated relay"]
    pub const fn with_budget(mut self, budget: RelayBudget) -> Self {
        self.budget = budget;
        self
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

    fn parties(&self, named: &[spr_indexer_api::SerializablePubkey]) -> RelayParties {
        RelayParties {
            fee_payer: self.fee_payer(),
            co_signers: match named {
                [] => self.co_signer.signer().into_iter().collect(),
                named => named.iter().map(|signer| signer.0).collect(),
            },
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
        if let RelayPayload::Transfer(RelayProofInputs {
            rail: RelayRail::Delegate { delegate },
            ..
        }) = &payload
        {
            if self.rings.delegate(ring).await? != Some(*delegate) {
                return Err(RelayError::DelegateSignature.into());
            }
        }
        let parties = self.parties(&request.co_signers);
        let Checked {
            owner_signature,
            signer,
            setup,
        } = PrepareCheck {
            request,
            payload: &payload,
            fee_payer: parties.fee_payer,
            slot: self.chain.slot().await?,
        }
        .check()?;
        let proven = match (&payload, self.stored_proof(&relay_id).await?) {
            (_, Some(stored)) => stored,
            // The wallet proved its seal, the relay only pays.
            (RelayPayload::Enroll(enrollment), None) => {
                self.reserve_enrollment(enrollment, &relay_id).await?;
                enrollment_step(enrollment, parties.fee_payer)
            }
            (_, None) => {
                let _proof = self
                    .proofs
                    .try_acquire()
                    .map_err(|_| RingRpcError::RelayProverBusy)?;
                self.prover
                    .prove(RelayProofRequest {
                        ring,
                        parties: parties.clone(),
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
            parties,
            signer,
        })
        .await
    }

    async fn stored_proof(&self, relay_id: &RelayId) -> Result<Option<ProvenRelay>, RingRpcError> {
        self.reservations()
            .by_relay(relay_id)
            .await?
            .and_then(|held| held.proven)
            .map(|stored| StoredProof::read(&stored))
            .transpose()
    }

    /// A held reservation resumes the same request, its nonce already passed.
    pub(crate) async fn holds(&self, relay_id: &RelayId) -> Result<bool, RingRpcError> {
        Ok(self.reservations().by_relay(relay_id).await?.is_some())
    }

    /// The owner's signature over the digest was checked, a retry finds the held charge.
    async fn reserve_enrollment(
        &self,
        enrollment: &RelayEnrollInputs,
        relay_id: &RelayId,
    ) -> Result<(), RingRpcError> {
        let rent = self
            .chain
            .rent_exempt_lamports(TrackingAuthorization::SIZE)
            .await?;
        let key = Sha256::new()
            .chain_update(ENROLL_KEY_DOMAIN)
            .chain_update(enrollment.request_digest())
            .finalize()
            .into();
        self.reserve(Reserve {
            key,
            relay_id,
            signer: enrollment.owner,
            lamports: rent.saturating_add(2 * LAMPORTS_PER_SIGNATURE),
            landing_rent: rent,
            buffer: None,
            proven: None,
            slot: self.chain.slot().await?,
            budget: self.budget,
        })
        .await
        .map(|_| ())
    }

    async fn reserve(&self, reserve: Reserve<'_>) -> Result<Reservation, RingRpcError> {
        match self.reservations().reserve(reserve).await? {
            ReserveOutcome::Held(held) => Ok(*held),
            ReserveOutcome::OverTotal => Err(RelayError::Budget.into()),
            ReserveOutcome::OverSigner => Err(RelayError::SignerBudget.into()),
        }
    }

    fn reservations(&self) -> RelayReservations<'_> {
        RelayReservations::new(self.store.connection())
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
        let delegate = seal.delegate;
        self.rings.check(ring).await?;
        let parties = self.parties(&[]);
        let stored = self.stored_proof(&relay_id).await?;
        let (payload, proven) = {
            let _proof = self
                .proofs
                .try_acquire()
                .map_err(|_| RingRpcError::RelayProverBusy)?;
            let payload =
                RelayPayload::Transfer(self.prover.seal_delegate(seal, parties.clone()).await?);
            let proven = match stored {
                Some(stored) => stored,
                None => {
                    self.prover
                        .prove(RelayProofRequest {
                            ring,
                            parties: parties.clone(),
                            payload: &payload,
                            owner_signature: None,
                        })
                        .await?
                }
            };
            (payload, proven)
        };
        self.stage(ProvenStep {
            relay_id,
            payload,
            setup: Vec::new(),
            proven,
            parties,
            signer: Some(delegate),
        })
        .await
    }

    /// A relay awaiting no signer is co-signed before the record lands.
    async fn stage(&self, proven: ProvenStep) -> Result<RelayStep, RingRpcError> {
        let ProvenStep {
            relay_id,
            payload,
            setup,
            proven,
            parties,
            signer,
        } = proven;
        let mut proven = proven;
        let setup_rent = self.setup_rent(&setup).await?;
        self.reserve_and_upload(RelaySpend {
            proven: &mut proven,
            signer,
            relay_id: &relay_id,
            setup_rent,
        })
        .await?;
        let fee_payer = self.fee_payer();
        let LatestBlockhash {
            blockhash,
            last_valid_block_height,
        } = self.chain.latest_blockhash().await?;
        let mut instructions: Vec<_> = setup.iter().map(|create| create.instruction()).collect();
        instructions.push(proven.instruction.clone());
        let message = compile_message(&fee_payer, &instructions, blockhash, proven.budget)?;
        let awaited = CoSignStep {
            payload: &payload,
            proven,
            named: &parties.co_signers,
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
        // A kept reservation resumes on a retry, the sweep closes its buffer otherwise.
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
    /// A frame past one transaction settles from a buffer the relay writes and pays for.
    fn wide_frame(&self, proven: &ProvenRelay) -> Result<Option<BufferedFrame>, RingRpcError> {
        if !matches!(
            proven.instruction.data.first(),
            Some(&(ring_tag::TRANSFER | ring_tag::AUTHORITY_TRANSFER))
        ) {
            return Ok(None);
        }
        let writer = self.fee_payer();
        let decision = AddressCeiling {
            payer: writer,
            instruction: &proven.instruction,
            budget: proven.budget,
            inputs: &[],
            merge_capacity: MergeCapacity {
                keyed: 0,
                zero_key: 0,
            },
        }
        .decide()
        .map_err(|error| RelayError::proof(error.into()))?;
        if !matches!(decision, CeilingDecision::Buffered(_)) {
            return Ok(None);
        }
        BufferedFrame::for_writer(&proven.instruction, writer)
            .map(Some)
            .map_err(|error| RelayError::proof(error.into()))
    }

    /// Nothing is paid before its reservation commits.
    async fn reserve_and_upload(&self, spend: RelaySpend<'_>) -> Result<(), RingRpcError> {
        let RelaySpend {
            proven,
            signer,
            relay_id,
            setup_rent,
        } = spend;
        let Some(frame) = self.wide_frame(proven)? else {
            if setup_rent > 0 {
                self.reserve(Reserve {
                    key: setup_key(relay_id),
                    relay_id,
                    signer: signer.ok_or(RelayError::OwnerSignature)?,
                    lamports: setup_rent.saturating_add(message_fee_of(&proven.instruction)),
                    landing_rent: setup_rent,
                    buffer: None,
                    proven: None,
                    slot: self.chain.slot().await?,
                    budget: self.budget,
                })
                .await?;
            }
            return Ok(());
        };
        let signer = signer.ok_or(RelayError::OwnerSignature)?;
        let writes = frame.writes().map_err(RelayError::proof)?;
        let settle = frame.settle();
        let held = self
            .reserve(Reserve {
                key: frame_key(&proven.instruction.data),
                relay_id,
                signer,
                lamports: self
                    .frame_cost(proven, &settle, writes.len())
                    .await?
                    .saturating_add(setup_rent),
                landing_rent: setup_rent,
                buffer: Some(ReservedBuffer {
                    ring: proven.instruction.program_id,
                    buffer: frame.buffer(),
                }),
                proven: Some(StoredProof::of(proven)?),
                slot: self.chain.slot().await?,
                budget: self.budget,
            })
            .await?;
        let budget = ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::WriteFrame));
        for (index, write) in writes.into_iter().enumerate().skip(held.uploaded) {
            self.reservations()
                .charge(&held.key, LAMPORTS_PER_SIGNATURE)
                .await?;
            self.land(write, budget).await?;
            self.reservations()
                .uploaded(&held.key, index + 1, self.chain.slot().await?)
                .await?;
        }
        proven.instruction = settle;
        proven.budget =
            ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::SettleBuffered));
        Ok(())
    }

    /// An idempotent create pays only for an account still missing.
    async fn setup_rent(
        &self,
        setup: &[CreateAssociatedTokenAccount],
    ) -> Result<u64, RingRpcError> {
        let mut rent = 0u64;
        for create in setup {
            if self.chain.account_data(create.address()).await?.is_some() {
                continue;
            }
            let data_len = match create.token_program.to_bytes() {
                SPL_TOKEN_PROGRAM_ID => SPL_TOKEN_ACCOUNT_LEN,
                _ => token_2022_account_len(
                    &self
                        .chain
                        .account_data(create.mint)
                        .await?
                        .ok_or(RingRpcError::StateUnavailable)?,
                )?,
            };
            rent = rent.saturating_add(self.chain.rent_exempt_lamports(data_len).await?);
        }
        Ok(rent)
    }

    /// The buffer's rent and a fee for every write, the settlement and the close, modelled at the base fee.
    async fn frame_cost(
        &self,
        proven: &ProvenRelay,
        settle: &Instruction,
        writes: usize,
    ) -> Result<u64, RingRpcError> {
        let rent = self
            .chain
            .rent_exempt_lamports(FRAME_BUFFER_HEADER_LEN + proven.instruction.data.len())
            .await?;
        let settle_signers = settle
            .accounts
            .iter()
            .filter(|account| account.is_signer)
            .count();
        // One signature per write and for the close, the fee payer's beside the settlement's own.
        let signatures = u64::try_from(writes + settle_signers + 2).unwrap_or(u64::MAX);
        Ok(rent.saturating_add(signatures.saturating_mul(LAMPORTS_PER_SIGNATURE)))
    }

    /// One transaction the relay alone signs, carried to its finalized outcome.
    async fn land(
        &self,
        instruction: Instruction,
        budget: ComputeBudgetConfig,
    ) -> Result<(), RingRpcError> {
        let LatestBlockhash {
            blockhash,
            last_valid_block_height,
        } = self.chain.latest_blockhash().await?;
        let message = compile_message(&self.fee_payer(), &[instruction], blockhash, budget)?;
        let transaction = sign_transaction(message, &[&self.fee_payer])?;
        self.chain.send(&transaction).await?;
        let attempt = Attempt {
            signature: transaction.signatures[0],
            last_valid_block_height,
        };
        loop {
            match attempt.landing(self.chain.as_ref()).await? {
                Landing::Pending => tokio::time::sleep(LANDING_POLL).await,
                Landing::Landed(ChainOutcome::Confirmed { .. }) => return Ok(()),
                Landing::Landed(ChainOutcome::Failed { reason }) => {
                    return Err(RelayError::SendRefused { reason }.into())
                }
                Landing::Expired => {
                    return Err(RelayError::SendRefused {
                        reason: EXPIRED.to_owned(),
                    }
                    .into())
                }
            }
        }
    }

    /// The rent returns before the charge does, a refused close stays for the next sweep.
    async fn release(&self, held: &Reservation) -> Result<(), RingRpcError> {
        if let Some(ReservedBuffer { ring, buffer }) = held.buffer {
            if self.chain.account_data(buffer).await?.is_some() {
                let close = close_frame_buffer(ring, self.fee_payer(), buffer);
                let budget =
                    ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::CloseFrameBuffer));
                self.reservations()
                    .charge(&held.key, LAMPORTS_PER_SIGNATURE)
                    .await?;
                self.land(close, budget).await?;
            }
        }
        Ok(self.reservations().release(held, 0).await?)
    }

    /// The settlement closed the buffer into the writer, only its fee and setup rent stay spent.
    async fn release_landed(
        &self,
        held: &Reservation,
        message: &VersionedMessage,
    ) -> Result<(), RingRpcError> {
        let landed = held.landing_rent.saturating_add(message_fee(message));
        Ok(self.reservations().release(held, landed).await?)
    }

    /// Past the window nothing of a live relay is left, a wallet that never signed let the blockhash lapse.
    pub async fn sweep_abandoned(&self) -> Result<(), RingRpcError> {
        let slot = self.chain.slot().await?;
        let before = slot.saturating_sub(ABANDONED_AFTER_SLOTS);
        for held in self.reservations().abandoned(before, SWEEP_PAGE).await? {
            let _transition = self.transitions.lock().await;
            let swept = async {
                let Some(mut record) = self.relays().get(&held.relay_id).await? else {
                    return self.release(&held).await;
                };
                match record.state {
                    RelayState::Sent { .. } => Ok(()),
                    RelayState::Confirmed { .. } => {
                        self.release_landed(&held, &record.message).await
                    }
                    RelayState::Failed { .. } => self.release(&held).await,
                    RelayState::AwaitingSignature => {
                        if self.chain.block_height().await? <= record.last_valid_block_height {
                            return Ok(());
                        }
                        record.state = RelayState::Failed {
                            reason: EXPIRED.to_owned(),
                        };
                        self.close(&held.relay_id, &record).await
                    }
                }
            }
            .await;
            if let Err(error) = swept {
                warn!("relay reservation did not sweep {}", redacted(&error));
            }
        }
        Ok(())
    }

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
            if let Err(error) = self.sweep_abandoned().await {
                warn!("relay sweep failed {}", redacted(&error));
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
                        // A failed transaction still paid, its rent rolled back.
                        if let Some(held) = self.reservations().by_relay(relay_id).await? {
                            self.reservations()
                                .charge(&held.key, message_fee(&record.message))
                                .await?;
                        }
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
                self.relays().update(relay_id, record).await?;
                match self.reservations().by_relay(relay_id).await? {
                    Some(held) => self.release_landed(&held, &record.message).await,
                    None => Ok(()),
                }
            }
            _ => {
                self.relays().update(relay_id, record).await?;
                if let Some(held) = self.reservations().by_relay(relay_id).await? {
                    if let Err(error) = self.release(&held).await {
                        warn!("relay buffer did not close {}", redacted(&error));
                    }
                }
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
    setup: Vec<CreateAssociatedTokenAccount>,
    proven: ProvenRelay,
    parties: RelayParties,
    /// The wallet party whose signature the check verified, it answers for a reservation.
    signer: Option<Address>,
}

struct RelaySpend<'a> {
    proven: &'a mut ProvenRelay,
    signer: Option<Address>,
    relay_id: &'a RelayId,
    setup_rent: u64,
}

struct CoSignStep<'a> {
    payload: &'a RelayPayload,
    proven: ProvenRelay,
    /// The prover names none outside it.
    named: &'a [Address],
}

struct Awaited {
    co_sign: Option<PendingCoSign>,
    signers: Vec<Address>,
}

impl CoSignStep<'_> {
    /// The service signs its own place in the run, each other approver signs the message.
    fn plan(self, co_signer: &dyn CoSignPolicy) -> Result<Awaited, RingRpcError> {
        let Self {
            payload,
            proven,
            named,
        } = self;
        if !proven
            .co_signers
            .iter()
            .all(|signer| named.contains(signer))
        {
            return Err(RelayError::CoSignRefused.into());
        }
        let own = co_signer
            .signer()
            .filter(|signer| proven.co_signers.contains(signer));
        let co_sign = own
            .map(|signer| {
                Ok::<_, RingRpcError>(PendingCoSign {
                    signer,
                    ring: payload.ring_program_id(),
                    flows: payload.flows()?,
                })
            })
            .transpose()?;
        let others = proven
            .co_signers
            .into_iter()
            .filter(|signer| Some(*signer) != own);
        Ok(Awaited {
            co_sign,
            signers: proven.signers.into_iter().chain(others).collect(),
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
            signer: None,
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
                let RelayIntent::Enroll {
                    owner_signature, ..
                } = &request.intent
                else {
                    return Err(RelayError::EnrollmentSignature.into());
                };
                if !owner_signature
                    .0
                    .verify(enrollment.owner.as_ref(), &enrollment.request_digest())
                {
                    return Err(RelayError::EnrollmentSignature.into());
                }
                return Ok(Checked {
                    signer: Some(enrollment.owner),
                    ..unsigned
                });
            }
        };
        if proof_inputs.rail.operation() != request.intent.operation() {
            return Err(RelayError::RailMismatch.into());
        }
        let setup = proof_inputs
            .token_account_setup(fee_payer, request.intent.token_account_setup())
            .map_err(RelayError::from)?;
        let signature = match &request.intent {
            RelayIntent::Anonymous {
                owner_signature, ..
            }
            | RelayIntent::Confidential {
                owner_signature, ..
            } => Some(<[u8; 64]>::from(owner_signature.0)),
            RelayIntent::Delegate { .. } => None,
            RelayIntent::Deposit { .. }
            | RelayIntent::Merge { .. }
            | RelayIntent::Enroll { .. } => return Ok(Checked { setup, ..unsigned }),
        };
        let digest = proof_inputs
            .spp_proof_inputs(fee_payer)
            .message_hash()
            .map_err(RelayProofInputsError::from)
            .map_err(RelayError::from)?;
        let Some(signature) = signature else {
            let (
                RelayRail::Delegate { delegate },
                RelayIntent::Delegate {
                    delegate_signature, ..
                },
            ) = (&proof_inputs.rail, &request.intent)
            else {
                return Err(RelayError::DelegateSignature.into());
            };
            if !delegate_signature.0.verify(delegate.as_ref(), &digest) {
                return Err(RelayError::DelegateSignature.into());
            }
            return Ok(Checked {
                signer: Some(*delegate),
                setup,
                ..unsigned
            });
        };
        match proof_inputs
            .sender
            .signing_pubkey
            .verify_message(&digest, &signature)
        {
            true => Ok(Checked {
                owner_signature: Some(signature),
                signer: proof_inputs
                    .sender
                    .signing_pubkey
                    .as_ed25519()
                    .ok()
                    .map(Address::new_from_array),
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

/// Modelled at the base fee, the relay sets no priority fee.
fn message_fee(message: &VersionedMessage) -> u64 {
    u64::from(message.header().num_required_signatures).saturating_mul(LAMPORTS_PER_SIGNATURE)
}

/// The instruction's signers beside the fee payer, or the payer alone among them.
fn message_fee_of(instruction: &Instruction) -> u64 {
    let signers = instruction
        .accounts
        .iter()
        .filter(|account| account.is_signer)
        .count();
    u64::try_from(signers + 1)
        .unwrap_or(u64::MAX)
        .saturating_mul(LAMPORTS_PER_SIGNATURE)
}

/// The size the associated token program allocates for a mint, its required extensions included.
fn token_2022_account_len(mint: &[u8]) -> Result<usize, RingRpcError> {
    let mint =
        StateWithExtensions::<Mint>::unpack(mint).map_err(|_| RingRpcError::StateUnavailable)?;
    let mint_extensions = mint
        .get_extension_types()
        .map_err(|_| RingRpcError::StateUnavailable)?;
    let mut extensions = ExtensionType::get_required_init_account_extensions(&mint_extensions);
    extensions.push(ExtensionType::ImmutableOwner);
    ExtensionType::try_calculate_account_len::<Account>(&extensions)
        .map_err(|_| RingRpcError::StateUnavailable)
}

fn setup_key(relay_id: &RelayId) -> [u8; 32] {
    Sha256::new()
        .chain_update(SETUP_KEY_DOMAIN)
        .chain_update(relay_id.0 .0)
        .finalize()
        .into()
}

fn frame_key(frame: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(FRAME_KEY_DOMAIN)
        .chain_update(frame)
        .finalize()
        .into()
}

/// A proven frame kept with its reservation, public once it lands.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredProof {
    program: SerializablePubkey,
    accounts: Vec<(SerializablePubkey, bool, bool)>,
    data: Base64String,
    co_signers: Vec<SerializablePubkey>,
    signers: Vec<SerializablePubkey>,
}

impl StoredProof {
    fn of(proven: &ProvenRelay) -> Result<String, RingRpcError> {
        serde_json::to_string(&Self {
            program: proven.instruction.program_id.into(),
            accounts: proven
                .instruction
                .accounts
                .iter()
                .map(|meta| (meta.pubkey.into(), meta.is_signer, meta.is_writable))
                .collect(),
            data: proven.instruction.data.clone().into(),
            co_signers: proven.co_signers.iter().copied().map(Into::into).collect(),
            signers: proven.signers.iter().copied().map(Into::into).collect(),
        })
        .map_err(|_| RingRpcError::StateUnavailable)
    }

    fn read(stored: &str) -> Result<ProvenRelay, RingRpcError> {
        let Self {
            program,
            accounts,
            data,
            co_signers,
            signers,
        } = serde_json::from_str(stored).map_err(|_| RingRpcError::StateUnavailable)?;
        Ok(ProvenRelay {
            instruction: Instruction {
                program_id: program.0,
                accounts: accounts
                    .into_iter()
                    .map(|(pubkey, is_signer, is_writable)| AccountMeta {
                        pubkey: pubkey.0,
                        is_signer,
                        is_writable,
                    })
                    .collect(),
                data: data.0,
            },
            budget: ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transfer)),
            co_signers: co_signers.into_iter().map(|signer| signer.0).collect(),
            signers: signers.into_iter().map(|signer| signer.0).collect(),
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
        co_signers: Vec::new(),
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
