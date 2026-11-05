//! Sends a ring operation and proves it again when the chain moved under its proof.

use std::{collections::VecDeque, time::Duration};

use custom_ring_interface::{
    compute_unit_limit,
    storage::{Revision, StorageRegistry},
    tracking::TrackingRegistry,
    CustomRingError, InstructionTag, RingPolicy,
};
use solana_address::Address;
use solana_commitment_config::CommitmentLevel;
use solana_instruction::Instruction;
use solana_instruction_error::InstructionError;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use solana_transaction_status_client_types::{TransactionConfirmationStatus, TransactionStatus};
use spr_client::{
    compile_message, sign_transaction, AsyncRpc, ClientError, ComputeBudgetConfig,
    RpcSendTransactionConfig,
};

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    address_ceiling::{FitSigners, FitTransport, TransactionFit},
    buffered::{write_budget, BufferedFrame},
    heap::boxed,
    AnonymousTransfer, CustomRing, CustomRingTransfer, DelegateTransfer, PreparedRingDeposit,
    PublicOwnerTransfer, RingError, RingMergeOperation,
};

#[cfg(test)]
#[path = "../tests/operations/submission.rs"]
mod tests;

/// The header the transaction sends, the size check and the send read one budget.
pub(crate) fn send_budget(tag: InstructionTag, priority_fee: Option<u64>) -> ComputeBudgetConfig {
    let budget = ComputeBudgetConfig::new(compute_unit_limit(tag));
    match priority_fee {
        Some(lamports) => budget.with_priority_fee(lamports),
        None => budget,
    }
}

/// The operation fits one transaction with no buffer.
pub(crate) fn check_transaction_size(
    payer: &Address,
    instruction: &Instruction,
    budget: ComputeBudgetConfig,
) -> Result<(), RingError> {
    TransactionFit::inline(instruction, FitSigners::new(*payer), budget)
        .map(drop)
        .map_err(RingError::from)
}

const MAX_ATTEMPTS: u8 = 3;
const PENDING_POLL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum SubmissionStatus {
    Settled(SettledSubmission),
    Pending { signature: Signature },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum SettledSubmission {
    Confirmed {
        signature: Signature,
        slot: u64,
    },
    Failed {
        signature: Signature,
        error: TransactionError,
    },
}

pub enum RingOperation<'a> {
    Transfer(Box<CustomRingTransfer<'a>>),
    Anonymous(Box<AnonymousTransfer<'a>>),
    PublicOwners(Box<PublicOwnerTransfer<'a>>),
    Delegate(Box<DelegateTransfer<'a>>),
    Merge(Box<RingMergeOperation>),
    Deposit(Box<PreparedRingDeposit>),
    /// A built instruction, sent as is, its budget from its tag.
    Instruction(Instruction),
}

macro_rules! operations {
    ($($variant:ident($ty:ty) => $wrap:expr,)*) => {$(
        impl<'a> From<$ty> for RingOperation<'a> {
            fn from(value: $ty) -> Self {
                Self::$variant($wrap(value))
            }
        }
    )*};
}

operations! {
    Transfer(CustomRingTransfer<'a>) => |transfer: CustomRingTransfer<'a>| Box::new(transfer.with_buffered_settlement()),
    Anonymous(AnonymousTransfer<'a>) => |transfer: AnonymousTransfer<'a>| Box::new(transfer.with_buffered_settlement()),
    PublicOwners(PublicOwnerTransfer<'a>) => |transfer: PublicOwnerTransfer<'a>| Box::new(transfer.with_buffered_settlement()),
    Delegate(DelegateTransfer<'a>) => |transfer: DelegateTransfer<'a>| Box::new(transfer.with_buffered_settlement()),
    Merge(RingMergeOperation) => Box::new,
    Deposit(PreparedRingDeposit) => Box::new,
    Instruction(Instruction) => core::convert::identity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundRoot {
    /// The registry the program reads the root from.
    pub registry: Address,
    pub revision: Revision,
    pub root: [u8; 32],
    pub tree: RootTree,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootTree {
    Storage,
    Tracking,
}

impl BoundRoot {
    /// The newest root of the ring's records registry.
    pub(crate) async fn own(
        policy: &RingPolicy,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Self, RingError> {
        Self::newest_of(policy.records, rpc).await
    }

    /// The newest root of the curator registry, `None` without a curator source.
    pub(crate) async fn curator(
        policy: &RingPolicy,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<Self>, RingError> {
        match policy.curator() {
            Some(curator) => Ok(Some(Self::newest_of(curator, rpc).await?)),
            None => Ok(None),
        }
    }

    pub(crate) async fn newest(
        ring: CustomRing,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Self, RingError> {
        Self::own(&*ring.require_policy(rpc).await?, rpc).await
    }

    pub(crate) async fn newest_of(
        registry: Address,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Self, RingError> {
        let newest = live_registry(registry, rpc).await?.newest();
        Ok(Self {
            registry,
            revision: newest.revision,
            root: newest.hash,
            tree: RootTree::Storage,
        })
    }

    /// The newest root of the ring's pinned tracking registry.
    pub(crate) async fn tracking(
        policy: &RingPolicy,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Self, RingError> {
        let newest = live_tracking(policy.tracking, rpc).await?.newest();
        Ok(Self {
            registry: policy.tracking,
            revision: newest.revision,
            root: newest.hash,
            tree: RootTree::Tracking,
        })
    }

    /// `true` once the registry no longer serves the root at its revision.
    async fn replaced(self, client: &(impl AsyncRpc + ?Sized)) -> Result<bool, RingError> {
        let served = match self.tree {
            RootTree::Storage => {
                let registry = live_registry(self.registry, client).await?;
                registry.root(self.revision, client.get_slot().await?)
            }
            RootTree::Tracking => {
                let registry = live_tracking(self.registry, client).await?;
                registry.root(self.revision, client.get_slot().await?)
            }
        };
        Ok(served != Ok(self.root))
    }
}

/// `NotStorageRegistry` unless `registry` is an initialized storage registry.
pub async fn live_registry(
    registry: Address,
    rpc: &(impl AsyncRpc + ?Sized),
) -> Result<StorageRegistry, RingError> {
    rpc.get_account(registry)
        .await?
        .and_then(|account| StorageRegistry::decode(&account.owner, &account.data))
        .ok_or(RingError::NotStorageRegistry { registry })
}

async fn live_tracking(
    registry: Address,
    rpc: &(impl AsyncRpc + ?Sized),
) -> Result<TrackingRegistry, RingError> {
    rpc.get_account(registry)
        .await?
        .and_then(|account| TrackingRegistry::decode(&account.owner, &account.data))
        .ok_or(RingError::NotStorageRegistry { registry })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundPolicy {
    pub ring: CustomRing,
    pub hash: [u8; 32],
}

/// Ring refusals a fresh proof fixes, rows parsed verbatim by the TS parity test.
const REPROOF: [(CustomRingError, Reproof); 4] = [
    (CustomRingError::RootNotServed, Reproof::Fixes),
    (CustomRingError::TrackingRootBelowFloor, Reproof::Fixes),
    (CustomRingError::UnboundRegistry, Reproof::Fixes),
    (CustomRingError::ProofVerificationFailed, Reproof::IfMoved),
];

enum Reproof {
    /// The program refused a root or registry the chain since replaced or raised.
    Fixes,
    /// Counts only once a value the proof binds moved on chain.
    IfMoved,
}

/// Every value a proof binds that the chain can move before it lands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BoundState {
    pub roots: Vec<BoundRoot>,
    pub policy: Option<BoundPolicy>,
}

impl BoundState {
    /// A failed verification counts only once a bound value moved.
    async fn reproof_fixes(
        &self,
        error: &TransactionError,
        client: &(impl AsyncRpc + ?Sized),
    ) -> Result<bool, RingError> {
        let Some(code) = ring_error(error) else {
            return Ok(matches!(error, TransactionError::BlockhashNotFound));
        };
        match REPROOF
            .iter()
            .find(|(stale, _)| code == *stale as u32)
            .map(|(_, reproof)| reproof)
        {
            Some(Reproof::Fixes) => Ok(true),
            Some(Reproof::IfMoved) => self.moved(client).await,
            None => Ok(false),
        }
    }

    async fn moved(&self, client: &(impl AsyncRpc + ?Sized)) -> Result<bool, RingError> {
        for root in &self.roots {
            if root.replaced(client).await? {
                return Ok(true);
            }
        }
        if let Some(policy) = self.policy {
            if policy.ring.require_policy(client).await?.policy_hash != policy.hash {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

struct Proved {
    instruction: Instruction,
    budget: ComputeBudgetConfig,
    bound: BoundState,
}

/// One transaction the submission owes, held from before its broadcast until its signature resolves.
struct Attempt {
    step: Step,
    sent: Option<Sent>,
}

struct Step {
    instruction: Instruction,
    budget: ComputeBudgetConfig,
    bound: BoundState,
    stage: Stage,
}

struct Sent {
    transaction: VersionedTransaction,
    last_valid_block_height: u64,
    /// Preflight refused it, a later lookup would read an unknown signature and lose the error.
    refused: Option<TransactionError>,
}

enum Stage {
    /// The confirmation ends the submission.
    Inline,
    /// The confirmation leads to the next chunk or the settlement.
    Write(Box<Upload>),
    /// The confirmation ends the submission and the program closed the buffer.
    Settle(Box<BufferedFrame>),
}

/// The chunks a confirmed write leaves, in offset order.
struct Upload {
    frame: BufferedFrame,
    writes: VecDeque<Instruction>,
    settle_budget: ComputeBudgetConfig,
}

impl Step {
    fn inline(proved: Proved) -> Self {
        Self {
            instruction: proved.instruction,
            budget: proved.budget,
            bound: proved.bound,
            stage: Stage::Inline,
        }
    }

    /// The header width of the settlement matches the fit's, the priority fee stays with it.
    fn upload(
        proved: Proved,
        writer: Address,
        priority_fee: Option<u64>,
    ) -> Result<Self, RingError> {
        let frame = BufferedFrame::for_writer(&proved.instruction, writer)?;
        let writes = frame.writes()?.into();
        let upload = Upload {
            frame,
            writes,
            settle_budget: send_budget(InstructionTag::SettleBuffered, priority_fee),
        };
        Ok(upload.next(proved.bound))
    }

    /// `None` when the confirmed step ended the submission.
    fn after_confirmation(self) -> Option<Self> {
        match self.stage {
            Stage::Inline | Stage::Settle(_) => None,
            Stage::Write(upload) => Some(upload.next(self.bound)),
        }
    }

    /// A failed upload or settlement can leave the writer's rent in a buffer only the writer closes.
    fn buffer(&self) -> Option<&BufferedFrame> {
        match &self.stage {
            Stage::Inline => None,
            Stage::Write(upload) => Some(&upload.frame),
            Stage::Settle(frame) => Some(frame),
        }
    }

    /// A write needs the writer alone, a transaction refuses a signer its message does not name.
    fn signed_by_writer_alone(&self) -> bool {
        matches!(self.stage, Stage::Write(_))
    }
}

impl Upload {
    /// The settlement follows the last write, the program checks the buffer against its digest.
    fn next(mut self, bound: BoundState) -> Step {
        match self.writes.pop_front() {
            Some(instruction) => Step {
                instruction,
                budget: write_budget(),
                bound,
                stage: Stage::Write(Box::new(self)),
            },
            None => Step {
                instruction: self.frame.settle(),
                budget: self.settle_budget,
                bound,
                stage: Stage::Settle(Box::new(self.frame)),
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Unknown,
    Confirmed {
        slot: u64,
    },
    Failed(TransactionError),
    /// A fresh proof fixes the failure.
    Stale(TransactionError),
}

#[must_use]
pub struct RingSubmission<'a> {
    operation: RingOperation<'a>,
    priority_fee: Option<u64>,
    pending: Option<Attempt>,
    attempts: u8,
    terminal: Option<SubmissionStatus>,
}

impl<'a> RingSubmission<'a> {
    pub fn new(operation: impl Into<RingOperation<'a>>) -> Self {
        Self {
            operation: operation.into(),
            priority_fee: None,
            pending: None,
            attempts: 0,
            terminal: None,
        }
    }

    /// Lamports the v1 header carries, refused before proving past the size ceiling.
    pub fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.priority_fee = Some(lamports);
        self.operation = self.operation.with_priority_fee(lamports);
        self
    }

    pub fn pending_transaction(&self) -> Option<&VersionedTransaction> {
        let sent = self.pending.as_ref()?.sent.as_ref()?;
        Some(&sent.transaction)
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    /// The notes of the deposit's latest attempt, the ones a confirmation settled, in slot order.
    pub fn deposit_utxos(&self) -> Option<&[spr_transaction::Utxo]> {
        match &self.operation {
            RingOperation::Deposit(deposit) => Some(deposit.utxos()),
            _ => None,
        }
    }

    /// Inputs stay reserved while the sent signature is unresolved, `Pending` can name an upload write.
    pub async fn send<R: AsyncRpc, I: RingIndexerBackend>(
        &mut self,
        client: &RingClient<R, I>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<SubmissionStatus, RingError> {
        if let Some(terminal) = &self.terminal {
            return Ok(terminal.clone());
        }
        loop {
            // 1. A held attempt reconciles ahead of any new proof or broadcast. Its transaction
            // can land until its blockhash expires, and a nullifier stops no double landing of a
            // deposit, so a new proof waits for a final status. Every RPC error below returns with
            // the attempt still held, and the next call resumes here.
            let attempt = match self.pending.take() {
                Some(attempt) => attempt,
                None => boxed(|| self.prepare(client, payer, signers)).await?,
            };
            let attempt = self.pending.insert(attempt);
            // 2. The signature enters the held state ahead of the bytes, a broadcast whose future
            // is dropped or whose answer is lost stays reconcilable. Only a preflight refusal says
            // the bytes did not land, any other send error leaves the outcome to the lookup.
            let sent = match &mut attempt.sent {
                Some(sent) => sent,
                unsent => {
                    let (blockhash, last_valid_block_height) =
                        client.get_latest_blockhash().await?;
                    let message = compile_message(
                        &payer.pubkey(),
                        core::slice::from_ref(&attempt.step.instruction),
                        blockhash,
                        attempt.step.budget,
                    )?;
                    // The signer list is not `Send`, it ends before the next await.
                    let transaction = {
                        let mut all: Vec<&dyn Signer> = vec![payer];
                        if !attempt.step.signed_by_writer_alone() {
                            all.extend(signers.iter().map(|signer| *signer as &dyn Signer));
                        }
                        sign_transaction(message, &all)?
                    };
                    let sent = unsent.insert(Sent {
                        transaction,
                        last_valid_block_height,
                        refused: None,
                    });
                    let config = RpcSendTransactionConfig {
                        preflight_commitment: Some(CommitmentLevel::Confirmed),
                        ..RpcSendTransactionConfig::default()
                    };
                    sent.refused = client
                        .send_transaction_with_config(&sent.transaction, config)
                        .await
                        .err()
                        .and_then(transaction_error);
                    sent
                }
            };
            let signature = sent.transaction.signatures[0];
            let last_valid_block_height = sent.last_valid_block_height;
            // 3. An unknown status returns as pending below, with nothing released.
            let observed = match sent.refused.clone() {
                Some(error) => Outcome::Failed(error),
                None => outcome(client.zolana(), signature, last_valid_block_height).await?,
            };
            // 4. Failed or expired is final, the transaction can no longer land, so the buffer
            // closes here and never earlier. The close runs ahead of the stale check, a new proof
            // writes another buffer and would orphan the rent of the old one.
            let observed = match observed {
                Outcome::Failed(error) => {
                    if let Some(frame) = attempt.step.buffer() {
                        boxed(|| frame.abandon(client.zolana(), payer)).await?;
                    }
                    match attempt
                        .step
                        .bound
                        .reproof_fixes(&error, client.zolana())
                        .await?
                    {
                        true => Outcome::Stale(error),
                        false => Outcome::Failed(error),
                    }
                }
                observed => observed,
            };
            if let Some(status) = self.settle(signature, observed) {
                return Ok(status);
            }
        }
    }

    pub async fn send_until_settled<R: AsyncRpc, I: RingIndexerBackend>(
        &mut self,
        client: &RingClient<R, I>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<SettledSubmission, RingError> {
        loop {
            match boxed(|| self.send(client, payer, signers)).await? {
                SubmissionStatus::Settled(settled) => return Ok(settled),
                SubmissionStatus::Pending { .. } => tokio::time::sleep(PENDING_POLL).await,
            }
        }
    }

    /// Proves the next attempt, nothing held and every earlier signature final.
    async fn prepare<R: AsyncRpc, I: RingIndexerBackend>(
        &mut self,
        client: &RingClient<R, I>,
        payer: &(dyn Signer + Sync),
        signers: &[&(dyn Signer + Sync)],
    ) -> Result<Attempt, RingError> {
        if self.attempts > 0 {
            self.operation.refresh_for_retry()?;
        }
        let public: Vec<Address> = core::iter::once(payer.pubkey())
            .chain(signers.iter().map(|signer| signer.pubkey()))
            .collect();
        self.operation
            .check_public_signers(client.zolana(), &public)
            .await?;
        let proved = boxed(|| {
            self.operation
                .prove(client, payer.pubkey(), self.priority_fee)
        })
        .await?;
        let message = FitSigners::new(payer.pubkey());
        let fit = match self.operation.settles_from_buffer() {
            true => TransactionFit::of(&proved.instruction, message, proved.budget)?,
            false => TransactionFit::inline(&proved.instruction, message, proved.budget)?,
        };
        let step = match fit.transport {
            FitTransport::Inline => Step::inline(proved),
            FitTransport::Buffered => Step::upload(proved, payer.pubkey(), self.priority_fee)?,
        };
        self.attempts += 1;
        Ok(Attempt { step, sent: None })
    }

    /// `None` continues the loop, with the next upload step held or a stale failure below the
    /// attempt limit released to a new proof.
    fn settle(&mut self, signature: Signature, outcome: Outcome) -> Option<SubmissionStatus> {
        let settled = match outcome {
            Outcome::Unknown => return Some(SubmissionStatus::Pending { signature }),
            Outcome::Confirmed { slot } => {
                let next = self
                    .pending
                    .take()
                    .and_then(|attempt| attempt.step.after_confirmation());
                if let Some(step) = next {
                    self.pending = Some(Attempt { step, sent: None });
                    return None;
                }
                SettledSubmission::Confirmed { signature, slot }
            }
            Outcome::Failed(error) => {
                self.pending = None;
                SettledSubmission::Failed { signature, error }
            }
            Outcome::Stale(error) => {
                self.pending = None;
                if self.attempts < MAX_ATTEMPTS {
                    return None;
                }
                SettledSubmission::Failed { signature, error }
            }
        };
        let terminal = SubmissionStatus::Settled(settled);
        self.terminal = Some(terminal.clone());
        Some(terminal)
    }
}

impl RingOperation<'_> {
    const fn settles_from_buffer(&self) -> bool {
        matches!(
            self,
            Self::Transfer(_) | Self::Anonymous(_) | Self::PublicOwners(_) | Self::Delegate(_)
        )
    }

    fn refresh_for_retry(&mut self) -> Result<(), RingError> {
        if let Self::Deposit(deposit) = self {
            **deposit = deposit.fresh_attempt()?;
        }
        Ok(())
    }

    async fn check_public_signers(
        &self,
        client: &(impl AsyncRpc + ?Sized),
        signers: &[Address],
    ) -> Result<(), RingError> {
        let signers = signers.iter().copied();
        match self {
            Self::Anonymous(transfer) => transfer.check_public_signers(signers),
            Self::Merge(operation) => {
                let config = operation.prepared.ring().require_config(client).await?;
                operation.prepared.check_public_signers(signers, &config)
            }
            Self::Deposit(deposit) => deposit.check_public_signers(signers),
            Self::Transfer(_)
            | Self::PublicOwners(_)
            | Self::Delegate(_)
            | Self::Instruction(_) => Ok(()),
        }
    }

    fn with_priority_fee(self, lamports: u64) -> Self {
        match self {
            Self::Transfer(transfer) => {
                Self::Transfer(Box::new(transfer.with_priority_fee(lamports)))
            }
            Self::Anonymous(transfer) => {
                Self::Anonymous(Box::new(transfer.with_priority_fee(lamports)))
            }
            Self::PublicOwners(transfer) => {
                Self::PublicOwners(Box::new(transfer.with_priority_fee(lamports)))
            }
            Self::Delegate(transfer) => {
                Self::Delegate(Box::new(transfer.with_priority_fee(lamports)))
            }
            Self::Merge(operation) => Self::Merge(Box::new(RingMergeOperation {
                prepared: operation.prepared.with_priority_fee(lamports),
                input: operation.input,
            })),
            Self::Deposit(deposit) => Self::Deposit(Box::new(deposit.with_priority_fee(lamports))),
            Self::Instruction(instruction) => Self::Instruction(instruction),
        }
    }

    async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        payer: Address,
        priority_fee: Option<u64>,
    ) -> Result<Proved, RingError> {
        let proved = |instruction, tag, bound| Proved {
            instruction,
            budget: send_budget(tag, priority_fee),
            bound,
        };
        Ok(match self {
            Self::Transfer(transfer) => {
                let proven = boxed(|| transfer.prove(client)).await?;
                proved(
                    proven.instruction()?,
                    InstructionTag::Transfer,
                    proven.bound(),
                )
            }
            Self::Anonymous(transfer) => {
                let proven = boxed(|| transfer.prove(client)).await?;
                proved(
                    proven.instruction()?,
                    InstructionTag::Transfer,
                    proven.bound(),
                )
            }
            Self::PublicOwners(transfer) => {
                let proven = boxed(|| transfer.prove(client)).await?;
                proved(
                    proven.instruction()?,
                    InstructionTag::Transfer,
                    proven.bound(),
                )
            }
            Self::Delegate(transfer) => {
                let proven = boxed(|| transfer.prove(client)).await?;
                proved(
                    proven.instruction()?,
                    InstructionTag::AuthorityTransfer,
                    proven.bound(),
                )
            }
            Self::Merge(operation) => {
                let proven = boxed(|| {
                    operation
                        .prepared
                        .clone()
                        .prove(operation.input.clone(), payer, client)
                })
                .await?;
                proved(
                    proven.instruction(payer)?,
                    InstructionTag::Merge,
                    BoundState {
                        roots: proven.bound_root().into_iter().collect(),
                        ..BoundState::default()
                    },
                )
            }
            Self::Deposit(deposit) => {
                let proven = boxed(|| deposit.prove_bound(client)).await?;
                proved(
                    proven.instruction,
                    InstructionTag::Deposit,
                    BoundState {
                        roots: proven.roots,
                        policy: proven.policy,
                    },
                )
            }
            Self::Instruction(instruction) => {
                let tag = instruction
                    .data
                    .first()
                    .and_then(|tag| InstructionTag::try_from(*tag).ok())
                    .ok_or(CustomRingError::InvalidInstructionData)?;
                proved(instruction.clone(), tag, BoundState::default())
            }
        })
    }
}

/// Past expiry only the ledger's absent answer releases the attempt and a failed lookup surfaces.
async fn outcome(
    client: &(impl AsyncRpc + ?Sized),
    signature: Signature,
    last_valid_block_height: u64,
) -> Result<Outcome, RingError> {
    if let Ok(Some(outcome)) = observe(client, signature).await {
        return Ok(outcome);
    }
    if client.get_block_height().await? <= last_valid_block_height {
        return Ok(Outcome::Unknown);
    }
    // A signature that landed between the lookups or left the status cache reads absent above. A
    // release on that answer rebuilds the operation and debits a deposit's funder a second time.
    let statuses = client
        .get_signature_statuses_with_history(vec![signature])
        .await?;
    Ok(decode_status(statuses).unwrap_or(Outcome::Failed(TransactionError::BlockhashNotFound)))
}

/// One transaction to its end, nothing proves again.
pub(crate) async fn send_and_settle(
    client: &(impl AsyncRpc + ?Sized),
    transaction: &VersionedTransaction,
    last_valid_block_height: u64,
) -> Result<SettledSubmission, RingError> {
    let signature = transaction.signatures[0];
    let config = RpcSendTransactionConfig {
        preflight_commitment: Some(CommitmentLevel::Confirmed),
        ..RpcSendTransactionConfig::default()
    };
    if let Some(error) = client
        .send_transaction_with_config(transaction, config)
        .await
        .err()
        .and_then(transaction_error)
    {
        return Ok(SettledSubmission::Failed { signature, error });
    }
    loop {
        match outcome(client, signature, last_valid_block_height).await? {
            Outcome::Unknown => tokio::time::sleep(PENDING_POLL).await,
            Outcome::Confirmed { slot } => {
                return Ok(SettledSubmission::Confirmed { signature, slot })
            }
            Outcome::Failed(error) | Outcome::Stale(error) => {
                return Ok(SettledSubmission::Failed { signature, error })
            }
        }
    }
}

/// `None` for a signature the cluster does not know.
async fn observe(
    client: &(impl AsyncRpc + ?Sized),
    signature: Signature,
) -> Result<Option<Outcome>, RingError> {
    let statuses = client.get_signature_statuses(vec![signature]).await?;
    Ok(decode_status(statuses))
}

fn transaction_error(error: ClientError) -> Option<TransactionError> {
    match error {
        ClientError::SolanaRpcTransaction { source, .. } => source.get_transaction_error(),
        _ => None,
    }
}

fn decode_status(statuses: Vec<Option<TransactionStatus>>) -> Option<Outcome> {
    let Ok([status]) = <[_; 1]>::try_from(statuses) else {
        return Some(Outcome::Unknown);
    };
    let status = status?;
    if !matches!(
        status.confirmation_status,
        Some(TransactionConfirmationStatus::Confirmed | TransactionConfirmationStatus::Finalized)
    ) {
        return Some(Outcome::Unknown);
    }
    Some(match status.err {
        None => Outcome::Confirmed { slot: status.slot },
        Some(error) => Outcome::Failed(error),
    })
}

/// The attempt compiles a one-instruction message.
fn ring_error(error: &TransactionError) -> Option<u32> {
    match error {
        TransactionError::InstructionError(0, InstructionError::Custom(code)) => Some(*code),
        _ => None,
    }
}
