//! The message a wallet signs for Ring RPC, checked against the request the wallet made.

use custom_ring_interface::cosign::ApprovalMask;
use custom_ring_interface::{
    compute_unit_limit, frame_digest, settle_buffered_data, stream::slot_tag, tag, AuditRecord,
    DepositPrefix, FrameBuffer, InstructionTag, ParsedTransact, RecordKind, RingMode, RingRail,
    RingTransactData, STORAGE_PROGRAM_ID,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{v1, VersionedMessage};
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::MAX_LOADED_ACCOUNTS_DATA_SIZE;
use spr_indexer_api::{Hash, SerializablePubkey};
use spr_keypair::{PublicKey, ShieldedAddress, X25519Pubkey};
use spr_program::instruction::CreateAssociatedTokenAccount;
use spr_transaction::{Mint, Utxo, WalletUtxo};
use thiserror::Error;
use zolana_ring_client::{
    rpc::{
        PrepareAuthorityTransferRequest, RelayEnrollInputs, RelayId, RelayQuote, TxViewingSecret,
        ENROLL_COMPUTE_UNITS,
    },
    AuditEnvelope, OpenedAudit,
};
use zolana_ring_policy::{ApprovalTotals, Member, OutputTotals, PublicTotals};

use crate::{pipeline::delegate_rail, CustomRing, CustomRingConfig, PendingSignature, RingError};

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MessageMismatch {
    #[error("the message does not decode as one valid canonical message")]
    Undecodable,
    #[error("the message is not a v1 message")]
    NotV1,
    #[error("the message fee payer is the signer or not the quoted relay fee payer")]
    FeePayer,
    #[error("the message budget is outside the operation's bounds")]
    Budget,
    #[error("the message carries instructions the request did not ask for")]
    Instructions,
    #[error("the message calls a program other than the ring")]
    Program,
    #[error("the message data differs from the request")]
    Data,
    #[error("the message accounts differ from the request")]
    Accounts,
    #[error("the message pays an owner the request does not name")]
    Recipients,
    #[error("the message publishes a transaction key other than the one the request names")]
    TransactionKey,
    #[error("the proven approval bits ask more than the co-signer accepts")]
    ApprovalMaskUnaccepted,
    #[error("the frame carries no approval digest and exact approval was asked")]
    MissingApprovalDigest,
    #[error("the opening does not rebuild the frame's approval digest")]
    FalseApprovalOpening,
    #[error("the opening's blinder served an earlier attempt")]
    ReusedApprovalBlinder,
    #[error("the totals pass a limit or name an asset with no limit")]
    ApprovalOverLimit,
    #[error("the message spends a held note the terms do not name")]
    SpendsUnnamedNote,
    #[error("the request asks for no signature")]
    Unrequested,
    #[error("the message settles a buffer, read it from the chain before signing")]
    SettlesBuffer,
    #[error("the signing key is not the key the request names")]
    Signer,
}

/// Built from the wallet's own request, never from Ring RPC's answer.
#[derive(Clone, Debug)]
pub(crate) enum ExpectedMessage {
    Deposit(ExpectedDeposit),
    Delegate(ExpectedDelegate),
    /// The sealing wallet hands each signer what it reads and signs nothing itself.
    Sealed(SealedTerms),
    PublicOwner(ExpectedPublicOwner),
    CoSigner(ExpectedCoSigner),
    Enroll(ExpectedEnroll),
}

/// The enrollment the owner proved and signed, the message differs from it in nothing.
#[derive(Clone, Debug)]
pub(crate) struct ExpectedEnroll {
    pub fee_payer: Address,
    pub inputs: RelayEnrollInputs,
}

/// What one public owner agrees to, its own slots and notes alone, the sealing wallet hands it over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayTransferTerms {
    pub ring: SerializablePubkey,
    pub fee_payer: SerializablePubkey,
    pub signer: SerializablePubkey,
    /// Each rebuilds its slot's commitment, no key opens another slot.
    pub slots: Vec<SlotOpening>,
    /// The signer's notes the transfer spends.
    pub nullifiers: Vec<Hash>,
    /// The token accounts the fee payer creates ahead of the ring instruction.
    pub setup: Vec<TokenAccountCreate>,
}

/// The preimage of one published output's `utxo_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SlotOpening {
    pub slot: u32,
    pub owner: SerializablePubkey,
    pub nullifier_pk: Hash,
    pub mint: SerializablePubkey,
    pub amount: u64,
    pub blinding: Hash,
    pub tree_id: u16,
    pub data_hash: Hash,
    pub ring_data_hash: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenAccountCreate {
    pub owner: SerializablePubkey,
    pub mint: SerializablePubkey,
    pub token_program: SerializablePubkey,
}

#[derive(Clone, Debug)]
pub(crate) struct SealedTerms {
    pub owners: Vec<RelayTransferTerms>,
    pub approval: Option<ApprovalOpening>,
}

/// The totals and blinder a frame's digest commits, no transaction secret and no slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApprovalOpening {
    pub blinder: Hash,
    pub outputs: Vec<OutputTotalsOpening>,
    pub public: Vec<PublicTotalsOpening>,
}

/// Amounts are decimal text, a `u128` does not survive every JSON reader.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OutputTotalsOpening {
    pub asset: Hash,
    pub peak: String,
    pub outflow: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PublicTotalsOpening {
    pub asset: Hash,
    pub peak: String,
    pub outflow: String,
    pub gross: String,
}

/// An outside co-signer reads the proven bits or the totals, never a slot.
#[must_use]
#[derive(Clone, Debug)]
pub enum CoSignerRule {
    /// The proven mask alone, no opening and no digest.
    Threshold {
        accepts: ApprovalMask,
    },
    Exact(ExactApproval),
}

#[must_use]
#[derive(Clone, Debug)]
pub struct ExactApproval {
    pub opening: ApprovalOpening,
    /// An asset the totals name with no limit here is refused.
    pub limits: Vec<ApprovalLimit>,
    /// The blinders of its earlier attempts, the only record of reuse the SDK has.
    pub seen_blinders: Vec<Hash>,
}

/// `peak` bounds one owner's outflow, `outflow` the sum over owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalLimit {
    pub mint: Address,
    pub peak: u128,
    pub outflow: u128,
}

/// A co-signer the frame names, what it signs is the rule it holds.
#[must_use]
pub struct CoSignerApproval<'a> {
    pub relay_id: RelayId,
    pub message: Vec<u8>,
    pub ring: Address,
    pub fee_payer: Address,
    pub signer: Address,
    pub config: &'a CustomRingConfig,
    /// The public creates a relay puts ahead of the ring instruction.
    pub setup: Vec<TokenAccountCreate>,
    pub rule: CoSignerRule,
}

#[derive(Clone, Debug)]
pub(crate) struct ExpectedCoSigner {
    ring: Address,
    fee_payer: Address,
    signer: Address,
    rail: RingRail,
    setup: Vec<Instruction>,
    rule: CoSignerRule,
}

/// One public owner reading its terms against the notes its wallet holds.
#[derive(Clone, Debug)]
pub(crate) struct ExpectedPublicOwner {
    terms: RelayTransferTerms,
    setup: Vec<Instruction>,
    /// From the ring account, a frame read under the wrong rail proves nothing.
    rail: RingRail,
    known_nullifiers: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub(crate) struct ExpectedDeposit {
    pub ring: CustomRing,
    pub fee_payer: Address,
    pub depositor: Address,
    /// The SPP deposit the ring forwards unchanged.
    pub spp: Instruction,
}

#[derive(Clone, Debug)]
pub(crate) struct ExpectedDelegate {
    pub ring: CustomRing,
    pub fee_payer: Address,
    pub delegate: Address,
    /// From the ring account, a frame read under the wrong rail or auditor proves nothing.
    pub rail: RingRail,
    pub auditor: X25519Pubkey,
    pub tx_viewing_key: TxViewingSecret,
    /// Change returns to an input's owner.
    pub sources: Vec<ExpectedOwner>,
    pub payments: Vec<ExpectedPayment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedOwner {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub viewing_u: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedPayment {
    pub owner: ExpectedOwner,
    pub mint: Address,
    pub amount: u64,
}

/// Only a check builds one.
#[must_use = "sign the verified message"]
#[derive(Debug)]
pub struct VerifiedMessage {
    bytes: Vec<u8>,
    signer: Address,
}

struct Envelope {
    ring: CustomRing,
    program: Address,
    units: u32,
    fee_payer: Address,
    signer: Address,
    /// Ahead of the ring instruction, exactly these.
    setup: Vec<Instruction>,
}

impl ExpectedMessage {
    pub fn check(
        &self,
        message: &[u8],
        signer: Address,
    ) -> Result<VerifiedMessage, MessageMismatch> {
        match self {
            Self::Deposit(deposit) => deposit.check(message),
            Self::Delegate(delegate) => delegate.check(message),
            Self::Sealed(_) => Err(MessageMismatch::Unrequested),
            Self::PublicOwner(owner) => check_inline(owner, message, signer),
            Self::CoSigner(co_signer) => check_inline(co_signer, message, signer),
            Self::Enroll(enroll) => enroll.check(message),
        }
    }

    pub fn settled_buffer(
        &self,
        message: &[u8],
        signer: Address,
    ) -> Result<Option<Address>, MessageMismatch> {
        match self {
            Self::Deposit(_) | Self::Sealed(_) | Self::Enroll(_) => Ok(None),
            Self::Delegate(delegate) => delegate.settled_buffer(message),
            Self::PublicOwner(owner) => settled_buffer(owner, message, signer),
            Self::CoSigner(co_signer) => settled_buffer(co_signer, message, signer),
        }
    }

    pub fn check_settled(
        &self,
        message: &[u8],
        buffer: &[u8],
        signer: Address,
    ) -> Result<VerifiedMessage, MessageMismatch> {
        match self {
            Self::Deposit(_) | Self::Enroll(_) => Err(MessageMismatch::Data),
            Self::Delegate(delegate) => delegate.check_settled(message, buffer),
            Self::Sealed(_) => Err(MessageMismatch::Unrequested),
            Self::PublicOwner(owner) => check_settled(owner, message, buffer, signer),
            Self::CoSigner(co_signer) => check_settled(co_signer, message, buffer, signer),
        }
    }

    pub fn terms_for(&self, signer: Address) -> Option<&RelayTransferTerms> {
        match self {
            Self::Sealed(sealed) => sealed.owners.iter().find(|terms| terms.signer.0 == signer),
            Self::PublicOwner(owner) => (owner.terms.signer.0 == signer).then_some(&owner.terms),
            Self::Deposit(_) | Self::Delegate(_) | Self::Enroll(_) | Self::CoSigner(_) => None,
        }
    }

    pub fn approval_opening(&self) -> Option<&ApprovalOpening> {
        match self {
            Self::Sealed(sealed) => sealed.approval.as_ref(),
            _ => None,
        }
    }
}

/// A frame a signer reads inline or, past one transaction, from the buffer its digest names.
trait ExpectedFrame {
    const TAG: InstructionTag;

    fn envelope(&self, signer: Address, tag: InstructionTag) -> Result<Envelope, MessageMismatch>;

    fn check_frame(
        &self,
        signer: Address,
        frame: &[u8],
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch>;
}

fn check_inline<E: ExpectedFrame>(
    expected: &E,
    message: &[u8],
    signer: Address,
) -> Result<VerifiedMessage, MessageMismatch> {
    let envelope = expected.envelope(signer, E::TAG)?;
    let instruction = envelope.open(message)?;
    if instruction.data.first() == Some(&tag::SETTLE_BUFFERED) {
        return Err(MessageMismatch::SettlesBuffer);
    }
    expected.check_frame(signer, &instruction.data, &instruction.accounts)?;
    Ok(envelope.verified(message))
}

/// The account a settling message reads its frame from, `None` on an inline message.
fn settled_buffer<E: ExpectedFrame>(
    expected: &E,
    message: &[u8],
    signer: Address,
) -> Result<Option<Address>, MessageMismatch> {
    let instruction = expected
        .envelope(signer, InstructionTag::SettleBuffered)?
        .open(message)?;
    match instruction.data.first() == Some(&tag::SETTLE_BUFFERED) {
        true => Ok(instruction.accounts.first().map(|meta| meta.pubkey)),
        false => Ok(None),
    }
}

/// The digest binds the buffer's frame, every check of an inline message then reads it.
fn check_settled<E: ExpectedFrame>(
    expected: &E,
    message: &[u8],
    buffer: &[u8],
    signer: Address,
) -> Result<VerifiedMessage, MessageMismatch> {
    let envelope = expected.envelope(signer, InstructionTag::SettleBuffered)?;
    let instruction = envelope.open(message)?;
    let [_, _, inner @ ..] = instruction.accounts.as_slice() else {
        return Err(MessageMismatch::Accounts);
    };
    let frame = FrameBuffer::of(buffer)
        .map_err(|_| MessageMismatch::Data)?
        .frame();
    let digest = frame_digest(frame).map_err(|_| MessageMismatch::Data)?;
    if instruction.data != settle_buffered_data(&digest) {
        return Err(MessageMismatch::Data);
    }
    expected.check_frame(signer, frame, inner)?;
    Ok(envelope.verified(message))
}

/// The proof binds each record to its slot under the key the frame publishes, a slot tag is an unproved hint.
fn open_stream(
    parsed: &ParsedTransact<'_>,
    tx_viewing_key: &TxViewingSecret,
    auditor: &X25519Pubkey,
) -> Result<OpenedAudit, MessageMismatch> {
    let data = parsed.data();
    let tx_viewing_key = tx_viewing_key
        .key()
        .map_err(|_| MessageMismatch::TransactionKey)?;
    if *data.tx_viewing_u != tx_viewing_key.pubkey().u() {
        return Err(MessageMismatch::TransactionKey);
    }
    AuditEnvelope {
        eph_u: *data.tx_viewing_u,
        salt: data.salt,
        ciphertext: data.envelope,
    }
    .open_sealed(&tx_viewing_key, auditor, parsed.audit_stream())
    .map_err(|_| MessageMismatch::Data)
}

/// The signer named once and read only, the ring account first.
fn check_signer(envelope: &Envelope, accounts: &[AccountMeta]) -> Result<(), MessageMismatch> {
    let mut named = accounts
        .iter()
        .filter(|meta| meta.pubkey == envelope.signer);
    let signs_once = matches!(
        (named.next(), named.next()),
        (Some(meta), None) if meta.is_signer && !meta.is_writable
    );
    if !signs_once || !envelope.reads_only(accounts.get(..1).unwrap_or_default()) {
        return Err(MessageMismatch::Accounts);
    }
    Ok(())
}

impl ExpectedDeposit {
    /// The ring prefix carries the proof and revisions, every SPP byte and account is the wallet's.
    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        let envelope = Envelope {
            ring: self.ring,
            program: self.ring.program_id(),
            units: compute_unit_limit(InstructionTag::Deposit),
            fee_payer: self.fee_payer,
            signer: self.depositor,
            setup: Vec::new(),
        };
        let instruction = envelope.open(message)?;
        let spp_data = instruction
            .data
            .get(size_of::<DepositPrefix>()..)
            .filter(|_| instruction.data.first() == Some(&tag::DEPOSIT));
        if spp_data != Some(self.spp.data.as_slice()) {
            return Err(MessageMismatch::Data);
        }
        let ring_accounts = instruction
            .accounts
            .len()
            .checked_sub(self.spp.accounts.len())
            .ok_or(MessageMismatch::Accounts)?;
        let (prefix, spp_accounts) = instruction.accounts.split_at(ring_accounts);
        if spp_accounts != self.spp.accounts.as_slice() || !envelope.reads_only(prefix) {
            return Err(MessageMismatch::Accounts);
        }
        Ok(envelope.verified(message))
    }
}

impl ExpectedEnroll {
    /// A swapped registry or authorization reads the owner's key into another account.
    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        let envelope = Envelope {
            ring: CustomRing::new(self.inputs.ring_program_id),
            program: STORAGE_PROGRAM_ID,
            units: ENROLL_COMPUTE_UNITS,
            fee_payer: self.fee_payer,
            signer: self.inputs.owner,
            setup: Vec::new(),
        };
        let instruction = envelope.open(message)?;
        let expected = self.inputs.instruction(self.fee_payer);
        if instruction.accounts != expected.accounts {
            return Err(MessageMismatch::Accounts);
        }
        let signed = RelayEnrollInputs {
            instruction_data: instruction.data,
            ..self.inputs.clone()
        };
        if signed.request_digest() != self.inputs.request_digest() {
            return Err(MessageMismatch::Data);
        }
        Ok(envelope.verified(message))
    }
}

impl ExpectedDelegate {
    pub fn new(
        request: &PrepareAuthorityTransferRequest,
        quote: &RelayQuote,
        config: &CustomRingConfig,
    ) -> Result<Self, RingError> {
        let transfer = &request.transfer;
        Ok(Self {
            ring: CustomRing::new(request.ring.0),
            fee_payer: quote.fee_payer.0,
            delegate: request.delegate.0,
            rail: delegate_rail(config.mode),
            auditor: config.auditor_pubkey,
            tx_viewing_key: request.tx_viewing_key.clone(),
            sources: transfer
                .sources
                .iter()
                .map(|source| ExpectedOwner::of(&source.0))
                .collect::<Result<_, RingError>>()?,
            payments: transfer
                .payments
                .iter()
                .map(|payment| {
                    Ok(ExpectedPayment {
                        owner: ExpectedOwner::of(&payment.recipient.0)?,
                        mint: payment.mint.0,
                        amount: payment.amount,
                    })
                })
                .collect::<Result<_, RingError>>()?,
        })
    }

    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        check_inline(self, message, self.delegate)
    }

    pub fn settled_buffer(&self, message: &[u8]) -> Result<Option<Address>, MessageMismatch> {
        settled_buffer(self, message, self.delegate)
    }

    pub fn check_settled(
        &self,
        message: &[u8],
        buffer: &[u8],
    ) -> Result<VerifiedMessage, MessageMismatch> {
        check_settled(self, message, buffer, self.delegate)
    }

    fn check_moved(&self, parsed: &ParsedTransact<'_>) -> Result<(), MessageMismatch> {
        let data = parsed.data();
        let opened = open_stream(parsed, &self.tx_viewing_key, &self.auditor)?;
        // The request names ring payments alone, a leg or a data commitment moves what no one asked.
        if !data.interface_transfers.is_empty() || data.has_data {
            return Err(MessageMismatch::Data);
        }
        let records = data
            .outputs
            .iter()
            .enumerate()
            .map(|(slot, output)| opened.record(slot, output.record))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| MessageMismatch::Data)?;
        let mut unpaid = self.payments.clone();
        for (output, record) in data.outputs.iter().zip(records) {
            match record.kind {
                RecordKind::Dummy => {}
                RecordKind::Exit => return Err(MessageMismatch::Recipients),
                RecordKind::Ring => {
                    let paid = unpaid.iter().position(|payment| payment.matches(&record));
                    match paid {
                        Some(index) => {
                            let payment = unpaid.swap_remove(index);
                            // A wrong hint strands the note with no scan reaching it.
                            if !data.rail.anonymous_frame()
                                && output.owner_tag != slot_tag(payment.owner.viewing_u)
                            {
                                return Err(MessageMismatch::Recipients);
                            }
                        }
                        None if self.sources.iter().any(|source| source.owns(&record)) => {}
                        None => return Err(MessageMismatch::Recipients),
                    }
                }
            }
        }
        match unpaid.is_empty() {
            true => Ok(()),
            false => Err(MessageMismatch::Recipients),
        }
    }
}

impl ExpectedFrame for ExpectedDelegate {
    const TAG: InstructionTag = InstructionTag::AuthorityTransfer;

    fn envelope(&self, signer: Address, tag: InstructionTag) -> Result<Envelope, MessageMismatch> {
        Ok(Envelope {
            ring: self.ring,
            program: self.ring.program_id(),
            units: compute_unit_limit(tag),
            fee_payer: self.fee_payer,
            signer,
            setup: Vec::new(),
        })
    }

    fn check_frame(
        &self,
        signer: Address,
        frame: &[u8],
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        let parsed = frame
            .split_first()
            .filter(|(tag, _)| **tag == tag::AUTHORITY_TRANSFER)
            .and_then(|(_, data)| RingTransactData::parse(data, self.rail).ok())
            .ok_or(MessageMismatch::Data)?;
        self.check_moved(&parsed)?;
        check_signer(&self.envelope(signer, Self::TAG)?, accounts)
    }
}

/// A public owner's approval, its own notes are a required input since its signature is the only gate on them.
#[must_use]
pub struct OwnerApproval<'a> {
    pub relay_id: RelayId,
    pub message: Vec<u8>,
    pub terms: RelayTransferTerms,
    pub config: &'a CustomRingConfig,
    /// Every note the wallet holds, the nullifiers are the wallet's own derivation.
    pub known_notes: &'a [WalletUtxo],
}

impl OwnerApproval<'_> {
    pub fn pending(self) -> PendingSignature {
        PendingSignature::expecting(
            self.relay_id,
            self.message,
            ExpectedMessage::PublicOwner(ExpectedPublicOwner::new(
                self.terms,
                self.config.mode,
                self.known_notes.iter().map(|note| note.nullifier).collect(),
            )),
        )
    }
}

fn setup_instructions(fee_payer: Address, setup: &[TokenAccountCreate]) -> Vec<Instruction> {
    setup
        .iter()
        .map(|create| {
            CreateAssociatedTokenAccount {
                payer: fee_payer,
                owner: create.owner.0,
                mint: create.mint.0,
                token_program: create.token_program.0,
            }
            .instruction()
        })
        .collect()
}

const fn transfer_rail(mode: RingMode) -> RingRail {
    match mode {
        RingMode::Anonymous => RingRail::Anonymous,
        RingMode::Confidential => RingRail::Confidential,
    }
}

impl ExpectedPublicOwner {
    pub fn new(terms: RelayTransferTerms, mode: RingMode, known_nullifiers: Vec<[u8; 32]>) -> Self {
        Self {
            setup: setup_instructions(terms.fee_payer.0, &terms.setup),
            rail: transfer_rail(mode),
            known_nullifiers,
            terms,
        }
    }

    /// A slot of another owner, an opening that rebuilds another commitment or a held note the terms do not name binds nothing.
    fn check_moved(&self, data: &RingTransactData<'_>) -> Result<(), MessageMismatch> {
        let terms = &self.terms;
        if terms.slots.is_empty() && terms.nullifiers.is_empty() {
            return Err(MessageMismatch::Unrequested);
        }
        for opening in &terms.slots {
            let published = data
                .outputs
                .get(opening.slot as usize)
                .ok_or(MessageMismatch::Recipients)?;
            let rebuilt = opening.utxo_hash(terms.ring.0)?;
            if opening.owner != terms.signer || rebuilt != *published.hash {
                return Err(MessageMismatch::Recipients);
            }
        }
        // A named note the wallet cannot place means no list stood behind the check.
        let named_and_held = terms.nullifiers.iter().all(|nullifier| {
            data.nullifiers.contains(&nullifier.0) && self.known_nullifiers.contains(&nullifier.0)
        });
        if !named_and_held {
            return Err(MessageMismatch::Data);
        }
        let spends_another = data.nullifiers.iter().any(|spent| {
            self.known_nullifiers.contains(spent)
                && !terms.nullifiers.iter().any(|named| named.0 == *spent)
        });
        match spends_another {
            true => Err(MessageMismatch::SpendsUnnamedNote),
            false => Ok(()),
        }
    }
}

impl SlotOpening {
    fn utxo_hash(&self, ring: Address) -> Result<[u8; 32], MessageMismatch> {
        Utxo {
            owner: PublicKey::from_ed25519(self.owner.0.as_array()),
            asset: Mint::new(self.mint.0, 0),
            amount: self.amount,
            blinding: self.blinding.0,
            ring_program_id: Some(ring),
            data: Default::default(),
        }
        .hash(
            &self.nullifier_pk.0,
            &self.data_hash.0,
            &self.ring_data_hash.0,
            self.tree_id,
        )
        .map_err(|_| MessageMismatch::Recipients)
    }
}

impl ExpectedFrame for ExpectedPublicOwner {
    const TAG: InstructionTag = InstructionTag::Transfer;

    /// Another key stays refused.
    fn envelope(&self, signer: Address, tag: InstructionTag) -> Result<Envelope, MessageMismatch> {
        if self.terms.signer.0 != signer {
            return Err(MessageMismatch::Unrequested);
        }
        Ok(Envelope {
            ring: CustomRing::new(self.terms.ring.0),
            program: self.terms.ring.0,
            units: compute_unit_limit(tag),
            fee_payer: self.terms.fee_payer.0,
            signer,
            setup: self.setup.clone(),
        })
    }

    fn check_frame(
        &self,
        signer: Address,
        frame: &[u8],
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        let parsed = frame
            .split_first()
            .filter(|(tag, _)| **tag == tag::TRANSFER)
            .and_then(|(_, data)| RingTransactData::parse(data, self.rail).ok())
            .ok_or(MessageMismatch::Data)?;
        self.check_moved(parsed.data())?;
        check_signer(&self.envelope(signer, Self::TAG)?, accounts)
    }
}

impl ApprovalOpening {
    pub fn of(totals: &ApprovalTotals, blinder: &[u8; 32]) -> Self {
        Self {
            blinder: Hash(*blinder),
            outputs: totals
                .outputs
                .iter()
                .map(|slot| OutputTotalsOpening {
                    asset: Hash(slot.asset),
                    peak: slot.peak.to_string(),
                    outflow: slot.outflow.to_string(),
                })
                .collect(),
            public: totals
                .public
                .iter()
                .map(|slot| PublicTotalsOpening {
                    asset: Hash(slot.asset),
                    peak: slot.peak.to_string(),
                    outflow: slot.outflow.to_string(),
                    gross: slot.gross.to_string(),
                })
                .collect(),
        }
    }

    fn totals(&self) -> Option<ApprovalTotals> {
        Some(ApprovalTotals {
            outputs: self
                .outputs
                .iter()
                .map(|slot| {
                    Some(OutputTotals {
                        asset: slot.asset.0,
                        peak: slot.peak.parse().ok()?,
                        outflow: slot.outflow.parse().ok()?,
                    })
                })
                .collect::<Option<_>>()?,
            public: self
                .public
                .iter()
                .map(|slot| {
                    Some(PublicTotals {
                        asset: slot.asset.0,
                        peak: slot.peak.parse().ok()?,
                        outflow: slot.outflow.parse().ok()?,
                        gross: slot.gross.parse().ok()?,
                    })
                })
                .collect::<Option<_>>()?,
        })
    }
}

impl CoSignerApproval<'_> {
    pub fn pending(self) -> PendingSignature {
        PendingSignature::expecting(
            self.relay_id,
            self.message,
            ExpectedMessage::CoSigner(ExpectedCoSigner {
                ring: self.ring,
                fee_payer: self.fee_payer,
                signer: self.signer,
                rail: transfer_rail(self.config.mode),
                setup: setup_instructions(self.fee_payer, &self.setup),
                rule: self.rule,
            }),
        )
    }
}

impl ExactApproval {
    /// The digest binds the totals, the limits then read them with no slot opened.
    fn check(&self, digest: Option<&[u8; 32]>) -> Result<(), MessageMismatch> {
        let digest = digest.ok_or(MessageMismatch::MissingApprovalDigest)?;
        let blinder = &self.opening.blinder;
        if self.seen_blinders.contains(blinder) {
            return Err(MessageMismatch::ReusedApprovalBlinder);
        }
        let totals = self
            .opening
            .totals()
            .ok_or(MessageMismatch::FalseApprovalOpening)?;
        let opens = totals
            .commitment(&blinder.0)
            .is_ok_and(|commitment| commitment == *digest);
        if !opens {
            return Err(MessageMismatch::FalseApprovalOpening);
        }
        let named = totals
            .outputs
            .iter()
            .map(|slot| slot.asset)
            .chain(totals.public.iter().map(|slot| slot.asset))
            .filter(|asset| *asset != [0; 32]);
        for asset in named {
            let limit = self
                .limits
                .iter()
                .find(|limit| {
                    Member::asset(&limit.mint).is_ok_and(|field| *field.as_bytes() == asset)
                })
                .ok_or(MessageMismatch::ApprovalOverLimit)?;
            if totals.peak_of(&asset) > limit.peak || totals.outflow_of(&asset) > limit.outflow {
                return Err(MessageMismatch::ApprovalOverLimit);
            }
        }
        Ok(())
    }
}

impl ExpectedFrame for ExpectedCoSigner {
    const TAG: InstructionTag = InstructionTag::Transfer;

    fn envelope(&self, signer: Address, tag: InstructionTag) -> Result<Envelope, MessageMismatch> {
        if self.signer != signer {
            return Err(MessageMismatch::Unrequested);
        }
        Ok(Envelope {
            ring: CustomRing::new(self.ring),
            program: self.ring,
            units: compute_unit_limit(tag),
            fee_payer: self.fee_payer,
            signer,
            setup: self.setup.clone(),
        })
    }

    fn check_frame(
        &self,
        signer: Address,
        frame: &[u8],
        accounts: &[AccountMeta],
    ) -> Result<(), MessageMismatch> {
        let parsed = frame
            .split_first()
            .filter(|(tag, _)| **tag == tag::TRANSFER)
            .and_then(|(_, data)| RingTransactData::parse(data, self.rail).ok())
            .ok_or(MessageMismatch::Data)?;
        let data = parsed.data();
        match &self.rule {
            CoSignerRule::Threshold { accepts } => {
                if data.approval.bits() & !accepts.bits() != 0 {
                    return Err(MessageMismatch::ApprovalMaskUnaccepted);
                }
            }
            CoSignerRule::Exact(exact) => exact.check(data.extensions.approval_totals)?,
        }
        check_signer(&self.envelope(signer, Self::TAG)?, accounts)
    }
}

impl ExpectedOwner {
    fn of(address: &ShieldedAddress) -> Result<Self, RingError> {
        Ok(Self {
            owner_key: address.signing_pubkey.confidential_view_tag()?,
            nullifier_pk: address.nullifier_pubkey,
            viewing_u: address.viewing_pubkey.u(),
        })
    }

    fn owns(&self, record: &AuditRecord) -> bool {
        record.owner_key == self.owner_key && record.nullifier_pk == self.nullifier_pk
    }
}

impl ExpectedPayment {
    fn matches(&self, record: &AuditRecord) -> bool {
        self.owner.owns(record)
            && record.mint == self.mint.to_bytes()
            && record.amount == self.amount
    }
}

impl VerifiedMessage {
    pub fn signer(&self) -> Address {
        self.signer
    }

    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, RingError> {
        if signer.try_pubkey()? != self.signer {
            return Err(MessageMismatch::Signer.into());
        }
        Ok(signer.try_sign_message(&self.bytes)?)
    }
}

impl Envelope {
    /// One canonical v1 message the quoted fee payer pays, holding only the ring instruction.
    fn open(&self, bytes: &[u8]) -> Result<Instruction, MessageMismatch> {
        let message = match wincode::deserialize(bytes) {
            Ok(VersionedMessage::V1(message)) => message,
            Ok(VersionedMessage::Legacy(_) | VersionedMessage::V0(_)) => {
                return Err(MessageMismatch::NotV1)
            }
            Err(_) => return Err(MessageMismatch::Undecodable),
        };
        if message.validate().is_err() || message.serialize() != bytes {
            return Err(MessageMismatch::Undecodable);
        }
        if message.fee_payer() != Some(&self.fee_payer) || self.fee_payer == self.signer {
            return Err(MessageMismatch::FeePayer);
        }
        let config = message.config;
        let within_budget = config
            .compute_unit_limit
            .is_some_and(|units| units <= self.units)
            && config
                .loaded_accounts_data_size_limit
                .is_some_and(|size| size <= MAX_LOADED_ACCOUNTS_DATA_SIZE)
            && config.heap_size.is_none();
        if !within_budget {
            return Err(MessageMismatch::Budget);
        }
        let (compiled, setup) = message
            .instructions
            .split_last()
            .ok_or(MessageMismatch::Instructions)?;
        let key = |index: u8| {
            message
                .account_keys
                .get(usize::from(index))
                .copied()
                .ok_or(MessageMismatch::Undecodable)
        };
        if setup.len() != self.setup.len() {
            return Err(MessageMismatch::Instructions);
        }
        for (compiled, expected) in setup.iter().zip(&self.setup) {
            let accounts = compiled
                .accounts
                .iter()
                .map(|&index| key(index))
                .collect::<Result<Vec<_>, _>>()?;
            let same = key(compiled.program_id_index)? == expected.program_id
                && compiled.data == expected.data
                && accounts
                    .iter()
                    .eq(expected.accounts.iter().map(|meta| &meta.pubkey));
            if !same {
                return Err(MessageMismatch::Instructions);
            }
        }
        if key(compiled.program_id_index)? != self.program {
            return Err(MessageMismatch::Program);
        }
        let accounts = compiled
            .accounts
            .iter()
            .map(|&index| {
                Ok(AccountMeta {
                    pubkey: key(index)?,
                    is_signer: message.is_signer(usize::from(index)),
                    is_writable: requests_write(&message, usize::from(index)),
                })
            })
            .collect::<Result<_, MessageMismatch>>()?;
        Ok(Instruction {
            program_id: self.program,
            accounts,
            data: compiled.data.clone(),
        })
    }

    /// The ring account first, then read only accounts that never name the signer.
    fn reads_only(&self, prefix: &[AccountMeta]) -> bool {
        match prefix.split_first() {
            Some((ring, rest)) => {
                *ring == AccountMeta::new_readonly(self.ring.policy_pda(), false)
                    && rest
                        .iter()
                        .all(|meta| !meta.is_writable && meta.pubkey != self.signer)
            }
            None => false,
        }
    }

    fn verified(&self, bytes: &[u8]) -> VerifiedMessage {
        VerifiedMessage {
            bytes: bytes.to_vec(),
            signer: self.signer,
        }
    }
}

/// The header's write role, the one `compile_message` assigns.
fn requests_write(message: &v1::Message, index: usize) -> bool {
    let header = message.header;
    let signers = usize::from(header.num_required_signatures);
    match index < signers {
        true => message.is_signer_writable(index),
        false => {
            index
                < message
                    .account_keys
                    .len()
                    .saturating_sub(usize::from(header.num_readonly_unsigned_accounts))
        }
    }
}
