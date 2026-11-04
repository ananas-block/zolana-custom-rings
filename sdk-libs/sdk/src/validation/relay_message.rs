//! The message a wallet signs for Ring RPC, checked against the request the wallet made.

use custom_ring_interface::{
    compute_unit_limit, frame_digest, settle_buffered_data, stream::slot_tag, tag, AuditRecord,
    DepositPrefix, FrameBuffer, InstructionTag, ParsedTransact, RecordKind, RingRail,
    RingTransactData,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{v1, VersionedMessage};
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::MAX_LOADED_ACCOUNTS_DATA_SIZE;
use spr_keypair::{ShieldedAddress, X25519Pubkey};
use thiserror::Error;
use zolana_ring_client::{
    rpc::{PrepareAuthorityTransferRequest, RelayQuote, TxViewingSecret},
    AuditEnvelope,
};

use crate::{pipeline::delegate_rail, CustomRing, CustomRingConfig, RingError};

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
    pub source: ExpectedOwner,
    pub mint: Address,
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
    fee_payer: Address,
    signer: Address,
    tag: InstructionTag,
}

impl ExpectedMessage {
    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        match self {
            Self::Deposit(deposit) => deposit.check(message),
            Self::Delegate(delegate) => delegate.check(message),
        }
    }
}

impl ExpectedDeposit {
    /// The ring prefix carries the proof and revisions, every SPP byte and account is the wallet's.
    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        let envelope = Envelope {
            ring: self.ring,
            fee_payer: self.fee_payer,
            signer: self.depositor,
            tag: InstructionTag::Deposit,
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
            source: ExpectedOwner::of(&transfer.source.0)?,
            mint: transfer.mint.0,
            payments: transfer
                .payments
                .iter()
                .map(|payment| {
                    Ok(ExpectedPayment {
                        owner: ExpectedOwner::of(&payment.recipient.0)?,
                        amount: payment.amount,
                    })
                })
                .collect::<Result<_, RingError>>()?,
        })
    }

    pub fn check(&self, message: &[u8]) -> Result<VerifiedMessage, MessageMismatch> {
        let envelope = self.envelope(InstructionTag::AuthorityTransfer);
        let instruction = envelope.open(message)?;
        if instruction.data.first() == Some(&tag::SETTLE_BUFFERED) {
            return Err(MessageMismatch::SettlesBuffer);
        }
        self.check_frame(&instruction.data, &instruction.accounts)?;
        Ok(envelope.verified(message))
    }

    /// The account a settling message reads its frame from, `None` on an inline message.
    pub fn settled_buffer(&self, message: &[u8]) -> Result<Option<Address>, MessageMismatch> {
        let instruction = self
            .envelope(InstructionTag::SettleBuffered)
            .open(message)?;
        match instruction.data.first() == Some(&tag::SETTLE_BUFFERED) {
            true => Ok(instruction.accounts.first().map(|meta| meta.pubkey)),
            false => Ok(None),
        }
    }

    /// The digest binds the buffer's frame, every check of an inline message then reads it.
    pub fn check_settled(
        &self,
        message: &[u8],
        buffer: &[u8],
    ) -> Result<VerifiedMessage, MessageMismatch> {
        let envelope = self.envelope(InstructionTag::SettleBuffered);
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
        self.check_frame(frame, inner)?;
        Ok(envelope.verified(message))
    }

    fn envelope(&self, tag: InstructionTag) -> Envelope {
        Envelope {
            ring: self.ring,
            fee_payer: self.fee_payer,
            signer: self.delegate,
            tag,
        }
    }

    fn check_frame(&self, frame: &[u8], accounts: &[AccountMeta]) -> Result<(), MessageMismatch> {
        let parsed = frame
            .split_first()
            .filter(|(tag, _)| **tag == tag::AUTHORITY_TRANSFER)
            .and_then(|(_, data)| RingTransactData::parse(data, self.rail).ok())
            .ok_or(MessageMismatch::Data)?;
        self.check_moved(&parsed)?;
        let mut named = accounts.iter().filter(|meta| meta.pubkey == self.delegate);
        let signs_once = matches!(
            (named.next(), named.next()),
            (Some(meta), None) if meta.is_signer && !meta.is_writable
        );
        let ring_account = accounts.get(..1).unwrap_or_default();
        let envelope = self.envelope(InstructionTag::AuthorityTransfer);
        if !signs_once || !envelope.reads_only(ring_account) {
            return Err(MessageMismatch::Accounts);
        }
        Ok(())
    }

    /// The proof binds each record to its slot under the key the frame publishes, a slot tag is an unproved hint.
    fn check_moved(&self, parsed: &ParsedTransact<'_>) -> Result<(), MessageMismatch> {
        let data = parsed.data();
        let tx_viewing_key = self
            .tx_viewing_key
            .key()
            .map_err(|_| MessageMismatch::TransactionKey)?;
        if *data.tx_viewing_u != tx_viewing_key.pubkey().u() {
            return Err(MessageMismatch::TransactionKey);
        }
        // The request names ring payments alone, a leg or a data commitment moves what no one asked.
        if !data.interface_transfers.is_empty() || data.has_data {
            return Err(MessageMismatch::Data);
        }
        let opened = AuditEnvelope {
            eph_u: *data.tx_viewing_u,
            salt: data.salt,
            ciphertext: data.envelope,
        }
        .open_sealed(&tx_viewing_key, &self.auditor, parsed.audit_stream())
        .map_err(|_| MessageMismatch::Data)?;
        let mut unpaid = self.payments.clone();
        for (slot, output) in data.outputs.iter().enumerate() {
            let record = opened
                .record(slot, output.record)
                .map_err(|_| MessageMismatch::Data)?;
            match record.kind {
                RecordKind::Dummy => {}
                RecordKind::Exit => return Err(MessageMismatch::Recipients),
                RecordKind::Ring => {
                    let paid = unpaid.iter().position(|payment| {
                        record.mint == self.mint.to_bytes() && payment.matches(&record)
                    });
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
                        None if self.source.owns(&record) => {}
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
        self.owner.owns(record) && record.amount == self.amount
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
            .is_some_and(|units| units <= compute_unit_limit(self.tag))
            && config
                .loaded_accounts_data_size_limit
                .is_some_and(|size| size <= MAX_LOADED_ACCOUNTS_DATA_SIZE)
            && config.heap_size.is_none();
        if !within_budget {
            return Err(MessageMismatch::Budget);
        }
        let [compiled] = message.instructions.as_slice() else {
            return Err(MessageMismatch::Instructions);
        };
        let key = |index: u8| {
            message
                .account_keys
                .get(usize::from(index))
                .copied()
                .ok_or(MessageMismatch::Undecodable)
        };
        if key(compiled.program_id_index)? != self.ring.program_id() {
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
            program_id: self.ring.program_id(),
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
