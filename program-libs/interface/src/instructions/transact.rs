//! The compact `Transfer` and `AuthorityTransfer` data, read in place and expanded into
//! the SPP `TransactIxData` the SPP proof's external data hash covers.

use solana_address::Address;
use spr_hasher::{primitives::solana_owner_identity, HasherError};
use spr_interface::{
    instruction::{
        instruction_data::{
            transact::{AnonymousRingEddsaProofData, Bsb22Commitment, CacheAccess, CacheWrite},
            validate_interface_transfers, MAX_CACHE_WRITES,
        },
        tag::{RING_AUTHORITY_TRANSACT, RING_TRANSACT},
        CircuitId, ExternalDataPreimage, InputUtxo, InterfaceTransfer, MessageData, OwnerTag,
        TransactIxData, TransactIxDataRef, TransactOutput, TransactProof, TreeContext,
    },
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    N_PUBLIC_SLOTS,
};
use wincode::{containers, len::FixIntLen, Serialize};

use crate::{
    anonymous_exit::ANONYMOUS_PARTIES,
    audit_stream::{
        sender_bundle_len, AuditKey, AuditStreamLayout, AUDIT_RECORD_LEN, DATA_TAIL_LEN,
        MIN_REPLY_LEN, RECIPIENT_BODY_LEN,
    },
    bytes::Bytes,
    disclosure::AuditLayout,
    error::CustomRingError,
    key_catalog::{
        RingCircuit, TransferShape, TransferSpend, ANONYMOUS_TRANSFER_SHAPES,
        CONFIDENTIAL_TRANSFER_SHAPES, ENTRY_TRANSFER_SHAPES,
    },
    output::{
        encode_confidential_output, encode_ring_body_output, encode_ring_sender_bundle_output,
        CONFIDENTIAL_DATA_FREE_BODY_LEN,
    },
    statement::{AuditHead, ConfidentialSender, SignerSet, TransferFamily, TransferRoots, TransferStatement},
    storage::Revision,
    tagged_x25519, AuditorMessage, CustomRingProof, InstructionTag, LiveRoots, PlainGroth16Proof,
    RingMode, RingPolicy, TAGGED_X25519_KEY_LEN,
};

const ZERO_FIELD: [u8; 32] = [0; 32];
/// Key support reads the shape alone.
const NO_PROOF_DATA: AnonymousRingEddsaProofData = AnonymousRingEddsaProofData {
    bsb22_commitment: Bsb22Commitment {
        commitment: ZERO_FIELD,
        commitment_pok: ZERO_FIELD,
    },
    default_owner_tag: None,
};
const ZERO_RECORD: [u8; AUDIT_RECORD_LEN] = [0; AUDIT_RECORD_LEN];
/// The frame's co-signer count, each opened as a wire of the anonymous statement.
pub const MAX_CO_SIGNERS: u8 = 5;

/// The program rail the data serves, fixed by the instruction tag and the ring mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingRail {
    Confidential,
    Anonymous,
    /// `AuthorityTransfer` on a confidential ring.
    Delegate,
    /// `AuthorityTransfer` on an anonymous ring, the anonymous frame with the delegate public.
    AnonymousDelegate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RailSigner {
    /// The confidential rail's owner signer run.
    Owners,
    /// The anonymous rail, the payer, the owner run and the co-signers sign.
    Payer,
    Delegate(Address),
    AnonymousDelegate(Address),
}

impl RailSigner {
    pub fn new(tag: InstructionTag, ring: &RingPolicy) -> Result<Self, CustomRingError> {
        let delegate = || {
            ring.delegate()
                .copied()
                .ok_or(CustomRingError::DelegateDisabled)
        };
        match RingRail::of(tag, ring.mode()?)? {
            RingRail::Anonymous => Ok(Self::Payer),
            RingRail::Confidential => Ok(Self::Owners),
            RingRail::Delegate => delegate().map(Self::Delegate),
            RingRail::AnonymousDelegate => delegate().map(Self::AnonymousDelegate),
        }
    }

    pub const fn rail(self) -> RingRail {
        match self {
            Self::Owners => RingRail::Confidential,
            Self::Payer => RingRail::Anonymous,
            Self::Delegate(_) => RingRail::Delegate,
            Self::AnonymousDelegate(_) => RingRail::AnonymousDelegate,
        }
    }
}

impl RingRail {
    pub fn new(tag: InstructionTag, ring: &RingPolicy) -> Result<Self, CustomRingError> {
        RailSigner::new(tag, ring).map(RailSigner::rail)
    }

    pub fn of(tag: InstructionTag, mode: RingMode) -> Result<Self, CustomRingError> {
        match (tag, mode) {
            (
                InstructionTag::Transfer
                | InstructionTag::HistoricalTransfer
                | InstructionTag::LegacyTransact,
                RingMode::Anonymous,
            ) => Ok(Self::Anonymous),
            (
                InstructionTag::Transfer
                | InstructionTag::HistoricalTransfer
                | InstructionTag::LegacyTransact,
                RingMode::Confidential | RingMode::ConfidentialEscrow,
            ) => Ok(Self::Confidential),
            (
                InstructionTag::AuthorityTransfer
                | InstructionTag::HistoricalAuthorityTransfer
                | InstructionTag::LegacyDelegateTransact,
                RingMode::Anonymous,
            ) => Ok(Self::AnonymousDelegate),
            (
                InstructionTag::AuthorityTransfer
                | InstructionTag::HistoricalAuthorityTransfer
                | InstructionTag::LegacyDelegateTransact,
                RingMode::Confidential | RingMode::ConfidentialEscrow,
            ) => Ok(Self::Delegate),
            _ => Err(CustomRingError::InvalidInstructionData),
        }
    }

    pub const fn spp_tag(self) -> u8 {
        match self {
            Self::Confidential | Self::Anonymous => RING_TRANSACT,
            Self::Delegate | Self::AnonymousDelegate => RING_AUTHORITY_TRANSACT,
        }
    }

    pub const fn is_delegate(self) -> bool {
        matches!(self, Self::Delegate | Self::AnonymousDelegate)
    }

    /// The statement and shapes of the anonymous keys.
    pub const fn is_anonymous_family(self) -> bool {
        matches!(self, Self::Anonymous | Self::AnonymousDelegate)
    }

    fn circuit(self, n_in: u8, n_out: u8, proof_data: AnonymousRingEddsaProofData) -> CircuitId {
        let slots = N_PUBLIC_SLOTS as u8;
        match self {
            Self::Confidential => CircuitId::ConfidentialRingEddsa(n_in, n_out, slots),
            Self::Anonymous => CircuitId::AnonymousRingEddsa(n_in, n_out, slots, proof_data),
            Self::Delegate | Self::AnonymousDelegate => {
                CircuitId::RingAuthority(n_in, n_out, slots)
            }
        }
    }

    /// The authority rail admits SPP's ring-authority widths alone.
    pub fn supports(self, shape: Shape) -> bool {
        match (
            u8::try_from(shape.n_inputs()),
            u8::try_from(shape.n_outputs()),
        ) {
            (Ok(n_in), Ok(n_out)) => self.circuit(n_in, n_out, NO_PROOF_DATA).is_supported(),
            _ => false,
        }
    }

    /// The audit key the header names, before the outputs are read.
    fn audit_key(self, header: &FrameHeader) -> Result<AuditKey, CustomRingError> {
        let supported = self.supports(Shape::new(
            usize::from(header.n_in),
            usize::from(header.n_out),
        ));
        let (n_out, inputs) = (usize::from(header.n_out), usize::from(header.input_count));
        let shapes = match (header.flags.entry, self.is_anonymous_family()) {
            (true, _) => &ENTRY_TRANSFER_SHAPES[..],
            (false, true) => &ANONYMOUS_TRANSFER_SHAPES[..],
            (false, false) => &CONFIDENTIAL_TRANSFER_SHAPES[..],
        };
        let key = TransferShape::of(shapes, n_out)
            .filter(|shape| supported && inputs <= usize::from(shape.inputs))
            .map(|shape| AuditKey {
                class: usize::from(shape.inputs),
                entry: header.flags.entry,
            })
            .ok_or(CustomRingError::RingShapeUnkeyed)?;
        if inputs == 0 || inputs > usize::from(header.n_in) {
            return Err(CustomRingError::RingTransactLength);
        }
        Ok(key)
    }
}

impl core::fmt::Display for RingRail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Confidential => "confidential",
            Self::Anonymous => "anonymous",
            Self::Delegate => "delegate",
            Self::AnonymousDelegate => "anonymous delegate",
        })
    }
}

/// The proven approval classes, the program reads each bit against its own configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApprovalMask(u8);

impl ApprovalMask {
    /// Some owner's outflow passed its asset's `cosign_above`.
    pub const OUTFLOW: u8 = 1 << 0;
    /// Some asset's gross withdrawal passed its `withdrawal_threshold`.
    pub const WITHDRAWAL: u8 = 1 << 1;
    const KNOWN: u8 = Self::OUTFLOW | Self::WITHDRAWAL;

    pub const fn new(bits: u8) -> Result<Self, CustomRingError> {
        match bits & !Self::KNOWN {
            0 => Ok(Self(bits)),
            _ => Err(CustomRingError::FlagNotAllowed),
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn outflow(self) -> bool {
        self.0 & Self::OUTFLOW != 0
    }

    pub const fn withdrawal(self) -> bool {
        self.0 & Self::WITHDRAWAL != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyProof<'a> {
    /// Token owners checked on chain, in SPL withdrawal order.
    pub spl_withdrawal_owners: &'a [[u8; 32]],
    /// Set exactly when a source names a curator registry.
    pub curator_revision: Option<Revision>,
}

/// What a frame reads beside the live registries, resolved by the program from its pinned accounts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForeignRoots {
    pub tracking: [u8; 32],
    /// Zero without a private source.
    pub private: [u8; 32],
}

/// One application message, forwarded ahead of the auditor's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppMessage<'a> {
    pub view_tag: &'a [u8; 32],
    pub data: &'a [u8],
}

/// SPP's optional fields a frame carries through, each absent by default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameExtensions<'a> {
    /// The transaction's application digest, distinct from a note's `data_hash`.
    pub data_hash: Option<&'a [u8; 32]>,
    /// The transaction's ring digest, distinct from a note's `ring_data_hash`.
    pub ring_data_hash: Option<&'a [u8; 32]>,
    pub private_revision: Option<Revision>,
    pub messages: Vec<AppMessage<'a>>,
    /// The cached selector, refused on the authority rails.
    pub cache: Option<CacheAccess>,
}

impl<'a> FrameExtensions<'a> {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn read(bytes: &mut Bytes<'a>) -> Result<Self, CustomRingError> {
        let flags = bytes.byte()?;
        if flags & !extension_flag::KNOWN != 0 {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let has = |bit: u8| flags & bit != 0;
        let data_hash = has(extension_flag::DATA_HASH)
            .then(|| bytes.array())
            .transpose()?;
        let ring_data_hash = has(extension_flag::RING_DATA_HASH)
            .then(|| bytes.array())
            .transpose()?;
        let private_revision = has(extension_flag::PRIVATE_SOURCE)
            .then(|| bytes.pod().copied())
            .transpose()?;
        let messages = match has(extension_flag::MESSAGES) {
            false => Vec::new(),
            true => {
                let count = bytes.byte()?;
                (0..count)
                    .map(|_| {
                        let view_tag = bytes.array()?;
                        let len = bytes.u16()?;
                        Ok(AppMessage {
                            view_tag,
                            data: bytes.take(usize::from(len))?,
                        })
                    })
                    .collect::<Result<_, CustomRingError>>()?
            }
        };
        let cache = has(extension_flag::CACHE)
            .then(|| read_cache_access(bytes))
            .transpose()?;
        Ok(Self {
            data_hash,
            ring_data_hash,
            private_revision,
            messages,
            cache,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), CustomRingError> {
        let flag = |set: bool, bit: u8| if set { bit } else { 0 };
        out.push(
            flag(self.data_hash.is_some(), extension_flag::DATA_HASH)
                | flag(self.ring_data_hash.is_some(), extension_flag::RING_DATA_HASH)
                | flag(self.private_revision.is_some(), extension_flag::PRIVATE_SOURCE)
                | flag(!self.messages.is_empty(), extension_flag::MESSAGES)
                | flag(self.cache.is_some(), extension_flag::CACHE),
        );
        if let Some(hash) = self.data_hash {
            out.extend_from_slice(hash);
        }
        if let Some(hash) = self.ring_data_hash {
            out.extend_from_slice(hash);
        }
        if let Some(revision) = self.private_revision {
            out.extend_from_slice(&revision.0);
        }
        if !self.messages.is_empty() {
            out.push(count_byte(self.messages.len())?);
            for message in &self.messages {
                let len = u16::try_from(message.data.len())
                    .map_err(|_| CustomRingError::OutputBodyLength)?;
                out.extend_from_slice(message.view_tag);
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(message.data);
            }
        }
        if let Some(cache) = &self.cache {
            write_cache_access(cache, out);
        }
        Ok(())
    }

    fn frame_len(&self) -> usize {
        const FIELD: usize = 32;
        1 + self.data_hash.map_or(0, |_| FIELD)
            + self.ring_data_hash.map_or(0, |_| FIELD)
            + self
                .private_revision
                .map_or(0, |_| core::mem::size_of::<Revision>())
            + match self.messages.is_empty() {
                true => 0,
                false => {
                    1 + self
                        .messages
                        .iter()
                        .map(|message| FIELD + 2 + message.data.len())
                        .sum::<usize>()
                }
            }
            + self.cache.map_or(0, |_| CACHE_ACCESS_LEN)
    }
}

/// The extension section's first byte, one bit per optional field.
pub mod extension_flag {
    pub const DATA_HASH: u8 = 1 << 0;
    pub const RING_DATA_HASH: u8 = 1 << 1;
    pub const PRIVATE_SOURCE: u8 = 1 << 2;
    pub const MESSAGES: u8 = 1 << 3;
    pub const CACHE: u8 = 1 << 4;
    pub const KNOWN: u8 = DATA_HASH | RING_DATA_HASH | PRIVATE_SOURCE | MESSAGES | CACHE;
}

const CACHE_ACCESS_LEN: usize = 8 + 2 * MAX_CACHE_WRITES;

fn read_cache_access(bytes: &mut Bytes<'_>) -> Result<CacheAccess, CustomRingError> {
    let read_bitmap = u64::from_le_bytes(*bytes.array()?);
    let mut write_slots = CacheAccess::NO_WRITES;
    for write in &mut write_slots {
        let [output, slot] = *bytes.array()?;
        *write = CacheWrite { output, slot };
    }
    Ok(CacheAccess {
        read_bitmap,
        write_slots,
    })
}

fn write_cache_access(cache: &CacheAccess, out: &mut Vec<u8>) {
    out.extend_from_slice(&cache.read_bitmap.to_le_bytes());
    for write in &cache.write_slots {
        out.extend_from_slice(&[write.output, write.slot]);
    }
}

/// The owner SPP's anonymous rail verifies and hides, the delivered audit publishes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InProofOwner<'a> {
    pub owner: &'a [u8; 32],
    pub commitment: &'a [u8; 32],
    pub commitment_pok: &'a [u8; 32],
}

impl InProofOwner<'_> {
    /// Ring notes only, a default-ring input would publish the owner SPP hides.
    fn proof_data(&self) -> AnonymousRingEddsaProofData {
        AnonymousRingEddsaProofData {
            bsb22_commitment: Bsb22Commitment {
                commitment: *self.commitment,
                commitment_pok: *self.commitment_pok,
            },
            default_owner_tag: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousProofData<'a> {
    pub commitment: &'a [u8; 32],
    pub commitment_pok: &'a [u8; 32],
    /// The hidden owner's default-ring key.
    pub default_owner_tag: Option<&'a [u8; 32]>,
}

/// The tree contexts inputs spend from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputTrees {
    One(TreeContext),
    /// Bit `i` of `second_inputs` spends input `i` from `second`.
    Two {
        first: TreeContext,
        second: TreeContext,
        second_inputs: u64,
    },
}

impl InputTrees {
    fn tree_index(self, input: usize) -> u8 {
        match self {
            Self::One(_) => 0,
            Self::Two { second_inputs, .. } => ((second_inputs >> input) & 1) as u8,
        }
    }

    fn contexts(self) -> Vec<TreeContext> {
        match self {
            Self::One(context) => vec![context],
            Self::Two { first, second, .. } => vec![first, second],
        }
    }
}

/// The bytes a slot hands SPP outside the proof, the external data hash binds them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotBody<'a> {
    /// A slot another message covers, such as change the sender bundle holds.
    None,
    /// Scheme 13 under the slot's view tag or recipient key.
    Recipient(&'a [u8]),
    /// Scheme 3 under its own owner tag, a default-ring wallet reads it.
    Exit(&'a [u8]),
}

/// A published output slot without its SPP framing, its record in the auditor message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingOutput<'a> {
    pub hash: &'a [u8; 32],
    pub owner_tag: &'a [u8; 32],
    pub body: SlotBody<'a>,
    pub record: &'a [u8; AUDIT_RECORD_LEN],
    /// Present exactly under `has_data`.
    pub tail: Option<&'a [u8; DATA_TAIL_LEN]>,
}

impl<'a> RingOutput<'a> {
    /// The frame's claim, the proof reads the slot's own ring id.
    pub const fn is_exit(&self) -> bool {
        matches!(self.body, SlotBody::Exit(_))
    }

    /// The slots a reply serves.
    const fn bears_recipient_body(&self) -> bool {
        matches!(self.body, SlotBody::Recipient(_))
    }

    /// The SPP output, the scheme framing rebuilt from the slot, `reply` after a recipient body.
    pub fn transact_output(&self, reply: &[u8]) -> Result<TransactOutput, CustomRingError> {
        let data = match self.body {
            SlotBody::None => None,
            SlotBody::Recipient(body) => Some(encode_ring_body_output(body, reply)?),
            SlotBody::Exit(payload) => Some(encode_confidential_output(payload)?),
        };
        Ok(TransactOutput {
            utxo_hash: *self.hash,
            owner_tag: OwnerTag::Inline(*self.owner_tag),
            data,
        })
    }

    const fn body_len(&self) -> usize {
        match self.body {
            SlotBody::None => 0,
            SlotBody::Recipient(body) | SlotBody::Exit(body) => body.len(),
        }
    }

    /// A frame with no data carries each body at its plain length.
    const fn has_plain_body(&self) -> bool {
        match self.body {
            SlotBody::None => true,
            SlotBody::Recipient(body) => body.len() == RECIPIENT_BODY_LEN,
            SlotBody::Exit(payload) => payload.len() == CONFIDENTIAL_DATA_FREE_BODY_LEN,
        }
    }
}

/// Bit `i` set when slot `i` carries a scheme 3 body, frame parsing alone reads it.
pub fn exits_bitmap(outputs: &[RingOutput<'_>]) -> u64 {
    slot_bits(outputs.iter().map(RingOutput::is_exit))
}

/// Bit `i` set when slot `i` carries no body, frame parsing alone reads it.
pub fn bodiless_bitmap(outputs: &[RingOutput<'_>]) -> u64 {
    slot_bits(outputs.iter().map(|output| output.body == SlotBody::None))
}

fn slot_bits(set: impl Iterator<Item = bool>) -> u64 {
    set.enumerate()
        .filter(|(_, set)| *set)
        .fold(0, |bits, (slot, _)| bits | 1 << slot)
}

/// Scheme 12, forwarded under its tag as the first SPP message, `m` fixes the length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramedSenderBundle<'a> {
    pub tag: &'a [u8; 32],
    pub body: &'a [u8],
}

/// Every reply of a frame, one length so a hidden dummy matches a recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Replies<'a> {
    /// `reply_len`, at least [`MIN_REPLY_LEN`].
    pub len: u16,
    /// `len` bytes per body-bearing slot, in slot order, the statement digests the region.
    pub region: &'a [u8],
}

impl<'a> Replies<'a> {
    fn checked(self, bodies: usize) -> Result<Self, CustomRingError> {
        let len = usize::from(self.len);
        match len >= MIN_REPLY_LEN && self.region.len() == len * bodies {
            true => Ok(self),
            false => Err(CustomRingError::ReplyLength),
        }
    }
}

/// One public leg's committed accounts, the asset account then the user account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settlement<'a> {
    pub asset_account: &'a [u8; 32],
    pub user_account: &'a [u8; 32],
}

/// The stream layout is always the one the data's own frame selects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTransact<'a> {
    data: RingTransactData<'a>,
    stream: AuditStreamLayout,
}

impl<'a> ParsedTransact<'a> {
    pub fn new(data: RingTransactData<'a>) -> Result<Self, CustomRingError> {
        let stream = data.audit_stream()?;
        Ok(Self { data, stream })
    }

    pub const fn data(&self) -> &RingTransactData<'a> {
        &self.data
    }

    pub fn into_data(self) -> RingTransactData<'a> {
        self.data
    }

    pub const fn audit_stream(&self) -> AuditStreamLayout {
        self.stream
    }

    /// The statement the transfer proof is verified against.
    pub fn transfer_statement<'s>(
        &'s self,
        binding: TransferBinding<'s>,
    ) -> Result<TransferStatement<'s>, CustomRingError> {
        let data = &self.data;
        let family = match data.rail {
            RingRail::Confidential => TransferFamily::Confidential {
                sender: match data.in_proof_owner {
                    Some(_) => ConfidentialSender::InProof(binding.sender),
                    None => ConfidentialSender::Signer,
                },
            },
            RingRail::Delegate => TransferFamily::Confidential {
                sender: ConfidentialSender::Authority,
            },
            RingRail::Anonymous | RingRail::AnonymousDelegate => TransferFamily::Anonymous {
                party_identities: binding.party_identities,
                public_owners: data.public_owners,
                delegate: data.rail == RingRail::AnonymousDelegate,
            },
        };
        Ok(TransferStatement {
            head: AuditHead {
                first_nullifier: data.first_nullifier()?,
                ring_id: binding.ring_id,
                tx_viewing_u: data.tx_viewing_u,
                auditor_pubkey: binding.auditor_pubkey,
                eph_u: data.eph_u,
                envelope: data.envelope,
                salt: data.salt,
                layout: data.audit_layout(),
            },
            family,
            approval_mask: data.approval_mask,
            no_spend: data.no_spend,
            outputs: &data.outputs,
            output_capacity: self.stream.capacity,
            input_count: data.nullifiers.len(),
            private_tx_hash: data.private_tx_hash,
            signers: binding.signers,
            roots: binding.roots,
            public_assets: binding.public_assets,
            public_amounts: binding.public_amounts,
            public_gross: binding.public_gross,
            withdrawal_hash: binding.withdrawal_hash,
        })
    }
}

/// What the program supplies beside the data for the transfer statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferBinding<'a> {
    /// `hash_bytes` of the ring program id.
    pub ring_id: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    /// The in-proof owner identity, otherwise zero.
    pub sender: &'a [u8; 32],
    /// Default on the in-proof and authority rails.
    pub signers: SignerSet,
    /// Zero outside the anonymous family.
    pub party_identities: &'a [[u8; 32]; ANONYMOUS_PARTIES],
    pub roots: &'a TransferRoots,
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amounts: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_gross: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub withdrawal_hash: &'a [u8; 32],
}

/// The data of `Transfer` and `AuthorityTransfer`, every count ahead of the sections it sizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingTransactData<'a> {
    pub rail: RingRail,
    /// SPP shape inputs.
    pub n_in: u8,
    /// SPP shape outputs, the key's `N`.
    pub n_out: u8,
    pub proof: &'a CustomRingProof,
    /// The tracking root the frame's rows open under, every rail reads it.
    pub tracking_revision: Revision,
    /// Present under a policy and on a frame whose thresholds read the own registry.
    pub own_revision: Option<Revision>,
    /// Present exactly on a policy ring, off the authority rails.
    pub policy: Option<PolicyProof<'a>>,
    pub approval_mask: ApprovalMask,
    /// Co-signer accounts the frame names, each opened as a wire on the anonymous family.
    pub co_signers: u8,
    /// The sealed `R` is zero.
    pub no_spend: bool,
    /// No hidden sender on an anonymous ring, SPP's confidential rail settles.
    pub public_owners: bool,
    pub expiry_unix_ts: u32,
    pub tx_viewing_u: &'a [u8; 32],
    /// Random per attempt, a resend under the same first nullifier reuses no keystream.
    pub salt: &'a [u8; 16],
    pub extensions: FrameExtensions<'a>,
    pub interface_transfers: Vec<InterfaceTransfer>,
    /// One tail per published slot, every data hash is zero while clear.
    pub has_data: bool,
    /// The key with entry capacity.
    pub entry: bool,
    /// The `m` published slots, slot `i` keeps its index in every derivation.
    pub outputs: Vec<RingOutput<'a>>,
    /// Set exactly under `REPLY_METADATA`.
    pub replies: Option<Replies<'a>>,
    /// Present exactly on the anonymous rail.
    pub sender: Option<FramedSenderBundle<'a>>,
    pub eph_u: &'a [u8; 32],
    /// `envelope_ct`, the transmitted length is the stream layout's.
    pub envelope: &'a [u8],
    pub private_tx_hash: &'a [u8; 32],
    /// Present exactly on the anonymous rail with a hidden sender.
    pub anonymous: Option<AnonymousProofData<'a>>,
    /// Set exactly on the in-proof owner rail, SPP's anonymous rail of a confidential ring.
    pub in_proof_owner: Option<InProofOwner<'a>>,
    pub spp_proof: &'a PlainGroth16Proof,
    /// One per spent input slot SPP publishes.
    pub nullifiers: &'a [[u8; 32]],
    pub input_trees: InputTrees,
}

impl<'a> RingTransactData<'a> {
    /// Every length fixed by the flags, the shape and the counts, trailing bytes refused.
    pub fn parse(data: &'a [u8], rail: RingRail) -> Result<ParsedTransact<'a>, CustomRingError> {
        let mut bytes = Bytes::new(data, CustomRingError::RingTransactLength);
        let flags = TransactFlags(bytes.byte()?);
        let header = FrameHeader::read(&mut bytes, rail)?;
        flags.check(rail, header.authorization)?;
        header.check_rail_flags(rail, flags)?;
        let input_count = header.input_count;
        let key = rail.audit_key(&header)?;
        let output_count = usize::from(header.output_count);
        let proof = bytes.pod()?;
        let tracking_revision = bytes.pod().copied()?;
        let own_revision = flags
            .reads_own_root()
            .then(|| bytes.pod().copied())
            .transpose()?;
        let mut policy = match flags.has(transact_flag::POLICY) {
            false => None,
            true => Some(PolicyProof {
                spl_withdrawal_owners: &[],
                curator_revision: flags
                    .has(transact_flag::CURATOR)
                    .then(|| bytes.pod().copied())
                    .transpose()?,
            }),
        };
        let expiry_unix_ts = bytes.u32()?;
        let tx_viewing_u = bytes.array()?;
        let salt = bytes.array()?;
        let extensions = match flags.has(transact_flag::EXTENSIONS) {
            false => FrameExtensions::default(),
            true => FrameExtensions::read(&mut bytes)?,
        };
        check_extensions(&extensions, rail)?;
        let interface_transfers = bytes.interface_transfers()?;
        if let Some(policy) = &mut policy {
            policy.spl_withdrawal_owners =
                bytes.fields(crate::spl_withdrawal_count(&interface_transfers))?;
        }
        let exits = bytes.bitmap(output_count)?;
        if rail.is_delegate() && exits != 0 {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let bodiless = bytes.bitmap(output_count)?;
        if exits & bodiless != 0 {
            return Err(CustomRingError::InvalidChangeBits);
        }
        let stream = AuditStreamLayout {
            key,
            inputs: usize::from(input_count),
            outputs: output_count,
            capacity: usize::from(header.n_out),
            has_data: header.flags.has_data,
        };
        let mut outputs = Vec::with_capacity(output_count);
        for slot in 0..output_count {
            let (exit, carries_body) = ((exits >> slot) & 1 == 1, (bodiless >> slot) & 1 == 0);
            let len = match (carries_body, stream.has_data, exit) {
                (false, ..) => 0,
                (true, true, _) => usize::from(bytes.u16()?),
                (true, false, true) => CONFIDENTIAL_DATA_FREE_BODY_LEN,
                (true, false, false) => RECIPIENT_BODY_LEN,
            };
            let hash = bytes.array()?;
            let owner_tag = bytes.array()?;
            let body = bytes.take(len)?;
            outputs.push(RingOutput {
                hash,
                owner_tag,
                body: match (carries_body, exit) {
                    (false, _) => SlotBody::None,
                    (true, true) => SlotBody::Exit(body),
                    (true, false) => SlotBody::Recipient(body),
                },
                record: &ZERO_RECORD,
                tail: None,
            });
        }
        let replies = match flags.has(transact_flag::REPLY_METADATA) {
            false => None,
            true => {
                let len = bytes.u16()?;
                let bodies = outputs
                    .iter()
                    .filter(|output| output.bears_recipient_body())
                    .count();
                Some(
                    Replies {
                        len,
                        region: bytes.take(usize::from(len) * bodies)?,
                    }
                    .checked(bodies)?,
                )
            }
        };
        let sender = match rail {
            RingRail::Anonymous => Some(FramedSenderBundle {
                tag: bytes.array()?,
                body: bytes.take(sender_bundle_len(output_count))?,
            }),
            _ => None,
        };
        let eph_u = bytes.array()?;
        let envelope = bytes.take(stream.envelope().len)?;
        for output in &mut outputs {
            output.record = bytes.array()?;
        }
        if stream.has_data {
            for output in &mut outputs {
                output.tail = Some(bytes.array()?);
            }
        }
        let private_tx_hash = bytes.array()?;
        let anonymous = (rail == RingRail::Anonymous && !flags.has(transact_flag::PUBLIC_OWNERS))
            .then(|| {
                Ok::<_, CustomRingError>(AnonymousProofData {
                    commitment: bytes.array()?,
                    commitment_pok: bytes.array()?,
                    default_owner_tag: header
                        .flags
                        .default_owner_tag
                        .then(|| bytes.array())
                        .transpose()?,
                })
            })
            .transpose()?;
        let in_proof_owner = match flags.has(transact_flag::OWNER_IN_PROOF) {
            false => None,
            true => Some(InProofOwner {
                owner: bytes.array()?,
                commitment: bytes.array()?,
                commitment_pok: bytes.array()?,
            }),
        };
        let spp_proof = bytes.pod()?;
        let nullifiers = bytes.fields(usize::from(input_count))?;
        let input_trees = match flags.has(transact_flag::SECOND_TREE) {
            false => InputTrees::One(bytes.tree_context()?),
            true => {
                let second_inputs = bytes.bitmap(usize::from(input_count))?;
                InputTrees::Two {
                    first: bytes.tree_context()?,
                    second: bytes.tree_context()?,
                    second_inputs,
                }
            }
        };
        if !bytes.rest().is_empty() {
            return Err(CustomRingError::RingTransactLength);
        }
        let data = Self {
            rail,
            n_in: header.n_in,
            n_out: header.n_out,
            proof,
            tracking_revision,
            own_revision,
            policy,
            approval_mask: header.authorization.approval_mask,
            co_signers: header.authorization.co_signers,
            no_spend: header.flags.no_spend,
            public_owners: flags.has(transact_flag::PUBLIC_OWNERS),
            expiry_unix_ts,
            tx_viewing_u,
            salt,
            extensions,
            interface_transfers,
            has_data: header.flags.has_data,
            entry: header.flags.entry,
            outputs,
            replies,
            sender,
            eph_u,
            envelope,
            private_tx_hash,
            anonymous,
            in_proof_owner,
            spp_proof,
            nullifiers,
            input_trees,
        };
        Ok(ParsedTransact { data, stream })
    }

    /// The bytes `parse` reads back, refusing what it refuses.
    pub fn encode(&self) -> Result<Vec<u8>, CustomRingError> {
        let flags = self.flags();
        let header = FrameHeader::of(self)?;
        flags.check(self.rail, header.authorization)?;
        header.check_rail_flags(self.rail, flags)?;
        check_extensions(&self.extensions, self.rail)?;
        let stream = self.audit_stream()?;
        let bears_bundle = self.rail == RingRail::Anonymous;
        let proves_hidden_owner = bears_bundle && !self.public_owners;
        let output_count = usize::from(header.output_count);
        if self.own_revision.is_some() != flags.reads_own_root()
            || self.anonymous.is_some() != proves_hidden_owner
            || self.sender.is_some() != bears_bundle
            || self
                .sender
                .is_some_and(|sender| sender.body.len() != sender_bundle_len(output_count))
            || self.envelope.len() != stream.envelope().len
            || !self.outputs.iter().all(|output| {
                output.tail.is_some() == self.has_data
                    && (self.has_data || output.has_plain_body())
            })
        {
            return Err(CustomRingError::RingTransactLength);
        }
        if self.rail.is_delegate() && self.outputs.iter().any(RingOutput::is_exit) {
            return Err(CustomRingError::FlagNotAllowed);
        }
        if let Some(replies) = self.replies {
            replies.checked(self.recipient_body_count())?;
        }
        let interface_transfers =
            <containers::Vec<InterfaceTransfer, FixIntLen<u8>> as Serialize>::serialize(
                &self.interface_transfers,
            )
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let mut out = Vec::with_capacity(self.frame_len(stream, interface_transfers.len())?);
        out.push(flags.0);
        out.extend(header.bytes()?);
        out.extend_from_slice(bytemuck::bytes_of(self.proof));
        out.extend_from_slice(&self.tracking_revision.0);
        if let Some(revision) = self.own_revision {
            out.extend_from_slice(&revision.0);
        }
        if let Some(revision) = self.policy.and_then(|policy| policy.curator_revision) {
            out.extend_from_slice(&revision.0);
        }
        out.extend_from_slice(&self.expiry_unix_ts.to_le_bytes());
        out.extend_from_slice(self.tx_viewing_u);
        out.extend_from_slice(self.salt);
        if !self.extensions.is_empty() {
            self.extensions.write(&mut out)?;
        }
        out.extend_from_slice(&interface_transfers);
        if let Some(policy) = &self.policy {
            if policy.spl_withdrawal_owners.len()
                != crate::spl_withdrawal_count(&self.interface_transfers)
            {
                return Err(CustomRingError::RingTransactLength);
            }
            for owner in policy.spl_withdrawal_owners {
                out.extend_from_slice(owner);
            }
        }
        push_bitmap(&mut out, self.outputs.iter().map(RingOutput::is_exit));
        push_bitmap(
            &mut out,
            self.outputs.iter().map(|output| output.body == SlotBody::None),
        );
        for output in &self.outputs {
            if self.has_data && output.body != SlotBody::None {
                let len = u16::try_from(output.body_len())
                    .map_err(|_| CustomRingError::OutputBodyLength)?;
                out.extend_from_slice(&len.to_le_bytes());
            }
            out.extend_from_slice(output.hash);
            out.extend_from_slice(output.owner_tag);
            if let SlotBody::Recipient(body) | SlotBody::Exit(body) = output.body {
                out.extend_from_slice(body);
            }
        }
        if let Some(replies) = self.replies {
            out.extend_from_slice(&replies.len.to_le_bytes());
            out.extend_from_slice(replies.region);
        }
        if let Some(sender) = self.sender {
            out.extend_from_slice(sender.tag);
            out.extend_from_slice(sender.body);
        }
        out.extend_from_slice(self.eph_u);
        out.extend_from_slice(self.envelope);
        for output in &self.outputs {
            out.extend_from_slice(output.record);
        }
        for tail in self.outputs.iter().filter_map(|output| output.tail) {
            out.extend_from_slice(tail);
        }
        out.extend_from_slice(self.private_tx_hash);
        if let Some(anonymous) = &self.anonymous {
            out.extend_from_slice(anonymous.commitment);
            out.extend_from_slice(anonymous.commitment_pok);
            if let Some(tag) = anonymous.default_owner_tag {
                out.extend_from_slice(tag);
            }
        }
        if let Some(owner) = &self.in_proof_owner {
            out.extend_from_slice(owner.owner);
            out.extend_from_slice(owner.commitment);
            out.extend_from_slice(owner.commitment_pok);
        }
        out.extend_from_slice(bytemuck::bytes_of(self.spp_proof));
        out.extend_from_slice(self.nullifiers.as_flattened());
        match self.input_trees {
            InputTrees::One(context) => push_tree_context(&mut out, context)?,
            InputTrees::Two {
                first,
                second,
                second_inputs,
            } => {
                if second_inputs >> self.nullifiers.len() != 0 {
                    return Err(CustomRingError::InvalidInstructionData);
                }
                push_bitmap(
                    &mut out,
                    (0..self.nullifiers.len()).map(|input| (second_inputs >> input) & 1 == 1),
                );
                push_tree_context(&mut out, first)?;
                push_tree_context(&mut out, second)?;
            }
        }
        Ok(out)
    }

    fn frame_len(
        &self,
        stream: AuditStreamLayout,
        interface_transfers: usize,
    ) -> Result<usize, CustomRingError> {
        const FIELD: usize = 32;
        let revision = core::mem::size_of::<Revision>();
        let policy = self.policy.map_or(0, |policy| {
            policy.curator_revision.map_or(0, |_| revision)
                + FIELD * policy.spl_withdrawal_owners.len()
        });
        let sender = self.sender.map_or(0, |sender| FIELD + sender.body.len());
        let replies = self.replies.map_or(0, |replies| 2 + replies.region.len());
        let anonymous = self.anonymous.map_or(0, |anonymous| {
            FIELD * (2 + usize::from(anonymous.default_owner_tag.is_some()))
        });
        let in_proof_owner = self.in_proof_owner.map_or(0, |_| 3 * FIELD);
        let inputs = self.nullifiers.len();
        let trees = match self.input_trees {
            InputTrees::One(context) => tree_context_len(context)?,
            InputTrees::Two { first, second, .. } => {
                inputs.div_ceil(8) + tree_context_len(first)? + tree_context_len(second)?
            }
        };
        let extensions = match self.extensions.is_empty() {
            true => 0,
            false => self.extensions.frame_len(),
        };
        let slots = self
            .outputs
            .iter()
            .map(|output| {
                let len_prefix = match self.has_data && output.body != SlotBody::None {
                    true => 2,
                    false => 0,
                };
                len_prefix + 2 * FIELD + output.body_len()
            })
            .sum::<usize>();
        Ok(FrameHeader::LEN
            + core::mem::size_of::<CustomRingProof>()
            + revision
            + self.own_revision.map_or(0, |_| revision)
            + policy
            + 4
            + FIELD
            + 16
            + extensions
            + interface_transfers
            + 2 * self.outputs.len().div_ceil(8)
            + slots
            + replies
            + sender
            + FIELD
            + stream.envelope().len
            + stream.records_len()
            + stream.tails_len()
            + FIELD
            + anonymous
            + in_proof_owner
            + core::mem::size_of::<PlainGroth16Proof>()
            + FIELD * inputs
            + trees)
    }

    /// Refuses a frame whose sections disagree with the ring's policy, `foreign` is what the program resolved from `tracking_revision` and the private source.
    pub fn roots(
        &self,
        policy: Option<&RingPolicy>,
        roots: &LiveRoots<'_>,
        foreign: ForeignRoots,
    ) -> Result<TransferRoots, CustomRingError> {
        let mut bound = TransferRoots {
            tracking_root: foreign.tracking,
            private_root: foreign.private,
            ..TransferRoots::default()
        };
        // The delegate reads no policy root, a restrictive update cannot fail its proof in flight.
        if self.rail.is_delegate() {
            return Ok(bound);
        }
        let policy = match (self.policy, policy) {
            (None, None) => None,
            (Some(_), None) => return Err(CustomRingError::UnexpectedPolicyProof),
            (None, Some(_)) => return Err(CustomRingError::MissingPolicyProof),
            (Some(proof), Some(policy)) => Some((proof, policy)),
        };
        let curator_revision =
            match policy.map(|(proof, policy)| (proof.curator_revision, policy.curator())) {
                None | Some((None, None)) => None,
                Some((Some(revision), Some(_))) => Some(revision),
                Some(_) => return Err(CustomRingError::FlagNotAllowed),
            };
        if let Some((_, policy)) = policy {
            bound.policy_hash = *policy.policy_hash()?;
        }
        if let Some(revision) = self.own_revision {
            bound.own_root = roots.own(revision)?;
        }
        if let Some(revision) = curator_revision {
            bound.curator_root = roots.curator(revision)?;
        }
        Ok(bound)
    }

    pub fn transfer_circuit(&self, legs: usize) -> Result<RingCircuit, CustomRingError> {
        RingCircuit::transfer(TransferSpend {
            rail: self.rail,
            inputs: self.nullifiers.len(),
            outputs: usize::from(self.n_out),
            spends_default_ring: self.entry,
            legs,
        })
        .ok_or(CustomRingError::RingShapeUnkeyed)
    }

    /// The run SPP reads as owner signers, between the nullifier PDAs and the settlement groups.
    pub fn owner_signers<'s, T>(
        &self,
        spp: &'s [T],
        settlements: usize,
    ) -> Result<&'s [T], CustomRingError> {
        let trees = match self.input_trees {
            InputTrees::One(_) => 1,
            InputTrees::Two { .. } => 2,
        };
        let start = crate::RING_TRANSACT_ACCOUNT_PREFIX_LEN + trees + self.nullifiers.len();
        spp.len()
            .checked_sub(settlements)
            .and_then(|end| spp.get(start..end))
            .ok_or(CustomRingError::InvalidSettlementAccounts)
    }

    /// The SPP selector of the data's shape and rail, a public-owner frame takes SPP's confidential rail on every ring.
    pub fn circuit(&self) -> CircuitId {
        let circuit = match (&self.in_proof_owner, self.public_owners, self.anonymous) {
            (Some(owner), ..) => {
                RingRail::Anonymous.circuit(self.n_in, self.n_out, owner.proof_data())
            }
            (None, true, _) => RingRail::Confidential.circuit(self.n_in, self.n_out, NO_PROOF_DATA),
            (None, false, anonymous) => {
                let proof_data =
                    anonymous.map_or(NO_PROOF_DATA, |anonymous| AnonymousRingEddsaProofData {
                        bsb22_commitment: Bsb22Commitment {
                            commitment: *anonymous.commitment,
                            commitment_pok: *anonymous.commitment_pok,
                        },
                        default_owner_tag: anonymous.default_owner_tag.copied(),
                    });
                self.rail.circuit(self.n_in, self.n_out, proof_data)
            }
        };
        match (circuit, self.extensions.cache) {
            (CircuitId::ConfidentialRingEddsa(n_in, n_out, slots), Some(access)) => {
                CircuitId::ConfidentialRingEddsaCached(n_in, n_out, slots, access)
            }
            (CircuitId::AnonymousRingEddsa(n_in, n_out, slots, proof_data), Some(access)) => {
                CircuitId::AnonymousRingEddsaCached(n_in, n_out, slots, proof_data, access)
            }
            (circuit, _) => circuit,
        }
    }

    pub fn first_nullifier(&self) -> Result<&'a [u8; 32], CustomRingError> {
        self.nullifiers
            .first()
            .ok_or(CustomRingError::RingTransactLength)
    }

    /// The in-proof owner's identity, `None` off that rail.
    pub fn in_proof_sender(&self) -> Result<Option<[u8; 32]>, HasherError> {
        self.in_proof_owner
            .map(|owner| solana_owner_identity(owner.owner))
            .transpose()
    }

    pub fn audit_layout(&self) -> AuditLayout {
        FrameFlags::of(self).audit_layout()
    }

    /// Every ciphertext length of the transfer, refusing a frame no key serves.
    pub fn audit_stream(&self) -> Result<AuditStreamLayout, CustomRingError> {
        let key = self.rail.audit_key(&FrameHeader::of(self)?)?;
        Ok(AuditStreamLayout {
            key,
            inputs: self.nullifiers.len(),
            outputs: self.outputs.len(),
            capacity: usize::from(self.n_out),
            has_data: self.has_data,
        })
    }

    fn recipient_body_count(&self) -> usize {
        self.outputs
            .iter()
            .filter(|output| output.bears_recipient_body())
            .count()
    }

    /// The reply of each slot in order, empty off a recipient body.
    pub fn slot_replies(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        let mut replies = self
            .replies
            .map(|replies| replies.region.chunks_exact(usize::from(replies.len)));
        self.outputs.iter().map(
            move |output| match (output.bears_recipient_body(), &mut replies) {
                (true, Some(replies)) => replies.next().unwrap_or_default(),
                _ => &[],
            },
        )
    }

    /// `0x04 || eph_u || envelope_ct || record_ct... || tail_ct...`.
    pub fn auditor_message(&self) -> Vec<u8> {
        let records = self.outputs.iter().map(|output| &output.record[..]);
        let tails = self
            .outputs
            .iter()
            .filter_map(|output| output.tail.map(|tail| &tail[..]));
        AuditorMessage::data(
            self.eph_u,
            core::iter::once(self.envelope).chain(records).chain(tails),
        )
    }

    /// The SPP data the program forwards, `b` decompressed for SPP's verifier.
    pub fn expand(&self, ring: &RingPolicy) -> Result<TransactIxData, CustomRingError> {
        self.transact_ix_data(ring, self.spp_proof_points()?)
    }

    pub fn spp_instruction_data(&self, ring: &RingPolicy) -> Result<Vec<u8>, CustomRingError> {
        self.spp_instruction_data_under(ring, self.spp_proof_points()?)
    }

    fn spp_proof_points(&self) -> Result<TransactProof, CustomRingError> {
        let b = groth16_solana::decompression::decompress_g2(&self.spp_proof.proof_b)
            .map_err(|_| CustomRingError::InvalidSppProofPoint)?;
        Ok(TransactProof {
            a: self.spp_proof.proof_a,
            b,
            c: self.spp_proof.proof_c,
        })
    }

    /// The tag and the expansion under `proof` in one buffer, the program's heap holds no second copy.
    pub fn spp_instruction_data_under(
        &self,
        ring: &RingPolicy,
        proof: TransactProof,
    ) -> Result<Vec<u8>, CustomRingError> {
        let expanded = self.transact_ix_data(ring, proof)?;
        validate_interface_transfers(&expanded.interface_transfers).map_err(invalid)?;
        let size = usize::try_from(wincode::serialized_size(&expanded).map_err(invalid)?)
            .map_err(invalid)?;
        let mut out = vec![0u8; 1 + size];
        out[0] = self.rail.spp_tag();
        wincode::serialize_into(&mut out[1..], &expanded).map_err(invalid)?;
        Ok(out)
    }

    /// The external data hash the SPP proof binds, computable before either proof exists.
    pub fn external_data_hash(
        &self,
        ring: &RingPolicy,
        settlements: &[Settlement<'_>],
    ) -> Result<[u8; 32], CustomRingError> {
        let expanded = self
            .transact_ix_data(ring, TransactProof::zeroed())?
            .serialize()
            .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let (_, external_data_prefix) =
            TransactIxDataRef::parse_with_external_data_prefix(&expanded)
                .map_err(|_| CustomRingError::InvalidInstructionData)?;
        let tag = [self.rail.spp_tag()];
        let mut preimage = ExternalDataPreimage::new(&tag, external_data_prefix);
        for settlement in settlements {
            preimage.push_settlement(settlement.asset_account, settlement.user_account)?;
        }
        Ok(preimage.finish()?)
    }

    /// The expansion under `proof`, a client sizes the transaction with a zeroed one.
    pub fn transact_ix_data(
        &self,
        ring: &RingPolicy,
        proof: TransactProof,
    ) -> Result<TransactIxData, CustomRingError> {
        let view_tag: [u8; 32] = core::array::from_fn(|i| ring.auditor_pubkey[i + 1]);
        Ok(TransactIxData {
            expiry_unix_ts: u64::from(self.expiry_unix_ts),
            tx_viewing_pk: tagged_x25519(self.tx_viewing_u),
            salt: *self.salt,
            interface_transfers: self.interface_transfers.clone(),
            data_hash: self.extensions.data_hash.copied(),
            ring_data_hash: self.extensions.ring_data_hash.copied(),
            outputs: {
                let mut outputs = Vec::with_capacity(self.outputs.len());
                for (output, reply) in self.outputs.iter().zip(self.slot_replies()) {
                    outputs.push(output.transact_output(reply)?);
                }
                outputs
            },
            // The auditor message stays last.
            messages: self
                .sender
                .map(|sender| {
                    encode_ring_sender_bundle_output(sender.body).map(|data| MessageData {
                        view_tag: *sender.tag,
                        data,
                    })
                })
                .transpose()?
                .into_iter()
                .chain(self.extensions.messages.iter().map(|message| MessageData {
                    view_tag: *message.view_tag,
                    data: message.data.to_vec(),
                }))
                .chain([MessageData {
                    view_tag,
                    data: self.auditor_message(),
                }])
                .collect(),
            private_tx_hash: *self.private_tx_hash,
            circuit: self.circuit(),
            proof,
            inputs: self
                .nullifiers
                .iter()
                .enumerate()
                .map(|(input, nullifier)| InputUtxo {
                    nullifier_hash: *nullifier,
                    tree_index: self.input_trees.tree_index(input),
                })
                .collect(),
            tree_contexts: self.input_trees.contexts(),
        })
    }

    fn flags(&self) -> TransactFlags {
        let bits = [
            (self.policy.is_some(), transact_flag::POLICY),
            (
                self.policy
                    .is_some_and(|policy| policy.curator_revision.is_some()),
                transact_flag::CURATOR,
            ),
            (
                self.policy.is_none() && self.own_revision.is_some(),
                transact_flag::OWN_ROOT,
            ),
            (self.in_proof_owner.is_some(), transact_flag::OWNER_IN_PROOF),
            (self.public_owners, transact_flag::PUBLIC_OWNERS),
            (
                matches!(self.input_trees, InputTrees::Two { .. }),
                transact_flag::SECOND_TREE,
            ),
            (self.replies.is_some(), transact_flag::REPLY_METADATA),
            (!self.extensions.is_empty(), transact_flag::EXTENSIONS),
        ];
        TransactFlags(
            bits.into_iter()
                .filter(|(set, _)| *set)
                .fold(0, |flags, (_, bit)| flags | bit),
        )
    }
}

/// Byte 0 of the compact data, one bit per optional section.
pub mod transact_flag {
    pub const BYTE: usize = 0;
    pub const POLICY: u8 = 1 << 0;
    pub const CURATOR: u8 = 1 << 1;
    /// The frame's thresholds read the own registry with no policy hash.
    pub const OWN_ROOT: u8 = 1 << 2;
    /// The confidential rail's owner signs inside SPP's anonymous rail proof.
    pub const OWNER_IN_PROOF: u8 = 1 << 3;
    /// An anonymous ring's frame with every live owner a published signer.
    pub const PUBLIC_OWNERS: u8 = 1 << 4;
    pub const SECOND_TREE: u8 = 1 << 5;
    /// Anonymous family only, the frame carries one reply per body-bearing slot.
    pub const REPLY_METADATA: u8 = 1 << 6;
    /// The frame carries SPP's optional fields.
    pub const EXTENSIONS: u8 = 1 << 7;
}

/// Byte 1, the index into `SPP_SUPPORTED_SHAPES` below these flags.
pub mod shape_flag {
    pub const BYTE: usize = 1;
    pub const DEFAULT_OWNER_TAG: u8 = 1 << 6;
    /// One tail per published slot and one length per body.
    pub const HAS_DATA: u8 = 1 << 7;
}

/// Byte 2, the published input count below these flags.
pub mod input_flag {
    pub const BYTE: usize = 2;
    pub const NO_SPEND: u8 = 1 << 6;
    pub const ENTRY: u8 = 1 << 7;
}

pub const OUTPUT_COUNT_BYTE: usize = 3;

/// Byte 4, the approval mask and the co-signer count above it.
pub mod authorization_byte {
    pub const BYTE: usize = 4;
    pub const APPROVAL_MASK: u8 = 0b0000_0011;
    pub const CO_SIGNERS_SHIFT: u32 = 2;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TransactFlags(u8);

impl TransactFlags {
    const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// The approval mask needs the own root its thresholds read, the delegate reads no policy and proves no threshold.
    fn check(self, rail: RingRail, authorization: Authorization) -> Result<(), CustomRingError> {
        let foreign_owner =
            self.has(transact_flag::OWNER_IN_PROOF) && rail != RingRail::Confidential;
        let foreign_public_owners =
            self.has(transact_flag::PUBLIC_OWNERS) && rail != RingRail::Anonymous;
        let foreign_reply =
            self.has(transact_flag::REPLY_METADATA) && !rail.is_anonymous_family();
        let delegate_reads_policy =
            rail.is_delegate() && (self.reads_own_root() || self.has(transact_flag::CURATOR));
        let delegate_approval = rail.is_delegate()
            && (!authorization.approval_mask.is_empty() || authorization.co_signers != 0);
        let curator_without_policy =
            self.has(transact_flag::CURATOR) && !self.has(transact_flag::POLICY);
        let approval_without_root =
            !authorization.approval_mask.is_empty() && !self.reads_own_root();
        if foreign_owner
            || foreign_public_owners
            || foreign_reply
            || delegate_reads_policy
            || delegate_approval
            || curator_without_policy
            || approval_without_root
            || authorization.co_signers > MAX_CO_SIGNERS
        {
            return Err(CustomRingError::FlagNotAllowed);
        }
        Ok(())
    }

    const fn reads_own_root(self) -> bool {
        self.has(transact_flag::POLICY) || self.has(transact_flag::OWN_ROOT)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Authorization {
    approval_mask: ApprovalMask,
    co_signers: u8,
}

impl Authorization {
    fn read(byte: u8) -> Result<Self, CustomRingError> {
        Ok(Self {
            approval_mask: ApprovalMask::new(byte & authorization_byte::APPROVAL_MASK)?,
            co_signers: byte >> authorization_byte::CO_SIGNERS_SHIFT,
        })
    }

    const fn byte(self) -> u8 {
        self.approval_mask.bits() | self.co_signers << authorization_byte::CO_SIGNERS_SHIFT
    }
}

/// The delegate's cached selector has no SPP rail, its entry would spend default-ring notes.
fn check_extensions(
    extensions: &FrameExtensions<'_>,
    rail: RingRail,
) -> Result<(), CustomRingError> {
    match rail.is_delegate() && extensions.cache.is_some() {
        true => Err(CustomRingError::FlagNotAllowed),
        false => Ok(()),
    }
}

/// Bytes 1 to 4 of the compact data, the SPP shape's index and the input count below their flags, `m`, then the authorization byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameHeader {
    n_in: u8,
    n_out: u8,
    input_count: u8,
    output_count: u8,
    flags: FrameFlags,
    authorization: Authorization,
}

impl FrameHeader {
    /// The shape index or the input count, bits 6 and 7 carry the flags.
    const LOW: u8 = 0b0011_1111;
    /// The flags byte and these four.
    const LEN: usize = 5;

    fn read(bytes: &mut Bytes<'_>, rail: RingRail) -> Result<Self, CustomRingError> {
        let [shape, inputs, output_count, authorization] = *bytes.array()?;
        let spp_shape = SPP_SUPPORTED_SHAPES
            .get(usize::from(shape & Self::LOW))
            .ok_or(CustomRingError::RingShapeUnkeyed)?;
        let flags = FrameFlags {
            default_owner_tag: shape & shape_flag::DEFAULT_OWNER_TAG != 0,
            has_data: shape & shape_flag::HAS_DATA != 0,
            no_spend: inputs & input_flag::NO_SPEND != 0,
            entry: inputs & input_flag::ENTRY != 0,
        };
        flags.check(rail)?;
        let header = Self {
            n_in: count_byte(spp_shape.n_inputs())?,
            n_out: count_byte(spp_shape.n_outputs())?,
            input_count: inputs & Self::LOW,
            output_count,
            flags,
            authorization: Authorization::read(authorization)?,
        };
        header.check_output_count()?;
        Ok(header)
    }

    fn of(data: &RingTransactData<'_>) -> Result<Self, CustomRingError> {
        let flags = FrameFlags::of(data);
        flags.check(data.rail)?;
        let header = Self {
            n_in: data.n_in,
            n_out: data.n_out,
            input_count: count_byte(data.nullifiers.len())?,
            output_count: count_byte(data.outputs.len())?,
            flags,
            authorization: Authorization {
                approval_mask: data.approval_mask,
                co_signers: data.co_signers,
            },
        };
        header.check_output_count()?;
        Ok(header)
    }

    const fn check_output_count(self) -> Result<(), CustomRingError> {
        match self.output_count >= 1 && self.output_count <= self.n_out {
            true => Ok(()),
            false => Err(CustomRingError::OutputCountOutOfRange),
        }
    }

    /// A public-owner frame carries no hidden owner's default tag.
    const fn check_rail_flags(
        self,
        rail: RingRail,
        flags: TransactFlags,
    ) -> Result<(), CustomRingError> {
        let public_tag = flags.has(transact_flag::PUBLIC_OWNERS) && self.flags.default_owner_tag;
        match public_tag || (rail.is_delegate() && self.flags.no_spend) {
            true => Err(CustomRingError::FlagNotAllowed),
            false => Ok(()),
        }
    }

    fn bytes(self) -> Result<[u8; 4], CustomRingError> {
        let shape = Shape::new(usize::from(self.n_in), usize::from(self.n_out));
        let index = SPP_SUPPORTED_SHAPES
            .iter()
            .position(|supported| *supported == shape)
            .ok_or(CustomRingError::RingShapeUnkeyed)?;
        if self.input_count > Self::LOW {
            return Err(CustomRingError::RingTransactLength);
        }
        let flag = |set: bool, bit: u8| if set { bit } else { 0 };
        let flags = self.flags;
        Ok([
            index as u8
                | flag(flags.default_owner_tag, shape_flag::DEFAULT_OWNER_TAG)
                | flag(flags.has_data, shape_flag::HAS_DATA),
            self.input_count
                | flag(flags.no_spend, input_flag::NO_SPEND)
                | flag(flags.entry, input_flag::ENTRY),
            self.output_count,
            self.authorization.byte(),
        ])
    }
}

const _: () = assert!(
    SPP_SUPPORTED_SHAPES.len() <= FrameHeader::LOW as usize + 1
        && spr_interface::MAX_TRANSACT_INPUTS <= FrameHeader::LOW as usize
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameFlags {
    /// Shape byte bit 6, the anonymous rail's default owner tag follows the commitment pok.
    default_owner_tag: bool,
    /// Shape byte bit 7.
    has_data: bool,
    /// Input byte bit 6.
    no_spend: bool,
    /// Input byte bit 7.
    entry: bool,
}

impl FrameFlags {
    fn of(data: &RingTransactData<'_>) -> Self {
        Self {
            default_owner_tag: data
                .anonymous
                .is_some_and(|anonymous| anonymous.default_owner_tag.is_some()),
            has_data: data.has_data,
            no_spend: data.no_spend,
            entry: data.entry,
        }
    }

    /// The anonymous rail alone takes a default owner tag, the delegate cannot spend a default-ring note.
    fn check(self, rail: RingRail) -> Result<(), CustomRingError> {
        let foreign_tag = self.default_owner_tag && rail != RingRail::Anonymous;
        match foreign_tag || (self.entry && rail.is_delegate()) {
            true => Err(CustomRingError::FlagNotAllowed),
            false => Ok(()),
        }
    }

    const fn audit_layout(self) -> AuditLayout {
        AuditLayout {
            has_data: self.has_data,
            entry: self.entry,
        }
    }
}

fn invalid<E>(_: E) -> CustomRingError {
    CustomRingError::InvalidInstructionData
}

fn count_byte(count: usize) -> Result<u8, CustomRingError> {
    u8::try_from(count).map_err(|_| CustomRingError::RingTransactLength)
}

fn push_bitmap(out: &mut Vec<u8>, bits: impl ExactSizeIterator<Item = bool>) {
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];
    for (index, _) in bits.enumerate().filter(|(_, set)| *set) {
        bytes[index / 8] |= 1 << (index % 8);
    }
    out.extend_from_slice(&bytes);
}

fn tree_context_len(context: TreeContext) -> Result<usize, CustomRingError> {
    let size = wincode::serialized_size(&context).map_err(invalid)?;
    usize::try_from(size).map_err(invalid)
}

fn push_tree_context(out: &mut Vec<u8>, context: TreeContext) -> Result<(), CustomRingError> {
    out.extend(
        <TreeContext as Serialize>::serialize(&context)
            .map_err(|_| CustomRingError::InvalidInstructionData)?,
    );
    Ok(())
}
