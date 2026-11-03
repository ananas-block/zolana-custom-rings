//! The compact `Transfer` and `AuthorityTransfer` data, read in place and expanded into
//! the SPP `TransactIxData` the SPP proof's external data hash covers.

use solana_address::Address;
use spr_hasher::{
    primitives::{pack_be, solana_owner_identity},
    HasherError,
};
use spr_interface::{
    instruction::{
        instruction_data::{
            transact::{AnonymousRingEddsaProofData, Bsb22Commitment},
            validate_interface_transfers,
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
    audit_stream::{AuditKey, AuditStreamLayout},
    bytes::Bytes,
    disclosure::{AnonymousSpend, AuditLayout},
    error::CustomRingError,
    key_catalog::{RingCircuit, TransferShape, TransferSpend, CONFIDENTIAL_TRANSFER_SHAPES},
    output::{
        encode_anonymous_recipient_output, encode_anonymous_sender_output,
        encode_confidential_output, encode_ring_confidential_delivered_output,
        CONFIDENTIAL_DATA_FREE_BODY_LEN,
    },
    statement::{AuditHead, TransferFamily, TransferStatement},
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

/// The program rail the data serves, fixed by the instruction tag and the ring mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingRail {
    Confidential,
    Anonymous,
    /// `AuthorityTransfer`, the SPP authority rail of a policy ring in `ConfidentialEscrow` mode.
    Delegate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RailSigner {
    /// The confidential rail's owner signer run.
    Owners,
    /// The anonymous rail, the payer alone signs.
    Payer,
    Delegate(Address),
}

impl RailSigner {
    pub fn new(tag: InstructionTag, ring: &RingPolicy) -> Result<Self, CustomRingError> {
        match RingRail::of(tag, ring.mode()?)? {
            RingRail::Anonymous => Ok(Self::Payer),
            RingRail::Confidential => Ok(Self::Owners),
            // Only SetDelegate writes a delegate, together with `ConfidentialEscrow` mode on a policy ring.
            RingRail::Delegate => ring
                .delegate()
                .copied()
                .map(Self::Delegate)
                .ok_or(CustomRingError::DelegateDisabled),
        }
    }

    pub const fn rail(self) -> RingRail {
        match self {
            Self::Owners => RingRail::Confidential,
            Self::Payer => RingRail::Anonymous,
            Self::Delegate(_) => RingRail::Delegate,
        }
    }
}

impl RingRail {
    pub fn new(tag: InstructionTag, ring: &RingPolicy) -> Result<Self, CustomRingError> {
        RailSigner::new(tag, ring).map(RailSigner::rail)
    }

    pub fn of(tag: InstructionTag, mode: RingMode) -> Result<Self, CustomRingError> {
        match (tag, mode) {
            (InstructionTag::Transfer | InstructionTag::LegacyTransact, RingMode::Anonymous) => {
                Ok(Self::Anonymous)
            }
            (
                InstructionTag::Transfer | InstructionTag::LegacyTransact,
                RingMode::Confidential | RingMode::ConfidentialEscrow,
            ) => Ok(Self::Confidential),
            (
                InstructionTag::AuthorityTransfer | InstructionTag::LegacyDelegateTransact,
                RingMode::Anonymous,
            ) => Err(CustomRingError::AnonymousRingRefused),
            (
                InstructionTag::AuthorityTransfer | InstructionTag::LegacyDelegateTransact,
                RingMode::Confidential | RingMode::ConfidentialEscrow,
            ) => Ok(Self::Delegate),
            _ => Err(CustomRingError::InvalidInstructionData),
        }
    }

    pub const fn spp_tag(self) -> u8 {
        match self {
            Self::Confidential | Self::Anonymous => RING_TRANSACT,
            Self::Delegate => RING_AUTHORITY_TRANSACT,
        }
    }

    pub const fn publishes_recipients(self) -> bool {
        !matches!(self, Self::Anonymous)
    }

    fn circuit(self, n_in: u8, n_out: u8, proof_data: AnonymousRingEddsaProofData) -> CircuitId {
        let slots = N_PUBLIC_SLOTS as u8;
        match self {
            Self::Confidential => CircuitId::ConfidentialRingEddsa(n_in, n_out, slots),
            Self::Anonymous => CircuitId::AnonymousRingEddsa(n_in, n_out, slots, proof_data),
            Self::Delegate => CircuitId::RingAuthority(n_in, n_out, slots),
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
        let key = match self {
            Self::Confidential | Self::Delegate => {
                TransferShape::of(&CONFIDENTIAL_TRANSFER_SHAPES, n_out)
                    .filter(|shape| inputs <= usize::from(shape.inputs))
                    .map(|shape| AuditKey::Confidential {
                        class: usize::from(shape.inputs),
                        input_prefixes: header.owner_in_proof || self == Self::Delegate,
                    })
            }
            Self::Anonymous => AnonymousSpend {
                inputs,
                outputs: n_out,
                spends_default_ring: header.flags.full_openings,
            }
            .audit_key()
            .map(AuditKey::Anonymous),
        };
        let key = key
            .filter(|_| supported)
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
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyProof<'a> {
    /// Token owners checked on chain, in SPL withdrawal order.
    pub spl_withdrawal_owners: &'a [[u8; 32]],
    /// Set exactly when a source names a curator registry.
    pub curator_revision: Option<Revision>,
    pub recipients: PolicyRecipients<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRecipients<'a> {
    /// The anonymous rail, every recipient zero.
    Hidden,
    /// One owner identity per output slot.
    Framed(&'a [[u8; 32]]),
}

/// Zero where the frame reads none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferRoots {
    pub policy_hash: [u8; 32],
    pub own_root: [u8; 32],
    pub curator_root: [u8; 32],
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

/// A published output slot without its SPP framing, with one ring disclosure ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingOutput<'a> {
    /// The confidential and delegate rails, scheme 10.
    Delivered {
        hash: &'a [u8; 32],
        u: &'a [u8; 32],
        /// The layout's key escrow flag fixes the length.
        body: &'a [u8],
    },
    /// Under a view tag, its scheme 1 body unproven.
    Anonymous {
        hash: &'a [u8; 32],
        tag: &'a [u8; 32],
        /// `None` on a change output, the sender bundle covers it.
        body: Option<&'a [u8]>,
        /// In the auditor message.
        record: &'a [u8],
    },
    /// A default-ring output, scheme 3 under its own owner tag.
    Exit {
        hash: &'a [u8; 32],
        owner_tag: &'a [u8; 32],
        payload: &'a [u8],
        /// In the auditor message.
        record: &'a [u8],
    },
}

impl<'a> RingOutput<'a> {
    pub const fn hash(&self) -> &'a [u8; 32] {
        match self {
            Self::Delivered { hash, .. }
            | Self::Anonymous { hash, .. }
            | Self::Exit { hash, .. } => hash,
        }
    }

    pub const fn owner_tag(&self) -> &'a [u8; 32] {
        match self {
            Self::Delivered { u: tag, .. }
            | Self::Anonymous { tag, .. }
            | Self::Exit { owner_tag: tag, .. } => tag,
        }
    }

    pub const fn is_exit(&self) -> bool {
        matches!(self, Self::Exit { .. })
    }

    /// The slot's ring disclosure ciphertext, the statement chains its hash.
    pub const fn ciphertext(&self) -> &'a [u8] {
        match self {
            Self::Delivered { body, .. } => body,
            Self::Anonymous { record, .. } | Self::Exit { record, .. } => record,
        }
    }

    /// The slot's bytes in the auditor message, empty on a delivered slot.
    pub const fn record(&self) -> &'a [u8] {
        match self {
            Self::Delivered { .. } => &[],
            Self::Anonymous { record, .. } | Self::Exit { record, .. } => record,
        }
    }

    /// `pack_be(u)` of a delivered slot, zeros for any other.
    pub fn recipient_key_fields(&self) -> [[u8; 32]; 2] {
        match self {
            Self::Delivered { u, .. } => pack_be(u),
            _ => [ZERO_FIELD; 2],
        }
    }

    /// The SPP output, the owner tag and the scheme framing rebuilt from the slot.
    pub fn transact_output(&self) -> Result<TransactOutput, CustomRingError> {
        let (owner_tag, data) = match *self {
            Self::Delivered { u, body, .. } => {
                (*u, Some(encode_ring_confidential_delivered_output(body)?))
            }
            Self::Anonymous { tag, body, .. } => (
                *tag,
                body.map(encode_anonymous_recipient_output).transpose()?,
            ),
            Self::Exit {
                owner_tag, payload, ..
            } => (*owner_tag, Some(encode_confidential_output(payload)?)),
        };
        Ok(TransactOutput {
            utxo_hash: *self.hash(),
            owner_tag: OwnerTag::Inline(owner_tag),
            data,
        })
    }

    /// Whether the slot uses the output encoding the key's family gives ring outputs.
    const fn fits(&self, key: AuditKey) -> bool {
        matches!(
            (self, key),
            (Self::Exit { .. }, _)
                | (Self::Delivered { .. }, AuditKey::Confidential { .. })
                | (Self::Anonymous { .. }, AuditKey::Anonymous(_))
        )
    }

    fn slot_frame_len(&self) -> usize {
        32 + match self {
            Self::Delivered { body, .. } => 32 + body.len(),
            Self::Anonymous { body, .. } => 32 + 2 + body.map_or(0, <[u8]>::len),
            Self::Exit { payload, .. } => 32 + payload.len(),
        }
    }

    /// A delivered slot has no record, the others read theirs after the output section.
    fn set_record(&mut self, bytes: &'a [u8]) {
        if let Self::Anonymous { record, .. } | Self::Exit { record, .. } = self {
            *record = bytes;
        }
    }
}

/// Bit `i` set when slot `i` exits.
pub fn exits_bitmap(outputs: &[RingOutput<'_>]) -> u64 {
    outputs
        .iter()
        .enumerate()
        .filter(|(_, output)| output.is_exit())
        .fold(0, |bits, (slot, _)| bits | 1 << slot)
}

/// No output carries data, every exit payload is a data-free scheme 3 body.
#[derive(Clone, Copy)]
struct SlotFrame {
    stream: AuditStreamLayout,
}

impl SlotFrame {
    fn read_exit<'a>(self, bytes: &mut Bytes<'a>) -> Result<RingOutput<'a>, CustomRingError> {
        Ok(RingOutput::Exit {
            hash: bytes.array()?,
            owner_tag: bytes.array()?,
            payload: bytes.take(CONFIDENTIAL_DATA_FREE_BODY_LEN)?,
            record: &[],
        })
    }

    fn read_ring<'a>(self, bytes: &mut Bytes<'a>) -> Result<RingOutput<'a>, CustomRingError> {
        let hash = bytes.array()?;
        Ok(match self.stream.key {
            AuditKey::Confidential { .. } => RingOutput::Delivered {
                hash,
                u: bytes.array()?,
                body: bytes.take(self.stream.delivered_body_len())?,
            },
            AuditKey::Anonymous(_) => {
                let tag = bytes.array()?;
                let body = read_anonymous_body(bytes)?;
                RingOutput::Anonymous {
                    hash,
                    tag,
                    body: (!body.is_empty()).then_some(body),
                    record: &[],
                }
            }
        })
    }

    fn write(self, output: &RingOutput<'_>, out: &mut Vec<u8>) -> Result<(), CustomRingError> {
        out.extend_from_slice(output.hash());
        match output {
            RingOutput::Delivered { u, body, .. } => {
                out.extend_from_slice(*u);
                out.extend_from_slice(body);
                Ok(())
            }
            RingOutput::Anonymous { tag, body, .. } => {
                out.extend_from_slice(*tag);
                match body {
                    Some(body) => write_anonymous_body(body, out),
                    None => {
                        out.extend_from_slice(&0u16.to_le_bytes());
                        Ok(())
                    }
                }
            }
            RingOutput::Exit {
                owner_tag, payload, ..
            } if payload.len() == CONFIDENTIAL_DATA_FREE_BODY_LEN => {
                out.extend_from_slice(*owner_tag);
                out.extend_from_slice(payload);
                Ok(())
            }
            RingOutput::Exit { .. } => Err(CustomRingError::DataFreeBodyLength),
        }
    }
}

/// Scheme 2, forwarded under its tag as the first SPP message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SenderBundle<'a> {
    pub tag: &'a [u8; 32],
    pub body: &'a [u8],
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

    /// The statement the transfer proof is verified against, a key escrow flag off the ring mode
    /// refused.
    pub fn transfer_statement<'s>(
        &'s self,
        binding: TransferBinding<'s>,
    ) -> Result<TransferStatement<'s>, CustomRingError> {
        let data = &self.data;
        if binding.key_escrow != data.key_escrow {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let family = match self.stream.key {
            AuditKey::Confidential { .. } => TransferFamily::Confidential {
                in_proof: data.in_proof_owner.is_some(),
                delegate: data.rail == RingRail::Delegate,
                sender: binding.sender,
                recipients: binding.recipients,
            },
            AuditKey::Anonymous(_) => TransferFamily::Anonymous {
                party_identities: binding.party_identities,
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
            exempt: data.exempt,
            approval_required: data.approval_required,
            outputs: &data.outputs,
            input_count: data.nullifiers.len(),
            private_tx_hash: data.private_tx_hash,
            policy_hash: &binding.roots.policy_hash,
            own_root: &binding.roots.own_root,
            curator_root: &binding.roots.curator_root,
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
    /// The ring mode escrows every output nullifier key, the frame flag has to agree.
    pub key_escrow: bool,
    /// The sole owner signer's or the in-proof owner's identity under a policy, zero otherwise.
    pub sender: &'a [u8; 32],
    /// Zero outside the anonymous rail.
    pub party_identities: &'a [[u8; 32]; 3],
    /// One per output slot, `RingTransactData::recipients`.
    pub recipients: &'a [[u8; 32]],
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
    /// SPP shape outputs.
    pub n_out: u8,
    pub proof: &'a CustomRingProof,
    /// Present exactly under a policy or an exemption.
    pub own_revision: Option<Revision>,
    /// Present exactly on a policy ring.
    pub policy: Option<PolicyProof<'a>>,
    pub exempt: bool,
    pub approval_required: bool,
    pub expiry_unix_ts: u32,
    pub tx_viewing_u: &'a [u8; 32],
    /// Random per attempt, a resend under the same first nullifier reuses no keystream.
    pub salt: &'a [u8; 16],
    pub interface_transfers: Vec<InterfaceTransfer>,
    /// The policy proof escrows every output nullifier key, the ring mode's.
    pub key_escrow: bool,
    /// The anonymous entry key, every spent UTXO opens in full.
    pub full_openings: bool,
    /// Published order.
    pub outputs: Vec<RingOutput<'a>>,
    /// Present exactly on the anonymous rail.
    pub sender: Option<SenderBundle<'a>>,
    pub eph_u: &'a [u8; 32],
    /// `envelope_ct`, the transmitted length is the stream layout's.
    pub envelope: &'a [u8],
    pub private_tx_hash: &'a [u8; 32],
    /// Present exactly on the anonymous rail.
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
        flags.check(rail)?;
        let header = FrameHeader::read(&mut bytes, rail, flags)?;
        let input_count = header.input_count;
        let key = rail.audit_key(&header)?;
        let output_count = usize::from(header.n_out);
        let proof = bytes.pod()?;
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
                recipients: match rail.publishes_recipients() {
                    false => PolicyRecipients::Hidden,
                    true => PolicyRecipients::Framed(bytes.fields(output_count)?),
                },
            }),
        };
        let expiry_unix_ts = bytes.u32()?;
        let tx_viewing_u = bytes.array()?;
        let salt = bytes.array()?;
        let interface_transfers = bytes.interface_transfers()?;
        if flags.has(transact_flag::EXEMPT) && !withdraws(&interface_transfers) {
            return Err(CustomRingError::ExemptionWithoutWithdrawal);
        }
        if let Some(policy) = &mut policy {
            policy.spl_withdrawal_owners =
                bytes.fields(crate::spl_withdrawal_count(&interface_transfers))?;
        }
        let exits = bytes.bitmap(output_count)?;
        if rail == RingRail::Delegate && exits != 0 {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let stream = AuditStreamLayout {
            key,
            key_escrow: header.flags.key_escrow,
            inputs: usize::from(input_count),
            outputs: output_count,
            exits,
        };
        let frame = SlotFrame { stream };
        let mut outputs = Vec::with_capacity(output_count);
        for slot in 0..output_count {
            outputs.push(match (exits >> slot) & 1 {
                1 => frame.read_exit(&mut bytes)?,
                _ => frame.read_ring(&mut bytes)?,
            });
        }
        let sender = match rail {
            RingRail::Anonymous => Some(SenderBundle {
                tag: bytes.array()?,
                body: Some(read_anonymous_body(&mut bytes)?)
                    .filter(|body| !body.is_empty())
                    .ok_or(CustomRingError::AnonymousBodyLength)?,
            }),
            RingRail::Confidential | RingRail::Delegate => None,
        };
        let eph_u = bytes.array()?;
        let envelope = bytes.take(stream.envelope().len)?;
        for (slot, output) in outputs.iter_mut().enumerate() {
            output.set_record(bytes.take(stream.record_len(slot))?);
        }
        let private_tx_hash = bytes.array()?;
        let anonymous = match rail {
            RingRail::Anonymous => Some(AnonymousProofData {
                commitment: bytes.array()?,
                commitment_pok: bytes.array()?,
                default_owner_tag: header
                    .flags
                    .default_owner_tag
                    .then(|| bytes.array())
                    .transpose()?,
            }),
            RingRail::Confidential | RingRail::Delegate => None,
        };
        let in_proof_owner = match header.owner_in_proof {
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
            own_revision,
            policy,
            exempt: flags.has(transact_flag::EXEMPT),
            approval_required: flags.has(transact_flag::APPROVAL_REQUIRED),
            expiry_unix_ts,
            tx_viewing_u,
            salt,
            interface_transfers,
            key_escrow: header.flags.key_escrow,
            full_openings: header.flags.full_openings,
            outputs,
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
        flags.check(self.rail)?;
        let header = FrameHeader::of(self)?;
        let output_count = self.outputs.len();
        let stream = self.audit_stream()?;
        let anonymous_rail = self.rail == RingRail::Anonymous;
        let frame = SlotFrame { stream };
        let policy_fits = self.policy.is_none_or(|policy| match policy.recipients {
            PolicyRecipients::Hidden => anonymous_rail,
            PolicyRecipients::Framed(recipients) => {
                !anonymous_rail && recipients.len() == output_count
            }
        });
        if self.exempt && !withdraws(&self.interface_transfers) {
            return Err(CustomRingError::ExemptionWithoutWithdrawal);
        }
        if !policy_fits
            || self.own_revision.is_some() != flags.reads_own_root()
            || self.anonymous.is_some() != anonymous_rail
            || self.sender.is_some() != anonymous_rail
            || self.envelope.len() != stream.envelope().len
            || !self.outputs.iter().enumerate().all(|(slot, output)| {
                output.fits(stream.key) && output.ciphertext().len() == stream.ciphertext_len(slot)
            })
        {
            return Err(CustomRingError::RingTransactLength);
        }
        if self.rail == RingRail::Delegate && self.outputs.iter().any(RingOutput::is_exit) {
            return Err(CustomRingError::FlagNotAllowed);
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
        if let Some(revision) = self.own_revision {
            out.extend_from_slice(&revision.0);
        }
        if let Some(policy) = &self.policy {
            if let Some(revision) = policy.curator_revision {
                out.extend_from_slice(&revision.0);
            }
            if let PolicyRecipients::Framed(recipients) = policy.recipients {
                out.extend_from_slice(recipients.as_flattened());
            }
        }
        out.extend_from_slice(&self.expiry_unix_ts.to_le_bytes());
        out.extend_from_slice(self.tx_viewing_u);
        out.extend_from_slice(self.salt);
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
        for output in &self.outputs {
            frame.write(output, &mut out)?;
        }
        if let Some(sender) = self.sender {
            out.extend_from_slice(sender.tag);
            write_anonymous_body(sender.body, &mut out)?;
        }
        out.extend_from_slice(self.eph_u);
        out.extend_from_slice(self.envelope);
        for output in &self.outputs {
            out.extend_from_slice(output.record());
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
            let recipients = match policy.recipients {
                PolicyRecipients::Hidden => 0,
                PolicyRecipients::Framed(recipients) => recipients.len(),
            };
            policy.curator_revision.map_or(0, |_| revision)
                + FIELD * (recipients + policy.spl_withdrawal_owners.len())
        });
        let sender = self
            .sender
            .map_or(0, |sender| FIELD + 2 + sender.body.len());
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
        Ok(1 + 2
            + core::mem::size_of::<CustomRingProof>()
            + self.own_revision.map_or(0, |_| revision)
            + policy
            + 4
            + FIELD
            + 16
            + interface_transfers
            + self.outputs.len().div_ceil(8)
            + self
                .outputs
                .iter()
                .map(RingOutput::slot_frame_len)
                .sum::<usize>()
            + sender
            + FIELD
            + stream.envelope().len
            + stream.records_len()
            + FIELD
            + anonymous
            + in_proof_owner
            + core::mem::size_of::<PlainGroth16Proof>()
            + FIELD * inputs
            + trees)
    }

    /// Refuses a frame whose sections disagree with the ring's policy.
    pub fn roots(
        &self,
        policy: Option<&RingPolicy>,
        roots: &LiveRoots<'_>,
    ) -> Result<TransferRoots, CustomRingError> {
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
        if self.approval_required && self.rail == RingRail::Delegate {
            return Err(CustomRingError::UnexpectedApproval);
        }
        let mut bound = TransferRoots::default();
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
            spends_default_ring: self.full_openings,
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

    /// The SPP selector of the data's shape and rail.
    pub fn circuit(&self) -> CircuitId {
        if let Some(owner) = &self.in_proof_owner {
            return RingRail::Anonymous.circuit(self.n_in, self.n_out, owner.proof_data());
        }
        let proof_data =
            self.anonymous
                .map_or(NO_PROOF_DATA, |anonymous| AnonymousRingEddsaProofData {
                    bsb22_commitment: Bsb22Commitment {
                        commitment: *anonymous.commitment,
                        commitment_pok: *anonymous.commitment_pok,
                    },
                    default_owner_tag: anonymous.default_owner_tag.copied(),
                });
        self.rail.circuit(self.n_in, self.n_out, proof_data)
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

    /// One per output slot, zero off a policy and on the anonymous rail.
    pub fn recipients(&self) -> Vec<[u8; 32]> {
        match self.policy.map(|policy| policy.recipients) {
            Some(PolicyRecipients::Framed(recipients)) => recipients.to_vec(),
            Some(PolicyRecipients::Hidden) | None => vec![ZERO_FIELD; self.outputs.len()],
        }
    }

    pub fn audit_layout(&self) -> AuditLayout {
        FrameFlags::of(self).audit_layout()
    }

    /// Every ciphertext length of the transfer, refusing a frame no key serves.
    pub fn audit_stream(&self) -> Result<AuditStreamLayout, CustomRingError> {
        let key = self.rail.audit_key(&FrameHeader::of(self)?)?;
        let outputs = usize::from(self.n_out);
        if self.outputs.len() != outputs {
            return Err(CustomRingError::RingTransactLength);
        }
        Ok(AuditStreamLayout {
            key,
            key_escrow: self.key_escrow,
            inputs: self.nullifiers.len(),
            outputs,
            exits: exits_bitmap(&self.outputs),
        })
    }

    /// `0x04 || eph_u || envelope_ct || record_ct...`.
    pub fn auditor_message(&self) -> Vec<u8> {
        AuditorMessage::data(
            self.eph_u,
            core::iter::once(self.envelope).chain(self.outputs.iter().map(RingOutput::record)),
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
            data_hash: None,
            ring_data_hash: None,
            outputs: {
                let mut outputs = Vec::with_capacity(self.outputs.len());
                for output in &self.outputs {
                    outputs.push(output.transact_output()?);
                }
                outputs
            },
            // The auditor message stays last.
            messages: self
                .sender
                .map(|sender| {
                    encode_anonymous_sender_output(sender.body).map(|data| MessageData {
                        view_tag: *sender.tag,
                        data,
                    })
                })
                .transpose()?
                .into_iter()
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
            (self.approval_required, transact_flag::APPROVAL_REQUIRED),
            (self.in_proof_owner.is_some(), transact_flag::OWNER_IN_PROOF),
            (self.exempt, transact_flag::EXEMPT),
            (
                matches!(self.input_trees, InputTrees::Two { .. }),
                transact_flag::SECOND_TREE,
            ),
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
    pub const APPROVAL_REQUIRED: u8 = 1 << 2;
    /// The confidential rail's owner signs inside SPP's anonymous rail proof.
    pub const OWNER_IN_PROOF: u8 = 1 << 3;
    /// Every public withdrawal stays within its record's threshold, the proof binds the claim.
    pub const EXEMPT: u8 = 1 << 4;
    pub const SECOND_TREE: u8 = 1 << 5;
    /// Bits 6 and 7 are refused.
    pub const KNOWN: u8 =
        POLICY | CURATOR | APPROVAL_REQUIRED | OWNER_IN_PROOF | EXEMPT | SECOND_TREE;
}

/// Byte 1, the index into `SPP_SUPPORTED_SHAPES` below these flags.
pub mod shape_flag {
    pub const BYTE: usize = 1;
    pub const DEFAULT_OWNER_TAG: u8 = 1 << 6;
    /// Bit 7 is refused.
    pub const RESERVED: u8 = 1 << 7;
}

/// Byte 2, the published input count below these flags.
pub mod input_flag {
    pub const BYTE: usize = 2;
    pub const KEY_ESCROW: u8 = 1 << 6;
    pub const FULL_OPENINGS: u8 = 1 << 7;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TransactFlags(u8);

impl TransactFlags {
    const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// The curator and approval flags need a policy, the in-proof owner flag the confidential rail, the exempt flag never a delegate frame.
    fn check(self, rail: RingRail) -> Result<(), CustomRingError> {
        let foreign_owner =
            self.has(transact_flag::OWNER_IN_PROOF) && rail != RingRail::Confidential;
        let delegate_exempt = self.has(transact_flag::EXEMPT) && rail == RingRail::Delegate;
        if self.0 & !transact_flag::KNOWN != 0 || foreign_owner || delegate_exempt {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let needs_policy =
            self.has(transact_flag::CURATOR) || self.has(transact_flag::APPROVAL_REQUIRED);
        if needs_policy && !self.has(transact_flag::POLICY) {
            return Err(CustomRingError::FlagNotAllowed);
        }
        Ok(())
    }

    const fn reads_own_root(self) -> bool {
        self.has(transact_flag::POLICY) || self.has(transact_flag::EXEMPT)
    }
}

/// Bytes 1 and 2 of the compact data, the SPP shape's index and the input count below their flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameHeader {
    n_in: u8,
    n_out: u8,
    input_count: u8,
    flags: FrameFlags,
    /// Byte 0's `OWNER_IN_PROOF`, the audit takes the sender key.
    owner_in_proof: bool,
}

impl FrameHeader {
    /// The shape index or the input count, bits 6 and 7 carry the flags.
    const LOW: u8 = 0b0011_1111;

    fn read(
        bytes: &mut Bytes<'_>,
        rail: RingRail,
        transact: TransactFlags,
    ) -> Result<Self, CustomRingError> {
        let [shape, inputs] = *bytes.array()?;
        if shape & shape_flag::RESERVED != 0 {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let spp_shape = SPP_SUPPORTED_SHAPES
            .get(usize::from(shape & Self::LOW))
            .ok_or(CustomRingError::RingShapeUnkeyed)?;
        let flags = FrameFlags {
            default_owner_tag: shape & shape_flag::DEFAULT_OWNER_TAG != 0,
            key_escrow: inputs & input_flag::KEY_ESCROW != 0,
            full_openings: inputs & input_flag::FULL_OPENINGS != 0,
        };
        flags.check(rail)?;
        Ok(Self {
            n_in: count_byte(spp_shape.n_inputs())?,
            n_out: count_byte(spp_shape.n_outputs())?,
            input_count: inputs & Self::LOW,
            flags,
            owner_in_proof: transact.has(transact_flag::OWNER_IN_PROOF),
        })
    }

    fn of(data: &RingTransactData<'_>) -> Result<Self, CustomRingError> {
        let flags = FrameFlags::of(data);
        flags.check(data.rail)?;
        Ok(Self {
            n_in: data.n_in,
            n_out: data.n_out,
            input_count: count_byte(data.nullifiers.len())?,
            flags,
            owner_in_proof: data.in_proof_owner.is_some(),
        })
    }

    fn bytes(self) -> Result<[u8; 2], CustomRingError> {
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
            index as u8 | flag(flags.default_owner_tag, shape_flag::DEFAULT_OWNER_TAG),
            self.input_count
                | flag(flags.key_escrow, input_flag::KEY_ESCROW)
                | flag(flags.full_openings, input_flag::FULL_OPENINGS),
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
    /// Input byte bit 6.
    key_escrow: bool,
    /// Input byte bit 7, the anonymous entry key.
    full_openings: bool,
}

impl FrameFlags {
    fn of(data: &RingTransactData<'_>) -> Self {
        Self {
            default_owner_tag: data
                .anonymous
                .is_some_and(|anonymous| anonymous.default_owner_tag.is_some()),
            key_escrow: data.key_escrow,
            full_openings: data.full_openings,
        }
    }

    /// The anonymous rail alone takes a default owner tag and the entry key, the audit binding
    /// holds the key escrow flag to the ring mode.
    fn check(self, rail: RingRail) -> Result<(), CustomRingError> {
        match rail != RingRail::Anonymous && (self.default_owner_tag || self.full_openings) {
            true => Err(CustomRingError::FlagNotAllowed),
            false => Ok(()),
        }
    }

    fn audit_layout(self) -> AuditLayout {
        AuditLayout {
            key_escrow: self.key_escrow,
            full_openings: self.full_openings,
        }
    }
}

fn invalid<E>(_: E) -> CustomRingError {
    CustomRingError::InvalidInstructionData
}

fn withdraws(transfers: &[InterfaceTransfer]) -> bool {
    transfers.iter().any(|transfer| !transfer.is_deposit())
}

fn read_anonymous_body<'a>(bytes: &mut Bytes<'a>) -> Result<&'a [u8], CustomRingError> {
    let len = bytes.u16()?;
    bytes.take(usize::from(len))
}

fn write_anonymous_body(body: &[u8], out: &mut Vec<u8>) -> Result<(), CustomRingError> {
    let len = u16::try_from(body.len())
        .ok()
        .filter(|len| *len != 0)
        .ok_or(CustomRingError::AnonymousBodyLength)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    Ok(())
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
