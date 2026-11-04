//! The compact transact data a proven transfer owns, and its instruction.

use custom_ring_interface::{
    cosign::ApprovalMask, statement::SignerDataCounts, storage::Revision, tag, AnonymousProofData,
    AppMessage, CustomRingProof, FrameExtensions, FramedSenderBundle, InProofOwner, InputTrees, PlainGroth16Proof, PolicyProof,
    Replies, RingOutput, RingPolicy, RingRail, RingTransactData, RootRead, SlotBody,
    AUDIT_RECORD_LEN, DATA_TAIL_LEN, MAX_SPP_CPI_ACCOUNTS,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_interface::instruction::{
    instruction_data::transact::CacheAccess, InterfaceTransfer, TransactProof,
};
use spr_program::instruction::{
    RingAuthorityTransact, RingTransact, TransactInterfaceTransferAccounts,
};

use crate::{CustomRing, RingError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OwnedBody {
    None,
    Recipient(Vec<u8>),
    Exit(Vec<u8>),
}

impl OwnedBody {
    fn of(body: SlotBody<'_>) -> Self {
        match body {
            SlotBody::None => Self::None,
            SlotBody::Recipient(body) => Self::Recipient(body.to_vec()),
            SlotBody::Exit(body) => Self::Exit(body.to_vec()),
        }
    }

    fn view(&self) -> SlotBody<'_> {
        match self {
            Self::None => SlotBody::None,
            Self::Recipient(body) => SlotBody::Recipient(body),
            Self::Exit(body) => SlotBody::Exit(body),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedOutput {
    pub hash: [u8; 32],
    pub owner_tag: [u8; 32],
    pub body: OwnedBody,
    pub record: [u8; AUDIT_RECORD_LEN],
    pub tail: Option<[u8; DATA_TAIL_LEN]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedSenderBundle {
    pub tag: [u8; 32],
    pub body: Vec<u8>,
}

impl OwnedSenderBundle {
    pub fn of(sender: FramedSenderBundle<'_>) -> Self {
        Self {
            tag: *sender.tag,
            body: sender.body.to_vec(),
        }
    }

    pub fn view(&self) -> FramedSenderBundle<'_> {
        FramedSenderBundle {
            tag: &self.tag,
            body: &self.body,
        }
    }
}

impl OwnedOutput {
    pub fn of(output: RingOutput<'_>) -> Self {
        Self {
            hash: *output.hash,
            owner_tag: output.owner_tag,
            body: OwnedBody::of(output.body),
            record: *output.record,
            tail: output.tail.copied(),
        }
    }

    pub fn is_exit(&self) -> bool {
        matches!(self.body, OwnedBody::Exit(_))
    }

    pub fn view(&self) -> RingOutput<'_> {
        RingOutput {
            hash: &self.hash,
            owner_tag: self.owner_tag,
            body: self.body.view(),
            record: &self.record,
            tail: self.tail.as_ref(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedAppMessage {
    pub view_tag: [u8; 32],
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OwnedExtensions {
    pub data_hash: Option<[u8; 32]>,
    pub ring_data_hash: Option<[u8; 32]>,
    pub messages: Vec<OwnedAppMessage>,
    pub cache: Option<CacheAccess>,
    pub approval_totals: Option<[u8; 32]>,
    pub signer_data_counts: Option<SignerDataCounts>,
}

impl OwnedExtensions {
    fn view(&self) -> FrameExtensions<'_> {
        FrameExtensions {
            data_hash: self.data_hash.as_ref(),
            ring_data_hash: self.ring_data_hash.as_ref(),
            messages: self
                .messages
                .iter()
                .map(|message| AppMessage {
                    view_tag: &message.view_tag,
                    data: &message.data,
                })
                .collect(),
            cache: self.cache,
            approval_totals: self.approval_totals.as_ref(),
            signer_data_counts: self.signer_data_counts,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnedInProofOwner {
    pub owner: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnedAnonymousProofData {
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
    pub default_owner_tag: Option<[u8; 32]>,
}

/// [`RingTransactData`] with every borrowed part owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransactParts {
    pub rail: RingRail,
    pub n_in: u8,
    pub n_out: u8,
    pub proof: CustomRingProof,
    pub tracking_revision: Revision,
    pub own_revision: Option<Revision>,
    pub policy: Option<PolicyProof>,
    pub spl_withdrawal_owners: Vec<[u8; 32]>,
    pub approval: ApprovalMask,
    pub no_spend: bool,
    pub public_owners: bool,
    pub expiry_unix_ts: u32,
    pub tx_viewing_u: [u8; 32],
    pub salt: [u8; 16],
    pub extensions: OwnedExtensions,
    pub interface_transfers: Vec<InterfaceTransfer>,
    pub has_data: bool,
    pub entry: bool,
    pub wide_owners: bool,
    pub outputs: Vec<OwnedOutput>,
    /// `reply_len` and the region, set exactly under `REPLY_METADATA`.
    pub replies: Option<(u16, Vec<u8>)>,
    pub sender: Option<OwnedSenderBundle>,
    pub envelope: Vec<u8>,
    pub private_tx_hash: [u8; 32],
    pub anonymous: Option<OwnedAnonymousProofData>,
    pub in_proof_owner: Option<OwnedInProofOwner>,
    pub spp_proof: PlainGroth16Proof,
    pub nullifiers: Vec<[u8; 32]>,
    pub input_trees: InputTrees,
}

impl TransactParts {
    /// Each record and tail sits beside its slot.
    pub fn seal_audit(
        &mut self,
        envelope: Vec<u8>,
        records: &[[u8; AUDIT_RECORD_LEN]],
        tails: &[[u8; DATA_TAIL_LEN]],
    ) {
        self.envelope = envelope;
        for (slot, output) in self.outputs.iter_mut().enumerate() {
            if let Some(record) = records.get(slot) {
                output.record = *record;
            }
            output.tail = tails.get(slot).copied();
        }
    }

    pub fn data(&self) -> RingTransactData<'_> {
        RingTransactData {
            rail: self.rail,
            n_in: self.n_in,
            n_out: self.n_out,
            proof: &self.proof,
            tracking_revision: self.tracking_revision,
            own_revision: self.own_revision,
            policy: self.policy,
            spl_withdrawal_owners: &self.spl_withdrawal_owners,
            approval: self.approval,
            no_spend: self.no_spend,
            public_owners: self.public_owners,
            expiry_unix_ts: self.expiry_unix_ts,
            tx_viewing_u: &self.tx_viewing_u,
            salt: &self.salt,
            extensions: self.extensions.view(),
            interface_transfers: self.interface_transfers.clone(),
            has_data: self.has_data,
            entry: self.entry,
            wide_owners: self.wide_owners,
            outputs: self.outputs.iter().map(OwnedOutput::view).collect(),
            replies: self
                .replies
                .as_ref()
                .map(|(len, region)| Replies { len: *len, region }),
            sender: self.sender.as_ref().map(OwnedSenderBundle::view),
            envelope: &self.envelope,
            private_tx_hash: &self.private_tx_hash,
            anonymous: self.anonymous.as_ref().map(|anonymous| AnonymousProofData {
                commitment: &anonymous.commitment,
                commitment_pok: &anonymous.commitment_pok,
                default_owner_tag: anonymous.default_owner_tag.as_ref(),
            }),
            in_proof_owner: self.in_proof_owner.as_ref().map(|owner| InProofOwner {
                owner: &owner.owner,
                commitment: &owner.commitment,
                commitment_pok: &owner.commitment_pok,
            }),
            spp_proof: &self.spp_proof,
            nullifiers: &self.nullifiers,
            input_trees: self.input_trees,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransactAccounts {
    pub payer: Address,
    /// One per tree context, in the data's order.
    pub input_trees: Vec<Address>,
    pub output_tree: Address,
    /// Only the confidential rail names owner signers.
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub co_signers: Vec<Address>,
    pub delegate: Option<Address>,
}

impl TransactAccounts {
    /// The ring prefix, then SPP's own list, the data's tag by its rail.
    pub fn instruction(
        &self,
        ring: CustomRing,
        config: &RingPolicy,
        parts: &TransactParts,
    ) -> Result<Instruction, RingError> {
        let data = parts.data();
        let expanded = data.transact_ix_data(config, TransactProof::zeroed())?;
        let spp = match parts.rail {
            RingRail::Delegate | RingRail::AnonymousDelegate => {
                RingAuthorityTransact {
                    payer: self.payer,
                    input_trees: self.input_trees.clone(),
                    output_tree: self.output_tree,
                    ring_program_id: ring.program_id(),
                    interface_transfer_accounts: self.interface_transfer_accounts.clone(),
                    data: expanded,
                }
                .instruction()
                .accounts
            }
            RingRail::Confidential | RingRail::Anonymous => {
                RingTransact {
                    payer: self.payer,
                    input_trees: self.input_trees.clone(),
                    output_tree: self.output_tree,
                    ring_program_id: ring.program_id(),
                    owner_signers: self.owner_signers.clone(),
                    interface_transfer_accounts: self.interface_transfer_accounts.clone(),
                    data: expanded,
                }
                .instruction()
                .accounts
            }
        };
        if spp.len() > MAX_SPP_CPI_ACCOUNTS {
            return Err(RingError::TooManySettlementAccounts {
                accounts: spp.len(),
                limit: MAX_SPP_CPI_ACCOUNTS,
            });
        }
        let mut accounts = vec![AccountMeta::new_readonly(ring.policy_pda(), false)];
        accounts.extend(
            config
                .root_registries(RootRead::transfer(config, parts.rail.is_delegate()))
                .map(|registry| AccountMeta::new_readonly(registry, false)),
        );
        accounts.extend(
            self.co_signers
                .iter()
                .flat_map(|co_signer| ring.co_signer_metas(*co_signer)),
        );
        accounts.extend(
            self.delegate
                .map(|delegate| AccountMeta::new_readonly(delegate, true)),
        );
        accounts.extend(spp);
        let mut bytes = vec![match parts.rail.is_delegate() {
            true => tag::AUTHORITY_TRANSFER,
            false => tag::TRANSFER,
        }];
        bytes.extend(data.encode()?);
        Ok(Instruction {
            program_id: ring.program_id(),
            accounts,
            data: bytes,
        })
    }
}
