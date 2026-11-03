//! The one ring proof of a transfer, one request over the audit and policy sections.

use custom_ring_interface::ciphertext_digest;
use custom_ring_interface::{
    delivered_body_len, key_catalog::RingCircuit, CustomRingProof, RingRail,
};
use serde::Serialize;
use spr_client::AsyncRpc;
use spr_hasher::primitives::solana_owner_identity;
use spr_transaction::TransactionError;

use super::{audit::AuditSection, policy::PolicyProving, Assembled};
use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    prover::{to_instruction_proof, RingRequest},
    request::{AnonymousTransfer, ConfidentialTransfer, TransferParams},
    RingError,
};

pub(crate) struct TransferRequest<'a> {
    pub circuit: RingCircuit,
    pub public_input_hash: [u8; 32],
    pub body: TransferBody<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum TransferBody<'a> {
    Confidential(Box<ConfidentialTransfer<'a>>),
    Anonymous(Box<AnonymousTransfer<'a>>),
}

impl Assembled {
    pub(crate) fn request(&self) -> Result<TransferRequest<'_>, RingError> {
        let frame = &self.frame;
        let parts = &frame.parts;
        let circuit = frame.policy.circuit();
        let audit = AuditSection {
            rail: &frame.rail,
            sealed: &frame.sealed,
            published: frame
                .rail
                .published_slots(&frame.proof_inputs, &frame.sender)?,
            inputs: &frame.proof_inputs,
            sender: &frame.sender,
            auditor: &self.auditor,
            body_len: delivered_body_len(parts.key_escrow),
        };
        let input_count =
            u8::try_from(frame.published_inputs).map_err(|_| TransactionError::TooManyInputs {
                got: frame.published_inputs,
                max: usize::from(u8::MAX),
            })?;
        let too_many = |got: usize| TransactionError::TooManyInputs {
            got,
            max: usize::from(u8::MAX),
        };
        let owner_run = &frame.accounts.owner_signers;
        let transfer = TransferParams {
            public_input_hash: self.public_input_hash,
            audit: audit.params()?,
            exempt: frame.policy.exempt,
            approval_required: frame.policy.approval_required,
            output_count: u8::try_from(parts.outputs.len())
                .map_err(|_| too_many(parts.outputs.len()))?,
            input_count,
            signer_count: u8::try_from(owner_run.len()).map_err(|_| too_many(owner_run.len()))?,
            private_tx_hash: parts.private_tx_hash,
            private_tx_blinding: frame.private_tx_blinding,
            policy: frame.policy.params(&PolicyProving {
                ring_id: frame.ring_id,
                public_assets: &frame.public_assets,
                public_amounts: &frame.public_amount_fields,
                public_gross: &frame.public_gross,
            })?,
        };
        let body = match circuit {
            RingCircuit::TransferConfidential { inputs: class, .. } => {
                let in_proof = parts.in_proof_owner.is_some();
                let delegate = parts.rail == RingRail::Delegate;
                TransferBody::Confidential(Box::new(ConfidentialTransfer {
                    transfer,
                    in_proof,
                    delegate,
                    outputs: audit.delivered_outputs()?,
                    inputs: audit.input_openings(usize::from(class))?,
                    sender: self.sender,
                    sender_pk_hash: frame.sender_pk_hash,
                    signers: signer_identities(owner_run, usize::from(class))?,
                }))
            }
            RingCircuit::TransferAnonymous { class, .. }
            | RingCircuit::TransferAnonymousEntry { class, .. } => {
                let entry = matches!(circuit, RingCircuit::TransferAnonymousEntry { .. });
                let sender_address = frame
                    .policy
                    .sender_address
                    .ok_or(RingError::SenderNotEnrolled)?;
                TransferBody::Anonymous(Box::new(AnonymousTransfer {
                    transfer,
                    outputs: audit.anonymous_outputs(&frame.policy.slot_addresses)?,
                    sender_key: entry.then(|| audit.sender_key()).transpose()?,
                    inputs: audit.input_openings(usize::from(class))?,
                    party_identities: self.party_identities,
                    signers: match entry {
                        true => Vec::new(),
                        false => signer_identities(owner_run, usize::from(class))?,
                    },
                    sender_nullifier_pk: sender_address.nullifier_pk,
                    sender_viewing_key: sender_address.viewing_u,
                    sender_address_revision: sender_address.address_revision,
                    sender_bundle_tag: frame
                        .rail
                        .published_sender(&frame.proof_inputs, &frame.sender.viewing_pubkey)?
                        .map_or([0; 32], |bundle| *bundle.tag),
                    reply_digest: match &parts.replies {
                        Some((_, region)) => ciphertext_digest(region)?,
                        None => [0; 32],
                    },
                }))
            }
            RingCircuit::ApplyRecords { .. }
            | RingCircuit::RegisterKey
            | RingCircuit::Deposit { .. }
            | RingCircuit::Merge { .. } => return Err(RingError::UncataloguedCircuit(circuit)),
        };
        Ok(TransferRequest {
            circuit,
            public_input_hash: self.public_input_hash,
            body,
        })
    }
}

/// The owner run in its order, zero past the run.
fn signer_identities(
    owners: &[solana_address::Address],
    slots: usize,
) -> Result<Vec<[u8; 32]>, RingError> {
    let mut identities = owners
        .iter()
        .map(|owner| Ok(solana_owner_identity(owner.as_array())?))
        .collect::<Result<Vec<_>, RingError>>()?;
    identities.resize(slots, [0; 32]);
    Ok(identities)
}

impl TransferRequest<'_> {
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<CustomRingProof, RingError> {
        let proof = RingRequest::new(self.circuit, &self.body)?
            .prove(client, self.public_input_hash)
            .await?;
        to_instruction_proof(proof)
    }
}
