//! The one ring proof of a transfer, one request over the audit and policy sections.

use custom_ring_interface::{key_catalog::RingCircuit, CustomRingProof, RingRail};
use serde::Serialize;
use spr_client::AsyncRpc;
use spr_hasher::hash_chain::create_nonzero_hash_chain_from_slice;
use spr_transaction::TransactionError;

use super::{audit::AuditSection, policy::PolicyProving, Assembled};
use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    prover::{to_instruction_proof, RingRequest},
    request::{AnonymousTransfer, ConfidentialTransfer, Opening, TransferParams},
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
        };
        let transfer = TransferParams {
            public_input_hash: self.public_input_hash,
            audit: audit.params()?,
            exempt: frame.policy.exempt,
            approval_required: frame.policy.approval_required,
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
                let input_hashes: Vec<[u8; 32]> = frame
                    .proof_inputs
                    .input_utxos
                    .iter()
                    .map(|input| input.private_tx_input_hash())
                    .collect();
                TransferBody::Confidential(Box::new(ConfidentialTransfer {
                    transfer,
                    in_proof,
                    delegate,
                    outputs: audit.delivered_outputs()?,
                    inputs: match in_proof || delegate {
                        true => audit.input_openings(usize::from(class))?,
                        false => vec![Opening::default(); usize::from(class)],
                    },
                    input_chain: create_nonzero_hash_chain_from_slice(&input_hashes)?,
                    sender: self.sender,
                    sender_pk_hash: frame.sender_pk_hash,
                }))
            }
            RingCircuit::TransferAnonymous { class, .. }
            | RingCircuit::TransferAnonymousEntry { class, .. } => {
                let entry = matches!(circuit, RingCircuit::TransferAnonymousEntry { .. });
                let count = frame.published_inputs;
                TransferBody::Anonymous(Box::new(AnonymousTransfer {
                    transfer,
                    outputs: audit.anonymous_outputs()?,
                    sender_key: entry.then(|| audit.sender_key()).transpose()?,
                    input_count: u8::try_from(count).map_err(|_| {
                        TransactionError::TooManyInputs {
                            got: count,
                            max: usize::from(u8::MAX),
                        }
                    })?,
                    inputs: audit.input_openings(usize::from(class))?,
                    party_identities: self.party_identities,
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
