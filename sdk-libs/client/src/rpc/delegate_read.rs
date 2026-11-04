//! `getDelegateNotes`, a victim's openings and secret for the ring's configured delegate alone.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};

use super::{
    base64, Attestation, GetWalletStatusResponse, ReadTarget, RequestBuildError, SignedRequest,
};

pub const GET_DELEGATE_NOTES: &str = "getDelegateNotes";
const DELEGATE_NOTES_DOMAIN: &str = "zolana/ring-rpc-delegate-notes/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDelegateNotesRequest {
    pub ring: SerializablePubkey,
    pub delegate: SerializablePubkey,
    pub owner: SerializablePubkey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
    pub timestamp: u64,
    pub nonce: Base64String,
    /// Raw Ed25519 over the `DelegateNotesAttestation` message.
    pub signature: SerializableSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetDelegateNotesResponse {
    /// Absent while the owner holds only zero key notes or its seal is unread, right aligned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier_secret: Option<Hash>,
    pub status: GetWalletStatusResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateNotesAttestation {
    pub target: ReadTarget,
    pub delegate: Address,
    pub owner: Address,
    pub cursor: Option<Base64String>,
}

pub type DelegateNotesRequest = SignedRequest<DelegateNotesAttestation>;

impl Attestation for DelegateNotesAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        let cursor = self.cursor.as_ref().map_or(&[][..], |cursor| &cursor.0);
        format!(
            "{DELEGATE_NOTES_DOMAIN}\n{}\ndelegate: {}\nowner: {}\ncursor: {}\ntimestamp: {timestamp}\nnonce: {}",
            self.target.lines(),
            self.delegate,
            self.owner,
            base64(cursor),
            base64(nonce),
        )
        .into_bytes()
    }
}

impl DelegateNotesRequest {
    /// `delegate` must be the attestation's delegate, the service checks the signature against it.
    pub fn sign<S: Signer + ?Sized>(
        self,
        delegate: &S,
    ) -> Result<GetDelegateNotesRequest, RequestBuildError> {
        let (timestamp, message) = self.message()?;
        let signature = delegate
            .try_sign_message(&message)
            .map_err(RequestBuildError::Signature)?;
        Ok(GetDelegateNotesRequest {
            ring: self.attestation.target.ring.into(),
            delegate: self.attestation.delegate.into(),
            owner: self.attestation.owner.into(),
            cursor: self.attestation.cursor.clone(),
            timestamp,
            nonce: self.nonce.to_vec().into(),
            signature: signature.into(),
        })
    }
}
