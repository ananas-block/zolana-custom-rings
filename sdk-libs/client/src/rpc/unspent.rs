//! `getUnspentUtxos`, what the auditor opened and has not seen spent, beside how far it looked.

use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};

use super::{
    base64, cursor_in_bounds, wallet_line, Attestation, ReadAuth, ReadBuildError, ReadSigner,
    ReadTarget, SignedRequest,
};

pub const GET_UNSPENT_UTXOS: &str = "getUnspentUtxos";
const UNSPENT_UTXOS_DOMAIN: &str = "zolana/ring-rpc-unspent-utxos/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetUnspentUtxosRequest {
    /// Required for derived keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ring_program_id: Option<SerializablePubkey>,
    /// The owner's record member, `solana_owner_identity(owner)`.
    pub owner: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
    /// Scopes the read to a wallet grant, it names the same owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<SerializablePubkey>,
    pub auth: ReadAuth,
}

/// Notes not seen spent through the finalized coverage boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetUnspentUtxosResponse {
    pub utxos: Vec<UnspentUtxoView>,
    pub coverage: Coverage,
    /// Empty on a wallet read, a row names another owner's spend links.
    pub unresolved: Vec<UnresolvedHistory>,
    pub cursor: Option<Base64String>,
}

/// Absence from the spend index proves nothing outside these slots or while `complete` is false.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Coverage {
    /// The first slot past the newest historical row, older notes are never covered.
    pub from_slot: u64,
    /// The completed finalized history boundary.
    pub through_slot: u64,
    /// False after a failed or partial pass, or while a spend or merge in the window has an input the auditor cannot name.
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnspentUtxoView {
    pub utxo_hash: Hash,
    pub asset: Hash,
    /// Absent while the asset registry does not know the asset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<SerializablePubkey>,
    pub amount: u64,
    pub kind: UnspentUtxoKind,
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub slot_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum UnspentUtxoKind {
    /// A note whose full opening rebuilt its commitment.
    #[serde(rename_all = "camelCase")]
    Opened { blinding: Hash, tree_id: u16 },
    /// An audit record of inherited fields, a wallet cannot spend from it.
    MergeOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnresolvedHistory {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub reason: UnresolvedReason,
    /// The commitments the auditor cannot name, empty on a historical row.
    pub inputs: Vec<Hash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UnresolvedReason {
    /// A transfer's evidence names a commitment no opening holds.
    UnknownSpend,
    /// A merge output waits on the opening of an input.
    UnknownMergeInput,
    /// A prefix-only evidence row fits several notes or none.
    HistoricalPrefix,
    /// A confirmed row the auditor could not read.
    UnreadableRow,
}

/// Binds the owner, the row set a grant scopes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnspentUtxosAttestation {
    pub target: ReadTarget,
    pub owner: [u8; 32],
    pub cursor: Option<Base64String>,
    pub wallet: Option<Address>,
}

#[must_use]
pub struct UnspentUtxosRequest {
    signed: SignedRequest<UnspentUtxosAttestation>,
}

impl Attestation for UnspentUtxosAttestation {
    fn message(&self, timestamp: u64, nonce: &[u8; 32]) -> Vec<u8> {
        let cursor = self.cursor.as_ref().map_or(&[][..], |cursor| &cursor.0);
        format!(
            "{UNSPENT_UTXOS_DOMAIN}\n{}\ntimestamp: {timestamp}\nnonce: {}\nowner: {}\ncursor: {}{}",
            self.target.lines(),
            base64(nonce),
            Hash(self.owner).to_base58(),
            base64(cursor),
            wallet_line(self.wallet),
        )
        .into_bytes()
    }
}

impl UnspentUtxosRequest {
    pub fn new(target: ReadTarget, owner: [u8; 32]) -> Self {
        Self {
            signed: SignedRequest::new(UnspentUtxosAttestation {
                target,
                owner,
                cursor: None,
                wallet: None,
            }),
        }
    }

    pub fn at(self, timestamp: u64) -> Self {
        Self {
            signed: self.signed.at(timestamp),
        }
    }

    pub fn with_cursor(mut self, cursor: Base64String) -> Result<Self, ReadBuildError> {
        if !cursor_in_bounds(&cursor.0) {
            return Err(ReadBuildError::Cursor);
        }
        self.signed.attestation.cursor = Some(cursor);
        Ok(self)
    }

    pub fn with_wallet(mut self, wallet: Address) -> Self {
        self.signed.attestation.wallet = Some(wallet);
        self
    }

    pub fn sign<S: ReadSigner + ?Sized>(
        self,
        signer: &S,
    ) -> Result<GetUnspentUtxosRequest, ReadBuildError> {
        let auth = self.signed.read_auth(signer)?;
        let UnspentUtxosAttestation {
            target,
            owner,
            cursor,
            wallet,
        } = self.signed.attestation;
        Ok(GetUnspentUtxosRequest {
            ring_program_id: Some(target.ring.to_bytes().into()),
            owner: Hash(owner),
            cursor,
            wallet: wallet.map(Into::into),
            auth,
        })
    }
}
