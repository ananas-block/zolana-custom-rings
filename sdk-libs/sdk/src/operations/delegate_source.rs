//! The key a delegate move spends a source's notes under. The public zero key needs no
//! enrollment, any other key comes only from the source's enrollment and must derive the
//! address the request names.
//!
//! Read [`ResolvedSource::resolve`] first, then [`ResolvedSource::check_notes`] on the recovered
//! notes before they reach a [`DelegateSource`](crate::DelegateSource).

use async_trait::async_trait;
use custom_ring_interface::tracking::TrackingAuthorization;
use solana_address::Address;
use spr_client::{AsyncRpc, ClientError};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{KeypairError, NullifierKey, ShieldedAddress, X25519Keypair, X25519Pubkey};
use spr_transaction::WalletUtxo;
use thiserror::Error;
use zolana_ring_client::{AuditError, SealedNullifierKey};

use crate::pipeline::same_owner;

#[derive(Debug, Error)]
pub enum DelegateSourceError {
    #[error("the source wallet has no enrolled nullifier key")]
    Unenrolled,
    #[error("the enrolled key derives another nullifier key than the source address names")]
    KeyMismatch,
    #[error("the enrollment seal opens to another key than its record holds")]
    SealMismatch,
    #[error("note {index} belongs to another owner or key than the source")]
    ForeignNote { index: usize },
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Seal(#[from] AuditError),
}

/// The single enrollment read every nonzero source resolves through.
#[async_trait]
pub trait SourceEnrollment: Sync {
    type Error: From<DelegateSourceError> + Send;

    /// `None` when `source` holds no enrollment.
    async fn escrowed_key(
        &self,
        source: &ShieldedAddress,
    ) -> Result<Option<NullifierKey>, Self::Error>;
}

pub struct TrackingEnrollment<'a, R> {
    pub rpc: &'a R,
    pub tracking_registry: Address,
    pub auditor: &'a X25519Keypair,
}

#[async_trait]
impl<R: AsyncRpc> SourceEnrollment for TrackingEnrollment<'_, R> {
    type Error = DelegateSourceError;

    async fn escrowed_key(
        &self,
        source: &ShieldedAddress,
    ) -> Result<Option<NullifierKey>, DelegateSourceError> {
        let owner = source.solana_address()?;
        let (authorization, _) =
            TrackingAuthorization::find_address(&self.tracking_registry, &owner);
        let Some(enrolled) = self
            .rpc
            .get_account(authorization)
            .await?
            .and_then(|account| TrackingAuthorization::decode(&account.owner, &account.data))
        else {
            return Ok(None);
        };
        let key = SealedNullifierKey {
            eph_pk: X25519Pubkey::from_u(enrolled.eph_u)?,
            ciphertext: enrolled.ciphertext,
        }
        .open(self.auditor)?;
        // The seal's pad alone does not bind the opened key to the storage program's record.
        if key.pubkey()? != enrolled.nullifier_pk {
            return Err(DelegateSourceError::SealMismatch);
        }
        Ok(Some(key))
    }
}

/// Only [`ResolvedSource::resolve`] builds one, the key is the zero key or the enrolled key.
pub struct ResolvedSource {
    address: ShieldedAddress,
    nullifier_key: NullifierKey,
}

impl ResolvedSource {
    pub async fn resolve<E: SourceEnrollment + ?Sized>(
        address: ShieldedAddress,
        enrollment: &E,
    ) -> Result<Self, E::Error> {
        // 1. The zero key's secret is public, its notes need no escrow.
        let nullifier_key = match address.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY {
            true => NullifierKey::from_secret([0; 31]),
            false => enrollment
                .escrowed_key(&address)
                .await?
                .ok_or(DelegateSourceError::Unenrolled)?,
        };
        // 2. An enrollment under another key would spend notes the named address does not hold.
        let derived = nullifier_key.pubkey().map_err(DelegateSourceError::from)?;
        if derived != address.nullifier_pubkey {
            return Err(DelegateSourceError::KeyMismatch.into());
        }
        Ok(Self {
            address,
            nullifier_key,
        })
    }

    /// Refuses the first note another owner holds or another key nullifies.
    pub fn check_notes(&self, notes: &[WalletUtxo]) -> Result<(), DelegateSourceError> {
        for (index, note) in notes.iter().enumerate() {
            let nullifier = self
                .nullifier_key
                .nullifier(&note.utxo_hash, &note.utxo.blinding)?;
            let owned = same_owner(&note.utxo.owner, &self.address.signing_pubkey)
                && note.nullifier_pubkey == self.address.nullifier_pubkey
                && note.nullifier == nullifier;
            if !owned {
                return Err(DelegateSourceError::ForeignNote { index });
            }
        }
        Ok(())
    }

    pub fn nullifier_key(&self) -> &NullifierKey {
        &self.nullifier_key
    }

    pub fn into_nullifier_key(self) -> NullifierKey {
        self.nullifier_key
    }
}

#[cfg(test)]
#[path = "../tests/operations/delegate_source.rs"]
mod tests;
