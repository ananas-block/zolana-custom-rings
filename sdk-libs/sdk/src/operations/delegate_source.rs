//! The key a delegate move spends a source's notes under, and the notes the move may spend. The
//! public zero key needs no enrollment, any other key comes only from the source's enrollment and
//! must derive the address the request names.
//!
//! Read [`ResolvedSource::resolve`] first, then [`ResolvedSource::check_notes`] on the recovered
//! notes before they reach a [`DelegateSource`](crate::DelegateSource), or
//! [`AllowedNullifiers::admit`] per requested source on the relay path.

use std::collections::BTreeSet;

use async_trait::async_trait;
use custom_ring_interface::InputClass;
use solana_address::Address;
use spr_client::{AsyncRpc, ClientError};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{
    KeypairError, NullifierKey, ShieldedAddress, X25519Keypair, SHIELDED_ADDRESS_LEN,
};
use spr_transaction::{TransactionError, WalletUtxo};
use thiserror::Error;
use zolana_ring_client::{CredentialError, CredentialLookup, CredentialResolver};

use crate::pipeline::same_owner;

#[derive(Debug, Error)]
pub enum DelegateSourceError {
    #[error("the source wallet has no enrolled nullifier key")]
    Unenrolled,
    #[error("the enrolled key derives another nullifier key than the source address names")]
    KeyMismatch,
    #[error("note {index} belongs to another owner or key than the source")]
    ForeignNote { index: usize },
    #[error("note {index} does not rebuild the hash or nullifier it carries")]
    UnboundOpening { index: usize },
    #[error("the allowed notes cover other sources than the request names")]
    SourcesMismatch,
    #[error("input {position} spends a note no requested source opening derives")]
    UnrequestedInput { position: usize },
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Credential(#[from] CredentialError),
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

/// The auditor opens the sealed key of the source's credential, only a present credential holds one.
pub struct CredentialEnrollment<'a, P, R> {
    pub photon: &'a P,
    pub rpc: &'a R,
    pub ring: Address,
    pub auditor: &'a X25519Keypair,
}

#[async_trait]
impl<P: AsyncRpc, R: AsyncRpc> SourceEnrollment for CredentialEnrollment<'_, P, R> {
    type Error = DelegateSourceError;

    async fn escrowed_key(
        &self,
        source: &ShieldedAddress,
    ) -> Result<Option<NullifierKey>, DelegateSourceError> {
        let owner = source.solana_address()?;
        match CredentialResolver::new(self.ring, owner)
            .resolve(self.photon, self.rpc)
            .await?
        {
            CredentialLookup::Present(present) => Ok(Some(present.nullifier_key(self.auditor)?)),
            CredentialLookup::Absent(_) => Ok(None),
            // A queued or partly served enrollment is no evidence of a missing one.
            CredentialLookup::Unknown(unknown) => Err(CredentialError::Unknown(unknown).into()),
        }
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
        self.nullifiers(notes).map(drop)
    }

    fn nullifiers(&self, notes: &[WalletUtxo]) -> Result<Vec<[u8; 32]>, DelegateSourceError> {
        notes
            .iter()
            .enumerate()
            .map(|(index, note)| self.nullifier_of(index, note))
            .collect()
    }

    fn nullifier_of(
        &self,
        index: usize,
        note: &WalletUtxo,
    ) -> Result<[u8; 32], DelegateSourceError> {
        // 1. Owner and key are opening fields the rebuilt hash commits, so a match binds the note.
        if !same_owner(&note.utxo.owner, &self.address.signing_pubkey)
            || note.nullifier_pubkey != self.address.nullifier_pubkey
        {
            return Err(DelegateSourceError::ForeignNote { index });
        }
        // 2. Rebuilt, not read, any carried hash yields its live nullifier under the shared zero key.
        let rebuilt = note.utxo.hash(
            &note.nullifier_pubkey,
            &note.data_hash.unwrap_or_default(),
            &note.ring_data_hash.unwrap_or_default(),
            note.tree_id,
        )?;
        let nullifier = self
            .nullifier_key
            .nullifier(&rebuilt, &note.utxo.blinding)?;
        // 3. Selection and the prover read the carried values, they must be the rebuilt ones.
        if rebuilt != note.utxo_hash || nullifier != note.nullifier {
            return Err(DelegateSourceError::UnboundOpening { index });
        }
        Ok(nullifier)
    }

    pub fn nullifier_key(&self) -> &NullifierKey {
        &self.nullifier_key
    }

    pub fn into_nullifier_key(self) -> NullifierKey {
        self.nullifier_key
    }
}

/// Filled only by [`Self::admit`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllowedNullifiers {
    sources: BTreeSet<[u8; SHIELDED_ADDRESS_LEN]>,
    nullifiers: BTreeSet<[u8; 32]>,
}

impl AllowedNullifiers {
    /// Admits nothing of `source` when one of its openings fails.
    pub fn admit(
        &mut self,
        source: &ResolvedSource,
        notes: &[WalletUtxo],
    ) -> Result<(), DelegateSourceError> {
        let nullifiers = source.nullifiers(notes)?;
        self.sources.insert(source.address.to_bytes());
        self.nullifiers.extend(nullifiers);
        Ok(())
    }

    pub fn check_sources<'s>(
        &self,
        requested: impl IntoIterator<Item = &'s ShieldedAddress>,
    ) -> Result<(), DelegateSourceError> {
        let requested: BTreeSet<_> = requested
            .into_iter()
            .map(ShieldedAddress::to_bytes)
            .collect();
        match requested == self.sources {
            true => Ok(()),
            false => Err(DelegateSourceError::SourcesMismatch),
        }
    }

    /// `inputs` in published order, only note positions answer to the set.
    pub fn check_inputs<'n>(
        &self,
        inputs: impl IntoIterator<Item = (InputClass, &'n [u8; 32])>,
    ) -> Result<(), DelegateSourceError> {
        let unrequested = inputs.into_iter().position(|(class, nullifier)| {
            class == InputClass::Note && !self.nullifiers.contains(nullifier)
        });
        match unrequested {
            Some(position) => Err(DelegateSourceError::UnrequestedInput { position }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "../tests/operations/delegate_source.rs"]
pub(crate) mod tests;
