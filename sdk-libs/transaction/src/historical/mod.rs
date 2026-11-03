//! Schemes 1 and 2 and the prefix evidence of statement version 2.

mod plaintext;
mod prefix;

use custom_ring_interface::encrypted_output;
use solana_address::Address;
use spr_event::{ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG, ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG};
use spr_keypair::{x25519::X25519_PUBKEY_LEN, ShieldedAddress, X25519Pubkey};
use spr_transaction::{Mint, ShieldedTransaction, Utxo};

pub use plaintext::{
    AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext,
    CommittedRecipientPlaintext, CommittedSenderPlaintext, UncommittedRecipientPlaintext,
    UncommittedSenderPlaintext,
};
pub use prefix::{
    assign_prefixed_inputs, InputPrefix, InvalidInputPrefix, PrefixAssignment, PrefixIndex,
    PrefixNotes, INPUT_PREFIX_BYTES,
};

use crate::{RingAssets, RingRailError};

/// The sender bundle's entry for an output no anonymous recipient reads.
pub const DUMMY_RECIPIENT_VIEWING_PK: [u8; X25519_PUBKEY_LEN] = {
    let mut key = [0u8; X25519_PUBKEY_LEN];
    key[0] = 0x04;
    key
};

/// The payload of a scheme 1 output.
pub fn recipient_output_body(data: &[u8]) -> Option<&[u8]> {
    encrypted_output(data)
        .filter(|(scheme, _)| *scheme == ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG)
        .map(|(_, payload)| payload)
}

/// The payload of a scheme 2 message.
pub fn sender_output_body(data: &[u8]) -> Option<&[u8]> {
    encrypted_output(data)
        .filter(|(scheme, _)| *scheme == ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG)
        .map(|(_, payload)| payload)
}

/// A scheme 1 or 2 site of a row, messages read past the outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalSite {
    Output(usize),
    Message(usize),
}

/// One site's ciphertext and the slot its stream reads, `None` on another scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoricalBody<'t> {
    pub site: HistoricalSite,
    pub ciphertext: &'t [u8],
    pub slot_index: u32,
}

/// Who reads a row's historical bodies, nothing here touches history, tags or sent payments.
#[derive(Clone, Copy, Debug)]
pub struct HistoricalReader<'a> {
    pub owner: &'a ShieldedAddress,
    pub assets: &'a RingAssets,
    pub ring: Address,
    pub first_nullifier: &'a [u8; 32],
}

/// A note whose rebuilt commitment names the reader, at its output position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalNote {
    pub position: usize,
    pub utxo: Utxo,
    pub nullifier_pk: [u8; 32],
    /// `false` under a mint the registry does not name, `utxo` then holds its asset id at zero.
    pub registered: bool,
}

impl<'t> HistoricalBody<'t> {
    pub fn of(tx: &'t ShieldedTransaction, site: HistoricalSite) -> Option<Self> {
        let (ciphertext, slot) = match site {
            HistoricalSite::Output(position) => (
                recipient_output_body(&tx.output_slots.get(position)?.payload)?,
                position,
            ),
            HistoricalSite::Message(message) => (
                sender_output_body(&tx.messages.get(message)?.data)?,
                tx.output_slots.len().checked_add(message)?,
            ),
        };
        Some(Self {
            site,
            ciphertext,
            slot_index: u32::try_from(slot).ok()?,
        })
    }
}

impl HistoricalReader<'_> {
    /// Only a rebuilt commitment proves a note the reader's, every other plaintext stays silent.
    pub fn notes(
        &self,
        tx: &ShieldedTransaction,
        site: HistoricalSite,
        plaintext: &[u8],
    ) -> Vec<HistoricalNote> {
        let note = |position: usize, utxo: Utxo| HistoricalNote {
            position,
            registered: self.assets.by_mint(&utxo.asset.asset).is_some(),
            utxo,
            nullifier_pk: self.owner.nullifier_pubkey,
        };
        match site {
            HistoricalSite::Output(position) => {
                let opened = AnonymousTransferRecipientPlaintext::deserialize(plaintext)
                    .ok()
                    .and_then(|plaintext| {
                        self.output(tx, position)?.open_recipient(plaintext).ok()?
                    });
                opened
                    .map(|utxo| note(position, utxo))
                    .into_iter()
                    .collect()
            }
            HistoricalSite::Message(_) => {
                let Ok(bundle) = AnonymousTransferSenderPlaintext::deserialize(plaintext) else {
                    return Vec::new();
                };
                if bundle.committed.owner_pubkey != self.owner.signing_pubkey {
                    return Vec::new();
                }
                let Some(output) = self.output(tx, 0) else {
                    return Vec::new();
                };
                let Ok(change) = output.sender_change(bundle, self.first_nullifier) else {
                    return Vec::new();
                };
                change
                    .into_iter()
                    .enumerate()
                    .filter(|(position, utxo)| {
                        self.output(tx, *position)
                            .is_some_and(|output| output.rebuilds(utxo))
                    })
                    .map(|(position, utxo)| note(position, utxo))
                    .collect()
            }
        }
    }

    fn output<'o>(
        &'o self,
        tx: &'o ShieldedTransaction,
        position: usize,
    ) -> Option<HistoricalOutput<'o>> {
        let context = &tx.output_slots.get(position)?.output_context;
        Some(HistoricalOutput {
            owner: self.owner,
            assets: self.assets,
            ring: self.ring,
            tree_id: context.tree_id,
            utxo_hash: &context.hash,
        })
    }
}

/// One published historical output, rebuilt from a plaintext and the reader's keys.
#[derive(Clone, Copy, Debug)]
pub struct HistoricalOutput<'a> {
    pub owner: &'a ShieldedAddress,
    pub assets: &'a RingAssets,
    pub ring: Address,
    pub tree_id: u16,
    pub utxo_hash: &'a [u8; 32],
}

impl HistoricalOutput<'_> {
    /// `None` unless the plaintext names the reader as owner and rebuilds the hash.
    pub fn open_recipient(
        &self,
        plaintext: AnonymousTransferRecipientPlaintext,
    ) -> Result<Option<Utxo>, RingRailError> {
        if plaintext.committed.owner_pubkey != self.owner.signing_pubkey {
            return Ok(None);
        }
        let asset = self.asset(&plaintext.committed.mint);
        let utxo = self.in_ring(plaintext.into_utxo(asset)?);
        Ok(self.rebuilds(&utxo).then_some(utxo))
    }

    /// The bundle's change in output order, the change leading at output 0.
    pub fn sender_change(
        &self,
        plaintext: AnonymousTransferSenderPlaintext,
        first_nullifier: &[u8; 32],
    ) -> Result<Vec<Utxo>, RingRailError> {
        let asset = self.asset(&plaintext.committed.spl_mint);
        let change = plaintext.into_utxos(first_nullifier, asset)?;
        Ok(change.into_iter().map(|utxo| self.in_ring(utxo)).collect())
    }

    /// Ring outputs commit to no data, a hashed record rebuilds nothing.
    pub fn rebuilds(&self, utxo: &Utxo) -> bool {
        utxo.data.ring_data().is_none()
            && utxo.data.utxo_data().is_none()
            && utxo
                .hash(
                    &self.owner.nullifier_pubkey,
                    &[0; 32],
                    &[0; 32],
                    self.tree_id,
                )
                .is_ok_and(|hash| hash == *self.utxo_hash)
    }

    /// The commitment reads the mint alone, the id only names a registered one.
    fn asset(&self, mint: &Address) -> Mint {
        self.assets.by_mint(mint).unwrap_or(Mint {
            asset: *mint,
            asset_id: 0,
        })
    }

    /// Every anonymous output is the ring's, its plaintext names no ring.
    fn in_ring(&self, utxo: Utxo) -> Utxo {
        Utxo {
            ring_program_id: Some(self.ring),
            ..utxo
        }
    }
}

/// Dummy entries left out.
pub fn listed_recipients(
    plaintext: &AnonymousTransferSenderPlaintext,
) -> impl Iterator<Item = &X25519Pubkey> {
    plaintext
        .uncommitted
        .recipient_viewing_pks
        .iter()
        .filter(|key| !is_dummy_recipient(key))
}

pub fn is_dummy_recipient(key: &X25519Pubkey) -> bool {
    *key.as_bytes() == DUMMY_RECIPIENT_VIEWING_PK
}

#[cfg(test)]
mod vector_tests;
