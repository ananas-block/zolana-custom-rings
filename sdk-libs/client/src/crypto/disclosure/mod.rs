//! The auditor stream of a ring transfer, mirrored by Go `prover/circuits/audit`, and the pad a merge keeps.

use custom_ring_interface::{
    domain::AUDIT_STREAM_LABEL, AnonymousRecord, AuditEvidence, AuditKey, AuditStreamLayout,
    CustomRingError, ExitRecord, STREAM_FIRST_COUNTER,
};
use spr_hasher::{
    primitives::{is_canonical_bn254_scalar_be, pack_be, right_align},
    Hasher, Poseidon,
};
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use spr_transaction::field::{field_add, field_sub};
use zeroize::{Zeroize, Zeroizing};
use zolana_ring_keys::RingStream;

use crate::{
    encryption::{opening_ring_stream, sealing_ring_stream},
    AuditError,
};

mod historical;

pub use historical::{historical_evidence, HistoricalEvidence};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputRecord {
    /// Its delivered body opens the slot, no bytes leave the prover.
    Delivered,
    /// A hidden dummy is the zero record.
    Anonymous(AnonymousRecord),
    Exit(ExitRecord),
}

impl OutputRecord {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Delivered => Vec::new(),
            Self::Anonymous(record) => record.encode(),
            Self::Exit(record) => record.encode(),
        }
    }

    /// The layout picks the kind, the message parse already fixed the length.
    fn decode(
        plaintext: &[u8],
        layout: AuditStreamLayout,
        slot: usize,
    ) -> Result<Self, AuditError> {
        Ok(match (layout.is_exit(slot), layout.key) {
            (true, _) => {
                Self::Exit(ExitRecord::decode(plaintext, layout.key_escrow).map_err(layout_error)?)
            }
            (false, AuditKey::Anonymous(_)) => {
                Self::Anonymous(AnonymousRecord::decode(plaintext).map_err(layout_error)?)
            }
            (false, AuditKey::Confidential { .. }) => Self::Delivered,
        })
    }
}

fn layout_error(_: CustomRingError) -> AuditError {
    AuditError::DisclosureLayout
}

/// Everything one transfer seals to its auditor under one ephemeral key.
pub struct AuditStreamSeal<'a> {
    pub layout: AuditStreamLayout,
    pub tx_viewing_key: &'a ViewingKey,
    pub evidence: AuditEvidence,
    /// One per slot.
    pub records: Vec<OutputRecord>,
}

pub struct SealedAuditStream {
    pub eph_u: [u8; 32],
    pub envelope: Vec<u8>,
    /// One per slot, empty on a delivered slot.
    pub records: Vec<Vec<u8>>,
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
}

impl AuditStreamSeal<'_> {
    /// A fresh ephemeral key per call, a reused one repeats the stream under another plaintext.
    pub fn seal(self, auditor_pk: &X25519Pubkey) -> Result<SealedAuditStream, AuditError> {
        self.seal_with(X25519Keypair::new(), auditor_pk)
    }

    /// Pins a vector, every build seals through [`Self::seal`].
    #[doc(hidden)]
    pub fn seal_with(
        self,
        ephemeral: X25519Keypair,
        auditor_pk: &X25519Pubkey,
    ) -> Result<SealedAuditStream, AuditError> {
        let Self {
            layout,
            tx_viewing_key,
            evidence,
            records,
        } = self;
        if records.len() != layout.outputs {
            return Err(AuditError::DisclosureLayout);
        }
        let stream = sealing_ring_stream(&ephemeral, auditor_pk, AUDIT_STREAM_LABEL)?;
        let mut plaintext = custom_ring_interface::AuditEnvelope {
            tx_viewing_secret: *tx_viewing_key.secret_bytes(),
            evidence,
        };
        let mut envelope = plaintext.encode();
        plaintext.tx_viewing_secret.zeroize();
        if envelope.len() != layout.envelope().len {
            envelope.zeroize();
            return Err(AuditError::DisclosureLayout);
        }
        stream.apply_at(STREAM_FIRST_COUNTER, &mut envelope);
        let records = records
            .iter()
            .enumerate()
            .map(|(slot, record)| {
                let mut ciphertext = record.encode();
                let region = layout.record(slot);
                if ciphertext.len() != region.len {
                    return Err(AuditError::DisclosureLayout);
                }
                stream.apply_at(region.start_counter, &mut ciphertext);
                Ok(ciphertext)
            })
            .collect::<Result<_, AuditError>>()?;
        Ok(SealedAuditStream {
            eph_u: ephemeral.pubkey().u(),
            envelope,
            records,
            ephemeral_sk: ephemeral.secret_bytes(),
        })
    }
}

/// The published envelope, its plaintext reads the rest of the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEnvelope<'a> {
    pub eph_u: [u8; 32],
    pub ciphertext: &'a [u8],
}

pub struct OpenedAudit {
    pub tx_viewing_key: ViewingKey,
    pub evidence: AuditEvidence,
    layout: AuditStreamLayout,
    stream: RingStream,
}

impl AuditEnvelope<'_> {
    /// The circuit seals the clamped encoding, an unclamped alias of the same key is refused.
    pub fn open(
        &self,
        auditor: &X25519Keypair,
        layout: AuditStreamLayout,
    ) -> Result<OpenedAudit, AuditError> {
        let stream = opening_ring_stream(
            auditor,
            &X25519Pubkey::from_u(self.eph_u)?,
            AUDIT_STREAM_LABEL,
        )?;
        let mut plaintext = Zeroizing::new(self.ciphertext.to_vec());
        stream.apply_at(STREAM_FIRST_COUNTER, &mut plaintext);
        let mut envelope = custom_ring_interface::AuditEnvelope::decode(&plaintext, layout)
            .map_err(|_| AuditError::DisclosureField)?;
        let tx_viewing_key = ViewingKey::from_canonical_bytes(&envelope.tx_viewing_secret)
            .map_err(|_| AuditError::NonCanonicalViewingKey);
        envelope.tx_viewing_secret.zeroize();
        check_evidence(&envelope.evidence)?;
        Ok(OpenedAudit {
            tx_viewing_key: tx_viewing_key?,
            evidence: envelope.evidence,
            layout,
            stream,
        })
    }
}

impl OpenedAudit {
    /// `ciphertext` is the slot's bytes in the auditor message.
    pub fn record(&self, slot: usize, ciphertext: &[u8]) -> Result<OutputRecord, AuditError> {
        let region = self.layout.record(slot);
        if ciphertext.len() != region.len {
            return Err(AuditError::DisclosureLayout);
        }
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        self.stream.apply_at(region.start_counter, &mut plaintext);
        OutputRecord::decode(&plaintext, self.layout, slot)
    }
}

/// Refuses evidence the proof cannot have bound, a hash outside the field names no input.
fn check_evidence(evidence: &AuditEvidence) -> Result<(), AuditError> {
    match evidence {
        AuditEvidence::InputHashes(hashes) => hashes
            .iter()
            .try_for_each(|hash| canonical(*hash).map(drop)),
        AuditEvidence::Entry {
            sender_nullifier_pk,
            inputs,
            ..
        } => {
            canonical(*sender_nullifier_pk)?;
            inputs.iter().try_for_each(|input| {
                canonical(input.hash)?;
                canonical(input.asset)?;
                canonical(input.blinding).map(drop)
            })
        }
    }
}

/// `be32(hash_i)` on every non-entry rail, a `None` input is a published dummy and reads zero.
pub fn input_hash_evidence(hashes: &[Option<[u8; 32]>]) -> Result<AuditEvidence, AuditError> {
    Ok(AuditEvidence::InputHashes(
        hashes
            .iter()
            .map(|hash| canonical(hash.unwrap_or_default()))
            .collect::<Result<_, _>>()?,
    ))
}

/// `pad_j = Poseidon(seed, j)`, a known pad reveals no other.
pub struct DisclosurePad {
    seed: Zeroizing<[u8; 32]>,
}

impl DisclosurePad {
    /// `seed = Poseidon(domain, pack_be(key), salt)`, the domain keeps a merge pad apart.
    pub(crate) fn keyed(
        domain: &[u8; 32],
        key: &[u8; 32],
        salt: &[u8; 16],
    ) -> Result<Self, AuditError> {
        let [key0, key1] = pack_be(key);
        Ok(Self {
            seed: Zeroizing::new(Poseidon::hashv(&[
                domain,
                &key0,
                &key1,
                &right_align(salt),
            ])?),
        })
    }

    /// `C_j = P_j + pad_j mod q`.
    pub fn encrypt(&self, plaintext: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, AuditError> {
        self.apply(plaintext, field_add)
    }

    pub fn decrypt(&self, published: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, AuditError> {
        self.apply(published, field_sub)
    }

    fn apply(
        &self,
        fields: &[[u8; 32]],
        combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    ) -> Result<Vec<[u8; 32]>, AuditError> {
        (0u64..)
            .zip(fields)
            .map(|(index, field)| {
                let pad = Poseidon::hashv(&[&*self.seed, &right_align(&index.to_be_bytes())])?;
                Ok(combine(&canonical(*field)?, &pad))
            })
            .collect()
    }
}

pub(crate) fn canonical(field: [u8; 32]) -> Result<[u8; 32], AuditError> {
    match is_canonical_bn254_scalar_be(&field) {
        true => Ok(field),
        false => Err(AuditError::DisclosureField),
    }
}

#[cfg(test)]
mod tests;
