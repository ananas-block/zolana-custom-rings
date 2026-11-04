//! The auditor stream of a ring transfer, mirrored by Go `prover/circuits/audit`, and the pad a merge keeps.

use custom_ring_interface::{
    domain::AUDIT_STREAM_LABEL, AuditEvidence, AuditRecord, AuditStreamLayout, DataTail,
    StreamRegion, AUDIT_RECORD_LEN, DATA_TAIL_LEN, STREAM_FIRST_COUNTER,
};
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use zeroize::{Zeroize, Zeroizing};
use zolana_ring_keys::RingStream;

use crate::{
    encryption::{opening_salted_stream, sealing_salted_stream},
    AuditError,
};

/// Everything one transfer seals to its auditor under its own viewing key.
pub struct AuditStreamSeal<'a> {
    pub layout: AuditStreamLayout,
    pub tx_viewing_key: &'a ViewingKey,
    pub salt: &'a [u8; 16],
    /// `R`, nullifiers at or past it are padding.
    pub real_inputs: u8,
    pub evidence: AuditEvidence,
    /// One per slot.
    pub records: Vec<AuditRecord>,
    /// One per slot under `has_data`, else none.
    pub tails: Vec<DataTail>,
}

pub struct SealedAuditStream {
    /// The transfer's own viewing key.
    pub eph_u: [u8; 32],
    pub envelope: Vec<u8>,
    /// One per slot.
    pub records: Vec<[u8; AUDIT_RECORD_LEN]>,
    /// One per slot under `has_data`, else none.
    pub tails: Vec<[u8; DATA_TAIL_LEN]>,
}

impl AuditStreamSeal<'_> {
    /// The salt separates a resend, the viewing key repeats under one first nullifier.
    pub fn seal(self, auditor_pk: &X25519Pubkey) -> Result<SealedAuditStream, AuditError> {
        let Self {
            layout,
            tx_viewing_key,
            salt,
            real_inputs,
            evidence,
            records,
            tails,
        } = self;
        let tails_expected = if layout.has_data { layout.outputs } else { 0 };
        if records.len() != layout.outputs || tails.len() != tails_expected {
            return Err(AuditError::DisclosureLayout);
        }
        let key = X25519Keypair::from_bytes(&tx_viewing_key.secret_bytes());
        let stream = sealing_salted_stream(&key, auditor_pk, salt, AUDIT_STREAM_LABEL)?;
        let mut plaintext = custom_ring_interface::AuditEnvelope {
            tx_viewing_secret: *tx_viewing_key.secret_bytes(),
            real_inputs,
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
                stream.apply_at(layout.record(slot).start_counter, &mut ciphertext);
                ciphertext
            })
            .collect();
        let tails = tails
            .iter()
            .enumerate()
            .map(|(slot, tail)| {
                let mut ciphertext = tail.encode();
                stream.apply_at(layout.tail(slot).start_counter, &mut ciphertext);
                ciphertext
            })
            .collect();
        Ok(SealedAuditStream {
            eph_u: tx_viewing_key.pubkey().u(),
            envelope,
            records,
            tails,
        })
    }
}

/// The published envelope, its plaintext reads the rest of the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEnvelope<'a> {
    pub eph_u: [u8; 32],
    pub salt: &'a [u8; 16],
    pub ciphertext: &'a [u8],
}

pub struct OpenedAudit {
    pub tx_viewing_key: ViewingKey,
    pub real_inputs: u8,
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
        let stream = opening_salted_stream(
            auditor,
            &X25519Pubkey::from_u(self.eph_u)?,
            self.salt,
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
            real_inputs: envelope.real_inputs,
            evidence: envelope.evidence,
            layout,
            stream,
        })
    }
}

impl OpenedAudit {
    /// `ciphertext` is the slot's bytes in the auditor message.
    pub fn record(&self, slot: usize, ciphertext: &[u8]) -> Result<AuditRecord, AuditError> {
        let plaintext = self.open_region(self.layout.record(slot), ciphertext)?;
        AuditRecord::decode(&plaintext).map_err(|_| AuditError::DisclosureField)
    }

    pub fn tail(&self, slot: usize, ciphertext: &[u8]) -> Result<DataTail, AuditError> {
        let plaintext = self.open_region(self.layout.tail(slot), ciphertext)?;
        DataTail::decode(&plaintext).map_err(|_| AuditError::DisclosureField)
    }

    fn open_region(
        &self,
        region: StreamRegion,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AuditError> {
        if ciphertext.len() != region.len {
            return Err(AuditError::DisclosureLayout);
        }
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        self.stream.apply_at(region.start_counter, &mut plaintext);
        Ok(plaintext)
    }
}

/// Refuses an opening the proof cannot have bound.
fn check_evidence(evidence: &AuditEvidence) -> Result<(), AuditError> {
    match evidence {
        AuditEvidence::None => Ok(()),
        AuditEvidence::Entry { inputs, .. } => inputs.iter().try_for_each(|input| {
            canonical(input.nullifier_pk)?;
            canonical(input.blinding)?;
            canonical(input.data_hash)?;
            canonical(input.ring_data_hash).map(drop)
        }),
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
