//! The evidence head of a statement version 2 envelope.

use custom_ring_interface::{
    domain::AUDIT_STREAM_LABEL, input_flag, tag, transact_flag, InstructionTag, RingMode, RingRail,
    STREAM_FIRST_COUNTER,
};
use spr_keypair::{X25519Keypair, X25519Pubkey};
use spr_transaction::ShieldedTransaction;
use zeroize::Zeroizing;
use zolana_ring_transaction::historical::{InputPrefix, INPUT_PREFIX_BYTES};

use crate::{encryption::opening_ring_stream, AuditError};

const FIELD_LEN: usize = 32;
const ENVELOPE_KEY_LEN: usize = 32;
const TAGGED_KEY_LEN: usize = 33;

/// What a version 2 envelope names of its spent notes, `None` entries are dummies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoricalEvidence {
    /// The signer rail discloses no input, an entry opening names no hash.
    Unnamed,
    Prefixes(Vec<Option<InputPrefix>>),
    /// Spent UTXO 0 by its hash, every later one by its prefix.
    Commitments {
        first: [u8; 32],
        prefixes: Vec<Option<InputPrefix>>,
    },
}

#[derive(Clone, Copy)]
enum EvidenceShape {
    Unnamed,
    Prefixes,
    Commitments,
}

/// `transact` is `tag || data` of the forwarding frame.
pub fn historical_evidence(
    transaction: &ShieldedTransaction,
    transact: &[u8],
    mode: RingMode,
    auditor: &X25519Keypair,
) -> Result<HistoricalEvidence, AuditError> {
    let inputs = transaction.nullifiers.len();
    let shape = evidence_shape(transact, mode).ok_or(AuditError::HistoricalFrame)?;
    let evidence_len = match shape {
        EvidenceShape::Unnamed => return Ok(HistoricalEvidence::Unnamed),
        EvidenceShape::Prefixes => inputs.checked_mul(INPUT_PREFIX_BYTES),
        EvidenceShape::Commitments => inputs
            .checked_sub(1)
            .and_then(|later| later.checked_mul(INPUT_PREFIX_BYTES))
            .and_then(|later| later.checked_add(FIELD_LEN)),
    }
    .ok_or(AuditError::DisclosureField)?;
    let message = transaction
        .messages
        .last()
        .ok_or(AuditError::MissingAuditorMessage)?;
    let (eph_pk, rest) = message
        .data
        .split_first_chunk::<TAGGED_KEY_LEN>()
        .ok_or(AuditError::AuditorMessageLength(message.data.len()))?;
    let envelope = rest
        .get(..ENVELOPE_KEY_LEN + evidence_len)
        .ok_or(AuditError::AuditorMessageLength(message.data.len()))?;
    let stream = opening_ring_stream(
        auditor,
        &X25519Pubkey::from_bytes(*eph_pk)?,
        AUDIT_STREAM_LABEL,
    )?;
    let mut plaintext = Zeroizing::new(envelope.to_vec());
    stream.apply_at(STREAM_FIRST_COUNTER, &mut plaintext);
    let evidence = plaintext
        .get(ENVELOPE_KEY_LEN..)
        .ok_or(AuditError::DisclosureField)?;
    decode_evidence(shape, evidence)
}

/// `tag || flags || shape || inputs`, the catalog frozen at statement version 2.
fn evidence_shape(transact: &[u8], mode: RingMode) -> Option<EvidenceShape> {
    let tag_byte = *transact.first()?;
    let flags = *transact.get(1 + transact_flag::BYTE)?;
    let input_flags = *transact.get(1 + input_flag::BYTE)?;
    if !matches!(
        tag_byte,
        tag::HISTORICAL_TRANSFER | tag::HISTORICAL_AUTHORITY_TRANSFER
    ) {
        return None;
    }
    let rail = RingRail::of(InstructionTag::try_from(tag_byte).ok()?, mode).ok()?;
    let in_proof = flags & transact_flag::OWNER_IN_PROOF != 0;
    Some(match rail {
        RingRail::Anonymous if input_flags & input_flag::FULL_OPENINGS != 0 => {
            EvidenceShape::Unnamed
        }
        RingRail::Anonymous if in_proof => EvidenceShape::Prefixes,
        RingRail::Anonymous => EvidenceShape::Commitments,
        RingRail::Delegate => EvidenceShape::Prefixes,
        RingRail::Confidential if in_proof => EvidenceShape::Prefixes,
        RingRail::Confidential => EvidenceShape::Unnamed,
    })
}

fn decode_evidence(
    shape: EvidenceShape,
    evidence: &[u8],
) -> Result<HistoricalEvidence, AuditError> {
    match shape {
        EvidenceShape::Unnamed => Ok(HistoricalEvidence::Unnamed),
        EvidenceShape::Prefixes => Ok(HistoricalEvidence::Prefixes(prefixes(evidence)?)),
        EvidenceShape::Commitments => {
            let (first, later) = evidence
                .split_first_chunk::<FIELD_LEN>()
                .ok_or(AuditError::DisclosureField)?;
            Ok(HistoricalEvidence::Commitments {
                first: *first,
                prefixes: prefixes(later)?,
            })
        }
    }
}

/// A zero chunk is a dummy, any other chunk off the field refuses.
fn prefixes(evidence: &[u8]) -> Result<Vec<Option<InputPrefix>>, AuditError> {
    let (chunks, _) = evidence.as_chunks::<INPUT_PREFIX_BYTES>();
    chunks
        .iter()
        .map(|chunk| InputPrefix::from_bytes(chunk).map_err(|_| AuditError::DisclosureField))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tag_byte: u8, flags: u8, input_flags: u8) -> [u8; 4] {
        [tag_byte, flags, 0, input_flags]
    }

    #[test]
    fn the_frame_flags_fix_what_a_version_2_envelope_names() {
        let shape = |tag_byte, flags, input_flags, mode| {
            evidence_shape(&frame(tag_byte, flags, input_flags), mode)
        };
        let transfer = tag::HISTORICAL_TRANSFER;
        assert!(matches!(
            shape(transfer, 0, 0, RingMode::Confidential),
            Some(EvidenceShape::Unnamed)
        ));
        assert!(matches!(
            shape(
                transfer,
                transact_flag::OWNER_IN_PROOF,
                0,
                RingMode::Confidential
            ),
            Some(EvidenceShape::Prefixes)
        ));
        assert!(matches!(
            shape(transfer, 0, 0, RingMode::Anonymous),
            Some(EvidenceShape::Commitments)
        ));
        assert!(matches!(
            shape(transfer, 0, input_flag::FULL_OPENINGS, RingMode::Anonymous),
            Some(EvidenceShape::Unnamed)
        ));
        assert!(matches!(
            shape(
                tag::HISTORICAL_AUTHORITY_TRANSFER,
                0,
                0,
                RingMode::Confidential
            ),
            Some(EvidenceShape::Prefixes)
        ));
        assert!(shape(tag::TRANSFER, 0, 0, RingMode::Confidential).is_none());
    }

    #[test]
    fn a_zero_chunk_is_a_dummy_and_a_chunk_off_the_field_refuses() {
        let mut named = [0u8; 16];
        named[15] = 1;
        let evidence = [&[0u8; 16][..], &named].concat();
        let read = prefixes(&evidence).unwrap();
        assert_eq!(read[0], None);
        assert!(read[1].is_some());
        assert!(prefixes(&[0xff; 16]).is_err());
    }
}
