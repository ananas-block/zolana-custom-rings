//! Ring output bodies in SPP's encrypted output framing, schemes SPP stores without parsing.
//!
//! Read after `program-libs/interface/src/proof/disclosure.rs`. Read before `program-libs/interface/src/codec/stream.rs`.

use spr_event::{OutputDataEncoding, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG};

use crate::{audit_stream::RECIPIENT_BODY_LEN, CustomRingError};

pub const RING_SENDER_BUNDLE_SCHEME_TAG: u8 = 9;
/// `u16le(body_len) || body || reply`, one form on every rail, the reply absent without reply metadata.
pub const RING_BODY_SCHEME_TAG: u8 = 10;

/// `0x04 || u`, the recipient key a scheme 3 body leads with.
pub const RECIPIENT_KEY_LEN: usize = 33;

/// Asset id, amount and blinding open every confidential plaintext.
const CONFIDENTIAL_PLAINTEXT_HEAD_LEN: usize = 8 + 8 + 32;

/// Scheme 3 body of an output with no data and no ring id, each one zero byte.
pub const CONFIDENTIAL_DATA_FREE_BODY_LEN: usize =
    RECIPIENT_KEY_LEN + CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 2;

/// The encoding tag and the u32 body length before the scheme byte.
const BODY_OFFSET: usize = 1 + 4;

pub fn encode_confidential_output(body: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    encode_encrypted_output(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, body)
}

pub fn encode_ring_body_output(body: &[u8], reply: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    let body_len = u16::try_from(body.len()).map_err(|_| CustomRingError::OutputBodyLength)?;
    encode_encrypted_output_parts(
        RING_BODY_SCHEME_TAG,
        &[&body_len.to_le_bytes(), body, reply],
    )
}

pub fn encode_ring_sender_bundle_output(body: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    encode_encrypted_output(RING_SENDER_BUNDLE_SCHEME_TAG, body)
}

/// `body || reply` of a well-formed ring body output, `None` otherwise.
pub fn ring_body_output(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (body_len, rest) =
        encrypted_output_body(data, RING_BODY_SCHEME_TAG)?.split_first_chunk()?;
    rest.split_at_checked(usize::from(u16::from_le_bytes(*body_len)))
        .filter(|(body, _)| body.len() >= RECIPIENT_BODY_LEN)
}

pub fn ring_sender_bundle_output_body(data: &[u8]) -> Option<&[u8]> {
    encrypted_output_body(data, RING_SENDER_BUNDLE_SCHEME_TAG)
}

/// `Encrypted(len || scheme || payload)`, the length counting the scheme byte.
fn encode_encrypted_output(scheme: u8, payload: &[u8]) -> Result<Vec<u8>, CustomRingError> {
    encode_encrypted_output_parts(scheme, &[payload])
}

fn encode_encrypted_output_parts(scheme: u8, parts: &[&[u8]]) -> Result<Vec<u8>, CustomRingError> {
    let body_len = parts.iter().map(|part| part.len()).sum::<usize>() + 1;
    let prefix = u32::try_from(body_len).map_err(|_| CustomRingError::OutputBodyLength)?;
    let mut out = Vec::with_capacity(BODY_OFFSET + body_len);
    out.push(OutputDataEncoding::ENCRYPTED_TAG);
    out.extend_from_slice(&prefix.to_le_bytes());
    out.push(scheme);
    parts.iter().for_each(|part| out.extend_from_slice(part));
    Ok(out)
}

fn encrypted_output_body(data: &[u8], scheme: u8) -> Option<&[u8]> {
    encrypted_output(data)
        .filter(|(scheme_byte, _)| *scheme_byte == scheme)
        .map(|(_, payload)| payload)
}

/// The scheme byte and payload of `Encrypted(len || scheme || payload)`.
pub fn encrypted_output(data: &[u8]) -> Option<(u8, &[u8])> {
    let (&encoding_tag, rest) = data.split_first()?;
    if encoding_tag != OutputDataEncoding::ENCRYPTED_TAG {
        return None;
    }
    let (len_bytes, body) = rest.split_first_chunk::<4>()?;
    let body_len = usize::try_from(u32::from_le_bytes(*len_bytes)).ok()?;
    let (&scheme_byte, payload) = body.split_first()?;
    (body_len == body.len()).then_some((scheme_byte, payload))
}
