//! Ring output bodies in SPP's encrypted output framing, schemes SPP stores without parsing.

use zolana_event::{
    OutputDataEncoding, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG,
};

pub const RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG: u8 = 10;
pub const RING_CONFIDENTIAL_PACKED_SCHEME_TAG: u8 = 11;

/// AES-CTR of the 32-byte blinding then the big-endian u64 amount.
pub const RING_DELIVERED_BODY_LEN: usize = 40;

/// `0x04 || u`, the recipient key a scheme 3 or scheme 11 body leads with.
pub const RECIPIENT_KEY_LEN: usize = 33;

/// Asset id, amount and blinding open every confidential plaintext.
const CONFIDENTIAL_PLAINTEXT_HEAD_LEN: usize = 8 + 8 + 32;

/// Scheme 3 body of an output with no data and no ring id, each one zero byte.
pub const CONFIDENTIAL_DATA_FREE_BODY_LEN: usize =
    RECIPIENT_KEY_LEN + CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 2;

/// Scheme 11 body of an output with no data.
pub const RING_PACKED_DATA_FREE_BODY_LEN: usize =
    RECIPIENT_KEY_LEN + CONFIDENTIAL_PLAINTEXT_HEAD_LEN + 1;

/// The encoding tag and the u32 body length before the scheme byte.
const BODY_OFFSET: usize = 1 + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingPackedBody<'a> {
    pub key: &'a [u8; RECIPIENT_KEY_LEN],
    pub ciphertext: &'a [u8],
}

pub fn ring_confidential_delivered_output_body(
    data: &[u8],
) -> Option<&[u8; RING_DELIVERED_BODY_LEN]> {
    encrypted_output_body(data, RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG)?
        .try_into()
        .ok()
}

pub fn ring_anonymous_output_body(data: &[u8]) -> Option<&[u8; RING_DELIVERED_BODY_LEN]> {
    encrypted_output_body(data, RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG)?
        .try_into()
        .ok()
}

/// `None` for a body shorter than [`RING_PACKED_DATA_FREE_BODY_LEN`].
pub fn ring_confidential_packed_output_body(data: &[u8]) -> Option<RingPackedBody<'_>> {
    let (key, ciphertext) = encrypted_output_body(data, RING_CONFIDENTIAL_PACKED_SCHEME_TAG)
        .filter(|body| body.len() >= RING_PACKED_DATA_FREE_BODY_LEN)?
        .split_first_chunk()?;
    Some(RingPackedBody { key, ciphertext })
}

pub fn encode_confidential_output(body: &[u8]) -> Vec<u8> {
    encode_encrypted_output(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, &[body])
}

pub fn encode_ring_anonymous_output(body: &[u8; RING_DELIVERED_BODY_LEN]) -> Vec<u8> {
    encode_encrypted_output(RING_ANONYMOUS_ENCRYPTED_SCHEME_TAG, &[body])
}

pub fn encode_ring_confidential_delivered_output(body: &[u8; RING_DELIVERED_BODY_LEN]) -> Vec<u8> {
    encode_encrypted_output(RING_CONFIDENTIAL_DELIVERED_SCHEME_TAG, &[body])
}

pub fn encode_ring_confidential_packed_output(
    key: &[u8; RECIPIENT_KEY_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    encode_encrypted_output(RING_CONFIDENTIAL_PACKED_SCHEME_TAG, &[key, ciphertext])
}

/// `Encrypted(len || scheme || payload)`, the length counting the scheme byte.
fn encode_encrypted_output(scheme: u8, payload: &[&[u8]]) -> Vec<u8> {
    let body_len: usize = 1 + payload.iter().map(|part| part.len()).sum::<usize>();
    let mut out = Vec::with_capacity(BODY_OFFSET + body_len);
    out.push(OutputDataEncoding::ENCRYPTED_TAG);
    out.extend_from_slice(
        &u32::try_from(body_len)
            .expect("ring output body length fits in u32")
            .to_le_bytes(),
    );
    out.push(scheme);
    payload.iter().for_each(|part| out.extend_from_slice(part));
    out
}

fn encrypted_output_body(data: &[u8], scheme: u8) -> Option<&[u8]> {
    let (&encoding_tag, rest) = data.split_first()?;
    if encoding_tag != OutputDataEncoding::ENCRYPTED_TAG {
        return None;
    }
    let (len_bytes, body) = rest.split_first_chunk::<4>()?;
    let body_len = usize::try_from(u32::from_le_bytes(*len_bytes)).ok()?;
    let (&scheme_byte, payload) = body.split_first()?;
    (body_len == body.len() && scheme_byte == scheme).then_some(payload)
}
