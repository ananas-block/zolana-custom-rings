//! An anonymous ring member's address and its `zolana:` payment request form.

use std::{fmt, str::FromStr};

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use solana_address::Address;
use custom_ring_interface::domain;
use spr_hasher::{
    primitives::{is_canonical_bn254_scalar_be, right_align},
    Hasher, Poseidon,
};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{
    shielded::{ShieldedAddress, SHIELDED_ADDRESS_LEN},
    viewing_key::ViewTag,
    NullifierKey,
};
use zeroize::Zeroizing;

use crate::RingKeyError;

pub const RING_ADDRESS_VERSION: u8 = 4;

pub const RING_ADDRESS_CHECKSUM_DOMAIN: &[u8] = b"zolana/ring-addr/v4";

pub const RING_PAYMENT_SCHEME: &str = "zolana:";

const CHECKSUM_LEN: usize = 4;

/// `"CRPS"`
const LIST_SALT_DOMAIN: u32 = 0x4352_5053;
/// `"CRPT"`
const LIST_TAG_DOMAIN: u32 = 0x4352_5054;

const LIST_SALT_LEN: usize = 32;

/// `version ‖ recipient ‖ ring_program_id ‖ list_salt`.
const BODY_LEN: usize = 1 + SHIELDED_ADDRESS_LEN + 32 + LIST_SALT_LEN;

pub const RING_ADDRESS_PAYLOAD_LEN: usize = BODY_LEN + CHECKSUM_LEN;

/// RFC 3986 unreserved characters stay literal, everything else is percent-encoded.
const LABEL_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Clone, PartialEq, Eq)]
pub struct RingAddress {
    pub recipient: ShieldedAddress,
    pub ring_program_id: Address,
    /// Read on a private list row, a resolver checks it against the tracking leaf's `list_tag`.
    pub list_salt: [u8; 32],
}

impl fmt::Debug for RingAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingAddress")
            .field("ring_program_id", &self.ring_program_id)
            .finish_non_exhaustive()
    }
}

impl RingAddress {
    /// An enrolled wallet's address, its salt derives from the nullifier key it enrolled.
    pub fn enrolled(
        recipient: ShieldedAddress,
        ring_program_id: Address,
        nullifier_key: &NullifierKey,
    ) -> Result<Self, RingKeyError> {
        Ok(Self {
            recipient,
            ring_program_id,
            list_salt: list_salt(nullifier_key)?,
        })
    }

    /// A zero nullifier key has salt zero and every other key a nonzero canonical one.
    pub fn check_list_salt(
        recipient: &ShieldedAddress,
        list_salt: &[u8; 32],
    ) -> Result<(), RingKeyError> {
        let zero_key = recipient.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY;
        let zero_salt = *list_salt == [0; LIST_SALT_LEN];
        match zero_key == zero_salt && is_canonical_bn254_scalar_be(list_salt) {
            true => Ok(()),
            false => Err(RingKeyError::InvalidRingAddressListSalt),
        }
    }

    /// `version ‖ recipient ‖ ring_program_id ‖ list_salt ‖ checksum`.
    pub fn to_bytes(&self) -> [u8; RING_ADDRESS_PAYLOAD_LEN] {
        let mut bytes = [0u8; RING_ADDRESS_PAYLOAD_LEN];
        let (body, tail) = bytes.split_at_mut(BODY_LEN);
        let (version, rest) = body.split_at_mut(1);
        let (recipient, rest) = rest.split_at_mut(SHIELDED_ADDRESS_LEN);
        let (program, salt) = rest.split_at_mut(32);
        version[0] = RING_ADDRESS_VERSION;
        recipient.copy_from_slice(&self.recipient.to_bytes());
        program.copy_from_slice(self.ring_program_id.as_array());
        salt.copy_from_slice(&self.list_salt);
        tail.copy_from_slice(&checksum(body));
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RingKeyError> {
        let bytes: &[u8; RING_ADDRESS_PAYLOAD_LEN] = bytes
            .try_into()
            .map_err(|_| RingKeyError::InvalidRingAddressLength)?;
        let (body, checksum_bytes) = bytes.split_at(BODY_LEN);
        let (&version, rest) = body
            .split_first()
            .ok_or(RingKeyError::InvalidRingAddressLength)?;
        if version != RING_ADDRESS_VERSION {
            return Err(RingKeyError::UnknownRingAddressVersion(version));
        }
        if *checksum_bytes != checksum(body) {
            return Err(RingKeyError::InvalidRingAddressChecksum);
        }
        let (recipient, rest) = rest
            .split_first_chunk::<SHIELDED_ADDRESS_LEN>()
            .ok_or(RingKeyError::InvalidRingAddressLength)?;
        let (program, salt) = rest
            .split_first_chunk::<32>()
            .ok_or(RingKeyError::InvalidRingAddressLength)?;
        let list_salt: [u8; LIST_SALT_LEN] = salt
            .try_into()
            .map_err(|_| RingKeyError::InvalidRingAddressLength)?;
        let recipient = ShieldedAddress::from_bytes(recipient)?;
        Self::check_list_salt(&recipient, &list_salt)?;
        Ok(Self {
            recipient,
            ring_program_id: Address::new_from_array(*program),
            list_salt,
        })
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    pub fn from_base58(text: &str) -> Result<Self, RingKeyError> {
        let mut bytes = [0u8; RING_ADDRESS_PAYLOAD_LEN];
        let len = bs58::decode(text)
            .onto(&mut bytes)
            .map_err(|error| match error {
                bs58::decode::Error::BufferTooSmall => RingKeyError::InvalidRingAddressLength,
                _ => RingKeyError::InvalidRingAddressBase58,
            })?;
        Self::from_bytes(&bytes[..len])
    }
}

/// `Poseidon(CRPS, secret)`, one way, a holder learns the owner's list position and never the secret.
pub fn list_salt(nullifier_key: &NullifierKey) -> Result<[u8; 32], RingKeyError> {
    let secret = Zeroizing::new(right_align(&*nullifier_key.secret()));
    Ok(Poseidon::hashv(&[&domain::field(LIST_SALT_DOMAIN), &*secret])?)
}

/// `Poseidon(CRPT, list_salt)`, the tracking leaf's commitment to the owner's one salt.
pub fn list_tag(list_salt: &[u8; 32]) -> Result<[u8; 32], RingKeyError> {
    Ok(Poseidon::hashv(&[&domain::field(LIST_TAG_DOMAIN), list_salt])?)
}

/// The first 4 bytes of `SHA256(domain ‖ body)`.
fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::new()
        .chain_update(RING_ADDRESS_CHECKSUM_DOMAIN)
        .chain_update(body)
        .finalize();
    core::array::from_fn(|i| digest[i])
}

/// `zolana:<address>?deposit_tag=&amount=&mint=&label=`, the query part is unauthenticated.
#[derive(Clone, PartialEq, Eq)]
pub struct RingPaymentRequest {
    pub address: RingAddress,
    /// The recipient's `recipient_request_view_tag`, read by a deposit and never by a transfer.
    pub deposit_tag: Option<ViewTag>,
    pub amount: Option<u64>,
    pub mint: Option<Address>,
    pub label: Option<String>,
}

impl fmt::Debug for RingPaymentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingPaymentRequest")
            .field("address", &self.address)
            .field("amount", &self.amount)
            .field("mint", &self.mint)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl RingPaymentRequest {
    pub fn new(address: RingAddress) -> Self {
        Self {
            address,
            deposit_tag: None,
            amount: None,
            mint: None,
            label: None,
        }
    }
}

impl fmt::Display for RingPaymentRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(RING_PAYMENT_SCHEME)?;
        formatter.write_str(&self.address.to_base58())?;
        let mut separator = '?';
        let mut write = |key: &str, value: fmt::Arguments<'_>| -> fmt::Result {
            write!(formatter, "{separator}{key}={value}")?;
            separator = '&';
            Ok(())
        };
        if let Some(tag) = &self.deposit_tag {
            write("deposit_tag", format_args!("{}", hex::encode(tag)))?;
        }
        if let Some(amount) = self.amount {
            write("amount", format_args!("{amount}"))?;
        }
        if let Some(mint) = &self.mint {
            write("mint", format_args!("{mint}"))?;
        }
        if let Some(label) = &self.label {
            write(
                "label",
                format_args!("{}", utf8_percent_encode(label, LABEL_ENCODE_SET)),
            )?;
        }
        Ok(())
    }
}

impl FromStr for RingPaymentRequest {
    type Err = RingKeyError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let rest = text
            .trim()
            .strip_prefix(RING_PAYMENT_SCHEME)
            .ok_or(RingKeyError::InvalidRingAddressScheme)?;
        let (address, query) = match rest.split_once('?') {
            Some((address, query)) => (address, Some(query)),
            None => (rest, None),
        };
        let address = RingAddress::from_base58(address)?;
        let (mut tag, mut amount, mut mint, mut label) = (None, None, None, None);
        for part in query.into_iter().flat_map(|query| query.split('&')) {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            match key {
                "deposit_tag" => replace_once(&mut tag, parse_tag(value)?)?,
                "amount" => replace_once(&mut amount, parse_amount(value)?)?,
                "mint" => replace_once(&mut mint, parse_mint(value)?)?,
                "label" => replace_once(&mut label, parse_label(value)?)?,
                _ => return Err(RingKeyError::UnknownRingPaymentKey),
            }
        }
        Ok(Self {
            address,
            deposit_tag: tag,
            amount,
            mint,
            label,
        })
    }
}

fn replace_once<T>(slot: &mut Option<T>, value: T) -> Result<(), RingKeyError> {
    if slot.replace(value).is_some() {
        return Err(RingKeyError::DuplicateRingPaymentKey);
    }
    Ok(())
}

/// Lowercase hex led by a zero byte, the one form a derived request tag takes.
fn parse_tag(value: &str) -> Result<ViewTag, RingKeyError> {
    let mut tag = ViewTag::default();
    hex::decode_to_slice(value, &mut tag).map_err(|_| RingKeyError::InvalidRingPaymentTag)?;
    match tag[0] == 0 && hex::encode(tag) == value {
        true => Ok(tag),
        false => Err(RingKeyError::InvalidRingPaymentTag),
    }
}

fn parse_amount(value: &str) -> Result<u64, RingKeyError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RingKeyError::InvalidRingPaymentAmount);
    }
    value
        .parse()
        .map_err(|_| RingKeyError::InvalidRingPaymentAmount)
}

fn parse_mint(value: &str) -> Result<Address, RingKeyError> {
    value
        .parse()
        .map_err(|_| RingKeyError::InvalidRingPaymentMint)
}

/// `percent_decode_str` keeps a bare `%`, every escape must be two hex digits.
fn parse_label(value: &str) -> Result<String, RingKeyError> {
    let escapes_complete = value.split('%').skip(1).all(|after| {
        after.len() >= 2 && after.bytes().take(2).all(|byte| byte.is_ascii_hexdigit())
    });
    if !escapes_complete {
        return Err(RingKeyError::InvalidRingPaymentLabel);
    }
    percent_decode_str(value)
        .decode_utf8()
        .map(|label| label.into_owned())
        .map_err(|_| RingKeyError::InvalidRingPaymentLabel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_escapes_everything_outside_the_unreserved_set() {
        let encoded = utf8_percent_encode("a b&c=d/é-._~!*'()", LABEL_ENCODE_SET).to_string();
        assert_eq!(encoded, "a%20b%26c%3Dd%2F%C3%A9-._~%21%2A%27%28%29");
        assert_eq!(parse_label(&encoded).unwrap(), "a b&c=d/é-._~!*'()");
    }

    #[test]
    fn label_rejects_incomplete_or_non_utf8_escapes() {
        for value in ["%", "%2", "%zz", "a%2", "%80"] {
            assert_eq!(
                parse_label(value).unwrap_err(),
                RingKeyError::InvalidRingPaymentLabel
            );
        }
    }

    #[test]
    fn amount_rejects_signs_blanks_and_overflow() {
        for value in ["", "+1", "-1", " 1", "1.0", "18446744073709551616"] {
            assert_eq!(
                parse_amount(value).unwrap_err(),
                RingKeyError::InvalidRingPaymentAmount
            );
        }
        assert_eq!(parse_amount("18446744073709551615").unwrap(), u64::MAX);
    }
}
