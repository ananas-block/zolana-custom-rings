//! `CRDEP001` is read and never written.

use custom_ring_interface::{
    domain::DEPOSIT_AUDIT_LABEL, RingDepositAuditCapsule, RingDepositAuditError,
    MAX_RING_DEPOSIT_AUDIT_SLOTS, STREAM_BLOCK_LEN, STREAM_FIRST_COUNTER, TAGGED_X25519_KEY_LEN,
};
use spr_keypair::{X25519Keypair, X25519Pubkey};
use zeroize::Zeroizing;

use super::{opening_ring_stream, DepositOpening, Result};

const HISTORICAL_MAGIC: &[u8; 8] = b"CRDEP001";
/// `owner_hash || blinding || owner_key`.
const HISTORICAL_OPENING_LEN: usize = 96;
const HISTORICAL_SLOT_BLOCKS: u32 = (HISTORICAL_OPENING_LEN / STREAM_BLOCK_LEN) as u32;
const HISTORICAL_PREFIX_LEN: usize =
    HISTORICAL_MAGIC.len() + 1 + TAGGED_X25519_KEY_LEN + HISTORICAL_OPENING_LEN;

/// `magic || slot || eph_pk || ciphertext` then the recipient's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoricalDepositCapsule<'a> {
    pub slot_index: u8,
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub ciphertext: &'a [u8; HISTORICAL_OPENING_LEN],
    pub recipient_ciphertext: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositCapsule<'a> {
    /// `CRDEP002`, tag 58.
    Record(RingDepositAuditCapsule<'a>),
    /// `CRDEP001`, tag 31.
    Historical(HistoricalDepositCapsule<'a>),
}

impl<'a> DepositCapsule<'a> {
    /// `None` for an output under neither magic.
    pub fn parse(bytes: &'a [u8]) -> core::result::Result<Option<Self>, RingDepositAuditError> {
        if bytes.starts_with(HISTORICAL_MAGIC) {
            return HistoricalDepositCapsule::parse(bytes)
                .map(|capsule| Some(Self::Historical(capsule)));
        }
        Ok(RingDepositAuditCapsule::parse(bytes)?.map(Self::Record))
    }

    pub const fn slot_index(&self) -> u8 {
        match self {
            Self::Record(capsule) => capsule.slot_index,
            Self::Historical(capsule) => capsule.slot_index,
        }
    }

    pub const fn recipient_ciphertext(&self) -> &'a [u8] {
        match self {
            Self::Record(capsule) => capsule.recipient_ciphertext,
            Self::Historical(capsule) => capsule.recipient_ciphertext,
        }
    }

    pub const fn is_historical(&self) -> bool {
        matches!(self, Self::Historical(_))
    }

    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::Record(capsule) => capsule.encode(),
            Self::Historical(capsule) => capsule.encode(),
        }
    }
}

impl<'a> HistoricalDepositCapsule<'a> {
    fn parse(bytes: &'a [u8]) -> core::result::Result<Self, RingDepositAuditError> {
        let truncated = RingDepositAuditError::Truncated;
        let (prefix, recipient_ciphertext) = bytes
            .split_at_checked(HISTORICAL_PREFIX_LEN)
            .ok_or(truncated)?;
        let (&slot_index, keys) = prefix[HISTORICAL_MAGIC.len()..]
            .split_first()
            .ok_or(truncated)?;
        if usize::from(slot_index) >= MAX_RING_DEPOSIT_AUDIT_SLOTS {
            return Err(RingDepositAuditError::InvalidSlot);
        }
        let (eph_pk, ciphertext) = keys
            .split_first_chunk::<TAGGED_X25519_KEY_LEN>()
            .ok_or(truncated)?;
        Ok(Self {
            slot_index,
            eph_pk,
            ciphertext: ciphertext.try_into().map_err(|_| truncated)?,
            recipient_ciphertext,
        })
    }

    pub fn encode(self) -> Vec<u8> {
        [
            &HISTORICAL_MAGIC[..],
            &[self.slot_index],
            self.eph_pk,
            self.ciphertext,
            self.recipient_ciphertext,
        ]
        .concat()
    }

    /// The caller checks the hash the opening rebuilds.
    pub(super) fn open(&self, auditor: &X25519Keypair) -> Result<DepositOpening> {
        let mut plaintext = Zeroizing::new(*self.ciphertext);
        opening_ring_stream(
            auditor,
            &X25519Pubkey::from_bytes(*self.eph_pk)?,
            DEPOSIT_AUDIT_LABEL,
        )?
        .apply_at(
            STREAM_FIRST_COUNTER + u32::from(self.slot_index) * HISTORICAL_SLOT_BLOCKS,
            &mut *plaintext,
        );
        let (owner_hash, rest) = plaintext.split_at(32);
        let (blinding, owner_key) = rest.split_at(32);
        let mut opening = DepositOpening {
            owner_hash: [0; 32],
            blinding: Zeroizing::new([0; 32]),
            owner_key: [0; 32],
            note: None,
        };
        opening.owner_hash.copy_from_slice(owner_hash);
        opening.blinding.copy_from_slice(blinding);
        opening.owner_key.copy_from_slice(owner_key);
        Ok(opening)
    }
}
