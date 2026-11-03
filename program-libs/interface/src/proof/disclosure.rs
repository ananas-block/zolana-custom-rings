//! The transfer layout element, the anonymous key choice and the input prefix, mirror
//! `prover/circuits/audit`.

use spr_hasher::primitives::{
    is_canonical_bn254_scalar_be, pack_be_chunks, BN254_SCALAR_MODULUS_BE, PACK_BE_CHUNK_BYTES,
};

use crate::{
    error::CustomRingError,
    key_catalog::{TransferShape, ANONYMOUS_TRANSFER_SHAPES, ENTRY_TRANSFER_SHAPES},
};

pub const DELIVERED_AUDIT_CAPACITIES: [usize; 4] = [2, 4, 8, 16];
/// The first bytes of a spent hash the evidence discloses.
pub const INPUT_PREFIX_BYTES: usize = 16;

/// The transfer statement's layout element, mirror `prover/circuits/audit/layout.go`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditLayout {
    /// The policy proof escrows every output nullifier key the disclosure leaves out.
    pub key_escrow: bool,
    /// The anonymous entry key, every spent UTXO opens in full.
    pub full_openings: bool,
}

impl AuditLayout {
    /// Every audit key refuses bits 0 and 2.
    pub const fn value(self) -> u8 {
        (self.key_escrow as u8) << 1 | (self.full_openings as u8) << 3
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousAuditKey {
    /// Publishes spent UTXO 0's hash and the prefix of every later one, every spent UTXO a note of the ring.
    Commitment { class: usize },
    /// Opens every spent UTXO, the key of a transfer that spends a default-ring note.
    Entry { class: usize },
}

impl AnonymousAuditKey {
    pub const fn class(self) -> usize {
        match self {
            Self::Commitment { class } | Self::Entry { class } => class,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnonymousSpend {
    /// Published inputs.
    pub inputs: usize,
    pub outputs: usize,
    /// A spent UTXO is a default-ring note, the commitment keys refuse ring id zero.
    pub spends_default_ring: bool,
}

impl AnonymousSpend {
    /// `None` when no key serves the spend, a larger spend splits.
    pub fn audit_key(self) -> Option<AnonymousAuditKey> {
        let shapes = match self.spends_default_ring {
            true => &ENTRY_TRANSFER_SHAPES[..],
            false => &ANONYMOUS_TRANSFER_SHAPES[..],
        };
        let class = usize::from(TransferShape::of(shapes, self.outputs)?.inputs);
        if self.inputs == 0 || self.inputs > class {
            return None;
        }
        Some(match self.spends_default_ring {
            true => AnonymousAuditKey::Entry { class },
            false => AnonymousAuditKey::Commitment { class },
        })
    }
}

/// `prefix16(input_hash)`, the first bytes of the big-endian hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InputPrefix(u128);

impl InputPrefix {
    /// No canonical hash has a larger prefix.
    const MAX: u128 = halves(&BN254_SCALAR_MODULUS_BE)[0];

    /// `None` for a hash at or above the modulus or below 2^128, a zero prefix names no input.
    pub fn of(hash: &[u8; 32]) -> Option<Self> {
        let [prefix, _] = halves(hash);
        (is_canonical_bn254_scalar_be(hash) && prefix != 0).then_some(Self(prefix))
    }

    pub const fn get(self) -> u128 {
        self.0
    }

    pub const fn to_bytes(self) -> [u8; INPUT_PREFIX_BYTES] {
        self.0.to_be_bytes()
    }

    /// `None` for the zero bytes of a published dummy, refuses a prefix no canonical hash has.
    pub fn from_bytes(bytes: &[u8; INPUT_PREFIX_BYTES]) -> Result<Option<Self>, CustomRingError> {
        match u128::from_be_bytes(*bytes) {
            0 => Ok(None),
            prefix if prefix <= Self::MAX => Ok(Some(Self(prefix))),
            _ => Err(CustomRingError::InvalidInstructionData),
        }
    }
}

const fn halves(field: &[u8; 32]) -> [u128; 2] {
    let (chunks, _) = field.as_chunks::<INPUT_PREFIX_BYTES>();
    [
        u128::from_be_bytes(chunks[0]),
        u128::from_be_bytes(chunks[1]),
    ]
}

/// Zero pads the plaintext at its end to whole 31-byte chunks, one chunk per field.
pub fn pack_disclosure(plaintext: &[u8]) -> Vec<[u8; 32]> {
    plaintext
        .chunks(PACK_BE_CHUNK_BYTES)
        .map(|chunk| {
            let mut field = [0u8; 32];
            field[1..1 + chunk.len()].copy_from_slice(chunk);
            field
        })
        .collect()
}

/// Inverts [`pack_disclosure`], `None` when a field holds bytes outside its chunk.
pub fn unpack_disclosure(fields: &[[u8; 32]], len: usize) -> Option<Vec<u8>> {
    if fields.len() != pack_be_chunks(len) {
        return None;
    }
    let mut plaintext = Vec::with_capacity(len);
    for (index, field) in fields.iter().enumerate() {
        let chunk = (len - index * PACK_BE_CHUNK_BYTES).min(PACK_BE_CHUNK_BYTES);
        let (bytes, padding) = field[1..].split_at(chunk);
        if field[0] != 0 || padding.iter().any(|byte| *byte != 0) {
            return None;
        }
        plaintext.extend_from_slice(bytes);
    }
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No canonical hash has a prefix above the modulus prefix.
    #[test]
    fn input_prefixes_read_back_and_refuse_a_prefix_above_the_modulus() {
        let mut below = BN254_SCALAR_MODULUS_BE;
        below[31] -= 1;
        let top = InputPrefix::of(&below).unwrap();
        assert_eq!(top.get(), InputPrefix::MAX);
        assert_eq!(InputPrefix::of(&BN254_SCALAR_MODULUS_BE), None);
        let mut short = [0; 32];
        short[16] = 1;
        assert_eq!(InputPrefix::of(&short), None);
        assert_eq!(InputPrefix::from_bytes(&top.to_bytes()), Ok(Some(top)));
        assert_eq!(InputPrefix::from_bytes(&[0; 16]), Ok(None));
        let over = (InputPrefix::MAX + 1).to_be_bytes();
        assert_eq!(
            InputPrefix::from_bytes(&over),
            Err(CustomRingError::InvalidInstructionData)
        );
    }

    #[test]
    fn the_layout_value_keeps_bits_zero_and_two_clear() {
        let flags = |key_escrow, full_openings| {
            AuditLayout {
                key_escrow,
                full_openings,
            }
            .value()
        };
        assert_eq!(flags(false, false), 0);
        assert_eq!(flags(true, false), 2);
        assert_eq!(flags(false, true), 8);
        assert_eq!(flags(true, true), 10);
    }

    #[test]
    fn a_spend_takes_its_family_class_at_its_output_count() {
        let key = |inputs, outputs, spends_default_ring| {
            AnonymousSpend {
                inputs,
                outputs,
                spends_default_ring,
            }
            .audit_key()
        };
        let commitment = |class| Some(AnonymousAuditKey::Commitment { class });
        let entry = |class| Some(AnonymousAuditKey::Entry { class });
        assert_eq!(key(1, 2, false), commitment(24));
        assert_eq!(key(24, 2, false), commitment(24));
        assert_eq!(key(25, 2, false), None);
        assert_eq!(key(16, 4, false), commitment(16));
        assert_eq!(key(17, 4, false), None);
        assert_eq!(key(5, 8, false), commitment(5));
        assert_eq!(key(6, 8, false), None);
        assert_eq!(key(0, 2, false), None);
        assert_eq!(key(1, 16, false), None);
        assert_eq!(key(1, 2, true), entry(8));
        assert_eq!(key(8, 4, true), entry(8));
        assert_eq!(key(2, 8, true), entry(2));
        assert_eq!(key(3, 8, true), None);
        assert_eq!(key(9, 4, true), None);
        assert_eq!(key(2, 16, true), None);
    }

    #[test]
    fn a_short_tail_chunk_is_left_aligned_and_zero_padded() {
        let plaintext: Vec<u8> = (1..=40).collect();
        let fields = pack_disclosure(&plaintext);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0][0], 0);
        assert_eq!(fields[0][1..], plaintext[..31]);
        assert_eq!(fields[1][..10], [0, 32, 33, 34, 35, 36, 37, 38, 39, 40]);
        assert_eq!(fields[1][10..], [0u8; 22]);
        assert_eq!(
            unpack_disclosure(&fields, 40).as_deref(),
            Some(&plaintext[..])
        );
    }

    #[test]
    fn unpacking_rejects_bytes_outside_a_chunk() {
        let plaintext: Vec<u8> = (1..=70).collect();
        let fields = pack_disclosure(&plaintext);
        assert_eq!(fields.len(), 3);
        assert_eq!(unpack_disclosure(&fields, 94), None);
        let mut padded = fields.clone();
        padded[2][9] = 1;
        assert_eq!(unpack_disclosure(&padded, 70), None);
        let mut widened = fields;
        widened[0][0] = 1;
        assert_eq!(unpack_disclosure(&widened, 70), None);
    }
}
