//! Regions of the ring auditor stream and the byte layout of every plaintext it and the
//! delivered bodies carry, mirror `prover/circuits/audit`.

use crate::{
    bytes::Bytes, disclosure::AnonymousAuditKey, error::CustomRingError, TAGGED_X25519_KEY_LEN,
};

pub const STREAM_BLOCK_LEN: usize = 16;
pub const STREAM_FIRST_COUNTER: u32 = 2;
/// The sealed `tx_viewing_sk`, the envelope's first bytes.
pub const ENVELOPE_KEY_LEN: usize = 32;
/// `be32(blinding) || u64be(amount) || owner_key`.
pub const ESCROWED_DELIVERED_BODY_LEN: usize = 72;
/// `be32(blinding) || u64be(amount) || owner_key || be32(nullifier_pk)`.
pub const DELIVERED_BODY_LEN: usize = 104;
/// `owner_key || be32(asset) || u64be(amount) || be32(nullifier_pk)`.
pub const ANONYMOUS_RECORD_LEN: usize = 104;
/// `be32(asset) || u64be(amount)`.
pub const ESCROWED_EXIT_RECORD_LEN: usize = 40;
/// `be32(asset) || u64be(amount) || be32(nullifier_pk)`.
pub const EXIT_RECORD_LEN: usize = 72;
/// `be32(hash) || u64be(amount) || be32(asset) || be32(blinding)`.
pub const ENTRY_INPUT_LEN: usize = 104;
/// `sender_key || be32(sender_nullifier_pk)`.
pub const ENTRY_EVIDENCE_HEAD_LEN: usize = 64;
/// `be32(hash_i)`, zero at a dummy.
pub const INPUT_HASH_LEN: usize = 32;
/// Scheme 11, `be32(blinding) || u64be(amount) || mint`.
pub const RECIPIENT_BODY_LEN: usize = 72;
/// `mint0 || u64be(amount0) || u64be(amount1) || output_seed`.
pub const SENDER_BUNDLE_HEAD_LEN: usize = 80;
/// `viewing_u || owner_key || nullifier_pk`, one byte for the wincode of no data.
pub const MIN_REPLY_LEN: usize = 97;
pub const ANONYMOUS_RECORD_BLOCKS: usize = ANONYMOUS_RECORD_LEN.div_ceil(STREAM_BLOCK_LEN);
pub const CONFIDENTIAL_RECORD_BLOCKS: usize = EXIT_RECORD_LEN.div_ceil(STREAM_BLOCK_LEN);
const ENVELOPE_KEY_BLOCKS: usize = ENVELOPE_KEY_LEN / STREAM_BLOCK_LEN;
const FIELD_LEN: usize = 32;
const AMOUNT_LEN: usize = 8;

const _: () = assert!(AMOUNT_LEN + 2 * FIELD_LEN == ESCROWED_DELIVERED_BODY_LEN);
const _: () = assert!(AMOUNT_LEN + 3 * FIELD_LEN == DELIVERED_BODY_LEN);
const _: () = assert!(AMOUNT_LEN + 3 * FIELD_LEN == ANONYMOUS_RECORD_LEN);
const _: () = assert!(AMOUNT_LEN + FIELD_LEN == ESCROWED_EXIT_RECORD_LEN);
const _: () = assert!(AMOUNT_LEN + 2 * FIELD_LEN == EXIT_RECORD_LEN);
const _: () = assert!(AMOUNT_LEN + 3 * FIELD_LEN == ENTRY_INPUT_LEN);
const _: () = assert!(AMOUNT_LEN + 2 * FIELD_LEN == RECIPIENT_BODY_LEN);
const _: () = assert!(2 * AMOUNT_LEN + 2 * FIELD_LEN == SENDER_BUNDLE_HEAD_LEN);
const _: () = assert!(3 * FIELD_LEN + 1 == MIN_REPLY_LEN);
const _: () = assert!(2 * FIELD_LEN == ENTRY_EVIDENCE_HEAD_LEN);
const _: () = assert!(DELIVERED_BODY_LEN == ANONYMOUS_RECORD_LEN);
const _: () = assert!(ESCROWED_DELIVERED_BODY_LEN == EXIT_RECORD_LEN);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKey {
    Confidential { class: usize },
    Anonymous(AnonymousAuditKey),
}

impl AuditKey {
    pub const fn class(self) -> usize {
        match self {
            Self::Confidential { class } => class,
            Self::Anonymous(key) => key.class(),
        }
    }

    /// `S`, the owner signers the key's statement chains.
    pub const fn signer_slots(self) -> usize {
        match self {
            Self::Confidential { class } => class,
            Self::Anonymous(AnonymousAuditKey::Commitment { class }) => class,
            Self::Anonymous(AnonymousAuditKey::Entry { .. }) => 0,
        }
    }

    /// `E_max`, the same at every rail of a key since one circuit serves them.
    pub const fn max_evidence_blocks(self) -> usize {
        let max_evidence_len = match self {
            Self::Confidential { class }
            | Self::Anonymous(AnonymousAuditKey::Commitment { class }) => INPUT_HASH_LEN * class,
            Self::Anonymous(AnonymousAuditKey::Entry { class }) => {
                ENTRY_EVIDENCE_HEAD_LEN + ENTRY_INPUT_LEN * class
            }
        };
        max_evidence_len.div_ceil(STREAM_BLOCK_LEN)
    }

    /// `R`.
    pub const fn record_blocks(self) -> usize {
        match self {
            Self::Confidential { .. } => CONFIDENTIAL_RECORD_BLOCKS,
            Self::Anonymous(_) => ANONYMOUS_RECORD_BLOCKS,
        }
    }

    /// `R0`.
    pub const fn first_record_counter(self) -> u32 {
        STREAM_FIRST_COUNTER + (ENVELOPE_KEY_BLOCKS + self.max_evidence_blocks()) as u32
    }
}

/// One stretch of the auditor keystream, no counter serves two regions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamRegion {
    pub start_counter: u32,
    pub max_blocks: usize,
    /// Transmitted bytes, padding and unused blocks never leave the prover.
    pub len: usize,
}

impl StreamRegion {
    /// Where the region starts in a keystream read from the first counter.
    pub const fn keystream_offset(self) -> usize {
        (self.start_counter - STREAM_FIRST_COUNTER) as usize * STREAM_BLOCK_LEN
    }
}

/// Every length of one transfer's ring ciphertexts, a frame of any other length is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditStreamLayout {
    pub key: AuditKey,
    pub key_escrow: bool,
    /// `n`, the frame's nullifier count, never the key capacity or a private live count.
    pub inputs: usize,
    /// `m`, the published slots.
    pub outputs: usize,
    /// `N`, the key's output capacity, the keystream spans every slot of it.
    pub capacity: usize,
    /// Bit `i` set when slot `i` exits.
    pub exits: u64,
}

impl AuditStreamLayout {
    /// Refuses an input count off the key, an output count off the capacity and an exit past the outputs.
    pub fn checked(self) -> Result<Self, CustomRingError> {
        let outputs_fit = self.outputs >= 1
            && self.outputs <= self.capacity
            && self.outputs <= u64::BITS as usize;
        let exits_fit = self.exits.checked_shr(self.outputs as u32).unwrap_or(0) == 0;
        match self.inputs >= 1 && self.inputs <= self.key.class() && outputs_fit && exits_fit {
            true => Ok(self),
            false => Err(CustomRingError::RingTransactLength),
        }
    }

    pub const fn max_evidence_blocks(self) -> usize {
        self.key.max_evidence_blocks()
    }

    pub const fn record_blocks(self) -> usize {
        self.key.record_blocks()
    }

    pub const fn first_record_counter(self) -> u32 {
        self.key.first_record_counter()
    }

    /// Slots at or past `n` stay absent from the evidence.
    pub const fn evidence_len(self) -> usize {
        match self.key {
            AuditKey::Confidential { .. }
            | AuditKey::Anonymous(AnonymousAuditKey::Commitment { .. }) => {
                INPUT_HASH_LEN * self.inputs
            }
            AuditKey::Anonymous(AnonymousAuditKey::Entry { .. }) => {
                ENTRY_EVIDENCE_HEAD_LEN + ENTRY_INPUT_LEN * self.inputs
            }
        }
    }

    pub const fn envelope(self) -> StreamRegion {
        StreamRegion {
            start_counter: STREAM_FIRST_COUNTER,
            max_blocks: ENVELOPE_KEY_BLOCKS + self.max_evidence_blocks(),
            len: ENVELOPE_KEY_LEN + self.evidence_len(),
        }
    }

    /// The range of slot `slot`, transmitting nothing on a delivered slot.
    pub const fn record(self, slot: usize) -> StreamRegion {
        StreamRegion {
            start_counter: self.first_record_counter() + (slot * self.record_blocks()) as u32,
            max_blocks: self.record_blocks(),
            len: self.record_len(slot),
        }
    }

    pub const fn is_exit(self, slot: usize) -> bool {
        slot < self.outputs && slot < u64::BITS as usize && (self.exits >> slot) & 1 == 1
    }

    pub const fn delivered_body_len(self) -> usize {
        delivered_body_len(self.key_escrow)
    }

    pub const fn exit_record_len(self) -> usize {
        exit_record_len(self.key_escrow)
    }

    /// Zero past the outputs and on a delivered slot.
    pub const fn record_len(self, slot: usize) -> usize {
        if slot >= self.outputs {
            return 0;
        }
        match (self.is_exit(slot), self.key) {
            (true, _) => self.exit_record_len(),
            (false, AuditKey::Anonymous(_)) => ANONYMOUS_RECORD_LEN,
            (false, AuditKey::Confidential { .. }) => 0,
        }
    }

    /// The one ring disclosure ciphertext of slot `slot`, zero past the outputs.
    pub const fn ciphertext_len(self, slot: usize) -> usize {
        match self.record_len(slot) {
            0 if slot < self.outputs => self.delivered_body_len(),
            len => len,
        }
    }

    pub fn records_len(self) -> usize {
        (0..self.outputs).map(|slot| self.record_len(slot)).sum()
    }

    /// `0x04 || eph_u || envelope_ct || record_ct...`.
    pub fn message_len(self) -> usize {
        TAGGED_X25519_KEY_LEN + self.envelope().len + self.records_len()
    }

    /// The blocks one `CTREncrypt` covers.
    pub const fn capacity_blocks(self) -> usize {
        self.envelope().max_blocks + self.capacity * self.record_blocks()
    }
}

pub const fn delivered_body_len(key_escrow: bool) -> usize {
    match key_escrow {
        true => ESCROWED_DELIVERED_BODY_LEN,
        false => DELIVERED_BODY_LEN,
    }
}

pub const fn exit_record_len(key_escrow: bool) -> usize {
    match key_escrow {
        true => ESCROWED_EXIT_RECORD_LEN,
        false => EXIT_RECORD_LEN,
    }
}

/// `m` fixes the bundle, never a slot count a reader inferred.
pub const fn sender_bundle_len(outputs: usize) -> usize {
    SENDER_BUNDLE_HEAD_LEN + FIELD_LEN * outputs
}

/// Zero fields off a UTXO.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryInput {
    pub hash: [u8; 32],
    pub amount: u64,
    pub asset: [u8; 32],
    pub blinding: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvidence {
    /// Signer, in-proof, authority and commitment, `be32(hash_i)` for `i < n`.
    InputHashes(Vec<[u8; 32]>),
    /// The anonymous entry key, the circuit holds every input to `sender_nullifier_pk`.
    Entry {
        sender_key: [u8; 32],
        sender_nullifier_pk: [u8; 32],
        inputs: Vec<EntryInput>,
    },
}

/// The envelope plaintext `tx_viewing_sk || evidence`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEnvelope {
    pub tx_viewing_secret: [u8; ENVELOPE_KEY_LEN],
    pub evidence: AuditEvidence,
}

impl AuditEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let evidence_len = match &self.evidence {
            AuditEvidence::InputHashes(hashes) => INPUT_HASH_LEN * hashes.len(),
            AuditEvidence::Entry { inputs, .. } => {
                ENTRY_EVIDENCE_HEAD_LEN + ENTRY_INPUT_LEN * inputs.len()
            }
        };
        let mut out = Vec::with_capacity(ENVELOPE_KEY_LEN + evidence_len);
        out.extend_from_slice(&self.tx_viewing_secret);
        match &self.evidence {
            AuditEvidence::InputHashes(hashes) => {
                hashes.iter().for_each(|hash| out.extend_from_slice(hash));
            }
            AuditEvidence::Entry {
                sender_key,
                sender_nullifier_pk,
                inputs,
            } => {
                out.extend_from_slice(sender_key);
                out.extend_from_slice(sender_nullifier_pk);
                for input in inputs {
                    out.extend_from_slice(&input.hash);
                    out.extend_from_slice(&input.amount.to_be_bytes());
                    out.extend_from_slice(&input.asset);
                    out.extend_from_slice(&input.blinding);
                }
            }
        }
        out
    }

    /// Refuses any length other than `layout`'s.
    pub fn decode(plaintext: &[u8], layout: AuditStreamLayout) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            let tx_viewing_secret = *bytes.array()?;
            let inputs = layout.inputs;
            let evidence = match layout.key {
                AuditKey::Confidential { .. }
                | AuditKey::Anonymous(AnonymousAuditKey::Commitment { .. }) => {
                    AuditEvidence::InputHashes(bytes.fields(inputs)?.to_vec())
                }
                AuditKey::Anonymous(AnonymousAuditKey::Entry { .. }) => AuditEvidence::Entry {
                    sender_key: *bytes.array()?,
                    sender_nullifier_pk: *bytes.array()?,
                    inputs: (0..inputs)
                        .map(|_| {
                            Ok(EntryInput {
                                hash: *bytes.array()?,
                                amount: read_amount(bytes)?,
                                asset: *bytes.array()?,
                                blinding: *bytes.array()?,
                            })
                        })
                        .collect::<Result<_, CustomRingError>>()?,
                },
            };
            Ok(Self {
                tx_viewing_secret,
                evidence,
            })
        })
    }
}

/// Scheme 11, the recipient rebuilds the commitment with its own bound keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecipientBody {
    pub blinding: [u8; 32],
    pub amount: u64,
    pub mint: [u8; 32],
}

impl RecipientBody {
    pub fn encode(&self) -> [u8; RECIPIENT_BODY_LEN] {
        let mut out = [0; RECIPIENT_BODY_LEN];
        out[..32].copy_from_slice(&self.blinding);
        out[32..40].copy_from_slice(&self.amount.to_be_bytes());
        out[40..].copy_from_slice(&self.mint);
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            Ok(Self {
                blinding: *bytes.array()?,
                amount: read_amount(bytes)?,
                mint: *bytes.array()?,
            })
        })
    }
}

/// Scheme 12, the cells the sender rebuilds change and recipients from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SenderBundle {
    /// Slot 0's mint when `change_bits` bit 0 is set, else zero.
    pub mint: [u8; 32],
    /// Slot 0's amount when `change_bits` bit 0 is set, else zero.
    pub amount: u64,
    /// Slot 1's amount in SOL when `change_bits` bit 1 is set, else zero.
    pub sol_amount: u64,
    pub output_seed: [u8; 32],
    /// One per published slot, zero on change, exit and dummy.
    pub recipient_keys: Vec<[u8; 32]>,
}

impl SenderBundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(sender_bundle_len(self.recipient_keys.len()));
        out.extend_from_slice(&self.mint);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.sol_amount.to_be_bytes());
        out.extend_from_slice(&self.output_seed);
        self.recipient_keys
            .iter()
            .for_each(|key| out.extend_from_slice(key));
        out
    }

    /// `outputs` is the frame's `m`.
    pub fn decode(plaintext: &[u8], outputs: usize) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            Ok(Self {
                mint: *bytes.array()?,
                amount: read_amount(bytes)?,
                sol_amount: read_amount(bytes)?,
                output_seed: *bytes.array()?,
                recipient_keys: bytes.fields(outputs)?.to_vec(),
            })
        })
    }
}

/// The plaintext recipient and auditor read from one delivered slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeliveredBody {
    pub blinding: [u8; 32],
    pub amount: u64,
    pub owner_key: [u8; 32],
    /// `None` exactly under key escrow.
    pub nullifier_pk: Option<[u8; 32]>,
}

impl DeliveredBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(delivered_body_len(self.nullifier_pk.is_none()));
        out.extend_from_slice(&self.blinding);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.owner_key);
        if let Some(nullifier_pk) = &self.nullifier_pk {
            out.extend_from_slice(nullifier_pk);
        }
        out
    }

    pub fn decode(plaintext: &[u8], key_escrow: bool) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            Ok(Self {
                blinding: *bytes.array()?,
                amount: read_amount(bytes)?,
                owner_key: *bytes.array()?,
                nullifier_pk: read_nullifier_pk(bytes, key_escrow)?,
            })
        })
    }
}

/// An anonymous ring output, a hidden dummy is the zero record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnonymousRecord {
    pub owner_key: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
    pub nullifier_pk: [u8; 32],
}

impl AnonymousRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ANONYMOUS_RECORD_LEN);
        out.extend_from_slice(&self.owner_key);
        out.extend_from_slice(&self.asset);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.nullifier_pk);
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            Ok(Self {
                owner_key: *bytes.array()?,
                asset: *bytes.array()?,
                amount: read_amount(bytes)?,
                nullifier_pk: *bytes.array()?,
            })
        })
    }
}

/// An exit of either family, its owner stays where zolana publishes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExitRecord {
    pub asset: [u8; 32],
    pub amount: u64,
    /// `None` exactly under key escrow.
    pub nullifier_pk: Option<[u8; 32]>,
}

impl ExitRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(exit_record_len(self.nullifier_pk.is_none()));
        out.extend_from_slice(&self.asset);
        out.extend_from_slice(&self.amount.to_be_bytes());
        if let Some(nullifier_pk) = &self.nullifier_pk {
            out.extend_from_slice(nullifier_pk);
        }
        out
    }

    pub fn decode(plaintext: &[u8], key_escrow: bool) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            Ok(Self {
                asset: *bytes.array()?,
                amount: read_amount(bytes)?,
                nullifier_pk: read_nullifier_pk(bytes, key_escrow)?,
            })
        })
    }
}

fn read_amount(bytes: &mut Bytes<'_>) -> Result<u64, CustomRingError> {
    Ok(u64::from_be_bytes(*bytes.array()?))
}

fn read_all<'a, T>(
    plaintext: &'a [u8],
    read: impl FnOnce(&mut Bytes<'a>) -> Result<T, CustomRingError>,
) -> Result<T, CustomRingError> {
    let mut bytes = Bytes::new(plaintext, CustomRingError::RingTransactLength);
    let value = read(&mut bytes)?;
    match bytes.rest().is_empty() {
        true => Ok(value),
        false => Err(CustomRingError::RingTransactLength),
    }
}

fn read_nullifier_pk(
    bytes: &mut Bytes<'_>,
    key_escrow: bool,
) -> Result<Option<[u8; 32]>, CustomRingError> {
    match key_escrow {
        true => Ok(None),
        false => Ok(Some(*bytes.array()?)),
    }
}
