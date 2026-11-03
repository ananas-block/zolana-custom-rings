//! Regions of the ring auditor stream and the byte layout of every plaintext it and the
//! delivered bodies carry, mirror `prover/circuits/audit`.

use crate::{
    bytes::Bytes,
    disclosure::{AnonymousAuditKey, InputPrefix, INPUT_PREFIX_BYTES},
    error::CustomRingError,
    TAGGED_X25519_KEY_LEN,
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
/// `u64be(amount) || be32(asset) || be32(blinding)`.
pub const ENTRY_INPUT_LEN: usize = 72;
/// `sender_key || be32(sender_nullifier_pk)`.
pub const ENTRY_EVIDENCE_HEAD_LEN: usize = 64;
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
const _: () = assert!(AMOUNT_LEN + 2 * FIELD_LEN == ENTRY_INPUT_LEN);
const _: () = assert!(2 * FIELD_LEN == ENTRY_EVIDENCE_HEAD_LEN);
const _: () = assert!(DELIVERED_BODY_LEN == ANONYMOUS_RECORD_LEN);
const _: () = assert!(ESCROWED_DELIVERED_BODY_LEN == EXIT_RECORD_LEN);

/// The transfer key family at its input class, with the rail bits its evidence reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKey {
    Confidential {
        class: usize,
        /// The in-proof and authority rails, the signer rail discloses no input.
        input_prefixes: bool,
    },
    Anonymous(AnonymousAuditKey),
}

impl AuditKey {
    pub const fn class(self) -> usize {
        match self {
            Self::Confidential { class, .. } => class,
            Self::Anonymous(key) => key.class(),
        }
    }

    /// `E_max`, the same at every rail of a key since one circuit serves them.
    pub const fn max_evidence_blocks(self) -> usize {
        let max_evidence_len = match self {
            Self::Confidential { class, .. } => INPUT_PREFIX_BYTES * class,
            Self::Anonymous(AnonymousAuditKey::Commitment { class }) => {
                FIELD_LEN + INPUT_PREFIX_BYTES * class.saturating_sub(1)
            }
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
    pub outputs: usize,
    /// Bit `i` set when slot `i` exits.
    pub exits: u64,
}

impl AuditStreamLayout {
    /// Refuses an input count off the key and an exit past the outputs.
    pub fn checked(self) -> Result<Self, CustomRingError> {
        let exits_fit = self.outputs <= u64::BITS as usize
            && self.exits.checked_shr(self.outputs as u32).unwrap_or(0) == 0;
        match self.inputs >= 1 && self.inputs <= self.key.class() && exits_fit {
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
            AuditKey::Confidential {
                input_prefixes: false,
                ..
            } => 0,
            AuditKey::Confidential {
                input_prefixes: true,
                ..
            } => INPUT_PREFIX_BYTES * self.inputs,
            AuditKey::Anonymous(AnonymousAuditKey::Commitment { .. }) => {
                FIELD_LEN + INPUT_PREFIX_BYTES * self.inputs.saturating_sub(1)
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
        self.envelope().max_blocks + self.outputs * self.record_blocks()
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryInput {
    pub amount: u64,
    pub asset: [u8; 32],
    pub blinding: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvidence {
    /// The signer rail.
    None,
    /// The in-proof and authority rails, `prefix16(input_hash_i)` for `i < n`.
    InputPrefixes(Vec<Option<InputPrefix>>),
    /// The anonymous commitment key.
    Commitment {
        first_input_hash: [u8; 32],
        /// `prefix16(input_hash_i)` for `1 <= i < n`.
        later_prefixes: Vec<Option<InputPrefix>>,
    },
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
            AuditEvidence::None => 0,
            AuditEvidence::InputPrefixes(prefixes) => INPUT_PREFIX_BYTES * prefixes.len(),
            AuditEvidence::Commitment { later_prefixes, .. } => {
                FIELD_LEN + INPUT_PREFIX_BYTES * later_prefixes.len()
            }
            AuditEvidence::Entry { inputs, .. } => {
                ENTRY_EVIDENCE_HEAD_LEN + ENTRY_INPUT_LEN * inputs.len()
            }
        };
        let mut out = Vec::with_capacity(ENVELOPE_KEY_LEN + evidence_len);
        out.extend_from_slice(&self.tx_viewing_secret);
        match &self.evidence {
            AuditEvidence::None => {}
            AuditEvidence::InputPrefixes(prefixes) => {
                prefixes.iter().for_each(|p| write_prefix(&mut out, p));
            }
            AuditEvidence::Commitment {
                first_input_hash,
                later_prefixes,
            } => {
                out.extend_from_slice(first_input_hash);
                later_prefixes
                    .iter()
                    .for_each(|p| write_prefix(&mut out, p));
            }
            AuditEvidence::Entry {
                sender_key,
                sender_nullifier_pk,
                inputs,
            } => {
                out.extend_from_slice(sender_key);
                out.extend_from_slice(sender_nullifier_pk);
                for input in inputs {
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
                AuditKey::Confidential {
                    input_prefixes: false,
                    ..
                } => AuditEvidence::None,
                AuditKey::Confidential {
                    input_prefixes: true,
                    ..
                } => AuditEvidence::InputPrefixes(read_prefixes(bytes, inputs)?),
                AuditKey::Anonymous(AnonymousAuditKey::Commitment { .. }) => {
                    AuditEvidence::Commitment {
                        first_input_hash: *bytes.array()?,
                        later_prefixes: read_prefixes(bytes, inputs.saturating_sub(1))?,
                    }
                }
                AuditKey::Anonymous(AnonymousAuditKey::Entry { .. }) => AuditEvidence::Entry {
                    sender_key: *bytes.array()?,
                    sender_nullifier_pk: *bytes.array()?,
                    inputs: (0..inputs)
                        .map(|_| {
                            Ok(EntryInput {
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

/// A published dummy slot is `None`, zero bytes as `prefix16`.
fn write_prefix(out: &mut Vec<u8>, prefix: &Option<InputPrefix>) {
    out.extend_from_slice(&prefix.map_or([0; INPUT_PREFIX_BYTES], InputPrefix::to_bytes));
}

fn read_prefixes(
    bytes: &mut Bytes<'_>,
    count: usize,
) -> Result<Vec<Option<InputPrefix>>, CustomRingError> {
    (0..count)
        .map(|_| InputPrefix::from_bytes(bytes.array()?))
        .collect()
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
