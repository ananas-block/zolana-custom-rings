//! Regions of the ring auditor stream and the byte layout of every plaintext it carries, mirror
//! `prover/circuits/audit`.

use crate::{bytes::Bytes, error::CustomRingError, TAGGED_X25519_KEY_LEN};

pub const STREAM_BLOCK_LEN: usize = 16;
pub const STREAM_FIRST_COUNTER: u32 = 2;
/// The sealed `tx_viewing_sk`, the envelope's first bytes.
pub const ENVELOPE_KEY_LEN: usize = 32;
/// `R`, spent notes among the published inputs, dummies last.
pub const REAL_INPUT_COUNT_LEN: usize = 1;
/// Keys with entry capacity alone, bit `i` set when input `i` is a default-ring note.
pub const DEFAULT_INPUT_BITS_LEN: usize = 8;
/// `kind || reserved || u64be(amount) || owner_key || mint || be32(nullifier_pk)`.
pub const AUDIT_RECORD_LEN: usize = 112;
/// `be32(data_hash) || be32(ring_data_hash)`.
pub const DATA_TAIL_LEN: usize = 64;
/// `owner_key || be32(nullifier_pk) || u64be(amount) || mint || be32(blinding) || be32(data_hash) || be32(ring_data_hash)`.
pub const ENTRY_INPUT_LEN: usize = 200;
/// `record || secret`, the deposit's blinding or the merge's seed.
pub const OPENING_RECORD_LEN: usize = AUDIT_RECORD_LEN + FIELD_LEN;
/// `be32(blinding) || u64be(amount) || mint`.
pub const RECIPIENT_BODY_LEN: usize = 72;
/// `mint0 || u64be(amount0) || u64be(amount1) || output_seed`.
pub const SENDER_BUNDLE_HEAD_LEN: usize = 80;
/// `viewing_u || owner_key || nullifier_pk`, one byte for the wincode of no data.
pub const MIN_REPLY_LEN: usize = 97;
pub const RECORD_BLOCKS: usize = AUDIT_RECORD_LEN / STREAM_BLOCK_LEN;
pub const TAIL_BLOCKS: usize = DATA_TAIL_LEN / STREAM_BLOCK_LEN;
const RECORD_RESERVED_LEN: usize = 7;
const FIELD_LEN: usize = 32;
const AMOUNT_LEN: usize = 8;

const _: () = assert!(1 + RECORD_RESERVED_LEN + AMOUNT_LEN + 3 * FIELD_LEN == AUDIT_RECORD_LEN);
const _: () = assert!(AUDIT_RECORD_LEN.is_multiple_of(STREAM_BLOCK_LEN));
const _: () = assert!(DATA_TAIL_LEN.is_multiple_of(STREAM_BLOCK_LEN));
const _: () = assert!(AMOUNT_LEN + 6 * FIELD_LEN == ENTRY_INPUT_LEN);
const _: () = assert!(AMOUNT_LEN + 2 * FIELD_LEN == RECIPIENT_BODY_LEN);
const _: () = assert!(2 * AMOUNT_LEN + 2 * FIELD_LEN == SENDER_BUNDLE_HEAD_LEN);
const _: () = assert!(3 * FIELD_LEN + 1 == MIN_REPLY_LEN);

/// One key's envelope, every rail of a key shares one circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditKey {
    /// The widest published input count.
    pub class: usize,
    /// Default bits and one evidence entry per published input.
    pub entry: bool,
}

impl AuditKey {
    pub const fn class(self) -> usize {
        self.class
    }

    /// `S`, the owner signers the key's statement chains.
    pub const fn signer_slots(self) -> usize {
        self.class
    }

    const fn head_len(self) -> usize {
        match self.entry {
            true => ENVELOPE_KEY_LEN + REAL_INPUT_COUNT_LEN + DEFAULT_INPUT_BITS_LEN,
            false => ENVELOPE_KEY_LEN + REAL_INPUT_COUNT_LEN,
        }
    }

    const fn entry_len(self) -> usize {
        match self.entry {
            true => ENTRY_INPUT_LEN,
            false => 0,
        }
    }

    /// `E`, the same at every published input count so no record's counter moves.
    pub const fn envelope_blocks(self) -> usize {
        (self.head_len() + self.entry_len() * self.class).div_ceil(STREAM_BLOCK_LEN)
    }

    /// `R0`.
    pub const fn first_record_counter(self) -> u32 {
        STREAM_FIRST_COUNTER + self.envelope_blocks() as u32
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

/// Every length of one transfer's auditor stream, a frame of any other length is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditStreamLayout {
    pub key: AuditKey,
    /// `n`, the frame's nullifier count, never the key capacity or a private live count.
    pub inputs: usize,
    /// `m`, the published slots.
    pub outputs: usize,
    /// `N`, the key's output capacity, records and tails span every slot of it.
    pub capacity: usize,
    /// The statement's bit, one tail per published slot.
    pub has_data: bool,
}

impl AuditStreamLayout {
    /// Refuses an input count off the key and an output count off the capacity.
    pub fn checked(self) -> Result<Self, CustomRingError> {
        let outputs_fit = self.outputs >= 1 && self.outputs <= self.capacity;
        match self.inputs >= 1 && self.inputs <= self.key.class() && outputs_fit {
            true => Ok(self),
            false => Err(CustomRingError::RingTransactLength),
        }
    }

    pub const fn first_record_counter(self) -> u32 {
        self.key.first_record_counter()
    }

    /// `T0`, past every record of `N` slots.
    pub const fn first_tail_counter(self) -> u32 {
        self.first_record_counter() + (self.capacity * RECORD_BLOCKS) as u32
    }

    /// Slots at or past `n` stay absent from the evidence.
    pub const fn envelope(self) -> StreamRegion {
        StreamRegion {
            start_counter: STREAM_FIRST_COUNTER,
            max_blocks: self.key.envelope_blocks(),
            len: self.key.head_len() + self.key.entry_len() * self.inputs,
        }
    }

    /// Slot `slot`'s record range, transmitting nothing past the outputs.
    pub const fn record(self, slot: usize) -> StreamRegion {
        StreamRegion {
            start_counter: self.first_record_counter() + (slot * RECORD_BLOCKS) as u32,
            max_blocks: RECORD_BLOCKS,
            len: self.record_len(slot),
        }
    }

    /// Slot `slot`'s tail range, transmitting nothing past the outputs or while `has_data` is clear.
    pub const fn tail(self, slot: usize) -> StreamRegion {
        StreamRegion {
            start_counter: self.first_tail_counter() + (slot * TAIL_BLOCKS) as u32,
            max_blocks: TAIL_BLOCKS,
            len: self.tail_len(slot),
        }
    }

    pub const fn record_len(self, slot: usize) -> usize {
        match slot < self.outputs {
            true => AUDIT_RECORD_LEN,
            false => 0,
        }
    }

    pub const fn tail_len(self, slot: usize) -> usize {
        match self.has_data && slot < self.outputs {
            true => DATA_TAIL_LEN,
            false => 0,
        }
    }

    pub const fn records_len(self) -> usize {
        AUDIT_RECORD_LEN * self.outputs
    }

    pub const fn tails_len(self) -> usize {
        match self.has_data {
            true => DATA_TAIL_LEN * self.outputs,
            false => 0,
        }
    }

    /// `0x04 || eph_u || envelope_ct || record_ct... || tail_ct...`.
    pub const fn message_len(self) -> usize {
        TAGGED_X25519_KEY_LEN + self.envelope().len + self.records_len() + self.tails_len()
    }

    /// The blocks a reader decrypts, a clear `has_data` reaches no tail.
    pub const fn capacity_blocks(self) -> usize {
        let tails = match self.has_data {
            true => self.capacity * TAIL_BLOCKS,
            false => 0,
        };
        self.key.envelope_blocks() + self.capacity * RECORD_BLOCKS + tails
    }
}

/// `m` fixes the bundle, never a slot count a reader inferred.
pub const fn sender_bundle_len(outputs: usize) -> usize {
    SENDER_BUNDLE_HEAD_LEN + FIELD_LEN * outputs
}

/// A record's first byte, the circuit derives it from the slot's domain and ring id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    #[default]
    Dummy = 0,
    Ring = 1,
    Exit = 2,
}

/// One published slot, the proof holds a dummy's plaintext to zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditRecord {
    pub kind: RecordKind,
    pub amount: u64,
    pub owner_key: [u8; 32],
    pub mint: [u8; 32],
    pub nullifier_pk: [u8; 32],
}

impl AuditRecord {
    pub fn encode(&self) -> [u8; AUDIT_RECORD_LEN] {
        let mut out = [0; AUDIT_RECORD_LEN];
        out[0] = self.kind as u8;
        out[8..16].copy_from_slice(&self.amount.to_be_bytes());
        out[16..48].copy_from_slice(&self.owner_key);
        out[48..80].copy_from_slice(&self.mint);
        out[80..].copy_from_slice(&self.nullifier_pk);
        out
    }

    /// Refuses a kind off the three, a set reserved byte and a dummy that carries a value.
    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            let kind = match bytes.byte()? {
                0 => RecordKind::Dummy,
                1 => RecordKind::Ring,
                2 => RecordKind::Exit,
                _ => return Err(CustomRingError::RingTransactLength),
            };
            let reserved: &[u8; RECORD_RESERVED_LEN] = bytes.array()?;
            if reserved.iter().any(|byte| *byte != 0) {
                return Err(CustomRingError::RingTransactLength);
            }
            let record = Self {
                kind,
                amount: read_amount(bytes)?,
                owner_key: *bytes.array()?,
                mint: *bytes.array()?,
                nullifier_pk: *bytes.array()?,
            };
            match kind == RecordKind::Dummy && record != Self::default() {
                true => Err(CustomRingError::RingTransactLength),
                false => Ok(record),
            }
        })
    }
}

/// A deposit or merge record, `secret` is the deposit's blinding or the merge's seed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpeningRecord {
    pub record: AuditRecord,
    pub secret: [u8; 32],
}

impl OpeningRecord {
    pub fn encode(&self) -> [u8; OPENING_RECORD_LEN] {
        let mut out = [0; OPENING_RECORD_LEN];
        out[..AUDIT_RECORD_LEN].copy_from_slice(&self.record.encode());
        out[AUDIT_RECORD_LEN..].copy_from_slice(&self.secret);
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            Ok(Self {
                record: AuditRecord::decode(bytes.take(AUDIT_RECORD_LEN)?)?,
                secret: *bytes.array()?,
            })
        })
    }
}

/// Zero fields while `has_data` is clear and on a dummy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataTail {
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
}

impl DataTail {
    pub fn encode(&self) -> [u8; DATA_TAIL_LEN] {
        let mut out = [0; DATA_TAIL_LEN];
        out[..FIELD_LEN].copy_from_slice(&self.data_hash);
        out[FIELD_LEN..].copy_from_slice(&self.ring_data_hash);
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            Ok(Self {
                data_hash: *bytes.array()?,
                ring_data_hash: *bytes.array()?,
            })
        })
    }
}

/// One default-ring input's opening, zero fields on any other slot, never a secret.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryInput {
    pub owner_key: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub amount: u64,
    pub mint: [u8; 32],
    pub blinding: [u8; 32],
    pub data_hash: [u8; 32],
    pub ring_data_hash: [u8; 32],
}

impl EntryInput {
    fn extend(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.owner_key);
        out.extend_from_slice(&self.nullifier_pk);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.mint);
        out.extend_from_slice(&self.blinding);
        out.extend_from_slice(&self.data_hash);
        out.extend_from_slice(&self.ring_data_hash);
    }

    fn read(bytes: &mut Bytes<'_>) -> Result<Self, CustomRingError> {
        Ok(Self {
            owner_key: *bytes.array()?,
            nullifier_pk: *bytes.array()?,
            amount: read_amount(bytes)?,
            mint: *bytes.array()?,
            blinding: *bytes.array()?,
            data_hash: *bytes.array()?,
            ring_data_hash: *bytes.array()?,
        })
    }
}

/// The envelope past its sealed key and count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvidence {
    /// A key with no entry capacity.
    None,
    Entry {
        /// Bit `i` set when input `i` is a live default-ring note.
        default_input_bits: u64,
        /// One per published input.
        inputs: Vec<EntryInput>,
    },
}

/// The envelope plaintext `tx_viewing_sk || R || default_input_bits || entries`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEnvelope {
    pub tx_viewing_secret: [u8; ENVELOPE_KEY_LEN],
    /// `R`, nullifiers at or past it are padding.
    pub real_inputs: u8,
    pub evidence: AuditEvidence,
}

impl AuditEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let evidence_len = match &self.evidence {
            AuditEvidence::None => 0,
            AuditEvidence::Entry { inputs, .. } => {
                DEFAULT_INPUT_BITS_LEN + ENTRY_INPUT_LEN * inputs.len()
            }
        };
        let mut out = Vec::with_capacity(ENVELOPE_KEY_LEN + REAL_INPUT_COUNT_LEN + evidence_len);
        out.extend_from_slice(&self.tx_viewing_secret);
        out.push(self.real_inputs);
        if let AuditEvidence::Entry {
            default_input_bits,
            inputs,
        } = &self.evidence
        {
            out.extend_from_slice(&default_input_bits.to_be_bytes());
            inputs.iter().for_each(|input| input.extend(&mut out));
        }
        out
    }

    /// Refuses any length other than `layout`'s.
    pub fn decode(plaintext: &[u8], layout: AuditStreamLayout) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            let tx_viewing_secret = *bytes.array()?;
            let real_inputs = bytes.byte()?;
            let evidence = match layout.key.entry {
                false => AuditEvidence::None,
                true => AuditEvidence::Entry {
                    default_input_bits: u64::from_be_bytes(*bytes.array()?),
                    inputs: (0..layout.inputs)
                        .map(|_| EntryInput::read(bytes))
                        .collect::<Result<_, CustomRingError>>()?,
                },
            };
            Ok(Self {
                tx_viewing_secret,
                real_inputs,
                evidence,
            })
        })
    }
}

/// The recipient's plaintext, outside the proof, one form on every rail.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecipientBody {
    pub blinding: [u8; 32],
    pub amount: u64,
    pub mint: [u8; 32],
    /// The commitment covers it, a nonzero value travels with the note.
    pub ring_data_hash: Option<[u8; 32]>,
    /// The application data under the note's `data_hash`.
    pub data: Vec<u8>,
}

impl RecipientBody {
    /// A plain note is exactly the head, an extended one follows it with one presence byte.
    pub fn encode(&self) -> Vec<u8> {
        let extended = self.ring_data_hash.is_some() || !self.data.is_empty();
        let mut out = Vec::with_capacity(RECIPIENT_BODY_LEN + 1 + FIELD_LEN + self.data.len());
        out.extend_from_slice(&self.blinding);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.mint);
        if extended {
            out.push(u8::from(self.ring_data_hash.is_some()));
            if let Some(ring_data_hash) = &self.ring_data_hash {
                out.extend_from_slice(ring_data_hash);
            }
            out.extend_from_slice(&self.data);
        }
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        let mut bytes = Bytes::new(plaintext, CustomRingError::RingTransactLength);
        let mut body = Self {
            blinding: *bytes.array()?,
            amount: read_amount(&mut bytes)?,
            mint: *bytes.array()?,
            ..Self::default()
        };
        if plaintext.len() == RECIPIENT_BODY_LEN {
            return Ok(body);
        }
        body.ring_data_hash = match bytes.byte()? {
            0 => None,
            1 => Some(*bytes.array()?),
            _ => return Err(CustomRingError::RingTransactLength),
        };
        body.data = bytes.rest().to_vec();
        Ok(body)
    }
}

/// The cells the sender rebuilds change and recipients from, outside the proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SenderBundle {
    /// Slot 0's mint when slot 0 is change, else zero.
    pub mint: [u8; 32],
    /// Slot 0's amount when slot 0 is change, else zero.
    pub amount: u64,
    /// Slot 1's amount in SOL when slot 1 is change, else zero.
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
