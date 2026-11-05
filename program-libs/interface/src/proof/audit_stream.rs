//! Mirror of `prover/circuits/audit`.
//!
//! SPP publishes these bytes and opens none of them. The proof holds the auditor's stream to each
//! slot's note, so every length and counter here must match the circuit, a record read at another
//! counter decrypts to noise. A key fixes the counters by its capacity, and a frame transmits its
//! published slots alone.
//!
//! Read after `program-libs/interface/src/proof/domain.rs`. Read before `program-libs/interface/src/proof/disclosure.rs`,
//! `prover/circuits/audit/audit.go`.

use crate::{bytes::Bytes, error::CustomRingError, TAGGED_X25519_KEY_LEN};

pub const STREAM_BLOCK_LEN: usize = 16;
pub const STREAM_FIRST_COUNTER: u32 = 2;
/// The sealed `tx_viewing_sk`, the envelope's first bytes.
pub const ENVELOPE_KEY_LEN: usize = 32;
/// `R`, spent notes among the published inputs, dummies last.
pub const REAL_INPUT_COUNT_LEN: usize = 1;
pub const ADDRESS_INPUT_BITS_LEN: usize = 8;
pub const ENVELOPE_HEAD_LEN: usize =
    ENVELOPE_KEY_LEN + REAL_INPUT_COUNT_LEN + ADDRESS_INPUT_BITS_LEN;
/// Keys with entry capacity alone, bit `i` set when input `i` is a default-ring note.
pub const DEFAULT_INPUT_BITS_LEN: usize = 8;
pub const AUDIT_RECORD_LEN: usize = 105;
pub const DATA_TAIL_LEN: usize = 64;
pub const ENTRY_INPUT_LEN: usize = 200;
/// The secret is the deposit's blinding or the merge's seed.
pub const OPENING_RECORD_LEN: usize = RECORD_STRIDE + FIELD_LEN;
pub const RECIPIENT_BODY_LEN: usize = 72;
/// `mint0 || u64be(amount0) || u64be(amount1) || output_seed`.
pub const SENDER_BUNDLE_HEAD_LEN: usize = 80;
/// `viewing_u || owner_key || nullifier_pk`, one byte for the wincode of no data.
pub const MIN_REPLY_LEN: usize = 97;
pub const RECORD_BLOCKS: usize = AUDIT_RECORD_LEN.div_ceil(STREAM_BLOCK_LEN);
/// The padding past a record keeps slot `i` at its counter, a transfer frame omits it.
pub const RECORD_STRIDE: usize = RECORD_BLOCKS * STREAM_BLOCK_LEN;
pub const TAIL_BLOCKS: usize = DATA_TAIL_LEN / STREAM_BLOCK_LEN;
const FIELD_LEN: usize = 32;
const AMOUNT_LEN: usize = 8;

const _: () = assert!(1 + AMOUNT_LEN + 3 * FIELD_LEN == AUDIT_RECORD_LEN);
const _: () = assert!(OPENING_RECORD_LEN.is_multiple_of(STREAM_BLOCK_LEN));
const _: () = assert!(DATA_TAIL_LEN.is_multiple_of(STREAM_BLOCK_LEN));
const _: () = assert!(AMOUNT_LEN + 6 * FIELD_LEN == ENTRY_INPUT_LEN);
const _: () = assert!(AMOUNT_LEN + 2 * FIELD_LEN == RECIPIENT_BODY_LEN);
const _: () = assert!(2 * AMOUNT_LEN + 2 * FIELD_LEN == SENDER_BUNDLE_HEAD_LEN);
const _: () = assert!(3 * FIELD_LEN + 1 == MIN_REPLY_LEN);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditKey {
    /// The widest published input count.
    pub class: usize,
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
        ENVELOPE_HEAD_LEN
            + if self.entry {
                DEFAULT_INPUT_BITS_LEN
            } else {
                0
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
    pub has_data: bool,
}

impl AuditStreamLayout {
    pub fn checked(self) -> Result<Self, CustomRingError> {
        let outputs_fit = self.outputs >= 1 && self.outputs <= self.capacity;
        match self.inputs >= 1
            && self.inputs <= self.key.class()
            && self.key.class() <= u64::BITS as usize
            && outputs_fit
        {
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

    pub const fn record(self, slot: usize) -> StreamRegion {
        StreamRegion {
            start_counter: self.first_record_counter() + (slot * RECORD_BLOCKS) as u32,
            max_blocks: RECORD_BLOCKS,
            len: self.record_len(slot),
        }
    }

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
        out[1..9].copy_from_slice(&self.amount.to_be_bytes());
        out[9..41].copy_from_slice(&self.owner_key);
        out[41..73].copy_from_slice(&self.mint);
        out[73..].copy_from_slice(&self.nullifier_pk);
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            let kind = match bytes.byte()? {
                0 => RecordKind::Dummy,
                1 => RecordKind::Ring,
                2 => RecordKind::Exit,
                _ => return Err(CustomRingError::RingTransactLength),
            };
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpeningRecord {
    pub record: AuditRecord,
    pub secret: [u8; 32],
}

impl OpeningRecord {
    pub fn encode(&self) -> [u8; OPENING_RECORD_LEN] {
        let mut out = [0; OPENING_RECORD_LEN];
        out[..AUDIT_RECORD_LEN].copy_from_slice(&self.record.encode());
        out[RECORD_STRIDE..].copy_from_slice(&self.secret);
        out
    }

    pub fn decode(plaintext: &[u8]) -> Result<Self, CustomRingError> {
        read_all(plaintext, |bytes| {
            let record = AuditRecord::decode(bytes.take(AUDIT_RECORD_LEN)?)?;
            let padding = bytes.take(RECORD_STRIDE - AUDIT_RECORD_LEN)?;
            if padding.iter().any(|byte| *byte != 0) {
                return Err(CustomRingError::RingTransactLength);
            }
            Ok(Self {
                record,
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

/// One default-ring input's opening, zero fields on any other slot, never its nullifier secret.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputClass {
    Note,
    Address,
    Dummy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputClassification {
    pub published_inputs: usize,
    pub capacity: usize,
    pub note_count: u8,
    pub address_input_bits: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputMap {
    classification: InputClassification,
    non_dummy_count: usize,
}

impl InputClassification {
    pub fn check(self) -> Result<InputMap, CustomRingError> {
        let non_dummy_count =
            usize::from(self.note_count) + self.address_input_bits.count_ones() as usize;
        if self.published_inputs == 0
            || self.published_inputs > self.capacity
            || self.capacity > u64::BITS as usize
            || non_dummy_count > self.published_inputs
            || self
                .address_input_bits
                .checked_shr(non_dummy_count as u32)
                .unwrap_or(0)
                != 0
        {
            return Err(CustomRingError::RingTransactLength);
        }
        Ok(InputMap {
            classification: self,
            non_dummy_count,
        })
    }
}

impl InputMap {
    pub fn from_classes(
        classes: &[InputClass],
        published_inputs: usize,
    ) -> Result<Self, CustomRingError> {
        if classes.len() > u64::BITS as usize {
            return Err(CustomRingError::RingTransactLength);
        }
        let mut note_count = 0;
        let mut address_input_bits = 0;
        let mut padding = false;
        for (slot, class) in classes.iter().enumerate() {
            if (padding || slot >= published_inputs) && *class != InputClass::Dummy {
                return Err(CustomRingError::RingTransactLength);
            }
            match class {
                InputClass::Note => note_count += 1,
                InputClass::Address => address_input_bits |= 1 << slot,
                InputClass::Dummy => padding = true,
            }
        }
        InputClassification {
            published_inputs,
            capacity: classes.len(),
            note_count,
            address_input_bits,
        }
        .check()
    }

    pub const fn note_count(self) -> u8 {
        self.classification.note_count
    }

    pub const fn address_input_bits(self) -> u64 {
        self.classification.address_input_bits
    }

    pub const fn published_inputs(self) -> usize {
        self.classification.published_inputs
    }

    pub const fn capacity(self) -> usize {
        self.classification.capacity
    }

    pub const fn non_dummy_count(self) -> usize {
        self.non_dummy_count
    }

    pub const fn slot(self, slot: usize) -> Option<InputClass> {
        if slot >= self.capacity() {
            None
        } else {
            Some(self.class_at(slot))
        }
    }

    pub fn classes(self) -> impl ExactSizeIterator<Item = InputClass> {
        (0..self.capacity()).map(move |slot| self.class_at(slot))
    }

    pub fn validate_default_input_bits(self, bits: u64) -> Result<(), CustomRingError> {
        if bits & self.address_input_bits() != 0
            || bits.checked_shr(self.non_dummy_count as u32).unwrap_or(0) != 0
        {
            return Err(CustomRingError::RingTransactLength);
        }
        Ok(())
    }

    const fn class_at(self, slot: usize) -> InputClass {
        if slot >= self.non_dummy_count {
            InputClass::Dummy
        } else if self.address_input_bits() & (1 << slot) != 0 {
            InputClass::Address
        } else {
            InputClass::Note
        }
    }
}

/// The envelope past its sealed key and count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvidence {
    None,
    Entry {
        default_input_bits: u64,
        /// One per published input.
        inputs: Vec<EntryInput>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEnvelope {
    pub tx_viewing_secret: [u8; ENVELOPE_KEY_LEN],
    pub real_inputs: u8,
    pub address_input_bits: u64,
    pub evidence: AuditEvidence,
}

impl AuditEnvelope {
    pub fn input_map(&self, layout: AuditStreamLayout) -> Result<InputMap, CustomRingError> {
        InputClassification {
            published_inputs: layout.inputs,
            capacity: layout.key.class(),
            note_count: self.real_inputs,
            address_input_bits: self.address_input_bits,
        }
        .check()
    }

    pub fn encode(&self) -> Vec<u8> {
        let evidence_len = match &self.evidence {
            AuditEvidence::None => 0,
            AuditEvidence::Entry { inputs, .. } => {
                DEFAULT_INPUT_BITS_LEN + ENTRY_INPUT_LEN * inputs.len()
            }
        };
        let mut out = Vec::with_capacity(ENVELOPE_HEAD_LEN + evidence_len);
        out.extend_from_slice(&self.tx_viewing_secret);
        out.push(self.real_inputs);
        out.extend_from_slice(&self.address_input_bits.to_be_bytes());
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
        layout.checked()?;
        read_all(plaintext, |bytes| {
            let tx_viewing_secret = *bytes.array()?;
            let real_inputs = bytes.byte()?;
            let address_input_bits = u64::from_be_bytes(*bytes.array()?);
            let evidence = match layout.key.entry {
                false => AuditEvidence::None,
                true => AuditEvidence::Entry {
                    default_input_bits: u64::from_be_bytes(*bytes.array()?),
                    inputs: (0..layout.inputs)
                        .map(|_| EntryInput::read(bytes))
                        .collect::<Result<_, CustomRingError>>()?,
                },
            };
            let envelope = Self {
                tx_viewing_secret,
                real_inputs,
                address_input_bits,
                evidence,
            };
            let inputs = envelope.input_map(layout)?;
            if let AuditEvidence::Entry {
                default_input_bits,
                inputs: openings,
            } = &envelope.evidence
            {
                inputs.validate_default_input_bits(*default_input_bits)?;
                for (slot, opening) in openings.iter().enumerate() {
                    if default_input_bits & (1 << slot) == 0 && *opening != EntryInput::default() {
                        return Err(CustomRingError::RingTransactLength);
                    }
                }
            }
            Ok(envelope)
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
    pub data: Vec<u8>,
}

impl RecipientBody {
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
    /// Slot 1's lamports when slot 1 is change, else zero.
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
