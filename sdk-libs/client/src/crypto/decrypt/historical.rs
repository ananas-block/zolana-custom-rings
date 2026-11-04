//! The auditor's read of a statement version 3 frame, tags 45 and 46, its frozen layout kept here alone.

use custom_ring_interface::{
    domain::AUDIT_STREAM_LABEL, ring_confidential_delivered_output_body, stream::DeliveredSlot,
    InstructionTag, RingMode, RingRail, STREAM_BLOCK_LEN, STREAM_FIRST_COUNTER,
    TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG,
};
use solana_address::Address;
use spr_event::confidential_encrypted_output_body;
use spr_interface::{shape::SPP_SUPPORTED_SHAPES, ZERO_NULLIFIER_PUBKEY};
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use spr_transaction::ShieldedTransaction;
use zeroize::Zeroizing;
use zolana_ring_transaction::{open_delivered_body, RingAssets};

use super::{auditor_message, Slot, SlotOpening, Transfer};
use crate::{
    disclosure::canonical,
    encryption::opening_ring_stream,
    types::{
        AuditedDefaultInput, AuditedInput, AuditedTransaction, AuditedUtxo, InputOpening,
        OutputOpening, OutputPayloadErrorKind, RingOwnerTag,
    },
    AuditError,
};

const ENVELOPE_KEY_LEN: usize = 32;
const INPUT_HASH_LEN: usize = 32;
const ENTRY_HEAD_LEN: usize = 64;
const ENTRY_INPUT_LEN: usize = 104;
const ANONYMOUS_RECORD_LEN: usize = 104;
const EXIT_RECORD_LEN: usize = 72;
const ESCROWED_EXIT_RECORD_LEN: usize = 40;
const DELIVERED_BODY_LEN: usize = 104;
const ESCROWED_DELIVERED_BODY_LEN: usize = 72;
/// `(outputs, widest inputs)` of every version 3 key, frozen with its verifying keys.
const CONFIDENTIAL_CLASSES: [(usize, usize); 4] = [(2, 24), (4, 24), (8, 16), (16, 5)];
const COMMITMENT_CLASSES: [(usize, usize); 3] = [(2, 24), (4, 16), (8, 5)];
const ENTRY_CLASSES: [(usize, usize); 3] = [(2, 8), (4, 8), (8, 2)];

/// `tag || flags || shape || inputs || outputs`.
const SHAPE_AT: usize = 2;
const INPUTS_AT: usize = 3;
const OUTPUTS_AT: usize = 4;
/// The shape index or the input count, the bits above carry flags.
const LOW_BITS: u8 = 0b0011_1111;
const SHAPE_RESERVED: u8 = 1 << 7;
const KEY_ESCROW: u8 = 1 << 6;
const FULL_OPENINGS: u8 = 1 << 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum V3Key {
    Confidential { class: usize },
    Commitment { class: usize },
    Entry { class: usize },
}

impl V3Key {
    const fn class(self) -> usize {
        match self {
            Self::Confidential { class } | Self::Commitment { class } | Self::Entry { class } => {
                class
            }
        }
    }

    const fn is_anonymous(self) -> bool {
        !matches!(self, Self::Confidential { .. })
    }

    const fn record_blocks(self) -> usize {
        match self.is_anonymous() {
            true => ANONYMOUS_RECORD_LEN.div_ceil(STREAM_BLOCK_LEN),
            false => EXIT_RECORD_LEN.div_ceil(STREAM_BLOCK_LEN),
        }
    }

    const fn evidence_len(self, inputs: usize) -> usize {
        match self {
            Self::Confidential { .. } | Self::Commitment { .. } => INPUT_HASH_LEN * inputs,
            Self::Entry { .. } => ENTRY_HEAD_LEN + ENTRY_INPUT_LEN * inputs,
        }
    }

    /// Records start past the evidence of the key's widest input count.
    const fn first_record_counter(self) -> u32 {
        let envelope = (ENVELOPE_KEY_LEN + self.evidence_len(self.class())).div_ceil(STREAM_BLOCK_LEN);
        STREAM_FIRST_COUNTER + envelope as u32
    }
}

/// What a tag 45 or 46 frame's head fixes of its auditor message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoricalLayout {
    key: V3Key,
    pub(super) key_escrow: bool,
    pub(super) inputs: usize,
    pub(super) outputs: usize,
}

impl HistoricalLayout {
    /// `frame` is `tag || data`, a shape off every version 3 key is refused.
    pub fn parse(frame: &[u8], mode: RingMode) -> Result<Self, AuditError> {
        let invalid = || AuditError::DisclosureLayout;
        let tag = InstructionTag::try_from(*frame.first().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let rail = RingRail::of(tag, mode).map_err(|_| invalid())?;
        let byte = |at: usize| frame.get(at).copied().ok_or_else(invalid);
        let shape_byte = byte(SHAPE_AT)?;
        if shape_byte & SHAPE_RESERVED != 0 {
            return Err(invalid());
        }
        let shape = SPP_SUPPORTED_SHAPES
            .get(usize::from(shape_byte & LOW_BITS))
            .ok_or_else(invalid)?;
        let input_byte = byte(INPUTS_AT)?;
        let inputs = usize::from(input_byte & LOW_BITS);
        let outputs = usize::from(byte(OUTPUTS_AT)?);
        let capacity = shape.n_outputs();
        let full_openings = input_byte & FULL_OPENINGS != 0;
        let classes: &[(usize, usize)] = match (rail, full_openings) {
            (RingRail::Anonymous, true) => &ENTRY_CLASSES,
            (RingRail::Anonymous, false) => &COMMITMENT_CLASSES,
            (_, true) => return Err(invalid()),
            (_, false) => &CONFIDENTIAL_CLASSES,
        };
        let class = classes
            .iter()
            .find(|(keyed, _)| *keyed == capacity)
            .map(|(_, class)| *class)
            .ok_or_else(invalid)?;
        if inputs == 0 || inputs > class.min(shape.n_inputs()) || outputs == 0 || outputs > capacity
        {
            return Err(invalid());
        }
        let key = match (rail, full_openings) {
            (RingRail::Anonymous, true) => V3Key::Entry { class },
            (RingRail::Anonymous, false) => V3Key::Commitment { class },
            _ => V3Key::Confidential { class },
        };
        Ok(Self {
            key,
            key_escrow: input_byte & KEY_ESCROW != 0,
            inputs,
            outputs,
        })
    }

    const fn exit_len(self) -> usize {
        match self.key_escrow {
            true => ESCROWED_EXIT_RECORD_LEN,
            false => EXIT_RECORD_LEN,
        }
    }

    const fn delivered_len(self) -> usize {
        match self.key_escrow {
            true => ESCROWED_DELIVERED_BODY_LEN,
            false => DELIVERED_BODY_LEN,
        }
    }

    /// A delivered slot transmits no record.
    const fn record_len(self, exit: bool) -> usize {
        match (exit, self.key.is_anonymous()) {
            (true, _) => self.exit_len(),
            (false, true) => ANONYMOUS_RECORD_LEN,
            (false, false) => 0,
        }
    }
}

enum Evidence {
    Hashes(Vec<[u8; 32]>),
    /// Every input of one sender, a zero entry a dummy.
    Entry {
        sender_key: [u8; 32],
        sender_nullifier_pk: [u8; 32],
        inputs: Vec<EntryOpening>,
    },
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct EntryOpening {
    hash: [u8; 32],
    amount: u64,
    asset: [u8; 32],
    blinding: [u8; 32],
}

/// A reader over bytes whose length the layout fixed.
struct Read<'a>(&'a [u8]);

impl Read<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], AuditError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(AuditError::DisclosureLayout)?;
        self.0 = rest;
        Ok(*head)
    }

    fn field(&mut self) -> Result<[u8; 32], AuditError> {
        canonical(self.take()?)
    }

    fn amount(&mut self) -> Result<u64, AuditError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn finish(&self) -> Result<(), AuditError> {
        match self.0.is_empty() {
            true => Ok(()),
            false => Err(AuditError::DisclosureLayout),
        }
    }
}

impl Evidence {
    fn decode(plaintext: &[u8], layout: HistoricalLayout) -> Result<Self, AuditError> {
        let mut read = Read(plaintext);
        let evidence = match layout.key {
            V3Key::Confidential { .. } | V3Key::Commitment { .. } => Self::Hashes(
                (0..layout.inputs)
                    .map(|_| read.field())
                    .collect::<Result<_, _>>()?,
            ),
            V3Key::Entry { .. } => Self::Entry {
                sender_key: read.take()?,
                sender_nullifier_pk: read.field()?,
                inputs: (0..layout.inputs)
                    .map(|_| {
                        Ok(EntryOpening {
                            hash: read.field()?,
                            amount: read.amount()?,
                            asset: read.field()?,
                            blinding: read.field()?,
                        })
                    })
                    .collect::<Result<_, AuditError>>()?,
            },
        };
        read.finish()?;
        Ok(evidence)
    }
}

/// One slot's decrypted record, the key off it under key escrow.
struct RecordRead {
    owner_key: [u8; 32],
    asset: [u8; 32],
    amount: u64,
    nullifier_pk: Option<[u8; 32]>,
}

impl RecordRead {
    fn anonymous(plaintext: &[u8]) -> Result<Self, AuditError> {
        let mut read = Read(plaintext);
        let record = Self {
            owner_key: read.take()?,
            asset: read.take()?,
            amount: read.amount()?,
            nullifier_pk: Some(read.take()?),
        };
        read.finish()?;
        Ok(record)
    }

    fn exit(plaintext: &[u8], owner_key: [u8; 32], key_escrow: bool) -> Result<Self, AuditError> {
        let mut read = Read(plaintext);
        let record = Self {
            owner_key,
            asset: read.take()?,
            amount: read.amount()?,
            nullifier_pk: (!key_escrow).then(|| read.take()).transpose()?,
        };
        read.finish()?;
        Ok(record)
    }

    fn is_zero(&self) -> bool {
        self.owner_key == [0; 32]
            && self.asset == [0; 32]
            && self.amount == 0
            && self.nullifier_pk == Some([0; 32])
    }
}

/// The fields a version 3 slot opens, the key candidates its layout leaves.
struct V3Note {
    owner_key: [u8; 32],
    amount: u64,
    blinding: [u8; 32],
    disclosed: Option<[u8; 32]>,
}

impl V3Note {
    /// The disclosed key, or under key escrow the one key the reader knows with no registry.
    fn candidate(&self) -> [u8; 32] {
        self.disclosed.unwrap_or(ZERO_NULLIFIER_PUBKEY)
    }

    fn utxo(&self, asset: [u8; 32], mint: Option<Address>) -> AuditedUtxo {
        AuditedUtxo {
            owner_key: self.owner_key,
            nullifier_pk: self.candidate(),
            asset,
            mint,
            amount: self.amount,
            blinding: self.blinding,
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
        }
    }

    /// Off the rebuilt commitment an escrowed key stays unnamed, no registry resolves it here.
    fn missed(&self, without_key: OutputPayloadErrorKind) -> OutputPayloadErrorKind {
        match self.disclosed {
            Some(_) => without_key,
            None => OutputPayloadErrorKind::EscrowPending,
        }
    }
}

/// Opens outputs and inputs from one frame and its row, old hash evidence reads as spent notes.
pub(super) fn audit(
    tx: &ShieldedTransaction,
    layout: HistoricalLayout,
    input_trees: Option<&[Option<u16>]>,
    auditor: &X25519Keypair,
    assets: &RingAssets,
) -> Result<AuditedTransaction, AuditError> {
    if layout.outputs != tx.output_slots.len() || layout.inputs != tx.nullifiers.len() {
        return Err(AuditError::DisclosureLayout);
    }
    let tx_viewing_pk = tx.tx_viewing_pk.ok_or(AuditError::MissingTxViewingPk)?;
    let salt = tx.salt.ok_or(AuditError::MissingSalt)?;
    let ring = tx.ring_program_id.ok_or(AuditError::MissingRingProgram)?;
    let first_nullifier = *tx.nullifiers.first().ok_or(AuditError::MissingNullifier)?;
    let data = auditor_message(tx, &auditor.pubkey())?;
    let wrong_length = || AuditError::AuditorMessageLength(data.len());
    let (eph_pk, rest) = data
        .split_first_chunk::<TAGGED_X25519_KEY_LEN>()
        .filter(|(key, _)| key[0] == VIEWING_PUBKEY_TAG)
        .ok_or_else(wrong_length)?;
    let envelope_len = ENVELOPE_KEY_LEN + layout.key.evidence_len(layout.inputs);
    let (envelope, mut records) = rest.split_at_checked(envelope_len).ok_or_else(wrong_length)?;
    let stream = opening_ring_stream(auditor, &X25519Pubkey::from_bytes(*eph_pk)?, AUDIT_STREAM_LABEL)?;
    let mut plaintext = Zeroizing::new(envelope.to_vec());
    stream.apply_at(STREAM_FIRST_COUNTER, &mut plaintext);
    let (secret, evidence) = plaintext
        .split_first_chunk::<ENVELOPE_KEY_LEN>()
        .ok_or_else(wrong_length)?;
    let tx_key = ViewingKey::from_canonical_bytes(secret)
        .map_err(|_| AuditError::NonCanonicalViewingKey)?;
    let evidence = Evidence::decode(evidence, layout)?;
    if tx_key.pubkey() != tx_viewing_pk {
        return Err(AuditError::TxViewingKeyMismatch);
    }
    let transfer = Transfer::new(ring, first_nullifier, &tx_key, &salt)?;
    let reader = V3Slots {
        transfer: &transfer,
        layout,
        tx_key: &tx_key,
        tx_viewing_pk: &tx_viewing_pk,
        salt: &salt,
        assets,
    };
    let mut audited = AuditedTransaction {
        tx_signature: tx.tx_signature,
        slot: tx.slot,
        tx_viewing_pk,
        real_inputs: 0,
        outputs: Vec::new(),
        payload_errors: Vec::new(),
        inputs: Vec::new(),
    };
    for (index, output) in (0u32..).zip(&tx.output_slots) {
        let slot = Slot { index, output };
        let exit = confidential_encrypted_output_body(&output.payload).is_some();
        let (ciphertext, rest) = records
            .split_at_checked(layout.record_len(exit))
            .ok_or_else(wrong_length)?;
        records = rest;
        let mut record = Zeroizing::new(ciphertext.to_vec());
        stream.apply_at(
            layout.key.first_record_counter() + index * layout.key.record_blocks() as u32,
            &mut record,
        );
        let opened = match (exit, layout.key.is_anonymous()) {
            (true, _) => reader.exit(slot, &record)?,
            (false, true) => reader.anonymous(slot, &record)?,
            (false, false) => reader.delivered(slot)?,
        };
        audited.place(index, output.output_context.clone(), opened);
    }
    if !records.is_empty() {
        return Err(wrong_length());
    }
    audited.inputs = reader.inputs(&evidence, &tx.nullifiers, input_trees)?;
    audited.real_inputs = u8::try_from(
        audited
            .inputs
            .iter()
            .filter(|input| input.opening.is_real())
            .count(),
    )
    .map_err(|_| AuditError::DisclosureLayout)?;
    Ok(audited)
}

struct V3Slots<'a> {
    transfer: &'a Transfer,
    layout: HistoricalLayout,
    tx_key: &'a ViewingKey,
    tx_viewing_pk: &'a X25519Pubkey,
    salt: &'a [u8; 16],
    assets: &'a RingAssets,
}

impl V3Slots<'_> {
    fn mint(&self, asset: &[u8; 32]) -> Option<Address> {
        self.assets.by_field(asset).map(|mint| mint.asset)
    }

    /// The zero record of a hidden dummy and a record outside the field open nothing.
    fn anonymous(&self, slot: Slot<'_>, plaintext: &[u8]) -> Result<SlotOpening, AuditError> {
        let record = RecordRead::anonymous(plaintext)?;
        if record.is_zero() {
            return self.transfer.verify_dummy(slot);
        }
        if canonical(record.asset).is_err() {
            return Ok(Err(OutputPayloadErrorKind::Disclosure));
        }
        let note = V3Note {
            owner_key: record.owner_key,
            amount: record.amount,
            blinding: self.transfer.blinding(slot)?,
            disclosed: record.nullifier_pk,
        };
        let utxo = note.utxo(record.asset, self.mint(&record.asset));
        let commitment = utxo.commitment(slot.tree_id(), Some(self.transfer.ring))?;
        Ok(slot.rebuilt(
            commitment,
            OutputOpening::Ring {
                utxo,
                owner_tag: RingOwnerTag(slot.owner_tag()),
            },
        ))
    }

    fn exit(&self, slot: Slot<'_>, plaintext: &[u8]) -> Result<SlotOpening, AuditError> {
        let record = RecordRead::exit(plaintext, slot.owner_tag(), self.layout.key_escrow)?;
        if canonical(record.asset).is_err() {
            return Ok(Err(OutputPayloadErrorKind::Disclosure));
        }
        let note = V3Note {
            owner_key: record.owner_key,
            amount: record.amount,
            blinding: self.transfer.blinding(slot)?,
            disclosed: record.nullifier_pk,
        };
        let utxo = note.utxo(record.asset, self.mint(&record.asset));
        let commitment = utxo.commitment(slot.tree_id(), None)?;
        Ok(match commitment == slot.output.output_context.hash {
            true => Ok(OutputOpening::Exit(utxo)),
            false => Err(note.missed(OutputPayloadErrorKind::Commitment)),
        })
    }

    /// A dummy publishes a random body, its commitment alone tells it from a ring output.
    fn delivered(&self, slot: Slot<'_>) -> Result<SlotOpening, AuditError> {
        let dummy = self.transfer.verify_dummy(slot)?;
        if dummy.is_ok() {
            return Ok(dummy);
        }
        let Some(ciphertext) = ring_confidential_delivered_output_body(&slot.output.payload)
            .filter(|body| body.len() == self.layout.delivered_len())
        else {
            return Ok(Err(OutputPayloadErrorKind::Frame));
        };
        let recipient_u = slot.owner_tag();
        let agreement = X25519Pubkey::from_u(recipient_u).ok().and_then(|recipient| {
            let agreement = Zeroizing::new(self.tx_key.ecdh(&recipient).ok()?);
            Some((recipient, agreement))
        });
        let Some((recipient, agreement)) = agreement else {
            return Ok(Err(OutputPayloadErrorKind::RecipientKey));
        };
        let secret = DeliveredSlot {
            agreement: &agreement,
            tx_viewing_pk: self.tx_viewing_pk.as_bytes(),
            recipient_viewing_pk: recipient.as_bytes(),
            salt: self.salt,
            output_index: slot.index,
            first_nullifier: &self.transfer.first_nullifier,
        }
        .secret()?;
        let body = open_delivered_body(ciphertext, &secret)?;
        let blinding = self.transfer.blinding(slot)?;
        if body.blinding != blinding {
            return Ok(Err(OutputPayloadErrorKind::Commitment));
        }
        let note = V3Note {
            owner_key: body.owner_key,
            amount: body.amount,
            blinding,
            disclosed: body.nullifier_pk,
        };
        // A delivered body names no asset, only a held one rebuilds it.
        for (asset, mint) in self.assets.fields() {
            let utxo = note.utxo(*asset, Some(mint.asset));
            if utxo.commitment(slot.tree_id(), Some(self.transfer.ring))?
                == slot.output.output_context.hash
            {
                return Ok(Ok(OutputOpening::Ring {
                    utxo,
                    owner_tag: RingOwnerTag(recipient_u),
                }));
            }
        }
        Ok(Err(note.missed(OutputPayloadErrorKind::UnknownAsset)))
    }

    fn inputs(
        &self,
        evidence: &Evidence,
        nullifiers: &[[u8; 32]],
        trees: Option<&[Option<u16>]>,
    ) -> Result<Vec<AuditedInput>, AuditError> {
        match evidence {
            Evidence::Hashes(hashes) => Ok(nullifiers
                .iter()
                .zip(hashes)
                .map(|(nullifier, hash)| AuditedInput {
                    nullifier: *nullifier,
                    opening: match *hash == [0; 32] {
                        true => InputOpening::Dummy,
                        false => InputOpening::Real,
                    },
                })
                .collect()),
            Evidence::Entry {
                sender_key,
                sender_nullifier_pk,
                inputs,
            } => (0..)
                .zip(nullifiers.iter().zip(inputs))
                .map(|(index, (nullifier, opening))| {
                    let tree = trees.and_then(|trees: &[Option<u16>]| {
                        trees.get(index as usize).copied().flatten()
                    });
                    Ok(AuditedInput {
                        nullifier: *nullifier,
                        opening: self.entry(opening, sender_key, sender_nullifier_pk, tree)?,
                    })
                })
                .collect(),
        }
    }

    /// The hash names the note, only a default-ring match is a note the auditor holds no ring record of.
    fn entry(
        &self,
        opening: &EntryOpening,
        sender_key: &[u8; 32],
        sender_nullifier_pk: &[u8; 32],
        tree: Option<u16>,
    ) -> Result<InputOpening, AuditError> {
        if *opening == EntryOpening::default() {
            return Ok(InputOpening::Dummy);
        }
        let utxo = AuditedUtxo {
            owner_key: *sender_key,
            nullifier_pk: *sender_nullifier_pk,
            asset: opening.asset,
            mint: self.mint(&opening.asset),
            amount: opening.amount,
            blinding: opening.blinding,
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
        };
        let commitment = tree.map(|tree| utxo.commitment(tree, None)).transpose()?;
        Ok(match commitment == Some(opening.hash) {
            true => InputOpening::External(AuditedDefaultInput { utxo, commitment }),
            false => InputOpening::Real,
        })
    }
}
