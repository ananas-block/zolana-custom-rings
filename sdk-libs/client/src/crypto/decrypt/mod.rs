//! Opens a ring transfer for its auditor from its stream, its bodies and the blindings its key derives.

use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
};

use custom_ring_interface::{
    blinding::ring_blinding_seed,
    ring_confidential_delivered_output_body,
    stream::{DeliveredSlot, SlotSecret},
    AnonymousRecord, AuditEvidence, AuditStreamLayout, AuditorMessage, EntryInput, ExitRecord,
    InputPrefix,
};
use solana_address::Address;
use spr_client::ProofInputUtxo;
use spr_event::confidential_encrypted_output_body;
use spr_hasher::primitives::right_align;
use spr_interface::tree_slot::tree_id_field;
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use spr_transaction::{
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, DUMMY_DOMAIN},
    OutputContext, OutputSlot, ShieldedTransaction,
};
use zeroize::Zeroizing;
use zolana_ring_transaction::{open_delivered_body, RingAssets};

use crate::{
    disclosure::{canonical, AuditEnvelope, OutputRecord},
    encryption::auditor_view_tag,
    known::KnownUtxoIndex,
    types::{
        AuditedInput, AuditedInputOpening, AuditedOutput, AuditedSender, AuditedTransaction,
        AuditedUtxo, EscrowPendingOutput, EscrowPendingSlot, InputOpening, InputRing, KnownUtxo,
        OutputOpening, OutputPayloadError, OutputPayloadErrorKind, OutputResolution, RingOwnerTag,
        UnresolvedOutput,
    },
    AuditError,
};

/// Takes the transaction as given, [`crate::RingScan::audit`] binds it to its confirmed event.
#[must_use = "run the audit explicitly"]
pub struct TransactionAudit<'a> {
    transaction: &'a ShieldedTransaction,
    layout: AuditStreamLayout,
    input_trees: Option<&'a [Option<u16>]>,
    known_utxos: Option<&'a dyn KnownUtxos>,
    escrowed_keys: Option<&'a dyn EscrowedKeys>,
}

pub trait KnownUtxos {
    fn utxo(&self, commitment: &[u8; 32]) -> Option<KnownUtxo>;
    /// The commitments of the notes of `owner_key` that carry `prefix`.
    fn with_prefix(&self, owner_key: &[u8; 32], prefix: InputPrefix) -> Vec<[u8; 32]>;
    /// The commitments of every note that carries `prefix`.
    fn with_prefix_of_anyone(&self, prefix: InputPrefix) -> Vec<[u8; 32]>;
}

impl<T: Borrow<KnownUtxo>> KnownUtxos for KnownUtxoIndex<T> {
    fn utxo(&self, commitment: &[u8; 32]) -> Option<KnownUtxo> {
        self.get(commitment).map(|record| *record.borrow())
    }

    fn with_prefix(&self, owner_key: &[u8; 32], prefix: InputPrefix) -> Vec<[u8; 32]> {
        self.prefixed(owner_key, prefix).to_vec()
    }

    fn with_prefix_of_anyone(&self, prefix: InputPrefix) -> Vec<[u8; 32]> {
        self.prefixed_by_anyone(prefix).to_vec()
    }
}

/// The nullifier key each registered owner escrows, keyed by its raw Solana key.
pub trait EscrowedKeys {
    fn nullifier_pk(&self, owner_key: &[u8; 32]) -> Option<[u8; 32]>;
}

impl EscrowedKeys for HashMap<[u8; 32], [u8; 32]> {
    fn nullifier_pk(&self, owner_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.get(owner_key).copied()
    }
}

struct NoEscrow;

impl EscrowedKeys for NoEscrow {
    fn nullifier_pk(&self, _owner_key: &[u8; 32]) -> Option<[u8; 32]> {
        None
    }
}

impl<'a> TransactionAudit<'a> {
    /// `layout` comes from [`crate::RingOrigin::audit_stream`].
    pub fn new(transaction: &'a ShieldedTransaction, layout: AuditStreamLayout) -> Self {
        Self {
            transaction,
            layout,
            input_trees: None,
            known_utxos: None,
            escrowed_keys: None,
        }
    }

    /// Every input commitment binds its tree id.
    pub fn with_input_trees(mut self, trees: &'a [Option<u16>]) -> Result<Self, AuditError> {
        let inputs = self.transaction.nullifiers.len();
        if trees.len() != inputs {
            return Err(AuditError::InputTreeCount {
                trees: trees.len(),
                inputs,
            });
        }
        self.input_trees = Some(trees);
        Ok(self)
    }

    /// Opens a commitment-layout input and resolves an entry input's ring.
    pub fn with_known_utxos(mut self, known: &'a dyn KnownUtxos) -> Self {
        self.known_utxos = Some(known);
        self
    }

    /// The output nullifier keys a key-escrow ring leaves out of its ciphertexts.
    pub fn with_escrowed_keys(mut self, keys: &'a dyn EscrowedKeys) -> Self {
        self.escrowed_keys = Some(keys);
        self
    }

    pub fn run(
        self,
        auditor: &X25519Keypair,
        assets: &RingAssets,
    ) -> Result<AuditedTransaction, AuditError> {
        let tx = self.transaction;
        let tx_viewing_pk = tx.tx_viewing_pk.ok_or(AuditError::MissingTxViewingPk)?;
        let salt = tx.salt.ok_or(AuditError::MissingSalt)?;
        let ring = tx.ring_program_id.ok_or(AuditError::MissingRingProgram)?;
        let first_nullifier = *tx.nullifiers.first().ok_or(AuditError::MissingNullifier)?;
        let data = auditor_message(tx, &auditor.pubkey())?;
        let layout = self.layout;
        check_published(layout, tx)?;
        let message = AuditorMessage::parse(data, layout)
            .ok_or(AuditError::AuditorMessageLength(data.len()))?;
        let opened = AuditEnvelope {
            eph_u: X25519Pubkey::from_bytes(*message.eph_pk)?.u(),
            ciphertext: message.envelope,
        }
        .open(auditor, layout)?;
        let tx_key = &opened.tx_viewing_key;
        // The audit proof binds the envelope to the published key.
        if tx_key.pubkey() != tx_viewing_pk {
            return Err(AuditError::TxViewingKeyMismatch);
        }
        let mut audited = AuditedTransaction {
            tx_signature: tx.tx_signature,
            slot: tx.slot,
            tx_viewing_pk,
            outputs: Vec::new(),
            payload_errors: Vec::new(),
            sender: None,
            inputs: Vec::new(),
            unresolved: Vec::new(),
        };
        let escrowed = self.escrowed_keys.unwrap_or(&NoEscrow);
        let transfer = Transfer {
            ring,
            tx_key,
            tx_viewing_pk,
            salt,
            first_nullifier,
            seed_out: derive_output_blinding_seed(
                &first_nullifier,
                &ring_blinding_seed(&tx_key.secret_bytes(), &salt)?,
            )?,
            body_len: layout.delivered_body_len(),
            assets,
        };
        for (index, output) in (0u32..).zip(&tx.output_slots) {
            let slot = Slot { index, output };
            let record = message
                .record(layout, index as usize)
                .ok_or(AuditError::AuditorMessageLength(data.len()))?;
            let read = match opened.record(index as usize, record)? {
                OutputRecord::Delivered => transfer.delivered(slot)?,
                OutputRecord::Anonymous(record) => {
                    SlotRead::Final(transfer.anonymous(slot, record)?)
                }
                OutputRecord::Exit(record) => transfer.exit(slot, record)?,
            };
            match read {
                SlotRead::Final(opened) => {
                    audited.place(slot.index, slot.output.output_context.clone(), opened)
                }
                SlotRead::Retained(output) => {
                    let resolution = output.resolve(escrowed, assets)?;
                    audited.settle(output, resolution);
                }
            }
        }
        let spent = transfer.inputs(SpentInputs {
            evidence: &opened.evidence,
            nullifiers: &tx.nullifiers,
            trees: self.input_trees,
            known: self.known_utxos,
        })?;
        audited.sender = spent.sender;
        audited.inputs = spent.inputs;
        Ok(audited)
    }
}

/// The frame fixes `n`, the outputs and the exit bits, a transaction of any other shape is refused.
fn check_published(layout: AuditStreamLayout, tx: &ShieldedTransaction) -> Result<(), AuditError> {
    let consistent = layout.outputs == tx.output_slots.len()
        && layout.inputs == tx.nullifiers.len()
        && tx
            .output_slots
            .iter()
            .enumerate()
            .all(|(slot, output)| layout.is_exit(slot) == is_exit(output));
    match consistent {
        true => Ok(()),
        false => Err(AuditError::DisclosureLayout),
    }
}

/// The program keeps the auditor message last, the tag of any earlier message is free frame bytes.
fn auditor_message<'a>(
    tx: &'a ShieldedTransaction,
    auditor_pk: &X25519Pubkey,
) -> Result<&'a [u8], AuditError> {
    tx.messages
        .last()
        .filter(|message| message.view_tag == auditor_view_tag(auditor_pk))
        .map(|message| message.data.as_slice())
        .ok_or(AuditError::MissingAuditorMessage)
}

/// The ring program encodes every exit under scheme 3, every other slot under its layout's scheme.
fn is_exit(slot: &OutputSlot) -> bool {
    confidential_encrypted_output_body(&slot.payload).is_some()
}

#[derive(Clone, Copy)]
struct Slot<'a> {
    index: u32,
    output: &'a OutputSlot,
}

impl<'a> Slot<'a> {
    fn owner_tag(self) -> [u8; 32] {
        self.output.view_tag
    }

    /// The layout's key escrow flag fixes the length, any other is refused.
    fn body(self, len: usize) -> Option<&'a [u8]> {
        ring_confidential_delivered_output_body(&self.output.payload)
            .filter(|body| body.len() == len)
    }

    fn tree_id(self) -> u16 {
        self.output.output_context.tree_id
    }

    fn rebuilt(self, commitment: [u8; 32], opening: OutputOpening) -> SlotOpening {
        match commitment == self.output.output_context.hash {
            true => Ok(opening),
            false => Err(OutputPayloadErrorKind::Commitment),
        }
    }
}

type SlotOpening = Result<OutputOpening, OutputPayloadErrorKind>;

enum SlotRead {
    Final(SlotOpening),
    Retained(UnresolvedOutput),
}

struct Transfer<'a> {
    ring: Address,
    tx_key: &'a ViewingKey,
    tx_viewing_pk: X25519Pubkey,
    salt: [u8; 16],
    first_nullifier: [u8; 32],
    seed_out: [u8; 32],
    body_len: usize,
    assets: &'a RingAssets,
}

struct Spent {
    sender: Option<AuditedSender>,
    inputs: Vec<AuditedInput>,
}

struct SpentInputs<'a> {
    evidence: &'a AuditEvidence,
    nullifiers: &'a [[u8; 32]],
    trees: Option<&'a [Option<u16>]>,
    known: Option<&'a dyn KnownUtxos>,
}

impl Transfer<'_> {
    /// The zero record of a hidden dummy and a record outside the field open nothing.
    fn anonymous(
        &self,
        slot: Slot<'_>,
        record: AnonymousRecord,
    ) -> Result<SlotOpening, AuditError> {
        if record == AnonymousRecord::default() {
            return self.verify_dummy(slot);
        }
        let AnonymousRecord {
            owner_key,
            asset,
            amount,
            nullifier_pk,
        } = record;
        if canonical(asset).is_err() {
            return Ok(Err(OutputPayloadErrorKind::Disclosure));
        }
        let utxo = AuditedUtxo {
            owner_key,
            nullifier_pk,
            asset,
            mint: self.mint(&asset),
            amount,
            blinding: self.blinding(slot)?,
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
        };
        let commitment = utxo.commitment(slot.tree_id(), Some(self.ring))?;
        Ok(slot.rebuilt(
            commitment,
            OutputOpening::Ring {
                utxo,
                owner_tag: RingOwnerTag::View(slot.owner_tag()),
            },
        ))
    }

    /// A dummy publishes a random body, its commitment alone tells it from a ring output.
    fn delivered(&self, slot: Slot<'_>) -> Result<SlotRead, AuditError> {
        let dummy = self.verify_dummy(slot)?;
        if dummy.is_ok() {
            return Ok(SlotRead::Final(dummy));
        }
        let refused = |kind| Ok(SlotRead::Final(Err(kind)));
        let recipient_u = slot.owner_tag();
        let Some(ciphertext) = slot.body(self.body_len) else {
            return refused(OutputPayloadErrorKind::Frame);
        };
        let Some(secret) = self.delivered_secret(slot, recipient_u)? else {
            return refused(OutputPayloadErrorKind::RecipientKey);
        };
        let body = open_delivered_body(ciphertext, &secret)?;
        let blinding = self.blinding(slot)?;
        if body.blinding != blinding {
            return refused(OutputPayloadErrorKind::Commitment);
        }
        Ok(SlotRead::Retained(UnresolvedOutput {
            slot_index: slot.index,
            context: slot.output.output_context.clone(),
            ring: self.ring,
            nullifier_pk: body.nullifier_pk,
            fields: EscrowPendingOutput {
                owner_key: body.owner_key,
                amount: body.amount,
                blinding,
                slot: EscrowPendingSlot::Ring { recipient_u },
            },
        }))
    }

    fn exit(&self, slot: Slot<'_>, record: ExitRecord) -> Result<SlotRead, AuditError> {
        if canonical(record.asset).is_err() {
            return Ok(SlotRead::Final(Err(OutputPayloadErrorKind::Disclosure)));
        }
        Ok(SlotRead::Retained(UnresolvedOutput {
            slot_index: slot.index,
            context: slot.output.output_context.clone(),
            ring: self.ring,
            nullifier_pk: record.nullifier_pk,
            fields: EscrowPendingOutput {
                owner_key: slot.owner_tag(),
                amount: record.amount,
                blinding: self.blinding(slot)?,
                slot: EscrowPendingSlot::Exit {
                    asset: record.asset,
                    mint: self.mint(&record.asset),
                },
            },
        }))
    }

    fn verify_dummy(&self, slot: Slot<'_>) -> Result<SlotOpening, AuditError> {
        let commitment = ProofInputUtxo {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(slot.tree_id()),
            blinding: self.blinding(slot)?,
            ..ProofInputUtxo::default()
        }
        .hash()?;
        Ok(slot.rebuilt(commitment, OutputOpening::Dummy))
    }

    fn delivered_secret(
        &self,
        slot: Slot<'_>,
        recipient_u: [u8; 32],
    ) -> Result<Option<SlotSecret>, AuditError> {
        let Ok(recipient) = X25519Pubkey::from_u(recipient_u) else {
            return Ok(None);
        };
        let Ok(agreement) = self.tx_key.ecdh(&recipient) else {
            return Ok(None);
        };
        let agreement = Zeroizing::new(agreement);
        Ok(Some(
            DeliveredSlot {
                agreement: &agreement,
                tx_viewing_pk: self.tx_viewing_pk.as_bytes(),
                recipient_viewing_pk: recipient.as_bytes(),
                salt: &self.salt,
                output_index: slot.index,
                first_nullifier: &self.first_nullifier,
            }
            .secret()?,
        ))
    }

    /// SPP's TXOB blinding under the seed the transaction key derives.
    fn blinding(&self, slot: Slot<'_>) -> Result<[u8; 32], AuditError> {
        Ok(derive_transact_output_blinding(
            &self.first_nullifier,
            &self.seed_out,
            slot.index,
        )?)
    }

    fn mint(&self, asset: &[u8; 32]) -> Option<Address> {
        mint_of(self.assets, asset)
    }

    /// Every key with evidence keeps dummies last as SPP does, opening k belongs to nullifier k.
    fn inputs(&self, spent: SpentInputs<'_>) -> Result<Spent, AuditError> {
        let SpentInputs {
            evidence,
            nullifiers,
            trees,
            known,
        } = spent;
        let name_inputs = |openings: Vec<InputOpening>| {
            nullifiers
                .iter()
                .zip(openings)
                .map(|(nullifier, opening)| AuditedInput {
                    nullifier: *nullifier,
                    opening,
                })
                .collect()
        };
        match evidence {
            AuditEvidence::None => Ok(Spent {
                sender: None,
                inputs: Vec::new(),
            }),
            AuditEvidence::InputPrefixes(prefixes) => Ok(Spent {
                sender: None,
                inputs: name_inputs(
                    PrefixedInputs {
                        known,
                        scope: PrefixScope::AnyOwner,
                        ring: self.ring,
                    }
                    .open(prefixes),
                ),
            }),
            AuditEvidence::Commitment {
                first_input_hash: first,
                later_prefixes: prefixes,
            } => {
                // The circuit proves spent UTXO 0 real and every spent UTXO under one owner key.
                let zero = known.and_then(|known| known.utxo(first));
                let later = PrefixedInputs {
                    known,
                    scope: zero.map_or(PrefixScope::AnyOwner, |zero| PrefixScope::Sender {
                        owner_key: zero.owner_key,
                        first: *first,
                    }),
                    ring: self.ring,
                }
                .open(prefixes);
                let mut openings = vec![zero
                    .map_or(InputOpening::UnseenHash { hash: *first }, |zero| {
                        InputOpening::Opened(ring_input(*first, zero))
                    })];
                openings.extend(later);
                Ok(Spent {
                    sender: zero.map(|zero| AuditedSender {
                        owner_key: zero.owner_key,
                        nullifier_pk: zero.owner.nullifier_pk(),
                    }),
                    inputs: name_inputs(openings),
                })
            }
            AuditEvidence::Entry {
                sender_key,
                sender_nullifier_pk,
                inputs: openings,
            } => {
                let inputs = nullifiers
                    .iter()
                    .zip(openings)
                    .enumerate()
                    .map(|(index, (nullifier, opening))| {
                        if *opening == EntryInput::default() {
                            return Ok(AuditedInput {
                                nullifier: *nullifier,
                                opening: InputOpening::Dummy,
                            });
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
                        let tree = trees.and_then(|trees| trees.get(index).copied().flatten());
                        Ok::<_, AuditError>(AuditedInput {
                            nullifier: *nullifier,
                            opening: InputOpening::Opened(AuditedInputOpening {
                                asset: utxo.asset,
                                mint: utxo.mint,
                                amount: utxo.amount,
                                blinding: utxo.blinding,
                                ring: tree
                                    .map(|tree| self.input_ring(&utxo, tree, known))
                                    .transpose()?,
                            }),
                        })
                    })
                    .collect::<Result<_, AuditError>>()?;
                Ok(Spent {
                    sender: Some(AuditedSender {
                        owner_key: *sender_key,
                        nullifier_pk: Some(*sender_nullifier_pk),
                    }),
                    inputs,
                })
            }
        }
    }

    fn input_ring(
        &self,
        utxo: &AuditedUtxo,
        tree_id: u16,
        known: Option<&dyn KnownUtxos>,
    ) -> Result<InputRing, AuditError> {
        let ring = utxo.commitment(tree_id, Some(self.ring))?;
        let default = utxo.commitment(tree_id, None)?;
        let found = |commitment| known.is_some_and(|known| known.utxo(commitment).is_some());
        Ok(match (found(&ring), found(&default)) {
            (true, false) => InputRing::Ring { commitment: ring },
            (false, true) => InputRing::Default {
                commitment: default,
            },
            _ => InputRing::Unresolved { ring, default },
        })
    }
}

struct PrefixedInputs<'a> {
    known: Option<&'a dyn KnownUtxos>,
    scope: PrefixScope,
    ring: Address,
}

#[derive(Clone, Copy)]
enum PrefixScope {
    /// The commitment key, the circuit binds a later input to the sender and its prefix.
    Sender {
        owner_key: [u8; 32],
        first: [u8; 32],
    },
    /// The rails that name no owner, and a commitment key before its first note opens.
    AnyOwner,
}

impl PrefixedInputs<'_> {
    fn open(self, prefixes: &[Option<InputPrefix>]) -> Vec<InputOpening> {
        let mut groups: Vec<(InputPrefix, Vec<usize>)> = Vec::new();
        for (position, prefix) in prefixes.iter().enumerate() {
            let Some(prefix) = *prefix else {
                continue;
            };
            match groups.iter_mut().find(|(group, _)| *group == prefix) {
                Some((_, positions)) => positions.push(position),
                None => groups.push((prefix, vec![position])),
            }
        }
        let mut openings = vec![InputOpening::Dummy; prefixes.len()];
        for (prefix, positions) in groups {
            let assigned = self.notes(prefix).assign(positions.len());
            for (position, opening) in positions.into_iter().zip(assigned) {
                openings[position] = opening;
            }
        }
        openings
    }

    fn notes(&self, prefix: InputPrefix) -> PrefixNotes {
        let Some(known) = self.known else {
            return PrefixNotes {
                prefix,
                notes: Vec::new(),
            };
        };
        let mut seen = HashSet::new();
        let candidates = match self.scope {
            PrefixScope::Sender { owner_key, .. } => known.with_prefix(&owner_key, prefix),
            PrefixScope::AnyOwner => known.with_prefix_of_anyone(prefix),
        };
        PrefixNotes {
            prefix,
            notes: candidates
                .into_iter()
                .filter_map(|commitment| Some((commitment, known.utxo(&commitment)?)))
                .filter(|(commitment, utxo)| {
                    let in_scope = match self.scope {
                        PrefixScope::Sender { owner_key, first } => {
                            *commitment != first && utxo.owner_key == owner_key
                        }
                        PrefixScope::AnyOwner => true,
                    };
                    in_scope
                        && InputPrefix::of(commitment) == Some(prefix)
                        && utxo
                            .commitment(Some(self.ring))
                            .is_ok_and(|ring| ring == *commitment)
                        && seen.insert(*commitment)
                })
                .collect(),
        }
    }
}

struct PrefixNotes {
    prefix: InputPrefix,
    notes: Vec<([u8; 32], KnownUtxo)>,
}

impl PrefixNotes {
    /// Exact only for one note in one position, notes sharing a prefix fit any of its positions.
    fn assign(self, inputs: usize) -> Vec<InputOpening> {
        match self.notes[..] {
            _ if self.notes.len() < inputs => vec![
                InputOpening::Unseen {
                    prefix: self.prefix,
                };
                inputs
            ],
            [(commitment, utxo)] => vec![InputOpening::Opened(ring_input(commitment, utxo))],
            _ => {
                let candidates = self
                    .notes
                    .iter()
                    .map(|(commitment, _)| *commitment)
                    .collect();
                vec![InputOpening::Ambiguous { candidates }; inputs]
            }
        }
    }
}

fn ring_input(commitment: [u8; 32], utxo: KnownUtxo) -> AuditedInputOpening {
    AuditedInputOpening {
        asset: utxo.asset,
        mint: utxo.mint,
        amount: utxo.amount,
        blinding: utxo.blinding,
        ring: Some(InputRing::Ring { commitment }),
    }
}

fn mint_of(assets: &RingAssets, asset: &[u8; 32]) -> Option<Address> {
    assets.by_field(asset).map(|mint| mint.asset)
}

impl UnresolvedOutput {
    /// Looks up the nullifier key and the asset alone, a note opens only when it rebuilds the commitment.
    pub fn resolve(
        &self,
        escrowed: &dyn EscrowedKeys,
        assets: &RingAssets,
    ) -> Result<OutputResolution, AuditError> {
        let EscrowPendingOutput {
            owner_key,
            amount,
            blinding,
            slot,
        } = self.fields;
        let Some(nullifier_pk) = self
            .nullifier_pk
            .or_else(|| escrowed.nullifier_pk(&owner_key))
        else {
            return Ok(OutputResolution::AwaitsKey);
        };
        let note = |asset, mint| AuditedUtxo {
            owner_key,
            nullifier_pk,
            asset,
            mint,
            amount,
            blinding,
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
        };
        let OutputContext { hash, tree_id, .. } = self.context;
        match slot {
            EscrowPendingSlot::Exit { asset, .. } => {
                let utxo = note(asset, mint_of(assets, &asset));
                Ok(match utxo.commitment(tree_id, None)? == hash {
                    true => OutputResolution::Opened(Box::new(OutputOpening::Exit(utxo))),
                    false => OutputResolution::Refused(OutputPayloadErrorKind::Commitment),
                })
            }
            EscrowPendingSlot::Ring { recipient_u } => {
                for (asset, mint) in assets.fields() {
                    let utxo = note(*asset, Some(mint.asset));
                    if utxo.commitment(tree_id, Some(self.ring))? == hash {
                        return Ok(OutputResolution::Opened(Box::new(OutputOpening::Ring {
                            utxo,
                            owner_tag: RingOwnerTag::Recipient(recipient_u),
                        })));
                    }
                }
                Ok(OutputResolution::AwaitsAsset)
            }
        }
    }
}

impl AuditedTransaction {
    /// Retries only the key and asset lookups, no disclosure or input opens again.
    pub fn resolve(
        &mut self,
        escrowed: &dyn EscrowedKeys,
        assets: &RingAssets,
    ) -> Result<(), AuditError> {
        for output in &mut self.outputs {
            output.opening.name_mint(assets);
        }
        for input in &mut self.inputs {
            if let InputOpening::Opened(opening) = &mut input.opening {
                opening.mint = opening.mint.or_else(|| mint_of(assets, &opening.asset));
            }
        }
        // A commitment error settles no output.
        let resolutions = self
            .unresolved
            .iter()
            .map(|output| output.resolve(escrowed, assets))
            .collect::<Result<Vec<_>, _>>()?;
        for (output, resolution) in core::mem::take(&mut self.unresolved)
            .into_iter()
            .zip(resolutions)
        {
            self.settle(output, resolution);
        }
        Ok(())
    }

    fn settle(&mut self, output: UnresolvedOutput, resolution: OutputResolution) {
        let (opened, waits) = match resolution {
            OutputResolution::Opened(opening) => (Ok(*opening), false),
            OutputResolution::Refused(kind) => (Err(kind), false),
            OutputResolution::AwaitsKey => (Ok(OutputOpening::EscrowPending(output.fields)), true),
            OutputResolution::AwaitsAsset => (Err(OutputPayloadErrorKind::UnknownAsset), true),
        };
        self.place(output.slot_index, output.context.clone(), opened);
        if waits {
            self.unresolved.push(output);
        }
    }

    /// A slot appears once, in published order.
    fn place(&mut self, slot_index: u32, context: OutputContext, opened: SlotOpening) {
        self.outputs
            .retain(|output| output.slot_index != slot_index);
        self.payload_errors
            .retain(|error| error.slot_index != slot_index);
        match opened {
            Ok(opening) => {
                let at = self
                    .outputs
                    .partition_point(|output| output.slot_index < slot_index);
                self.outputs.insert(
                    at,
                    AuditedOutput {
                        slot_index,
                        context,
                        opening,
                    },
                );
            }
            Err(kind) => {
                let at = self
                    .payload_errors
                    .partition_point(|error| error.slot_index < slot_index);
                self.payload_errors
                    .insert(at, OutputPayloadError { slot_index, kind });
            }
        }
    }
}

impl OutputOpening {
    fn name_mint(&mut self, assets: &RingAssets) {
        let (asset, mint) = match self {
            Self::Ring { utxo, .. } | Self::Exit(utxo) => (utxo.asset, &mut utxo.mint),
            Self::EscrowPending(EscrowPendingOutput {
                slot: EscrowPendingSlot::Exit { asset, mint },
                ..
            }) => (*asset, mint),
            Self::EscrowPending(_) | Self::Dummy => return,
        };
        *mint = mint.or_else(|| mint_of(assets, &asset));
    }
}

#[cfg(test)]
mod tests;
