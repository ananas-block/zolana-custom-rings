//! The audit half of a ring transfer, its stream sealed to the auditor.

use custom_ring_interface::{
    AnonymousAuditKey, AnonymousRecord, AuditEvidence, AuditKey, AuditLayout, AuditStreamLayout,
    AuditorMessage, EntryInput, ExitRecord, RingOutput,
};
use spr_event::MessageData;
use spr_hasher::primitives::hash_bytes;
use spr_keypair::{ShieldedAddress, X25519Pubkey};
use spr_transaction::{
    instructions::transact::SppProofInputs, utxo::SppProofInputUtxo, SppProofOutputUtxo,
    TransactionError,
};
use zeroize::Zeroizing;
use zolana_ring_client::{commitment_evidence, prefix_evidence, AuditStreamSeal, OutputRecord};
use zolana_ring_transaction::{PublishedSlot, RingOutputRail};

use crate::{
    request::{owner_key, AnonymousOutput, AuditParams, DeliveredOutput, Opening},
    RingError,
};

pub(crate) struct SealedAudit {
    pub flags: AuditLayout,
    pub eph_u: [u8; 32],
    pub envelope: Vec<u8>,
    /// One per slot, empty on a delivered slot.
    pub records: Vec<Vec<u8>>,
    eph_sk: Zeroizing<[u8; 32]>,
}

pub(crate) struct PresealedAudit {
    pub message: MessageData,
    pub eph_sk: Zeroizing<[u8; 32]>,
}

pub(super) struct AuditSeal<'a> {
    pub rail: &'a RingOutputRail,
    pub layout: AuditStreamLayout,
    pub flags: AuditLayout,
    pub published: &'a [PublishedSlot<'a>],
    pub inputs: &'a SppProofInputs,
    pub sender: &'a ShieldedAddress,
    pub auditor: &'a X25519Pubkey,
}

impl SealedAudit {
    /// The secret opens the stream with the auditor public key alone.
    pub(crate) fn ephemeral_secret(&self) -> &Zeroizing<[u8; 32]> {
        &self.eph_sk
    }
}

impl AuditSeal<'_> {
    pub fn seal(self) -> Result<SealedAudit, RingError> {
        let records = self
            .published
            .iter()
            .map(|slot| output_record(slot, self.layout))
            .collect::<Result<_, _>>()?;
        let sealed = AuditStreamSeal {
            layout: self.layout,
            tx_viewing_key: self.rail.tx_viewing_key(),
            evidence: self.evidence()?,
            records,
        }
        .seal(self.auditor)?;
        Ok(SealedAudit {
            flags: self.flags,
            eph_u: sealed.eph_u,
            envelope: sealed.envelope,
            records: sealed.records,
            eph_sk: sealed.ephemeral_sk,
        })
    }

    fn evidence(&self) -> Result<AuditEvidence, RingError> {
        let published = || {
            self.inputs
                .input_utxos
                .iter()
                .filter(|input| !input.is_compact())
        };
        let hashes = || -> Vec<_> { published().map(published_hash).collect() };
        Ok(match self.layout.key {
            AuditKey::Confidential {
                input_prefixes: false,
                ..
            } => AuditEvidence::None,
            AuditKey::Confidential {
                input_prefixes: true,
                ..
            } => prefix_evidence(&hashes())?,
            AuditKey::Anonymous(AnonymousAuditKey::Commitment { .. }) => {
                commitment_evidence(&hashes())?
            }
            AuditKey::Anonymous(AnonymousAuditKey::Entry { .. }) => AuditEvidence::Entry {
                sender_key: owner_key(&self.sender.signing_pubkey)?,
                sender_nullifier_pk: self.sender.nullifier_pubkey,
                inputs: published()
                    .map(|input| match input.is_dummy() {
                        true => Ok(EntryInput::default()),
                        false => Ok(EntryInput {
                            amount: input.utxo.amount,
                            asset: hash_bytes(input.utxo.asset.asset.as_array())?,
                            blinding: input.utxo.blinding,
                        }),
                    })
                    .collect::<Result<_, RingError>>()?,
            },
        })
    }
}

fn published_hash(input: &SppProofInputUtxo) -> Option<[u8; 32]> {
    (!input.is_dummy()).then(|| input.private_tx_input_hash())
}

impl PresealedAudit {
    /// Refused unless the message sits under the ring auditor's tag in the layout of the transfer.
    pub fn open(
        self,
        layout: AuditStreamLayout,
        flags: AuditLayout,
        auditor: &X25519Pubkey,
    ) -> Result<SealedAudit, RingError> {
        let message = AuditorMessage::parse(&self.message.data, layout)
            .filter(|_| self.message.view_tag == auditor.u())
            .ok_or(RingError::RelayAuditorMessage)?;
        let eph_u = message.eph_pk[1..]
            .try_into()
            .map_err(|_| RingError::RelayAuditorMessage)?;
        let records = (0..layout.outputs)
            .map(|slot| message.record(layout, slot).map(<[u8]>::to_vec))
            .collect::<Option<_>>()
            .ok_or(RingError::RelayAuditorMessage)?;
        Ok(SealedAudit {
            flags,
            eph_u,
            envelope: message.envelope.to_vec(),
            records,
            eph_sk: self.eph_sk,
        })
    }
}

impl SealedAudit {
    /// The message the program expands under the auditor's view tag.
    pub fn message(&self, auditor: &X25519Pubkey) -> MessageData {
        MessageData {
            view_tag: auditor.u(),
            data: AuditorMessage::data(
                &self.eph_u,
                core::iter::once(self.envelope.as_slice())
                    .chain(self.records.iter().map(Vec::as_slice)),
            ),
        }
    }
}

pub(super) struct AuditSection<'a> {
    pub rail: &'a RingOutputRail,
    pub sealed: &'a SealedAudit,
    pub published: Vec<PublishedSlot<'a>>,
    pub inputs: &'a SppProofInputs,
    pub sender: &'a ShieldedAddress,
    pub auditor: &'a X25519Pubkey,
    pub body_len: usize,
}

impl AuditSection<'_> {
    pub fn params(&self) -> Result<AuditParams, RingError> {
        Ok(AuditParams {
            first_nullifier: self
                .inputs
                .input_utxos
                .first()
                .ok_or(TransactionError::NoInputs)?
                .nullifier(),
            tx_viewing_sk: self.rail.tx_viewing_key().secret_bytes(),
            eph_sk: self.sealed.eph_sk.clone(),
            auditor_pk: *self.auditor,
            salt: self.rail.salt(),
            layout: self.sealed.flags.value(),
        })
    }

    pub fn delivered_outputs(&self) -> Result<Vec<DeliveredOutput>, RingError> {
        let tree = self.inputs.output_tree_id;
        let body_len = self.body_len;
        self.published
            .iter()
            .map(|slot| delivered_output(slot, tree, body_len))
            .collect()
    }

    pub fn anonymous_outputs(&self) -> Result<Vec<AnonymousOutput>, RingError> {
        let tree = self.inputs.output_tree_id;
        self.published
            .iter()
            .map(|slot| anonymous_output(slot, tree))
            .collect()
    }

    /// The spent notes' openings in SPP order, zero past them to the key's input class.
    pub fn input_openings(&self, class: usize) -> Result<Vec<Opening>, RingError> {
        let mut openings = self
            .inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .map(Opening::input)
            .collect::<Result<Vec<_>, _>>()?;
        openings.resize(class, Opening::default());
        Ok(openings)
    }

    pub fn sender_key(&self) -> Result<[u8; 32], RingError> {
        owner_key(&self.sender.signing_pubkey)
    }
}

fn slot_owner_key(output: &SppProofOutputUtxo) -> Result<[u8; 32], RingError> {
    output
        .owner_address
        .map(|owner| owner_key(&owner.signing_pubkey))
        .transpose()
        .map(Option::unwrap_or_default)
}

/// A hidden dummy is the zero record, its bytes publish as a real output's would.
fn output_record(
    slot: &PublishedSlot<'_>,
    layout: AuditStreamLayout,
) -> Result<OutputRecord, RingError> {
    let output = slot.output;
    let owner = output.owner_address;
    let asset = hash_bytes(output.asset.asset.as_array())?;
    Ok(match (slot.wire.is_exit(), layout.key, owner) {
        (true, _, owner) => OutputRecord::Exit(ExitRecord {
            asset,
            amount: output.amount,
            nullifier_pk: owner
                .map(|owner| owner.nullifier_pubkey)
                .filter(|_| !layout.key_escrow),
        }),
        (false, AuditKey::Confidential { .. }, _) => OutputRecord::Delivered,
        (false, AuditKey::Anonymous(_), None) => {
            OutputRecord::Anonymous(AnonymousRecord::default())
        }
        (false, AuditKey::Anonymous(_), Some(owner)) => OutputRecord::Anonymous(AnonymousRecord {
            owner_key: owner_key(&owner.signing_pubkey)?,
            asset,
            amount: output.amount,
            nullifier_pk: owner.nullifier_pubkey,
        }),
    })
}

/// A dummy binds its published key and body as a ring output does, an exit's zero body keeps the
/// layout's length.
fn delivered_output(
    slot: &PublishedSlot<'_>,
    tree: u16,
    body_len: usize,
) -> Result<DeliveredOutput, RingError> {
    let output = slot.output;
    let (recipient_key, body) = match slot.wire {
        RingOutput::Delivered { u, body, .. } => (*u, body.to_vec()),
        RingOutput::Anonymous { .. } | RingOutput::Exit { .. } => ([0; 32], vec![0; body_len]),
    };
    let ring = !output.is_dummy() && !slot.wire.is_exit();
    Ok(DeliveredOutput {
        output: Opening::output(output, tree)?,
        recipient_key,
        owner_key: match ring {
            true => slot_owner_key(output)?,
            false => [0; 32],
        },
        body,
    })
}

/// An exit's owner key stays out of its record, a dummy names none.
fn anonymous_output(slot: &PublishedSlot<'_>, tree: u16) -> Result<AnonymousOutput, RingError> {
    let output = slot.output;
    Ok(AnonymousOutput {
        output: Opening::output(output, tree)?,
        owner_key: slot_owner_key(output)?,
    })
}
