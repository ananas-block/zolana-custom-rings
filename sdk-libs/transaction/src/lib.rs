//! Ring output rails as the ring program expands them, mirrored by Go `prover/circuits/audit`.

mod assets;
mod error;
mod published;
mod ring_delivered;
mod ring_packed;

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

use custom_ring_interface::{
    blinding::ring_blinding_seed,
    stream::{DeliveredSlot, RingTag, SlotSecret, TagIndex},
    RingOutput, RING_DELIVERED_BODY_LEN,
};
use rand::{rngs::OsRng, RngCore};
use spr_event::MessageData;
use spr_interface::{instruction::instruction_data::transact::OwnerTag, MAX_OUTPUTS};
use spr_keypair::{random_salt, viewing_key::Salt, ShieldedAddress, ViewingKey, X25519Pubkey};
use spr_transaction::{
    instructions::transact::{
        ConfidentialTransaction, OutputEncoder, OutputEncryption, ResolvedOwnerTag, SppProofInputs,
    },
    serialization::confidential::{Confidential, ConfidentialEncode, ConfidentialOutputPlaintext},
    Data, SppProofOutputUtxo, TransactionError, UtxoSerialization, SOL_ASSET_ID,
};

pub use assets::RingAssets;
pub use error::RingRailError;
pub use published::PublishedSlot;
pub use ring_delivered::{
    delivered_ring_data, is_contributory, RingDelivered, RingDeliveredBody, RingDeliveredNote,
    RingDeliveryOpening, RingUtxoOwner,
};
pub use ring_packed::{RingPacked, RingPackedPlaintext};

#[derive(Clone, Debug)]
pub enum RingDelivery {
    /// Scheme 11 sealed to the owner's viewing key, at `PACKED_AUDIT_CAPACITIES`.
    Packed,
    /// Scheme 10 delivered to the owner's viewing key, at `DELIVERED_AUDIT_CAPACITIES`.
    Delivered,
    /// Scheme 9 under a stream tag, each payment delivered to its ring address key.
    Anonymous(Box<AnonymousSlots>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamPosition {
    Inbox(TagIndex),
    /// The one pair-anchored payment of a transfer.
    Pair(TagIndex),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPayment {
    /// The ring address key the body opens under.
    pub recipient: X25519Pubkey,
    pub tag: RingTag,
    pub position: StreamPosition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousSlot {
    Payment(StreamPayment),
    /// Under a free tag, delivered to the sender's ring change key.
    Change {
        tag: RingTag,
    },
    Exit,
    /// Under a free tag.
    Dummy {
        tag: RingTag,
    },
}

/// The payments of an anonymous transfer by final slot index.
#[must_use]
#[derive(Clone, Debug)]
pub struct AnonymousSlots {
    change_key: X25519Pubkey,
    payments: BTreeMap<u32, StreamPayment>,
    ring_address_keys: BTreeSet<[u8; 33]>,
    /// Drawn ahead, a change slot's owner tag resolves before its ring data.
    free_tags: [RingTag; MAX_OUTPUTS],
}

impl AnonymousSlots {
    /// `change_key` is the sender's ring change key, the sender finds its change through its spends.
    pub fn new(change_key: X25519Pubkey) -> Self {
        Self {
            change_key,
            payments: BTreeMap::new(),
            ring_address_keys: BTreeSet::new(),
            free_tags: core::array::from_fn(|_| free_tag()),
        }
    }

    /// Refuses a taken slot, a repeated tag and a second pair payment.
    pub fn with_payment(
        mut self,
        slot_index: u32,
        payment: StreamPayment,
    ) -> Result<Self, RingRailError> {
        let paired = |payment: &StreamPayment| matches!(payment.position, StreamPosition::Pair(_));
        if self.payments.contains_key(&slot_index)
            || self.payments.values().any(|other| other.tag == payment.tag)
            || (paired(&payment) && self.payments.values().any(paired))
        {
            return Err(RingRailError::RingPaymentSlot {
                slot_index: slot_index as usize,
            });
        }
        self.ring_address_keys.insert(*payment.recipient.as_bytes());
        self.payments.insert(slot_index, payment);
        Ok(self)
    }

    /// The sender's own ring address keys, no exit may name one.
    pub fn with_ring_address_keys(mut self, keys: impl IntoIterator<Item = X25519Pubkey>) -> Self {
        self.ring_address_keys
            .extend(keys.into_iter().map(|key| *key.as_bytes()));
        self
    }

    pub fn change_key(&self) -> X25519Pubkey {
        self.change_key
    }

    pub fn payment(&self, slot_index: u32) -> Option<StreamPayment> {
        self.payments.get(&slot_index).copied()
    }

    fn slot(
        &self,
        output: &SppProofOutputUtxo,
        sender: &ShieldedAddress,
        slot_index: u32,
    ) -> Result<AnonymousSlot, RingRailError> {
        let index = slot_index as usize;
        let payment = self.payments.get(&slot_index);
        let Some(owner) = output
            .owner_address
            .filter(|_| output.ring_program_id.is_some())
        else {
            if payment.is_some() {
                return Err(RingRailError::RingPaymentSlot { slot_index: index });
            }
            return match output.owner_address {
                Some(owner)
                    if self
                        .ring_address_keys
                        .contains(owner.viewing_pubkey.as_bytes()) =>
                {
                    Err(RingRailError::RingAddressExit { slot_index: index })
                }
                Some(owner) if owner.signing_pubkey == sender.signing_pubkey => {
                    Err(RingRailError::RingSenderExit { slot_index: index })
                }
                Some(_) => Ok(AnonymousSlot::Exit),
                None => Ok(AnonymousSlot::Dummy {
                    tag: self.free_tag(index)?,
                }),
            };
        };
        match payment {
            Some(payment) if payment.recipient == owner.viewing_pubkey => {
                Ok(AnonymousSlot::Payment(*payment))
            }
            Some(_) => Err(RingRailError::RingPaymentSlot { slot_index: index }),
            None if owner == *sender => Ok(AnonymousSlot::Change {
                tag: self.free_tag(index)?,
            }),
            None => Err(RingRailError::UnplannedRingOutput { slot_index: index }),
        }
    }

    fn free_tag(&self, slot_index: usize) -> Result<RingTag, RingRailError> {
        Ok(self
            .free_tags
            .get(slot_index)
            .copied()
            .ok_or(TransactionError::TooManyOutputs)?)
    }

    fn check_planned(&self, slots: usize) -> Result<(), RingRailError> {
        match self.payments.keys().find(|index| **index as usize >= slots) {
            Some(index) => Err(RingRailError::RingPaymentSlot {
                slot_index: *index as usize,
            }),
            None => Ok(()),
        }
    }
}

#[must_use]
#[derive(Clone)]
pub struct RingOutputRail {
    tx_viewing_key: ViewingKey,
    salt: Salt,
    delivery: RingDelivery,
}

#[derive(Clone, Copy)]
enum Slot {
    Ring {
        recipient: X25519Pubkey,
        tag: Option<RingTag>,
    },
    Exit,
    Dummy {
        tag: Option<RingTag>,
    },
    Compact,
}

impl RingOutputRail {
    /// A fresh salt per rail, a resent attempt under the same first nullifier repeats no keystream.
    pub fn new(tx_viewing_key: ViewingKey, delivery: RingDelivery) -> Self {
        Self {
            tx_viewing_key,
            salt: random_salt(),
            delivery,
        }
    }

    /// SPP's encryption fixes the slots and blindings, the rail then re-encodes every slot.
    pub fn encrypt(
        &self,
        transaction: ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<SppProofInputs, RingRailError> {
        let blinding_seed = self.blinding_seed()?;
        let transaction = match transaction.blinding_seed() == &blinding_seed {
            true => transaction,
            false => transaction.with_blinding_seed(blinding_seed)?,
        };
        let encoder = SppEncoder {
            rail: self,
            refusal: RefCell::new(None),
        };
        let encrypted = OutputEncryption {
            sender,
            tx_viewing_key: &self.tx_viewing_key,
            encoder: &encoder,
        }
        .encrypt(transaction);
        let mut inputs = match (encrypted, encoder.refusal.into_inner()) {
            (Err(_), Some(refusal)) => return Err(refusal),
            (encrypted, _) => encrypted?,
        };
        self.reencode(&mut inputs, sender)?;
        Ok(inputs)
    }

    /// Replaces every published slot with the rail's encoding under its salt.
    fn reencode(
        &self,
        inputs: &mut SppProofInputs,
        sender: &ShieldedAddress,
    ) -> Result<(), RingRailError> {
        let first_nullifier = inputs
            .input_utxos
            .first()
            .ok_or(TransactionError::NoInputs)?
            .nullifier();
        let tree_id = inputs.output_tree_id;
        let mut published = inputs.external_data.outputs.iter_mut();
        let mut resolved = inputs.external_data.resolved_owner_tags.iter();
        for (index, output) in inputs.output_utxos.iter_mut().enumerate() {
            if output.is_compact() {
                continue;
            }
            if matches!(self.delivery, RingDelivery::Anonymous(_))
                && output.ring_data_hash.is_some()
            {
                return Err(RingRailError::DeliveredOutputData { slot_index: index });
            }
            let framing = RingRailError::RingOutputFraming { slot_index: index };
            let slot_index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            let (transact_output, resolved) = published
                .next()
                .zip(resolved.next())
                .ok_or(RingRailError::RingOutputFraming { slot_index: index })?;
            let encoded = self.encode(&SlotEncode {
                output,
                sender,
                slot_index,
                first_nullifier,
                owner_tag: ResolvedOwnerTag {
                    tag: transact_output.owner_tag,
                    resolved: *resolved,
                },
            })?;
            if encoded.message.view_tag != *resolved {
                return Err(framing);
            }
            if let Some(ring_data_hash) = encoded.ring_data_hash {
                output.ring_data_hash = Some(ring_data_hash);
                transact_output.utxo_hash = output.hash(tree_id)?;
            }
            transact_output.data = Some(encoded.message.data);
        }
        inputs.external_data.salt = self.salt;
        Ok(())
    }

    /// A transaction padded before [`Self::encrypt`] takes the seed before its padding.
    pub fn blinding_seed(&self) -> Result<[u8; 32], RingRailError> {
        Ok(ring_blinding_seed(
            &self.tx_viewing_key.secret_bytes(),
            &self.salt,
        )?)
    }

    pub fn tx_viewing_key(&self) -> &ViewingKey {
        &self.tx_viewing_key
    }

    pub fn salt(&self) -> Salt {
        self.salt
    }

    pub fn delivery(&self) -> &RingDelivery {
        &self.delivery
    }

    /// The body key and ring data root of the delivered ring output at `slot_index`.
    pub fn slot_secret(
        &self,
        recipient: &X25519Pubkey,
        first_nullifier: &[u8; 32],
        slot_index: u32,
    ) -> Result<SlotSecret, RingRailError> {
        Ok(DeliveredSlot {
            agreement: &self.tx_viewing_key.ecdh(recipient)?,
            tx_viewing_pk: self.tx_viewing_key.pubkey().as_bytes(),
            recipient_viewing_pk: recipient.as_bytes(),
            salt: &self.salt,
            output_index: slot_index,
            first_nullifier,
        }
        .secret()?)
    }

    fn slot(
        &self,
        output: &SppProofOutputUtxo,
        sender: &ShieldedAddress,
        slot_index: u32,
    ) -> Result<Slot, RingRailError> {
        let index = slot_index as usize;
        let delivered = !matches!(self.delivery, RingDelivery::Packed);
        let anonymous = matches!(self.delivery, RingDelivery::Anonymous(_));
        if output.is_compact() {
            return match delivered {
                true => Err(RingRailError::DeliveredCompactPadding { slot_index: index }),
                false => Ok(Slot::Compact),
            };
        }
        // An anonymous output's ring data is the rail's own, checked where the rail sets it.
        let carries_data = !output.data.is_empty()
            || output.data_hash.is_some()
            || (output.ring_data_hash.is_some() && !anonymous);
        if delivered && !output.is_dummy() && carries_data {
            return Err(RingRailError::DeliveredOutputData { slot_index: index });
        }
        let owner = || {
            output
                .owner_address
                .map(|owner| owner.viewing_pubkey)
                .ok_or(RingRailError::Transaction(
                    TransactionError::OutputWithoutOwner { slot_index: index },
                ))
        };
        Ok(match &self.delivery {
            RingDelivery::Anonymous(slots) => match slots.slot(output, sender, slot_index)? {
                AnonymousSlot::Payment(payment) => Slot::Ring {
                    recipient: payment.recipient,
                    tag: Some(payment.tag),
                },
                AnonymousSlot::Change { tag } => Slot::Ring {
                    recipient: slots.change_key,
                    tag: Some(tag),
                },
                AnonymousSlot::Exit => Slot::Exit,
                AnonymousSlot::Dummy { tag } => Slot::Dummy { tag: Some(tag) },
            },
            RingDelivery::Packed | RingDelivery::Delivered => match output.is_dummy() {
                true => Slot::Dummy { tag: None },
                false if is_ring_output(output) => Slot::Ring {
                    recipient: owner()?,
                    tag: None,
                },
                false => Slot::Exit,
            },
        })
    }

    /// The published bytes of a slot through the ring program's own expansion.
    fn framed(
        output: RingOutput<'_>,
        owner_tag: &ResolvedOwnerTag,
        slot_index: usize,
    ) -> Result<MessageData, RingRailError> {
        let framing = || RingRailError::RingOutputFraming { slot_index };
        let expanded = output.transact_output();
        if expanded.owner_tag != owner_tag.tag {
            return Err(framing());
        }
        Ok(MessageData {
            view_tag: owner_tag.resolved,
            data: expanded.data.ok_or_else(framing)?,
        })
    }

    fn dummy_ciphertext(&self, slot: &SlotEncode<'_>) -> Result<Vec<u8>, RingRailError> {
        let plaintext = RingPackedPlaintext {
            asset_id: SOL_ASSET_ID,
            amount: 0,
            blinding: [0; 32],
            data: Data::default(),
        }
        .serialize()?;
        Ok(self.tx_viewing_key.encrypt_slot(
            &ViewingKey::new().pubkey(),
            &plaintext,
            self.salt,
            slot.slot_index,
        )?)
    }
}

impl RingOutputRail {
    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, RingRailError> {
        if let RingDelivery::Anonymous(slots) = &self.delivery {
            slots.check_planned(transaction.outputs().len())?;
        }
        let mut owner_tags = transaction.owner_tags(&sender.signing_pubkey)?;
        for (index, (output, owner_tag)) in transaction
            .outputs()
            .iter()
            .zip(&mut owner_tags)
            .enumerate()
        {
            let slot_index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            let resolved = match self.slot(output, sender, slot_index)? {
                Slot::Compact => continue,
                Slot::Exit => owner_tag.resolved,
                Slot::Ring { tag: Some(tag), .. } | Slot::Dummy { tag: Some(tag) } => tag.field(),
                Slot::Ring {
                    recipient,
                    tag: None,
                } => recipient.u(),
                // A random key publishes as a real recipient's would.
                Slot::Dummy { tag: None } => ViewingKey::new().pubkey().u(),
            };
            *owner_tag = ResolvedOwnerTag {
                tag: OwnerTag::Inline(resolved),
                resolved,
            };
        }
        Ok(owner_tags)
    }

    /// Scheme 3 to the exit's owner, under the rail's salt.
    fn exit_slot(&self, slot: &SlotEncode<'_>) -> Result<MessageData, RingRailError> {
        let output = slot.output;
        let owner = output
            .owner_address
            .ok_or(TransactionError::OutputWithoutOwner {
                slot_index: slot.slot_index as usize,
            })?;
        let plaintext = ConfidentialOutputPlaintext {
            asset_id: output.asset.asset_id,
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: output.ring_program_id,
            data: output.data.clone(),
        };
        Ok(Confidential::encode_plaintext(
            &plaintext,
            slot.owner_tag.resolved,
            &ConfidentialEncode {
                tx: self.tx_viewing_key.clone(),
                recipient_pubkey: owner.viewing_pubkey,
                salt: self.salt,
                slot_index: slot.slot_index,
            },
        )?)
    }

    fn encode(&self, slot: &SlotEncode<'_>) -> Result<EncodedSlot, RingRailError> {
        let slot_index = slot.slot_index as usize;
        // The expansion ignores the hash, only the published bytes are kept.
        let hash = [0; 32];
        let owner_tag = &slot.owner_tag;
        match self.slot(slot.output, slot.sender, slot.slot_index)? {
            Slot::Compact => Err(RingRailError::DeliveredCompactPadding { slot_index }),
            Slot::Exit => self.exit_slot(slot).map(EncodedSlot::from),
            Slot::Ring {
                recipient,
                tag: None,
            } if matches!(self.delivery, RingDelivery::Packed) => RingPacked::encode_plaintext(
                &RingPackedPlaintext::from(slot.output),
                owner_tag.resolved,
                &ConfidentialEncode {
                    tx: self.tx_viewing_key.clone(),
                    recipient_pubkey: recipient,
                    salt: self.salt,
                    slot_index: slot.slot_index,
                },
            )
            .map(EncodedSlot::from),
            Slot::Ring { recipient, tag } => {
                let secret =
                    self.slot_secret(&recipient, &slot.first_nullifier, slot.slot_index)?;
                let body = RingDeliveredBody {
                    blinding: slot.output.blinding,
                    amount: slot.output.amount,
                }
                .seal(&secret)?;
                let output = match tag {
                    Some(tag) => RingOutput::Anonymous {
                        hash: &hash,
                        tag,
                        body: &body,
                    },
                    None => RingOutput::Delivered {
                        hash: &hash,
                        u: &owner_tag.resolved,
                        body: &body,
                    },
                };
                Ok(EncodedSlot {
                    message: Self::framed(output, owner_tag, slot_index)?,
                    ring_data_hash: tag
                        .map(|tag| delivered_ring_data(&secret, Some(&tag)))
                        .transpose()?,
                })
            }
            Slot::Dummy { tag } => {
                let body = random_body();
                let ciphertext;
                let output = match (tag, &self.delivery) {
                    (Some(tag), _) => RingOutput::Anonymous {
                        hash: &hash,
                        tag,
                        body: &body,
                    },
                    (None, RingDelivery::Packed) => {
                        ciphertext = self.dummy_ciphertext(slot)?;
                        RingOutput::Packed {
                            hash: &hash,
                            u: &owner_tag.resolved,
                            ciphertext: &ciphertext,
                        }
                    }
                    (None, _) => RingOutput::Delivered {
                        hash: &hash,
                        u: &owner_tag.resolved,
                        body: &body,
                    },
                };
                Self::framed(output, owner_tag, slot_index).map(EncodedSlot::from)
            }
        }
    }
}

/// Ring data only on an anonymous ring output.
struct EncodedSlot {
    message: MessageData,
    ring_data_hash: Option<[u8; 32]>,
}

impl From<MessageData> for EncodedSlot {
    fn from(message: MessageData) -> Self {
        Self {
            message,
            ring_data_hash: None,
        }
    }
}

/// The pinned SPP encryption under the rail's owner tags, every slot re-encoded after it.
struct SppEncoder<'a> {
    rail: &'a RingOutputRail,
    refusal: RefCell<Option<RingRailError>>,
}

impl OutputEncoder for SppEncoder<'_> {
    fn owner_tags(
        &self,
        transaction: &ConfidentialTransaction,
        sender: &ShieldedAddress,
    ) -> Result<Vec<ResolvedOwnerTag>, TransactionError> {
        self.rail
            .owner_tags(transaction, sender)
            .map_err(|refusal| match refusal {
                RingRailError::Transaction(error) => error,
                refusal => {
                    let slots = transaction.outputs().len();
                    self.refusal.replace(Some(refusal));
                    TransactionError::OwnerTagCountMismatch {
                        got: 0,
                        expected: slots,
                    }
                }
            })
    }

    fn encode_slot(
        &self,
        plaintext: &ConfidentialOutputPlaintext,
        view_tag: [u8; 32],
        cx: &ConfidentialEncode,
    ) -> Result<MessageData, TransactionError> {
        Confidential::encode_plaintext(plaintext, view_tag, cx)
    }
}

pub struct SlotEncode<'a> {
    pub output: &'a SppProofOutputUtxo,
    pub sender: &'a ShieldedAddress,
    pub slot_index: u32,
    pub first_nullifier: [u8; 32],
    pub owner_tag: ResolvedOwnerTag,
}

fn is_ring_output(output: &SppProofOutputUtxo) -> bool {
    !output.is_dummy() && output.ring_program_id.is_some()
}

/// `low128` of a uniform field element, distributed as every stream-derived tag.
fn free_tag() -> RingTag {
    loop {
        let mut value = [0u8; 32];
        OsRng.fill_bytes(&mut value);
        // Uniform below 2^254, `from_field` rejects the draws at or above the modulus.
        value[0] &= 0x3f;
        if let Ok(tag) = RingTag::from_field(&value) {
            return tag;
        }
    }
}

fn random_body() -> [u8; RING_DELIVERED_BODY_LEN] {
    let mut body = [0u8; RING_DELIVERED_BODY_LEN];
    OsRng.fill_bytes(&mut body);
    body
}
