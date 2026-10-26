//! The slots a sealed ring transfer publishes, in the compact form the ring program expands.

use custom_ring_interface::{
    ring_anonymous_output_body, ring_confidential_delivered_output_body, stream::RingTag,
    RingOutput,
};
use zolana_event::confidential_encrypted_output_body;
use zolana_interface::instruction::instruction_data::transact::{OwnerTag, TransactOutput};
use zolana_keypair::{ShieldedAddress, X25519Pubkey};
use zolana_transaction::{
    instructions::transact::SppProofInputs, SppProofOutputUtxo, TransactionError,
};

use crate::{AnonymousSlot, RingDelivery, RingOutputRail, RingRailError, Slot};

#[derive(Clone, Copy, Debug)]
pub struct PublishedSlot<'a> {
    pub output: &'a SppProofOutputUtxo,
    pub wire: RingOutput<'a>,
    /// The key a delivered or anonymous ring output's body opens under.
    pub recipient: Option<X25519Pubkey>,
    /// Set on the anonymous rail.
    pub anonymous: Option<AnonymousSlot>,
}

impl RingOutputRail {
    /// Every published slot in order, each expanding to exactly the output the SPP proof binds.
    pub fn published_slots<'a>(
        &self,
        inputs: &'a SppProofInputs,
        sender: &ShieldedAddress,
    ) -> Result<Vec<PublishedSlot<'a>>, RingRailError> {
        let mut published = inputs.external_data.outputs.iter();
        let mut slots = Vec::with_capacity(inputs.external_data.outputs.len());
        for (index, output) in inputs.output_utxos.iter().enumerate() {
            let framing = RingRailError::RingOutputFraming { slot_index: index };
            let slot_index = u32::try_from(index).map_err(|_| TransactionError::TooManyOutputs)?;
            let slot = self.slot(output, sender, slot_index)?;
            let anonymous = match &self.delivery {
                RingDelivery::Anonymous(plan) => Some(plan.slot(output, sender, slot_index)?),
                RingDelivery::Delivered => None,
            };
            let recipient = match slot {
                Slot::Ring { recipient, .. } => Some(recipient),
                Slot::Exit | Slot::Dummy { .. } => None,
            };
            slots.push(PublishedSlot {
                output,
                wire: self.wire(slot, published.next().ok_or(framing)?, index)?,
                recipient,
                anonymous,
            });
        }
        match published.next() {
            Some(_) => Err(RingRailError::RingOutputFraming {
                slot_index: inputs.output_utxos.len(),
            }),
            None => Ok(slots),
        }
    }

    /// The round trip through the program's expansion refuses any other framing.
    fn wire<'a>(
        &self,
        slot: Slot,
        published: &'a TransactOutput,
        slot_index: usize,
    ) -> Result<RingOutput<'a>, RingRailError> {
        let framing = || RingRailError::RingOutputFraming { slot_index };
        let OwnerTag::Inline(owner_tag) = &published.owner_tag else {
            return Err(framing());
        };
        let data = published.data.as_deref().ok_or_else(framing)?;
        let hash = &published.utxo_hash;
        let wire = match (slot, &self.delivery) {
            (Slot::Exit, _) => RingOutput::Exit {
                hash,
                owner_tag,
                payload: confidential_encrypted_output_body(data).ok_or_else(framing)?,
            },
            (_, RingDelivery::Delivered) => RingOutput::Delivered {
                hash,
                u: owner_tag,
                body: ring_confidential_delivered_output_body(data).ok_or_else(framing)?,
            },
            (_, RingDelivery::Anonymous(_)) => RingOutput::Anonymous {
                hash,
                tag: RingTag::from_owner_tag(owner_tag).ok_or_else(framing)?,
                body: ring_anonymous_output_body(data).ok_or_else(framing)?,
            },
        };
        if wire.transact_output() != *published {
            return Err(framing());
        }
        Ok(wire)
    }
}
