//! Compact ring frames expand into canonical SPP bytes for settlement and external data hashing.
//!
//! Read after `program-libs/interface/src/instructions/transact.rs` and `program-libs/interface/src/codec/output.rs`.
//! Read before `programs/custom-ring/src/instructions/transfer/processor.rs`.

use spr_interface::instruction::{
    ExternalDataPreimage, InputUtxo, MessageData, OutputDataRef, OwnerTag, SegmentedBytes,
    TransactExternalDataRef, TransactIxData, TransactIxDataRef, TransactOutput, TransactOutputRef,
    TransactProof,
};

use super::{RingOutput, RingTransactData, Settlement, SlotBody, invalid};
use crate::{
    AuditorMessage, RingPolicy,
    error::CustomRingError,
    output::{OutputPayload, encode_ring_sender_bundle_output},
    tagged_x25519,
};

struct SppExpansion<'frame, 'data> {
    frame: &'frame RingTransactData<'data>,
    ring: &'frame RingPolicy,
    proof: TransactProof,
}

struct EncodedSppInstruction {
    data: Vec<u8>,
    external_data_prefix_len: usize,
}

impl<'a> RingOutput<'a> {
    pub fn transact_output(&self, reply: &[u8]) -> Result<TransactOutput, CustomRingError> {
        Ok(TransactOutput {
            utxo_hash: *self.hash,
            owner_tag: OwnerTag::Inline(self.owner_tag),
            data: self.payload(reply).map(OutputPayload::encode).transpose()?,
        })
    }

    fn payload<'reply>(&self, reply: &'reply [u8]) -> Option<OutputPayload<'reply>>
    where
        'a: 'reply,
    {
        match self.body {
            SlotBody::None => None,
            SlotBody::Recipient(body) => Some(OutputPayload::Recipient { body, reply }),
            SlotBody::Exit(body) => Some(OutputPayload::Confidential(body)),
        }
    }
}

impl RingTransactData<'_> {
    pub fn auditor_message(&self) -> Vec<u8> {
        AuditorMessage::data(self.tx_viewing_u, self.auditor_ciphertexts())
    }

    /// The SPP data the program forwards, `b` decompressed for SPP's verifier.
    pub fn expand(&self, ring: &RingPolicy) -> Result<TransactIxData, CustomRingError> {
        self.transact_ix_data(ring, self.spp_proof_points()?)
    }

    pub fn spp_instruction_data(&self, ring: &RingPolicy) -> Result<Vec<u8>, CustomRingError> {
        self.spp_instruction_data_under(ring, self.spp_proof_points()?)
    }

    fn spp_proof_points(&self) -> Result<TransactProof, CustomRingError> {
        let b = groth16_solana::decompression::decompress_g2(&self.spp_proof.proof_b)
            .map_err(|_| CustomRingError::InvalidSppProofPoint)?;
        Ok(TransactProof {
            a: self.spp_proof.proof_a,
            b,
            c: self.spp_proof.proof_c,
        })
    }

    /// The tag and the expansion under `proof` in one buffer, the program's heap holds no second copy.
    pub fn spp_instruction_data_under(
        &self,
        ring: &RingPolicy,
        proof: TransactProof,
    ) -> Result<Vec<u8>, CustomRingError> {
        Ok(SppExpansion {
            frame: self,
            ring,
            proof,
        }
        .encode()?
        .data)
    }

    /// The external data hash the SPP proof binds, computable before either proof exists.
    pub fn external_data_hash(
        &self,
        ring: &RingPolicy,
        settlements: &[Settlement<'_>],
    ) -> Result<[u8; 32], CustomRingError> {
        SppExpansion {
            frame: self,
            ring,
            proof: TransactProof::zeroed(),
        }
        .encode()?
        .external_data_hash(settlements)
    }

    /// The expansion under `proof`, a client sizes the transaction with a zeroed one.
    pub fn transact_ix_data(
        &self,
        ring: &RingPolicy,
        proof: TransactProof,
    ) -> Result<TransactIxData, CustomRingError> {
        self.validate_under(self.audit_stream()?)?;
        // The auditor's `u` without its tag, the program takes it from the account and a frame names no reader.
        let view_tag = auditor_tag(ring);
        Ok(TransactIxData {
            expiry_unix_ts: u64::from(self.expiry_unix_ts),
            tx_viewing_pk: tagged_x25519(self.tx_viewing_u),
            salt: *self.salt,
            interface_transfers: self.interface_transfers.clone(),
            data_hash: self.extensions.data_hash.copied(),
            ring_data_hash: self.extensions.ring_data_hash.copied(),
            outputs: {
                let mut outputs = Vec::with_capacity(self.outputs.len());
                for (output, reply) in self.outputs.iter().zip(self.slot_replies()) {
                    outputs.push(output.transact_output(reply)?);
                }
                outputs
            },
            // The auditor message stays last.
            messages: self
                .sender
                .map(|sender| {
                    encode_ring_sender_bundle_output(sender.body).map(|data| MessageData {
                        view_tag: *sender.tag,
                        data,
                    })
                })
                .transpose()?
                .into_iter()
                .chain(self.extensions.messages.iter().map(|message| MessageData {
                    view_tag: *message.view_tag,
                    data: message.data.to_vec(),
                }))
                .chain([MessageData {
                    view_tag,
                    data: self.auditor_message(),
                }])
                .collect(),
            private_tx_hash: *self.private_tx_hash,
            circuit: self.circuit(),
            proof,
            inputs: self.input_utxos().collect(),
            tree_contexts: self.input_trees.contexts(),
        })
    }

    fn input_utxos(&self) -> impl Iterator<Item = InputUtxo> + '_ {
        self.nullifiers
            .iter()
            .enumerate()
            .map(|(input, nullifier)| InputUtxo {
                nullifier_hash: *nullifier,
                tree_index: self.input_trees.tree_index(input),
            })
    }

    fn auditor_ciphertexts(&self) -> impl Iterator<Item = &[u8]> + Clone {
        let records = self.outputs.iter().map(|output| &output.record[..]);
        let tails = self
            .outputs
            .iter()
            .filter_map(|output| output.tail.map(|tail| &tail[..]));
        core::iter::once(self.envelope).chain(records).chain(tails)
    }
}

impl SppExpansion<'_, '_> {
    fn encode(self) -> Result<EncodedSppInstruction, CustomRingError> {
        let frame = self.frame;
        // 1. Frame validation binds section lengths to the audit layout and reply count to recipient slots.
        frame.validate_under(frame.audit_stream()?)?;
        // 2. Reply chunks follow recipient slots only, after each body and outside its inner length.
        // The complete framed payload must fit SPP's `u16` data length.
        let mut output_headers = Vec::with_capacity(frame.outputs.len());
        for (output, reply) in frame.outputs.iter().zip(frame.slot_replies()) {
            output_headers.push(
                output
                    .payload(reply)
                    .map(OutputPayload::header)
                    .transpose()?,
            );
        }
        let output_segments = frame
            .outputs
            .iter()
            .zip(frame.slot_replies())
            .zip(&output_headers)
            .map(|((output, reply), header)| {
                output
                    .payload(reply)
                    .zip(header.as_ref())
                    .map(|(payload, header)| payload.segments(header))
            })
            .collect::<Vec<_>>();
        let mut outputs = Vec::with_capacity(frame.outputs.len());
        for (output, segments) in frame.outputs.iter().zip(&output_segments) {
            outputs.push(TransactOutputRef {
                utxo_hash: output.hash,
                owner_tag: OwnerTag::Inline(output.owner_tag),
                data: segments
                    .as_ref()
                    .map(|segments| SegmentedBytes::new(segments))
                    .transpose()
                    .map_err(invalid)?,
            });
        }
        let sender_payload = frame
            .sender
            .map(|sender| OutputPayload::SenderBundle(sender.body));
        let sender_header = sender_payload.map(OutputPayload::header).transpose()?;
        let sender_segments = sender_payload
            .zip(sender_header.as_ref())
            .map(|(payload, header)| payload.segments(header));
        let application_segments = frame
            .extensions
            .messages
            .iter()
            .map(|message| [message.data])
            .collect::<Vec<_>>();
        // 3. The auditor payload binds the tagged viewing key, envelope, all output records, then data tails in slot order.
        let tx_viewing_pk = tagged_x25519(frame.tx_viewing_u);
        let mut auditor_segments =
            Vec::with_capacity(2 + frame.outputs.len() * (1 + usize::from(frame.has_data)));
        auditor_segments.push(&tx_viewing_pk[..]);
        auditor_segments.extend(frame.auditor_ciphertexts());
        let auditor_tag = auditor_tag(self.ring);
        // 4. SPP receives the optional sender, application messages, then the auditor message under the ring's auditor tag.
        let mut messages = Vec::with_capacity(
            frame.extensions.messages.len() + 1 + usize::from(frame.sender.is_some()),
        );
        if let Some((sender, segments)) = frame.sender.zip(sender_segments.as_ref()) {
            messages.push(OutputDataRef {
                view_tag: sender.tag,
                data: SegmentedBytes::new(segments).map_err(invalid)?,
            });
        }
        for (message, segments) in frame.extensions.messages.iter().zip(&application_segments) {
            messages.push(OutputDataRef {
                view_tag: message.view_tag,
                data: SegmentedBytes::new(segments).map_err(invalid)?,
            });
        }
        messages.push(OutputDataRef {
            view_tag: &auditor_tag,
            data: SegmentedBytes::new(&auditor_segments).map_err(invalid)?,
        });
        // 5. The SPP schema owns the external data boundary through messages, before `private_tx_hash` and the proof suffix.
        let expanded = TransactIxDataRef {
            external_data: TransactExternalDataRef {
                expiry_unix_ts: u64::from(frame.expiry_unix_ts),
                tx_viewing_pk: &tx_viewing_pk,
                salt: frame.salt,
                interface_transfers: frame.interface_transfers.clone(),
                data_hash: frame.extensions.data_hash.copied(),
                ring_data_hash: frame.extensions.ring_data_hash.copied(),
                outputs,
                messages,
            },
            private_tx_hash: frame.private_tx_hash,
            circuit: frame.circuit(),
            proof: self.proof,
            inputs: frame.input_utxos().collect(),
            tree_contexts: frame.input_trees.contexts(),
        };
        let size = expanded.serialized_size().map_err(invalid)?;
        let external_data_prefix_len = expanded.external_data_prefix_len().map_err(invalid)?;
        let instruction_len = size
            .checked_add(1)
            .ok_or(CustomRingError::InvalidInstructionData)?;
        let mut data = vec![0; instruction_len];
        data[0] = frame.rail.spp_tag();
        expanded.serialize_into(&mut data[1..]).map_err(invalid)?;
        Ok(EncodedSppInstruction {
            data,
            external_data_prefix_len,
        })
    }
}

impl EncodedSppInstruction {
    fn external_data_hash(
        &self,
        settlements: &[Settlement<'_>],
    ) -> Result<[u8; 32], CustomRingError> {
        // 1. The SPP instruction discriminator precedes the exact serialized prefix through messages.
        let tag = [self.data[0]];
        let prefix = &self.data[1..1 + self.external_data_prefix_len];
        let mut preimage = ExternalDataPreimage::new(&tag, prefix);
        // 2. The caller must supply settlements in transfer order. Each pair binds asset then user after the prefix.
        // Inline owner tags are already in the prefix.
        for settlement in settlements {
            preimage.push_settlement(settlement.asset_account, settlement.user_account)?;
        }
        Ok(preimage.finish()?)
    }
}

fn auditor_tag(ring: &RingPolicy) -> [u8; 32] {
    core::array::from_fn(|index| ring.auditor_pubkey[index + 1])
}
