//! Scheme 11, a packed custom ring slot, its ring id read from the transaction.

use custom_ring_interface::{encode_ring_confidential_packed_output, RECIPIENT_KEY_LEN};
use wincode::{SchemaRead, SchemaWrite};
use spr_event::MessageData;
use spr_keypair::{constants::SALT_LEN, ViewingKey};
use spr_transaction::{
    serialization::confidential::{Confidential, ConfidentialEncode},
    Data, DecodeCx, SppProofOutputUtxo, TransactionError, UtxoSerialization,
};

use crate::RingRailError;

#[derive(SchemaWrite, SchemaRead, Clone, Debug, PartialEq, Eq)]
pub struct RingPackedPlaintext {
    pub asset_id: u64,
    pub amount: u64,
    pub blinding: [u8; 32],
    pub data: Data,
}

impl RingPackedPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        self.data.validate()?;
        Ok(wincode::serialize(self)?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let parsed: Self = wincode::deserialize_exact(bytes)?;
        parsed.data.validate()?;
        Ok(parsed)
    }
}

impl From<&SppProofOutputUtxo> for RingPackedPlaintext {
    fn from(output: &SppProofOutputUtxo) -> Self {
        Self {
            asset_id: output.asset.asset_id,
            amount: output.amount,
            blinding: output.blinding,
            data: output.data.clone(),
        }
    }
}

/// The scheme 3 key schedule and body, `recipient_pk || ciphertext`.
pub struct RingPacked;

impl RingPacked {
    /// The scheme 11 slot of `plaintext`, published under `view_tag`.
    pub fn encode_plaintext(
        plaintext: &RingPackedPlaintext,
        view_tag: [u8; 32],
        cx: &ConfidentialEncode,
    ) -> Result<MessageData, RingRailError> {
        let body = Confidential::encrypt(&plaintext.serialize()?, cx)?;
        let (key, ciphertext) = body
            .split_first_chunk::<RECIPIENT_KEY_LEN>()
            .ok_or(TransactionError::MissingOutput)?;
        Ok(MessageData {
            view_tag,
            data: encode_ring_confidential_packed_output(key, ciphertext),
        })
    }

    /// The owner's opening of a scheme 11 body, `body` the bytes after the scheme byte.
    pub fn decode(body: &[u8], cx: &DecodeCx) -> Result<RingPackedPlaintext, TransactionError> {
        RingPackedPlaintext::deserialize(&Confidential::decrypt(body, cx)?)
    }

    pub fn decrypt_with_tx_key(
        tx: &ViewingKey,
        body: &[u8],
        salt: [u8; SALT_LEN],
        slot_index: u32,
    ) -> Result<RingPackedPlaintext, TransactionError> {
        let recipient_pubkey = Confidential::embedded_viewing_pk(body)?;
        let ciphertext = body
            .get(RECIPIENT_KEY_LEN..)
            .ok_or(TransactionError::InvalidLength {
                expected: RECIPIENT_KEY_LEN,
                actual: body.len(),
            })?;
        let bytes = tx.decrypt_slot_ephemeral(&recipient_pubkey, ciphertext, salt, slot_index)?;
        RingPackedPlaintext::deserialize(&bytes)
    }
}
