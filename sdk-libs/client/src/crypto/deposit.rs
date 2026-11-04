//! Deposits publish asset, amount and ring in the clear, only the blinding and memo stay sealed.

use borsh::BorshDeserialize;
use solana_address::Address;
use spr_event::{EncryptedRingDepositOutput, OutputDataEncoding, ENCRYPTED_RING_DEPOSIT_SCHEME};
use spr_event_parser::decode_encrypted_ring_deposit_output_data;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{ShieldedAddress, X25519Pubkey};
use spr_transaction::{
    AssetRegistry, DecryptLabel, DecryptRequest, DepositPayload, Mint, ShieldedKeys,
    ShieldedTransaction, TransactionError, WalletUtxo,
};
use zeroize::Zeroizing;
use zolana_ring_transaction::{is_contributory, RingDepositPlaintext};

use crate::{exactly_one, AnonymousError};

/// One deposit slot of a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDeposit {
    /// The note's owner tag, the account the value was shielded for.
    pub depositor: [u8; 32],
    pub asset: Address,
    pub amount: u64,
}

/// The deposits of `ring` in one indexed transaction, in slot order.
pub fn ring_deposits_in(
    slots: impl IntoIterator<Item = ([u8; 32], Vec<u8>)>,
    ring: Address,
) -> Vec<RingDeposit> {
    slots
        .into_iter()
        .filter_map(|(view_tag, payload)| deposit_of(&view_tag, &payload, ring))
        .collect()
}

fn deposit_of(view_tag: &[u8; 32], payload: &[u8], ring: Address) -> Option<RingDeposit> {
    let OutputDataEncoding::Encrypted(blob) = OutputDataEncoding::try_from_slice(payload).ok()?
    else {
        return None;
    };
    let (&ENCRYPTED_RING_DEPOSIT_SCHEME, body) = blob.split_first()? else {
        return None;
    };
    let output = EncryptedRingDepositOutput::try_from_slice(body).ok()?;
    (output.ring_program_id == ring.to_bytes()).then(|| RingDeposit {
        depositor: *view_tag,
        asset: Address::new_from_array(output.asset),
        amount: output.amount,
    })
}

pub(crate) struct DepositOpener<'a, K: ?Sized> {
    pub keys: &'a K,
    pub address: &'a ShieldedAddress,
    pub assets: &'a AssetRegistry,
    pub deposit_payload: DepositPayload,
}

pub(crate) struct DepositSlot<'a> {
    pub deposit: &'a ShieldedTransaction,
    pub position: usize,
    pub viewing_pubkey: X25519Pubkey,
}

pub(crate) enum OpenedDeposit {
    Note(Box<WalletUtxo>),
    /// Its hash rebuilt under a mint the registry does not name, the asset id zero.
    UnknownMint(Box<WalletUtxo>),
}

impl<K: ShieldedKeys + ?Sized> DepositOpener<'_, K> {
    /// Deposits of any ring among `transactions` under a held viewing key's tag, nullifiers unset.
    pub(crate) fn open_held(
        &self,
        transactions: &[ShieldedTransaction],
    ) -> Result<Vec<OpenedDeposit>, AnonymousError> {
        let held = self.keys.viewing_public_keys();
        let mut opened = Vec::new();
        for deposit in transactions {
            for (position, slot) in deposit.output_slots.iter().enumerate() {
                let Some(&viewing_pubkey) = held.iter().find(|key| key.u() == slot.view_tag) else {
                    continue;
                };
                opened.extend(self.open(DepositSlot {
                    deposit,
                    position,
                    viewing_pubkey,
                })?);
            }
        }
        Ok(opened)
    }

    /// A deposit's published hash, not its decryption, proves it the owner's.
    pub(crate) fn open(
        &self,
        slot: DepositSlot<'_>,
    ) -> Result<Option<OpenedDeposit>, AnonymousError> {
        let DepositSlot {
            deposit,
            position,
            viewing_pubkey,
        } = slot;
        let slot = &deposit.output_slots[position];
        let context = &slot.output_context;
        let Ok(output) = decode_encrypted_ring_deposit_output_data(&slot.payload) else {
            return Ok(None);
        };
        let Ok(tx_viewing_pubkey) = X25519Pubkey::from_bytes(output.encrypted.tx_viewing_pk) else {
            return Ok(None);
        };
        if !is_contributory(&tx_viewing_pubkey) {
            return Ok(None);
        }
        let ciphertext = match (self.deposit_payload)(&output.encrypted.ciphertext) {
            Ok(wrapped) => wrapped.unwrap_or(&output.encrypted.ciphertext),
            Err(_) => return Ok(None),
        };
        let request = DecryptRequest {
            ciphertext,
            viewing_pubkey,
            tx_viewing_pubkey,
            salt: output.encrypted.salt,
            slot_index: 0,
            label: DecryptLabel::RingDeposit,
        };
        let plaintext = Zeroizing::new(exactly_one(self.keys.decrypt(&[request])?)?);
        let Ok(plaintext) = RingDepositPlaintext::deserialize(&plaintext) else {
            return Ok(None);
        };
        let mint = Address::new_from_array(output.asset);
        let (asset, registered) = match self.assets.mint(&mint) {
            Ok(asset) => (asset, true),
            // The commitment reads the mint alone.
            Err(TransactionError::UnknownMint(mint)) => (
                Mint {
                    asset: mint,
                    asset_id: 0,
                },
                false,
            ),
            Err(_) => return Ok(None),
        };
        let utxo = plaintext.into_utxo(
            self.address.signing_pubkey,
            asset,
            output.amount,
            Address::new_from_array(output.ring_program_id),
        );
        let data_hash = output.data_hash.unwrap_or_default();
        // Utxo data under a zero data hash is unbound.
        if utxo.data.utxo_data().is_some() && data_hash == [0; 32] {
            return Ok(None);
        }
        // An enrollment finalizes the key for later notes and leaves a zero-key commitment valid, so only the
        // published commitment selects the key, never the current tracking record. A third key rebuilds nothing.
        let Some(nullifier_pubkey) = [self.address.nullifier_pubkey, ZERO_NULLIFIER_PUBKEY]
            .into_iter()
            .find(|candidate| {
                utxo.hash(
                    candidate,
                    &data_hash,
                    &output.ring_data_hash,
                    context.tree_id,
                )
                .is_ok_and(|hash| hash == context.hash)
            })
        else {
            return Ok(None);
        };
        let opened = Box::new(WalletUtxo {
            utxo,
            nullifier_pubkey,
            utxo_hash: context.hash,
            nullifier: [0; 32],
            tx_viewing_key: None,
            data_hash: output.data_hash,
            ring_data_hash: Some(output.ring_data_hash),
            tree_id: context.tree_id,
            leaf_index: context.leaf_index,
            latest_tree_id: None,
            slot: deposit.slot,
            tx_signature: deposit.tx_signature,
            slot_index: u32::try_from(position).map_err(|_| TransactionError::TooManyOutputs)?,
        });
        Ok(Some(match registered {
            true => OpenedDeposit::Note(opened),
            false => OpenedDeposit::UnknownMint(opened),
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use custom_ring_interface::RingDepositAuditCapsule;
    use solana_signature::Signature;
    use spr_client::{EncryptedUtxoMatch, OutputContext, OutputSlot};
    use spr_event::{encode_encrypted_ring_deposit_output, EncryptedRingDepositOutput};
    use spr_keypair::{hash::owner_hash, ShieldedKeypair, SigningKey, ViewingKey};
    use spr_transaction::{owner_utxo_hash, Utxo};
    use zolana_ring_transaction::{RingAssets, RingDepositPlaintext};

    use super::*;
    use crate::deposit_payload;

    pub(crate) const RING: Address = Address::new_from_array([0x90; 32]);
    pub(crate) const TREE: u16 = 9;
    pub(crate) const AMOUNT: u64 = 25;
    /// Canonical and neither the wallet's key nor zero.
    pub(crate) const THIRD_KEY: [u8; 32] = [0x11; 32];

    pub(crate) fn wallet(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
    }

    pub(crate) fn ring_note(owner: &ShieldedAddress, blinding: [u8; 32]) -> Utxo {
        Utxo {
            owner: owner.signing_pubkey,
            asset: Mint::SOL,
            amount: AMOUNT,
            blinding,
            ring_program_id: Some(RING),
            data: Default::default(),
        }
    }

    /// A deposit to `owner` under its bootstrap tag, its commitment under `nullifier_pk`.
    pub(crate) fn deposit_under(
        owner: &ShieldedAddress,
        nullifier_pk: &[u8; 32],
        blinding: [u8; 32],
    ) -> EncryptedUtxoMatch {
        let encrypted = RingDepositPlaintext {
            blinding,
            utxo_data: None,
            memo: None,
            ring_data: Vec::new(),
        }
        .encrypt(&owner.viewing_pubkey)
        .unwrap();
        let payload = encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
            owner_utxo_hash: owner_utxo_hash(
                &owner_hash(&owner.signing_pubkey, nullifier_pk).unwrap(),
                &blinding,
            )
            .unwrap(),
            asset: Mint::SOL.asset.to_bytes(),
            amount: AMOUNT,
            data_hash: None,
            ring_program_id: RING.to_bytes(),
            ring_data_hash: [0; 32],
            encrypted,
        });
        let hash = ring_note(owner, blinding)
            .hash(nullifier_pk, &[0; 32], &[0; 32], TREE)
            .unwrap();
        EncryptedUtxoMatch {
            slot: 1,
            tx_signature: Signature::from([blinding[31]; 64]),
            output_slot: OutputSlot {
                view_tag: owner.viewing_pubkey.u(),
                output_context: OutputContext {
                    hash,
                    tree_id: TREE,
                    leaf_index: 0,
                },
                payload,
            },
            tx_viewing_pk: None,
            salt: None,
        }
    }

    /// The row a ring's history serves for `deposit`.
    pub(crate) fn ring_row(deposit: EncryptedUtxoMatch) -> ShieldedTransaction {
        ShieldedTransaction {
            ring_program_id: Some(RING),
            ..deposit.into_proofless_transaction().unwrap()
        }
    }

    /// The note `owner` opens from a deposit committed under `nullifier_pk`.
    fn opened_under(nullifier_pk: &[u8; 32]) -> Option<WalletUtxo> {
        let owner = wallet(7);
        let address = owner.shielded_address().unwrap();
        let row = ring_row(deposit_under(&address, nullifier_pk, [0x12; 32]));
        let assets = RingAssets::new([]).unwrap();
        let mut opened = DepositOpener {
            keys: &owner,
            address: &address,
            assets: assets.registry(),
            deposit_payload,
        }
        .open_held(core::slice::from_ref(&row))
        .unwrap();
        opened.pop().map(|deposit| match deposit {
            OpenedDeposit::Note(utxo) | OpenedDeposit::UnknownMint(utxo) => *utxo,
        })
    }

    #[test]
    fn a_deposit_committed_under_zero_opens_under_zero_for_an_enrolled_address() {
        let note = opened_under(&ZERO_NULLIFIER_PUBKEY).unwrap();
        assert_eq!(note.nullifier_pubkey, ZERO_NULLIFIER_PUBKEY);
        assert_eq!(note.utxo.amount, AMOUNT);
    }

    #[test]
    fn a_deposit_committed_under_the_address_key_keeps_that_key() {
        let key = wallet(7).shielded_address().unwrap().nullifier_pubkey;
        assert_eq!(opened_under(&key).unwrap().nullifier_pubkey, key);
    }

    #[test]
    fn a_deposit_committed_under_a_third_key_opens_nothing() {
        assert_eq!(opened_under(&THIRD_KEY), None);
    }

    #[test]
    fn recipient_opens_plain_and_auditor_wrapped_ciphertexts() {
        let recipient = ViewingKey::new();
        let plaintext = RingDepositPlaintext {
            blinding: [7; 32],
            utxo_data: Some(vec![1, 2]),
            memo: Some(vec![3]),
            ring_data: vec![4],
        };
        let mut encrypted = plaintext.encrypt(&recipient.pubkey()).unwrap();
        assert_eq!(
            RingDepositPlaintext::decrypt(&encrypted, &recipient).unwrap(),
            plaintext
        );
        assert_eq!(deposit_payload(&encrypted.ciphertext).unwrap(), None);
        encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: 7,
            eph_pk: &[2; 33],
            ciphertext: &[3; custom_ring_interface::RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
            recipient_ciphertext: &encrypted.ciphertext,
        }
        .encode();
        let wrapped = encrypted.ciphertext.clone();
        encrypted.ciphertext = deposit_payload(&wrapped).unwrap().unwrap().to_vec();
        assert_eq!(
            RingDepositPlaintext::decrypt(&encrypted, &recipient).unwrap(),
            plaintext
        );
        assert!(deposit_payload(
            &wrapped[..custom_ring_interface::RING_DEPOSIT_AUDIT_PREFIX_LEN - 1]
        )
        .is_err());
    }
}
