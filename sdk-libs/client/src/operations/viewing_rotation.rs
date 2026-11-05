//! A wallet's viewing key rotation through zolana's `UserRecord`.
//!
//! Read before `viewing_key`, whose resolver confirms the record once the update lands. Read
//! after `RotatingRingKeys` and `ViewingHistory`, the two halves of a wallet a rotation moves
//! together.
//!
//! A rotation runs in two steps. [`ViewingRotation::rotate`] is local, and the wallet stores the
//! new viewing secret and the rotated history before [`UpdateViewingKey::send`] publishes the key.
//! A record naming a key the wallet lost routes every later payment to notes nobody opens. A
//! wallet that stops between the steps already holds and scans the new key, and a repeated send
//! publishes it. The record holds only the current key, the history keeps every earlier one, and
//! notes sealed to an earlier key open through it.

use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{
    sign_transaction, user_registry::build_key_update_transaction, AsyncRpc, ClientError,
};
use spr_keypair::{ViewingKey, X25519Pubkey};
use spr_transaction::{ShieldedKeys, TransactionError};
use thiserror::Error;
use zolana_ring_keys::{RingKeyError, RotatingRingKeys};

use crate::{AnonymousError, ViewingHistory, ViewingKeyError, ViewingKeyResolver};

/// [`Self::rotate`] moves both to one current key.
#[must_use]
pub struct ViewingRotation {
    pub keys: RotatingRingKeys,
    pub history: ViewingHistory,
}

/// Publishes the holder's current viewing key in the owner's `UserRecord`, the payer may be the owner.
#[must_use]
pub struct UpdateViewingKey<'a> {
    pub owner: &'a (dyn Signer + Sync),
    pub payer: &'a (dyn Signer + Sync),
    pub keys: &'a RotatingRingKeys,
    pub history: &'a ViewingHistory,
}

/// The record held `viewing_pubkey` at the confirming read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdatedViewingKey {
    /// `None` when the record already held the key.
    pub signature: Option<Signature>,
    pub viewing_pubkey: X25519Pubkey,
}

#[derive(Debug, Error)]
pub enum ViewingRotationError {
    #[error(transparent)]
    Keys(#[from] RingKeyError),
    #[error(transparent)]
    History(#[from] AnonymousError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Record(#[from] ViewingKeyError),
    #[error("the viewing history's current key differs from the key holder's")]
    HistoryNotCurrent,
    #[error("the user record does not hold the rotated viewing key")]
    NotPublished,
}

impl ViewingRotation {
    /// `next` becomes current in both, every earlier key stays held and scanned.
    pub fn rotate(self, next: ViewingKey, rotated_at: i64) -> Result<Self, ViewingRotationError> {
        let history = self.history.with_rotated_key(next.pubkey(), rotated_at)?;
        let keys = self.keys.rotate(next)?;
        Ok(Self { keys, history })
    }
}

impl UpdateViewingKey<'_> {
    pub async fn send<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<UpdatedViewingKey, ViewingRotationError> {
        // 1. No sync reads a key the history lacks. Publishing one routes payments to notes the
        //    wallet never finds.
        let address = self.keys.address()?;
        if self.history.current().viewing_pubkey() != address.viewing_pubkey {
            return Err(ViewingRotationError::HistoryNotCurrent);
        }
        // 2. zolana's builder refuses a missing record and a changed nullifier key, and the
        //    program refuses the changed key again. `None` is a record that already holds the
        //    key, the case of a send repeated after its update landed.
        let owner = self.owner.pubkey();
        let message =
            build_key_update_transaction(rpc, owner, &address, Some(self.payer.pubkey())).await?;
        let signature = match message {
            Some(message) => {
                let signers: [&dyn Signer; 2] = [self.owner, self.payer];
                Some(
                    rpc.process_transaction(sign_transaction(message, &signers)?)
                        .await?,
                )
            }
            None => None,
        };
        // 3. Senders read the record. A concurrent `UPDATE_KEYS` of the owner can leave it at
        //    another key than the one the send carried.
        let resolved = ViewingKeyResolver::new(owner)
            .with_credential(address.nullifier_pubkey)
            .resolve(rpc)
            .await?;
        match resolved {
            Some(resolved) if resolved.viewing_pubkey == address.viewing_pubkey => {
                Ok(UpdatedViewingKey {
                    signature,
                    viewing_pubkey: address.viewing_pubkey,
                })
            }
            _ => Err(ViewingRotationError::NotPublished),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use borsh::{BorshDeserialize, BorshSerialize};
    use solana_account::Account;
    use solana_address::Address;
    use solana_hash::Hash;
    use solana_keypair::Keypair;
    use solana_transaction::versioned::VersionedTransaction;
    use spr_keypair::{shielded::ShieldedKeypair, SigningKey};
    use spr_transaction::{DecryptLabel, DecryptRequest};
    use spr_user_registry_interface::{
        instruction::{discriminator, UpdateKeysData},
        user_record_pda, user_registry_program_id, MergeEncryptionScheme, UserRecord,
    };

    use super::*;

    /// One user record, `UPDATE_KEYS` replaces its viewing key.
    struct Registry {
        record: Mutex<UserRecord>,
        sent: Mutex<Vec<UpdateKeysData>>,
    }

    impl Registry {
        fn holding(owner: &Keypair, identity: &ShieldedKeypair) -> Self {
            let owner = owner.pubkey();
            Self {
                record: Mutex::new(UserRecord {
                    owner,
                    bump: user_record_pda(&owner).1,
                    nullifier_pubkey: identity.shielded_address().unwrap().nullifier_pubkey,
                    viewing_pubkey: *identity.viewing_pubkey().as_bytes(),
                    merge_encryption: MergeEncryptionScheme::Disabled,
                }),
                sent: Mutex::default(),
            }
        }

        fn sent(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl AsyncRpc for Registry {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            let record = self.record.lock().unwrap();
            if address != user_record_pda(&record.owner).0 {
                return Ok(None);
            }
            let mut data = vec![UserRecord::DISCRIMINATOR];
            record.serialize(&mut data).unwrap();
            Ok(Some(Account {
                data,
                owner: user_registry_program_id(),
                ..Account::default()
            }))
        }

        async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
            Ok((Hash::default(), 0))
        }

        async fn process_transaction(
            &self,
            transaction: VersionedTransaction,
        ) -> Result<Signature, ClientError> {
            let [instruction] = transaction.message.instructions() else {
                panic!("one instruction");
            };
            let (tag, payload) = instruction.data.split_first().unwrap();
            assert_eq!(*tag, discriminator::UPDATE_KEYS);
            let update = UpdateKeysData::try_from_slice(payload).unwrap();
            let mut record = self.record.lock().unwrap();
            assert_eq!(update.nullifier_pubkey, record.nullifier_pubkey);
            record.viewing_pubkey = update.viewing_pubkey;
            self.sent.lock().unwrap().push(update);
            Ok(transaction.signatures[0])
        }
    }

    fn identity(seed: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
    }

    fn rotation(identity: &ShieldedKeypair) -> ViewingRotation {
        ViewingRotation {
            keys: RotatingRingKeys::new(identity).unwrap(),
            history: ViewingHistory::new(identity.viewing_pubkey(), 0),
        }
    }

    fn sealed_note(tx: &ViewingKey, recipient: &X25519Pubkey) -> Vec<u8> {
        tx.encrypt_slot(recipient, b"old note", [5; 16], 0).unwrap()
    }

    fn open<K: ShieldedKeys>(
        keys: &K,
        tx: &ViewingKey,
        recipient: X25519Pubkey,
        ciphertext: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransactionError> {
        keys.decrypt(&[DecryptRequest {
            ciphertext,
            viewing_pubkey: recipient,
            tx_viewing_pubkey: tx.pubkey(),
            salt: [5; 16],
            slot_index: 0,
            label: DecryptLabel::Utxo,
        }])
    }

    #[tokio::test]
    async fn a_rotation_resolves_to_the_new_key_and_a_repeat_sends_nothing() {
        let (owner, identity) = (Keypair::new(), identity(1));
        let registry = Registry::holding(&owner, &identity);
        let rotated = rotation(&identity).rotate(ViewingKey::new(), 1).unwrap();
        let new = rotated.keys.address().unwrap().viewing_pubkey;
        let update = || UpdateViewingKey {
            owner: &owner,
            payer: &owner,
            keys: &rotated.keys,
            history: &rotated.history,
        };
        let updated = update().send(&registry).await.unwrap();
        assert!(updated.signature.is_some());
        assert_eq!(updated.viewing_pubkey, new);
        let resolved = ViewingKeyResolver::new(owner.pubkey())
            .resolve(&registry)
            .await
            .unwrap();
        assert_eq!(resolved.map(|key| key.viewing_pubkey), Some(new));
        assert_eq!(rotated.history.current().viewing_pubkey(), new);
        assert!(rotated.history.entry(&identity.viewing_pubkey()).is_some());

        let repeated = update().send(&registry).await.unwrap();
        assert_eq!(repeated.signature, None);
        assert_eq!(registry.sent(), 1);
    }

    #[test]
    fn a_note_sealed_to_the_old_key_opens_only_with_the_retained_key() {
        let identity = identity(2);
        let next = ViewingKey::new();
        let rotated = rotation(&identity).rotate(next.clone(), 1).unwrap();
        let (tx, old) = (ViewingKey::new(), identity.viewing_pubkey());
        let ciphertext = sealed_note(&tx, &old);
        let opened = open(&rotated.keys, &tx, old, &ciphertext).unwrap();
        assert_eq!(opened, [b"old note".to_vec()]);
        let mut current_only = identity.clone();
        current_only.viewing_key = next;
        let forgotten = RotatingRingKeys::new(&current_only).unwrap();
        assert!(open(&forgotten, &tx, old, &ciphertext).is_err());
    }

    #[tokio::test]
    async fn a_rotation_under_another_nullifier_key_is_refused_before_any_send() {
        let (owner, identity) = (Keypair::new(), identity(3));
        let registry = Registry::holding(&owner, &identity);
        let rotated = rotation(&self::identity(4))
            .rotate(ViewingKey::new(), 1)
            .unwrap();
        let refused = UpdateViewingKey {
            owner: &owner,
            payer: &owner,
            keys: &rotated.keys,
            history: &rotated.history,
        }
        .send(&registry)
        .await;
        assert!(
            matches!(
                refused,
                Err(ViewingRotationError::Client(
                    ClientError::UserRegistryNullifierKeyMismatch { .. }
                ))
            ),
            "{refused:?}"
        );
        assert_eq!(registry.sent(), 0);
    }

    #[tokio::test]
    async fn a_holder_ahead_of_its_history_is_refused_before_any_send() {
        let (owner, identity) = (Keypair::new(), identity(5));
        let registry = Registry::holding(&owner, &identity);
        let keys = RotatingRingKeys::new(&identity)
            .unwrap()
            .rotate(ViewingKey::new())
            .unwrap();
        let history = ViewingHistory::new(identity.viewing_pubkey(), 0);
        let refused = UpdateViewingKey {
            owner: &owner,
            payer: &owner,
            keys: &keys,
            history: &history,
        }
        .send(&registry)
        .await;
        assert!(matches!(
            refused,
            Err(ViewingRotationError::HistoryNotCurrent)
        ));
        assert_eq!(registry.sent(), 0);
    }
}
