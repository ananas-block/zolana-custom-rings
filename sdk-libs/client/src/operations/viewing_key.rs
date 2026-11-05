//! A ring recipient's current viewing key, read from zolana's `UserRecord`.
//!
//! Read before `spr_client::user_registry`, whose checked fetch derives the canonical PDA and
//! refuses a foreign program owner, a malformed record, a non-canonical stored bump and a record
//! stored for another owner. Read after `ViewingHistory`, where a wallet keeps the keys a rotation
//! replaced.
//!
//! The record holds only the current key, and a later `UPDATE_KEYS` can replace it after any
//! completed read. Notes sealed to an earlier key open through the recipient's `ViewingHistory`.
//! The read stays off chain and adds no account to an anonymous transaction.

use solana_address::Address;
use spr_client::{user_registry::fetch_user_record_optional_checked_async, AsyncRpc, ClientError};
use spr_keypair::{KeypairError, X25519Pubkey};
use thiserror::Error;

/// The RPC node's account state is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedViewingKey {
    pub viewing_pubkey: X25519Pubkey,
}

#[derive(Debug, Error)]
pub enum ViewingKeyError {
    #[error("the user record read or its account checks failed")]
    Record(#[source] ClientError),
    #[error("the user record holds no canonical X25519 viewing key")]
    InvalidViewingKey(#[source] KeypairError),
    #[error("the user record nullifier key differs from the credential")]
    NullifierKeyMismatch,
}

#[must_use]
pub struct ViewingKeyResolver {
    owner: Address,
    credential_nullifier_pk: Option<[u8; 32]>,
}

impl ViewingKeyResolver {
    pub fn new(owner: Address) -> Self {
        Self {
            owner,
            credential_nullifier_pk: None,
        }
    }

    /// A record with another nullifier key is refused.
    pub fn with_credential(self, nullifier_pk: [u8; 32]) -> Self {
        Self {
            credential_nullifier_pk: Some(nullifier_pk),
            ..self
        }
    }

    /// `None` only for an owner without a record, an RPC failure is an error.
    pub async fn resolve<R: AsyncRpc>(
        self,
        rpc: &R,
    ) -> Result<Option<ResolvedViewingKey>, ViewingKeyError> {
        // 1. Only an absent account at the canonical PDA is a missing record. A record that
        //    fails a check stays an error and never reads as an unregistered owner.
        let Some(record) = fetch_user_record_optional_checked_async(rpc, self.owner)
            .await
            .map_err(ViewingKeyError::Record)?
        else {
            return Ok(None);
        };
        // 2. Neither `REGISTER` nor `UPDATE_KEYS` checks the key encoding. A wrong tag or a u
        //    at or above p is an encoding no wallet derives, and no note may be sealed to it.
        let viewing_pubkey = X25519Pubkey::from_bytes(record.viewing_pubkey)
            .map_err(ViewingKeyError::InvalidViewingKey)?;
        // 3. `UPDATE_KEYS` refuses a nullifier key rotation. A record with another key holds
        //    another shielded identity than the credential, and its viewing key need not belong
        //    to the credential holder.
        if self
            .credential_nullifier_pk
            .is_some_and(|nullifier_pk| nullifier_pk != record.nullifier_pubkey)
        {
            return Err(ViewingKeyError::NullifierKeyMismatch);
        }
        Ok(Some(ResolvedViewingKey { viewing_pubkey }))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use async_trait::async_trait;
    use borsh::BorshSerialize;
    use solana_account::Account;
    use spr_keypair::ViewingKey;
    use spr_user_registry_interface::{
        user_record_pda, user_registry_program_id, MergeEncryptionScheme, UserRecord,
        USER_RECORD_SEED,
    };

    use super::*;
    use crate::ViewingHistory;

    const OWNER: Address = Address::new_from_array([7; 32]);
    const NULLIFIER_PK: [u8; 32] = [9; 32];

    #[derive(Default)]
    struct Accounts(Mutex<HashMap<Address, Account>>);

    #[async_trait]
    impl AsyncRpc for Accounts {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok(self.0.lock().unwrap().get(&address).cloned())
        }
    }

    impl Accounts {
        fn holding(record: &UserRecord) -> Self {
            let accounts = Self::default();
            accounts.store(user_record_pda(&OWNER).0, record);
            accounts
        }

        fn store(&self, address: Address, record: &UserRecord) {
            let mut data = vec![UserRecord::DISCRIMINATOR];
            record.serialize(&mut data).unwrap();
            let account = Account {
                data,
                owner: user_registry_program_id(),
                ..Account::default()
            };
            self.0.lock().unwrap().insert(address, account);
        }

        fn edit(&self, address: Address, edit: impl FnOnce(&mut Account)) {
            edit(self.0.lock().unwrap().get_mut(&address).unwrap());
        }
    }

    fn record(viewing_pubkey: X25519Pubkey) -> UserRecord {
        UserRecord {
            owner: OWNER,
            bump: user_record_pda(&OWNER).1,
            nullifier_pubkey: NULLIFIER_PK,
            viewing_pubkey: *viewing_pubkey.as_bytes(),
            merge_encryption: MergeEncryptionScheme::Disabled,
        }
    }

    async fn resolve(accounts: &Accounts) -> Result<Option<ResolvedViewingKey>, ViewingKeyError> {
        ViewingKeyResolver::new(OWNER)
            .with_credential(NULLIFIER_PK)
            .resolve(accounts)
            .await
    }

    fn refused_record(result: Result<Option<ResolvedViewingKey>, ViewingKeyError>) -> String {
        match result {
            Err(ViewingKeyError::Record(ClientError::Rpc(message))) => message,
            other => panic!("expected a refused record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_registered_owner_resolves_to_the_record_viewing_key() {
        let viewing_pubkey = ViewingKey::new().pubkey();
        let accounts = Accounts::holding(&record(viewing_pubkey));
        let resolved = resolve(&accounts).await.unwrap();
        assert_eq!(resolved, Some(ResolvedViewingKey { viewing_pubkey }));
        let unenrolled = ViewingKeyResolver::new(OWNER).resolve(&accounts).await;
        assert_eq!(unenrolled.unwrap(), resolved);
    }

    #[tokio::test]
    async fn an_owner_without_a_record_at_the_canonical_pda_is_missing() {
        let accounts = Accounts::default();
        assert_eq!(resolve(&accounts).await.unwrap(), None);
        let (_, canonical_bump) = user_record_pda(&OWNER);
        let other_pda = (0..canonical_bump)
            .rev()
            .find_map(|bump| {
                Address::create_program_address(
                    &[USER_RECORD_SEED, OWNER.as_ref(), &[bump]],
                    &user_registry_program_id(),
                )
                .ok()
            })
            .unwrap();
        accounts.store(other_pda, &record(ViewingKey::new().pubkey()));
        assert_eq!(resolve(&accounts).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_stored_bump_other_than_the_canonical_one_is_refused() {
        let mut stored = record(ViewingKey::new().pubkey());
        stored.bump = stored.bump.wrapping_sub(1);
        let message = refused_record(resolve(&Accounts::holding(&stored)).await);
        assert!(message.contains("non-canonical bump"), "{message}");
    }

    #[tokio::test]
    async fn a_record_owned_by_another_program_is_refused() {
        let accounts = Accounts::holding(&record(ViewingKey::new().pubkey()));
        accounts.edit(user_record_pda(&OWNER).0, |account| {
            account.owner = Address::new_from_array([3; 32]);
        });
        let message = refused_record(resolve(&accounts).await);
        assert!(
            message.contains("not owned by the user registry"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn a_record_storing_another_owner_is_refused() {
        let mut stored = record(ViewingKey::new().pubkey());
        stored.owner = Address::new_from_array([8; 32]);
        let message = refused_record(resolve(&Accounts::holding(&stored)).await);
        assert!(message.contains("stores a different owner"), "{message}");
    }

    #[tokio::test]
    async fn a_viewing_key_with_a_wrong_tag_or_a_non_canonical_u_is_refused() {
        let mut wrong_tag = *ViewingKey::new().pubkey().as_bytes();
        wrong_tag[0] = 2;
        let mut non_canonical_u = [0xff; 33];
        non_canonical_u[0] = spr_keypair::x25519::X25519_KEY_TAG;
        for viewing_pubkey in [wrong_tag, non_canonical_u] {
            let stored = UserRecord {
                viewing_pubkey,
                ..record(ViewingKey::new().pubkey())
            };
            let result = resolve(&Accounts::holding(&stored)).await;
            assert!(
                matches!(result, Err(ViewingKeyError::InvalidViewingKey(_))),
                "{result:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_record_nullifier_key_other_than_the_credential_is_refused() {
        let stored = UserRecord {
            nullifier_pubkey: [1; 32],
            ..record(ViewingKey::new().pubkey())
        };
        let result = resolve(&Accounts::holding(&stored)).await;
        assert!(
            matches!(result, Err(ViewingKeyError::NullifierKeyMismatch)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_rotated_record_resolves_to_the_new_key_and_the_history_keeps_the_old() {
        let old = ViewingKey::new().pubkey();
        let new = ViewingKey::new().pubkey();
        let accounts = Accounts::holding(&record(old));
        let history =
            ViewingHistory::new(resolve(&accounts).await.unwrap().unwrap().viewing_pubkey, 0);
        accounts.store(user_record_pda(&OWNER).0, &record(new));
        let resolved = resolve(&accounts).await.unwrap().unwrap();
        assert_eq!(resolved.viewing_pubkey, new);
        let history = history
            .with_rotated_key(resolved.viewing_pubkey, 1)
            .unwrap();
        assert_eq!(history.current().viewing_pubkey(), new);
        assert!(history.entry(&old).is_some());
    }
}
