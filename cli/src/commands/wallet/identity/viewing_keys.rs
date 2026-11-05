//! `key rotate`, a new viewing key in the member's user record and tracking row, and the key holder
//! every wallet command loads.
//!
//! Read before `wallet`, whose scans and stores take the holder [`Context::ring_keys`] returns.
//! Read after `zolana_ring_client::UpdateViewingKey`, the send and record check `rotate` runs.
//!
//! The identity viewing key derives from the sender keypair. Every rotated key is a random secret
//! in its own owner-only file, `<n>.key` for the n-th rotation, never overwritten. The holder
//! applies the files in order, the newest key current and every earlier one retained, and notes
//! sealed to a retired key still open. The anonymous wallet store stays keyed by the identity key.

use std::path::{Path, PathBuf};

use anyhow::{ensure, Context as _, Result};
use custom_ring_sdk::Enroll;
use solana_signer::Signer;
use spr_keypair::{ShieldedKeypair, ViewingKey};
use spr_transaction::ShieldedKeys;
use zolana_ring_client::{UpdateViewingKey, ViewingKeyResolver, ViewingRotation};
use zolana_ring_keys::{ListSaltHolder, RotatingRingKeys};
use zolana_secret_file::{create_key32, read_key32, Access};

use crate::{line, wallet::unix_now, Context};

/// Under the `keys/` that `new` writes into `.gitignore`, one directory per owner.
pub const ROTATED_VIEWING_KEY_DIR: &str = "keys/viewing-keys";

struct RotatedKeys {
    dir: PathBuf,
}

impl Context {
    /// The identity key and every rotated key of `identity`, the newest current.
    pub fn ring_keys(&self, identity: &ShieldedKeypair) -> Result<RotatingRingKeys> {
        RotatedKeys::of(self, identity).holder(identity)
    }
}

pub fn rotate(ctx: &Context) -> Result<()> {
    let config = ctx.ring_config()?;
    let owner = ctx.sender()?;
    let identity = ShieldedKeypair::from_keypair(&owner)?;
    let rotated = RotatedKeys::of(ctx, &identity);
    let keys = rotated.holder(&identity)?;
    let rpc = ctx.chain().rpc();
    let published = ctx
        .block(async {
            ViewingKeyResolver::new(owner.pubkey())
                .with_credential(identity.shielded_address()?.nullifier_pubkey)
                .resolve(rpc)
                .await
                .map_err(anyhow::Error::from)
        })?
        .context("the sender has no user record, register its keys before a rotation")?;
    // 1. A record key the wallet never held came from another copy of the wallet. Publishing
    //    over it strands every payment sealed to that key.
    ensure!(
        keys.viewing_public_keys()
            .contains(&published.viewing_pubkey),
        "the user record names a viewing key the wallet does not hold"
    );
    let store = ctx.anonymous_wallet_store(identity.viewing_pubkey());
    let rotation = if published.viewing_pubkey == keys.address()?.viewing_pubkey {
        // 2. The secret file lands before the history and the record name its key. A run
        //    stopped after the update then still holds the key every new payment is sealed to.
        let next = ViewingKey::new();
        rotated.store(&next)?;
        store.update(|wallet| {
            let rotation = ViewingRotation {
                keys,
                history: wallet.history().clone(),
            }
            .rotate(next, unix_now()?)?;
            wallet.update_history(rotation.history.clone())?;
            Ok(rotation)
        })?
    } else {
        // 3. An older held key in the record is a stopped run's. Its stored key publishes before
        //    a new one starts, and the history takes it first when the run stopped before that.
        store.update(|wallet| {
            let current = keys.address()?.viewing_pubkey;
            if wallet.history().entry(&current).is_none() {
                let caught_up = wallet
                    .history()
                    .clone()
                    .with_rotated_key(current, unix_now()?)?;
                wallet.update_history(caught_up)?;
            }
            Ok(ViewingRotation {
                keys,
                history: wallet.history().clone(),
            })
        })?
    };
    let updated = ctx.block(async {
        UpdateViewingKey {
            owner: &owner,
            payer: ctx.member_payer(config.mode, owner.pubkey())?,
            keys: &rotation.keys,
            history: &rotation.history,
        }
        .send(rpc)
        .await
        .map_err(anyhow::Error::from)
    })?;
    line(
        "viewing key",
        hex::encode(updated.viewing_pubkey.as_bytes()),
    );
    match updated.signature {
        Some(signature) => line("signature", signature),
        None => line("record", "already current"),
    }
    // 4. Senders read a recipient's viewing key from its tracking row, the rotation moves it there
    //    too. The row grants the new key once an apply lands it in a root.
    let payer = ctx.member_payer(config.mode, owner.pubkey())?;
    let rotation = ctx.block(
        Enroll {
            ring: ctx.ring,
            payer: payer.pubkey(),
            owner: owner.pubkey(),
            nullifier_key: &identity.nullifier_key,
            viewing_pubkey: updated.viewing_pubkey,
            list_salt: identity.list_salt(&ctx.ring.program_id())?,
        }
        .prove(ctx.ring_client()),
    )?;
    ensure!(
        rotation.parsed()?.proof.is_none(),
        "the sender has no tracking authorization, register its key before a rotation"
    );
    let signature = ctx.send(&[payer, &owner], &[rotation.instruction()])?;
    line("tracking rotation", signature);
    Ok(())
}

impl RotatedKeys {
    fn of(ctx: &Context, identity: &ShieldedKeypair) -> Self {
        Self {
            dir: ctx
                .path(Path::new(ROTATED_VIEWING_KEY_DIR))
                .join(identity.pubkey().to_string()),
        }
    }

    fn holder(&self, identity: &ShieldedKeypair) -> Result<RotatingRingKeys> {
        let mut keys = RotatingRingKeys::new(identity)?;
        for path in self.stored() {
            let secret = read_key32(&path, Access::OwnerOnly)?;
            let next = ViewingKey::from_canonical_bytes(&secret)
                .with_context(|| format!("{} holds no viewing key", path.display()))?;
            keys = keys.rotate(next)?;
        }
        Ok(keys)
    }

    fn store(&self, next: &ViewingKey) -> Result<()> {
        let path = self.path(self.stored().count() + 1);
        Ok(create_key32(&path, &next.secret_bytes())?)
    }

    /// Oldest first, a gap ends the rotations.
    fn stored(&self) -> impl Iterator<Item = PathBuf> + '_ {
        (1..)
            .map(|rotation| self.path(rotation))
            .take_while(|path| path.exists())
    }

    fn path(&self, rotation: usize) -> PathBuf {
        self.dir.join(format!("{rotation}.key"))
    }
}

#[cfg(test)]
mod tests {
    use spr_transaction::{DecryptLabel, DecryptRequest};

    use super::*;
    use crate::wallet::fixtures::keypair;

    struct Dir(PathBuf);

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rotated(test: &str) -> (RotatedKeys, Dir) {
        let dir = std::env::temp_dir().join(format!("ring-viewing-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (RotatedKeys { dir: dir.clone() }, Dir(dir))
    }

    #[test]
    fn the_holder_takes_the_newest_file_as_current_and_opens_a_note_to_the_identity_key() {
        let (rotated, _dir) = rotated("holder");
        let identity = keypair(1);
        let (first, second) = (ViewingKey::new(), ViewingKey::new());
        rotated.store(&first).unwrap();
        rotated.store(&second).unwrap();
        let keys = rotated.holder(&identity).unwrap();
        assert_eq!(keys.address().unwrap().viewing_pubkey, second.pubkey());
        assert_eq!(keys.identity_viewing_pubkey(), identity.viewing_pubkey());
        let (tx, old) = (ViewingKey::new(), identity.viewing_pubkey());
        let ciphertext = tx.encrypt_slot(&old, b"old note", [5; 16], 0).unwrap();
        let opened = keys.decrypt(&[DecryptRequest {
            ciphertext: &ciphertext,
            viewing_pubkey: old,
            tx_viewing_pubkey: tx.pubkey(),
            salt: [5; 16],
            slot_index: 0,
            label: DecryptLabel::Utxo,
        }]);
        assert_eq!(opened.unwrap(), [b"old note".to_vec()]);
    }

    #[test]
    fn a_secret_no_viewing_key_derives_is_refused() {
        let (rotated, _dir) = rotated("refused");
        let identity = keypair(2);
        rotated.store(&ViewingKey::new()).unwrap();
        let mut unclamped = [0x41; 32];
        unclamped[31] = 0xff;
        create_key32(&rotated.path(2), &unclamped).unwrap();
        assert!(rotated.holder(&identity).is_err());
    }
}
