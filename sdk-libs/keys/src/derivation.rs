use hkdf::Hkdf;
use sha2::Sha256;
use solana_address::Address;
use zeroize::Zeroizing;
use zolana_keypair::{KeypairError, ViewingKey};

use crate::RingKeyError;

/// Followed by the ring program address and the address index.
pub const INFO_RING_ADDRESS_KEY_PREFIX: &[u8] = b"TSPP/ring_address_key/";

/// Followed by the ring program address.
pub const INFO_RING_CHANGE_KEY_PREFIX: &[u8] = b"TSPP/ring_change_key/";

/// zolana-keypair's `DST_X25519_VIEW_ROOT`, the salt of the view root extract.
const DST_X25519_VIEW_ROOT: &[u8] = b"TSPP/view_root/x25519/v1";

pub trait RingViewingKey {
    /// The key of ring address `index` in `ring`, the recipient key its inbox stream derives from.
    fn ring_address_key(&self, ring: &Address, index: u32) -> Result<ViewingKey, RingKeyError>;

    /// The key a sender's change in `ring` is delivered to, found from the sender's own spends.
    fn ring_change_key(&self, ring: &Address) -> Result<ViewingKey, RingKeyError>;
}

impl RingViewingKey for ViewingKey {
    fn ring_address_key(&self, ring: &Address, index: u32) -> Result<ViewingKey, RingKeyError> {
        let secret = derive_secret32(
            self,
            &[
                INFO_RING_ADDRESS_KEY_PREFIX,
                ring.as_array(),
                &index.to_be_bytes(),
            ],
        )?;
        Ok(ViewingKey::from_bytes(&secret))
    }

    fn ring_change_key(&self, ring: &Address) -> Result<ViewingKey, RingKeyError> {
        let secret = derive_secret32(self, &[INFO_RING_CHANGE_KEY_PREFIX, ring.as_array()])?;
        Ok(ViewingKey::from_bytes(&secret))
    }
}

/// zolana-keypair's private `derive_secret32`, HKDF-Expand of the view root.
fn derive_secret32(key: &ViewingKey, info: &[&[u8]]) -> Result<Zeroizing<[u8; 32]>, KeypairError> {
    let (view_root, _) =
        Hkdf::<Sha256>::extract(Some(DST_X25519_VIEW_ROOT), key.secret_bytes().as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::from_prk(&view_root)
        .map_err(|_| KeypairError::Hkdf)?
        .expand_multi_info(info, out.as_mut_slice())
        .map_err(|_| KeypairError::Hkdf)?;
    Ok(out)
}
