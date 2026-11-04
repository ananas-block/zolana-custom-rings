use custom_ring_interface::domain;
use spr_hasher::primitives::right_align;
use spr_keypair::{KeypairError, NullifierKey};
use zeroize::Zeroizing;

use crate::RingKeyError;

pub fn list_salt(key: &NullifierKey) -> Result<[u8; 32], RingKeyError> {
    let secret = Zeroizing::new(right_align(&key.secret()));
    Ok(domain::list_salt(&secret).map_err(KeypairError::from)?)
}

pub fn list_tag(key: &NullifierKey) -> Result<[u8; 32], RingKeyError> {
    Ok(domain::list_tag(&list_salt(key)?).map_err(KeypairError::from)?)
}
