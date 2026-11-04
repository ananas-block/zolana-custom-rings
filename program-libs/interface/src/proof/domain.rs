//! Domain tags of the ring hashes, distinct ASCII tags absorbed as the first
//! Poseidon input and mirrored by Go `prover/circuits/shared/derivation.go`.

use spr_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};

/// `"CRDS"`
pub const DELIVERED_SLOT_SECRET: u32 = 0x4352_4453;
/// `"CRRT"`, a recipient or dummy slot's view tag.
pub const RECIPIENT_TAG: u32 = 0x4352_5254;
/// `"CRST"`, the sender bundle's view tag.
pub const SENDER_TAG: u32 = 0x4352_5354;
/// `"CRBS"`
pub const BLINDING_SEED: u32 = 0x4352_4253;
/// `"CR_S"`, the root of every auditor stream.
pub const AUDIT_SHARED_SECRET: u32 = 0x4352_5f53;
/// `"CRTB"`, defined beside the table hash in the policy crate the interface depends on.
pub use zolana_ring_policy::POLICY_TABLE_DOMAIN as POLICY_TABLE;
/// `"CRQW"`
pub const QUEUE_WRITE: u32 = 0x4352_5157;
/// `"CRAD"`
pub const AUTHORIZED_ADDRESS: u32 = 0x4352_4144;
/// `"CRAP"`
pub const APPLY_RECORDS: u32 = 0x4352_4150;
/// `"CRRG"`
pub const REGISTER_KEY: u32 = 0x4352_5247;
/// `"CRDB"`
pub const DEPOSIT_BLINDING: u32 = 0x4352_4442;
/// `"CRDP"`
pub const DEPOSIT_STATEMENT: u32 = 0x4352_4450;
/// `"CRMG"`
pub const MERGE_STATEMENT: u32 = 0x4352_4d47;
/// `"CRPW"`
pub const WITHDRAWALS: u32 = 0x4352_5057;
/// `"CRRU"`
pub const RECORD_UPDATE: u32 = 0x4352_5255;
/// `"CRWG"`
pub use zolana_ring_policy::WALLET_GRANT_DOMAIN as WALLET_GRANT;

/// `"CRTX"`
pub const TRANSFER_STATEMENT: u32 = 0x4352_5458;
/// Bound nonzero and last into every transfer statement, a layout change raises it.
pub const TRANSFER_STATEMENT_VERSION: u8 = 4;

pub const AUDIT_STREAM_LABEL: &[u8; 10] = b"CRING/adt1";
pub const DELIVERED_BODY_LABEL: &[u8; 10] = b"CRING/bdy1";
pub const RECIPIENT_BODY_LABEL: &[u8; 10] = b"CRING/rcp1";
pub const REPLY_LABEL: &[u8; 10] = b"CRING/rpl1";
pub const SENDER_BUNDLE_LABEL: &[u8; 10] = b"CRING/snd1";
pub const REGISTER_KEY_LABEL: &[u8; 10] = b"CRING/nfk1";
pub const DEPOSIT_AUDIT_LABEL: &[u8; 10] = b"CRING/dep1";

pub fn field(domain: u32) -> [u8; 32] {
    right_align(&domain.to_be_bytes())
}

/// `Poseidon(CRDB, blinding_secret)`.
pub fn deposit_blinding(blinding_secret: &[u8; 32]) -> Result<[u8; 32], HasherError> {
    Poseidon::hashv(&[&field(DEPOSIT_BLINDING), blinding_secret])
}
