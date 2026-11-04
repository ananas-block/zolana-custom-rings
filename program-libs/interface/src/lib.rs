//! Account layouts, instruction data, errors and statements of the custom ring
//! program, shared by the program, the SDKs and the services.

#[path = "instructions/anonymous_exit.rs"]
pub mod anonymous_exit;
#[path = "proof/audit_stream.rs"]
pub mod audit_stream;
#[path = "proof/blinding.rs"]
pub mod blinding;
#[path = "codec/bytes.rs"]
mod bytes;
#[path = "instructions/cosign.rs"]
pub mod cosign;
#[path = "instructions/deposit.rs"]
pub mod deposit;
#[path = "instructions/deposit_audit.rs"]
pub mod deposit_audit;
#[path = "proof/disclosure.rs"]
pub mod disclosure;
#[path = "proof/domain.rs"]
pub mod domain;
pub mod error;
#[path = "accounts/frame_buffer.rs"]
pub mod frame_buffer;
#[path = "instructions/instruction.rs"]
pub mod instruction;
#[path = "proof/key_catalog.rs"]
pub mod key_catalog;
#[path = "accounts/member_registry.rs"]
pub mod member_registry;
#[path = "instructions/merge.rs"]
pub mod merge;
#[path = "codec/output.rs"]
pub mod output;
#[path = "proof/ring_keys.rs"]
pub mod ring_keys;
#[path = "codec/spp.rs"]
pub mod spp;
#[path = "accounts/state.rs"]
pub mod state;
#[path = "proof/statement.rs"]
pub mod statement;
#[path = "accounts/storage.rs"]
pub mod storage;
#[path = "instructions/storage.rs"]
pub mod storage_instruction;
#[path = "codec/stream.rs"]
pub mod stream;
#[path = "accounts/tracking.rs"]
pub mod tracking;
#[path = "instructions/transact.rs"]
pub mod transact;
#[path = "proof/verification.rs"]
mod verification;
#[path = "instructions/withdrawals.rs"]
pub mod withdrawals;
pub use withdrawals::*;

// Keep the generated modules at their existing public paths.
#[cfg(feature = "verifying-keys")]
mod verifying_keys;
#[cfg(feature = "verifying-keys")]
pub use verifying_keys::*;

#[cfg(feature = "verifying-keys")]
pub fn proving_key_hashes() -> impl Iterator<Item = (&'static str, [u8; 32])> {
    PROVING_KEY_SHA256S.iter().copied()
}

pub use anonymous_exit::*;
pub use audit_stream::*;
pub use deposit::*;
pub use deposit_audit::*;
pub use disclosure::*;
pub use error::CustomRingError;
pub use frame_buffer::*;
pub use instruction::*;
pub use member_registry::*;
pub use merge::*;
pub use output::*;
pub use spp::*;
pub use state::*;
pub use statement::*;
pub use transact::*;
pub use verification::RingProof;

/// Not a deployable key, no keypair exists for it.
pub const STORAGE_PROGRAM_ID: solana_address::Address =
    solana_address::Address::new_from_array([0x53; 32]);

/// One-byte `0x04` scheme tag followed by a canonical X25519 u-coordinate.
pub use output::RECIPIENT_KEY_LEN as TAGGED_X25519_KEY_LEN;
pub const VIEWING_PUBKEY_TAG: u8 = 4;
/// AES-256-CTR ciphertext of `0x00 || nullifier_secret`.
pub const REGISTER_KEY_CIPHERTEXT_LEN: usize = 32;

pub fn tagged_x25519(u: &[u8; 32]) -> [u8; TAGGED_X25519_KEY_LEN] {
    let mut key = [VIEWING_PUBKEY_TAG; TAGGED_X25519_KEY_LEN];
    key[1..].copy_from_slice(u);
    key
}

/// `0x04 || eph_u || envelope_ct || record_ct... || tail_ct...`, published under the auditor's view tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditorMessage<'a> {
    pub eph_pk: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub envelope: &'a [u8],
    /// One record per published slot.
    pub records: &'a [u8],
    /// One tail per published slot, empty while `has_data` is clear.
    pub tails: &'a [u8],
}

impl<'a> AuditorMessage<'a> {
    /// `None` unless the key is tagged and every length is `layout`'s.
    pub fn parse(data: &'a [u8], layout: AuditStreamLayout) -> Option<Self> {
        let (eph_pk, rest) = data.split_first_chunk::<TAGGED_X25519_KEY_LEN>()?;
        let (envelope, rest) = rest.split_at_checked(layout.envelope().len)?;
        let (records, tails) = rest.split_at_checked(layout.records_len())?;
        (eph_pk[0] == VIEWING_PUBKEY_TAG && tails.len() == layout.tails_len()).then_some(Self {
            eph_pk,
            envelope,
            records,
            tails,
        })
    }

    pub fn record(&self, slot: usize) -> Option<&'a [u8; AUDIT_RECORD_LEN]> {
        self.records.as_chunks().0.get(slot)
    }

    pub fn tail(&self, slot: usize) -> Option<&'a [u8; DATA_TAIL_LEN]> {
        self.tails.as_chunks().0.get(slot)
    }

    /// `ciphertexts` is the envelope, the records and the tails in slot order.
    pub fn data<'c>(
        eph_u: &[u8; 32],
        ciphertexts: impl Iterator<Item = &'c [u8]> + Clone,
    ) -> Vec<u8> {
        let len = ciphertexts.clone().map(<[u8]>::len).sum::<usize>();
        let mut data = Vec::with_capacity(TAGGED_X25519_KEY_LEN + len);
        data.extend_from_slice(&tagged_x25519(eph_u));
        ciphertexts.for_each(|ciphertext| data.extend_from_slice(ciphertext));
        data
    }
}

pub const READER_KEY_P256: u8 = 0x00;
pub const READER_KEY_ED25519: u8 = 0x01;
pub type ReaderKeyBytes = [u8; 34];
