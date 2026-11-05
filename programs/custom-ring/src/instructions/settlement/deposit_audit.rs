//! Builds the deposit statement from the entries SPP reads and verifies the ring proof over it.
//!
//! Each owner commitment and ciphertext comes out of SPP's own data, so the proof speaks of the notes
//! SPP appends. The roots, the auditor key and the assets come from accounts, and the frame's key capacity selects only the width.
//!
//! Read after `instructions/settlement/forward.rs`. Read before `prover/circuits/deposit.go`.

use custom_ring_interface::{
    key_catalog::RingCircuit, storage::Revision, tag, CustomRingError, CustomRingProof,
    DepositContext, DepositPrefix, DepositPublicInput, DepositRegistry, DepositedAsset,
    RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN,
    TAGGED_X25519_KEY_LEN, VIEWING_PUBKEY_TAG,
};
use pinocchio::{Address, ProgramResult};
use spr_interface::instruction::{
    instruction_data::deposit::RingDepositIxDataRef, tag::RING_DEPOSIT,
};

use crate::instructions::verifier::{ring_key, RingProof};

pub(crate) struct AuditedDeposit<'a> {
    pub proof: CustomRingProof,
    pub key_capacity: u8,
    pub tracking_revision: Revision,
    pub own_revision: Revision,
    pub curator_revision: Revision,
    pub spp_data: &'a [u8],
}

impl<'a> AuditedDeposit<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, CustomRingError> {
        let mut spp_data = data;
        let prefix = DepositPrefix::parse(&mut spp_data)?;
        if prefix.tag != tag::DEPOSIT || spp_data.first() != Some(&RING_DEPOSIT) {
            return Err(CustomRingError::InvalidAuditedDeposit);
        }
        Ok(Self {
            proof: prefix.proof,
            key_capacity: prefix.key_capacity,
            tracking_revision: prefix.tracking_revision,
            own_revision: prefix.own_revision,
            curator_revision: prefix.curator_revision,
            spp_data,
        })
    }
}

#[must_use]
pub(crate) struct DepositVerification<'a> {
    pub program_id: &'a Address,
    pub tree: &'a Address,
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub tracking_root: &'a [u8; 32],
    pub registry: Option<DepositRegistry<'a>>,
    pub assets: &'a [DepositedAsset],
    pub audited: &'a AuditedDeposit<'a>,
    pub deposit: &'a RingDepositIxDataRef<'a>,
}

impl DepositVerification<'_> {
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        // 1. One capsule per output at its own index, all under one ephemeral key. The circuit seals
        // every record in the one stream that key opens.
        let invalid = CustomRingError::InvalidDepositDisclosure;
        let count = self.deposit.deposits.len();
        if !(1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).contains(&count) {
            return Err(invalid.into());
        }
        let mut owners = [[0; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        let mut ciphertexts =
            [[0; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
        let mut eph_pk = [0; TAGGED_X25519_KEY_LEN];
        for (slot, entry) in self.deposit.deposits.iter().enumerate() {
            let capsule = RingDepositAuditCapsule::parse(entry.encrypted.ciphertext)
                .ok()
                .flatten()
                .filter(|capsule| usize::from(capsule.slot_index) == slot)
                .filter(|capsule| capsule.eph_pk[0] == VIEWING_PUBKEY_TAG)
                .filter(|capsule| slot == 0 || *capsule.eph_pk == eph_pk)
                .ok_or(invalid)?;
            eph_pk = *capsule.eph_pk;
            owners[slot] = *entry.owner_utxo_hash;
            ciphertexts[slot] = *capsule.ciphertext;
        }
        // 2. The context hash covers the SPP data and the asset cells bind each mint, the proof speaks of
        // no other amount, asset or owner.
        let context_hash = DepositContext {
            program_id: self.program_id.as_array(),
            tree: self.tree.as_array(),
            spp_data: self.audited.spp_data,
        }
        .hash()
        .map_err(CustomRingError::from)?;
        let public_input = DepositPublicInput {
            context_hash: &context_hash,
            key_capacity: self.audited.key_capacity,
            owner_utxo_hashes: &owners[..count],
            ciphertexts: &ciphertexts[..count],
            assets: self.assets,
            auditor_pk: self.auditor_pubkey,
            eph_pk: &eph_pk,
            tracking_root: self.tracking_root,
            registry: self.registry,
        }
        .hash()?;
        // 3. The auditor can recover the opening of each deposited owner commitment.
        RingProof {
            proof: &self.audited.proof,
            statement: public_input,
            key: ring_key(RingCircuit::Deposit {
                capacity: self.audited.key_capacity,
            })?,
        }
        .verify()
    }
}
