use custom_ring_interface::{
    CustomRingError, ParsedTransact, RingMode, RingPolicy, TransferBinding,
};
use pinocchio::{Address, ProgramResult};
use zolana_ring_policy::ring_id_field;

use super::accounts::TransactAccounts;
use crate::instructions::verifier::{ring_key, RingProof};

#[must_use]
pub(super) struct RingStatements<'a> {
    pub program_id: &'a Address,
    pub ring: &'a RingPolicy,
    pub transfer: &'a ParsedTransact<'a>,
    pub accounts: &'a TransactAccounts,
    pub key_escrow: bool,
}

impl RingStatements<'_> {
    #[inline(never)]
    pub fn verify(self) -> ProgramResult {
        let ring_id = ring_id_field(self.program_id.as_array()).map_err(CustomRingError::from)?;
        let data = self.transfer.data();
        let slots = &self.accounts.public_slots;
        let public_assets = slots.asset_fields().map_err(CustomRingError::from)?;
        let public_amounts = slots.amount_fields().map_err(CustomRingError::from)?;
        let public_gross = slots.gross_fields();
        let withdrawal_hash =
            custom_ring_interface::policy_withdrawal_hash(&self.accounts.withdrawals)
                .map_err(CustomRingError::from)?;
        let recipients = data.recipients();
        let statement = self
            .transfer
            .transfer_statement(TransferBinding {
                ring_id: &ring_id,
                auditor_pubkey: &self.ring.auditor_pubkey,
                key_escrow: self.key_escrow,
                sender: &self.accounts.sender,
                signers: self.accounts.signers,
                party_identities: &self.accounts.party_identities,
                recipients: &recipients,
                roots: &self.accounts.roots,
                public_assets: &public_assets,
                public_amounts: &public_amounts,
                public_gross: &public_gross,
                withdrawal_hash: &withdrawal_hash,
            })?
            .hash()
            .map_err(CustomRingError::from)?;
        RingProof {
            proof: data.proof,
            statement,
            key: ring_key(data.transfer_circuit(self.accounts.withdrawals.len(), 0)?)?,
        }
        .verify()
    }
}

/// `ConfidentialEscrow` mode alone, its proof escrows every output nullifier key.
pub(super) fn escrows_keys(ring: &RingPolicy) -> Result<bool, CustomRingError> {
    Ok(ring.mode()? == RingMode::ConfidentialEscrow)
}
