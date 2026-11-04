//! The co-signers a ring operation carries, decided by the program's own rule.

use custom_ring_interface::{cosign::CoSignDemand, CustomRingError};
use solana_address::Address;
use solana_instruction::AccountMeta;
use spr_client::AsyncRpc;

use crate::{CustomRing, CustomRingConfig, RingError};

#[must_use]
pub(crate) struct CoSignerChoice<'a> {
    pub ring: CustomRing,
    pub config: &'a CustomRingConfig,
    pub demand: CoSignDemand,
    /// The caller's co-signers, read only when the demand needs one.
    pub supplied: &'a [Address],
}

impl CoSignerChoice<'_> {
    /// Each signer's record covers a class the earlier ones left, the first uncovered class refuses.
    pub async fn resolve(self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<Vec<Address>, RingError> {
        let mut requirement = self.demand.requirement(self.config.account())?;
        let mut signers = Vec::new();
        for signer in self.supplied {
            if requirement.is_satisfied() {
                break;
            }
            let record = self
                .ring
                .co_signer(rpc, signer)
                .await?
                .ok_or(CustomRingError::InvalidCoSignerRecord)?;
            let (rest, signer) = requirement.cover(record.account())?;
            requirement = rest;
            signers.push(signer);
        }
        requirement.check_satisfied()?;
        Ok(signers)
    }
}

impl CustomRing {
    /// The program reads the record first, the signer next.
    pub fn co_signer_metas(self, signer: Address) -> [AccountMeta; 2] {
        [
            AccountMeta::new_readonly(self.co_signer_pda(&signer), false),
            AccountMeta::new_readonly(signer, true),
        ]
    }
}
