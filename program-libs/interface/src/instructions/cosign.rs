//! The co-signer a ring operation must carry, one rule for the program and the SDKs.

use crate::{CoSignScope, CustomRingError, PublicLeg, RingProgramConfig, SOL_ASSET_ADDRESS};
use solana_address::Address;

pub struct CoSignDemand {
    /// Demands the co-signer whatever its scope.
    pub approval_required: bool,
    pub classes: CoSignScope,
    /// Public withdrawal total per mint, each mint once.
    pub withdrawals: Vec<(Address, u128)>,
}

impl CoSignDemand {
    /// A transact is a transfer, each leg adds its class and a withdrawal its amount.
    pub fn transact(approval_required: bool, legs: &[PublicLeg]) -> Self {
        let mut classes = CoSignScope::TRANSFERS;
        let mut withdrawals: Vec<(Address, u128)> = Vec::new();
        for leg in legs {
            if leg.transfer.is_deposit() {
                classes = classes | CoSignScope::DEPOSITS;
                continue;
            }
            classes = classes | CoSignScope::WITHDRAWALS;
            let mint = Address::new_from_array(leg.mint.unwrap_or(SOL_ASSET_ADDRESS));
            let amount = u128::from(leg.transfer.amount());
            // A u128 sum of u64 legs never overflows.
            match withdrawals.iter_mut().find(|(seen, _)| *seen == mint) {
                Some((_, total)) => *total += amount,
                None => withdrawals.push((mint, amount)),
            }
        }
        Self {
            approval_required,
            classes,
            withdrawals,
        }
    }

    /// A shared class demands the co-signer, withdrawals only for a mint past or without its threshold.
    pub fn signer(&self, config: &RingProgramConfig) -> Result<Option<Address>, CustomRingError> {
        let co_signer = config.co_signer().copied();
        if self.approval_required {
            return co_signer
                .map(Some)
                .ok_or(CustomRingError::ApprovalWithoutCoSigner);
        }
        let (Some(co_signer), Some(scope)) = (co_signer, config.co_sign_scope()) else {
            return Ok(None);
        };
        let shared = |class| scope.contains(class) && self.classes.contains(class);
        let in_scope = shared(CoSignScope::TRANSFERS)
            || shared(CoSignScope::DEPOSITS)
            || (shared(CoSignScope::WITHDRAWALS)
                && self.withdrawals.iter().any(|(mint, total)| {
                    config
                        .threshold(mint)
                        .is_none_or(|threshold| *total > u128::from(threshold))
                }));
        Ok(in_scope.then_some(co_signer))
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Zeroable;
    use zolana_interface::instruction::InterfaceTransfer;

    use super::*;
    use crate::WithdrawalThresholdRow;

    const CO_SIGNER: Address = Address::new_from_array([7; 32]);
    const USDC: [u8; 32] = [9; 32];

    fn config(scope: CoSignScope, thresholds: &[([u8; 32], u64)]) -> RingProgramConfig {
        let mut config = RingProgramConfig::zeroed();
        config.co_signer = CO_SIGNER;
        config.co_sign_scope = scope.bits();
        config.threshold_count = thresholds.len() as u8;
        for (row, (mint, amount)) in config.thresholds.iter_mut().zip(thresholds) {
            *row = WithdrawalThresholdRow {
                mint: Address::new_from_array(*mint),
                amount: amount.to_le_bytes(),
            };
        }
        config
    }

    fn sol(amount: u64) -> PublicLeg {
        PublicLeg {
            transfer: InterfaceTransfer::SolWithdrawal { amount },
            mint: None,
        }
    }

    fn usdc(amount: u64) -> PublicLeg {
        PublicLeg {
            transfer: InterfaceTransfer::SplWithdrawal {
                amount,
                spl_interface_bump: 255,
            },
            mint: Some(USDC),
        }
    }

    #[test]
    fn withdrawals_sum_per_mint_and_a_scoped_class_or_an_unlisted_mint_demands_the_co_signer() {
        let deposit = PublicLeg {
            transfer: InterfaceTransfer::SolDeposit { amount: 5 },
            mint: None,
        };
        let sol_only = config(CoSignScope::WITHDRAWALS, &[(SOL_ASSET_ADDRESS, 100)]);
        let both = config(
            CoSignScope::WITHDRAWALS,
            &[(SOL_ASSET_ADDRESS, 100), (USDC, 100)],
        );
        let deposits = config(CoSignScope::DEPOSITS, &[]);
        for (legs, config, demanded) in [
            (vec![sol(60)], &sol_only, None),
            (vec![sol(60), sol(60)], &sol_only, Some(CO_SIGNER)),
            (vec![usdc(1)], &sol_only, Some(CO_SIGNER)),
            (vec![sol(60), usdc(60)], &both, None),
            (vec![deposit], &deposits, Some(CO_SIGNER)),
            (vec![deposit], &sol_only, None),
        ] {
            assert_eq!(
                CoSignDemand::transact(false, &legs).signer(config),
                Ok(demanded),
                "{legs:?}"
            );
        }
    }
}
