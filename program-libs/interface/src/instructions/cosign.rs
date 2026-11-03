//! The co-signer a ring operation must carry, one rule for the program and the SDKs.

use crate::{CoSignScope, CoSigner, CustomRingError, PublicSlots, RingPolicy};
use solana_address::Address;

#[derive(Clone, Debug)]
pub struct CoSignDemand {
    /// Demands a co-signer of any scope when no class is shared.
    pub approval_required: bool,
    pub classes: CoSignScope,
}

impl CoSignDemand {
    pub fn transact(approval_required: bool, slots: &PublicSlots) -> Self {
        Self {
            approval_required,
            classes: slots.classes(),
        }
    }

    /// Only a transfer proof verified under the exempt bit may waive the withdrawal class.
    #[must_use]
    pub fn exempt_withdrawals(self) -> Self {
        let kept = self.classes.bits() & !CoSignScope::WITHDRAWALS.bits();
        Self {
            classes: CoSignScope::new(kept).unwrap_or(self.classes),
            ..self
        }
    }

    /// `None` when no record covers a class of the operation and no approval is demanded.
    pub fn requirement(
        &self,
        ring: &RingPolicy,
    ) -> Result<Option<CoSignRequirement>, CustomRingError> {
        let covered = ring.co_signers.covered();
        let shared = covered.map_or(0, CoSignScope::bits) & self.classes.bits();
        if let Some(classes) = CoSignScope::new(shared) {
            return Ok(Some(CoSignRequirement::Covering(classes)));
        }
        if !self.approval_required {
            return Ok(None);
        }
        covered
            .map(|_| Some(CoSignRequirement::Any))
            .ok_or(CustomRingError::ApprovalWithoutCoSigner)
    }
}

/// One `CoSigner` record must satisfy it, its signer signs the operation.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoSignRequirement {
    /// The policy proof demands approval and no class is shared.
    Any,
    Covering(CoSignScope),
}

impl CoSignRequirement {
    pub fn check(self, record: &CoSigner) -> Result<Address, CustomRingError> {
        let covers = match self {
            Self::Any => true,
            Self::Covering(classes) => record.scope().is_some_and(|scope| scope.contains(classes)),
        };
        covers
            .then_some(record.signer)
            .ok_or(CustomRingError::CoSignerOutOfScope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoSignerCounts, PublicLeg};
    use bytemuck::Zeroable;
    use spr_interface::instruction::InterfaceTransfer;
    #[test]
    fn exemption_waives_only_withdrawals() {
        let legs = [
            PublicLeg {
                transfer: InterfaceTransfer::SolWithdrawal { amount: 60 },
                mint: None,
            },
            PublicLeg {
                transfer: InterfaceTransfer::SolWithdrawal { amount: 60 },
                mint: None,
            },
            PublicLeg {
                transfer: InterfaceTransfer::SolDeposit { amount: 100 },
                mint: None,
            },
        ];
        let slots = PublicSlots::fold(legs.map(Ok::<_, CustomRingError>)).unwrap();
        let demand = CoSignDemand::transact(false, &slots);
        let config = |scope: CoSignScope| {
            let mut config = RingPolicy::zeroed();
            config.co_signers = CoSignerCounts::default().added(scope).unwrap();
            config
        };
        let covering = |classes| Ok(Some(CoSignRequirement::Covering(classes)));
        let withdrawals = config(CoSignScope::WITHDRAWALS);
        assert_eq!(
            demand.requirement(&withdrawals),
            covering(CoSignScope::WITHDRAWALS)
        );
        let exempt = CoSignDemand::transact(false, &slots).exempt_withdrawals();
        assert_eq!(exempt.requirement(&withdrawals), Ok(None));
        for scope in [CoSignScope::TRANSFERS, CoSignScope::DEPOSITS] {
            assert_eq!(exempt.requirement(&config(scope)), covering(scope));
        }
        let approval = CoSignDemand::transact(true, &slots).exempt_withdrawals();
        assert_eq!(
            approval.requirement(&withdrawals),
            Ok(Some(CoSignRequirement::Any))
        );
        assert_eq!(
            approval.requirement(&RingPolicy::zeroed()),
            Err(CustomRingError::ApprovalWithoutCoSigner)
        );
    }
}
