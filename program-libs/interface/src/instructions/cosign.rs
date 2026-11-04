//! One co-sign rule for the program and the SDKs.

use crate::{CoSignScope, CoSigner, CustomRingError, RingPolicy};
use solana_address::Address;

/// Proven by the transfer statement, the program derives no threshold itself.
#[must_use]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApprovalMask(u8);

impl ApprovalMask {
    /// Some `outflow(o,a)` exceeds a nonzero `cosign_above(a)`.
    pub const OUTFLOW: Self = Self(1);
    /// Some `gross(a)` exceeds a nonzero `withdrawal_threshold(a)`.
    pub const WITHDRAWAL: Self = Self(2);

    pub const fn new(bits: u8) -> Option<Self> {
        if bits & !(Self::OUTFLOW.0 | Self::WITHDRAWAL.0) != 0 {
            return None;
        }
        Some(Self(bits))
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn classes(self) -> CoSignScope {
        let class = |mask: Self, class: CoSignScope| match self.0 & mask.0 != 0 {
            true => class,
            false => CoSignScope::NONE,
        };
        class(Self::OUTFLOW, CoSignScope::APPROVE_OUTFLOW)
            | class(Self::WITHDRAWAL, CoSignScope::APPROVE_WITHDRAWAL)
    }
}

/// Each record covers a new class.
pub const MAX_CO_SIGNERS: usize = 5;
const _: () = assert!(CoSignScope::ALL.bits().count_ones() as usize == MAX_CO_SIGNERS);

/// A transfer's economic operation, merge and delegate demand nothing.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignOperation {
    /// Clear under the statement's `no_spend`.
    pub spends_note: bool,
    pub public_legs: CoSignScope,
    pub approval: ApprovalMask,
}

impl CoSignOperation {
    pub fn demand(self) -> CoSignDemand {
        let spend = match self.spends_note {
            true => CoSignScope::TRANSFERS,
            false => CoSignScope::NONE,
        };
        CoSignDemand {
            classes: spend | self.public_legs | self.approval.classes(),
        }
    }
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignDemand {
    pub classes: CoSignScope,
}

impl CoSignDemand {
    pub const NONE: Self = Self {
        classes: CoSignScope::NONE,
    };
    pub const DEPOSIT: Self = Self {
        classes: CoSignScope::DEPOSITS,
    };

    /// Approval classes never drop out.
    pub fn requirement(self, ring: &RingPolicy) -> Option<CoSignRequirement> {
        let configured = ring.co_signers.covered().unwrap_or(CoSignScope::NONE);
        let classes = self
            .classes
            .intersection(configured | CoSignScope::APPROVALS);
        (!classes.is_empty()).then_some(CoSignRequirement { uncovered: classes })
    }
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignRequirement {
    uncovered: CoSignScope,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignCover {
    pub signer: Address,
    pub rest: Option<CoSignRequirement>,
}

impl CoSignRequirement {
    pub const fn uncovered(self) -> CoSignScope {
        self.uncovered
    }

    pub fn cover(self, record: &CoSigner) -> Result<CoSignCover, CustomRingError> {
        let scope = record
            .scope()
            .filter(|scope| scope.intersects(self.uncovered))
            .ok_or(CustomRingError::CoSignerOutOfScope)?;
        let uncovered = self.uncovered.without(scope);
        Ok(CoSignCover {
            signer: record.signer,
            rest: (!uncovered.is_empty()).then_some(Self { uncovered }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoSignerCounts, CO_SIGNER};
    use bytemuck::Zeroable;

    const OUTFLOW: CoSignScope = CoSignScope::APPROVE_OUTFLOW;
    const WITHDRAWAL: CoSignScope = CoSignScope::APPROVE_WITHDRAWAL;

    fn ring(scopes: &[CoSignScope]) -> RingPolicy {
        let mut ring = RingPolicy::zeroed();
        ring.co_signers = scopes
            .iter()
            .fold(CoSignerCounts::default(), |counts, scope| {
                counts.added(*scope).unwrap()
            });
        ring
    }

    fn record(scope: CoSignScope, signer: u8) -> CoSigner {
        CoSigner {
            discriminator: CO_SIGNER,
            signer: Address::new_from_array([signer; 32]),
            scope: scope.bits(),
            bump: 0,
        }
    }

    fn operation(spends_note: bool, public_legs: CoSignScope, bits: u8) -> CoSignDemand {
        CoSignOperation {
            spends_note,
            public_legs,
            approval: ApprovalMask::new(bits).unwrap(),
        }
        .demand()
    }

    #[test]
    fn an_optional_class_without_a_record_demands_nothing() {
        let all = CoSignScope::TRANSFERS | CoSignScope::DEPOSITS | CoSignScope::WITHDRAWALS;
        let demand = operation(true, all, 0);
        assert_eq!(demand.requirement(&ring(&[])), None);
        let one = demand.requirement(&ring(&[CoSignScope::DEPOSITS])).unwrap();
        assert_eq!(one.uncovered(), CoSignScope::DEPOSITS);
    }

    #[test]
    fn a_pure_deposit_needs_no_transfer_co_signer() {
        let transfers = ring(&[CoSignScope::TRANSFERS]);
        let no_spend = operation(false, CoSignScope::DEPOSITS, 0);
        assert_eq!(no_spend.requirement(&transfers), None);
        assert_eq!(CoSignDemand::DEPOSIT.requirement(&transfers), None);
    }

    #[test]
    fn a_proven_bit_needs_its_approver_with_or_without_a_record() {
        for (bit, class, other) in [
            (ApprovalMask::OUTFLOW, OUTFLOW, WITHDRAWAL),
            (ApprovalMask::WITHDRAWAL, WITHDRAWAL, OUTFLOW),
        ] {
            let requirement = operation(true, CoSignScope::NONE, bit.bits())
                .requirement(&ring(&[]))
                .unwrap();
            assert_eq!(requirement.uncovered(), class);
            assert_eq!(
                requirement.cover(&record(other, 1)),
                Err(CustomRingError::CoSignerOutOfScope)
            );
            assert_eq!(requirement.cover(&record(class, 2)).unwrap().rest, None);
        }
        let below = operation(true, CoSignScope::NONE, 0);
        assert_eq!(below.requirement(&ring(&[])), None);
    }

    /// Withdrawing 5000 under `cosign_above` 100 and `withdrawal_threshold` 1000 sets both bits.
    #[test]
    fn separate_approvers_settle_a_transaction_past_both_thresholds() {
        let requirement = operation(true, CoSignScope::NONE, 3)
            .requirement(&ring(&[OUTFLOW, WITHDRAWAL]))
            .unwrap();
        let first = requirement.cover(&record(OUTFLOW, 1)).unwrap();
        assert_eq!(first.signer, Address::new_from_array([1; 32]));
        let rest = first.rest.unwrap();
        assert_eq!(rest.uncovered(), WITHDRAWAL);
        assert_eq!(rest.cover(&record(WITHDRAWAL, 2)).unwrap().rest, None);
        let one_for_both = requirement.cover(&record(OUTFLOW | WITHDRAWAL, 3));
        assert_eq!(one_for_both.unwrap().rest, None);
    }

    #[test]
    fn an_unrelated_or_repeated_record_covers_nothing() {
        let configured = ring(&[CoSignScope::TRANSFERS, CoSignScope::DEPOSITS]);
        let start = operation(true, CoSignScope::DEPOSITS, 0)
            .requirement(&configured)
            .unwrap();
        assert_eq!(
            start.cover(&record(WITHDRAWAL, 1)),
            Err(CustomRingError::CoSignerOutOfScope)
        );
        let rest = start
            .cover(&record(CoSignScope::TRANSFERS, 2))
            .unwrap()
            .rest
            .unwrap();
        assert_eq!(
            rest.cover(&record(CoSignScope::TRANSFERS, 2)),
            Err(CustomRingError::CoSignerOutOfScope)
        );
    }

    #[test]
    fn a_record_scope_is_a_nonzero_subset_of_the_five_classes() {
        assert_eq!(CoSignScope::new(0), None);
        assert_eq!(CoSignScope::new(32), None);
        assert_eq!(CoSignScope::new(31), Some(CoSignScope::ALL));
        let counts = CoSignerCounts::default()
            .added(CoSignScope::APPROVE_OUTFLOW)
            .unwrap()
            .added(CoSignScope::ALL)
            .unwrap();
        assert_eq!(
            counts.covered(),
            Some(CoSignScope::TRANSFERS | CoSignScope::DEPOSITS | CoSignScope::WITHDRAWALS)
        );
        let rest = counts.removed(CoSignScope::ALL).unwrap();
        assert_eq!(rest.covered(), None);
        assert_eq!(
            rest.removed(CoSignScope::TRANSFERS),
            Err(CustomRingError::CoSignerCountOutOfRange)
        );
    }

    #[test]
    fn merge_and_delegate_demand_nothing() {
        assert_eq!(
            CoSignDemand::NONE.requirement(&ring(&[CoSignScope::ALL])),
            None
        );
    }
}
