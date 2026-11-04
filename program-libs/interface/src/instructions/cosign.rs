//! The co-signers a ring operation must carry, one rule for the program and the SDKs.

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

/// A co-signer serves a class or adds nothing, the rail refuses it past this count.
pub const MAX_CO_SIGNERS: usize = 5;

/// The frame's co-signer byte, the mask below the count.
#[must_use]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoSignHeader {
    pub approval: ApprovalMask,
    /// `[record, signer]` pairs ahead of the SPP accounts.
    pub co_signers: u8,
}

impl CoSignHeader {
    const MASK_BITS: u8 = 2;
    const COUNT_BITS: u8 = 3;

    pub fn from_byte(byte: u8) -> Result<Self, CustomRingError> {
        if byte >> (Self::MASK_BITS + Self::COUNT_BITS) != 0 {
            return Err(CustomRingError::FlagNotAllowed);
        }
        let co_signers = byte >> Self::MASK_BITS;
        if usize::from(co_signers) > MAX_CO_SIGNERS {
            return Err(CustomRingError::TooManyCoSigners);
        }
        Ok(Self {
            approval: ApprovalMask::new(byte & ((1 << Self::MASK_BITS) - 1))
                .ok_or(CustomRingError::FlagNotAllowed)?,
            co_signers,
        })
    }

    pub const fn byte(self) -> u8 {
        self.approval.bits() | self.co_signers << Self::MASK_BITS
    }
}

/// A transfer's economic operation, merge and delegate demand nothing.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignOperation {
    /// Clear under the statement's `no_spend`.
    pub spends_note: bool,
    /// `PublicSlots::classes`.
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

    /// An optional class with no record drops out, an approval class with no record fails closed.
    pub fn requirement(self, ring: &RingPolicy) -> Result<CoSignRequirement, CustomRingError> {
        let covered = ring.co_signers.covered();
        if self
            .classes
            .intersection(CoSignScope::APPROVALS)
            .without(covered)
            != CoSignScope::NONE
        {
            return Err(CustomRingError::ApproverMissing);
        }
        Ok(CoSignRequirement {
            uncovered: self.classes.intersection(covered),
        })
    }
}

/// The classes no carried record covers yet.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoSignRequirement {
    uncovered: CoSignScope,
}

impl CoSignRequirement {
    /// True until a demanded class is outstanding.
    pub const fn is_satisfied(self) -> bool {
        self.uncovered.is_empty()
    }

    pub const fn uncovered(self) -> CoSignScope {
        self.uncovered
    }

    /// The record's signer, `CoSignerOutOfScope` unless it covers an outstanding class, so an unrelated or repeated record is refused.
    pub fn cover(self, record: &CoSigner) -> Result<(Self, Address), CustomRingError> {
        let scope = record.scope().ok_or(CustomRingError::CoSignerOutOfScope)?;
        if !scope.intersects(self.uncovered) {
            return Err(CustomRingError::CoSignerOutOfScope);
        }
        Ok((
            Self {
                uncovered: self.uncovered.without(scope),
            },
            record.signer,
        ))
    }

    /// `MissingCoSigner` while a demanded class is outstanding.
    pub const fn check_satisfied(self) -> Result<(), CustomRingError> {
        match self.is_satisfied() {
            true => Ok(()),
            false => Err(CustomRingError::MissingCoSigner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoSignerCounts, CO_SIGNER};
    use bytemuck::Zeroable;

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
        assert!(demand.requirement(&ring(&[])).unwrap().is_satisfied());
        let one = demand.requirement(&ring(&[CoSignScope::DEPOSITS])).unwrap();
        assert_eq!(one.uncovered(), CoSignScope::DEPOSITS);
    }

    #[test]
    fn a_pure_deposit_needs_no_transfer_co_signer() {
        let transfers = ring(&[CoSignScope::TRANSFERS]);
        let no_spend = operation(false, CoSignScope::DEPOSITS, 0);
        assert!(no_spend.requirement(&transfers).unwrap().is_satisfied());
        assert!(CoSignDemand::DEPOSIT
            .requirement(&transfers)
            .unwrap()
            .is_satisfied());
    }

    #[test]
    fn a_proven_bit_fails_closed_without_its_approver() {
        for (bit, other) in [
            (ApprovalMask::OUTFLOW, CoSignScope::APPROVE_WITHDRAWAL),
            (ApprovalMask::WITHDRAWAL, CoSignScope::APPROVE_OUTFLOW),
        ] {
            let demand = operation(true, CoSignScope::NONE, bit.bits());
            assert_eq!(
                demand.requirement(&ring(&[])),
                Err(CustomRingError::ApproverMissing)
            );
            assert_eq!(
                demand.requirement(&ring(&[other, CoSignScope::TRANSFERS])),
                Err(CustomRingError::ApproverMissing)
            );
        }
        let below = operation(true, CoSignScope::NONE, 0);
        assert!(below.requirement(&ring(&[])).unwrap().is_satisfied());
    }

    #[test]
    fn each_class_needs_a_covering_record() {
        let (outflow, withdrawal) = (
            CoSignScope::APPROVE_OUTFLOW,
            CoSignScope::APPROVE_WITHDRAWAL,
        );
        let configured = ring(&[outflow, withdrawal]);
        let start = operation(false, CoSignScope::NONE, 3)
            .requirement(&configured)
            .unwrap();
        let (rest, first) = start.cover(&record(outflow, 1)).unwrap();
        assert_eq!(first, Address::new_from_array([1; 32]));
        assert_eq!(
            rest.check_satisfied(),
            Err(CustomRingError::MissingCoSigner)
        );
        let (done, _) = rest.cover(&record(withdrawal, 2)).unwrap();
        assert_eq!(done.check_satisfied(), Ok(()));
        let (one_for_both, _) = start.cover(&record(outflow | withdrawal, 3)).unwrap();
        assert_eq!(one_for_both.check_satisfied(), Ok(()));
    }

    #[test]
    fn an_unrelated_or_repeated_record_satisfies_nothing() {
        let configured = ring(&[CoSignScope::TRANSFERS, CoSignScope::DEPOSITS]);
        let start = operation(true, CoSignScope::NONE, 0)
            .requirement(&configured)
            .unwrap();
        assert_eq!(
            start.cover(&record(CoSignScope::DEPOSITS, 1)),
            Err(CustomRingError::CoSignerOutOfScope)
        );
        let (done, _) = start.cover(&record(CoSignScope::TRANSFERS, 2)).unwrap();
        assert_eq!(
            done.cover(&record(CoSignScope::TRANSFERS, 2)),
            Err(CustomRingError::CoSignerOutOfScope)
        );
    }

    #[test]
    fn merge_and_delegate_refuse_any_record() {
        let configured = ring(&[CoSignScope::ALL]);
        let none = CoSignDemand::NONE.requirement(&configured).unwrap();
        assert!(none.is_satisfied());
        assert_eq!(
            none.cover(&record(CoSignScope::ALL, 1)),
            Err(CustomRingError::CoSignerOutOfScope)
        );
    }

    #[test]
    fn the_header_refuses_a_count_past_five_and_unknown_bits() {
        let header = CoSignHeader {
            approval: ApprovalMask::WITHDRAWAL,
            co_signers: 5,
        };
        assert_eq!(CoSignHeader::from_byte(header.byte()), Ok(header));
        assert_eq!(
            CoSignHeader::from_byte(6 << 2),
            Err(CustomRingError::TooManyCoSigners)
        );
        assert_eq!(
            CoSignHeader::from_byte(1 << 5),
            Err(CustomRingError::FlagNotAllowed)
        );
    }
}
