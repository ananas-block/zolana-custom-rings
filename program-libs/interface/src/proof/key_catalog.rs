//! Every ring circuit and its proving key, no verifying keys.
use spr_interface::N_PUBLIC_SLOTS;

use crate::{member_registry::APPLY_BATCH, transact::RingRail};

pub use crate::ring_keys::RING_KEYS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingCircuit {
    /// The signer, in-proof and authority rails, every recipient published.
    TransferConfidential {
        outputs: u8,
        inputs: u8,
        withdrawals: u8,
    },
    /// The anonymous rail over ring notes, spent UTXO 0 names the hidden sender.
    TransferAnonymous {
        outputs: u8,
        class: u8,
        withdrawals: u8,
    },
    /// The anonymous rail spending a default-ring note, every spent UTXO opens to the auditor.
    TransferAnonymousEntry {
        outputs: u8,
        class: u8,
        withdrawals: u8,
    },
    ApplyRecords {
        writes: u8,
    },
    ApplyEnrollments {
        writes: u8,
    },
    RegisterKey,
    Deposit {
        capacity: u8,
    },
    Merge {
        width: u8,
    },
}

/// One transfer family at one output count, mirror `ConfidentialShapes`, `AnonymousShapes` and `EntryShapes` in `prover/circuits/transfer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferShape {
    pub outputs: u8,
    /// The widest published input count the key serves.
    pub inputs: u8,
    /// Keyed leg capacities, ascending, zero past them.
    pub withdrawals: [u8; 2],
}

pub const CONFIDENTIAL_TRANSFER_SHAPES: [TransferShape; 4] = [
    TransferShape {
        outputs: 2,
        inputs: 24,
        withdrawals: [4, 32],
    },
    TransferShape {
        outputs: 4,
        inputs: 24,
        withdrawals: [4, 32],
    },
    TransferShape {
        outputs: 8,
        inputs: 16,
        withdrawals: [4, 32],
    },
    TransferShape {
        outputs: 16,
        inputs: 5,
        withdrawals: [8, 0],
    },
];

pub const ANONYMOUS_TRANSFER_SHAPES: [TransferShape; 3] = [
    TransferShape {
        outputs: 2,
        inputs: 24,
        withdrawals: [4, 32],
    },
    TransferShape {
        outputs: 4,
        inputs: 16,
        withdrawals: [4, 32],
    },
    TransferShape {
        outputs: 8,
        inputs: 5,
        withdrawals: [24, 0],
    },
];

pub const ENTRY_TRANSFER_SHAPES: [TransferShape; 3] = [
    TransferShape {
        outputs: 2,
        inputs: 8,
        withdrawals: [4, 0],
    },
    TransferShape {
        outputs: 4,
        inputs: 8,
        withdrawals: [4, 0],
    },
    TransferShape {
        outputs: 8,
        inputs: 2,
        withdrawals: [4, 0],
    },
];

impl TransferShape {
    /// The family's shape at `outputs`, `None` off the catalog.
    pub fn of(family: &[Self], outputs: usize) -> Option<Self> {
        family
            .iter()
            .copied()
            .find(|shape| usize::from(shape.outputs) == outputs)
    }

    /// The smallest keyed capacity holding `legs`, `None` past the widest.
    pub fn withdrawal_capacity(self, legs: usize) -> Option<u8> {
        self.withdrawals
            .iter()
            .copied()
            .filter(|capacity| *capacity != 0)
            .find(|capacity| usize::from(*capacity) >= legs)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferSpend {
    pub rail: RingRail,
    /// Published inputs, the spent notes.
    pub inputs: usize,
    pub outputs: usize,
    pub spends_default_ring: bool,
    /// Public withdrawal legs.
    pub legs: usize,
}

impl RingCircuit {
    /// The one transfer key serving the spend, `None` when the catalog keys none.
    pub fn transfer(spend: TransferSpend) -> Option<Self> {
        let shapes = match (spend.rail, spend.spends_default_ring) {
            (RingRail::Anonymous, false) => &ANONYMOUS_TRANSFER_SHAPES[..],
            (RingRail::Anonymous, true) => &ENTRY_TRANSFER_SHAPES[..],
            (RingRail::Confidential | RingRail::Delegate, false) => {
                &CONFIDENTIAL_TRANSFER_SHAPES[..]
            }
            (RingRail::Confidential | RingRail::Delegate, true) => return None,
        };
        let shape = TransferShape::of(shapes, spend.outputs)?;
        if spend.inputs == 0 || spend.inputs > usize::from(shape.inputs) {
            return None;
        }
        let withdrawals = shape.withdrawal_capacity(spend.legs)?;
        Some(match (spend.rail, spend.spends_default_ring) {
            (RingRail::Anonymous, false) => Self::TransferAnonymous {
                outputs: shape.outputs,
                class: shape.inputs,
                withdrawals,
            },
            (RingRail::Anonymous, true) => Self::TransferAnonymousEntry {
                outputs: shape.outputs,
                class: shape.inputs,
                withdrawals,
            },
            _ => Self::TransferConfidential {
                outputs: shape.outputs,
                inputs: shape.inputs,
                withdrawals,
            },
        })
    }

    pub const fn deposit(count: u8) -> Self {
        Self::Deposit {
            capacity: match count {
                0..=1 => 1,
                2 => 2,
                3..=4 => 4,
                _ => 8,
            },
        }
    }

    pub const fn apply_records(pending: u64) -> Self {
        Self::ApplyRecords {
            writes: apply_width(pending),
        }
    }

    pub const fn apply_enrollments(pending: u64) -> Self {
        Self::ApplyEnrollments {
            writes: apply_width(pending),
        }
    }
}

const fn apply_width(pending: u64) -> u8 {
    match pending {
        0..=1 => 1,
        2 => 2,
        3..=4 => 4,
        5..=8 => 8,
        _ => APPLY_BATCH as u8,
    }
}

/// A transfer key's record pool widths, mirror `recordCapacity` in `prover/circuits/policy/record_pool.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordPools {
    pub own: usize,
    pub curator: usize,
}

/// `Q` on the confidential and commitment keys.
pub const SCREENED_OWNERS: usize = 4;
/// `Q` on the entry keys.
pub const SCREENED_ENTRY_OWNERS: usize = 1;

struct PolicyShape {
    screened_owners: usize,
    outputs: usize,
    withdrawals: usize,
}

impl RingCircuit {
    /// The withdrawal slots of a transfer key, `None` outside the transfer keys.
    pub fn withdrawals(self) -> Option<u8> {
        match self {
            Self::TransferConfidential { withdrawals, .. }
            | Self::TransferAnonymous { withdrawals, .. }
            | Self::TransferAnonymousEntry { withdrawals, .. } => Some(withdrawals),
            _ => None,
        }
    }

    /// Each pool takes as many subjects as records, `None` outside the transfer keys.
    pub fn record_pools(self) -> Option<RecordPools> {
        let shape = match self {
            Self::TransferConfidential {
                outputs,
                withdrawals,
                ..
            }
            | Self::TransferAnonymous {
                outputs,
                withdrawals,
                ..
            } => PolicyShape {
                screened_owners: SCREENED_OWNERS,
                outputs: outputs.into(),
                withdrawals: withdrawals.into(),
            },
            Self::TransferAnonymousEntry {
                outputs,
                withdrawals,
                ..
            } => PolicyShape {
                screened_owners: SCREENED_ENTRY_OWNERS,
                outputs: outputs.into(),
                withdrawals: withdrawals.into(),
            },
            _ => return None,
        };
        // Withdrawals settle through the public slots, their assets are at most N_PUBLIC_SLOTS.
        let withdrawal_assets = shape.withdrawals.min(N_PUBLIC_SLOTS);
        let distinct = shape.screened_owners + 2 * shape.outputs + shape.withdrawals;
        Some(RecordPools {
            own: distinct + withdrawal_assets.max(N_PUBLIC_SLOTS),
            curator: distinct + withdrawal_assets,
        })
    }
}

/// `name` is the prover's circuit name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingKey {
    pub circuit: RingCircuit,
    pub name: &'static str,
}

impl RingKey {
    pub fn file_name(self) -> String {
        format!("{}.key", self.name.replace('-', "_"))
    }

    /// The release lock section, `custom-ring-deposit-2` reads `deposit_2_key`.
    pub fn section(self) -> String {
        let stem = self.name.strip_prefix(NAME_PREFIX).unwrap_or(self.name);
        key_suffixed(&stem.replace('-', "_"), "_")
    }

    pub fn asset(self, tag: &str) -> String {
        format!("{}-{tag}.key", key_suffixed(self.name, "-"))
    }
}

const NAME_PREFIX: &str = "custom-ring-";

/// One `key` suffix, a name that already ends in key takes none.
fn key_suffixed(name: &str, separator: &str) -> String {
    match name.ends_with("key") {
        true => name.to_owned(),
        false => format!("{name}{separator}key"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_carry_one_key_suffix() {
        let deposit = RingKey {
            circuit: RingCircuit::Deposit { capacity: 2 },
            name: "custom-ring-deposit-2",
        };
        let register = RingKey {
            circuit: RingCircuit::RegisterKey,
            name: "custom-ring-register-key",
        };
        assert_eq!(deposit.file_name(), "custom_ring_deposit_2.key");
        assert_eq!(deposit.section(), "deposit_2_key");
        assert_eq!(deposit.asset("v6"), "custom-ring-deposit-2-key-v6.key");
        assert_eq!(register.section(), "register_key");
        assert_eq!(register.asset("v6"), "custom-ring-register-key-v6.key");
    }

    #[test]
    fn a_transfer_takes_the_smallest_keyed_capacity_of_its_family() {
        let spend = |rail, inputs, outputs, spends_default_ring, legs| {
            RingCircuit::transfer(TransferSpend {
                rail,
                inputs,
                outputs,
                spends_default_ring,
                legs,
            })
        };
        assert_eq!(
            spend(RingRail::Confidential, 3, 2, false, 0),
            Some(RingCircuit::TransferConfidential {
                outputs: 2,
                inputs: 24,
                withdrawals: 4
            })
        );
        assert_eq!(
            spend(RingRail::Delegate, 2, 2, false, 5),
            Some(RingCircuit::TransferConfidential {
                outputs: 2,
                inputs: 24,
                withdrawals: 32
            })
        );
        assert_eq!(spend(RingRail::Confidential, 25, 2, false, 0), None);
        assert_eq!(
            spend(RingRail::Confidential, 5, 16, false, 8),
            Some(RingCircuit::TransferConfidential {
                outputs: 16,
                inputs: 5,
                withdrawals: 8
            })
        );
        assert_eq!(spend(RingRail::Confidential, 6, 16, false, 0), None);
        assert_eq!(spend(RingRail::Confidential, 1, 16, false, 9), None);
        assert_eq!(spend(RingRail::Confidential, 0, 2, false, 0), None);
        assert_eq!(spend(RingRail::Confidential, 1, 2, true, 0), None);
        assert_eq!(
            spend(RingRail::Anonymous, 5, 8, false, 24),
            Some(RingCircuit::TransferAnonymous {
                outputs: 8,
                class: 5,
                withdrawals: 24
            })
        );
        assert_eq!(spend(RingRail::Anonymous, 6, 8, false, 0), None);
        assert_eq!(
            spend(RingRail::Anonymous, 2, 8, true, 4),
            Some(RingCircuit::TransferAnonymousEntry {
                outputs: 8,
                class: 2,
                withdrawals: 4
            })
        );
        assert_eq!(spend(RingRail::Anonymous, 2, 8, true, 5), None);
        assert_eq!(spend(RingRail::Anonymous, 1, 16, false, 0), None);
    }

    #[test]
    fn the_pools_hold_every_screened_owner_output_and_withdrawal() {
        let pools = |circuit: RingCircuit| {
            let pools = circuit.record_pools().unwrap();
            (pools.own, pools.curator)
        };
        let confidential = |outputs, inputs, withdrawals| RingCircuit::TransferConfidential {
            outputs,
            inputs,
            withdrawals,
        };
        let commitment = |outputs, class, withdrawals| RingCircuit::TransferAnonymous {
            outputs,
            class,
            withdrawals,
        };
        let entry = |outputs, class, withdrawals| RingCircuit::TransferAnonymousEntry {
            outputs,
            class,
            withdrawals,
        };
        assert_eq!(pools(confidential(2, 24, 4)), (15, 15));
        assert_eq!(pools(confidential(2, 24, 32)), (43, 43));
        assert_eq!(pools(confidential(4, 24, 4)), (19, 19));
        assert_eq!(pools(confidential(4, 24, 32)), (47, 47));
        assert_eq!(pools(confidential(8, 16, 4)), (27, 27));
        assert_eq!(pools(confidential(8, 16, 32)), (55, 55));
        assert_eq!(pools(confidential(16, 5, 8)), (47, 47));
        assert_eq!(pools(commitment(2, 24, 4)), (15, 15));
        assert_eq!(pools(commitment(4, 16, 32)), (47, 47));
        assert_eq!(pools(commitment(8, 5, 24)), (47, 47));
        assert_eq!(pools(entry(2, 8, 4)), (12, 12));
        assert_eq!(pools(entry(4, 8, 4)), (16, 16));
        assert_eq!(pools(entry(8, 2, 4)), (24, 24));
    }
}
