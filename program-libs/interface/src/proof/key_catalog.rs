//! Every ring circuit and its proving key, no verifying keys.
use spr_interface::{shape::MAX_TRANSACTION_ADDRESSES, N_PUBLIC_SLOTS};

use crate::{
    member_registry::APPLY_BATCH, private_list::PRIVATE_LIST_APPLY_WIDTHS, transact::RingRail,
};

pub use crate::ring_keys::RING_KEYS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingCircuit {
    /// The signer, in-proof and authority rails.
    TransferConfidential {
        outputs: u8,
        inputs: u8,
        withdrawals: u8,
        owners: u8,
        data: bool,
    },
    /// The signer and in-proof rails spending a default-ring note.
    TransferConfidentialEntry {
        outputs: u8,
        class: u8,
        withdrawals: u8,
        owners: u8,
        data: bool,
    },
    /// The hidden sender, public owner and authority rails over ring notes.
    TransferAnonymous {
        outputs: u8,
        class: u8,
        withdrawals: u8,
        owners: u8,
        data: bool,
    },
    /// The hidden sender and public owner rails spending a default-ring note.
    TransferAnonymousEntry {
        outputs: u8,
        class: u8,
        withdrawals: u8,
        owners: u8,
        data: bool,
    },
    ApplyRecords {
        writes: u8,
    },
    ApplyEnrollments {
        writes: u8,
    },
    ApplyPrivateList {
        writes: u8,
    },
    RegisterKey,
    Deposit {
        capacity: u8,
    },
    Merge,
}

/// One transfer family at one output count, mirror `ConfidentialBases`, `AnonymousBases` and `EntryBases` in `prover/circuits/transfer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferShape {
    pub outputs: u8,
    /// The widest published input count the key serves.
    pub inputs: u8,
    /// Keyed leg capacities, ascending, zero past them.
    pub withdrawals: [u8; 2],
    /// Keyed owner rows, ascending, zero past them, mirror `ownerCapacities`.
    pub owners: [u8; 2],
}

pub const CONFIDENTIAL_TRANSFER_SHAPES: [TransferShape; 4] = [
    TransferShape {
        outputs: 2,
        inputs: 24,
        withdrawals: [4, 32],
        owners: [4, 24],
    },
    TransferShape {
        outputs: 4,
        inputs: 24,
        withdrawals: [4, 32],
        owners: [4, 24],
    },
    TransferShape {
        outputs: 8,
        inputs: 16,
        withdrawals: [4, 32],
        owners: [4, 16],
    },
    TransferShape {
        outputs: 16,
        inputs: 5,
        withdrawals: [8, 0],
        owners: [4, 5],
    },
];

pub const ANONYMOUS_TRANSFER_SHAPES: [TransferShape; 3] = [
    TransferShape {
        outputs: 2,
        inputs: 24,
        withdrawals: [4, 32],
        owners: [4, 24],
    },
    TransferShape {
        outputs: 4,
        inputs: 16,
        withdrawals: [4, 32],
        owners: [4, 16],
    },
    TransferShape {
        outputs: 8,
        inputs: 5,
        withdrawals: [24, 0],
        owners: [4, 5],
    },
];

pub const ENTRY_TRANSFER_SHAPES: [TransferShape; 3] = [
    TransferShape {
        outputs: 2,
        inputs: 8,
        withdrawals: [4, 0],
        owners: [4, 8],
    },
    TransferShape {
        outputs: 4,
        inputs: 8,
        withdrawals: [4, 0],
        owners: [4, 8],
    },
    TransferShape {
        outputs: 8,
        inputs: 2,
        withdrawals: [4, 0],
        owners: [2, 0],
    },
];

impl TransferShape {
    /// `None` on the delegate rails spending a default-ring note, SPP's authority rail holds every input to the ring.
    pub fn family(rail: RingRail, entry: bool) -> Option<&'static [Self]> {
        match (rail, entry) {
            (RingRail::Anonymous | RingRail::AnonymousDelegate, false) => {
                Some(&ANONYMOUS_TRANSFER_SHAPES)
            }
            (RingRail::Anonymous | RingRail::Confidential, true) => Some(&ENTRY_TRANSFER_SHAPES),
            (RingRail::Confidential | RingRail::Delegate, false) => {
                Some(&CONFIDENTIAL_TRANSFER_SHAPES)
            }
            (RingRail::Delegate | RingRail::AnonymousDelegate, true) => None,
        }
    }

    /// The family's shape at `outputs`, `None` off the catalog.
    pub fn of(family: &[Self], outputs: usize) -> Option<Self> {
        family
            .iter()
            .copied()
            .find(|shape| usize::from(shape.outputs) == outputs)
    }

    /// The smallest keyed capacity holding `legs`, `None` past the widest.
    pub fn withdrawal_capacity(self, legs: usize) -> Option<u8> {
        smallest_capacity(self.withdrawals, legs)
    }

    /// The smallest keyed row count holding `owners`, `None` past the widest.
    pub fn owner_capacity(self, owners: usize) -> Option<u8> {
        smallest_capacity(self.owners, owners)
    }
}

fn smallest_capacity(capacities: [u8; 2], needed: usize) -> Option<u8> {
    capacities
        .into_iter()
        .filter(|capacity| *capacity != 0)
        .find(|capacity| usize::from(*capacity) >= needed)
}

/// Addresses SPP takes beside its nullifier PDAs, zolana/docs/spec.md.
const SPP_ADDRESSES: usize = 4;
/// Ring program, ring, ring config, own, curator, tracking.
const RING_ADDRESSES: usize = 6;
/// A buffered settle's buffer and rent payer.
const BUFFER_ADDRESSES: usize = 2;

/// What takes a v1 transaction's addresses beside its owner signers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferAddresses {
    /// The shape's nullifier PDAs.
    pub n_inputs: usize,
    pub co_signers: usize,
    pub legs: usize,
    pub buffered: bool,
}

impl TransferAddresses {
    /// The owner signers that fit, a co-signer takes its record too.
    pub const fn owner_signers(self) -> usize {
        let buffer = if self.buffered { BUFFER_ADDRESSES } else { 0 };
        MAX_TRANSACTION_ADDRESSES
            .saturating_sub(SPP_ADDRESSES + RING_ADDRESSES + buffer)
            .saturating_sub(self.n_inputs + 2 * self.co_signers + self.legs)
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
    /// Distinct live input owners, rows the key opens.
    pub owners: usize,
    /// The frame carries data tails.
    pub has_data: bool,
}

impl RingCircuit {
    /// The one transfer key serving the spend, `None` when the catalog keys none.
    pub fn transfer(spend: TransferSpend) -> Option<Self> {
        let shapes = TransferShape::family(spend.rail, spend.spends_default_ring)?;
        let shape = TransferShape::of(shapes, spend.outputs)?;
        if spend.inputs == 0 || spend.inputs > usize::from(shape.inputs) {
            return None;
        }
        let withdrawals = shape.withdrawal_capacity(spend.legs)?;
        let owners = shape.owner_capacity(spend.owners)?;
        let (outputs, class, data) = (shape.outputs, shape.inputs, spend.has_data);
        Some(match (spend.rail, spend.spends_default_ring) {
            (RingRail::Anonymous | RingRail::AnonymousDelegate, false) => Self::TransferAnonymous {
                outputs,
                class,
                withdrawals,
                owners,
                data,
            },
            (RingRail::Anonymous, true) => Self::TransferAnonymousEntry {
                outputs,
                class,
                withdrawals,
                owners,
                data,
            },
            (_, true) => Self::TransferConfidentialEntry {
                outputs,
                class,
                withdrawals,
                owners,
                data,
            },
            (_, false) => Self::TransferConfidential {
                outputs,
                inputs: class,
                withdrawals,
                owners,
                data,
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

    /// The narrowest width holding `count` writes, `None` for an empty or oversized batch.
    pub fn apply_private_list(count: u64) -> Option<Self> {
        (count > 0)
            .then(|| {
                PRIVATE_LIST_APPLY_WIDTHS
                    .into_iter()
                    .find(|width| u64::from(*width) >= count)
            })
            .flatten()
            .map(|writes| Self::ApplyPrivateList { writes })
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
    pub tracking: usize,
}

impl RingCircuit {
    /// The withdrawal slots of a transfer key, `None` outside the transfer keys.
    pub fn withdrawals(self) -> Option<u8> {
        match self {
            Self::TransferConfidential { withdrawals, .. }
            | Self::TransferConfidentialEntry { withdrawals, .. }
            | Self::TransferAnonymous { withdrawals, .. }
            | Self::TransferAnonymousEntry { withdrawals, .. } => Some(withdrawals),
            _ => None,
        }
    }

    /// The owner rows of a transfer key, `None` outside the transfer keys.
    pub fn owners(self) -> Option<u8> {
        match self {
            Self::TransferConfidential { owners, .. }
            | Self::TransferConfidentialEntry { owners, .. }
            | Self::TransferAnonymous { owners, .. }
            | Self::TransferAnonymousEntry { owners, .. } => Some(owners),
            _ => None,
        }
    }

    /// Each pool takes as many subjects as records, `None` outside the transfer keys.
    pub fn record_pools(self) -> Option<RecordPools> {
        let (outputs, withdrawals, owners) = match self {
            Self::TransferConfidential {
                outputs,
                withdrawals,
                owners,
                ..
            }
            | Self::TransferConfidentialEntry {
                outputs,
                withdrawals,
                owners,
                ..
            }
            | Self::TransferAnonymous {
                outputs,
                withdrawals,
                owners,
                ..
            }
            | Self::TransferAnonymousEntry {
                outputs,
                withdrawals,
                owners,
                ..
            } => (
                usize::from(outputs),
                usize::from(withdrawals),
                usize::from(owners),
            ),
            _ => return None,
        };
        // Withdrawals settle through the public slots, their assets are at most N_PUBLIC_SLOTS.
        let withdrawal_assets = withdrawals.min(N_PUBLIC_SLOTS);
        let distinct = owners + 2 * outputs + withdrawals;
        Some(RecordPools {
            own: distinct + withdrawal_assets.max(N_PUBLIC_SLOTS),
            curator: distinct + withdrawal_assets,
            tracking: owners + outputs,
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
        let spend = |rail, inputs, outputs, spends_default_ring, legs, owners| {
            RingCircuit::transfer(TransferSpend {
                rail,
                inputs,
                outputs,
                spends_default_ring,
                legs,
                owners,
                has_data: false,
            })
        };
        let confidential = |outputs, inputs, withdrawals, owners| {
            Some(RingCircuit::TransferConfidential {
                outputs,
                inputs,
                withdrawals,
                owners,
                data: false,
            })
        };
        let anonymous = |outputs, class, withdrawals, owners| {
            Some(RingCircuit::TransferAnonymous {
                outputs,
                class,
                withdrawals,
                owners,
                data: false,
            })
        };
        let entry = |outputs, class, withdrawals, owners| {
            Some(RingCircuit::TransferAnonymousEntry {
                outputs,
                class,
                withdrawals,
                owners,
                data: false,
            })
        };
        use RingRail::{Anonymous, Confidential, Delegate};
        assert_eq!(
            spend(Confidential, 3, 2, false, 0, 1),
            confidential(2, 24, 4, 4)
        );
        assert_eq!(
            spend(Delegate, 2, 2, false, 5, 2),
            confidential(2, 24, 32, 4)
        );
        assert_eq!(spend(Confidential, 25, 2, false, 0, 1), None);
        assert_eq!(
            spend(Confidential, 5, 16, false, 8, 1),
            confidential(16, 5, 8, 4)
        );
        assert_eq!(spend(Confidential, 6, 16, false, 0, 1), None);
        assert_eq!(spend(Confidential, 1, 16, false, 9, 1), None);
        assert_eq!(spend(Confidential, 0, 2, false, 0, 1), None);
        assert_eq!(
            spend(Confidential, 1, 2, true, 0, 1),
            Some(RingCircuit::TransferConfidentialEntry {
                outputs: 2,
                class: 8,
                withdrawals: 4,
                owners: 4,
                data: false
            })
        );
        assert_eq!(spend(Delegate, 1, 2, true, 0, 1), None);
        assert_eq!(spend(Anonymous, 5, 8, false, 24, 1), anonymous(8, 5, 24, 4));
        assert_eq!(spend(Anonymous, 6, 8, false, 0, 1), None);
        assert_eq!(spend(Anonymous, 2, 8, true, 4, 2), entry(8, 2, 4, 2));
        assert_eq!(spend(Anonymous, 2, 8, true, 5, 1), None);
        assert_eq!(spend(Anonymous, 1, 16, false, 0, 1), None);
    }

    #[test]
    fn a_transfer_takes_the_smallest_owner_rows_holding_its_owners() {
        let owners = |outputs, inputs, owners| {
            RingCircuit::transfer(TransferSpend {
                rail: RingRail::Confidential,
                inputs,
                outputs,
                spends_default_ring: false,
                legs: 0,
                owners,
                has_data: false,
            })
            .and_then(RingCircuit::owners)
        };
        assert_eq!(owners(2, 24, 4), Some(4));
        assert_eq!(owners(2, 24, 5), Some(24));
        assert_eq!(owners(2, 24, 24), Some(24));
        assert_eq!(owners(2, 24, 25), None);
        assert_eq!(owners(8, 16, 16), Some(16));
        assert_eq!(owners(16, 5, 5), Some(5));
        assert_eq!(owners(16, 5, 6), None);
    }

    #[test]
    fn a_frame_with_tails_takes_the_data_key() {
        let circuit = RingCircuit::transfer(TransferSpend {
            rail: RingRail::Confidential,
            inputs: 2,
            outputs: 2,
            spends_default_ring: false,
            legs: 0,
            owners: 1,
            has_data: true,
        });
        assert_eq!(
            circuit,
            Some(RingCircuit::TransferConfidential {
                outputs: 2,
                inputs: 24,
                withdrawals: 4,
                owners: 4,
                data: true
            })
        );
    }

    #[test]
    fn the_address_bound_leaves_room_for_each_key_of_the_catalog() {
        let bound = |n_inputs, co_signers, legs, buffered| {
            TransferAddresses {
                n_inputs,
                co_signers,
                legs,
                buffered,
            }
            .owner_signers()
        };
        assert_eq!(bound(24, 0, 0, false), 30);
        assert_eq!(bound(32, 0, 0, false), 22);
        assert_eq!(bound(24, 5, 4, false), 16);
        assert_eq!(bound(24, 0, 0, true), 28);
        assert_eq!(bound(64, 5, 32, true), 0);
        for shape in CONFIDENTIAL_TRANSFER_SHAPES
            .iter()
            .chain(&ANONYMOUS_TRANSFER_SHAPES)
            .chain(&ENTRY_TRANSFER_SHAPES)
        {
            let n_inputs = usize::from(shape.inputs);
            assert!(
                usize::from(shape.owners[1].max(shape.owners[0])) <= bound(n_inputs, 0, 0, false)
            );
        }
    }

    #[test]
    fn the_pools_hold_every_screened_owner_output_and_withdrawal() {
        let pools = |circuit: RingCircuit| {
            let pools = circuit.record_pools().unwrap();
            (pools.own, pools.curator, pools.tracking)
        };
        let confidential =
            |outputs, inputs, withdrawals, owners| RingCircuit::TransferConfidential {
                outputs,
                inputs,
                withdrawals,
                owners,
                data: false,
            };
        let commitment = |outputs, class, withdrawals, owners| RingCircuit::TransferAnonymous {
            outputs,
            class,
            withdrawals,
            owners,
            data: false,
        };
        let entry = |outputs, class, withdrawals, owners| RingCircuit::TransferAnonymousEntry {
            outputs,
            class,
            withdrawals,
            owners,
            data: false,
        };
        assert_eq!(pools(confidential(2, 24, 4, 4)), (15, 15, 6));
        assert_eq!(pools(confidential(2, 24, 32, 4)), (43, 43, 6));
        assert_eq!(pools(confidential(2, 24, 4, 24)), (35, 35, 26));
        assert_eq!(pools(confidential(16, 5, 8, 4)), (47, 47, 20));
        assert_eq!(pools(commitment(4, 16, 32, 4)), (47, 47, 8));
        assert_eq!(pools(commitment(8, 5, 24, 5)), (48, 48, 13));
        assert_eq!(pools(entry(2, 8, 4, 4)), (15, 15, 6));
        assert_eq!(pools(entry(8, 2, 4, 2)), (25, 25, 10));
    }
}
