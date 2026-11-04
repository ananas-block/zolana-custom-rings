//! Every ring circuit and its proving key, no verifying keys.
use spr_interface::{shape::MAX_TRANSACTION_ADDRESSES, N_PUBLIC_SLOTS};

use crate::{
    audit_stream::AuditKey, member_registry::APPLY_BATCH, private_list::PRIVATE_LIST_APPLY_WIDTHS,
    transact::RingRail,
};

pub use crate::ring_keys::RING_KEYS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingCircuit {
    /// Every rail, the statement's bits name it.
    Transfer {
        outputs: u8,
        /// The widest published input count.
        inputs: u8,
        withdrawals: u8,
        owners: u8,
        /// One evidence slot per input, the key also spends default-ring notes.
        entry: bool,
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

/// One transfer key, mirror `Shapes` in `prover/circuits/transfer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferShape {
    pub outputs: u8,
    pub inputs: u8,
    pub withdrawals: u8,
    pub owners: u8,
    pub entry: bool,
}

const fn narrow(outputs: u8, inputs: u8, withdrawals: u8, owners: u8) -> TransferShape {
    TransferShape {
        outputs,
        inputs,
        withdrawals,
        owners,
        entry: false,
    }
}

const fn entry(outputs: u8, inputs: u8, owners: u8) -> TransferShape {
    TransferShape {
        outputs,
        inputs,
        withdrawals: 4,
        owners,
        entry: true,
    }
}

/// Ascending outputs, a frame takes the first that holds its SPP width.
const NARROW_SHAPES: [TransferShape; 4] = [
    narrow(2, 24, 4, 4),
    narrow(4, 24, 4, 4),
    narrow(8, 16, 4, 4),
    narrow(16, 5, 8, 5),
];
const WIDE_SHAPE: TransferShape = narrow(8, 24, 32, 24);
const ENTRY_SHAPES: [TransferShape; 2] = [entry(4, 8, 8), entry(8, 2, 2)];

pub const TRANSFER_SHAPES: [TransferShape; 7] = [
    NARROW_SHAPES[0],
    NARROW_SHAPES[1],
    NARROW_SHAPES[2],
    NARROW_SHAPES[3],
    WIDE_SHAPE,
    ENTRY_SHAPES[0],
    ENTRY_SHAPES[1],
];

/// What names a frame's key, nothing else moves a record's counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameKey {
    pub rail: RingRail,
    pub outputs: usize,
    pub spends_default_ring: bool,
    pub wide: bool,
}

impl FrameKey {
    pub fn shape(self) -> Option<TransferShape> {
        let holds = |shape: &TransferShape| self.outputs <= usize::from(shape.outputs);
        // SPP's authority rail holds every input to the ring.
        let delegate = matches!(self.rail, RingRail::Delegate | RingRail::AnonymousDelegate);
        if delegate && self.spends_default_ring {
            return None;
        }
        match (self.spends_default_ring, self.wide) {
            (true, _) => ENTRY_SHAPES.into_iter().find(holds),
            (false, true) => Some(WIDE_SHAPE).filter(holds),
            (false, false) => NARROW_SHAPES.into_iter().find(holds),
        }
    }
}

impl TransferShape {
    fn holds(self, spend: TransferSpend) -> bool {
        (1..=usize::from(self.inputs)).contains(&spend.inputs)
            && spend.legs <= usize::from(self.withdrawals)
            && spend.owners <= usize::from(self.owners)
    }

    pub const fn audit_key(self) -> AuditKey {
        AuditKey {
            class: self.inputs as usize,
            entry: self.entry,
        }
    }

    const fn circuit(self) -> RingCircuit {
        RingCircuit::Transfer {
            outputs: self.outputs,
            inputs: self.inputs,
            withdrawals: self.withdrawals,
            owners: self.owners,
            entry: self.entry,
        }
    }
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
    /// The header's wide flag, `fitted` derives it from the spend.
    pub wide: bool,
}

impl TransferSpend {
    /// The wide flag follows the narrow key failing to hold the spend.
    #[must_use]
    pub fn fitted(self) -> Self {
        let narrow = FrameKey {
            wide: false,
            ..self.frame_key()
        }
        .shape();
        Self {
            wide: !narrow.is_some_and(|shape| shape.holds(self)),
            ..self
        }
    }

    const fn frame_key(self) -> FrameKey {
        FrameKey {
            rail: self.rail,
            outputs: self.outputs,
            spends_default_ring: self.spends_default_ring,
            wide: self.wide,
        }
    }
}

impl RingCircuit {
    /// The one transfer key serving the spend, `None` when the catalog keys none.
    pub fn transfer(spend: TransferSpend) -> Option<Self> {
        spend
            .frame_key()
            .shape()
            .filter(|shape| shape.holds(spend))
            .map(TransferShape::circuit)
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
            Self::Transfer { withdrawals, .. } => Some(withdrawals),
            _ => None,
        }
    }

    /// The owner rows of a transfer key, `None` outside the transfer keys.
    pub fn owners(self) -> Option<u8> {
        match self {
            Self::Transfer { owners, .. } => Some(owners),
            _ => None,
        }
    }

    /// Each pool takes as many subjects as records, `None` outside the transfer keys.
    pub fn record_pools(self) -> Option<RecordPools> {
        let Self::Transfer {
            outputs,
            withdrawals,
            owners,
            ..
        } = self
        else {
            return None;
        };
        let (outputs, withdrawals, owners) = (
            usize::from(outputs),
            usize::from(withdrawals),
            usize::from(owners),
        );
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

    fn spend(
        rail: RingRail,
        outputs: usize,
        spends_default_ring: bool,
        wide: bool,
    ) -> TransferSpend {
        TransferSpend {
            rail,
            inputs: 1,
            outputs,
            spends_default_ring,
            legs: 0,
            owners: 1,
            wide,
        }
    }

    const fn transfer(outputs: u8, inputs: u8, withdrawals: u8, owners: u8) -> RingCircuit {
        narrow(outputs, inputs, withdrawals, owners).circuit()
    }

    #[test]
    fn every_rail_shares_the_key_of_its_output_width() {
        for rail in [
            RingRail::Confidential,
            RingRail::Anonymous,
            RingRail::Delegate,
            RingRail::AnonymousDelegate,
        ] {
            let key = |outputs| RingCircuit::transfer(spend(rail, outputs, false, false));
            assert_eq!(key(2), Some(transfer(2, 24, 4, 4)));
            assert_eq!(key(4), Some(transfer(4, 24, 4, 4)));
            assert_eq!(key(8), Some(transfer(8, 16, 4, 4)));
            assert_eq!(key(16), Some(transfer(16, 5, 8, 5)));
            assert_eq!(key(17), None);
        }
    }

    #[test]
    fn the_wide_flag_names_the_one_wide_key() {
        let wide =
            |outputs| RingCircuit::transfer(spend(RingRail::Confidential, outputs, false, true));
        assert_eq!(wide(2), Some(transfer(8, 24, 32, 24)));
        assert_eq!(wide(8), Some(transfer(8, 24, 32, 24)));
        assert_eq!(wide(16), None);
    }

    #[test]
    fn a_spend_past_its_key_is_unkeyed() {
        let past = |inputs, legs, owners, wide| {
            RingCircuit::transfer(TransferSpend {
                inputs,
                legs,
                owners,
                ..spend(RingRail::Confidential, 2, false, wide)
            })
        };
        assert_eq!(past(24, 4, 4, false), Some(transfer(2, 24, 4, 4)));
        assert_eq!(past(0, 0, 1, false), None);
        assert_eq!(past(25, 0, 1, false), None);
        assert_eq!(past(1, 5, 1, false), None);
        assert_eq!(past(1, 0, 5, false), None);
        assert_eq!(past(1, 5, 5, true), Some(transfer(8, 24, 32, 24)));
        assert_eq!(past(1, 33, 1, true), None);
        assert_eq!(past(1, 0, 25, true), None);
    }

    #[test]
    fn a_spend_past_the_narrow_key_fits_the_wide_flag() {
        let fitted = |outputs, inputs, legs, owners| {
            TransferSpend {
                inputs,
                legs,
                owners,
                ..spend(RingRail::Confidential, outputs, false, false)
            }
            .fitted()
            .wide
        };
        assert!(!fitted(2, 24, 4, 4));
        assert!(fitted(2, 1, 5, 1));
        assert!(fitted(2, 5, 0, 5));
        assert!(!fitted(16, 5, 8, 5));
        assert!(fitted(8, 17, 0, 1));
    }

    #[test]
    fn an_entry_takes_the_first_entry_key_holding_its_width() {
        let entered = |rail, outputs, inputs, owners| {
            RingCircuit::transfer(TransferSpend {
                inputs,
                owners,
                ..spend(rail, outputs, true, false)
            })
        };
        let first = Some(entry(4, 8, 8).circuit());
        assert_eq!(entered(RingRail::Confidential, 2, 8, 8), first);
        assert_eq!(entered(RingRail::Anonymous, 4, 1, 1), first);
        assert_eq!(
            entered(RingRail::Anonymous, 8, 2, 2),
            Some(entry(8, 2, 2).circuit())
        );
        assert_eq!(entered(RingRail::Anonymous, 8, 3, 1), None);
        assert_eq!(entered(RingRail::Delegate, 2, 1, 1), None);
        assert_eq!(entered(RingRail::AnonymousDelegate, 2, 1, 1), None);
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
        for shape in TRANSFER_SHAPES {
            let n_inputs = usize::from(shape.inputs);
            assert!(usize::from(shape.owners) <= bound(n_inputs, 0, 0, false));
        }
    }

    #[test]
    fn the_pools_hold_every_screened_owner_output_and_withdrawal() {
        let pools = |circuit: RingCircuit| {
            let pools = circuit.record_pools().unwrap();
            (pools.own, pools.curator, pools.tracking)
        };
        assert_eq!(pools(transfer(2, 24, 4, 4)), (15, 15, 6));
        assert_eq!(pools(transfer(8, 24, 32, 24)), (75, 75, 32));
        assert_eq!(pools(transfer(16, 5, 8, 5)), (48, 48, 21));
        assert_eq!(pools(entry(4, 8, 8).circuit()), (23, 23, 12));
        assert_eq!(pools(entry(8, 2, 2).circuit()), (25, 25, 10));
    }
}
