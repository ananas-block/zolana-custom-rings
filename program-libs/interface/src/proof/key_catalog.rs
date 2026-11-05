//! Every ring circuit and its proving key, no verifying keys.
//!
//! A frame names its key by shape, and a key's widths fix its statement chains, its stream and its
//! record pools. A frame off the catalog has no key and `RingShapeUnkeyed` refuses it.
//!
//! Read after `program-libs/interface/src/codec/stream.rs`. Read before `program-libs/interface/src/proof/verification.rs`,
//! `programs/custom-ring/src/instructions/verification/verifier.rs`.

use spr_interface::{shape::MAX_TRANSACTION_ADDRESSES, N_PUBLIC_SLOTS};

use crate::{audit_stream::AuditKey, member_registry::APPLY_BATCH, transact::RingRail};

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
        /// A salted and a public record per owner fit.
        wide: bool,
    },
    ApplyRecords {
        writes: u8,
        mode: ApplyMode,
    },
    ApplyEnrollments {
        writes: u8,
    },
    RegisterKey,
    Deposit {
        capacity: u8,
    },
    Merge,
}

/// Mirror `Key.Private` in `prover/ring/keys.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    /// No write needs a tracking row, the key compiles no row opening.
    Public,
    /// At least one private owner write, the key compiles a tracking row opening per write slot.
    Private,
}

/// One transfer key, mirror `Shapes` in `prover/circuits/transfer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferShape {
    pub outputs: u8,
    pub inputs: u8,
    pub withdrawals: u8,
    pub owners: u8,
    pub entry: bool,
    pub wide: bool,
    /// The most tracking rows one inline transaction on the key opens.
    pub tracking: u8,
    /// The most owner and asset records one inline transaction reads in a pool, public slot assets aside.
    pub records: u8,
}

const fn narrow(
    outputs: u8,
    inputs: u8,
    withdrawals: u8,
    owners: u8,
    pools: [u8; 2],
) -> TransferShape {
    TransferShape {
        outputs,
        inputs,
        withdrawals,
        owners,
        entry: false,
        wide: false,
        tracking: pools[0],
        records: pools[1],
    }
}

const fn wide(
    outputs: u8,
    inputs: u8,
    withdrawals: u8,
    owners: u8,
    pools: [u8; 2],
) -> TransferShape {
    TransferShape {
        entry: false,
        wide: true,
        ..narrow(outputs, inputs, withdrawals, owners, pools)
    }
}

const fn entry(
    outputs: u8,
    inputs: u8,
    withdrawals: u8,
    owners: u8,
    pools: [u8; 2],
) -> TransferShape {
    TransferShape {
        entry: true,
        wide: true,
        ..narrow(outputs, inputs, withdrawals, owners, pools)
    }
}

/// Ascending outputs, a frame takes the first that holds its SPP width.
const NARROW_SHAPES: [TransferShape; 3] = [
    narrow(2, 24, 4, 4, [6, 12]),
    narrow(4, 24, 4, 4, [8, 16]),
    narrow(8, 16, 4, 4, [12, 24]),
];
/// The wide flag takes the first row holding the frame, the last only past 24 inputs.
const WIDE_SHAPES: [TransferShape; 2] =
    [wide(8, 24, 32, 13, [42, 88]), wide(2, 40, 4, 8, [11, 24])];
/// A frame takes the first row holding its width.
const ENTRY_SHAPES: [TransferShape; 3] = [
    entry(4, 8, 4, 8, [14, 32]),
    entry(8, 2, 4, 2, [14, 36]),
    entry(8, 5, 4, 4, [15, 38]),
];
const WIDE_ENTRY_SHAPE: TransferShape = entry(8, 8, 32, 8, [38, 80]);

/// Each key's widths and pools are exactly what the inline transactions it serves reach, pinned
/// by `ring-xtask inline-capacity`.
pub const TRANSFER_SHAPES: [TransferShape; 9] = [
    NARROW_SHAPES[0],
    NARROW_SHAPES[1],
    NARROW_SHAPES[2],
    WIDE_SHAPES[0],
    WIDE_SHAPES[1],
    ENTRY_SHAPES[0],
    ENTRY_SHAPES[1],
    ENTRY_SHAPES[2],
    WIDE_ENTRY_SHAPE,
];

/// What names a frame's key, nothing else moves a record's counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameKey {
    pub rail: RingRail,
    /// `n`, the frame's nullifier count.
    pub inputs: usize,
    pub outputs: usize,
    pub spends_default_ring: bool,
    pub wide: bool,
}

impl FrameKey {
    pub fn shape(self) -> Option<TransferShape> {
        let holds = |shape: &TransferShape| {
            self.outputs <= usize::from(shape.outputs) && self.inputs <= usize::from(shape.inputs)
        };
        // SPP's authority rail holds every input to the ring.
        let delegate = matches!(self.rail, RingRail::Delegate | RingRail::AnonymousDelegate);
        if delegate && self.spends_default_ring {
            return None;
        }
        match (self.spends_default_ring, self.wide) {
            (true, false) => ENTRY_SHAPES.into_iter().find(holds),
            (true, true) => Some(WIDE_ENTRY_SHAPE).filter(holds),
            (false, true) => WIDE_SHAPES.into_iter().find(holds),
            (false, false) => NARROW_SHAPES.into_iter().find(holds),
        }
    }
}

impl TransferShape {
    fn holds(self, spend: TransferSpend) -> bool {
        (1..=usize::from(self.inputs)).contains(&spend.inputs)
            && spend.legs <= usize::from(self.withdrawals)
            && spend.owners <= usize::from(self.owners)
            && self
                .circuit()
                .record_pools()
                .is_some_and(|pools| spend.pools.within(pools))
    }

    pub const fn audit_key(self) -> AuditKey {
        AuditKey {
            class: self.inputs as usize,
            entry: self.entry,
        }
    }

    /// A stream sealed under one row opens under the other, its records and tails keep their counters.
    /// The first record counter moves with an entry key's class, the first tail counter with `N`.
    #[must_use]
    pub const fn seals_like(self, other: Self, has_data: bool) -> bool {
        self.audit_key().first_record_counter() == other.audit_key().first_record_counter()
            && (!has_data || self.outputs == other.outputs)
    }

    /// The catalog row of `circuit`, `None` outside the transfer keys.
    #[must_use]
    pub fn of(circuit: RingCircuit) -> Option<Self> {
        TRANSFER_SHAPES
            .into_iter()
            .find(|shape| shape.circuit() == circuit)
    }

    const fn circuit(self) -> RingCircuit {
        RingCircuit::Transfer {
            outputs: self.outputs,
            inputs: self.inputs,
            withdrawals: self.withdrawals,
            owners: self.owners,
            entry: self.entry,
            wide: self.wide,
        }
    }
}

/// Addresses SPP takes beside its nullifier PDAs, zolana/docs/spec.md.
const SPP_ADDRESSES: usize = 4;
/// Ring program, ring, ring config, own, curator, tracking.
const RING_ADDRESSES: usize = 6;

/// The only spend input that moves a row's address cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowAuthorization {
    /// Every row signs in the owner run.
    Run,
    /// One row signs inside SPP's anonymous proof and spends ring notes only.
    InProof,
    /// One row hides, every withdrawal names one destination.
    Hidden,
}

impl RowAuthorization {
    /// Rows outside the owner run, each takes its nullifier PDA alone.
    pub const fn unsigned_rows(self) -> usize {
        match self {
            Self::Run => 0,
            Self::InProof | Self::Hidden => 1,
        }
    }
}

/// What takes a v1 transaction's addresses beside its owner signers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferAddresses {
    /// The shape's nullifier PDAs.
    pub n_inputs: usize,
    pub co_signers: usize,
    pub legs: usize,
}

impl TransferAddresses {
    /// The owner signers that fit, a co-signer takes its record too.
    #[must_use]
    pub const fn owner_signers(self) -> usize {
        MAX_TRANSACTION_ADDRESSES
            .saturating_sub(SPP_ADDRESSES + RING_ADDRESSES)
            .saturating_sub(self.n_inputs)
            .saturating_sub(self.co_signers.saturating_mul(2))
            .saturating_sub(self.legs)
    }

    /// The rows that fit, one bound for the catalog's pools and the SDK's refusal.
    #[must_use]
    pub const fn owner_rows(self, authorization: RowAuthorization) -> usize {
        self.owner_signers() + authorization.unsigned_rows()
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
    /// Distinct records the spend opens in each pool, a salted read takes a row beside the public one.
    pub pools: RecordPools,
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
            inputs: self.inputs,
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

    pub const fn apply_records(pending: u64, mode: ApplyMode) -> Self {
        Self::ApplyRecords {
            writes: apply_width(pending),
            mode,
        }
    }

    pub const fn apply_enrollments(pending: u64) -> Self {
        Self::ApplyEnrollments {
            writes: apply_width(pending),
        }
    }
}

/// The narrowest apply key width holding `pending` writes up to `APPLY_BATCH`, the same for every apply circuit.
pub const fn apply_width(pending: u64) -> u8 {
    match pending {
        0..=1 => 1,
        2 => 2,
        3..=4 => 4,
        5..=8 => 8,
        _ => APPLY_BATCH as u8,
    }
}

/// A transfer key's record pool widths, mirror `recordCapacity` in `prover/circuits/policy/record_pool.go`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordPools {
    pub own: usize,
    pub curator: usize,
    pub tracking: usize,
}

impl RecordPools {
    const fn within(self, capacity: Self) -> bool {
        self.own <= capacity.own
            && self.curator <= capacity.curator
            && self.tracking <= capacity.tracking
    }
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
        let shape = TransferShape::of(self)?;
        // Withdrawals settle through the public slots, their assets are at most N_PUBLIC_SLOTS.
        let withdrawal_assets = usize::from(shape.withdrawals).min(N_PUBLIC_SLOTS);
        // An input slot takes no row, its asset reads a payment's record or a free one and a spend
        // past the rows selects the wide key.
        let records = usize::from(shape.records);
        Some(RecordPools {
            own: records + withdrawal_assets.max(N_PUBLIC_SLOTS),
            curator: records + withdrawal_assets,
            tracking: usize::from(shape.tracking),
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
            pools: RecordPools::default(),
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
    fn the_wide_flag_names_the_wide_key_of_the_width() {
        let key =
            |outputs| RingCircuit::transfer(spend(RingRail::Confidential, outputs, false, true));
        assert_eq!(key(2), Some(wide(8, 24, 32, 24).circuit()));
        assert_eq!(key(8), Some(wide(8, 24, 32, 24).circuit()));
        assert_eq!(key(16), Some(wide(16, 5, 8, 5).circuit()));
        assert_eq!(key(17), None);
    }

    #[test]
    fn the_published_inputs_route_a_two_output_wide_spend() {
        let wide_spend = |inputs, legs, owners| {
            RingCircuit::transfer(TransferSpend {
                inputs,
                legs,
                owners,
                ..spend(RingRail::Confidential, 2, false, true)
            })
        };
        let forty_nine = Some(wide(2, 49, 4, 12).circuit());
        assert_eq!(wide_spend(24, 0, 1), Some(wide(8, 24, 32, 24).circuit()));
        assert_eq!(wide_spend(25, 0, 1), forty_nine);
        assert_eq!(wide_spend(49, 4, 12), forty_nine);
        assert_eq!(wide_spend(50, 0, 1), None);
        assert_eq!(wide_spend(25, 5, 1), None);
        assert_eq!(wide_spend(25, 0, 13), None);
        assert_eq!(
            forty_nine.and_then(RingCircuit::record_pools),
            Some(RecordPools {
                own: 41,
                curator: 41,
                tracking: 18
            })
        );
    }

    #[test]
    fn a_narrow_spend_past_24_inputs_fits_the_wide_flag() {
        let fitted = |inputs| {
            TransferSpend {
                inputs,
                ..spend(RingRail::Confidential, 2, false, false)
            }
            .fitted()
        };
        assert!(!fitted(24).wide);
        assert_eq!(
            RingCircuit::transfer(fitted(24)),
            Some(transfer(2, 24, 4, 4))
        );
        assert!(fitted(25).wide);
        assert_eq!(
            RingCircuit::transfer(fitted(25)),
            Some(wide(2, 49, 4, 12).circuit())
        );
    }

    #[test]
    fn an_entry_past_the_small_keys_fits_the_wide_entry_key() {
        let entered = |inputs, outputs, legs, owners| {
            RingCircuit::transfer(
                TransferSpend {
                    inputs,
                    legs,
                    owners,
                    ..spend(RingRail::Anonymous, outputs, true, false)
                }
                .fitted(),
            )
        };
        let wide_entry = Some(entry(2, 24, 32, 12).circuit());
        assert_eq!(entered(8, 2, 4, 8), Some(entry(4, 8, 4, 8).circuit()));
        assert_eq!(entered(2, 8, 4, 2), Some(entry(8, 2, 4, 2).circuit()));
        assert_eq!(entered(9, 2, 0, 1), wide_entry);
        assert_eq!(entered(24, 2, 32, 12), wide_entry);
        assert_eq!(entered(1, 2, 5, 1), wide_entry);
        assert_eq!(entered(25, 2, 0, 1), None);
        assert_eq!(entered(9, 4, 0, 1), None);
        assert_eq!(entered(9, 2, 33, 1), None);
        assert_eq!(entered(9, 2, 0, 13), None);
        assert_eq!(
            wide_entry.and_then(RingCircuit::record_pools),
            Some(RecordPools {
                own: 95,
                curator: 95,
                tracking: 45
            })
        );
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
        assert_eq!(past(1, 5, 5, true), Some(wide(8, 24, 32, 24).circuit()));
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
        let first = Some(entry(4, 8, 4, 8).circuit());
        assert_eq!(entered(RingRail::Confidential, 2, 8, 8), first);
        assert_eq!(entered(RingRail::Anonymous, 4, 1, 1), first);
        assert_eq!(
            entered(RingRail::Anonymous, 8, 2, 2),
            Some(entry(8, 2, 4, 2).circuit())
        );
        let four_inputs = Some(entry(8, 4, 4, 4).circuit());
        assert_eq!(entered(RingRail::Anonymous, 8, 3, 1), four_inputs);
        assert_eq!(entered(RingRail::Confidential, 8, 4, 4), four_inputs);
        assert_eq!(entered(RingRail::Anonymous, 8, 5, 1), None);
        assert_eq!(entered(RingRail::Delegate, 2, 1, 1), None);
        assert_eq!(entered(RingRail::AnonymousDelegate, 2, 1, 1), None);
    }

    #[test]
    fn the_address_bound_leaves_room_for_each_key_of_the_catalog() {
        let bound = |n_inputs, co_signers, legs| {
            TransferAddresses {
                n_inputs,
                co_signers,
                legs,
            }
            .owner_signers()
        };
        assert_eq!(bound(24, 0, 0), 30);
        assert_eq!(bound(32, 0, 0), 22);
        assert_eq!(bound(24, 5, 4), 16);
        assert_eq!(bound(64, 5, 32), 0);
        for shape in TRANSFER_SHAPES {
            let owners = usize::from(shape.owners);
            assert!(owners <= bound(owners, 0, 0));
        }
    }

    #[test]
    fn oversized_account_counts_leave_no_owner_capacity() {
        let base = TransferAddresses::default();
        for accounts in [
            TransferAddresses {
                n_inputs: usize::MAX,
                ..base
            },
            TransferAddresses {
                co_signers: usize::MAX,
                ..base
            },
            TransferAddresses {
                legs: usize::MAX,
                ..base
            },
        ] {
            assert_eq!(accounts.owner_signers(), 0);
        }
    }

    #[test]
    fn the_pools_hold_every_screened_owner_output_and_withdrawal() {
        let pools = |circuit: RingCircuit| {
            let pools = circuit.record_pools().unwrap();
            (pools.own, pools.curator, pools.tracking)
        };
        assert_eq!(pools(transfer(2, 24, 4, 4)), (15, 15, 6));
        assert_eq!(pools(wide(8, 24, 32, 24).circuit()), (113, 113, 51));
        assert_eq!(pools(transfer(16, 5, 8, 5)), (48, 48, 21));
        assert_eq!(pools(wide(16, 5, 8, 5).circuit()), (77, 77, 29));
        assert_eq!(pools(entry(4, 8, 4, 8).circuit()), (39, 39, 16));
        assert_eq!(pools(entry(8, 2, 4, 2).circuit()), (39, 39, 14));
        assert_eq!(pools(wide(16, 8, 8, 8).circuit()), (83, 83, 32));
        assert_eq!(pools(entry(8, 4, 4, 4).circuit()), (43, 43, 16));
    }

    #[test]
    fn a_spend_past_a_narrow_keys_pools_moves_to_the_wide_key() {
        let fitted = |outputs, pools| {
            RingCircuit::transfer(
                TransferSpend {
                    pools,
                    ..spend(RingRail::Confidential, outputs, false, false)
                }
                .fitted(),
            )
        };
        let tracked = RecordPools {
            tracking: 7,
            ..RecordPools::default()
        };
        assert_eq!(fitted(2, tracked), Some(wide(8, 24, 32, 24).circuit()));
        // Two owners, the payment's asset and 13 unmatched input assets hold the 15 narrow rows.
        let distinct_assets = |unmatched: usize| RecordPools {
            own: 2 + 1 + unmatched,
            ..RecordPools::default()
        };
        assert_eq!(fitted(2, distinct_assets(12)), Some(transfer(2, 24, 4, 4)));
        assert_eq!(
            fitted(2, distinct_assets(13)),
            Some(wide(8, 24, 32, 24).circuit())
        );
        assert_eq!(
            fitted(2, RecordPools::default()),
            Some(transfer(2, 24, 4, 4))
        );
        let past_sixteen = RecordPools {
            own: 78,
            ..RecordPools::default()
        };
        assert_eq!(fitted(16, past_sixteen), None);
        // 29 owners and one asset, each owner a public and a salted record.
        let salted = RecordPools {
            own: 2 * 29 + 1,
            curator: 2 * 29 + 1,
            tracking: 29,
        };
        assert_eq!(fitted(16, salted), Some(wide(16, 5, 8, 5).circuit()));
        let public = RecordPools {
            own: 29 + 1,
            curator: 29 + 1,
            tracking: 21,
        };
        assert_eq!(fitted(16, public), Some(transfer(16, 5, 8, 5)));
    }

    #[test]
    fn sixteen_outputs_past_five_inputs_take_the_eight_input_key() {
        let fitted = |inputs, legs, owners| {
            let spend = TransferSpend {
                inputs,
                legs,
                owners,
                ..spend(RingRail::Confidential, 16, false, false)
            }
            .fitted();
            (spend.wide, RingCircuit::transfer(spend))
        };
        let eight = Some(wide(16, 8, 8, 8).circuit());
        assert_eq!(fitted(5, 8, 5), (false, Some(transfer(16, 5, 8, 5))));
        assert_eq!(fitted(6, 0, 1), (true, eight));
        assert_eq!(fitted(8, 8, 8), (true, eight));
        assert_eq!(fitted(9, 0, 1), (true, None));
        assert_eq!(fitted(8, 9, 1), (true, None));
        assert_eq!(fitted(8, 0, 9), (true, None));
    }

    #[test]
    fn ordinary_seals_keep_record_positions_across_input_capacities() {
        let smaller = narrow(2, 24, 4, 4);
        let larger = wide(2, 49, 4, 12);
        assert!(smaller.seals_like(larger, false));
        assert!(smaller.seals_like(larger, true));
    }

    #[test]
    fn data_tails_bind_output_capacity() {
        let smaller = narrow(2, 24, 4, 4);
        let larger = wide(8, 24, 32, 24);
        assert!(smaller.seals_like(larger, false));
        assert!(!smaller.seals_like(larger, true));
    }

    #[test]
    fn entry_seals_bind_input_capacity() {
        let smaller = entry(8, 2, 4, 2);
        let larger = entry(8, 4, 4, 4);
        assert!(!smaller.seals_like(larger, false));
        assert!(!smaller.seals_like(larger, true));
    }

    #[test]
    fn record_pool_width_does_not_move_the_stream() {
        let smaller = narrow(16, 5, 8, 5);
        let larger = wide(16, 5, 8, 5);
        assert!(smaller.seals_like(larger, false));
        assert!(smaller.seals_like(larger, true));
    }
}
