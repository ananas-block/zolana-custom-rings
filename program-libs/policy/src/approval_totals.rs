//! The totals a transfer proof binds for a co-signer, mirror `Screening.AssertApprovalTotals` in `prover/circuits/policy/screen.go`.

use spr_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::right_align, HasherError};

use crate::quantities::{asset_flows, ordered_owners, DebitTransfer, PublicGross};

/// "CRAO".
pub const APPROVAL_TOTALS_DOMAIN: u32 = 0x4352_414f;

/// `peak` is one owner's largest outflow of the asset, the value `cosign_above` compares.
#[must_use]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutputTotals {
    /// Zero on a dummy slot.
    pub asset: [u8; 32],
    pub peak: u128,
    pub outflow: u128,
}

/// `peak` and `outflow` read debits alone, a charged asset reads whole under its live output.
#[must_use]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicTotals {
    pub asset: [u8; 32],
    pub peak: u128,
    pub outflow: u128,
    pub gross: u128,
}

/// The layout every key commits, a slot past the live ones reads zeros.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalTotals {
    /// One per output slot of the key.
    pub outputs: Vec<OutputTotals>,
    /// One per public slot of the statement.
    pub public: Vec<PublicTotals>,
}

impl ApprovalTotals {
    /// `slot_assets` holds `None` on a dummy slot, `public_slots` follows the statement's order.
    pub fn new(
        transfer: &DebitTransfer<'_>,
        slot_assets: &[Option<[u8; 32]>],
        public_slots: &[PublicGross],
    ) -> Self {
        let owners = ordered_owners(transfer);
        Self {
            outputs: slot_assets
                .iter()
                .map(|slot| {
                    slot.map_or(OutputTotals::default(), |asset| {
                        let (peak, outflow) = peak_and_sum(
                            asset_flows(transfer, &owners, &asset)
                                .iter()
                                .map(|row| row.outflow),
                        );
                        OutputTotals {
                            asset,
                            peak,
                            outflow,
                        }
                    })
                })
                .collect(),
            public: public_slots
                .iter()
                .map(|slot| {
                    let (peak, outflow) = peak_and_sum(
                        asset_flows(transfer, &owners, &slot.asset)
                            .iter()
                            .map(|row| row.debit),
                    );
                    PublicTotals {
                        asset: slot.asset,
                        peak,
                        outflow,
                        gross: slot.gross,
                    }
                })
                .collect(),
        }
    }

    /// The largest peak the layout holds for `asset`, zero when absent.
    pub fn peak_of(&self, asset: &[u8; 32]) -> u128 {
        let outputs = self.outputs.iter().filter(|slot| slot.asset == *asset);
        let public = self.public.iter().filter(|slot| slot.asset == *asset);
        outputs
            .map(|slot| slot.peak)
            .chain(public.map(|slot| slot.peak))
            .max()
            .unwrap_or(0)
    }

    /// The frame's `approval_totals` extension, `HashChain4(CRAO, blinder, layout)`, the blinder fresh per transaction.
    pub fn commitment(&self, blinder: &[u8; 32]) -> Result<[u8; 32], HasherError> {
        let mut fields = vec![right_align(&APPROVAL_TOTALS_DOMAIN.to_be_bytes()), *blinder];
        for slot in &self.outputs {
            fields.extend([
                slot.asset,
                right_align(&slot.peak.to_be_bytes()),
                right_align(&slot.outflow.to_be_bytes()),
            ]);
        }
        for slot in &self.public {
            fields.extend([
                slot.asset,
                right_align(&slot.peak.to_be_bytes()),
                right_align(&slot.outflow.to_be_bytes()),
                right_align(&slot.gross.to_be_bytes()),
            ]);
        }
        create_hash_chain_4_from_slice(&fields)
    }
}

fn peak_and_sum(values: impl Iterator<Item = u128>) -> (u128, u128) {
    values.fold((0, 0), |(peak, sum), value| (peak.max(value), sum + value))
}
