//! The withdrawal exemption, the waiver of the co-signer the withdrawal class alone demands.

use custom_ring_interface::{cosign::CoSignDemand, RingPolicy};
use spr_interface::N_PUBLIC_SLOTS;
use zolana_ring_client::records::RecordPoolRead;

use crate::RingError;

pub(super) fn waives_co_signer(
    ring: &RingPolicy,
    demand: &CoSignDemand,
) -> Result<bool, RingError> {
    Ok(!demand.withdrawals.is_empty()
        && demand.requirement(ring)?.is_some()
        && demand
            .clone()
            .exempt_withdrawals()
            .requirement(ring)?
            .is_none())
}

/// The bound the exempt proof asserts, checked before proving.
pub(super) fn thresholds_cover(
    pool: &RecordPoolRead,
    assets: &[[u8; 32]; N_PUBLIC_SLOTS],
    gross: &[u128; N_PUBLIC_SLOTS],
) -> bool {
    assets.iter().zip(gross).all(|(asset, gross)| {
        *gross == 0
            || pool
                .record(asset)
                .is_some_and(|record| u128::from(record.mint_policy.withdrawal_threshold) >= *gross)
    })
}
