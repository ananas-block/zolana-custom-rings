use super::*;

/// The operator can consolidate notes owned by the persistent demo wallet. The
/// command proves, lands and reads back the merge instead of stopping at an
/// instruction-builder assertion.
#[test]
fn cli_merges_fragmented_custom_ring_notes() -> Result<()> {
    cli_merge_fragments(&[3_000_000, 5_000_000])
}

#[test]
fn cli_merges_twenty_four_custom_ring_utxos() -> Result<()> {
    cli_merge_fragments(&[3_000_000; 24])
}

/// A requested count above the anonymous key's width leaves the excess notes unspent.
#[test]
fn cli_caps_anonymous_merge_at_supported_width() -> Result<()> {
    cli_merge_fragments(&[3_000_000; custom_ring_sdk::MAX_RING_MERGE_INPUTS])
}
