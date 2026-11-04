use custom_ring_interface::{compute_unit_limit, tag, CustomRingError, InstructionTag};

#[test]
fn ring_dispatch_tags_do_not_collide_with_forwarded_spp_tags() {
    let tags = [
        spr_interface::instruction::tag::RING_DEPOSIT,
        tag::INITIALIZE,
        tag::UPDATE_POLICY,
        tag::TRANSFER,
        tag::MERGE,
        tag::UPDATE_AUTHORITY,
        tag::SET_PAUSED,
        tag::SET_CO_SIGNER,
        tag::CLEAR_CO_SIGNER,
        tag::SET_DELEGATE,
        tag::AUTHORITY_TRANSFER,
        tag::DEPOSIT,
        tag::HISTORICAL_TRANSFER,
        tag::HISTORICAL_TRANSFER_V3,
        tag::HISTORICAL_AUTHORITY_TRANSFER,
        tag::HISTORICAL_AUTHORITY_TRANSFER_V3,
        tag::HISTORICAL_DEPOSIT,
        tag::HISTORICAL_MERGE,
        tag::HISTORICAL_MERGE_V3,
        tag::LEGACY_TRANSACT,
        tag::LEGACY_DELEGATE_TRANSACT,
        tag::WRITE_FRAME,
        tag::CLOSE_FRAME_BUFFER,
        tag::SETTLE_BUFFERED,
        tag::FRAME_EVENT,
    ];
    let unique: std::collections::BTreeSet<_> = tags.into_iter().collect();
    assert_eq!(unique.len(), tags.len());
}

/// A statement version is hashed and unreadable, the tag alone tells a frame apart.
#[test]
fn every_frame_generation_has_its_own_tag() {
    assert_eq!(
        (
            tag::TRANSFER,
            tag::AUTHORITY_TRANSFER,
            tag::MERGE,
            tag::DEPOSIT
        ),
        (55, 56, 57, 58)
    );
    assert_eq!(
        (tag::HISTORICAL_TRANSFER, tag::HISTORICAL_AUTHORITY_TRANSFER),
        (43, 44)
    );
    assert_eq!(tag::HISTORICAL_MERGE_V3, 47);
    assert_eq!(
        tag::HISTORICAL_MERGE,
        spr_interface::instruction::tag::RING_MERGE_TRANSACT
    );
}

#[test]
fn retired_tags_name_no_instruction() {
    for retired in [
        1, 2, 4, 5, 7, 8, 9, 10, 12, 18, 22, 23, 26, 28, 29, 30, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 48,
    ] {
        assert_eq!(
            InstructionTag::try_from(retired),
            Err(CustomRingError::InvalidInstructionData),
            "{retired}"
        );
    }
}

#[test]
fn every_tag_names_one_instruction_and_its_budget() {
    for value in 0..=u8::MAX {
        if let Ok(tag) = InstructionTag::try_from(value) {
            assert!((50_000..=1_400_000).contains(&compute_unit_limit(tag)));
        }
    }
    assert_eq!(
        InstructionTag::try_from(0),
        Err(CustomRingError::InvalidInstructionData)
    );
    assert_eq!(compute_unit_limit(InstructionTag::SetPaused), 50_000);
    assert_eq!(compute_unit_limit(InstructionTag::UpdatePolicy), 150_000);
    assert_eq!(compute_unit_limit(InstructionTag::Transfer), 1_400_000);
}
