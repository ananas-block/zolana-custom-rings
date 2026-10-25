use super::*;

const TABLE: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
    .rule(Rule::require(Subject::Asset, ListId::Allow))
    .build();

const EMPTY: RuleTable = RuleTable::builder().build();

const GROUP: RuleTable = RuleTable::builder()
    .rule(Rule::require_any(
        Subject::OutputOwner,
        ListSet::of(&[ListId::Allow, ListId::Frozen]),
    ))
    .build();

fn sources(entries: &[(ListId, [u8; 32])]) -> SourceMap {
    SourceMap::new(entries).unwrap()
}

/// `tail` is `[guard_tag, mask, mode, subject]`.
fn packed(tail: [u8; 4], threshold: u64, alternative: u8) -> [u8; 32] {
    let mut row = [0u8; 32];
    row[19] = alternative;
    row[20..28].copy_from_slice(&threshold.to_be_bytes());
    row[28..].copy_from_slice(&tail);
    row
}

fn sender_rules() -> impl Iterator<Item = Rule> {
    ListId::ALL
        .into_iter()
        .map(|list_id| Rule::require(Subject::Sender, list_id))
        .chain(
            ListId::ALL
                .into_iter()
                .map(|list_id| Rule::forbid(Subject::Sender, list_id)),
        )
}

fn with_rules(
    mut builder: RuleTableBuilder,
    rules: impl Iterator<Item = Rule>,
) -> RuleTableBuilder {
    for rule in rules {
        builder = builder.rule(rule);
    }
    builder
}

#[test]
fn the_table_keeps_declaration_order_and_the_pool() {
    let rules = TABLE.rules();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].subject, Subject::OutputOwner);
    assert_eq!(rules[1].primary_mode(), Mode::Absent);
    assert_eq!(rules[2], Rule::require(Subject::Asset, ListId::Allow));
    assert_eq!(RuleTable::empty(), EMPTY);
    assert!(EMPTY.is_empty());
    assert_eq!(EMPTY.encode(), EncodedRuleTable::default());
}

#[test]
fn an_own_list_maps_to_the_zero_registry_and_one_curator_serves_the_rest() {
    let map = sources(&[(ListId::Allow, [0u8; 32]), (ListId::Block, [9u8; 32])]);
    assert_eq!(map.registry(ListId::Allow), Some(&[0u8; 32]));
    assert_eq!(map.registry(ListId::Block), Some(&[9u8; 32]));
    assert_eq!(map.registry(ListId::Frozen), None);
    assert_eq!(map.curator(), Some([9u8; 32]));
    assert_eq!(sources(&[(ListId::Allow, [0u8; 32])]).curator(), None);
    assert_eq!(
        SourceMap::new(&[(ListId::Allow, [9u8; 32]), (ListId::Block, [8u8; 32])]),
        Err(SourceMapError::SeveralCurators)
    );
    let mut slots = *map.slots();
    slots[ListId::Frozen.slot()] = PolicySource {
        list_id: ListId::Frozen as u8,
        registry: [8u8; 32],
    };
    assert_eq!(
        SourceMap::from_slots(slots),
        Err(SourceMapError::SeveralCurators)
    );
}

#[test]
fn rows_pack_the_circuit_byte_positions() {
    assert_eq!(
        Rule::require(Subject::OutputOwner, ListId::Allow).encoded(),
        packed([0, 0b0000_0001, 1, 1], 0, 0)
    );
    assert_eq!(
        Rule::forbid(Subject::Sender, ListId::Frozen).encoded(),
        packed([0, 0b0000_0100, 2, 2], 0, 0)
    );
    assert_eq!(
        Rule::require(Subject::OutputOwner, ListId::Approval)
            .above(2000)
            .encoded(),
        packed([1, 0b0100_0000, 1, 1], 2000, 0)
    );
    assert_eq!(
        Rule::require(Subject::Asset, ListId::Allow).encoded(),
        packed([0, 1, 1, 4], 0, 0)
    );
    assert_eq!(
        Rule::any_of(
            Subject::OutputOwner,
            ListSet::single(ListId::Allow),
            ListSet::single(ListId::Block),
        )
        .encoded(),
        packed([0, 0b0000_0001, 1, 1], 0, 0b0000_0010)
    );
    assert_eq!(
        Rule::forbid_all(
            Subject::OutputOwner,
            ListSet::of(&[ListId::Block, ListId::Frozen])
        )
        .encoded(),
        packed([0, 0b0000_0110, 2, 1], 0, 0)
    );
    assert_eq!(
        Rule::require_any(
            Subject::Sender,
            ListSet::of(&[ListId::Allow, ListId::Frozen])
        )
        .encoded(),
        packed([0, 0b0000_0101, 1, 2], 0, 0)
    );
}

#[test]
fn a_group_references_the_union_of_its_lists() {
    assert_eq!(
        Rule::require(Subject::OutputOwner, ListId::Allow)
            .referenced()
            .bits(),
        0b0000_0001
    );
    assert_eq!(
        Rule::any_of(
            Subject::OutputOwner,
            ListSet::single(ListId::Allow),
            ListSet::single(ListId::Frozen),
        )
        .referenced()
        .bits(),
        0b0000_0101
    );
    assert_eq!(
        Rule::forbid_all(
            Subject::OutputOwner,
            ListSet::of(&[ListId::Block, ListId::Frozen])
        )
        .referenced()
        .bits(),
        0b0000_0110
    );
    assert_eq!(
        Rule::require(Subject::Asset, ListId::Allow).referenced(),
        ListSet::single(ListId::Allow)
    );
    assert_eq!(
        TABLE.referenced(),
        ListSet::of(&[ListId::Allow, ListId::Frozen])
    );
    assert_eq!(TABLE.encode().referenced(), TABLE.referenced());
}

#[test]
fn every_constructor_round_trips_through_its_row() {
    let rules = [
        Rule::require(Subject::OutputOwner, ListId::Allow),
        Rule::forbid(Subject::Sender, ListId::Frozen),
        Rule::require_any(
            Subject::Sender,
            ListSet::of(&[ListId::Allow, ListId::Approval]),
        ),
        Rule::forbid_all(
            Subject::OutputOwner,
            ListSet::of(&[ListId::Block, ListId::Frozen]),
        ),
        Rule::any_of(
            Subject::OutputOwner,
            ListSet::single(ListId::Allow),
            ListSet::single(ListId::Block),
        ),
        Rule::require(Subject::Asset, ListId::Allow),
        Rule::require(Subject::OutputOwner, ListId::Approval).above(2000),
        Rule::require(Subject::Asset, ListId::Allow).above(u64::MAX),
    ];
    for rule in rules {
        assert_eq!(Rule::decode(&rule.encoded()), Ok(rule));
    }
}

type Tamper = fn(&mut [u8; 32]);

#[test]
fn decode_refuses_every_row_encoded_never_emits() {
    let base = Rule::require(Subject::OutputOwner, ListId::Allow);
    let cases: [(Tamper, RuleTableError); 16] = [
        (|row| row[0] = 1, RuleTableError::ReservedBytes),
        (|row| row[18] = 1, RuleTableError::ReservedBytes),
        (|row| row[31] = 0, RuleTableError::UnknownSubject),
        (|row| row[31] = 3, RuleTableError::ExitDestination),
        (|row| row[31] = 5, RuleTableError::UnknownSubject),
        (|row| row[30] = 0, RuleTableError::UnknownMode),
        (|row| row[30] = 3, RuleTableError::UnknownMode),
        (|row| row[19] = 0b0000_0001, RuleTableError::ListInBothSets),
        (
            |row| {
                row[30] = 2;
                row[19] = 0b0000_0010;
            },
            RuleTableError::NonCanonicalAlternative,
        ),
        (
            |row| {
                row[29] = 0;
                row[19] = 0b0000_0010;
            },
            RuleTableError::EmptyLists,
        ),
        (
            |row| {
                row[29] = 0;
                row[30] = 2;
            },
            RuleTableError::EmptyLists,
        ),
        (|row| row[29] = 0, RuleTableError::EmptyLists),
        (|row| row[28] = 3, RuleTableError::UnknownGuardTag),
        (|row| row[27] = 1, RuleTableError::ThresholdWithoutGuard),
        (|row| row[28] = 1, RuleTableError::ZeroThreshold),
        (
            |row| {
                row[31] = 2;
                row[28] = 1;
                row[27] = 1;
            },
            RuleTableError::SenderGuard,
        ),
    ];
    for (edit, expected) in cases {
        let mut row = base.encoded();
        edit(&mut row);
        assert_eq!(Rule::decode(&row), Err(expected), "{expected:?}");
    }
}

#[test]
fn alternatives_list_presences_before_absences_in_slot_order() {
    let rule = Rule::any_of(
        Subject::OutputOwner,
        ListSet::of(&[ListId::Frozen, ListId::Allow]),
        ListSet::of(&[ListId::Escrow, ListId::Block]),
    );
    assert_eq!(
        rule.alternatives().collect::<Vec<_>>(),
        [
            (ListId::Allow, Mode::Present),
            (ListId::Frozen, Mode::Present),
            (ListId::Block, Mode::Absent),
            (ListId::Escrow, Mode::Absent),
        ]
    );
    assert_eq!(rule.primary_mode(), Mode::Present);
    assert_eq!(
        Rule::forbid(Subject::Sender, ListId::Frozen)
            .alternatives()
            .collect::<Vec<_>>(),
        [(ListId::Frozen, Mode::Absent)]
    );
    assert_eq!(
        Rule::require(Subject::Asset, ListId::Allow)
            .alternatives()
            .count(),
        1
    );
}

#[test]
fn validation_needs_a_source_for_every_list_of_a_group() {
    let both = sources(&[(ListId::Allow, [0u8; 32]), (ListId::Frozen, [5u8; 32])]);
    assert_eq!(GROUP.encode().validate(&both), Ok(GROUP));
    let only_one = sources(&[(ListId::Allow, [0u8; 32])]);
    assert_eq!(
        GROUP.encode().validate(&only_one),
        Err(PolicyTableError::MissingSource(ListId::Frozen))
    );
}

#[test]
#[should_panic(expected = "a group names no list")]
fn an_empty_group_is_rejected() {
    let _ = RuleTable::builder()
        .rule(Rule::require_any(Subject::OutputOwner, ListSet::EMPTY))
        .build();
}

#[test]
fn rule_encoding_is_injective_over_every_field() {
    let base = Rule::require(Subject::OutputOwner, ListId::Allow);
    let variants = [
        base,
        Rule::require(Subject::Sender, ListId::Allow),
        Rule::require(Subject::OutputOwner, ListId::Block),
        Rule::forbid(Subject::OutputOwner, ListId::Allow),
        Rule::any_of(
            Subject::OutputOwner,
            ListSet::single(ListId::Allow),
            ListSet::single(ListId::Block),
        ),
        Rule::require(Subject::OutputOwner, ListId::Allow).above(5),
        Rule::require(Subject::OutputOwner, ListId::Allow).above(6),
        Rule::require(Subject::Asset, ListId::Allow),
    ];
    for (i, a) in variants.iter().enumerate() {
        for b in variants.iter().skip(i + 1) {
            assert_ne!(a.encoded(), b.encoded());
        }
    }
}

#[test]
fn policy_hash_binds_the_sources_and_the_inline_members() {
    let map = sources(&[(ListId::Allow, [0u8; 32]), (ListId::Frozen, [5u8; 32])]);
    let baseline = TABLE.hash(&map).unwrap();
    let other_registry = sources(&[(ListId::Allow, [0u8; 32]), (ListId::Frozen, [6u8; 32])]);
    assert_ne!(baseline, TABLE.hash(&other_registry).unwrap());
    let extra_slot = sources(&[
        (ListId::Allow, [0u8; 32]),
        (ListId::Frozen, [5u8; 32]),
        (ListId::Escrow, [5u8; 32]),
    ]);
    assert_ne!(baseline, TABLE.hash(&extra_slot).unwrap());
    const REORDERED: RuleTable = RuleTable::builder()
        .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::require(Subject::Asset, ListId::Allow))
        .build();
    assert_ne!(baseline, REORDERED.hash(&map).unwrap());
    const OTHER_ASSETS: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
        .rule(Rule::forbid(Subject::Asset, ListId::Frozen))
        .build();
    assert_ne!(baseline, OTHER_ASSETS.hash(&map).unwrap());
}

#[test]
fn validation_refuses_an_overlong_count_and_a_rule_without_a_source() {
    let map = sources(&[(ListId::Allow, [4u8; 32]), (ListId::Frozen, [4u8; 32])]);
    assert_eq!(TABLE.encode().validate(&map), Ok(TABLE));
    let mut overflowing = TABLE.encode();
    overflowing.rule_count = MAX_RULES as u8 + 1;
    assert_eq!(
        overflowing.validate(&map),
        Err(PolicyTableError::Table(RuleTableError::TooManyRules))
    );
    let allow_only = sources(&[(ListId::Allow, [4u8; 32])]);
    assert_eq!(
        TABLE.encode().validate(&allow_only),
        Err(PolicyTableError::MissingSource(ListId::Frozen))
    );
}

#[test]
fn validation_refuses_a_rule_over_a_list_its_members_write() {
    for list_id in [ListId::RingViewing, ListId::Recovery, ListId::Escrow] {
        let map = sources(&[(ListId::Allow, [0u8; 32]), (list_id, [0u8; 32])]);
        let required = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, list_id))
            .build();
        let alternative = RuleTable::builder()
            .rule(Rule::any_of(
                Subject::Sender,
                ListSet::single(ListId::Allow),
                ListSet::single(list_id),
            ))
            .build();
        for table in [required, alternative] {
            assert_eq!(
                table.encode().validate(&map),
                Err(PolicyTableError::Table(RuleTableError::MemberWrittenList)),
                "{list_id:?}"
            );
        }
    }
}

#[test]
fn an_empty_table_hashes_the_empty_map() {
    let baseline = EMPTY.hash(&SourceMap::default()).unwrap();
    let with_slot = sources(&[(ListId::Allow, [4u8; 32])]);
    assert_ne!(baseline, EMPTY.hash(&with_slot).unwrap());
}

#[test]
fn the_source_map_is_positional_and_rejects_duplicates() {
    assert_eq!(
        SourceMap::new(&[(ListId::Allow, [4u8; 32]), (ListId::Allow, [5u8; 32]),]),
        Err(SourceMapError::Duplicate)
    );
    let map = sources(&[(ListId::Frozen, [5u8; 32])]);
    assert_eq!(SourceMap::from_slots(*map.slots()), Ok(map));
    let mut slots = *map.slots();
    slots.swap(0, 2);
    assert_eq!(
        SourceMap::from_slots(slots),
        Err(SourceMapError::NotPositional)
    );
    let mut empty_with_registry = *map.slots();
    empty_with_registry[0].registry = [6u8; 32];
    assert_eq!(
        SourceMap::from_slots(empty_with_registry),
        Err(SourceMapError::NotPositional)
    );
}

#[test]
fn signatures_ignore_the_guard_and_bind_both_sets() {
    let mixed = Rule::any_of(
        Subject::OutputOwner,
        ListSet::single(ListId::Allow),
        ListSet::single(ListId::Block),
    );
    assert_eq!(
        RuleTable::builder()
            .rule(mixed)
            .rule(mixed.above(5))
            .try_build(),
        Err(RuleTableError::DuplicateRule)
    );
    let distinct = RuleTable::builder()
        .rule(Rule::require_any(
            Subject::OutputOwner,
            ListSet::single(ListId::Allow),
        ))
        .rule(mixed)
        .try_build()
        .unwrap();
    assert_eq!(distinct.rules().len(), 2);
}

#[test]
#[should_panic(expected = "duplicate rule")]
fn duplicate_rules_are_rejected() {
    let _ = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(10))
        .build();
}

#[test]
#[should_panic(expected = "sender rules take no amount guard")]
fn sender_guards_are_rejected() {
    let _ = RuleTable::builder()
        .rule(Rule::forbid(Subject::Sender, ListId::Frozen).above(10))
        .build();
}

#[test]
fn an_owner_guard_needs_no_inline_membership() {
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(7))
        .build();
    assert_eq!(table.rules().len(), 1);
}

#[test]
fn owner_and_asset_list_guards_can_coexist() {
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(7))
        .rule(Rule::require(Subject::Asset, ListId::Allow).above(9))
        .build();
    assert_eq!(table.rules().len(), 2);
}

#[test]
fn an_asset_rule_reads_lists_and_refuses_an_empty_mask() {
    let rule = Rule::require(Subject::Asset, ListId::Approval).above(7);
    let table = RuleTable::builder().rule(rule).build();
    assert_eq!(table.rules(), &[rule]);
    assert_eq!(Rule::decode(&rule.encoded()), Ok(rule));
    assert_eq!(
        Rule::decode(&packed([0, 0, 1, 4], 0, 0)),
        Err(RuleTableError::EmptyLists)
    );
    let forbid = Rule::forbid(Subject::Asset, ListId::Block);
    assert_eq!(Rule::decode(&forbid.encoded()), Ok(forbid));
}

#[test]
fn table_fields_bind_sources_and_all_rules_without_mint_tables() {
    let table = with_rules(RuleTable::builder(), sender_rules().take(MAX_RULES)).build();
    let map = SourceMap::default();
    let fields = table.encode().fields(&map);
    assert_eq!(fields.len(), 44);
    assert_eq!(fields[0], right_align(b"CRTB"));
    assert_eq!(fields[1], field_u8(12));
    assert_eq!(fields[18], field_u8(16));
    assert_eq!(fields[34], table.rules()[15].encoded());
    assert!(fields[35..].iter().all(|field| *field == [0; 32]));
    assert_eq!(table.encode().decode(), Ok(table));
    let hash = table.hash(&map).unwrap();
    let mut changed = table.encode();
    changed.rules[15][20] ^= 1;
    assert_ne!(hash, changed.hash(&map).unwrap());
    assert_ne!(
        hash,
        table.hash(&sources(&[(ListId::Escrow, [6; 32])])).unwrap()
    );
    let mut padded = TABLE.encode();
    padded.rules[3][0] = 1;
    assert_eq!(padded.decode(), Err(RuleTableError::NonZeroPadding));
}
#[test]
fn per_asset_guards_are_configured_independently_of_mint_records() {
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
        .build();
    assert_eq!(table.encode().decode(), Ok(table));
    assert_eq!(
        RuleTable::builder()
            .rule(Rule::require(Subject::Sender, ListId::Allow).above_by_asset())
            .try_build(),
        Err(RuleTableError::PerAssetGuardNotOwner)
    );
}
