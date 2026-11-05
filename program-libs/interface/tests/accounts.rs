use bytemuck::Zeroable;
use custom_ring_interface::{
    owner_grant::OwnerGrant,
    storage::{RegistryId, RootUpdate, StorageError, StorageRegistry},
    storage_instruction::{
        AssetWrite, InitializeIxData, OwnerGrantIxData, PrivateWriteCheckpoint, StorageUpdateIxData,
    },
    ApplyRecordsIxData, CredentialRead, CustomRingError, NewRing, PolicyUpdate, RecordWriteData,
    RingAccount, RingMode, RingPolicy, RingRole, RingRoles, SourceSlot, WriteRecordsIxData,
    MEMBER_REGISTRY_EMPTY_ROOT, N_SOURCE_SLOTS, READER_KEY_ED25519, ROOT_HISTORY,
};
use solana_address::Address;
use zolana_ring_policy::{ListId, ListSet, Member, MintPolicy, Rule, RuleTable, Subject};

const PROGRAM: Address = Address::new_from_array([7; 32]);
fn key(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}

fn roles() -> RingRoles {
    RingRoles {
        admin: key(1),
        policy: key(2),
        pauser: key(3),
        cosign_admin: key(4),
    }
}

fn ring(records: Address) -> Box<RingPolicy> {
    NewRing {
        bump: 254,
        mode: RingMode::Confidential,
        roles: roles(),
        auditor_pubkey: [4; 33],
        created_slot: 0,
        records,
    }
    .account()
}

#[test]
fn decode_needs_the_owner_the_length_and_the_discriminator() {
    let ring = ring(Address::default());
    let bytes = bytemuck::bytes_of(&*ring).to_vec();
    assert_eq!(RingPolicy::decode(&PROGRAM, &PROGRAM, &bytes), Some(*ring));
    let other = Address::new_from_array([8; 32]);
    assert_eq!(RingPolicy::decode(&other, &PROGRAM, &bytes), None);
    assert_eq!(RingPolicy::decode(&PROGRAM, &PROGRAM, &bytes[1..]), None);
    for unknown in [10, 13] {
        let mut stale = bytes.clone();
        stale[0] = unknown;
        assert_eq!(RingPolicy::decode(&PROGRAM, &PROGRAM, &stale), None);
    }
}

#[test]
fn decode_refuses_values_no_setter_writes() {
    let mut mode = *ring(Address::default());
    mode.mode = 3;
    assert!(RingPolicy::decode(&PROGRAM, &PROGRAM, bytemuck::bytes_of(&mode)).is_none());
    assert_eq!(mode.mode(), Err(CustomRingError::InvalidRingMode));
}

#[test]
fn role_keys_stay_nonzero_and_apart() {
    assert_eq!(roles().check(None), Ok(()));
    assert_eq!(
        roles().check(Some(&key(2))),
        Err(CustomRingError::DuplicateRoleKey)
    );
    let mut ring = ring(Address::default());
    assert_eq!(
        ring.rotate_role(RingRole::Pauser, key(1)),
        Err(CustomRingError::DuplicateRoleKey)
    );
    assert_eq!(
        ring.rotate_role(RingRole::Pauser, Address::default()),
        Err(CustomRingError::ZeroRoleKey)
    );
    assert_eq!(ring.roles, roles());
    ring.rotate_role(RingRole::Pauser, key(9)).unwrap();
    assert_eq!(ring.roles.key(RingRole::Pauser), &key(9));
    assert_eq!(ring.check_role(RingRole::Policy, &key(2)), Ok(()));
    assert_eq!(
        ring.check_role(RingRole::Pauser, &key(2)),
        Err(CustomRingError::UnauthorizedAuthority)
    );
}

#[test]
fn a_policy_write_validates_and_repins_the_table() {
    let mut policy = ring(Address::default());
    assert_eq!(policy.policy_hash(), Err(CustomRingError::PolicyNotSet));
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    let table = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .build()
        .encode();
    let update = |sources, rules, slot| PolicyUpdate {
        sources,
        rules,
        slot,
    };
    assert_eq!(
        policy.set_policy(update(sources, table, 3)),
        Err(CustomRingError::InvalidSource)
    );
    sources[ListId::Allow.slot()].list_id = ListId::Allow as u8;
    policy.set_policy(update(sources, table, 3)).unwrap();
    let hash = *policy.policy_hash().unwrap();
    assert_eq!(hash, table.hash(&policy.source_map().unwrap()).unwrap());
    assert_eq!((policy.generation(), policy.generation_slot()), (1, 3));
    let mut padded = table;
    padded.rules[1][0] = 1;
    assert_eq!(
        policy.set_policy(update(sources, padded, 4)),
        Err(CustomRingError::InvalidPolicyRules)
    );
    assert_eq!(policy.policy_hash(), Ok(&hash));
}

#[test]
fn a_policy_write_refuses_each_table_form_and_keeps_the_pinned_table() {
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    for list_id in [ListId::Allow, ListId::Block, ListId::Frozen] {
        sources[list_id.slot()].list_id = list_id as u8;
    }
    let write = |rule: Rule, slot| PolicyUpdate {
        sources,
        rules: RuleTable::builder().rule(rule).build().encode(),
        slot,
    };
    let subject = Subject::OutputOwner;
    let allow = ListSet::single(ListId::Allow);
    let block = ListSet::single(ListId::Block);
    let mut policy = ring(Address::default());
    policy
        .set_policy(PolicyUpdate {
            rules: RuleTable::builder()
                .rule(Rule::require(subject, ListId::Allow))
                .rule(Rule::forbid(subject, ListId::Block))
                .rule(Rule::forbid(subject, ListId::Frozen))
                .build()
                .encode(),
            ..write(Rule::require(subject, ListId::Allow), 1)
        })
        .unwrap();
    let pinned = *policy;
    for (rule, refusal) in [
        (
            Rule::forbid_only_on_all(subject, ListSet::of(&[ListId::Block, ListId::Frozen])),
            CustomRingError::MultiListAbsenceRule,
        ),
        (
            Rule::require(subject, ListId::Block),
            CustomRingError::InvertedListPolarity,
        ),
        (
            Rule::forbid(subject, ListId::Allow),
            CustomRingError::InvertedListPolarity,
        ),
        (
            Rule::any_of(subject, allow, block),
            CustomRingError::MixedPolarityRule,
        ),
    ] {
        assert_eq!(policy.set_policy(write(rule, 2)), Err(refusal), "{rule:?}");
        assert_eq!(*policy, pinned);
    }
}

#[test]
fn the_grant_scopes_owner_and_reader_and_checks_its_scheme() {
    let reader = {
        let mut reader = [7; 34];
        reader[0] = READER_KEY_ED25519;
        reader
    };
    let (one, _) = OwnerGrant::find_address(&key(1), &key(2), &reader);
    let mut other_reader = reader;
    other_reader[33] = 8;
    for other in [
        OwnerGrant::find_address(&key(1), &key(3), &reader).0,
        OwnerGrant::find_address(&key(9), &key(2), &reader).0,
        OwnerGrant::find_address(&key(1), &key(2), &other_reader).0,
    ] {
        assert_ne!(one, other);
    }
    let ix = OwnerGrantIxData {
        ring_program: PROGRAM,
        reader,
        active: 1,
    };
    assert_eq!(ix.check(), Ok(()));
    let mut unknown = reader;
    unknown[0] = 9;
    assert_eq!(
        OwnerGrantIxData {
            ring_program: PROGRAM,
            reader: unknown,
            active: 1
        }
        .check(),
        Err(StorageError::InvalidReaderKey)
    );
    assert_eq!(
        OwnerGrantIxData {
            ring_program: PROGRAM,
            reader,
            active: 2
        }
        .check(),
        Err(StorageError::InvalidInstructionData)
    );
}

fn apply_ix() -> ApplyRecordsIxData {
    ApplyRecordsIxData {
        new_root: [8; 32],
        new_next_index: 1u32.to_le_bytes(),
        ..ApplyRecordsIxData::zeroed()
    }
}

fn list_write(list: ListId) -> RecordWriteData {
    RecordWriteData {
        member: [1; 32],
        lists: WriteRecordsIxData {
            mask: list.record_bit().to_le_bytes(),
            value: list.record_bit().to_le_bytes(),
        },
        mint_policy: custom_ring_interface::mint_policy_write(None),
    }
}

fn update_of<'a>(
    revision: u64,
    writes: Vec<RecordWriteData>,
    apply: &'a ApplyRecordsIxData,
) -> StorageUpdateIxData<'a> {
    let private = writes.iter().any(|write| {
        u64::from_le_bytes(write.lists.mask) & ListSet::PRIVATE_LISTS.record_bits() != 0
    });
    StorageUpdateIxData {
        revision: revision.into(),
        writes,
        asset_writes: Vec::new(),
        credential_read: if private {
            CredentialRead::new(0, &[0]).unwrap()
        } else {
            CredentialRead::empty()
        },
        private_write: private.then_some(PrivateWriteCheckpoint {
            ring_program: PROGRAM,
            sequence: 0,
        }),
        apply,
    }
}

fn update_data<'a>(
    revision: u64,
    list: ListId,
    apply: &'a ApplyRecordsIxData,
) -> StorageUpdateIxData<'a> {
    update_of(revision, vec![list_write(list)], apply)
}

fn public_registry(grace_slots: u64) -> StorageRegistry {
    StorageRegistry::new(
        key(1),
        &InitializeIxData {
            registry_id: RegistryId([1; 32]),
            grace_slots: grace_slots.to_le_bytes(),
            ring_id: [0; 32],
            private_ring_id: [0; 32],
        },
    )
}

fn pinned_registry(ring_id: [u8; 32]) -> StorageRegistry {
    StorageRegistry::new(
        key(1),
        &InitializeIxData {
            registry_id: RegistryId([1; 32]),
            grace_slots: 10u64.to_le_bytes(),
            ring_id,
            private_ring_id: [3; 32],
        },
    )
}

#[test]
fn a_policy_write_ends_every_older_root_at_once_and_a_reader_write_keeps_grace() {
    let apply = apply_ix();
    let mut registry = public_registry(10);
    registry
        .update(RootUpdate {
            slot: 1,
            data: &update_data(0, ListId::Reader, &apply),
            absence_checkpoint: None,
        })
        .unwrap();
    assert!(registry.root(0.into(), 1).is_ok());
    assert!(registry.root(0.into(), 10).is_ok());
    assert_eq!(registry.root(0.into(), 11), Err(StorageError::RootExpired));
    registry
        .update(RootUpdate {
            slot: 1,
            data: &update_data(1, ListId::Block, &apply),
            absence_checkpoint: None,
        })
        .unwrap();
    assert_eq!(registry.root(1.into(), 1), Err(StorageError::RootExpired));
    assert_eq!(registry.root(0.into(), 1), Err(StorageError::RootExpired));
    assert!(registry.root(2.into(), 1).is_ok());
}

#[test]
fn a_policy_write_runs_through_a_full_history() {
    let apply = apply_ix();
    let mut registry = public_registry(u64::MAX);
    let revision = ROOT_HISTORY as u64 - 1;
    for earlier in 0..revision {
        registry
            .update(RootUpdate {
                slot: 1,
                data: &update_data(earlier, ListId::Reader, &apply),
                absence_checkpoint: None,
            })
            .unwrap();
    }
    assert_eq!(
        registry.update(RootUpdate {
            slot: 2,
            data: &update_data(revision, ListId::Reader, &apply),
            absence_checkpoint: None,
        }),
        Err(StorageError::HistoryFull)
    );
    registry
        .update(RootUpdate {
            slot: 2,
            data: &update_data(revision, ListId::Block, &apply),
            absence_checkpoint: None,
        })
        .unwrap();
    assert_eq!(
        registry.root((revision - 1).into(), 2),
        Err(StorageError::RootExpired)
    );
}

#[test]
fn update_data_round_trips_and_refuses_no_writes() {
    let apply = apply_ix();
    let data = update_data(7, ListId::Block, &apply);
    let encoded = data.encode().unwrap();
    assert_eq!(StorageUpdateIxData::parse(&encoded), Ok(data));
    let mut no_writes = encoded;
    no_writes[8] = 0;
    assert_eq!(
        StorageUpdateIxData::parse(&no_writes),
        Err(StorageError::InvalidInstructionData)
    );
}

#[test]
fn a_mint_settings_tag_above_one_is_no_entry() {
    let apply = apply_ix();
    let mut data = update_data(0, ListId::Reader, &apply);
    data.writes[0].mint_policy[0] = 2;
    assert!(data.entries().next().unwrap().is_err());
}

#[test]
fn the_masks_alone_decide_zero_grace() {
    let apply = apply_ix();
    for list in [
        ListId::Allow,
        ListId::Block,
        ListId::Frozen,
        ListId::Approval,
    ] {
        assert!(update_data(0, list, &apply).reaches_policy(), "{list:?}");
        let mut clears = list_write(list);
        clears.lists.value = [0; 8];
        assert!(update_of(0, vec![clears], &apply).reaches_policy());
    }
    for list in [ListId::Reader, ListId::RingViewing] {
        assert!(!update_data(0, list, &apply).reaches_policy(), "{list:?}");
    }
    let mixed = vec![list_write(ListId::Reader), list_write(ListId::Allow)];
    assert!(update_of(0, mixed, &apply).reaches_policy());
    let mut mint = list_write(ListId::Reader);
    mint.mint_policy = custom_ring_interface::mint_policy_write(Some(MintPolicy::EMPTY));
    assert!(update_of(0, vec![mint], &apply).reaches_policy());
}

#[test]
fn private_writes_require_a_ring_and_checkpoint_before_any_root_changes() {
    let apply = apply_ix();
    let data = update_data(0, ListId::PrivateBlock, &apply);
    let mut public = public_registry(10);
    let before = public;
    assert_eq!(
        public.update(RootUpdate {
            slot: 1,
            data: &data,
            absence_checkpoint: Some(5)
        }),
        Err(StorageError::PrivateWriteWithoutRing)
    );
    assert_eq!(public, before);
    for ring_id in [[3; 32], [0; 32]] {
        let mut source = pinned_registry(ring_id);
        let before = source;
        assert_eq!(source.newest().hash, MEMBER_REGISTRY_EMPTY_ROOT);
        assert_eq!(
            source.update(RootUpdate {
                slot: 1,
                data: &data,
                absence_checkpoint: None
            }),
            Err(StorageError::InvalidCredentialRead)
        );
        assert_eq!(source, before);
        let stale = update_data(1, ListId::PrivateBlock, &apply);
        assert_eq!(
            source.update(RootUpdate {
                slot: 1,
                data: &stale,
                absence_checkpoint: Some(99)
            }),
            Err(StorageError::RevisionChanged)
        );
        assert_eq!(source, before);
    }
}

#[test]
fn private_updates_keep_the_maximum_checkpoint_and_retire_old_roots() {
    let apply = apply_ix();
    for ring_id in [[3; 32], [0; 32]] {
        let mut source = pinned_registry(ring_id);
        for (revision, checkpoint, floor) in [(0, 5, 5), (1, 3, 5), (2, 8, 8)] {
            source
                .update(RootUpdate {
                    slot: 1,
                    data: &update_data(revision, ListId::PrivateBlock, &apply),
                    absence_checkpoint: Some(checkpoint),
                })
                .unwrap();
            assert_eq!(source.absence_floor(), floor);
            assert_eq!(
                source.root(revision.into(), 1),
                Err(StorageError::RootExpired)
            );
        }
        source
            .update(RootUpdate {
                slot: 1,
                data: &update_data(3, ListId::Reader, &apply),
                absence_checkpoint: None,
            })
            .unwrap();
        assert_eq!(source.absence_floor(), 8);
        assert_eq!(source.root(3.into(), 1), Ok(apply.new_root));
    }
}

#[test]
fn public_updates_refuse_a_checkpoint_without_mutation() {
    let apply = apply_ix();
    let mut source = pinned_registry([3; 32]);
    let before = source;
    assert_eq!(
        source.update(RootUpdate {
            slot: 1,
            data: &update_data(0, ListId::Block, &apply),
            absence_checkpoint: Some(99),
        }),
        Err(StorageError::InvalidCredentialRead)
    );
    assert_eq!(source, before);
}

#[test]
fn private_masks_require_credentials_even_when_the_write_clears_the_bit() {
    let apply = apply_ix();
    let mut data = update_data(0, ListId::PrivateBlock, &apply);
    data.writes[0].lists.value = [0; 8];
    assert_eq!(data.credential_writes(), Ok(1));
    assert!(StorageUpdateIxData::parse(&data.encode().unwrap()).is_ok());
    data.credential_read = CredentialRead::empty();
    data.private_write = None;
    assert_eq!(data.encode(), Err(StorageError::InvalidCredentialRead));
}

#[test]
fn asset_preimages_exempt_only_the_matching_private_write() {
    let apply = apply_ix();
    let mint = key(9);
    let mut asset = list_write(ListId::PrivateBlock);
    asset.member = *Member::asset(&mint).unwrap().as_bytes();
    let mut data = update_of(0, vec![asset, list_write(ListId::PrivateBlock)], &apply);
    data.asset_writes = vec![AssetWrite {
        write_index: 0,
        mint,
    }];
    assert_eq!(data.credential_writes(), Ok(0b10));
    assert!(StorageUpdateIxData::parse(&data.encode().unwrap()).is_ok());
    data.writes.pop();
    data.credential_read = CredentialRead::empty();
    data.private_write = None;
    assert_eq!(data.credential_writes(), Ok(0));
    assert!(StorageUpdateIxData::parse(&data.encode().unwrap()).is_ok());
    for invalid in [
        AssetWrite {
            write_index: 1,
            mint,
        },
        AssetWrite {
            write_index: 0,
            mint: key(8),
        },
    ] {
        data.asset_writes = vec![invalid];
        assert_eq!(
            data.credential_writes(),
            Err(StorageError::InvalidAssetWrite)
        );
    }
    data.asset_writes = vec![AssetWrite {
        write_index: 0,
        mint,
    }];
    data.writes[0].lists = list_write(ListId::Block).lists;
    assert!(data.entries().all(|entry| entry.is_ok()));
    assert_eq!(
        data.credential_writes(),
        Err(StorageError::InvalidAssetWrite)
    );
}

#[test]
fn asset_write_indices_are_distinct_and_in_increasing_order() {
    let apply = apply_ix();
    let mint = key(9);
    let mut asset = list_write(ListId::PrivateBlock);
    asset.member = *Member::asset(&mint).unwrap().as_bytes();
    let mut data = update_of(0, vec![asset, asset], &apply);
    for indexes in [[0, 0], [1, 0], [0, 2]] {
        data.asset_writes = indexes
            .map(|write_index| AssetWrite { write_index, mint })
            .to_vec();
        assert_eq!(
            data.credential_writes(),
            Err(StorageError::InvalidAssetWrite)
        );
    }
    data.asset_writes = [0, 1]
        .map(|write_index| AssetWrite { write_index, mint })
        .to_vec();
    data.credential_read = CredentialRead::empty();
    data.private_write = None;
    assert_eq!(data.credential_writes(), Ok(0));
    assert!(data.encode().is_ok());
}

#[test]
fn public_update_parser_rejects_unused_credential_metadata() {
    let apply = apply_ix();
    let mut data = update_data(0, ListId::Block, &apply);
    let encoded = data.encode().unwrap();
    data.credential_read = CredentialRead::new(0, &[0]).unwrap();
    data.private_write = Some(PrivateWriteCheckpoint {
        ring_program: PROGRAM,
        sequence: 0,
    });
    assert_eq!(data.encode(), Err(StorageError::InvalidCredentialRead));
    let read_offset = 8 + 1 + core::mem::size_of::<RecordWriteData>() + 1;
    let mut invalid = encoded.clone();
    invalid[read_offset] = 1;
    assert_eq!(
        StorageUpdateIxData::parse(&invalid),
        Err(StorageError::InvalidCredentialRead)
    );
    let mut extended = encoded.clone();
    extended.push(0);
    assert_eq!(
        StorageUpdateIxData::parse(&extended),
        Err(StorageError::InvalidInstructionData)
    );
    assert!(StorageUpdateIxData::parse(&encoded[..encoded.len() - 1]).is_err());
}

#[test]
fn private_update_wire_retains_the_exact_checkpoint_sequence() {
    let apply = apply_ix();
    let mut data = update_data(0, ListId::PrivateBlock, &apply);
    for sequence in [0, u64::from(u32::MAX) + 1, u64::MAX] {
        data.private_write.as_mut().unwrap().sequence = sequence;
        let encoded = data.encode().unwrap();
        let sequence_offset = encoded.len() - core::mem::size_of::<ApplyRecordsIxData>() - 8;
        assert_eq!(
            &encoded[sequence_offset - 32..sequence_offset],
            PROGRAM.as_array()
        );
        assert_eq!(
            &encoded[sequence_offset..sequence_offset + 8],
            sequence.to_le_bytes()
        );
        assert_eq!(StorageUpdateIxData::parse(&encoded), Ok(data.clone()));
        for missing in 1..=8 {
            let mut truncated = encoded.clone();
            truncated.drain(sequence_offset..sequence_offset + missing);
            assert_eq!(
                StorageUpdateIxData::parse(&truncated),
                Err(StorageError::InvalidInstructionData)
            );
        }
    }
    data.private_write = None;
    assert_eq!(data.encode(), Err(StorageError::InvalidCredentialRead));
}

#[test]
fn public_update_wire_has_no_private_checkpoint_header() {
    let apply = apply_ix();
    let data = update_data(7, ListId::Block, &apply);
    let mut expected = 7u64.to_le_bytes().to_vec();
    expected.push(1);
    expected.extend_from_slice(bytemuck::cast_slice(&data.writes));
    expected.extend_from_slice(&[0, 0, 0, 0]);
    expected.extend_from_slice(bytemuck::bytes_of(&apply));
    assert_eq!(data.encode().unwrap(), expected);
    assert_eq!(StorageUpdateIxData::parse(&expected), Ok(data));
}
