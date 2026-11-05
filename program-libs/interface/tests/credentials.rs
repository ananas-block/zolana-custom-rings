use bytemuck::Zeroable;
use custom_ring_interface::{
    credential::credential_owner, AddressRootSelection, AuditCredential, CredentialRead,
    CredentialRootSelection, CredentialStateRoot, CredentialTreeRead, CustomRingError,
    CustomRingProof, EnrollIxData, EnrollRequest, Enrollment, CREDENTIAL_PDA_SEED,
};
use solana_address::Address;
use spr_hasher::primitives::{right_align, solana_owner_identity};
use spr_interface::{
    instruction::TransactProof, pda, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    SHIELDED_POOL_PROGRAM_ID,
};
use spr_program::{program::PdaOwner, ADDRESS_TREE_ID};
use spr_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule, UTXO_TREE_HEIGHT};

const RING_PROGRAM: Address = Address::new_from_array([7; 32]);
const SPP: Address = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);

fn enrollment() -> EnrollIxData {
    EnrollIxData {
        nullifier_pk: right_align(&[3]),
        list_tag: right_align(&[4]),
        eph_u: [5; 32],
        ciphertext: [6; 64],
    }
}

fn credential() -> AuditCredential {
    Enrollment {
        ring_id: &right_align(&[1]),
        auditor_pubkey: &[4; 33],
        owner: &Address::new_from_array([2; 32]),
        ix: &enrollment(),
    }
    .credential()
    .unwrap()
}

fn tree_data(tree_id: u16) -> Vec<u8> {
    let mut data = vec![0; TreeAccount::account_size()];
    TreeAccount::init(
        &mut data,
        TREE_ACCOUNT_DISCRIMINATOR,
        UTXO_TREE_HEIGHT as u8,
        pda::tree(tree_id).to_bytes(),
        tree_id,
        NullifierTreeInitParams::default(),
        TreeFeeSchedule::default(),
    )
    .unwrap();
    data
}

#[test]
fn enrollment_requires_both_proofs_and_the_complete_root_index() {
    let ix = enrollment();
    let register_key = CustomRingProof::zeroed();
    let request = EnrollRequest {
        ix: &ix,
        register_key: &register_key,
        transact: TransactProof {
            a: [1; 32],
            b: [2; 128],
            c: [3; 32],
        },
        address_root_index: 0x1234,
    };
    let encoded = request.encode().unwrap();
    let parsed = EnrollRequest::parse(&encoded).unwrap();
    assert_eq!(parsed.address_root_index, 0x1234);
    assert_eq!(parsed.ix, &ix);
    assert_eq!(parsed.transact, request.transact);
    for len in 0..encoded.len() {
        assert_eq!(
            EnrollRequest::parse(&encoded[..len]),
            Err(CustomRingError::InvalidInstructionData)
        );
    }
    let mut extended = encoded;
    extended.push(0);
    assert_eq!(
        EnrollRequest::parse(&extended),
        Err(CustomRingError::InvalidInstructionData)
    );
}

#[test]
fn enrollment_rejects_zero_and_noncanonical_keys() {
    use custom_ring_interface::storage::StorageError;
    assert_eq!(enrollment().check(), Ok(()));
    let mut zero = enrollment();
    zero.nullifier_pk = spr_interface::ZERO_NULLIFIER_PUBKEY;
    assert_eq!(zero.check(), Err(StorageError::ZeroNullifierKey));
    for invalid in [
        EnrollIxData {
            nullifier_pk: [0xff; 32],
            ..enrollment()
        },
        EnrollIxData {
            list_tag: [0xff; 32],
            ..enrollment()
        },
    ] {
        assert_eq!(invalid.check(), Err(StorageError::InvalidInstructionData));
    }
}

#[test]
fn credential_hashes_bind_context_and_seal_while_the_address_stays_per_owner() {
    let original = credential();
    assert_eq!(original.member, solana_owner_identity(&[2; 32]).unwrap());
    assert_ne!(
        original.register_key_hash().unwrap(),
        original.state_hash().unwrap()
    );
    let changed = [
        AuditCredential {
            ring_id: right_align(&[8]),
            ..original
        },
        AuditCredential {
            member: right_align(&[8]),
            ..original
        },
        AuditCredential {
            nullifier_pk: right_align(&[8]),
            ..original
        },
        AuditCredential {
            list_tag: right_align(&[8]),
            ..original
        },
        AuditCredential {
            auditor_pubkey: [8; 33],
            ..original
        },
        AuditCredential {
            eph_u: [8; 32],
            ..original
        },
        AuditCredential {
            ciphertext: [8; 64],
            ..original
        },
    ];
    for (index, value) in changed.into_iter().enumerate() {
        assert_ne!(
            value.register_key_hash().unwrap(),
            original.register_key_hash().unwrap()
        );
        assert_ne!(value.state_hash().unwrap(), original.state_hash().unwrap());
        assert_eq!(
            value.seed().unwrap() == original.seed().unwrap(),
            index >= 2
        );
    }
    assert_ne!(
        original.data_hash(&right_align(&[1])).unwrap(),
        original.data_hash(&right_align(&[2])).unwrap()
    );
}

#[test]
fn credential_owner_uses_the_dedicated_ring_pda() {
    let pda = Address::find_program_address(&[CREDENTIAL_PDA_SEED], &RING_PROGRAM).0;
    assert_eq!(
        credential_owner(&RING_PROGRAM).unwrap(),
        *PdaOwner::new(&pda).unwrap().owner_hash()
    );
    let other = Address::new_from_array([8; 32]);
    assert_ne!(
        credential_owner(&RING_PROGRAM).unwrap(),
        credential_owner(&other).unwrap()
    );
    let authority =
        Address::find_program_address(&[spr_interface::RING_AUTH_PDA_SEED], &RING_PROGRAM).0;
    assert_ne!(
        credential_owner(&RING_PROGRAM).unwrap(),
        *PdaOwner::new(&authority).unwrap().owner_hash()
    );
}

#[test]
fn retained_state_roots_remain_readable_while_addresses_are_queued_or_trees_are_paused() {
    let address = pda::tree(ADDRESS_TREE_ID);
    let mut data = tree_data(ADDRESS_TREE_ID);
    let expected = {
        let mut tree = TreeAccount::from_bytes(&mut data, address.to_bytes()).unwrap();
        tree.utxo_tree().append(right_align(&[9]), 1).unwrap();
        tree.nullifier_tree().queue_next_index += 1;
        assert_eq!(tree.nullifier_tree().sequence_number, 0);
        tree.set_paused(true);
        tree.utxo_tree().root()
    };
    assert_eq!(
        CredentialTreeRead {
            address: &address,
            owner: &SPP,
            data: &mut data
        }
        .state_root(1),
        Ok(CredentialStateRoot {
            tree_id: ADDRESS_TREE_ID,
            root: expected
        })
    );
    let checkpoint = CredentialTreeRead {
        address: &address,
        owner: &SPP,
        data: &mut data,
    }
    .checkpoint(0)
    .unwrap();
    assert_eq!(checkpoint.sequence(), 0);
}

#[test]
fn credential_roots_refuse_foreign_owners_addresses_and_queue_accounts() {
    let address = pda::tree(ADDRESS_TREE_ID);
    let mut data = tree_data(ADDRESS_TREE_ID);
    let other = Address::new_from_array([9; 32]);
    assert_eq!(
        CredentialTreeRead {
            address: &address,
            owner: &other,
            data: &mut data
        }
        .state_root(0),
        Err(CustomRingError::InvalidCredentialRoots)
    );
    assert_eq!(
        CredentialTreeRead {
            address: &other,
            owner: &SPP,
            data: &mut data
        }
        .state_root(0),
        Err(CustomRingError::InvalidCredentialRoots)
    );
    data[0] ^= 1;
    assert_eq!(
        CredentialTreeRead {
            address: &address,
            owner: &SPP,
            data: &mut data
        }
        .state_root(0),
        Err(CustomRingError::InvalidCredentialRoots)
    );
    let mut queued = [0; 64];
    assert_eq!(
        CredentialTreeRead {
            address: &address,
            owner: &SPP,
            data: &mut queued
        }
        .checkpoint(0),
        Err(CustomRingError::InvalidCredentialRoots)
    );
}

#[test]
fn checkpoint_sequences_follow_history_wrap_and_enforce_the_floor() {
    let address = pda::tree(ADDRESS_TREE_ID);
    let mut data = tree_data(ADDRESS_TREE_ID);
    let mut tree = TreeAccount::from_bytes(&mut data, address.to_bytes()).unwrap();
    let history = tree.nullifier_tree();
    let capacity = history.root_history.roots.len();
    for (index, root) in history.root_history.roots.iter_mut().enumerate() {
        *root = right_align(&(index as u64 + 1).to_be_bytes());
    }
    history.root_history.current_index = 1;
    history.sequence_number = capacity as u64;
    let latest = AddressRootSelection {
        tree_id: ADDRESS_TREE_ID,
        root_index: 0,
        history,
    }
    .checkpoint()
    .unwrap();
    let previous = AddressRootSelection {
        tree_id: ADDRESS_TREE_ID,
        root_index: (capacity - 1) as u16,
        history,
    }
    .checkpoint()
    .unwrap();
    assert_eq!(latest.sequence(), capacity as u64);
    assert_eq!(previous.sequence(), capacity as u64 - 1);
    assert_eq!(latest.above(capacity as u64), Ok(right_align(&[1])));
    assert_eq!(
        previous.above(capacity as u64),
        Err(CustomRingError::AbsenceRootBelowFloor)
    );
    assert_eq!(
        AddressRootSelection {
            tree_id: ADDRESS_TREE_ID + 1,
            root_index: 0,
            history
        }
        .checkpoint(),
        Err(CustomRingError::InvalidAddressTree)
    );
    assert_ne!(latest.root(), previous.root());
    assert_eq!(
        AddressRootSelection {
            tree_id: ADDRESS_TREE_ID,
            root_index: capacity as u16,
            history
        }
        .checkpoint(),
        Err(CustomRingError::InvalidAddressCheckpoint)
    );
    history.root_history.current_index = capacity as u64;
    assert_eq!(
        AddressRootSelection {
            tree_id: ADDRESS_TREE_ID,
            root_index: 0,
            history
        }
        .checkpoint(),
        Err(CustomRingError::InvalidAddressCheckpoint)
    );
    history.root_history.current_index = 1;
    history.sequence_number = 0;
    assert_eq!(
        AddressRootSelection {
            tree_id: ADDRESS_TREE_ID,
            root_index: (capacity - 1) as u16,
            history
        }
        .checkpoint(),
        Err(CustomRingError::InvalidAddressCheckpoint)
    );
    history.root_history.roots[0] = [0; 32];
    assert_eq!(
        AddressRootSelection {
            tree_id: ADDRESS_TREE_ID,
            root_index: 0,
            history
        }
        .checkpoint(),
        Err(CustomRingError::InvalidAddressCheckpoint)
    );
}

#[test]
fn credential_tables_require_sorted_distinct_roots_and_pad_with_the_first() {
    let address = pda::tree(ADDRESS_TREE_ID);
    let mut data = tree_data(ADDRESS_TREE_ID);
    let checkpoint = CredentialTreeRead {
        address: &address,
        owner: &SPP,
        data: &mut data,
    }
    .checkpoint(0)
    .unwrap();
    let roots = [1, 4, 7].map(|tree_id| CredentialStateRoot {
        tree_id,
        root: right_align(&[tree_id as u8]),
    });
    let select = |state_roots: &[CredentialStateRoot]| {
        CredentialRootSelection {
            ring_program: &RING_PROGRAM,
            address_checkpoint: checkpoint,
            state_roots,
            capacity: 4,
        }
        .roots()
    };
    let selected = select(&roots).unwrap();
    assert_eq!(
        selected.state_roots(),
        &[roots[0], roots[1], roots[2], roots[0]]
    );
    assert_eq!(
        selected.owner_hash(),
        &credential_owner(&RING_PROGRAM).unwrap()
    );
    for invalid in [
        vec![],
        vec![roots[0], roots[0]],
        vec![roots[1], roots[0]],
        vec![CredentialStateRoot {
            tree_id: 1,
            root: [0; 32],
        }],
    ] {
        assert_eq!(
            select(&invalid),
            Err(CustomRingError::InvalidCredentialRoots)
        );
    }
}

#[test]
fn credential_read_parser_rejects_empty_metadata_and_truncated_indexes() {
    for bytes in [&[1, 0, 0][..], &[0, 0, 1][..], &[0, 0, 1, 0][..]] {
        let mut data = bytes;
        assert_eq!(
            CredentialRead::decode(&mut data),
            Err(CustomRingError::InvalidCredentialRead)
        );
    }
    let mut bytes = &[0, 0, 1, 7, 0, 99][..];
    let parsed = CredentialRead::decode(&mut bytes).unwrap();
    assert_eq!(parsed.state_root_indexes(), &[7]);
    assert_eq!(bytes, &[99]);
    assert!(parsed.check_capacity(1).is_ok());
    assert_eq!(
        CredentialRead::empty().check_capacity(1),
        Err(CustomRingError::InvalidCredentialRead)
    );
}
