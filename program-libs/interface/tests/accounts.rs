use bytemuck::Zeroable;
use custom_ring_interface::{
    domain,
    member_registry::AuthorizedAddress,
    storage::{AddressAuthorization, FirstEnrollment, StorageError},
    storage_instruction::{AddressWriteData, EnrollAddressIxData, StorageWriteData},
    CustomRingError, NewRing, QueueEntry, RingAccount, RingMode, RingPolicy, RingRole, RingRoles,
    SourceSlot, N_SOURCE_SLOTS,
};
use serde_json::{json, Value};
use solana_address::Address;
use spr_hasher::{
    primitives::{pack_be, right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use zolana_ring_policy::{ListId, Rule, RuleTable, Subject};

const PROGRAM: Address = Address::new_from_array([7; 32]);
const ENROLL_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/registry/enroll_address.json"
);

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
    for retired in [10, 13] {
        let mut stale = bytes.clone();
        stale[0] = retired;
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
    assert_eq!(
        policy.set_policy(sources, table, 3),
        Err(CustomRingError::InvalidSource)
    );
    sources[ListId::Allow.slot()].list_id = ListId::Allow as u8;
    policy.set_policy(sources, table, 3).unwrap();
    let hash = *policy.policy_hash().unwrap();
    assert_eq!(hash, table.hash(&policy.source_map().unwrap()).unwrap());
    assert_eq!((policy.generation(), policy.generation_slot()), (1, 3));
    let mut padded = table;
    padded.rules[1][0] = 1;
    assert_eq!(
        policy.set_policy(sources, padded, 4),
        Err(CustomRingError::InvalidPolicyRules)
    );
    assert_eq!(policy.policy_hash(), Ok(&hash));
}

fn first_enrollment(viewing_u: [u8; 32]) -> AddressAuthorization {
    FirstEnrollment {
        registry: key(0x11),
        owner: key(0x12),
        bump: 253,
        ring_id: [0x13; 32],
        ix: &EnrollAddressIxData {
            nullifier_pk: [0x14; 32],
            viewing_u,
        },
    }
    .account()
}

fn write_at(owner: Address, address_revision: u64) -> AddressWriteData {
    AddressWriteData {
        owner,
        address_revision: address_revision.to_le_bytes(),
    }
}

#[test]
fn the_address_hash_binds_ring_owner_keys_and_revision() {
    let address = AuthorizedAddress {
        ring_id: [1; 32],
        nullifier_pk: [2; 32],
        viewing_u: [3; 32],
        address_revision: 9,
    };
    let member = [4; 32];
    let [view0, view1] = pack_be(&address.viewing_u);
    assert_eq!(
        address.hash(&member).unwrap(),
        Poseidon::hashv(&[
            &domain::field(domain::AUTHORIZED_ADDRESS),
            &address.ring_id,
            &member,
            &address.nullifier_pk,
            &view0,
            &view1,
            &right_align(&9u64.to_be_bytes()),
        ])
        .unwrap()
    );
    let moved = [
        AuthorizedAddress {
            ring_id: [9; 32],
            ..address
        },
        AuthorizedAddress {
            nullifier_pk: [9; 32],
            ..address
        },
        AuthorizedAddress {
            viewing_u: [9; 32],
            ..address
        },
        AuthorizedAddress {
            address_revision: 10,
            ..address
        },
    ];
    for other in moved {
        assert_ne!(other.hash(&member), address.hash(&member));
    }
    assert_ne!(address.hash(&[5; 32]), address.hash(&member));
}

#[test]
fn an_applied_address_chains_its_hash_once_and_preserves_at_zero() {
    let mut account = first_enrollment([0x15; 32]);
    let owner = account.owner;
    let member = solana_owner_identity(owner.as_array()).unwrap();
    assert_eq!(
        account.apply(&write_at(owner, 2)),
        Err(StorageError::InvalidAddressAuthorization)
    );
    assert_eq!(account.applied_revision(), 0);
    let entry = account.apply(&write_at(owner, 1)).unwrap();
    assert_eq!(account.applied_revision(), 1);
    assert_eq!(
        entry,
        QueueEntry {
            member,
            address_hash: account.address().hash(&member).unwrap(),
            ..QueueEntry::default()
        }
    );
    assert_eq!(
        account.apply(&write_at(owner, 1)),
        Err(StorageError::AddressAlreadyApplied)
    );
    assert_ne!(
        entry.hash().unwrap(),
        QueueEntry {
            address_hash: [0; 32],
            ..entry
        }
        .hash()
        .unwrap()
    );
}

#[test]
fn a_rotation_moves_the_revision_and_refuses_a_nullifier_key_change() {
    let mut account = first_enrollment([0x15; 32]);
    let rotated = EnrollAddressIxData {
        nullifier_pk: account.nullifier_pk,
        viewing_u: [0x16; 32],
    };
    assert_eq!(account.enroll(&rotated), Ok(()));
    assert_eq!((account.viewing_u, account.revision()), ([0x16; 32], 2));
    assert_eq!(
        account.enroll(&EnrollAddressIxData {
            nullifier_pk: [0x17; 32],
            ..rotated
        }),
        Err(StorageError::NullifierKeyChanged)
    );
    assert_eq!(account.revision(), 2);
    account.revision = u64::MAX.to_le_bytes();
    assert_eq!(
        account.enroll(&rotated),
        Err(StorageError::RevisionOverflow)
    );
}

#[test]
fn an_address_write_needs_an_authorization_for_its_entry() {
    let write = StorageWriteData::Address(write_at(key(0x12), 1));
    assert_eq!(
        write.entry(),
        Err(CustomRingError::AddressWriteNeedsAuthorization)
    );
    let encoded = StorageWriteData::encode_all(&[write]);
    assert_eq!(encoded[0], 2);
    assert_eq!(encoded.len(), 1 + 40);
    assert_eq!(StorageWriteData::parse_all(&encoded), Ok(vec![write]));
    assert_eq!(
        StorageWriteData::parse_all(&encoded[..40]),
        Err(CustomRingError::InvalidInstructionData)
    );
}

#[test]
fn the_enrollment_checks_the_viewing_key_it_stores() {
    let check = |viewing_u| {
        EnrollAddressIxData {
            nullifier_pk: [1; 32],
            viewing_u,
        }
        .check()
    };
    assert_eq!(check([9; 32]), Ok(()));
    assert_eq!(check([0; 32]), Err(StorageError::NonCanonicalViewingKey));
    assert_eq!(check([0xff; 32]), Err(StorageError::NonCanonicalViewingKey));
    // The nullifier key is fixed, one no leaf can hash would lock the owner out for good.
    assert_eq!(
        EnrollAddressIxData {
            nullifier_pk: [0xff; 32],
            viewing_u: [9; 32],
        }
        .check(),
        Err(StorageError::InvalidInstructionData)
    );
}

fn enroll_vector() -> Value {
    let registry = key(0x31);
    let owner = key(0x32);
    let ix = EnrollAddressIxData {
        nullifier_pk: [0x23; 32],
        viewing_u: [0x34; 32],
    };
    let (authorization, bump) = AddressAuthorization::find_address(&registry, &owner);
    let mut account = FirstEnrollment {
        registry,
        owner,
        bump,
        ring_id: [0x25; 32],
        ix: &ix,
    }
    .account();
    let member = solana_owner_identity(owner.as_array()).unwrap();
    let write = write_at(owner, 1);
    let entry = account.apply(&write).unwrap();
    json!({
        "description": "One owner enrollment and its authority apply. enroll_data follows tag 5, nullifier_pk || viewing_u, the ring id comes from the registry. The authorization PDA has seeds [address, registry, owner]. address_hash is Poseidon(CRAD, ring_id, member, nullifier_pk, view0, view1, address_revision) and the ADDRESS write body is owner || address_revision u64 LE. entry_hash is the queue entry Poseidon(CRQW, member, mask, value, escrow_key, mint_policy, withdrawal_threshold, limits_0, limits_1, limits_2, address_hash). account is the authorization after the apply. Produced by program-libs/interface/tests/accounts.rs.",
        "registry": hex::encode(registry),
        "owner": hex::encode(owner),
        "member": hex::encode(member),
        "ring_id": hex::encode(account.ring_id),
        "nullifier_pk": hex::encode(ix.nullifier_pk),
        "viewing_u": hex::encode(ix.viewing_u),
        "enroll_data": hex::encode(bytemuck::bytes_of(&ix)),
        "authorization": hex::encode(authorization),
        "bump": bump,
        "address_revision": 1,
        "address_hash": hex::encode(entry.address_hash),
        "address_write": hex::encode(StorageWriteData::encode_all(&[StorageWriteData::Address(write)])),
        "entry_hash": hex::encode(entry.hash().unwrap()),
        "account": hex::encode(bytemuck::bytes_of(&account)),
    })
}

#[test]
fn the_enrollment_is_the_shared_vector() {
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(ENROLL_VECTOR).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, enroll_vector());
}

#[test]
#[ignore = "rewrites test-vectors/registry/enroll_address.json"]
fn write_enroll_address_vector() {
    let json = serde_json::to_string_pretty(&enroll_vector()).expect("json");
    std::fs::write(ENROLL_VECTOR, json + "\n").expect("write vector file");
}
