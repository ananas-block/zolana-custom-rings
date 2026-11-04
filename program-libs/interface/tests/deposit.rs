use custom_ring_interface::{
    CustomRingProof, DepositContext, DepositPublicInput, DepositRegistry, DepositedAsset,
    OpeningRecord, PlainGroth16Proof, RecordKind, MAX_RING_DEPOSIT_AUDIT_SLOTS,
    RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN as CT,
};
use serde::Deserialize;
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice,
    primitives::{hash_bytes, solana_owner_identity},
    Hasher, HasherError, Poseidon,
};

#[test]
fn context_binds_ring_tree_wire_and_wire_length() {
    let ring = [1; 32];
    let tree = [2; 32];
    let context = DepositContext {
        program_id: &ring,
        tree: &tree,
        spp_data: &[1],
    };
    let expected = context.hash().unwrap();
    for changed in [
        DepositContext {
            program_id: &[3; 32],
            ..context
        },
        DepositContext {
            tree: &[3; 32],
            ..context
        },
        DepositContext {
            spp_data: &[2],
            ..context
        },
        DepositContext {
            spp_data: &[0, 1],
            ..context
        },
    ] {
        assert_ne!(expected, changed.hash().unwrap());
    }
}

#[test]
fn public_statement_binds_each_opening_ciphertext_key_and_context() {
    let owners = [[1; 32], [2; 32]];
    let ciphertexts = [[3; CT], [4; CT]];
    let assets = [asset(10, 11), asset(12, 13)];
    let input = DepositPublicInput {
        context_hash: &[5; 32],
        anonymous: false,
        owner_utxo_hashes: &owners,
        ciphertexts: &ciphertexts,
        assets: &assets,
        auditor_pk: &[6; 33],
        eph_pk: &[7; 33],
        tracking_root: &[14; 32],
        registry: None,
    };
    let registry = |own_root, policy_hash| {
        Some(DepositRegistry {
            own_root,
            curator_root: None,
            policy_hash,
        })
    };
    let expected = input.hash().unwrap();
    for changed in [
        DepositPublicInput {
            context_hash: &[6; 32],
            ..input
        },
        DepositPublicInput {
            anonymous: true,
            ..input
        },
        DepositPublicInput {
            owner_utxo_hashes: &[[2; 32], [1; 32]],
            ..input
        },
        DepositPublicInput {
            ciphertexts: &[[4; CT], [3; CT]],
            ..input
        },
        DepositPublicInput {
            auditor_pk: &[7; 33],
            ..input
        },
        DepositPublicInput {
            eph_pk: &[8; 33],
            ..input
        },
        DepositPublicInput {
            assets: &[asset(10, 11), asset(12, 14)],
            ..input
        },
        DepositPublicInput {
            assets: &[asset(10, 11), asset(14, 13)],
            ..input
        },
        DepositPublicInput {
            tracking_root: &[15; 32],
            ..input
        },
        DepositPublicInput {
            registry: registry(&[9; 32], None),
            ..input
        },
        DepositPublicInput {
            registry: registry(&[0; 32], Some(&[9; 32])),
            ..input
        },
        DepositPublicInput {
            registry: Some(DepositRegistry {
                own_root: &[0; 32],
                curator_root: Some(&[9; 32]),
                policy_hash: None,
            }),
            ..input
        },
        DepositPublicInput {
            owner_utxo_hashes: &owners[..1],
            ciphertexts: &ciphertexts[..1],
            assets: &assets[..1],
            ..input
        },
    ] {
        assert_ne!(expected, changed.hash().unwrap());
    }
}

fn asset(asset: u8, amount: u64) -> DepositedAsset {
    DepositedAsset {
        asset: [asset; 32],
        amount,
    }
}

#[test]
fn statement_rejects_empty_oversized_and_mismatched_batches() {
    let input = DepositPublicInput {
        context_hash: &[0; 32],
        anonymous: false,
        owner_utxo_hashes: &[],
        ciphertexts: &[],
        assets: &[],
        auditor_pk: &[0; 33],
        eph_pk: &[0; 33],
        tracking_root: &[14; 32],
        registry: None,
    };
    assert_eq!(input.hash(), Err(HasherError::InvalidNumFields));
    assert_eq!(
        DepositPublicInput {
            owner_utxo_hashes: &[[0; 32]; 9],
            ciphertexts: &[[0; CT]; 9],
            assets: &[asset(0, 0); 9],
            ..input
        }
        .hash(),
        Err(HasherError::InvalidNumFields)
    );
    assert_eq!(
        DepositPublicInput {
            owner_utxo_hashes: &[[0; 32]],
            ..input
        }
        .hash(),
        Err(HasherError::InvalidNumFields)
    );
    assert_eq!(
        DepositPublicInput {
            owner_utxo_hashes: &[[0; 32]],
            ciphertexts: &[[0; CT]],
            ..input
        }
        .hash(),
        Err(HasherError::InvalidNumFields)
    );
}

#[test]
fn proof_prefix_size_matches_the_instruction_serializer() {
    let proof = CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: [1; 32],
            proof_b: [2; 64],
            proof_c: [3; 32],
        },
        commitment: [4; 32],
        commitment_pok: [5; 32],
    };
    let bytes = wincode::serialize(&proof).unwrap();
    assert_eq!(bytes.len(), CustomRingProof::SIZE);
    assert_eq!(&bytes[..32], &[1; 32]);
    assert_eq!(&bytes[160..], &[5; 32]);
}

#[derive(Deserialize)]
struct VectorCase {
    context_hash: String,
    anonymous: bool,
    records: Vec<String>,
    ciphertexts: Vec<String>,
    owner_utxo_hashes: Vec<String>,
    assets: Vec<String>,
    amounts: Vec<u64>,
    auditor_pubkey: String,
    eph_pk: String,
    tracking_root: String,
    own_root: String,
    curator_root: String,
    policy_hash: String,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Deserialize)]
struct Vectors {
    cases: Vec<VectorCase>,
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}

/// The Go witnesses solve under these statements, and each record alone rebuilds its published note.
#[test]
fn solved_go_deposits_reach_the_program_statement_and_the_reader() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/deposit/deposit.json"
    );
    let vectors: Vectors = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for case in &vectors.cases {
        let owners: Vec<[u8; 32]> = case.owner_utxo_hashes.iter().map(|v| array(v)).collect();
        let ciphertexts: Vec<[u8; CT]> = case.ciphertexts.iter().map(|v| array(v)).collect();
        let assets: Vec<DepositedAsset> = case
            .assets
            .iter()
            .zip(&case.amounts)
            .map(|(asset, amount)| DepositedAsset {
                asset: array(asset),
                amount: *amount,
            })
            .collect();
        for (slot, plaintext) in case.records.iter().enumerate() {
            let opened = OpeningRecord::decode(&hex::decode(plaintext).unwrap()).unwrap();
            assert_eq!(opened.record.kind, RecordKind::Ring);
            assert_eq!(opened.record.amount, assets[slot].amount);
            assert_eq!(hash_bytes(&opened.record.mint).unwrap(), assets[slot].asset);
            let owner = Poseidon::hashv(&[
                &solana_owner_identity(&opened.record.owner_key).unwrap(),
                &opened.record.nullifier_pk,
            ])
            .unwrap();
            assert_eq!(
                Poseidon::hashv(&[&owner, &opened.secret]).unwrap(),
                owners[slot]
            );
        }
        let (own_root, curator_root, policy_hash) = (
            array(&case.own_root),
            array(&case.curator_root),
            array(&case.policy_hash),
        );
        let input = DepositPublicInput {
            context_hash: &array(&case.context_hash),
            anonymous: case.anonymous,
            owner_utxo_hashes: &owners,
            ciphertexts: &ciphertexts,
            assets: &assets,
            auditor_pk: &array(&case.auditor_pubkey),
            eph_pk: &array(&case.eph_pk),
            tracking_root: &array(&case.tracking_root),
            registry: (policy_hash != [0; 32]).then_some(DepositRegistry {
                own_root: &own_root,
                curator_root: (curator_root != [0; 32]).then_some(&curator_root),
                policy_hash: Some(&policy_hash),
            }),
        };
        let elements: Vec<String> = input.elements().unwrap().iter().map(hex::encode).collect();
        assert_eq!(elements, case.elements);
        assert_eq!(input.hash().unwrap(), array::<32>(&case.public_input_hash));
    }
}

/// HashChain4 pads zeros, every count hashes one length.
#[test]
fn a_zero_tail_stays_injective_at_the_one_length() {
    let owners = [[1; 32]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    let ciphertexts = [[3; CT]; MAX_RING_DEPOSIT_AUDIT_SLOTS];
    let assets: [DepositedAsset; MAX_RING_DEPOSIT_AUDIT_SLOTS] =
        core::array::from_fn(|_| asset(10, 11));
    let chain = |count: usize| {
        DepositPublicInput {
            context_hash: &[5; 32],
            anonymous: false,
            owner_utxo_hashes: &owners[..count],
            ciphertexts: &ciphertexts[..count],
            assets: &assets[..count],
            auditor_pk: &[6; 33],
            eph_pk: &[7; 33],
            tracking_root: &[14; 32],
            registry: None,
        }
        .elements()
        .unwrap()
    };
    let hash = |elements: &[[u8; 32]]| create_hash_chain_4_from_slice(elements).unwrap();
    let one = chain(1);
    assert_eq!(one.last(), Some(&[0; 32]));
    let reference = hash(&one);
    let padded = |zeros: usize| hash(&[one.to_vec(), vec![[0; 32]; zeros]].concat());
    assert_eq!((padded(1), padded(2)), (reference, reference));
    assert_ne!(padded(3), reference);
    let mut moved = one;
    moved.last_mut().unwrap()[31] = 1;
    assert_ne!(hash(&moved), reference);
    let hashes: std::collections::BTreeSet<_> = (1..=MAX_RING_DEPOSIT_AUDIT_SLOTS)
        .map(|count| hash(&chain(count)))
        .collect();
    assert_eq!(hashes.len(), MAX_RING_DEPOSIT_AUDIT_SLOTS);
}

#[test]
fn a_salted_deposit_takes_the_narrowest_key_it_fits() {
    let widths = [1, 2, 4, 8].map(custom_ring_interface::DepositSubjects::pool_width);
    assert_eq!(widths, [2, 4, 8, 21]);
    let key = |slots, recipients, assets, salted_keys| {
        custom_ring_interface::DepositSubjects {
            slots,
            recipients,
            assets,
            salted_keys,
        }
        .key_capacity()
    };
    // No salted list keeps the count's key.
    for (slots, capacity) in [(1, 1), (2, 2), (3, 4), (4, 4), (5, 8), (8, 8)] {
        let subjects = usize::from(slots);
        assert_eq!(key(slots, subjects, subjects.min(5), 0), Some(capacity));
    }
    // A salted record moves one recipient up one key, not to the widest.
    assert_eq!(key(1, 1, 1, 1), Some(2));
    assert_eq!(key(2, 2, 1, 2), Some(4));
    assert_eq!(key(3, 3, 1, 3), Some(4));
    assert_eq!(key(4, 4, 1, 4), Some(8));
    assert_eq!(key(8, 8, 5, 8), Some(8));
    assert_eq!(key(9, 9, 5, 9), None);
}
