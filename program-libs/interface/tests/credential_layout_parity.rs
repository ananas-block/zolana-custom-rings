mod frames;
mod ring_policy;

use bytemuck::Zeroable;
use custom_ring_interface::{
    ANONYMOUS_PARTIES, AddressCheckpoint, AddressRootSelection, ApplyRecordsStatement,
    AuditCredential, CredentialRead, CredentialRootSelection, CredentialRoots, CredentialStateRoot,
    CustomRingProof, DepositPrefix, DepositPublicInput, DepositRegistry, DepositedAsset,
    EnrollIxData, EnrollRequest, InstructionTag, MergePublicInput, OPENING_RECORD_LEN,
    ParsedTransact, PrivateWrites, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN, SignerSet, TransferBinding,
    TransferRoots, credential::credential_owner, domain,
    key_catalog::{ApplyMode, RingCircuit},
    storage::Revision,
};
use solana_address::Address;
use spr_hasher::{
    hash_chain::{create_hash_chain_4_from_slice, create_hash_chain_from_slice},
    primitives::{hash_bytes, pack_be, right_align},
};
use spr_interface::{N_PUBLIC_SLOTS, instruction::TransactProof};
use spr_program::ADDRESS_TREE_ID;
use spr_tree::nullifier_tree::layout::NullifierTreeLayout;

const RING_PROGRAM: Address = Address::new_from_array([0x71; 32]);
const FIRST_STATE: CredentialStateRoot = CredentialStateRoot {
    tree_id: 0x1234,
    root: [0x11; 32],
};

#[test]
fn credential_fields_match_register_key_and_state_domain_order() {
    let credential = AuditCredential {
        ring_id: [1; 32],
        member: [2; 32],
        nullifier_pk: [3; 32],
        list_tag: [4; 32],
        auditor_pubkey: [5; 33],
        eph_u: [6; 32],
        ciphertext: [7; 64],
    };
    let encoded = borsh::to_vec(&credential).unwrap();
    assert_eq!(encoded.len(), 257);
    assert_eq!(
        &encoded[..128],
        [[1; 32], [2; 32], [3; 32], [4; 32]].concat()
    );
    assert_eq!(&encoded[128..161], &[5; 33]);
    assert_eq!(&encoded[161..193], &[6; 32]);
    assert_eq!(&encoded[193..], &[7; 64]);

    let auditor = pack_be::<33, 2>(&credential.auditor_pubkey);
    let ephemeral = pack_be::<33, 2>(&custom_ring_interface::tagged_x25519(&credential.eph_u));
    let mut expected = [
        domain::field(domain::REGISTER_KEY),
        credential.ring_id,
        credential.member,
        credential.nullifier_pk,
        credential.list_tag,
        auditor[0],
        auditor[1],
        ephemeral[0],
        ephemeral[1],
        hash_bytes(&credential.ciphertext).unwrap(),
    ];
    assert_eq!(credential.elements(domain::REGISTER_KEY).unwrap(), expected);
    assert_eq!(
        credential.register_key_hash().unwrap(),
        create_hash_chain_4_from_slice(&expected).unwrap()
    );
    expected[0] = domain::field(domain::CREDENTIAL_STATE);
    assert_eq!(
        credential.elements(domain::CREDENTIAL_STATE).unwrap(),
        expected
    );
    assert_eq!(
        credential.state_hash().unwrap(),
        create_hash_chain_4_from_slice(&expected).unwrap()
    );
    assert_ne!(
        credential.register_key_hash().unwrap(),
        credential.state_hash().unwrap()
    );
}

#[test]
fn enroll_payload_keeps_both_proofs_before_the_little_endian_root_index() {
    let ix = EnrollIxData {
        nullifier_pk: [1; 32],
        list_tag: [2; 32],
        eph_u: [3; 32],
        ciphertext: [4; 64],
    };
    let register_key = CustomRingProof::zeroed();
    let transact = TransactProof {
        a: [5; 32],
        b: [6; 128],
        c: [7; 32],
    };
    let request = EnrollRequest {
        ix: &ix,
        register_key: &register_key,
        transact,
        address_root_index: 0x1234,
    };
    let bytes = request.encode().unwrap();
    assert_eq!(InstructionTag::Enroll as u8, 65);
    assert_eq!(bytes.len(), 546);
    assert_eq!(&bytes[..160], bytemuck::bytes_of(&ix));
    assert_eq!(&bytes[160..352], bytemuck::bytes_of(&register_key));
    assert_eq!(
        &bytes[352..544],
        wincode::serialize(&request.transact).unwrap()
    );
    assert_eq!(&bytes[544..], &[0x34, 0x12]);
    let parsed = EnrollRequest::parse(&bytes).unwrap();
    assert_eq!(parsed.ix, &ix);
    assert_eq!(parsed.register_key, &register_key);
    assert_eq!(parsed.transact, request.transact);
    assert_eq!(parsed.address_root_index, 0x1234);
    for length in [159, 351, 543, 544, 545] {
        assert!(EnrollRequest::parse(&bytes[..length]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(EnrollRequest::parse(&trailing).is_err());
}

#[test]
fn credential_read_and_deposit_prefix_preserve_the_exact_spp_suffix() {
    let read = CredentialRead::new(0x1234, &[0x5678, 0x9abc]).unwrap();
    let mut read_bytes = Vec::new();
    read.encode_into(&mut read_bytes);
    assert_eq!(read_bytes, [0x34, 0x12, 2, 0x78, 0x56, 0xbc, 0x9a]);
    let prefix = DepositPrefix {
        tag: InstructionTag::Deposit as u8,
        key_capacity: 2,
        proof: CustomRingProof::zeroed(),
        credential_read: read.clone(),
        own_revision: Revision::from(0x0102_0304_0506_0708),
        curator_revision: Revision::from(0x1112_1314_1516_1718),
    };
    let mut bytes = prefix.encode().unwrap();
    assert_eq!(bytes.len(), 217);
    assert_eq!(&bytes[..2], &[58, 2]);
    assert_eq!(&bytes[194..201], &read_bytes);
    assert_eq!(&bytes[201..209], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&bytes[209..217], &0x1112_1314_1516_1718u64.to_le_bytes());
    bytes.extend_from_slice(&[0xa1, 0xb2, 0xc3]);
    let mut remaining = bytes.as_slice();
    assert_eq!(DepositPrefix::parse(&mut remaining).unwrap(), prefix);
    assert_eq!(remaining, &[0xa1, 0xb2, 0xc3]);

    let mut state_bytes = Vec::new();
    CredentialRead::new_state(0x5678)
        .encode_state_into(&mut state_bytes)
        .unwrap();
    assert_eq!(state_bytes, [1, 0x78, 0x56]);
    assert!(read.encode_state_into(&mut Vec::new()).is_err());
    assert!(CredentialRead::new(1, &[]).is_err());
    assert!(CredentialRead::decode_state(&mut &[2, 0, 0, 1, 0][..]).is_err());
    let too_many = DepositPrefix {
        key_capacity: 1,
        ..prefix
    };
    assert!(too_many.encode().is_err());
}

#[test]
fn state_root_padding_repeats_the_first_sorted_pair() {
    let second = CredentialStateRoot {
        tree_id: 0x5678,
        root: [0x12; 32],
    };
    let roots = CredentialRootSelection {
        ring_program: &RING_PROGRAM,
        address_checkpoint: checkpoint(),
        state_roots: &[FIRST_STATE, second],
        capacity: 4,
    }
    .roots()
    .unwrap();
    assert_eq!(
        roots.state_roots(),
        &[FIRST_STATE, second, FIRST_STATE, FIRST_STATE]
    );
    assert_eq!(
        roots.elements().collect::<Vec<_>>(),
        vec![
            credential_owner(&RING_PROGRAM).unwrap(),
            [0x13; 32],
            right_align(&[0x12, 0x34]),
            FIRST_STATE.root,
            right_align(&[0x56, 0x78]),
            second.root,
            right_align(&[0x12, 0x34]),
            FIRST_STATE.root,
            right_align(&[0x12, 0x34]),
            FIRST_STATE.root,
        ]
    );
    for states in [
        vec![],
        vec![second, FIRST_STATE],
        vec![FIRST_STATE, FIRST_STATE],
        vec![CredentialStateRoot {
            root: [0; 32],
            ..FIRST_STATE
        }],
    ] {
        assert!(
            CredentialRootSelection {
                ring_program: &RING_PROGRAM,
                address_checkpoint: checkpoint(),
                state_roots: &states,
                capacity: 4,
            }
            .roots()
            .is_err()
        );
    }
}

#[test]
fn deposit_statement_binds_ring_identity_before_count_and_padded_roots() {
    let credentials = roots(2);
    let ring_id = [0x21; 32];
    let owner = [[0x22; 32]];
    let ciphertexts = [[0x23; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]];
    let assets = [DepositedAsset {
        asset: [0x24; 32],
        amount: 0x0102_0304_0506_0708,
    }];
    let auditor = [0x25; 33];
    let ephemeral = [0x26; 33];
    let mut statement = DepositPublicInput {
        context_hash: &[0x20; 32],
        ring_id: &ring_id,
        owner_utxo_hashes: &owner,
        ciphertexts: &ciphertexts,
        assets: &assets,
        auditor_pk: &auditor,
        eph_pk: &ephemeral,
        credentials: &credentials,
        registry: Some(DepositRegistry {
            own_root: &[0x27; 32],
            curator_root: Some(&[0x28; 32]),
            policy_hash: &[0x29; 32],
        }),
    };
    let mut expected = vec![
        domain::field(domain::DEPOSIT_STATEMENT),
        [0x20; 32],
        ring_id,
        right_align(&[1]),
        owner[0],
        hash_bytes(&ciphertexts[0]).unwrap(),
    ];
    expected.resize(20, [0; 32]);
    expected.extend(pack_be::<33, 2>(&auditor));
    expected.extend(pack_be::<33, 2>(&ephemeral));
    expected.extend(credentials.elements());
    expected.extend([
        [0x27; 32],
        [0x28; 32],
        [0x29; 32],
        assets[0].asset,
        right_align(&assets[0].amount.to_be_bytes()),
    ]);
    expected.resize(49, [0; 32]);
    assert_eq!(statement.element_count(), 49);
    assert_eq!(statement.elements().unwrap(), expected);
    let digest = create_hash_chain_4_from_slice(&expected).unwrap();
    assert_eq!(statement.hash().unwrap(), digest);
    statement.ring_id = &[0x2a; 32];
    assert_ne!(statement.hash().unwrap(), digest);
}

#[test]
fn merge_statement_uses_one_state_pair_without_an_address_root() {
    let credentials = CredentialRoots::state_only(&RING_PROGRAM, FIRST_STATE).unwrap();
    let auditor = [0x21; 33];
    let ephemeral = [0x22; 33];
    let ciphertext = [0x23; OPENING_RECORD_LEN];
    let mut statement = MergePublicInput {
        output_utxo_hash: &[1; 32],
        first_nullifier: &[2; 32],
        ring_id: &[3; 32],
        auditor_pk: &auditor,
        eph_pk: &ephemeral,
        ciphertext: &ciphertext,
        payer: &[4; 32],
        published_owner: &[0; 32],
        credentials: &credentials,
    };
    let mut expected = vec![
        domain::field(domain::MERGE_STATEMENT),
        [1; 32],
        [2; 32],
        [3; 32],
    ];
    expected.extend(pack_be::<33, 2>(&auditor));
    expected.extend(pack_be::<33, 2>(&ephemeral));
    expected.extend([
        hash_bytes(&ciphertext).unwrap(),
        [4; 32],
        [0; 32],
        credential_owner(&RING_PROGRAM).unwrap(),
        right_align(&[0x12, 0x34]),
        FIRST_STATE.root,
    ]);
    assert_eq!(expected.len(), 14);
    assert_eq!(statement.elements().unwrap(), expected);
    assert_eq!(
        statement.hash().unwrap(),
        create_hash_chain_from_slice(&expected).unwrap()
    );
    let with_address = roots(1);
    statement.credentials = &with_address;
    assert!(statement.elements().is_err());
    let wide = CredentialRoots::empty(2).unwrap();
    statement.credentials = &wide;
    assert!(statement.elements().is_err());
}

#[test]
fn apply_records_appends_private_write_identity_and_credential_roots() {
    let statement = ApplyRecordsStatement {
        old_root: [1; 32],
        new_root: [2; 32],
        old_next_index: 3,
        new_next_index: 4,
        chain_start: [5; 32],
        chain_end: [6; 32],
        count: 2,
        private: Some(PrivateWrites {
            credential_writes: 1,
            private_ring_id: [7; 32],
            credentials: roots(2),
        }),
    };
    let public_prefix = vec![
        domain::field(domain::APPLY_RECORDS),
        [1; 32],
        [2; 32],
        right_align(&[3]),
        right_align(&[4]),
        [5; 32],
        [6; 32],
        right_align(&[2]),
    ];
    let mut expected = public_prefix.clone();
    expected.extend([right_align(&[1]), [7; 32]]);
    expected.extend(roots(2).elements());
    assert_eq!(expected.len(), 16);
    assert_eq!(statement.elements(), expected);
    assert_eq!(
        statement.hash().unwrap(),
        create_hash_chain_4_from_slice(&expected).unwrap()
    );
    assert_eq!(
        statement.circuit(),
        RingCircuit::ApplyRecords {
            writes: 2,
            mode: ApplyMode::Private
        }
    );
    let public = ApplyRecordsStatement {
        private: None,
        ..statement
    };
    assert_eq!(public.elements(), public_prefix);
    assert_eq!(
        public.circuit(),
        RingCircuit::ApplyRecords {
            writes: 2,
            mode: ApplyMode::Public
        }
    );
}

#[test]
fn transfer_statement_keeps_credential_pairs_before_public_amounts() {
    let fixture = frames::Fixture::new();
    let ring = ring_policy::config();
    let public = [[4; 32]; N_PUBLIC_SLOTS];
    for (_, data) in fixture.cases() {
        let withdrawals = data
            .interface_transfers
            .iter()
            .filter(|transfer| !transfer.is_deposit())
            .count();
        let capacity = data
            .transfer_circuit(withdrawals)
            .unwrap()
            .credential_capacity()
            .unwrap();
        let roots = TransferRoots {
            policy_hash: [1; 32],
            own_root: [2; 32],
            curator_root: [3; 32],
            credentials: roots(capacity),
        };
        let parsed = ParsedTransact::new(data).unwrap();
        let statement = parsed
            .transfer_statement(TransferBinding {
                ring_id: &fixture.fields[60],
                auditor_pubkey: &ring.auditor_pubkey,
                sender: &fixture.fields[61],
                signers: SignerSet::default(),
                party_identities: &[[0; 32]; ANONYMOUS_PARTIES],
                roots: &roots,
                public_assets: &public,
                public_amounts: &public,
                public_gross: &public,
                withdrawal_hash: &fixture.fields[62],
            })
            .unwrap();
        let elements = statement.elements().unwrap();
        let credential_start = 30 + ANONYMOUS_PARTIES;
        let credential_end = credential_start + 2 + 2 * capacity;
        assert_eq!(
            &elements[credential_start - 3..credential_start],
            &[[1; 32], [2; 32], [3; 32]]
        );
        assert_eq!(
            &elements[credential_start..credential_end],
            roots.credentials.elements().collect::<Vec<_>>()
        );
        assert_eq!(&elements[credential_end..credential_end + 9], &[[4; 32]; 9]);
        assert_eq!(elements[credential_end + 9], fixture.fields[62]);
        assert_eq!(
            elements.last(),
            Some(&right_align(&(elements.len() as u64).to_be_bytes()))
        );
        assert_eq!(statement.element_count(), elements.len());
    }
}

fn roots(capacity: usize) -> CredentialRoots {
    CredentialRootSelection {
        ring_program: &RING_PROGRAM,
        address_checkpoint: checkpoint(),
        state_roots: &[FIRST_STATE],
        capacity,
    }
    .roots()
    .unwrap()
}

fn checkpoint() -> AddressCheckpoint {
    let bytes = vec![0; core::mem::size_of::<NullifierTreeLayout<4>>()];
    let mut history: NullifierTreeLayout<4> = wincode::deserialize(&bytes).unwrap();
    history.sequence_number = 7;
    history.root_history.current_index = 2;
    history.root_history.roots[1] = [0x13; 32];
    AddressRootSelection {
        tree_id: ADDRESS_TREE_ID,
        root_index: 1,
        history: &history,
    }
    .checkpoint()
    .unwrap()
}
