use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{
        AddressAuthorization, RegistryId, Revision, RootUpdate, StorageError, StorageRegistry,
    },
    storage_instruction::{
        tag, AddressWriteData, EnrollAddressIxData, EscrowWriteData, InitializeIxData,
        StorageUpdateIxData, StorageWriteData, UpdateMode,
    },
    ApplyRecordsIxData, CustomRingProof, PlainGroth16Proof, RecordWriteData, WriteRecordsIxData,
};
use litesvm::LiteSVM;
use serde_json::Value;
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_transaction_error::TransactionError;
use spr_client::{
    compile_message,
    prover::{Proof, ProofCompressed},
    sign_transaction, ComputeBudgetConfig,
};

const PROGRAM: Address = custom_ring_interface::STORAGE_PROGRAM_ID;
const GRACE: u64 = 10;
const REGISTRY_ID: RegistryId = RegistryId([1; 32]);
const CURATOR_ID: RegistryId = RegistryId([2; 32]);
const RING_ID: [u8; 32] = [7; 32];
const SYSTEM: Address = Address::new_from_array([0; 32]);
/// Any address serves the CPI owner.
const CPI_OWNER_PROGRAM: Address = Address::new_from_array([0x63; 32]);
const NULLIFIER_PK: [u8; 32] = [3; 32];
const VIEWING_U: [u8; 32] = [4; 32];

struct Store {
    svm: LiteSVM,
    authority: Keypair,
    payer: Keypair,
    registry: Address,
    proofs: Value,
}

impl Store {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.warp_to_slot(0);
        let program = std::env::var_os("SBF_OUT_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").into())
            .join("storage_program.so");
        svm.add_program(PROGRAM, &std::fs::read(program).unwrap())
            .unwrap();
        let authority = Keypair::new_from_array([9; 32]);
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
        let registry = StorageRegistry::find_address(&authority.pubkey(), &REGISTRY_ID).0;
        let proofs: Value = serde_json::from_str(include_str!("proofs.json")).unwrap();
        // The apply proofs bind the registry address.
        assert_eq!(hex::encode(registry), proofs["registry"].as_str().unwrap());
        Self {
            svm,
            authority,
            payer,
            registry,
            proofs,
        }
    }

    fn initialize(&mut self, grace_slots: u64) {
        let (registry, data) = (
            self.registry,
            InitializeIxData {
                registry_id: REGISTRY_ID,
                grace_slots: grace_slots.to_le_bytes(),
                ring_id: RING_ID,
            },
        );
        self.send_as_authority(self.initialize_instruction(registry, &data))
            .unwrap();
    }

    fn initialize_instruction(&self, registry: Address, data: &InitializeIxData) -> Instruction {
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: [&[tag::INITIALIZE], bytemuck::bytes_of(data)].concat(),
        }
    }

    fn enroll(
        &self,
        registry: Address,
        owner: &Address,
        nullifier_pk: [u8; 32],
        viewing_u: [u8; 32],
    ) -> Instruction {
        let data = EnrollAddressIxData {
            nullifier_pk,
            viewing_u,
        };
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(*owner, true),
                AccountMeta::new_readonly(registry, false),
                AccountMeta::new(
                    AddressAuthorization::find_address(&registry, owner).0,
                    false,
                ),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: [&[tag::ENROLL_ADDRESS], bytemuck::bytes_of(&data)].concat(),
        }
    }

    fn enrolled(&mut self, owner: &Keypair) -> AddressAuthorization {
        self.send(
            self.enroll(self.registry, &owner.pubkey(), NULLIFIER_PK, VIEWING_U),
            &[owner],
        )
        .unwrap();
        self.authorization(&owner.pubkey())
    }

    fn authorization(&self, owner: &Address) -> AddressAuthorization {
        let address = AddressAuthorization::find_address(&self.registry, owner).0;
        *bytemuck::from_bytes(&self.svm.get_account(&address).unwrap().data)
    }

    /// An update at revision 0 past every check ahead of the proof, the zero proof fails there.
    fn address_update(
        &self,
        writes: Vec<StorageWriteData>,
        authorizations: &[AccountMeta],
    ) -> Instruction {
        let apply = ApplyRecordsIxData::zeroed();
        let data = StorageUpdateIxData {
            revision: 0.into(),
            writes,
            apply: &apply,
        };
        Instruction {
            program_id: PROGRAM,
            accounts: [
                vec![
                    AccountMeta::new_readonly(self.authority.pubkey(), true),
                    AccountMeta::new(self.registry, false),
                ],
                authorizations.to_vec(),
            ]
            .concat(),
            data: [vec![UpdateMode::Graced.tag()], data.encode().unwrap()].concat(),
        }
    }

    fn update(&self, revision: u64) -> Instruction {
        self.update_with(revision, UpdateMode::Graced)
    }

    fn update_with(&self, revision: u64, mode: UpdateMode) -> Instruction {
        let vector = &self.proofs[format!("update{revision}")];
        let writes = vector["writes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| write(vector, entry))
            .collect::<Vec<_>>();
        let apply = ApplyRecordsIxData {
            proof: proof(vector),
            new_root: field(&vector["root"]),
            new_next_index: u32::try_from(vector["nextIndex"].as_u64().unwrap())
                .unwrap()
                .to_le_bytes(),
        };
        let data = StorageUpdateIxData {
            revision: revision.into(),
            writes,
            apply: &apply,
        };
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(self.registry, false),
            ],
            data: [vec![mode.tag()], data.encode().unwrap()].concat(),
        }
    }

    fn update_authority(&self, authority: &Keypair, new_authority: &Keypair) -> Instruction {
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new_readonly(new_authority.pubkey(), true),
                AccountMeta::new(self.registry, false),
            ],
            data: vec![tag::UPDATE_AUTHORITY],
        }
    }

    fn registry(&self) -> StorageRegistry {
        *bytemuck::from_bytes(&self.svm.get_account(&self.registry).unwrap().data)
    }

    fn root(&self, revision: u64) -> Result<[u8; 32], StorageError> {
        self.registry().root(
            Revision::from(revision),
            self.svm.get_sysvar::<solana_clock::Clock>().slot,
        )
    }

    fn send_as_authority(&mut self, instruction: Instruction) -> Result<(), TransactionError> {
        let authority = self.authority.insecure_clone();
        self.send(instruction, &[&authority])
    }

    fn send(
        &mut self,
        instruction: Instruction,
        signers: &[&Keypair],
    ) -> Result<(), TransactionError> {
        self.svm.expire_blockhash();
        let signers = [&self.payer]
            .into_iter()
            .chain(signers.iter().copied())
            .map(|signer| signer as &dyn Signer)
            .collect::<Vec<_>>();
        let message = compile_message(
            &self.payer.pubkey(),
            &[instruction],
            self.svm.latest_blockhash(),
            ComputeBudgetConfig::new(1_400_000),
        )
        .unwrap();
        let transaction = sign_transaction(message, &signers).unwrap();
        self.svm
            .send_transaction(transaction)
            .map(|_| ())
            .map_err(|failed| failed.err)
    }
}

fn address_write(owner: &Address, revision: u64) -> StorageWriteData {
    StorageWriteData::Address(AddressWriteData {
        owner: *owner,
        address_revision: revision.to_le_bytes(),
    })
}

fn authorization_meta(registry: &Address, owner: &Address) -> AccountMeta {
    AccountMeta::new(AddressAuthorization::find_address(registry, owner).0, false)
}

fn refusal(code: u32) -> Result<(), TransactionError> {
    Err(TransactionError::InstructionError(
        0,
        InstructionError::Custom(code),
    ))
}

fn write(vector: &Value, entry: &Value) -> StorageWriteData {
    if field(&entry["escrowKey"]) != [0; 32] {
        let escrow = &vector["escrow"];
        return StorageWriteData::Escrow(EscrowWriteData {
            owner: Address::new_from_array(field(&escrow["owner"])),
            nullifier_pk: field(&escrow["nullifierPk"]),
            eph_u: field(&escrow["ephU"]),
            ciphertext: field(&escrow["ciphertext"]),
        });
    }
    StorageWriteData::Record(RecordWriteData {
        member: field(&entry["member"]),
        lists: WriteRecordsIxData {
            mask: entry["mask"].as_u64().unwrap().to_le_bytes(),
            value: entry["value"].as_u64().unwrap().to_le_bytes(),
        },
        mint_policy: custom_ring_interface::mint_policy_write(None),
    })
}

fn field(value: &Value) -> [u8; 32] {
    hex::decode(value.as_str().unwrap().strip_prefix("0x").unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn proof(vector: &Value) -> CustomRingProof {
    let compressed =
        ProofCompressed::try_from(Proof::from_gnark_json(&vector["proof"].to_string()).unwrap())
            .unwrap();
    let commitment = compressed.commitment.unwrap();
    CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: compressed.a,
            proof_b: compressed.compressed_b().unwrap(),
            proof_c: compressed.c,
        },
        commitment: commitment.commitment,
        commitment_pok: commitment.commitment_pok,
    }
}

#[test]
fn authority_rotates_and_the_old_authority_is_refused() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let old = store.authority.insecure_clone();
    let new = Keypair::new();
    store
        .send(store.update_authority(&old, &new), &[&old, &new])
        .unwrap();
    assert_eq!(
        store.send(store.update_authority(&old, &old), &[&old]),
        refusal(StorageError::Unauthorized as u32)
    );
    assert_eq!(
        store.send_as_authority(store.update(0)),
        refusal(StorageError::Unauthorized as u32)
    );
    let mut update = store.update(0);
    update.accounts[0].pubkey = new.pubkey();
    store.send(update, &[&new]).unwrap();
}

#[test]
fn an_escrow_write_applies() {
    let mut store = Store::new();
    store.initialize(GRACE);
    for revision in 0..3 {
        store.send_as_authority(store.update(revision)).unwrap();
    }
    assert_eq!(store.root(3), Ok(field(&store.proofs["update2"]["root"])));
}

#[test]
fn updates_retire_roots_by_mode() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut wrong_authority = store.update(0);
    wrong_authority.accounts[0].pubkey = store.payer.pubkey();
    assert_eq!(
        store.send(wrong_authority, &[]),
        refusal(StorageError::Unauthorized as u32)
    );
    let mut forged = store.update(0);
    *forged.data.last_mut().unwrap() ^= 1;
    assert_eq!(
        store.send_as_authority(forged),
        refusal(StorageError::ProofVerificationFailed as u32)
    );
    store.send_as_authority(store.update(0)).unwrap();
    assert_eq!(
        store.send_as_authority(store.update(0)),
        refusal(StorageError::RevisionChanged as u32)
    );

    let seeded = store.svm.clone();
    for mode in [UpdateMode::Graced, UpdateMode::Immediate] {
        store.svm = seeded.clone();
        store.send_as_authority(store.update_with(1, mode)).unwrap();
        if mode == UpdateMode::Graced {
            store.svm.warp_to_slot(GRACE - 1);
            assert!(store.root(1).is_ok());
            store.svm.warp_to_slot(GRACE);
        }
        assert_eq!(store.root(1), Err(StorageError::RootExpired));
        store.send_as_authority(store.update(2)).unwrap();
        assert_eq!(store.root(1), Err(StorageError::RootExpired));
    }
}

#[test]
fn unbounded_grace_keeps_both_update_modes() {
    let mut store = Store::new();
    store.initialize(u64::MAX);
    store.svm.warp_to_slot(1);
    store.send_as_authority(store.update(0)).unwrap();
    store
        .send_as_authority(store.update_with(1, UpdateMode::Immediate))
        .unwrap();
}

#[test]
fn a_graced_update_never_evicts_a_root_that_still_verifies() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut account = store.svm.get_account(&store.registry).unwrap();
    let oldest = bytemuck::from_bytes_mut::<StorageRegistry>(&mut account.data)
        .roots
        .last_mut()
        .unwrap();
    oldest.expires_at = GRACE.to_le_bytes();
    store.svm.set_account(store.registry, account).unwrap();
    assert_eq!(
        store.send_as_authority(store.update(0)),
        refusal(StorageError::HistoryFull as u32)
    );
    let full = store.svm.clone();
    store
        .send_as_authority(store.update_with(0, UpdateMode::Immediate))
        .unwrap();
    store.svm = full;
    // Evictable from the slot `RootExpired` starts refusing it.
    store.svm.warp_to_slot(GRACE);
    store.send_as_authority(store.update(0)).unwrap();
}

/// The indexer projects every update through `StorageRegistry::update`.
#[test]
fn the_program_rotates_roots_as_the_indexer_projects_them() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut projected = store.registry();
    for (revision, mode) in [
        (0, UpdateMode::Graced),
        (1, UpdateMode::Graced),
        (2, UpdateMode::Immediate),
    ] {
        let slot = revision + 1;
        store.svm.warp_to_slot(slot);
        let instruction = store.update_with(revision, mode);
        let data = StorageUpdateIxData::parse(&instruction.data[1..]).unwrap();
        projected
            .update(RootUpdate {
                mode,
                slot,
                data: &data,
            })
            .unwrap();
        store.send_as_authority(instruction).unwrap();
        assert_eq!(store.registry(), projected);
    }
}

#[test]
fn the_first_enrollment_copies_the_registry_s_ring_at_revision_one() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let owner = Keypair::new();
    let account = store.enrolled(&owner);
    assert_eq!(account.registry, store.registry);
    assert_eq!(account.owner, owner.pubkey());
    assert_eq!(account.ring_id, RING_ID);
    assert_eq!(account.nullifier_pk, NULLIFIER_PK);
    assert_eq!(account.viewing_u, VIEWING_U);
    assert_eq!((account.revision(), account.applied_revision()), (1, 0));
    assert_eq!(
        account.bump,
        AddressAuthorization::find_address(&store.registry, &owner.pubkey()).1
    );
}

#[test]
fn a_later_enrollment_rotates_the_viewing_key_alone() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let owner = Keypair::new();
    store.enrolled(&owner);
    let rotated = [5; 32];
    store
        .send(
            store.enroll(store.registry, &owner.pubkey(), NULLIFIER_PK, rotated),
            &[&owner],
        )
        .unwrap();
    let account = store.authorization(&owner.pubkey());
    assert_eq!((account.viewing_u, account.revision()), (rotated, 2));
    assert_eq!(
        store.send(
            store.enroll(store.registry, &owner.pubkey(), [6; 32], rotated),
            &[&owner],
        ),
        refusal(StorageError::NullifierKeyChanged as u32)
    );
}

#[test]
fn enrollment_takes_the_owner_s_signature_and_a_canonical_key() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let owner = Keypair::new();
    let mut unsigned = store.enroll(store.registry, &owner.pubkey(), NULLIFIER_PK, VIEWING_U);
    unsigned.accounts[1].is_signer = false;
    assert_eq!(
        store.send(unsigned, &[]),
        refusal(StorageError::MissingSignature as u32)
    );
    let modulus: [u8; 32] = core::array::from_fn(|byte| match byte {
        0 => 0xed,
        31 => 0x7f,
        _ => 0xff,
    });
    for viewing_u in [[0; 32], modulus] {
        assert_eq!(
            store.send(
                store.enroll(store.registry, &owner.pubkey(), NULLIFIER_PK, viewing_u),
                &[&owner],
            ),
            refusal(StorageError::NonCanonicalViewingKey as u32)
        );
    }
    let mut foreign = store.enroll(store.registry, &owner.pubkey(), NULLIFIER_PK, VIEWING_U);
    foreign.accounts[3].pubkey =
        AddressAuthorization::find_address(&store.registry, &Keypair::new().pubkey()).0;
    assert_eq!(
        store.send(foreign, &[&owner]),
        refusal(StorageError::InvalidAddressAuthorization as u32)
    );
}

/// Only a registry naming a ring takes an address, the owner names no ring.
#[test]
fn a_curator_registry_refuses_enrollment() {
    let mut store = Store::new();
    let curator = StorageRegistry::find_address(&store.authority.pubkey(), &CURATOR_ID).0;
    let data = InitializeIxData {
        registry_id: CURATOR_ID,
        grace_slots: GRACE.to_le_bytes(),
        ring_id: [0; 32],
    };
    store
        .send_as_authority(store.initialize_instruction(curator, &data))
        .unwrap();
    let owner = Keypair::new();
    assert_eq!(
        store.send(
            store.enroll(curator, &owner.pubkey(), NULLIFIER_PK, VIEWING_U),
            &[&owner],
        ),
        refusal(StorageError::RegistryServesNoRing as u32)
    );
    assert_eq!(
        store.send(
            store.enroll(PROGRAM, &owner.pubkey(), NULLIFIER_PK, VIEWING_U),
            &[&owner],
        ),
        refusal(StorageError::InvalidRegistry as u32)
    );
}

/// The runtime sets the signer flag a program's `invoke_signed` raises, one code path.
#[test]
fn a_program_owner_enrolls_through_cpi() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let dir = std::env::var_os("SBF_OUT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").into());
    store
        .svm
        .add_program(
            CPI_OWNER_PROGRAM,
            &std::fs::read(dir.join("storage_cpi_owner.so")).unwrap(),
        )
        .unwrap();
    let owner = Address::find_program_address(&[b"owner"], &CPI_OWNER_PROGRAM).0;
    let mut enroll = store.enroll(store.registry, &owner, NULLIFIER_PK, VIEWING_U);
    enroll.program_id = CPI_OWNER_PROGRAM;
    enroll.accounts[1].is_signer = false;
    enroll
        .accounts
        .push(AccountMeta::new_readonly(PROGRAM, false));
    store.send(enroll, &[]).unwrap();
    let account = store.authorization(&owner);
    assert_eq!((account.owner, account.revision()), (owner, 1));
    assert_eq!(account.ring_id, RING_ID);
}

#[test]
fn an_address_write_reads_the_owner_s_authorization_ahead_of_the_proof() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let owner = Keypair::new();
    store.enrolled(&owner);
    let meta = authorization_meta(&store.registry, &owner.pubkey());
    let at_revision = |revision| vec![address_write(&owner.pubkey(), revision)];
    assert_eq!(
        store.send_as_authority(store.address_update(at_revision(1), std::slice::from_ref(&meta))),
        refusal(StorageError::ProofVerificationFailed as u32)
    );
    let refused = StorageError::InvalidAddressAuthorization as u32;
    // A batch without the account or with another owner's cannot chain the entry.
    assert_eq!(
        store.send_as_authority(store.address_update(at_revision(1), &[])),
        refusal(refused)
    );
    let stranger = Keypair::new();
    store.enrolled(&stranger);
    let foreign = authorization_meta(&store.registry, &stranger.pubkey());
    assert_eq!(
        store.send_as_authority(store.address_update(at_revision(1), &[foreign])),
        refusal(refused)
    );
    // Only the newest revision applies, an authority cannot pick an older address.
    assert_eq!(
        store.send_as_authority(store.address_update(at_revision(2), std::slice::from_ref(&meta))),
        refusal(refused)
    );
    let read_only = AccountMeta::new_readonly(meta.pubkey, false);
    assert_eq!(
        store.send_as_authority(store.address_update(at_revision(1), &[read_only])),
        refusal(refused)
    );
    assert_eq!(
        store
            .send_as_authority(store.address_update(at_revision(1), &[meta.clone(), meta.clone()])),
        refusal(refused)
    );
    let unenrolled = Keypair::new();
    assert_eq!(
        store.send_as_authority(store.address_update(
            vec![address_write(&unenrolled.pubkey(), 1)],
            &[authorization_meta(&store.registry, &unenrolled.pubkey())],
        )),
        refusal(refused)
    );
}

#[test]
fn an_applied_revision_applies_once_and_a_rotation_opens_the_next() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let owner = Keypair::new();
    let mut account = store.enrolled(&owner);
    let meta = authorization_meta(&store.registry, &owner.pubkey());
    account.applied_revision = account.revision;
    let mut stored = store.svm.get_account(&meta.pubkey).unwrap();
    stored.data.copy_from_slice(bytemuck::bytes_of(&account));
    store.svm.set_account(meta.pubkey, stored).unwrap();
    let write = vec![address_write(&owner.pubkey(), 1)];
    assert_eq!(
        store.send_as_authority(store.address_update(write, std::slice::from_ref(&meta))),
        refusal(StorageError::AddressAlreadyApplied as u32)
    );
    store
        .send(
            store.enroll(store.registry, &owner.pubkey(), NULLIFIER_PK, [5; 32]),
            &[&owner],
        )
        .unwrap();
    let next = vec![address_write(&owner.pubkey(), 2)];
    assert_eq!(
        store.send_as_authority(store.address_update(next, &[meta])),
        refusal(StorageError::ProofVerificationFailed as u32)
    );
}

/// A record or escrow write holds no address, a trailing account cannot lend it one.
#[test]
fn an_authority_batch_cannot_change_an_address() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let owner = Keypair::new();
    store.enrolled(&owner);
    let meta = authorization_meta(&store.registry, &owner.pubkey());
    let record = StorageWriteData::Record(RecordWriteData {
        member: [1; 32],
        lists: WriteRecordsIxData {
            mask: 1u64.to_le_bytes(),
            value: 1u64.to_le_bytes(),
        },
        mint_policy: custom_ring_interface::mint_policy_write(None),
    });
    assert_eq!(record.entry().unwrap().address_hash, [0; 32]);
    assert_eq!(
        store.send_as_authority(store.address_update(vec![record], std::slice::from_ref(&meta))),
        refusal(StorageError::InvalidAddressAuthorization as u32)
    );
    let escrow = StorageWriteData::Escrow(EscrowWriteData {
        owner: owner.pubkey(),
        nullifier_pk: NULLIFIER_PK,
        eph_u: [8; 32],
        ciphertext: [9; 32],
    });
    assert_eq!(escrow.entry().unwrap().address_hash, [0; 32]);
    assert_eq!(
        store.send_as_authority(store.address_update(vec![escrow], &[meta])),
        refusal(StorageError::InvalidAddressAuthorization as u32)
    );
}
