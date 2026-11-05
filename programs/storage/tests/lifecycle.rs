use bytemuck::Zeroable;
use custom_ring_interface::{
    mint_policy_write,
    owner_grant::OwnerGrant,
    storage::{RegistryId, Revision, RootUpdate, StorageError, StorageRegistry},
    storage_instruction::{
        tag, InitializeIxData, OwnerGrantIxData, PrivateWriteCheckpoint, StorageUpdateIxData,
    },
    ApplyRecordsIxData, CredentialRead, CustomRingError, CustomRingProof, PlainGroth16Proof,
    RecordWriteData, WriteRecordsIxData, READER_KEY_ED25519, ROOT_HISTORY,
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
use spr_interface::{
    pda, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, SHIELDED_POOL_PROGRAM_ID,
};
use spr_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule, UTXO_TREE_HEIGHT};
use zolana_ring_policy::{ring_id_field, ListId, ListSet};

const PROGRAM: Address = custom_ring_interface::STORAGE_PROGRAM_ID;
const GRACE: u64 = 10;
const REGISTRY_ID: RegistryId = RegistryId([1; 32]);
const CURATOR_ID: RegistryId = RegistryId([2; 32]);
const PRIVATE_ID: RegistryId = RegistryId([3; 32]);
const RING_ID: [u8; 32] = [7; 32];
const RING_PROGRAM: Address = Address::new_from_array([0x52; 32]);
const SPP: Address = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
const SYSTEM: Address = Address::new_from_array([0; 32]);
/// Any address serves the CPI owner.
const CPI_OWNER_PROGRAM: Address = Address::new_from_array([0x63; 32]);

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
        svm.add_program(
            PROGRAM,
            &std::fs::read(deploy_dir().join("storage_program.so")).unwrap(),
        )
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
                private_ring_id: [0; 32],
            },
        );
        self.send_as_authority(self.initialize_instruction(registry, &data))
            .unwrap();
    }

    fn initialize_pinned(&mut self, registry_id: RegistryId, ring_id: [u8; 32]) -> Address {
        let source = StorageRegistry::find_address(&self.authority.pubkey(), &registry_id).0;
        let data = InitializeIxData {
            registry_id,
            grace_slots: GRACE.to_le_bytes(),
            ring_id,
            private_ring_id: ring_id_field(RING_PROGRAM.as_array()).unwrap(),
        };
        self.send_as_authority(self.initialize_instruction(source, &data))
            .unwrap();
        source
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

    fn seed(&mut self, address: Address, data: &[u8]) {
        let mut account = self.svm.get_account(&self.payer.pubkey()).unwrap();
        account.lamports = self.svm.minimum_balance_for_rent_exemption(data.len());
        account.data = data.to_vec();
        account.owner = PROGRAM;
        self.svm.set_account(address, account).unwrap();
    }

    fn seed_tree(&mut self, tree_id: u16) -> Address {
        let address = pda::tree(tree_id);
        let mut data = vec![0; TreeAccount::account_size()];
        TreeAccount::init(
            &mut data,
            TREE_ACCOUNT_DISCRIMINATOR,
            UTXO_TREE_HEIGHT as u8,
            address.to_bytes(),
            tree_id,
            NullifierTreeInitParams::default(),
            TreeFeeSchedule::default(),
        )
        .unwrap();
        self.seed(address, &data);
        let mut account = self.svm.get_account(&address).unwrap();
        account.owner = SPP;
        self.svm.set_account(address, account).unwrap();
        address
    }

    fn private_update(&self, registry: Address) -> Instruction {
        let mut instruction = self.zero_proof_update_of(registry, 0, ListId::PrivateBlock);
        instruction.accounts.extend(
            [pda::tree(0), pda::tree(1)].map(|address| AccountMeta::new_readonly(address, false)),
        );
        instruction
    }

    fn grant(&self, owner: &Address, reader: [u8; 34], active: u8) -> Instruction {
        let data = OwnerGrantIxData {
            ring_program: RING_PROGRAM,
            reader,
            active,
        };
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(*owner, true),
                AccountMeta::new(
                    OwnerGrant::find_address(&RING_PROGRAM, owner, &reader).0,
                    false,
                ),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: [&[tag::OWNER_GRANT], bytemuck::bytes_of(&data)].concat(),
        }
    }

    /// An update at `revision` past every check ahead of the proof, the zero proof fails there.
    fn zero_proof_update(&self, revision: u64, list: ListId) -> Instruction {
        self.zero_proof_update_of(self.registry, revision, list)
    }

    fn zero_proof_update_of(&self, registry: Address, revision: u64, list: ListId) -> Instruction {
        let apply = ApplyRecordsIxData {
            new_root: [8; 32],
            new_next_index: 2u32.to_le_bytes(),
            ..ApplyRecordsIxData::zeroed()
        };
        let data = StorageUpdateIxData {
            revision: revision.into(),
            writes: vec![RecordWriteData {
                member: allow_write().member,
                lists: WriteRecordsIxData {
                    mask: list.record_bit().to_le_bytes(),
                    value: list.record_bit().to_le_bytes(),
                },
                mint_policy: mint_policy_write(None),
            }],
            asset_writes: Vec::new(),
            credential_read: if ListSet::PRIVATE_LISTS.contains(list) {
                CredentialRead::new(0, &[0]).unwrap()
            } else {
                CredentialRead::empty()
            },
            private_write: ListSet::PRIVATE_LISTS.contains(list).then_some(
                PrivateWriteCheckpoint {
                    ring_program: RING_PROGRAM,
                    sequence: 0,
                },
            ),
            apply: &apply,
        };
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(registry, false),
            ],
            data: [vec![tag::UPDATE], data.encode().unwrap()].concat(),
        }
    }

    fn update(&self, revision: u64) -> Instruction {
        let vector = &self.proofs[format!("update{revision}")];
        let writes = vector["writes"]
            .as_array()
            .unwrap()
            .iter()
            .map(write)
            .collect::<Vec<_>>();
        let apply = ApplyRecordsIxData {
            proof: proof(vector),
            new_root: field(&vector["root"]),
            new_next_index: u32::try_from(vector["nextIndex"].as_u64().unwrap())
                .unwrap()
                .to_le_bytes(),
            restrictive: u8::from(vector["restrictive"].as_bool().unwrap()),
        };
        let data = StorageUpdateIxData {
            revision: revision.into(),
            writes,
            asset_writes: Vec::new(),
            credential_read: CredentialRead::empty(),
            private_write: None,
            apply: &apply,
        };
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new_readonly(self.authority.pubkey(), true),
                AccountMeta::new(self.registry, false),
            ],
            data: [vec![tag::UPDATE], data.encode().unwrap()].concat(),
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

    fn add_cpi_owner(&mut self) -> Address {
        self.svm
            .add_program(
                CPI_OWNER_PROGRAM,
                &std::fs::read(deploy_dir().join("storage_cpi_owner.so")).unwrap(),
            )
            .unwrap();
        Address::find_program_address(&[b"owner"], &CPI_OWNER_PROGRAM).0
    }
}

fn deploy_dir() -> std::path::PathBuf {
    std::env::var_os("SBF_OUT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").into())
}

/// Forwards `instruction` through the CPI owner, the owner signs its PDA.
fn through_cpi_owner(mut instruction: Instruction) -> Instruction {
    instruction.program_id = CPI_OWNER_PROGRAM;
    instruction.accounts[1].is_signer = false;
    instruction
        .accounts
        .push(AccountMeta::new_readonly(PROGRAM, false));
    instruction
}

fn allow_write() -> RecordWriteData {
    RecordWriteData {
        member: [1; 32],
        lists: WriteRecordsIxData {
            mask: 1u64.to_le_bytes(),
            value: 1u64.to_le_bytes(),
        },
        mint_policy: mint_policy_write(None),
    }
}

/// Missing artifact, a private update passes every check and stops where no private apply key exists.
fn private_key_lookup() -> Result<(), TransactionError> {
    refusal(StorageError::UnsupportedBatch)
}

fn refusal(code: impl Into<pinocchio::error::ProgramError>) -> Result<(), TransactionError> {
    let pinocchio::error::ProgramError::Custom(code) = code.into() else {
        panic!("expected a custom error");
    };
    Err(TransactionError::InstructionError(
        0,
        InstructionError::Custom(code),
    ))
}

fn write(entry: &Value) -> RecordWriteData {
    RecordWriteData {
        member: field(&entry["member"]),
        lists: WriteRecordsIxData {
            mask: entry["mask"].as_u64().unwrap().to_le_bytes(),
            value: entry["value"].as_u64().unwrap().to_le_bytes(),
        },
        mint_policy: mint_policy_write(None),
    }
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
        refusal(StorageError::Unauthorized)
    );
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(0, ListId::Reader)),
        refusal(StorageError::Unauthorized)
    );
    let mut update = store.zero_proof_update(0, ListId::Reader);
    update.accounts[0].pubkey = new.pubkey();
    assert_eq!(
        store.send(update, &[&new]),
        refusal(StorageError::ProofVerificationFailed)
    );
}

#[test]
fn unknown_tags_are_refused() {
    let mut store = Store::new();
    store.initialize(GRACE);
    for unknown in [2, 3, 5, 6, 7, 9, 10] {
        let mut instruction = store.zero_proof_update(0, ListId::Block);
        instruction.data[0] = unknown;
        assert_eq!(
            store.send_as_authority(instruction),
            refusal(StorageError::InvalidInstructionData)
        );
    }
}

#[test]
fn an_update_reaches_the_proof_past_its_revision_and_authority() {
    let mut store = Store::new();
    store.initialize(GRACE);
    for list in [ListId::Reader, ListId::Block] {
        assert_eq!(
            store.send_as_authority(store.zero_proof_update(0, list)),
            refusal(StorageError::ProofVerificationFailed)
        );
    }
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(1, ListId::Reader)),
        refusal(StorageError::RevisionChanged)
    );
    let mut wrong_authority = store.zero_proof_update(0, ListId::Reader);
    wrong_authority.accounts[0].pubkey = store.payer.pubkey();
    assert_eq!(
        store.send(wrong_authority, &[]),
        refusal(StorageError::Unauthorized)
    );
}

#[test]
fn a_failed_proof_leaves_the_full_history_unchanged() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut full = store.registry();
    full.roots[ROOT_HISTORY - 1].expires_at = GRACE.to_le_bytes();
    store.seed(store.registry, bytemuck::bytes_of(&full));
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(0, ListId::Reader)),
        refusal(StorageError::ProofVerificationFailed)
    );
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(0, ListId::Block)),
        refusal(StorageError::ProofVerificationFailed)
    );
    store.svm.warp_to_slot(GRACE);
    assert_eq!(
        store.send_as_authority(store.zero_proof_update(0, ListId::Reader)),
        refusal(StorageError::ProofVerificationFailed)
    );
    assert_eq!(store.registry(), full);
}

fn reader(byte: u8) -> [u8; 34] {
    let mut key = [byte; 34];
    key[0] = READER_KEY_ED25519;
    key
}

#[test]
fn an_owner_grants_and_revokes_a_reader_alone() {
    let mut store = Store::new();
    let owner = Keypair::new();
    let granted = reader(7);
    store
        .send(store.grant(&owner.pubkey(), granted, 1), &[&owner])
        .unwrap();
    let (address, _) = OwnerGrant::find_address(&RING_PROGRAM, &owner.pubkey(), &granted);
    let read = |store: &Store| {
        let account = store.svm.get_account(&address).unwrap();
        OwnerGrant::decode(&account.owner, &account.data).unwrap()
    };
    assert!(read(&store).is_active());
    store
        .send(store.grant(&owner.pubkey(), granted, 0), &[&owner])
        .unwrap();
    assert!(!read(&store).is_active());
    store
        .send(store.grant(&owner.pubkey(), granted, 1), &[&owner])
        .unwrap();
    assert!(read(&store).is_active());
}

#[test]
fn a_grant_refuses_a_stranger_and_a_malformed_reader() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let owner = Keypair::new();
    let mut unsigned = store.grant(&owner.pubkey(), reader(7), 1);
    unsigned.accounts[1].is_signer = false;
    assert_eq!(
        store.send(unsigned, &[]),
        refusal(StorageError::MissingSignature)
    );
    let stranger = Keypair::new();
    let mut foreign = store.grant(&stranger.pubkey(), reader(7), 1);
    foreign.accounts[2].pubkey =
        OwnerGrant::find_address(&RING_PROGRAM, &owner.pubkey(), &reader(7)).0;
    assert_eq!(
        store.send(foreign, &[&stranger]),
        refusal(StorageError::InvalidOwnerGrant)
    );
    let mut unknown_scheme = reader(7);
    unknown_scheme[0] = 9;
    assert_eq!(
        store.send(store.grant(&owner.pubkey(), unknown_scheme, 1), &[&owner]),
        refusal(StorageError::InvalidReaderKey)
    );
    assert_eq!(
        store.send(store.grant(&owner.pubkey(), reader(7), 2), &[&owner]),
        refusal(StorageError::InvalidInstructionData)
    );
    let mut policy = store.grant(&owner.pubkey(), reader(7), 1);
    policy.accounts[2].pubkey = store.registry;
    assert_eq!(
        store.send(policy, &[&owner]),
        refusal(StorageError::InvalidOwnerGrant)
    );
}

#[test]
fn a_program_owner_writes_its_grant_through_cpi() {
    let mut store = Store::new();
    let owner = store.add_cpi_owner();
    let instruction = store.grant(&owner, reader(7), 1);
    store.send(through_cpi_owner(instruction), &[]).unwrap();
    let address = OwnerGrant::find_address(&RING_PROGRAM, &owner, &reader(7)).0;
    let account = store.svm.get_account(&address).unwrap();
    assert!(OwnerGrant::decode(&account.owner, &account.data)
        .unwrap()
        .is_active());
}

#[test]
fn a_curator_initializes_without_a_ring() {
    let mut store = Store::new();
    let curator = StorageRegistry::find_address(&store.authority.pubkey(), &CURATOR_ID).0;
    let data = InitializeIxData {
        registry_id: CURATOR_ID,
        grace_slots: GRACE.to_le_bytes(),
        ring_id: [0; 32],
        private_ring_id: [0; 32],
    };
    store
        .send_as_authority(store.initialize_instruction(curator, &data))
        .unwrap();
    assert_eq!(
        store.send_as_authority(store.initialize_instruction(curator, &data)),
        refusal(StorageError::AlreadyInitialized)
    );
}

#[test]
#[ignore = "missing artifact, proofs.json needs the rotated apply keys"]
fn record_writes_apply_with_a_real_proof() {
    let mut store = Store::new();
    store.initialize(GRACE);
    store.send_as_authority(store.update(0)).unwrap();
    store.send_as_authority(store.update(1)).unwrap();
    assert_eq!(store.root(1), Err(StorageError::RootExpired));
    // The approval grant tightens nothing and keeps the block list root served.
    store.send_as_authority(store.update(2)).unwrap();
    assert_eq!(store.root(3), Ok(field(&store.proofs["update2"]["root"])));
    assert_eq!(store.root(2), Ok(field(&store.proofs["update1"]["root"])));
}

#[test]
#[ignore = "missing artifact, proofs.json needs the rotated apply keys"]
fn a_block_list_addition_claimed_permissive_fails_the_real_proof() {
    let mut store = Store::new();
    store.initialize(GRACE);
    store.send_as_authority(store.update(0)).unwrap();
    let mut permissive = store.update(1);
    *permissive.data.last_mut().unwrap() = 0;
    assert_eq!(
        store.send_as_authority(permissive),
        refusal(StorageError::ProofVerificationFailed)
    );
}

#[test]
#[ignore = "missing artifact, proofs.json needs the rotated apply keys"]
fn a_forged_root_fails_the_real_proof() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut forged = store.update(0);
    let root_end = forged.data.len() - 5;
    forged.data[root_end - 1] ^= 1;
    assert_eq!(
        store.send_as_authority(forged),
        refusal(StorageError::ProofVerificationFailed)
    );
    store.send_as_authority(store.update(0)).unwrap();
    assert_eq!(
        store.send_as_authority(store.update(0)),
        refusal(StorageError::RevisionChanged)
    );
}

/// The indexer projects every update through `StorageRegistry::update`.
#[test]
#[ignore = "missing artifact, proofs.json needs the rotated apply keys"]
fn the_program_rotates_roots_as_the_indexer_projects_them() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let mut projected = store.registry();
    for revision in 0..3 {
        let slot = revision + 1;
        store.svm.warp_to_slot(slot);
        let instruction = store.update(revision);
        let data = StorageUpdateIxData::parse(&instruction.data[1..]).unwrap();
        projected
            .update(RootUpdate {
                slot,
                data: &data,
                absence_checkpoint: None,
            })
            .unwrap();
        store.send_as_authority(instruction).unwrap();
        assert_eq!(store.registry(), projected);
    }
}

#[test]
fn a_private_write_requires_the_pinned_ring_program_before_reading_trees() {
    let mut store = Store::new();
    store.initialize(GRACE);
    assert_eq!(
        store.send_as_authority(store.private_update(store.registry)),
        refusal(StorageError::PrivateWriteWithoutRing)
    );
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    let mut instruction = store.private_update(registry);
    let mut data = StorageUpdateIxData::parse(&instruction.data[1..]).unwrap();
    data.private_write.as_mut().unwrap().ring_program = Address::new_from_array([8; 32]);
    instruction.data = [vec![tag::UPDATE], data.encode().unwrap()].concat();
    assert_eq!(
        store.send_as_authority(instruction),
        refusal(StorageError::InvalidPrivateRing)
    );
}

#[test]
fn a_private_write_refuses_missing_or_substituted_credential_accounts() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    let address_tree = store.seed_tree(0);
    let state_tree = store.seed_tree(1);
    let before = store.svm.get_account(&registry).unwrap();
    let mut missing = store.private_update(registry);
    missing.accounts.truncate(2);
    assert_eq!(
        store.send_as_authority(missing),
        refusal(StorageError::MissingAccounts)
    );
    let mut missing_state = store.private_update(registry);
    missing_state.accounts.pop();
    assert_eq!(
        store.send_as_authority(missing_state),
        refusal(StorageError::InvalidCredentialRead)
    );
    let mut wrong_tree = store.private_update(registry);
    wrong_tree.accounts[2].pubkey = state_tree;
    assert_eq!(
        store.send_as_authority(wrong_tree),
        refusal(CustomRingError::InvalidAddressTree)
    );
    let mut queue = store.private_update(registry);
    let queue_address = Address::new_from_array([0x71; 32]);
    store.seed(queue_address, &[0; 64]);
    let mut queued = store.svm.get_account(&queue_address).unwrap();
    queued.owner = SPP;
    store.svm.set_account(queue_address, queued).unwrap();
    queue.accounts[2].pubkey = queue_address;
    assert_eq!(
        store.send_as_authority(queue),
        refusal(CustomRingError::InvalidCredentialRoots)
    );
    let mut account = store.svm.get_account(&address_tree).unwrap();
    account.owner = PROGRAM;
    store.svm.set_account(address_tree, account).unwrap();
    assert_eq!(
        store.send_as_authority(store.private_update(registry)),
        refusal(CustomRingError::InvalidCredentialRoots)
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}

#[test]
fn private_proof_failure_and_stale_revision_keep_the_root_and_floor() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    let address = store.seed_tree(0);
    store.seed_tree(1);
    let mut account = store.svm.get_account(&address).unwrap();
    {
        let mut tree = TreeAccount::from_bytes(&mut account.data, address.to_bytes()).unwrap();
        let history = tree.nullifier_tree();
        history.sequence_number = 9;
        history.root_history.current_index = 2;
        history.root_history.roots[1] = [9; 32];
    }
    store.svm.set_account(address, account).unwrap();
    let before = store.svm.get_account(&registry).unwrap();
    for root_index in [0, 1] {
        let mut instruction = store.private_update(registry);
        let mut data = StorageUpdateIxData::parse(&instruction.data[1..]).unwrap();
        data.credential_read = CredentialRead::new(root_index, &[0]).unwrap();
        data.private_write.as_mut().unwrap().sequence = 8 + u64::from(root_index);
        instruction.data = [vec![tag::UPDATE], data.encode().unwrap()].concat();
        assert_eq!(store.send_as_authority(instruction), private_key_lookup());
        assert_eq!(store.svm.get_account(&registry).unwrap(), before);
    }
    let mut stale = store.private_update(registry);
    let mut data = StorageUpdateIxData::parse(&stale.data[1..]).unwrap();
    data.revision = Revision::from(1);
    stale.data = [vec![tag::UPDATE], data.encode().unwrap()].concat();
    assert_eq!(
        store.send_as_authority(stale),
        refusal(StorageError::RevisionChanged)
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}

#[test]
fn public_writes_refuse_extra_credential_accounts() {
    let mut store = Store::new();
    store.initialize(GRACE);
    let tree = store.seed_tree(0);
    let before = store.registry();
    let mut instruction = store.zero_proof_update(0, ListId::Block);
    instruction
        .accounts
        .push(AccountMeta::new_readonly(tree, false));
    assert_eq!(
        store.send_as_authority(instruction),
        refusal(StorageError::InvalidCredentialRead)
    );
    assert_eq!(store.registry(), before);
}

#[test]
fn owner_grants_are_bound_to_the_ring_namespace() {
    let mut store = Store::new();
    let owner = Keypair::new();
    let reader = reader(7);
    let mut instruction = store.grant(&owner.pubkey(), reader, 1);
    let foreign_program = Address::new_from_array([0x55; 32]);
    let data = OwnerGrantIxData {
        ring_program: foreign_program,
        reader,
        active: 1,
    };
    instruction.data = [&[tag::OWNER_GRANT][..], bytemuck::bytes_of(&data)].concat();
    assert_eq!(
        store.send(instruction, &[&owner]),
        refusal(StorageError::InvalidOwnerGrant)
    );
    store
        .send(store.grant(&owner.pubkey(), reader, 1), &[&owner])
        .unwrap();
    let expected = OwnerGrant::find_address(&RING_PROGRAM, &owner.pubkey(), &reader).0;
    let other = OwnerGrant::find_address(&foreign_program, &owner.pubkey(), &reader).0;
    assert!(store.svm.get_account(&expected).is_some());
    assert!(store.svm.get_account(&other).is_none());
}

#[test]
fn a_private_write_refuses_a_false_checkpoint_sequence_before_the_proof() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    store.seed_tree(0);
    store.seed_tree(1);
    let before = store.svm.get_account(&registry).unwrap();
    for sequence in [1, u64::MAX] {
        let mut instruction = store.private_update(registry);
        let mut data = StorageUpdateIxData::parse(&instruction.data[1..]).unwrap();
        data.private_write.as_mut().unwrap().sequence = sequence;
        instruction.data = [vec![tag::UPDATE], data.encode().unwrap()].concat();
        assert_eq!(
            store.send_as_authority(instruction),
            refusal(StorageError::InvalidCredentialRead)
        );
        assert_eq!(store.svm.get_account(&registry).unwrap(), before);
    }
    assert_eq!(
        store.send_as_authority(store.private_update(registry)),
        private_key_lookup()
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}

/// Skips the checks `StorageUpdateIxData::encode` runs.
fn set_first_write_lists(instruction: &mut Instruction, bits: u64) {
    let write = 1 + 8 + 1;
    let lists = write + core::mem::offset_of!(RecordWriteData, lists);
    for field in [
        core::mem::offset_of!(WriteRecordsIxData, mask),
        core::mem::offset_of!(WriteRecordsIxData, value),
    ] {
        instruction.data[lists + field..lists + field + 8].copy_from_slice(&bits.to_le_bytes());
    }
}

#[test]
fn a_public_update_carrying_a_private_owner_write_is_refused_before_any_key() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    store.seed_tree(0);
    store.seed_tree(1);
    let before = store.svm.get_account(&registry).unwrap();
    for list in [ListId::PrivateBlock, ListId::PrivateAllow] {
        let mut instruction = store.zero_proof_update_of(registry, 0, ListId::Block);
        set_first_write_lists(&mut instruction, list.record_bit());
        assert_eq!(
            store.send_as_authority(instruction),
            refusal(StorageError::InvalidCredentialRead)
        );
    }
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}

#[test]
fn a_private_update_without_its_checkpoint_is_refused_before_any_key() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    store.seed_tree(0);
    store.seed_tree(1);
    let before = store.svm.get_account(&registry).unwrap();
    // 1. The credential read names state roots, the checkpoint bytes are cut.
    let mut cut = store.private_update(registry);
    let apply = cut.data.len() - core::mem::size_of::<ApplyRecordsIxData>();
    cut.data.drain(apply - 40..apply);
    assert_eq!(
        store.send_as_authority(cut),
        refusal(StorageError::InvalidInstructionData)
    );
    // 2. The private write carries neither credential read nor checkpoint.
    let mut bare = store.zero_proof_update_of(registry, 0, ListId::Block);
    set_first_write_lists(&mut bare, ListId::PrivateBlock.record_bit());
    bare.accounts
        .extend(store.private_update(registry).accounts[2..].iter().cloned());
    assert_eq!(
        store.send_as_authority(bare),
        refusal(StorageError::InvalidCredentialRead)
    );
    // 3. A checkpoint on a batch with no private owner write names no key either.
    let mut declared = store.private_update(registry);
    set_first_write_lists(&mut declared, ListId::Block.record_bit());
    assert_eq!(
        store.send_as_authority(declared),
        refusal(StorageError::InvalidCredentialRead)
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}

#[test]
fn each_mode_reaches_its_own_apply_key() {
    let mut store = Store::new();
    let registry = store.initialize_pinned(PRIVATE_ID, RING_ID);
    store.seed_tree(0);
    store.seed_tree(1);
    let before = store.svm.get_account(&registry).unwrap();
    // The public key has a verifying key, the zero proof fails its pairing.
    assert_eq!(
        store.send_as_authority(store.zero_proof_update_of(registry, 0, ListId::Block)),
        refusal(StorageError::ProofVerificationFailed)
    );
    // The same write count with a private owner write looks up the private key instead.
    assert_eq!(
        store.send_as_authority(store.private_update(registry)),
        private_key_lookup()
    );
    assert_eq!(store.svm.get_account(&registry).unwrap(), before);
}
