use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Revision, StorageError},
    storage_instruction::tag as storage_tag,
    CredentialRead, RecordWriteData,
};
use zolana_ring_policy::ListId;

use super::*;
use crate::tests::support::ring;

const AUTHORITY: Address = Address::new_from_array([3; 32]);
const REGISTRY: Address = Address::new_from_array([4; 32]);

fn write_of(list: ListId) -> RecordWriteData {
    let mut write = RecordWriteData::zeroed();
    write.member = [1; 32];
    write.lists.mask = list.record_bit().to_le_bytes();
    write
}

fn update(list: ListId) -> Result<Instruction, RingError> {
    let apply = ApplyRecordsIxData::zeroed();
    UpdateStorage {
        authority: AUTHORITY,
        registry: REGISTRY,
        data: StorageUpdateIxData {
            revision: Revision::from(1),
            writes: vec![write_of(list)],
            asset_writes: Vec::new(),
            credential_read: CredentialRead::empty(),
            private_write: None,
            apply: &apply,
        },
        credential_trees: None,
    }
    .instruction()
}

#[test]
fn a_rings_records_bind_its_own_credentials_at_their_own_address() {
    let storage = InitializeStorage::records(ring(), AUTHORITY);
    assert_eq!(storage.private_ring_id, ring().ring_id().unwrap());
    assert_eq!(
        storage.registry(),
        StorageRegistry::find_address(&AUTHORITY, &RegistryId(ring().program_id().to_bytes())).0
    );
    let data = storage.instruction().data;
    assert_eq!(data[0], storage_tag::INITIALIZE);
    let sent: &InitializeIxData = bytemuck::from_bytes(&data[1..]);
    assert_eq!(sent.private_ring_id, storage.private_ring_id);
}

#[test]
fn a_public_write_names_the_authority_and_registry_alone() {
    let accounts = update(ListId::Block).unwrap().accounts;
    assert_eq!(
        accounts.iter().map(|meta| meta.pubkey).collect::<Vec<_>>(),
        [AUTHORITY, REGISTRY]
    );
}

#[test]
fn a_private_write_without_its_credential_read_is_refused() {
    assert!(matches!(
        update(ListId::PrivateBlock),
        Err(RingError::Storage(StorageError::InvalidCredentialRead))
    ));
}

mod private_write {
    //! A salted owner write against the unit chain, its credential enrolled in the fixture tree and
    //! tree 0 holding its address at `SEQUENCE` when `applied`.

    use async_trait::async_trait;
    use custom_ring_interface::{
        credential::CredentialAuthority, storage::chain_start, CredentialTreeRead, RingMode,
    };
    use solana_account::Account;
    use spr_client::{
        rpc::{
            Context, GetMerkleProofsResponse, GetNonInclusionProofsResponse,
            GetShieldedTransactionsByNullifiersResponse, IndexerRpcConfig, MerkleContext,
            NonInclusionProof, NULLIFIER_TREE_HEIGHT,
        },
        ClientError, HistoryFilters, PaginationToken,
    };
    use spr_hasher::{primitives::BN254_SCALAR_MODULUS_BE, Hasher, Poseidon};
    use spr_interface::pda;
    use spr_program::program::NewAddress;
    use spr_tree::TreeAccount;
    use zolana_ring_member_registry::{MemberRegistryTree, RecordTree};
    use zolana_ring_policy::{ListSet, Member};

    use super::*;
    use crate::tests::support::{
        credential_of, keypair, program, Chain, RingSettings, CREDENTIAL_TREE_ID, SLOT,
    };

    const SEQUENCE: u64 = 40;
    const ADDRESS_INDEX: u64 = 3;
    /// The largest field element, every derived address sorts below it.
    const ADDRESS_NEXT: [u8; 32] = {
        let mut next = BN254_SCALAR_MODULUS_BE;
        next[31] -= 1;
        next
    };

    fn list_salt() -> [u8; 32] {
        let mut salt = [0; 32];
        salt[31] = 0x2a;
        salt
    }

    fn owner() -> Address {
        keypair(1)
            .shielded_address()
            .unwrap()
            .solana_address()
            .unwrap()
    }

    /// The credential address `Enroll` derives for the owner, apart from the code under test.
    fn credential_address() -> [u8; 32] {
        let credential = credential_of(
            &keypair(1).shielded_address().unwrap(),
            domain::list_tag(&list_salt()).unwrap(),
        );
        let authority = CredentialAuthority::derive(&program()).unwrap();
        *NewAddress::derive(authority.owner(), credential.seed().unwrap())
            .unwrap()
            .address()
    }

    /// The unit chain, its Photon answering every gap as tree 0's init gap until `applied`.
    #[derive(Clone)]
    struct Ledger {
        chain: Chain,
        applied: Option<NonInclusionProof>,
    }

    impl Ledger {
        fn new() -> Self {
            let address = keypair(1).shielded_address().unwrap();
            let chain = Chain::ring(RingSettings::new(RingMode::Confidential))
                .with_credential_tag(&[address], domain::list_tag(&list_salt()).unwrap());
            Self {
                chain,
                applied: None,
            }
        }

        /// Tree 0 holds the credential address at history index 1, one apply behind its latest.
        async fn applied() -> Self {
            let ledger = Self::new();
            let tree = pda::tree(0);
            let address = credential_address();
            let path = Poseidon::zero_bytes()[..NULLIFIER_TREE_HEIGHT].to_vec();
            let root = path.iter().enumerate().fold(
                Poseidon::hashv(&[&address, &ADDRESS_NEXT]).unwrap(),
                |node, (level, sibling)| match (ADDRESS_INDEX >> level) & 1 {
                    0 => Poseidon::hashv(&[&node, sibling]).unwrap(),
                    _ => Poseidon::hashv(&[sibling, &node]).unwrap(),
                },
            );
            let mut account = ledger.chain.get_account(tree).await.unwrap().unwrap();
            {
                let mut tree_account =
                    TreeAccount::from_bytes(&mut account.data, tree.to_bytes()).unwrap();
                let history = tree_account.nullifier_tree();
                history.root_history.roots[1] = root;
                history.root_history.roots[2] = [9; 32];
                history.root_history.current_index = 3;
                history.sequence_number = SEQUENCE + 1;
            }
            let mut successor = address;
            for byte in successor.iter_mut().rev() {
                let (sum, carry) = byte.overflowing_add(1);
                *byte = sum;
                if !carry {
                    break;
                }
            }
            Self {
                chain: ledger.chain.with(tree, account),
                applied: Some(NonInclusionProof {
                    leaf: successor,
                    merkle_context: MerkleContext { tree_type: 0, tree },
                    path,
                    low_element: address,
                    low_element_index: ADDRESS_INDEX,
                    high_element: ADDRESS_NEXT,
                    high_element_index: 0,
                    root,
                    root_seq: SEQUENCE,
                    root_index: 1,
                }),
            }
        }
    }

    #[async_trait]
    impl AsyncRpc for Ledger {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            self.chain.get_account(address).await
        }

        async fn get_multiple_accounts(
            &self,
            addresses: Vec<Address>,
        ) -> Result<Vec<Option<Account>>, ClientError> {
            self.chain.get_multiple_accounts(addresses).await
        }

        async fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<[u8; 32]>,
            pagination_token: Option<PaginationToken>,
            limit: Option<u32>,
            filters: HistoryFilters,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            self.chain
                .get_shielded_transactions_by_nullifiers(
                    nullifiers,
                    pagination_token,
                    limit,
                    filters,
                    config,
                )
                .await
        }

        async fn get_merkle_proofs(
            &self,
            tree_account: Address,
            leaves: Vec<[u8; 32]>,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetMerkleProofsResponse, ClientError> {
            self.chain
                .get_merkle_proofs(tree_account, leaves, config)
                .await
        }

        async fn get_non_inclusion_proofs(
            &self,
            tree_account: Address,
            leaves: Vec<[u8; 32]>,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetNonInclusionProofsResponse, ClientError> {
            match &self.applied {
                Some(applied) => Ok(GetNonInclusionProofsResponse {
                    context: Context {
                        block_time: 0,
                        slot: SLOT,
                    },
                    proofs: vec![applied.clone()],
                }),
                None => {
                    self.chain
                        .get_non_inclusion_proofs(tree_account, leaves, config)
                        .await
                }
            }
        }
    }

    /// One PrivateAllow write of the owner's salted key into a ring's fresh records.
    struct Batch {
        inputs: ApplyProofInputs,
        registry: StorageRegistry,
        written_key: [u8; 32],
    }

    impl Batch {
        fn new() -> Self {
            let member = Member::from_bytes(owner_member(&owner()).unwrap()).unwrap();
            let written_key = *Member::salted(&member, &list_salt()).unwrap().as_bytes();
            let mut write = RecordWriteData::zeroed();
            write.member = written_key;
            let mask = ListSet::single(ListId::PrivateAllow).record_bits();
            write.lists.mask = mask.to_le_bytes();
            write.lists.value = mask.to_le_bytes();
            let storage = InitializeStorage::records(ring(), AUTHORITY);
            let registry = StorageRegistry::new(
                AUTHORITY,
                &InitializeIxData {
                    registry_id: storage.registry_id,
                    grace_slots: storage.grace_slots.to_le_bytes(),
                    ring_id: storage.ring_id,
                    private_ring_id: storage.private_ring_id,
                },
            );
            let inputs = MemberRegistryTree::new()
                .unwrap()
                .apply(
                    chain_start(&storage.registry(), Revision::default()).unwrap(),
                    &[write.storage_entry().unwrap()],
                )
                .unwrap()
                .proof;
            Self {
                inputs,
                registry,
                written_key,
            }
        }

        fn write<'a>(&'a self, owners: &'a [SaltedOwnerWrite]) -> PrivateStorageWrite<'a> {
            PrivateStorageWrite {
                ring: ring(),
                inputs: &self.inputs,
                registry: &self.registry,
                asset_writes: &[],
                owners,
            }
        }
    }

    fn salted_owner() -> SaltedOwnerWrite {
        SaltedOwnerWrite {
            write_index: 0,
            owner: owner(),
            list_salt: list_salt(),
        }
    }

    /// The update carrying `plan`'s credential section with `sequence` in its header.
    fn update_of(batch: &Batch, plan: &PrivateWritePlan, sequence: u64) -> Instruction {
        let apply = ApplyRecordsIxData::zeroed();
        let mut write = RecordWriteData::zeroed();
        write.member = batch.written_key;
        let mask = ListSet::single(ListId::PrivateAllow).record_bits();
        write.lists.mask = mask.to_le_bytes();
        write.lists.value = mask.to_le_bytes();
        UpdateStorage {
            authority: AUTHORITY,
            registry: REGISTRY,
            data: StorageUpdateIxData {
                revision: Revision::default(),
                writes: vec![write],
                asset_writes: Vec::new(),
                credential_read: plan.credential_read.clone(),
                private_write: Some(PrivateWriteCheckpoint {
                    sequence,
                    ..plan.private_write
                }),
                apply: &apply,
            },
            credential_trees: Some(plan.credential_trees.clone()),
        }
        .instruction()
        .unwrap()
    }

    /// The sequence Storage reads from tree 0 at the update's address root index.
    async fn storage_sequence(ledger: &Ledger, instruction: &Instruction) -> u64 {
        let data = StorageUpdateIxData::parse(&instruction.data[1..]).unwrap();
        let tree = instruction.accounts[2].pubkey;
        let account = ledger.get_account(tree).await.unwrap().unwrap();
        let mut bytes = account.data;
        CredentialTreeRead {
            address: &tree,
            owner: &account.owner,
            data: &mut bytes,
        }
        .checkpoint(data.credential_read.address_root_index())
        .unwrap()
        .sequence()
    }

    #[tokio::test]
    async fn an_applied_owner_writes_under_the_checkpoint_storage_reads() {
        let (ledger, batch) = (Ledger::applied().await, Batch::new());
        let owners = [salted_owner()];
        let plan = batch.write(&owners).plan(&ledger).await.unwrap();
        assert_eq!(
            plan.private_write,
            PrivateWriteCheckpoint {
                ring_program: program(),
                sequence: SEQUENCE,
            }
        );
        assert_eq!(plan.statement.credential_writes, 1);
        let opened = plan.body.credentials[0].as_ref().unwrap();
        assert_eq!(
            (opened.list_salt, opened.address_index, opened.address_next),
            (list_salt(), ADDRESS_INDEX, ADDRESS_NEXT)
        );
        assert!(plan.body.credentials[1..].iter().all(Option::is_none));
        let instruction = update_of(&batch, &plan, plan.private_write.sequence);
        assert_eq!(
            instruction
                .accounts
                .iter()
                .map(|meta| meta.pubkey)
                .collect::<Vec<_>>(),
            [
                AUTHORITY,
                REGISTRY,
                pda::tree(0),
                pda::tree(CREDENTIAL_TREE_ID)
            ]
        );
        assert_eq!(storage_sequence(&ledger, &instruction).await, SEQUENCE);
    }

    /// The prover at `ZOLANA_PROVER_URL` proves the plan, `prove_apply` checks it against the pinned key.
    #[cfg(feature = "proofs")]
    #[tokio::test]
    async fn a_real_proof_opens_the_credential_and_address_under_the_checkpoint() {
        let (ledger, batch) = (Ledger::applied().await, Batch::new());
        let owners = [salted_owner()];
        let plan = batch.write(&owners).plan(&ledger).await.unwrap();
        let client = ledger.chain.clone().client();
        let apply = prove_apply(&client, plan.circuit, &plan.statement, &plan.body)
            .await
            .unwrap();
        assert_eq!(apply.new_root, plan.statement.new_root);
    }

    #[tokio::test]
    async fn a_lower_header_sequence_is_not_the_checkpoint_storage_reads() {
        let (ledger, batch) = (Ledger::applied().await, Batch::new());
        let owners = [salted_owner()];
        let plan = batch.write(&owners).plan(&ledger).await.unwrap();
        let lowered = update_of(&batch, &plan, SEQUENCE - 1);
        let sent = StorageUpdateIxData::parse(&lowered.data[1..]).unwrap();
        assert_ne!(
            sent.private_write.unwrap().sequence,
            storage_sequence(&ledger, &lowered).await
        );
    }

    #[tokio::test]
    async fn a_queued_owner_is_refused_before_any_proof() {
        let (ledger, batch) = (Ledger::new(), Batch::new());
        let owners = [salted_owner()];
        let refused = batch.write(&owners).plan(&ledger).await;
        assert!(matches!(
            refused,
            Err(RingError::Credential(error))
                if matches!(*error, CredentialError::AddressQueued { address } if address == credential_address())
        ));
    }

    #[tokio::test]
    async fn a_salt_that_does_not_hash_to_the_written_key_is_refused() {
        let (ledger, batch) = (Ledger::applied().await, Batch::new());
        let mut salted = salted_owner();
        salted.list_salt[31] ^= 1;
        let refused = batch.write(&[salted]).plan(&ledger).await;
        assert!(matches!(
            refused,
            Err(RingError::Credential(error))
                if matches!(*error, CredentialError::ListKeyMismatch { write_index: 0 })
        ));
    }

    #[tokio::test]
    async fn a_private_write_naming_no_owner_is_refused() {
        let (ledger, batch) = (Ledger::applied().await, Batch::new());
        let refused = batch.write(&[]).plan(&ledger).await;
        assert!(matches!(
            refused,
            Err(RingError::Credential(error))
                if matches!(*error, CredentialError::CredentialWritesMismatch)
        ));
    }
}
