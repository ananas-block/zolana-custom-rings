//! The chain and indexer every unit test reads, accounts from one map and the queries recorded.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use borsh::BorshSerialize;
use bytemuck::{Pod, Zeroable};
use custom_ring_interface::{
    credential::CredentialAuthority,
    storage::{RegistryId, Revision, StorageRegistry},
    storage_instruction::InitializeIxData,
    AuditCredential, CoSignScope, CoSigner, CoSignerCounts, NewRing, PolicyUpdate, RingMode,
    RingPolicy, RingRoles, SourceSlot, CO_SIGNER, N_SOURCE_SLOTS, RING_POLICY_PDA_SEED,
    STORAGE_PROGRAM_ID,
};
use solana_account::Account;
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    rpc::{
        GetNonInclusionProofsResponse, GetShieldedTransactionsByNullifiersResponse,
        NonInclusionProof, OutputContext, OutputSlot, PaginationToken, ShieldedTransaction,
        TransactionEvents, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
    },
    AsyncProverClient, AsyncRpc, AsyncWitnessReader, AsyncZolanaClient, ClientError, Context,
    GetMerkleProofsResponse, HistoryFilters, IndexerRpcConfig, InputWitnesses, MerkleContext,
    MerkleProof, ProofDataSource,
};
use spr_event::OutputDataEncoding;
use spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;
use spr_hasher::{Hasher, Poseidon};
use spr_indexer_api::{Base64String, Hash, SerializablePubkey};
use spr_interface::{
    state::{
        default_tree_fees,
        discriminator::{RING_CONFIG, TREE_ACCOUNT_DISCRIMINATOR},
        nullifier_tree_params, RingConfig,
    },
    RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID,
};
use spr_keypair::ShieldedAddress;
use spr_keypair::{random_blinding, NullifierKey, ShieldedKeypair, SigningKey, X25519Keypair};
use spr_program::program::{NewAddress, ACCOUNT_BLINDING_SEED};
use spr_transaction::{
    utxo::{
        derive_output_blinding_seed, derive_transact_output_blinding, ProofInputUtxo,
        SppProofInputUtxo,
    },
    Data, Mint, Utxo, WalletUtxo, SOL_MINT,
};
use spr_tree::{
    nullifier_tree::constants::NULLIFIER_TREE_INIT_ROOT_40, TreeAccount, UTXO_TREE_HEIGHT,
};
use spr_user_registry_interface::{
    user_record_pda, user_registry_program_id, MergeEncryptionScheme, UserRecord,
};
use zolana_ring_client::{AsyncRingIndexer, RingIndexerError, ViewingHistory};
use zolana_ring_indexer::rpc::{
    GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse, GetStorageRecordPoolRequest,
    GetStorageRecordPoolResponse, RingIndexedMemberRecordView, RingMemberOpening,
    RingMemberRecordView, RingRecordPathView, StorageRootView,
};
use zolana_ring_member_registry::{
    Canopy, MemberRecord, MemberRegistryTree, RecordOpening, RecordTree,
};
use zolana_ring_policy::RuleTable;

use crate::client::RingClient;
use crate::{trees::PoolTree, CustomRing, REDACTED};

pub(crate) const SLOT: u64 = 2_359_301;
/// The ring's own `StorageRegistry`, its newest root at `REVISION`.
pub(crate) const RECORDS: Address = Address::new_from_array([0x5a; 32]);
pub(crate) const REVISION: u64 = 1;
/// Every `keypair(seed)` below it holds a credential under its own nullifier key.
const ENROLLED_SEEDS: u8 = 64;
/// The note tree and tree 0, the address tree every credential address lands in.
pub(crate) const TREE_ID: u16 = 0;
/// The state tree every fixture credential sits in.
pub(crate) const CREDENTIAL_TREE_ID: u16 = 5;
const ENROLLMENT_SLOT: u64 = 9;

pub(crate) fn program() -> Address {
    Address::new_from_array([42; 32])
}

pub(crate) fn ring() -> CustomRing {
    CustomRing::new(program())
}

pub(crate) fn payer() -> Address {
    Address::new_from_array([7; 32])
}

pub(crate) fn authority() -> Address {
    Address::new_from_array([8; 32])
}

pub(crate) fn auditor() -> X25519Keypair {
    X25519Keypair::from_bytes(&[5; 32])
}

pub(crate) fn keypair(seed: u8) -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32])).unwrap()
}

pub(crate) fn history(owner: &ShieldedKeypair) -> ViewingHistory {
    ViewingHistory::new(owner.viewing_pubkey(), 0)
}

pub(crate) fn wallet(utxo: Utxo, key: &NullifierKey, tree_id: u16, leaf_index: u64) -> WalletUtxo {
    let nullifier_pubkey = key.pubkey().unwrap();
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0; 32], &[0; 32], tree_id)
        .unwrap();
    WalletUtxo {
        nullifier: key.nullifier(&utxo_hash, &utxo.blinding).unwrap(),
        utxo,
        nullifier_pubkey,
        utxo_hash,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Default::default(),
        slot_index: 0,
    }
}

pub(crate) fn ring_utxo(
    owner: &ShieldedKeypair,
    asset: Mint,
    amount: u64,
    leaf: u64,
) -> WalletUtxo {
    wallet(
        Utxo {
            owner: owner.signing_pubkey(),
            asset,
            amount,
            blinding: random_blinding(),
            ring_program_id: Some(program()),
            data: Data::default(),
        },
        &owner.nullifier_key,
        TREE_ID,
        leaf,
    )
}

pub(crate) fn redacts(printed: &str, fields: &[&str]) -> bool {
    fields
        .iter()
        .all(|field| printed.contains(&format!("{field}: {REDACTED:?}")))
}

pub(crate) fn account<T: Pod>(owner: Address, value: &T) -> Account {
    Account {
        lamports: 1,
        data: bytemuck::bytes_of(value).to_vec(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

pub(crate) fn empty(owner: Address) -> Account {
    Account {
        lamports: 1,
        data: Vec::new(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

struct LeafTree(BTreeMap<u64, [u8; 32]>);

impl LeafTree {
    fn new<'a>(leaves: impl IntoIterator<Item = (&'a [u8; 32], &'a u64)>) -> Self {
        Self(
            leaves
                .into_iter()
                .map(|(leaf, index)| (*index, *leaf))
                .collect(),
        )
    }

    fn node(&self, level: usize, position: u64) -> [u8; 32] {
        let first = position << level;
        if self.0.range(first..first + (1 << level)).next().is_none() {
            return Poseidon::zero_bytes()[level];
        }
        if level == 0 {
            return self.0[&position];
        }
        let child = |offset| self.node(level - 1, 2 * position + offset);
        Poseidon::hashv(&[&child(0), &child(1)]).unwrap()
    }
}

fn tree_account(tree: PoolTree) -> Account {
    let mut data = vec![0u8; TreeAccount::account_size()];
    let params = nullifier_tree_params();
    TreeAccount::init(
        &mut data,
        TREE_ACCOUNT_DISCRIMINATOR,
        UTXO_TREE_HEIGHT as u8,
        tree.address.to_bytes(),
        tree.id,
        params,
        default_tree_fees(params.input_queue_zkp_batch_size).unwrap(),
    )
    .unwrap();
    Account {
        lamports: 1,
        data,
        owner: Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        executable: false,
        rent_epoch: 0,
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RingSettings {
    pub mode: RingMode,
    pub has_policy: bool,
    pub co_signer: Option<(Address, CoSignScope)>,
    pub delegate: Option<Address>,
    pub created_slot: u64,
}

impl RingSettings {
    pub(crate) const fn new(mode: RingMode) -> Self {
        Self {
            mode,
            has_policy: false,
            co_signer: None,
            delegate: None,
            created_slot: 0,
        }
    }

    /// A policy ring's hash is a stand-in until `with_registry` pins its table.
    pub(crate) fn config(&self) -> Box<RingPolicy> {
        let mut config = NewRing {
            bump: Address::find_program_address(&[RING_POLICY_PDA_SEED], &program()).1,
            mode: self.mode,
            roles: RingRoles {
                admin: authority(),
                policy: Address::new_from_array([0xa2; 32]),
                pauser: Address::new_from_array([0xa3; 32]),
                cosign_admin: Address::new_from_array([0xa4; 32]),
            },
            auditor_pubkey: *auditor().pubkey().as_bytes(),
            created_slot: self.created_slot,
            records: Address::default(),
        }
        .account();
        if self.has_policy {
            config.policy_hash = [0x11; 32];
        }
        if let Some((_, scope)) = self.co_signer {
            config.co_signers = CoSignerCounts::default().added(scope).expect("one record");
        }
        if let Some(delegate) = self.delegate {
            config.delegate = delegate;
        }
        config
    }
}

fn policy_update(sources: [SourceSlot; N_SOURCE_SLOTS], rules: &RuleTable) -> PolicyUpdate {
    PolicyUpdate {
        sources,
        rules: rules.encode(),
        slot: SLOT,
    }
}

/// Clones share the query log.
#[derive(Clone, Default)]
pub(crate) struct Chain {
    accounts: HashMap<Address, Account>,
    /// Leaf indexes a Merkle proof request may name, every one settled in the tree's account.
    leaves: HashMap<[u8; 32], u64>,
    /// Leaves the indexer serves that the tree's account lacks.
    unsettled: HashMap<[u8; 32], u64>,
    registry: Option<Arc<Registry>>,
    /// A second registry address the same tree answers for.
    curator: Option<Address>,
    /// The leaves of every Merkle proof request.
    pub proof_requests: Arc<Mutex<Vec<Vec<[u8; 32]>>>>,
    pub witness_requests: Arc<Mutex<Vec<Vec<[u8; 32]>>>>,
    /// The ring of every record opening or pool request.
    pub record_requests: Arc<Mutex<Vec<SerializablePubkey>>>,
    credentials: Option<Arc<CredentialFixture>>,
}

impl Chain {
    pub(crate) fn ring(settings: RingSettings) -> Self {
        let registration = RingConfig {
            discriminator: RING_CONFIG,
            authority: authority(),
            program_id: program(),
            ring_authority_transact_is_enabled: 1,
            paused: 0,
            activated: 1,
            bump: Address::find_program_address(&[RING_AUTH_PDA_SEED], &program()).1,
        };
        let chain = Self::default().with_credential_fixture(CredentialFixture::enrolled());
        let chain = match settings.co_signer {
            Some((signer, scope)) => chain.with(
                ring().co_signer_pda(&signer),
                account(
                    program(),
                    &CoSigner {
                        discriminator: CO_SIGNER,
                        signer,
                        scope: scope.bits(),
                        bump: Address::find_program_address(
                            &[CoSigner::SEED, signer.as_ref()],
                            &program(),
                        )
                        .1,
                    },
                ),
            ),
            None => chain,
        };
        chain
            .with(ring().policy_pda(), account(program(), &*settings.config()))
            .with(
                ring().ring_auth_pda(),
                account(
                    Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
                    &registration,
                ),
            )
            .with_tree(TREE_ID)
    }

    pub(crate) fn with(mut self, address: Address, account: Account) -> Self {
        self.accounts.insert(address, account);
        self
    }

    pub(crate) fn with_tree(self, id: u16) -> Self {
        let tree = PoolTree {
            address: spr_interface::pda::tree(id),
            id,
        };
        self.with(tree.address, tree_account(tree))
    }

    /// The ring account pinning `rules`, every list read from the ring's records.
    pub(crate) fn with_registry(self, registry: Registry, rules: &RuleTable) -> Self {
        let policy = registry.policy(self.ring_account(), rules);
        self.with_records(registry)
            .with(ring().policy_pda(), policy)
    }

    /// `rules` read the Block list from a curator registry the same tree answers for.
    pub(crate) fn with_curator(self, curator: Address, rules: &RuleTable) -> Self {
        use zolana_ring_policy::ListId;
        let mut ring_account = self.ring_account();
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        for list in rules.referenced().iter() {
            sources[list.slot()].list_id = list as u8;
        }
        sources[ListId::Block.slot()].registry = curator;
        ring_account
            .set_policy(policy_update(sources, rules))
            .unwrap();
        let records = self
            .registry
            .as_ref()
            .expect("the records precede the curator")
            .records();
        Self {
            curator: Some(curator),
            ..self
        }
        .with(ring().policy_pda(), account(program(), &*ring_account))
        .with(curator, records)
    }

    /// The ring's records registry alone, the ring stays audit-only.
    pub(crate) fn with_records(self, registry: Registry) -> Self {
        let mut ring_account = self.ring_account();
        ring_account.records = RECORDS;
        let records = registry.records();
        Self {
            registry: Some(Arc::new(registry)),
            ..self
        }
        .with(ring().policy_pda(), account(program(), &*ring_account))
        .with(RECORDS, records)
    }

    fn ring_account(&self) -> Box<RingPolicy> {
        self.accounts
            .get(&ring().policy_pda())
            .map(|account| Box::new(*bytemuck::from_bytes::<RingPolicy>(&account.data)))
            .expect("Chain::ring writes the ring account")
    }

    /// `addresses` alone hold credentials, a test of the output predicate names its keys.
    pub(crate) fn with_credentials(self, addresses: &[ShieldedAddress]) -> Self {
        self.with_credential_tag(addresses, FIXTURE_LIST_TAG)
    }

    /// One tag in every credential, a test of a salt names the tag it hashes to.
    pub(crate) fn with_credential_tag(
        self,
        addresses: &[ShieldedAddress],
        list_tag: [u8; 32],
    ) -> Self {
        let credentials: Vec<_> = addresses
            .iter()
            .map(|address| credential_of(address, list_tag))
            .collect();
        self.with_credential_fixture(Arc::new(CredentialFixture::of(&credentials)))
    }

    /// Exactly these credentials, each enrolled once in the fixture's state tree.
    pub(crate) fn with_enrolled(self, credentials: &[AuditCredential]) -> Self {
        self.with_credential_fixture(Arc::new(CredentialFixture::of(credentials)))
    }

    /// `address`'s user record naming `address`'s keys.
    pub(crate) fn with_user_record(self, address: &ShieldedAddress) -> Self {
        let owner = address.solana_address().unwrap();
        let (record_address, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner,
            bump,
            nullifier_pubkey: address.nullifier_pubkey,
            viewing_pubkey: *address.viewing_pubkey.as_bytes(),
            merge_encryption: MergeEncryptionScheme::Disabled,
        };
        let mut data = vec![UserRecord::DISCRIMINATOR];
        record.serialize(&mut data).unwrap();
        self.with(
            record_address,
            Account {
                lamports: 1,
                data,
                owner: user_registry_program_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
    }

    fn with_credential_fixture(self, fixture: Arc<CredentialFixture>) -> Self {
        let tree = fixture.tree.clone();
        Self {
            credentials: Some(fixture),
            ..self
        }
        .with(spr_interface::pda::tree(CREDENTIAL_TREE_ID), tree)
    }

    /// The indexed route, the prover fetches the input proofs and no witness is read here.
    pub(crate) fn client(self) -> RingClient<Chain, Chain> {
        self.client_on(ProofDataSource::Prover)
    }

    /// The client route, an assembly reads its input witnesses here.
    pub(crate) fn witness_client(self) -> RingClient<Chain, Chain> {
        self.client_on(ProofDataSource::Client)
    }

    fn client_on(self, source: ProofDataSource) -> RingClient<Chain, Chain> {
        let prover = || AsyncProverClient::local().with_proof_data_source(source);
        RingClient::new(
            AsyncZolanaClient::new(self.clone(), self, prover()),
            prover(),
        )
    }
}

const CONTEXT: Context = Context {
    block_time: 0,
    slot: SLOT,
};

#[async_trait]
impl AsyncRpc for Chain {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        Ok(self.accounts.get(&address).cloned())
    }

    async fn get_multiple_accounts(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Account>>, ClientError> {
        Ok(addresses
            .iter()
            .map(|address| self.accounts.get(address).cloned())
            .collect())
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        Ok(SLOT)
    }

    async fn get_shielded_transactions_by_nullifiers(
        &self,
        nullifiers: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        _filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
        let fixture = self.credential_fixture()?;
        Ok(GetShieldedTransactionsByNullifiersResponse {
            context: CONTEXT,
            output_tree_id: None,
            data: nullifiers
                .iter()
                .filter_map(|address| fixture.enrollments.get(address))
                .map(|enrollment| TransactionEvents {
                    slot: enrollment.slot,
                    signature: enrollment.tx_signature,
                    events: vec![enrollment.clone()],
                })
                .collect(),
            pagination_token: None,
        })
    }

    /// Tree 0 holds only its init leaf, every address falls in its one gap.
    async fn get_non_inclusion_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetNonInclusionProofsResponse, ClientError> {
        let mut high_element = BN254_SCALAR_MODULUS_BE;
        high_element[31] -= 1;
        Ok(GetNonInclusionProofsResponse {
            context: CONTEXT,
            proofs: leaves
                .into_iter()
                .map(|leaf| NonInclusionProof {
                    leaf,
                    merkle_context: MerkleContext {
                        tree_type: 0,
                        tree: tree_account,
                    },
                    path: Poseidon::zero_bytes()[..NULLIFIER_TREE_HEIGHT].to_vec(),
                    low_element: [0; 32],
                    low_element_index: 0,
                    high_element,
                    high_element_index: 0,
                    root: NULLIFIER_TREE_INIT_ROOT_40,
                    root_seq: 0,
                    root_index: 0,
                })
                .collect(),
        })
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        if tree_account == spr_interface::pda::tree(CREDENTIAL_TREE_ID) {
            return self.credential_fixture()?.proofs(tree_account, &leaves);
        }
        self.proof_requests.lock().unwrap().push(leaves.clone());
        let mut data = self.accounts[&tree_account].data.clone();
        let mut tree = TreeAccount::from_bytes(&mut data, tree_account.to_bytes()).unwrap();
        let root_index = tree.utxo_tree().current_root_index();
        let served = LeafTree::new(self.leaves.iter().chain(&self.unsettled));
        let proofs = leaves
            .iter()
            .map(|leaf| {
                let leaf_index = self
                    .leaves
                    .get(leaf)
                    .or_else(|| self.unsettled.get(leaf))
                    .copied()
                    .unwrap_or_default();
                MerkleProof {
                    leaf: *leaf,
                    merkle_context: MerkleContext {
                        tree_type: 0,
                        tree: tree_account,
                    },
                    path: (0..STATE_TREE_HEIGHT)
                        .map(|level| served.node(level, (leaf_index >> level) ^ 1))
                        .collect(),
                    leaf_index,
                    root: served.node(STATE_TREE_HEIGHT, 0),
                    root_seq: SLOT,
                    root_index,
                }
            })
            .collect();
        Ok(GetMerkleProofsResponse {
            context: CONTEXT,
            proofs,
        })
    }
}

#[async_trait]
impl AsyncRingIndexer for Chain {
    async fn get_storage_member_openings(
        &self,
        request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
        self.record_requests.lock().unwrap().push(request.registry);
        let registry = self
            .registry
            .as_ref()
            .filter(|_| request.registry == RECORDS.into())
            .ok_or(ClientError::UnsupportedRpcMethod(
                "get_storage_member_openings",
            ))?;
        Ok(GetStorageMemberOpeningsResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: SLOT,
            },
            root: registry.root_view(),
            openings: request
                .members
                .iter()
                .map(|member| registry.opening(&member.0))
                .collect(),
        })
    }

    async fn get_storage_record_pool(
        &self,
        request: GetStorageRecordPoolRequest,
    ) -> Result<GetStorageRecordPoolResponse, RingIndexerError> {
        self.record_requests.lock().unwrap().push(request.registry);
        let registry = self
            .registry
            .as_ref()
            .filter(|_| {
                request.registry == RECORDS.into()
                    || self.curator.map(Into::into) == Some(request.registry)
            })
            .ok_or(ClientError::UnsupportedRpcMethod("get_storage_record_pool"))?;
        let members: Vec<[u8; 32]> = request.members.iter().map(|member| member.0).collect();
        let pool = registry
            .tree
            .record_pool(
                &members,
                Canopy::covering(request.openings as usize).unwrap(),
            )
            .unwrap();
        Ok(GetStorageRecordPoolResponse {
            context: spr_indexer_api::Context {
                block_time: 0,
                slot: SLOT,
            },
            root: registry.root_view(),
            records: pool
                .records
                .iter()
                .zip(&pool.proof.paths)
                .map(|(record, path)| RingIndexedMemberRecordView {
                    record: registry.view(record),
                    path: RingRecordPathView {
                        index: path.index,
                        siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
                    },
                })
                .collect(),
            canopy: pool.proof.canopy.into_iter().map(Hash).collect(),
            subjects: pool
                .subjects
                .iter()
                .map(|subject| subject.record_index)
                .collect(),
        })
    }
}

impl Chain {
    fn credential_fixture(&self) -> Result<&CredentialFixture, ClientError> {
        self.credentials
            .as_deref()
            .ok_or(ClientError::UnsupportedRpcMethod(
                "get_shielded_transactions_by_nullifiers",
            ))
    }
}

/// The tag a fixture credential holds when a test names no salt.
pub(crate) const FIXTURE_LIST_TAG: [u8; 32] = [0x06; 32];

/// `address`'s credential in the test ring, sealed to nothing a test opens.
pub(crate) fn credential_of(address: &ShieldedAddress, list_tag: [u8; 32]) -> AuditCredential {
    AuditCredential {
        ring_id: ring().ring_id().unwrap(),
        member: address.signing_pubkey.owner_proof_input_hash().unwrap(),
        nullifier_pk: address.nullifier_pubkey,
        list_tag,
        auditor_pubkey: *auditor().pubkey().as_bytes(),
        eph_u: [0x05; 32],
        ciphertext: [0x07; 64],
    }
}

/// Each credential's `Enroll` output, appended in order to one state tree, the leaves built here
/// apart from the SDK code that reads them.
struct CredentialFixture {
    /// By credential address.
    enrollments: HashMap<[u8; 32], ShieldedTransaction>,
    /// Each leaf's index and path, computed once.
    paths: HashMap<[u8; 32], (u64, Vec<[u8; 32]>)>,
    root: [u8; 32],
    tree: Account,
}

impl CredentialFixture {
    fn enrolled() -> Arc<Self> {
        static FIXTURE: std::sync::OnceLock<Arc<CredentialFixture>> = std::sync::OnceLock::new();
        Arc::clone(FIXTURE.get_or_init(|| {
            let credentials: Vec<_> = (0..ENROLLED_SEEDS)
                .map(|seed| {
                    credential_of(&keypair(seed).shielded_address().unwrap(), FIXTURE_LIST_TAG)
                })
                .collect();
            Arc::new(Self::of(&credentials))
        }))
    }

    fn of(credentials: &[AuditCredential]) -> Self {
        let authority = CredentialAuthority::derive(&program()).unwrap();
        let tree_address = spr_interface::pda::tree(CREDENTIAL_TREE_ID);
        let mut tree = tree_account(PoolTree {
            address: tree_address,
            id: CREDENTIAL_TREE_ID,
        });
        let mut enrollments = HashMap::new();
        let mut leaves = Vec::new();
        for (leaf_index, credential) in (0..).zip(credentials) {
            let address = *NewAddress::derive(authority.owner(), credential.seed().unwrap())
                .unwrap()
                .address();
            let seed = derive_output_blinding_seed(&address, &ACCOUNT_BLINDING_SEED).unwrap();
            let blinding = derive_transact_output_blinding(&address, &seed, 0).unwrap();
            let leaf = ProofInputUtxo::new(
                *authority.owner().owner_hash(),
                &SOL_MINT,
                0,
                &blinding,
                CREDENTIAL_TREE_ID,
            )
            .unwrap()
            .with_data_hash(credential.data_hash(&address).unwrap())
            .hash()
            .unwrap();
            TreeAccount::from_bytes(&mut tree.data, tree_address.to_bytes())
                .unwrap()
                .utxo_tree()
                .append(leaf, ENROLLMENT_SLOT)
                .unwrap();
            let mut state = address.to_vec();
            credential.serialize(&mut state).unwrap();
            enrollments.insert(
                address,
                ShieldedTransaction {
                    slot: ENROLLMENT_SLOT,
                    tx_signature: Signature::from([1; 64]),
                    event_index: Some(0),
                    tx_viewing_pk: None,
                    salt: None,
                    output_slots: vec![OutputSlot {
                        view_tag: [0; 32],
                        output_context: OutputContext {
                            hash: leaf,
                            tree_id: CREDENTIAL_TREE_ID,
                            leaf_index,
                        },
                        payload: borsh::to_vec(&OutputDataEncoding::Plaintext(state)).unwrap(),
                    }],
                    messages: Vec::new(),
                    nullifiers: vec![address],
                    proofless: false,
                    ring_config: None,
                    ring_program_id: None,
                },
            );
            leaves.push(leaf);
        }
        // One pass per level, the unwritten right side of each level is the zero subtree.
        let zero = Poseidon::zero_bytes();
        let mut levels = Vec::with_capacity(STATE_TREE_HEIGHT);
        let mut level = leaves.clone();
        for zero_subtree in &zero[..STATE_TREE_HEIGHT] {
            let parents = level
                .chunks(2)
                .map(|pair| {
                    Poseidon::hashv(&[&pair[0], pair.get(1).unwrap_or(zero_subtree)]).unwrap()
                })
                .collect();
            levels.push(core::mem::replace(&mut level, parents));
        }
        let root = level.first().copied().unwrap_or(zero[STATE_TREE_HEIGHT]);
        let paths = (0..)
            .zip(&leaves)
            .map(|(index, leaf)| {
                let path = (0..STATE_TREE_HEIGHT)
                    .map(|height| {
                        levels[height]
                            .get(((index >> height) ^ 1) as usize)
                            .copied()
                            .unwrap_or(zero[height])
                    })
                    .collect();
                (*leaf, (index, path))
            })
            .collect();
        Self {
            enrollments,
            paths,
            root,
            tree,
        }
    }

    fn proofs(
        &self,
        tree_account: Address,
        leaves: &[[u8; 32]],
    ) -> Result<GetMerkleProofsResponse, ClientError> {
        let mut data = self.tree.data.clone();
        let mut tree = TreeAccount::from_bytes(&mut data, tree_account.to_bytes()).unwrap();
        let root_index = tree.utxo_tree().current_root_index();
        let proofs = leaves
            .iter()
            .map(|leaf| {
                let (leaf_index, path) = self.paths[leaf].clone();
                MerkleProof {
                    leaf: *leaf,
                    merkle_context: MerkleContext {
                        tree_type: 0,
                        tree: tree_account,
                    },
                    path,
                    leaf_index,
                    root: self.root,
                    root_seq: SLOT,
                    root_index,
                }
            })
            .collect();
        Ok(GetMerkleProofsResponse {
            context: CONTEXT,
            proofs,
        })
    }
}

/// `note` under the zero key, its commitment and nullifier follow.
pub(crate) fn zero_key(mut note: WalletUtxo) -> WalletUtxo {
    let key = NullifierKey::from_secret([0; 31]);
    note.nullifier_pubkey = spr_interface::ZERO_NULLIFIER_PUBKEY;
    note.utxo_hash = note
        .utxo
        .hash(&note.nullifier_pubkey, &[0; 32], &[0; 32], note.tree_id)
        .unwrap();
    note.nullifier = key.nullifier(&note.utxo_hash, &note.utxo.blinding).unwrap();
    note
}

/// No test proves on the client route.
impl AsyncWitnessReader for Chain {
    fn input_witnesses(
        &self,
        inputs: &[&SppProofInputUtxo],
        _dummy_nullifiers: &[[u8; 32]],
        _config: Option<IndexerRpcConfig>,
    ) -> impl std::future::Future<Output = Result<InputWitnesses, ClientError>> + Send {
        self.witness_requests
            .lock()
            .unwrap()
            .push(inputs.iter().map(|input| input.utxo_hash).collect());
        std::future::ready(Err(ClientError::NoInputs))
    }
}

pub(crate) struct Registry {
    tree: MemberRegistryTree,
}

impl Registry {
    /// Each owner with `lists` set, ordered as the linked records require.
    pub(crate) fn new(owners: &[(&ShieldedKeypair, u64)]) -> Self {
        let mut members: Vec<([u8; 32], u64)> = owners
            .iter()
            .map(|(owner, lists)| {
                let address = owner.shielded_address().unwrap();
                (
                    address.signing_pubkey.owner_proof_input_hash().unwrap(),
                    *lists,
                )
            })
            .collect();
        members.sort_by_key(|(member, _)| *member);
        let mut records = vec![MemberRecord {
            next: members
                .first()
                .map_or(MemberRecord::SENTINEL.next, |(member, _)| *member),
            ..MemberRecord::SENTINEL
        }];
        for (position, (member, lists)) in members.iter().enumerate() {
            records.push(MemberRecord {
                mint_policy: Default::default(),
                member: *member,
                next: members
                    .get(position + 1)
                    .map_or(MemberRecord::SENTINEL.next, |(next, _)| *next),
                lists: *lists,
            });
        }
        Self {
            tree: MemberRegistryTree::from_records(records).unwrap(),
        }
    }

    pub(crate) fn with_mint(self, mint: Address, policy: zolana_ring_policy::MintPolicy) -> Self {
        let tree = self
            .tree
            .apply(
                [0; 32],
                &[custom_ring_interface::RecordWrite {
                    member: *zolana_ring_policy::Member::asset(&mint).unwrap().as_bytes(),
                    mask: 0,
                    value: 0,
                    mint_policy: Some(policy),
                }],
            )
            .unwrap()
            .tree;
        Self { tree }
    }

    pub(crate) fn root(&self) -> [u8; 32] {
        self.tree.root().unwrap()
    }

    /// The `RECORDS` registry at `REVISION`.
    fn records(&self) -> Account {
        let mut records = StorageRegistry::new(
            authority(),
            &InitializeIxData {
                registry_id: RegistryId([0; 32]),
                grace_slots: 0u64.to_le_bytes(),
                ring_id: ring().ring_id().unwrap(),
                private_ring_id: [0; 32],
            },
        );
        records.roots[0].hash = self.root();
        records.roots[0].revision = Revision::from(REVISION);
        account(STORAGE_PROGRAM_ID, &records)
    }

    /// `rules` over the records.
    fn policy(&self, mut policy: Box<RingPolicy>, rules: &RuleTable) -> Account {
        policy.records = RECORDS;
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        for list in rules.referenced().iter() {
            sources[list.slot()].list_id = list as u8;
        }
        policy.set_policy(policy_update(sources, rules)).unwrap();
        account(program(), &*policy)
    }

    fn root_view(&self) -> StorageRootView {
        StorageRootView {
            root: Hash(self.root()),
            revision: REVISION,
            next_index: self.tree.records().len() as u64,
        }
    }

    fn opening(&self, member: &[u8; 32]) -> RingMemberOpening {
        let opening = self.tree.opening(member).unwrap();
        let (present, record, path) = match opening {
            RecordOpening::Present { record, path } => (true, record, path),
            RecordOpening::Absent { low, path } => (false, low, path),
        };
        RingMemberOpening {
            present,
            record: self.view(&record),
            path: RingRecordPathView {
                index: path.index,
                siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
            },
        }
    }

    fn view(&self, record: &MemberRecord) -> RingMemberRecordView {
        RingMemberRecordView {
            member: Hash(record.member),
            next: Hash(record.next),
            lists: record.lists,
            mint_policy: record.mint_policy,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MessageCase {
    pub name: String,
    pub message: Base64String,
    /// A `MessageMismatch` variant, or `Accepted`.
    pub verdict: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct MessageVector<R> {
    pub description: String,
    pub request: R,
    pub cases: Vec<MessageCase>,
}

pub(crate) fn verdict(checked: Result<crate::VerifiedMessage, crate::MessageMismatch>) -> String {
    checked.map_or_else(
        |mismatch| format!("{mismatch:?}"),
        |_| "Accepted".to_owned(),
    )
}

/// Compiled as Ring RPC compiles its relay messages.
pub(crate) fn relay_message(
    fee_payer: &Address,
    instructions: &[solana_instruction::Instruction],
    units: u32,
) -> Base64String {
    spr_client::compile_message(
        fee_payer,
        instructions,
        solana_message::Hash::new_from_array([0x7b; 32]),
        spr_client::ComputeBudgetConfig::new(units),
    )
    .unwrap()
    .serialize()
    .into()
}

/// `UPDATE_RELAY_MESSAGES=1` rewrites the file from `fresh`, the committed file is the one read.
pub(crate) fn pinned_vector<V>(name: &str, fresh: V) -> V
where
    V: serde::Serialize + serde::de::DeserializeOwned,
{
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/rpc")
        .join(name);
    if std::env::var_os("UPDATE_RELAY_MESSAGES").is_some() {
        let json = serde_json::to_string_pretty(&fresh).unwrap();
        std::fs::write(&path, json + "\n").unwrap();
    }
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
