use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Mutex,
};

use async_trait::async_trait;
use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::{Revision, StorageRegistry},
    storage_instruction::tag,
    ApplyRecordsIxData, RING_POLICY, STORAGE_PROGRAM_ID,
};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use spr_indexer_api::{Context, Hash};
use zolana_ring_indexer::{
    rpc::{
        GetStorageApplyProofInputsRequest, GetStorageApplyProofInputsResponse,
        GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
    },
    tracking::GetPendingEnrollmentsResponse,
};
use zolana_ring_member_registry::ApplyProofInputs;

use super::*;
use crate::{
    landing::{ChainOutcome, ChainSubmit, LatestBlockhash, Simulation},
    upstream::RingConfiguration,
};

const RING: Address = Address::new_from_array([1; 32]);
const REGISTRY: Address = Address::new_from_array([2; 32]);
const SLOT: u64 = 1_000;

#[derive(Default)]
struct StubChain {
    slot: AtomicU64,
    accounts: Mutex<HashMap<Address, Account>>,
    proofs: AtomicUsize,
    named: Mutex<Vec<Vec<Address>>>,
    sent: Mutex<Vec<VersionedTransaction>>,
    outcome: Mutex<Option<ChainOutcome>>,
    during_proof: Mutex<Option<DuringProof>>,
}

type DuringProof = Box<dyn Fn(&StubChain) + Send + Sync>;

fn owner(byte: u8) -> Address {
    Address::new_from_array([byte; 32])
}

fn stored(owner: Address, data: &[u8]) -> Account {
    Account {
        lamports: 1,
        data: data.to_vec(),
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

impl StubChain {
    fn new() -> Arc<Self> {
        let chain = Self::default();
        chain.slot.store(SLOT, Ordering::Relaxed);
        let mut policy = RingPolicy::zeroed();
        policy.discriminator = RING_POLICY;
        policy.tracking = REGISTRY;
        chain.accounts.lock().unwrap().insert(
            CustomRing::new(RING).policy_pda(),
            stored(RING, bytemuck::bytes_of(&policy)),
        );
        chain.tracking(|_| {});
        Arc::new(chain)
    }

    fn tracking(&self, write: impl FnOnce(&mut TrackingRegistry)) {
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts.entry(REGISTRY).or_insert_with(|| {
            let mut registry = TrackingRegistry::zeroed();
            registry.discriminator = TrackingRegistry::DISCRIMINATOR;
            registry.next_index = 1u64.to_le_bytes();
            stored(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&registry))
        });
        write(bytemuck::from_bytes_mut(&mut account.data));
    }

    /// `applied` of `revision`, zero marks a first enrollment.
    fn enroll(&self, owner: Address, revision: u64, applied: u64) {
        let mut authorization = TrackingAuthorization::zeroed();
        authorization.discriminator = TrackingAuthorization::DISCRIMINATOR;
        authorization.registry = REGISTRY;
        authorization.owner = owner;
        authorization.revision = revision.to_le_bytes();
        authorization.applied_revision = applied.to_le_bytes();
        self.accounts.lock().unwrap().insert(
            TrackingAuthorization::find_address(&REGISTRY, &owner).0,
            stored(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&authorization)),
        );
    }

    fn revision_of(&self, owner: Address) -> Option<TrackingAuthorization> {
        let accounts = self.accounts.lock().unwrap();
        accounts
            .get(&TrackingAuthorization::find_address(&REGISTRY, &owner).0)
            .and_then(|account| TrackingAuthorization::decode(&account.owner, &account.data))
    }

    fn named(&self) -> Vec<Vec<Address>> {
        self.named.lock().unwrap().clone()
    }

    fn landed(&self, outcome: ChainOutcome) {
        *self.outcome.lock().unwrap() = Some(outcome);
    }
}

#[async_trait]
impl ChainSubmit for StubChain {
    async fn account_data(
        &self,
        _address: solana_address::Address,
    ) -> Result<Option<Vec<u8>>, RingRpcError> {
        Ok(None)
    }

    async fn rent_exempt_lamports(&self, _data_len: usize) -> Result<u64, RingRpcError> {
        Ok(0)
    }

    async fn slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.slot.load(Ordering::Relaxed))
    }

    async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
        Ok(LatestBlockhash {
            blockhash: solana_hash::Hash::new_from_array([7; 32]),
            last_valid_block_height: u64::MAX,
        })
    }

    async fn block_height(&self) -> Result<u64, RingRpcError> {
        Ok(0)
    }

    async fn send(&self, transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
        self.sent.lock().unwrap().push(transaction.clone());
        Ok(())
    }

    async fn outcome(&self, _signature: Signature) -> Result<Option<ChainOutcome>, RingRpcError> {
        Ok(self.outcome.lock().unwrap().take())
    }

    async fn simulate(&self, _message: &VersionedMessage) -> Result<Simulation, RingRpcError> {
        unreachable!("an applier sends without a simulation")
    }
}

#[async_trait]
impl StorageChain for StubChain {
    async fn account(&self, address: Address) -> Result<Option<Account>, RingRpcError> {
        Ok(self.accounts.lock().unwrap().get(&address).cloned())
    }

    async fn ring_config(&self, _ring: Address) -> Result<Option<RingConfiguration>, RingRpcError> {
        unreachable!("an applier reads no ring role")
    }

    async fn member_openings(
        &self,
        _request: GetStorageMemberOpeningsRequest,
    ) -> Result<GetStorageMemberOpeningsResponse, RingRpcError> {
        unreachable!("an applier reads no policy leaf")
    }

    async fn apply_inputs(
        &self,
        _request: GetStorageApplyProofInputsRequest,
    ) -> Result<GetStorageApplyProofInputsResponse, RingRpcError> {
        unreachable!("an applier writes no policy leaf")
    }

    async fn prove_apply(
        &self,
        _inputs: &ApplyProofInputs,
        _registry: &StorageRegistry,
    ) -> Result<ApplyRecordsIxData, RingRpcError> {
        unreachable!("an applier writes no policy leaf")
    }

    async fn pending_enrollments(
        &self,
        request: GetPendingEnrollmentsRequest,
    ) -> Result<GetPendingEnrollmentsResponse, RingRpcError> {
        let accounts = self.accounts.lock().unwrap();
        let mut pending: Vec<_> = accounts
            .values()
            .filter_map(|account| TrackingAuthorization::decode(&account.owner, &account.data))
            .filter(|authorization| {
                authorization.is_pending()
                    && request
                        .after
                        .is_none_or(|after| after.0.to_bytes() < authorization.owner.to_bytes())
            })
            .collect();
        pending.sort_by_key(|authorization| authorization.owner.to_bytes());
        pending.truncate(request.limit as usize);
        let hash = |bytes| Hash(bytes);
        Ok(GetPendingEnrollmentsResponse {
            context: Context::default(),
            next_after: pending
                .last()
                .filter(|_| pending.len() as u64 == request.limit)
                .map(|authorization| authorization.owner.into()),
            enrollments: pending
                .iter()
                .map(|authorization| RingPendingEnrollmentView {
                    owner: authorization.owner.into(),
                    member: hash([0; 32]),
                    nullifier_pk: hash(authorization.nullifier_pk),
                    ct_hash: hash([0; 32]),
                    viewing_u: hash(authorization.viewing_u),
                    revision: authorization.revision(),
                    applied_revision: authorization.applied_revision(),
                    list_tag: hash(authorization.list_tag),
                })
                .collect(),
        })
    }

    async fn prove_enrollments(
        &self,
        registry: Address,
        owners: &[Address],
    ) -> Result<ProvedEnrollments, RingRpcError> {
        self.proofs.fetch_add(1, Ordering::Relaxed);
        self.named.lock().unwrap().push(owners.to_vec());
        let revision = self
            .accounts
            .lock()
            .unwrap()
            .get(&registry)
            .and_then(|account| TrackingRegistry::decode(&account.owner, &account.data))
            .expect("registry")
            .newest()
            .revision;
        let revisions = owners
            .iter()
            .map(|owner| self.revision_of(*owner).expect("enrolled").revision())
            .collect();
        if let Some(act) = self.during_proof.lock().unwrap().take() {
            act(self);
        }
        Ok(ProvedEnrollments {
            instruction: Instruction {
                program_id: STORAGE_PROGRAM_ID,
                accounts: vec![AccountMeta::new(registry, false)],
                data: vec![tag::APPLY_ENROLLMENTS],
            },
            revision,
            revisions,
        })
    }
}

fn applier(chain: &Arc<StubChain>) -> EnrollmentApplier {
    EnrollmentApplierParts {
        chain: chain.clone(),
        payer: Keypair::new_from_array([9; 32]),
        rings: vec![RING],
    }
    .applier()
}

/// Settles the sent apply as failed, its accounts stay pending for the next pass.
fn refused(chain: &StubChain) {
    chain.landed(ChainOutcome::Failed {
        reason: String::new(),
    });
}

#[tokio::test]
async fn an_apply_names_pending_accounts_under_the_payer_alone_and_waits_for_its_landing() {
    let chain = StubChain::new();
    chain.enroll(owner(4), 1, 0);
    chain.enroll(owner(3), 2, 1);
    chain.enroll(owner(5), 1, 1);
    let mut applier = applier(&chain);

    applier.flush().await;
    assert_eq!(chain.named(), [vec![owner(3), owner(4)]]);
    let sent = chain.sent.lock().unwrap().clone();
    let [transaction] = sent.as_slice() else {
        panic!("one apply, {sent:?}");
    };
    assert_eq!(transaction.signatures.len(), 1);
    assert_eq!(
        transaction.message.static_account_keys()[0],
        applier.payer()
    );

    applier.flush().await;
    assert_eq!(chain.proofs.load(Ordering::Relaxed), 1);

    refused(&chain);
    applier.flush().await;
    assert_eq!(chain.proofs.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn an_account_that_moves_while_pending_sits_out_one_rotation_period() {
    let chain = StubChain::new();
    chain.enroll(owner(3), 1, 0);
    chain.enroll(owner(4), 1, 0);
    let mut applier = applier(&chain);
    applier.flush().await;

    refused(&chain);
    chain.enroll(owner(3), 2, 0);
    applier.flush().await;
    assert_eq!(chain.named().last().unwrap(), &[owner(4)]);

    refused(&chain);
    chain
        .slot
        .store(SLOT + TRACKING_GRACE_SLOTS, Ordering::Relaxed);
    applier.flush().await;
    assert_eq!(chain.named().last().unwrap(), &[owner(3), owner(4)]);
}

#[tokio::test]
async fn a_held_page_leaves_the_batch_to_the_next_page() {
    let chain = StubChain::new();
    (1..=APPLY_BATCH as u8 + 1).for_each(|byte| chain.enroll(owner(byte), 1, 0));
    let mut applier = applier(&chain);
    applier.flush().await;
    assert_eq!(chain.named()[0].len(), APPLY_BATCH);

    refused(&chain);
    chain.enroll(owner(1), 2, 0);
    applier.flush().await;
    let named = chain.named();
    let batch = named.last().unwrap();
    assert_eq!(batch.len(), APPLY_BATCH);
    assert!(!batch.contains(&owner(1)));
    assert!(batch.contains(&owner(APPLY_BATCH as u8 + 1)));
}

#[tokio::test]
async fn a_rotation_during_the_proof_sends_nothing_and_holds_the_account() {
    let chain = StubChain::new();
    chain.enroll(owner(3), 1, 0);
    chain.enroll(owner(4), 1, 0);
    *chain.during_proof.lock().unwrap() =
        Some(Box::new(|chain: &StubChain| chain.enroll(owner(3), 2, 0)));
    let mut applier = applier(&chain);

    applier.flush().await;
    assert!(chain.sent.lock().unwrap().is_empty());

    applier.flush().await;
    assert_eq!(chain.named().last().unwrap(), &[owner(4)]);
    assert_eq!(chain.sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_root_another_applier_moved_during_the_proof_sends_nothing() {
    let chain = StubChain::new();
    chain.enroll(owner(3), 1, 0);
    *chain.during_proof.lock().unwrap() = Some(Box::new(|chain: &StubChain| {
        chain.tracking(|registry| registry.roots[0].revision = Revision::from(1))
    }));
    let mut applier = applier(&chain);

    applier.flush().await;
    assert!(chain.sent.lock().unwrap().is_empty());

    applier.flush().await;
    assert_eq!(chain.sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_full_tree_leaves_out_a_first_enrollment_and_applies_a_rotation() {
    let chain = StubChain::new();
    chain.tracking(|registry| registry.next_index = TRACKING_CAPACITY.to_le_bytes());
    chain.enroll(owner(3), 1, 0);
    chain.enroll(owner(4), 2, 1);
    applier(&chain).flush().await;
    assert_eq!(chain.named(), [vec![owner(4)]]);
}

#[tokio::test]
async fn a_full_history_waits_without_a_proof() {
    let chain = StubChain::new();
    chain.enroll(owner(3), 1, 0);
    chain.tracking(|registry| {
        registry.roots[ROOT_HISTORY - 1].expires_at = (SLOT + 1).to_le_bytes()
    });
    let mut applier = applier(&chain);
    applier.flush().await;
    assert_eq!(chain.proofs.load(Ordering::Relaxed), 0);

    chain.slot.store(SLOT + 1, Ordering::Relaxed);
    applier.flush().await;
    assert_eq!(chain.proofs.load(Ordering::Relaxed), 1);
}
