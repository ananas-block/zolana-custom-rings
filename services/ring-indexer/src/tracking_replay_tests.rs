use bytemuck::Zeroable;
use custom_ring_interface::{
    storage_instruction::{tag, EnrollIxData, EnrollRequest, InitializeTrackingIxData},
    tracking::{TrackingAuthorization, TrackingRegistry, TRACKING_GRACE_SLOTS},
    CustomRingProof, STORAGE_PROGRAM_ID, VIEWING_PUBKEY_TAG,
};
use sea_orm::TransactionTrait;
use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::Hash;
use zolana_ring_indexer::tracking::GetPendingEnrollmentsRequest;

use super::{account, block, replay_indexer, rpc, Chain};
use crate::{
    api,
    block::{BlockInfo, BlockMetadata, Instruction, InstructionGroup, TransactionInfo},
    indexer::Indexer,
    storage::{self, Enrollment, RingCursor, TrackingState, TrackingStore},
    tests::{database, field},
};

const OWNER: Address = Address::new_from_array([51; 32]);
const NEWEST_SLOT: u64 = 5_000;

struct Ledger {
    indexer: Indexer,
    cursor: RingCursor,
    chain: std::sync::Arc<std::sync::Mutex<Chain>>,
    handle: jsonrpsee::server::ServerHandle,
    registry: Address,
    authorization: Address,
}

fn ix_data(viewing: u8) -> EnrollIxData {
    EnrollIxData {
        nullifier_pk: field(1),
        list_tag: field(2),
        viewing_u: field(viewing),
        eph_u: field(4),
        ciphertext: [5; 32],
    }
}

fn instruction(accounts: Vec<Address>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: STORAGE_PROGRAM_ID,
        data,
        accounts,
        stack_height: Some(1),
    }
}

impl Ledger {
    async fn new() -> Self {
        let creator = Address::new_from_array([50; 32]);
        let ring_id = field(9);
        let (registry, _) = TrackingRegistry::find_address(&creator, &ring_id);
        let (authorization, _) = TrackingAuthorization::find_address(&registry, &OWNER);
        let mut auditor_pubkey = [9; 33];
        auditor_pubkey[0] = VIEWING_PUBKEY_TAG;
        let data = InitializeTrackingIxData {
            ring_id,
            auditor_pubkey,
        };
        let chain = std::sync::Arc::new(std::sync::Mutex::new(Chain {
            blocks: [(NEWEST_SLOT, block(NEWEST_SLOT, vec![]))].into(),
            ..Default::default()
        }));
        let (rpc, handle) = rpc(chain.clone()).await;
        let mut ledger = Self {
            indexer: replay_indexer(std::sync::Arc::new(database().await), rpc),
            cursor: RingCursor::new(0),
            chain,
            handle,
            registry,
            authorization,
        };
        let initialize = instruction(
            vec![creator, creator, registry],
            [&[tag::INITIALIZE_TRACKING][..], bytemuck::bytes_of(&data)].concat(),
        );
        ledger.land(1, initialize).await.unwrap();
        ledger
    }

    /// The account as the chain holds it now, whatever slot the replay reached.
    fn hold_account(&self, viewing: u8, revision: u64) {
        let account_image = TrackingAuthorization {
            discriminator: TrackingAuthorization::DISCRIMINATOR,
            bump: 1,
            registry: self.registry,
            owner: OWNER,
            nullifier_pk: field(1),
            list_tag: field(2),
            viewing_u: field(viewing),
            eph_u: field(4),
            ciphertext: [5; 32],
            revision: revision.to_le_bytes(),
            applied_revision: [0; 8],
            last_enroll_slot: [0; 8],
        };
        self.chain.lock().unwrap().accounts.insert(
            self.authorization.to_string(),
            account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&account_image)),
        );
    }

    fn enroll(&self, viewing: u8, proof: Option<&CustomRingProof>) -> Instruction {
        let ix = ix_data(viewing);
        let request = EnrollRequest { ix: &ix, proof };
        instruction(
            vec![OWNER, OWNER, self.registry, self.authorization],
            [&[tag::ENROLL][..], &request.encode()].concat(),
        )
    }

    async fn land(&mut self, slot: u64, instruction: Instruction) -> anyhow::Result<()> {
        let block = BlockInfo {
            metadata: BlockMetadata {
                slot,
                blockhash: Hash(field(slot as u8)),
                ..Default::default()
            },
            transactions: vec![TransactionInfo {
                signature: Signature::from([1; 64]),
                error: None,
                instruction_groups: vec![InstructionGroup {
                    outer_instruction: instruction,
                    inner_instructions: vec![],
                }],
            }],
        };
        let tx = self.indexer.db.begin().await?;
        self.indexer
            .apply_block(&tx, &block, &mut self.cursor)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    fn store(&self) -> TrackingStore<'_, sea_orm::DatabaseConnection> {
        TrackingStore::new(self.indexer.db.as_ref(), self.registry.to_bytes())
    }

    async fn state(&self) -> TrackingState {
        self.store().state().await.unwrap().unwrap()
    }

    async fn enrollment(&self) -> Option<Enrollment> {
        self.store().enrollment(&OWNER.to_bytes()).await.unwrap()
    }

    async fn stop(self) {
        self.handle.stop().unwrap();
        self.handle.stopped().await;
    }
}

#[tokio::test]
async fn a_replayed_enrollment_takes_final_fields_from_the_account_and_its_key_from_the_block() {
    let mut ledger = Ledger::new().await;
    // The chain moved on, a replay of the first enrollment still reads revision 1 from the block.
    ledger.hold_account(7, 2);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    let held = ledger.enrollment().await.unwrap();
    assert_eq!(held.revision, 1);
    assert_eq!(held.viewing_u, field(3));
    assert_eq!(
        (
            held.nullifier_pk,
            held.list_tag,
            held.eph_u,
            held.ciphertext
        ),
        (field(1), field(2), field(4), [5; 32])
    );
    assert_eq!(held.authorization, ledger.authorization.to_bytes());
    assert_eq!(ledger.state().await.account.reserved_leaves(), 2);
    ledger.stop().await;
}

#[tokio::test]
async fn a_rotation_moves_only_the_view_key_and_the_revision_in_block_order() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3, 1);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    let first = ledger.enrollment().await.unwrap();
    let slot = 2 + TRACKING_GRACE_SLOTS;
    ledger.land(slot, ledger.enroll(6, None)).await.unwrap();
    assert_eq!(
        ledger.enrollment().await.unwrap(),
        Enrollment {
            viewing_u: field(6),
            revision: 2,
            last_enroll_slot: slot,
            ..first
        }
    );
    assert_eq!(ledger.state().await.account.reserved_leaves(), 2);
    assert!(ledger.state().await.fault.is_none());
    ledger.stop().await;
}

#[tokio::test]
async fn a_rotation_inside_the_rate_limit_stops_the_projection() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3, 1);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    let first = ledger.enrollment().await.unwrap();
    let slot = 1 + TRACKING_GRACE_SLOTS;
    ledger.land(slot, ledger.enroll(6, None)).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("rate limit"), "{fault}");
    assert_eq!(ledger.enrollment().await, Some(first));
    ledger.stop().await;
}

#[tokio::test]
async fn a_first_enrollment_without_a_proof_stops_the_projection() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3, 1);
    ledger.land(2, ledger.enroll(3, None)).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("no proof"), "{fault}");
    assert_eq!(ledger.enrollment().await, None);
    ledger.stop().await;
}

#[tokio::test]
async fn an_unreadable_authorization_retries_and_quarantines_nothing() {
    let mut ledger = Ledger::new().await;
    let proof = CustomRingProof::zeroed();
    let error = ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("no tracking authorization"),
        "{error:#}"
    );
    assert!(ledger.state().await.fault.is_none());
    assert_eq!(ledger.enrollment().await, None);
    ledger.stop().await;
}

#[tokio::test]
async fn an_authorization_of_another_owner_stops_the_projection() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3, 1);
    let foreign = Address::new_from_array([52; 32]);
    let proof = CustomRingProof::zeroed();
    let ix = ix_data(3);
    let request = EnrollRequest {
        ix: &ix,
        proof: Some(&proof),
    };
    let enroll = instruction(
        vec![foreign, foreign, ledger.registry, ledger.authorization],
        [&[tag::ENROLL][..], &request.encode()].concat(),
    );
    ledger.land(2, enroll).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("another owner"), "{fault}");
    ledger.stop().await;
}

#[tokio::test]
async fn a_rolled_back_enrollment_leaves_no_row_and_restores_the_reservation() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3, 1);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    let tx = ledger.indexer.db.begin().await.unwrap();
    storage::rollback(&tx, &mut ledger.cursor).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(ledger.enrollment().await, None);
    assert_eq!(ledger.state().await.account.reserved_leaves(), 1);
    let tx = ledger.indexer.db.begin().await.unwrap();
    storage::rollback(&tx, &mut ledger.cursor).await.unwrap();
    tx.commit().await.unwrap();
    assert!(ledger.store().state().await.unwrap().is_none());
    ledger.stop().await;
}

#[tokio::test]
async fn pending_enrollments_serve_the_newest_revision_at_a_confirmed_tip() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3, 1);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    let image = {
        let state = ledger.state().await;
        account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&*state.account))
    };
    {
        let mut chain = ledger.chain.lock().unwrap();
        chain.blocks.insert(2, block(2, vec![]));
        chain.accounts.insert(ledger.registry.to_string(), image);
    }
    ledger
        .cursor
        .resume(ledger.indexer.db.as_ref())
        .await
        .unwrap();
    let request = GetPendingEnrollmentsRequest {
        registry: ledger.registry.into(),
        after: None,
        limit: 1,
    };
    let read = |request| {
        api::pending_enrollments(
            ledger.indexer.db.as_ref(),
            ledger.indexer.rpc.as_ref(),
            request,
        )
    };
    let page = read(request.clone()).await.unwrap();
    let [row] = page.enrollments.as_slice() else {
        panic!("one owner is pending, {:?}", page.enrollments);
    };
    assert_eq!((row.revision, row.applied_revision), (1, 0));
    assert_eq!(row.viewing_u, Hash(field(3)));
    assert_eq!(page.next_after, Some(OWNER.into()));
    let past = GetPendingEnrollmentsRequest {
        after: page.next_after,
        ..request.clone()
    };
    assert!(read(past).await.unwrap().enrollments.is_empty());
    let unbounded = GetPendingEnrollmentsRequest {
        limit: 0,
        ..request
    };
    assert!(matches!(
        read(unbounded).await,
        Err(crate::error::RingApiError::InvalidRequest(_))
    ));
    ledger.stop().await;
}
