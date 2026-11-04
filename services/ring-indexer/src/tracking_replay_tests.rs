use bytemuck::Zeroable;
use custom_ring_interface::{
    storage::Revision,
    storage_instruction::{
        tag, ApplyEnrollmentsIxData, EnrollIxData, EnrollRequest, InitializeTrackingIxData,
    },
    tracking::{
        tracking_chain_start, TrackingAuthorization, TrackingEntry, TrackingRegistry,
        TRACKING_EMPTY_ROOT,
    },
    CustomRingProof, STORAGE_PROGRAM_ID, VIEWING_PUBKEY_TAG,
};
use sea_orm::TransactionTrait;
use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::Hash;
use zolana_ring_indexer::{
    rpc::RingRecordPathView,
    tracking::{
        GetPendingEnrollmentsRequest, GetTrackingApplyProofInputsRequest,
        GetTrackingOpeningsRequest, GetTrackingRecordPoolRequest, GetTrackingRecordsRequest,
        RingTrackingRecordView,
    },
    tree::{OpeningCheck, QuadPathOf, RecordOpening, RecordTree, TrackingRecord},
};
use zolana_ring_member_registry::TrackingTree;

use super::{account, apply_data, block, replay_indexer, rpc, Chain};
use crate::{
    api,
    block::{BlockInfo, BlockMetadata, Instruction, InstructionGroup, TransactionInfo},
    indexer::{Indexer, RegistryCall},
    storage::{self, Enrollment, RingCursor, TrackingState, TrackingStore},
    tests::{database, field},
    tracking_registry::TrackingCall,
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
        ciphertext: [5; 64],
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
            registry: self.registry,
            owner: OWNER,
            nullifier_pk: field(1),
            list_tag: field(2),
            viewing_u: field(viewing),
            eph_u: field(4),
            ciphertext: [5; 64],
            revision: revision.to_le_bytes(),
            applied_revision: [0; 8],
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
        self.land_all(slot, vec![instruction]).await
    }

    async fn land_all(&mut self, slot: u64, instructions: Vec<Instruction>) -> anyhow::Result<()> {
        let transactions = instructions
            .into_iter()
            .map(|instruction| settled(instruction, vec![]))
            .collect();
        self.land_transactions(slot, transactions).await
    }

    async fn land_transactions(
        &mut self,
        slot: u64,
        transactions: Vec<TransactionInfo>,
    ) -> anyhow::Result<()> {
        let block = BlockInfo {
            metadata: BlockMetadata {
                slot,
                blockhash: Hash(field(slot as u8)),
                ..Default::default()
            },
            transactions,
        };
        let tx = self.indexer.db.begin().await?;
        self.indexer
            .apply_block(&tx, &block, &mut self.cursor)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The tracking entry of the account at `viewing` and `revision`.
    fn entry(&self, viewing: u8, revision: u64) -> TrackingEntry {
        TrackingAuthorization {
            discriminator: TrackingAuthorization::DISCRIMINATOR,
            registry: self.registry,
            owner: OWNER,
            nullifier_pk: field(1),
            list_tag: field(2),
            viewing_u: field(viewing),
            eph_u: field(4),
            ciphertext: [5; 64],
            revision: revision.to_le_bytes(),
            applied_revision: [0; 8],
        }
        .entry()
        .unwrap()
    }

    /// The apply an honest applier proves at the projected revision.
    async fn apply(&self, tree: &mut TrackingTree, entries: &[TrackingEntry]) -> Instruction {
        let revision: Revision = self.state().await.account.newest().revision;
        let chain_start = tracking_chain_start(&self.registry, revision).unwrap();
        let inputs = tree.apply(chain_start, entries).unwrap();
        let data = ApplyEnrollmentsIxData {
            revision,
            apply: apply_data(inputs.new_root, inputs.new_next_index),
        };
        instruction(
            vec![self.registry, self.authorization],
            [&[tag::APPLY_ENROLLMENTS][..], bytemuck::bytes_of(&data)].concat(),
        )
    }

    /// The chain confirms the projection at `slot`.
    async fn serve(&mut self, slot: u64) {
        let state = self.state().await;
        {
            let mut chain = self.chain.lock().unwrap();
            chain.blocks.insert(slot, block(slot, vec![]));
            chain.accounts.insert(
                self.registry.to_string(),
                account(STORAGE_PROGRAM_ID, bytemuck::bytes_of(&*state.account)),
            );
        }
        self.cursor.resume(self.indexer.db.as_ref()).await.unwrap();
    }

    fn member(&self) -> [u8; 32] {
        self.entry(3, 1).member
    }

    fn store(&self) -> TrackingStore<'_, sea_orm::DatabaseConnection> {
        TrackingStore::new(self.indexer.db.as_ref(), self.registry.to_bytes())
    }

    async fn state(&self) -> TrackingState {
        self.store().state().await.unwrap().unwrap()
    }

    async fn enrollment(&self) -> Option<Enrollment> {
        self.enrollment_of(OWNER).await
    }

    async fn enrollment_of(&self, owner: Address) -> Option<Enrollment> {
        self.store().enrollment(&owner.to_bytes()).await.unwrap()
    }

    async fn stop(self) {
        self.handle.stop().unwrap();
        self.handle.stopped().await;
    }
}

#[tokio::test]
async fn a_replayed_enrollment_takes_final_fields_from_the_account_and_its_key_from_the_block() {
    let mut ledger = Ledger::new().await;
    // A replay of the first enrollment reads revision 1 from the block.
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
        (field(1), field(2), field(4), [5; 64])
    );
    assert_eq!(held.authorization, ledger.authorization.to_bytes());
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
    let slot = 3;
    ledger.land(slot, ledger.enroll(6, None)).await.unwrap();
    assert_eq!(
        ledger.enrollment().await.unwrap(),
        Enrollment {
            viewing_u: field(6),
            revision: 2,
            ..first
        }
    );
    assert!(ledger.state().await.fault.is_none());
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
async fn a_rolled_back_enrollment_leaves_no_row() {
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
    ledger.serve(2).await;
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

fn settled(
    outer_instruction: Instruction,
    inner_instructions: Vec<Instruction>,
) -> TransactionInfo {
    TransactionInfo {
        signature: Signature::from([1; 64]),
        error: None,
        instruction_groups: vec![InstructionGroup {
            outer_instruction,
            inner_instructions,
        }],
    }
}

fn wire_record(view: &RingTrackingRecordView) -> TrackingRecord {
    TrackingRecord {
        member: view.member.0,
        next: view.next.0,
        nullifier_pk: view.nullifier_pk.0,
        ct_hash: view.ct_hash.0,
        viewing_u: view.viewing_u.0,
        revision: view.revision,
        list_tag: view.list_tag.0,
    }
}

fn wire_path(path: &RingRecordPathView) -> QuadPathOf<13> {
    QuadPathOf {
        index: path.index,
        siblings: core::array::from_fn(|level| {
            path.siblings[level].clone().map(|sibling| sibling.0)
        }),
    }
}

/// An enrollment landed at slot 2, nothing applied.
async fn enrolled() -> Ledger {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3, 1);
    let proof = CustomRingProof::zeroed();
    ledger
        .land(2, ledger.enroll(3, Some(&proof)))
        .await
        .unwrap();
    ledger
}

#[tokio::test]
async fn an_applied_enrollment_opens_under_the_program_root_with_its_seal() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry(3, 1)]).await;
    ledger.land(3, apply).await.unwrap();
    let state = ledger.state().await;
    assert_eq!(state.fault, None);
    let root = tree.root().unwrap();
    assert_eq!(state.account.newest().hash, root);
    assert_eq!(state.account.next_index(), 2);
    assert_eq!(state.account.roots[1].hash, TRACKING_EMPTY_ROOT);
    ledger.serve(3).await;
    let member = ledger.member();
    let (db, rpc) = (ledger.indexer.db.as_ref(), ledger.indexer.rpc.as_ref());
    let registry = ledger.registry.into();
    let absent = field(77);
    let opened = api::tracking_openings(
        db,
        rpc,
        GetTrackingOpeningsRequest {
            registry,
            members: vec![Hash(member), Hash(absent)],
            expected_root: Hash(root),
        },
    )
    .await
    .unwrap();
    let [present, missing] = opened.openings.as_slice() else {
        panic!("two members open twice");
    };
    assert!(present.present && !missing.present);
    let verified = OpeningCheck {
        opening: &RecordOpening::Present {
            record: wire_record(&present.record),
            path: wire_path(&present.path),
        },
        root: &root,
        member: &member,
    }
    .verify()
    .unwrap();
    assert_eq!(verified.map(|record| record.revision), Some(1));
    let no_row = OpeningCheck {
        opening: &RecordOpening::Absent {
            low: wire_record(&missing.record),
            path: wire_path(&missing.path),
        },
        root: &root,
        member: &absent,
    }
    .verify()
    .unwrap();
    assert_eq!(no_row, None);
    let seal = present.record.seal.as_ref().unwrap();
    assert_eq!(seal.owner, OWNER.into());
    assert_eq!(seal.ciphertext.0, [5; 64]);
    assert_eq!(seal.eph_pk.0[1..], field(4));
    let page = api::tracking_records(
        db,
        rpc,
        GetTrackingRecordsRequest {
            registry,
            expected_root: Hash(root),
            start_index: 1,
            limit: 16,
        },
    )
    .await
    .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].record, present.record);
    assert_eq!(page.next_leaf_index, None);
    let pool = api::tracking_record_pool(
        db,
        rpc,
        GetTrackingRecordPoolRequest {
            registry,
            members: vec![Hash(member)],
            expected_root: Hash(root),
            openings: 4,
        },
    )
    .await
    .unwrap();
    assert_eq!(pool.records[0].record, present.record);
    let pending = api::pending_enrollments(
        db,
        rpc,
        GetPendingEnrollmentsRequest {
            registry,
            after: None,
            limit: 8,
        },
    )
    .await
    .unwrap();
    assert!(pending.enrollments.is_empty());
    ledger.stop().await;
}

#[tokio::test]
async fn an_apply_reads_the_newest_rotation_ordered_before_it_in_the_block() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry(6, 2)]).await;
    let slot = 3;
    ledger
        .land_all(slot, vec![ledger.enroll(6, None), apply])
        .await
        .unwrap();
    let state = ledger.state().await;
    assert_eq!(state.fault, None);
    assert_eq!(state.account.newest().hash, tree.root().unwrap());
    let held = ledger.enrollment().await.unwrap();
    assert_eq!((held.revision, held.applied_revision), (2, 2));
    let leaf = ledger
        .store()
        .tree()
        .record(&ledger.member(), 1)
        .await
        .unwrap()
        .unwrap()
        .record;
    assert_eq!((leaf.revision, leaf.viewing_u), (2, field(6)));
    ledger.stop().await;
}

#[tokio::test]
async fn a_rotation_after_an_apply_stays_pending_behind_the_leaf() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry(3, 1)]).await;
    let slot = 3;
    ledger
        .land_all(slot, vec![apply, ledger.enroll(6, None)])
        .await
        .unwrap();
    let state = ledger.state().await;
    assert_eq!(state.fault, None);
    let held = ledger.enrollment().await.unwrap();
    assert_eq!((held.revision, held.applied_revision), (2, 1));
    assert_eq!(ledger.store().pending(None, 8).await.unwrap(), [held]);
    let leaf = ledger
        .store()
        .tree()
        .record(&ledger.member(), 1)
        .await
        .unwrap()
        .unwrap()
        .record;
    assert_eq!((leaf.revision, leaf.viewing_u), (1, field(3)));
    ledger.stop().await;
}

#[tokio::test]
async fn a_root_off_the_projected_entry_stops_the_projection_and_applies_nothing() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    // The proof names a rotation the block never holds.
    let apply = ledger.apply(&mut tree, &[ledger.entry(6, 2)]).await;
    ledger.land(3, apply).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("applied root mismatch"), "{fault}");
    let held = ledger.enrollment().await.unwrap();
    assert_eq!(held.applied_revision, 0);
    ledger.stop().await;
}

#[tokio::test]
async fn a_second_apply_of_one_revision_stops_the_projection() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry(3, 1)]).await;
    ledger.land(3, apply).await.unwrap();
    let again = ledger.apply(&mut tree, &[ledger.entry(3, 1)]).await;
    ledger.land(4, again).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("already applied"), "{fault}");
    ledger.stop().await;
}

#[tokio::test]
async fn an_apply_naming_no_enrollment_stops_the_projection() {
    let mut ledger = Ledger::new().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry(3, 1)]).await;
    ledger.land(2, apply).await.unwrap();
    let fault = ledger.state().await.fault.unwrap();
    assert!(fault.contains("names no enrollment"), "{fault}");
    ledger.stop().await;
}

#[tokio::test]
async fn a_rolled_back_apply_replays_to_the_same_root() {
    let mut ledger = enrolled().await;
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry(3, 1)]).await;
    ledger.land(3, apply.clone()).await.unwrap();
    let applied = ledger.state().await;
    let tx = ledger.indexer.db.begin().await.unwrap();
    storage::rollback(&tx, &mut ledger.cursor).await.unwrap();
    tx.commit().await.unwrap();
    let rewound = ledger.state().await;
    assert_eq!(rewound.account.newest().hash, TRACKING_EMPTY_ROOT);
    let member = ledger.member();
    let leaf = ledger.store().tree().record(&member, u64::MAX >> 1).await;
    assert_eq!(leaf.unwrap(), None);
    assert_eq!(ledger.enrollment().await.unwrap().applied_revision, 0);
    ledger.land(3, apply).await.unwrap();
    assert_eq!(ledger.state().await, applied);
    ledger.stop().await;
}

#[tokio::test]
async fn apply_proof_inputs_reach_the_root_the_program_records() {
    let mut ledger = enrolled().await;
    ledger.serve(2).await;
    let (db, rpc) = (ledger.indexer.db.clone(), ledger.indexer.rpc.clone());
    let registry = ledger.registry;
    let request = |owners: Vec<Address>| GetTrackingApplyProofInputsRequest {
        registry: registry.into(),
        owners: owners.into_iter().map(Into::into).collect(),
    };
    let unknown = request(vec![Address::new_from_array([60; 32])]);
    assert!(matches!(
        api::tracking_apply_proof_inputs(db.as_ref(), rpc.as_ref(), unknown).await,
        Err(crate::error::RingApiError::InvalidRequest(_))
    ));
    let twice = request(vec![OWNER, OWNER]);
    assert!(matches!(
        api::tracking_apply_proof_inputs(db.as_ref(), rpc.as_ref(), twice).await,
        Err(crate::error::RingApiError::InvalidRequest(_))
    ));
    let inputs = api::tracking_apply_proof_inputs(db.as_ref(), rpc.as_ref(), request(vec![OWNER]))
        .await
        .unwrap();
    let mut tree = TrackingTree::new().unwrap();
    let apply = ledger.apply(&mut tree, &[ledger.entry(3, 1)]).await;
    assert_eq!(inputs.new_root, Hash(tree.root().unwrap()));
    assert_eq!(inputs.old_root, Hash(TRACKING_EMPTY_ROOT));
    let [write] = inputs.writes.as_slice() else {
        panic!("one owner writes once");
    };
    assert!(!write.exists);
    assert_eq!(write.member, Hash(ledger.member()));
    ledger.land(3, apply).await.unwrap();
    ledger.serve(3).await;
    assert!(matches!(
        api::tracking_apply_proof_inputs(db.as_ref(), rpc.as_ref(), request(vec![OWNER])).await,
        Err(crate::error::RingApiError::InvalidRequest(_))
    ));
    ledger.stop().await;
}

#[tokio::test]
async fn a_registry_off_its_canonical_address_is_not_indexed() {
    let mut ledger = Ledger::new().await;
    let forged = Address::new_from_array([70; 32]);
    let data = InitializeTrackingIxData {
        ring_id: field(9),
        auditor_pubkey: [9; 33],
    };
    let creator = Address::new_from_array([50; 32]);
    let initialize = instruction(
        vec![creator, creator, forged],
        [&[tag::INITIALIZE_TRACKING][..], bytemuck::bytes_of(&data)].concat(),
    );
    ledger.land(2, initialize).await.unwrap();
    let store: TrackingStore<'_, _> =
        TrackingStore::new(ledger.indexer.db.as_ref(), forged.to_bytes());
    assert!(store.state().await.unwrap().is_none());
    ledger.stop().await;
}

#[tokio::test]
async fn a_program_owner_enrolls_through_its_own_cross_program_call() {
    let mut ledger = Ledger::new().await;
    ledger.hold_account(3, 1);
    let proof = CustomRingProof::zeroed();
    let caller = Instruction {
        program_id: Address::new_from_array([61; 32]),
        data: vec![1],
        accounts: vec![],
        stack_height: Some(1),
    };
    let inner = ledger.enroll(3, Some(&proof));
    ledger
        .land_transactions(2, vec![settled(caller, vec![inner])])
        .await
        .unwrap();
    assert_eq!(ledger.enrollment().await.unwrap().revision, 1);
    ledger.stop().await;
}

#[tokio::test]
async fn a_failed_enrollment_leaves_no_row() {
    let mut ledger = Ledger::new().await;
    let proof = CustomRingProof::zeroed();
    let failed = TransactionInfo {
        error: Some("custom program error".into()),
        ..settled(ledger.enroll(3, Some(&proof)), vec![])
    };
    ledger.land_transactions(2, vec![failed]).await.unwrap();
    assert_eq!(ledger.enrollment().await, None);
    ledger.stop().await;
}

const ENROLL_VECTOR: &str = include_str!("../../../test-vectors/registry/tracking_enroll.json");

fn vector_field(vector: &serde_json::Value, name: &str) -> [u8; 32] {
    hex::decode(vector[name].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// The shared vector's enrollment reaches its chain through the block path and the account.
#[tokio::test]
async fn the_shared_enrollment_vector_projects_to_its_entry_and_chain() {
    let vector: serde_json::Value = serde_json::from_str(ENROLL_VECTOR).unwrap();
    let mut ledger = Ledger::new().await;
    ledger.registry = Address::new_from_array(vector_field(&vector, "registry"));
    ledger.authorization = Address::new_from_array(vector_field(&vector, "authorization"));
    let owner = Address::new_from_array(vector_field(&vector, "owner"));
    let data = InitializeTrackingIxData {
        ring_id: field(9),
        auditor_pubkey: [9; 33],
    };
    <TrackingCall as RegistryCall<TrackingRegistry>>::create(
        &ledger.store(),
        &TrackingState {
            registry: ledger.registry.to_bytes(),
            account: Box::new(TrackingRegistry::new(&data)),
            fault: None,
        },
    )
    .await
    .unwrap();
    let image = hex::decode(vector["account"].as_str().unwrap()).unwrap();
    ledger.chain.lock().unwrap().accounts.insert(
        ledger.authorization.to_string(),
        account(STORAGE_PROGRAM_ID, &image),
    );
    let enroll_data = hex::decode(vector["enroll_data"].as_str().unwrap()).unwrap();
    let proof = CustomRingProof::zeroed();
    let enroll = instruction(
        vec![owner, owner, ledger.registry, ledger.authorization],
        [&[tag::ENROLL][..], &enroll_data, bytemuck::bytes_of(&proof)].concat(),
    );
    ledger.land(2, enroll).await.unwrap();
    assert_eq!(ledger.state().await.fault, None);
    let held = ledger.enrollment_of(owner).await.unwrap();
    assert_eq!(held.member, vector_field(&vector, "member"));
    assert_eq!(held.ct_hash, vector_field(&vector, "ct_hash"));
    ledger.serve(2).await;
    let inputs = api::tracking_apply_proof_inputs(
        ledger.indexer.db.as_ref(),
        ledger.indexer.rpc.as_ref(),
        GetTrackingApplyProofInputsRequest {
            registry: ledger.registry.into(),
            owners: vec![owner.into()],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        inputs.chain_start,
        Hash(vector_field(&vector, "chain_start"))
    );
    assert_eq!(inputs.chain_end, Hash(vector_field(&vector, "chain_end")));
    ledger.stop().await;
}
