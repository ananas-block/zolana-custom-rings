use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use sea_orm::{ConnectionTrait, Statement};
use solana_message::Message;
use zolana_ring_policy::AssetLimits;

use super::*;
use crate::{cosign::ApproveClass, record_update::MAX_LIMIT_WINDOW_SLOTS};

const RING: Address = Address::new_from_array([9; 32]);
const SOL: Address = Address::new_from_array([3; 32]);
const USDC: Address = Address::new_from_array([4; 32]);
const WINDOW: u64 = 50;
const CAP: u64 = 100;
const START_SLOT: u64 = 1_000;

fn capped(limits: AssetLimits) -> MintPolicy {
    MintPolicy {
        limits,
        ..MintPolicy::EMPTY
    }
}

fn member(byte: u8) -> Member {
    Member::from_bytes([byte; 32]).expect("member")
}

fn flow(owner: u8, asset: Address, debit: u64) -> OwnerFlow {
    OwnerFlow {
        owner: member(owner),
        flow: AssetFlow {
            asset,
            debit: debit.into(),
            charged_outflow: debit.into(),
            deposited: 0,
            withdrawn: 0,
        },
    }
}

/// The slot and the limits move under a running co-signer, every asset answers the same limits.
struct Clocked {
    slot: Arc<AtomicU64>,
    limits: std::sync::Mutex<AssetLimits>,
    frame_reads: AtomicUsize,
    frame: Vec<OwnerFlow>,
}

const SENDER_LIMITS: AssetLimits = AssetLimits {
    sender_cap: CAP,
    sender_window_slots: WINDOW,
    ..AssetLimits::EMPTY
};

impl AssetLimitSource for Clocked {
    async fn co_signer_scope(
        &self,
        _ring: Address,
        _signer: Address,
    ) -> Result<CoSignScope, RingRpcError> {
        Ok(CoSignScope::ALL)
    }

    async fn current_slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.slot.load(Ordering::Relaxed))
    }

    async fn asset_policies(
        &self,
        _ring: Address,
        assets: &[Address],
    ) -> Result<Vec<Option<MintPolicy>>, RingRpcError> {
        let limits = *self.limits.lock().expect("limits");
        Ok(vec![Some(capped(limits)); assets.len()])
    }

    async fn transfer_flows(
        &self,
        _ring: Address,
        _message: &VersionedMessage,
    ) -> Result<FrameRead, RingRpcError> {
        self.frame_reads.fetch_add(1, Ordering::Relaxed);
        Ok(FrameRead::Transfer(TransferRead {
            flows: self.frame.clone(),
            spends_note: true,
            approval_bits: None,
            co_signers: Vec::new(),
        }))
    }
}

struct Window {
    co_signer: LimitedCoSigner<Clocked>,
    store: Store,
    slot: Arc<AtomicU64>,
}

impl Window {
    async fn open(url: &str) -> Self {
        Self::over(
            Store::open(url, crate::database::STORE_CONNECTIONS)
                .await
                .expect("store"),
            Vec::new(),
        )
    }

    fn over(store: Store, frame: Vec<OwnerFlow>) -> Self {
        let slot = Arc::new(AtomicU64::new(START_SLOT));
        let co_signer = LimitedCoSignerInit {
            signer: Keypair::new_from_array([5; 32]),
            limits: Clocked {
                slot: slot.clone(),
                limits: std::sync::Mutex::new(SENDER_LIMITS),
                frame_reads: AtomicUsize::new(0),
                frame,
            },
            store: Arc::new(store.clone()),
            approval: CoSignerApproval::new([ApproveClass::Transfers, ApproveClass::Deposits]),
        }
        .build();
        Self {
            co_signer,
            store,
            slot,
        }
    }

    async fn decide(&self, nonce: u8, flows: Vec<OwnerFlow>) -> CoSignDecision {
        self.co_signer
            .decide(&request(nonce, flows))
            .await
            .expect("decision")
    }

    async fn signed(&self, nonce: u8, flows: Vec<OwnerFlow>) -> Signature {
        match self.decide(nonce, flows).await {
            CoSignDecision::Signed(signature) => signature,
            refused => panic!("within the cap, got {refused:?}"),
        }
    }

    async fn refuses(&self, nonce: u8, flows: Vec<OwnerFlow>) {
        assert_eq!(
            self.decide(nonce, flows).await,
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );
    }

    async fn clear(&self) {
        self.store
            .connection()
            .execute_unprepared("DELETE FROM cosign_usage")
            .await
            .expect("empty usage");
    }

    fn limit(&self, limits: AssetLimits) {
        *self.co_signer.limits.limits.lock().expect("limits") = limits;
    }

    /// `(owner, slot, outflow)` of every reservation, confirmed or not.
    async fn rows(&self) -> Vec<(u8, i64, u128)> {
        let connection = self.store.connection();
        let mut rows: Vec<_> = connection
            .query_all(Statement::from_string(
                connection.get_database_backend(),
                "SELECT owner, slot, outflow_hi, outflow_lo FROM cosign_usage",
            ))
            .await
            .expect("rows")
            .iter()
            .map(|row| {
                let owner: Vec<u8> = row.try_get("", "owner").expect("owner");
                let half = |column| {
                    u128::try_from(row.try_get::<i64>("", column).expect("half")).expect("sign")
                };
                (
                    owner[0],
                    row.try_get("", "slot").expect("slot"),
                    (half("outflow_hi") << 32) + half("outflow_lo"),
                )
            })
            .collect();
        rows.sort_unstable();
        rows
    }
}

fn message(nonce: u8) -> VersionedMessage {
    VersionedMessage::Legacy(Message {
        account_keys: vec![Address::new_from_array([nonce; 32])],
        ..Message::default()
    })
}

fn request(nonce: u8, flows: Vec<OwnerFlow>) -> CoSignRequest {
    CoSignRequest {
        ring: RING,
        message: message(nonce),
        flows: CoSignFlows::Published(flows),
    }
}

/// Removed on drop, a restart reopens the same file.
struct StoreFile(PathBuf);

impl StoreFile {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cosign-window-{name}-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }

    fn url(&self) -> String {
        format!("sqlite://{}?mode=rwc", self.0.display())
    }
}

impl Drop for StoreFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A zero window reads no row, the checked transaction alone meets the cap.
#[tokio::test]
async fn a_zero_window_counts_the_checked_transaction_alone() {
    let window = Window::open("sqlite::memory:").await;
    window.limit(AssetLimits {
        sender_window_slots: 0,
        ..SENDER_LIMITS
    });
    window.signed(1, vec![flow(7, SOL, CAP)]).await;
    window.signed(2, vec![flow(7, SOL, CAP)]).await;
    window.refuses(3, vec![flow(7, SOL, CAP + 1)]).await;
}

#[tokio::test]
async fn a_reservation_of_a_slot_past_the_reader_still_counts() {
    let window = Window::open("sqlite::memory:").await;
    window.slot.store(START_SLOT + 5, Ordering::Relaxed);
    window.signed(1, vec![flow(7, SOL, CAP)]).await;
    window.slot.store(START_SLOT, Ordering::Relaxed);
    window.refuses(2, vec![flow(7, SOL, 1)]).await;
}

/// Halves sum exactly up to `u64::MAX`, one unit past it refuses.
async fn assert_ring_total_sums_exactly_to_u64_max(window: &Window) {
    window.limit(AssetLimits {
        volume_cap: u64::MAX,
        volume_window_slots: WINDOW,
        ..AssetLimits::EMPTY
    });
    window.signed(1, vec![flow(7, SOL, u64::MAX - 1)]).await;
    window.signed(2, vec![flow(8, SOL, 1)]).await;
    window.refuses(3, vec![flow(9, SOL, 1)]).await;
}

/// A measure past 2^64 stores capped and still reads past every cap.
async fn assert_measure_past_u64_reads_past_every_later_cap(window: &Window) {
    window.limit(SENDER_LIMITS);
    let deposited = |amount| OwnerFlow {
        owner: member(7),
        flow: AssetFlow {
            deposited: amount,
            ..flow(7, SOL, 0).flow
        },
    };
    window.signed(1, vec![deposited(u128::MAX)]).await;
    window.limit(AssetLimits {
        deposit_cap: u64::MAX,
        deposit_window_slots: WINDOW,
        ..AssetLimits::EMPTY
    });
    window.refuses(2, vec![deposited(1)]).await;
}

#[tokio::test]
async fn a_ring_total_sums_exactly_to_u64_max_and_refuses_one_past() {
    assert_ring_total_sums_exactly_to_u64_max(&Window::open("sqlite::memory:").await).await;
}

#[tokio::test]
async fn a_measure_past_u64_reserved_uncapped_reads_past_every_later_cap() {
    let window = Window::open("sqlite::memory:").await;
    assert_measure_past_u64_reads_past_every_later_cap(&window).await;
}

#[tokio::test]
#[ignore = "needs RING_RPC_TEST_POSTGRES_URL"]
async fn the_summed_halves_read_alike_on_postgres() {
    let url = std::env::var("RING_RPC_TEST_POSTGRES_URL").expect("postgres url");
    let window = Window::open(&url).await;
    window.clear().await;
    assert_ring_total_sums_exactly_to_u64_max(&window).await;
    window.clear().await;
    assert_measure_past_u64_reads_past_every_later_cap(&window).await;
}

#[tokio::test]
async fn a_reservation_prunes_rows_past_the_longest_window() {
    let window = Window::open("sqlite::memory:").await;
    window.signed(1, vec![flow(7, SOL, 1)]).await;
    window
        .slot
        .store(START_SLOT + MAX_LIMIT_WINDOW_SLOTS + 1, Ordering::Relaxed);
    window.signed(2, vec![flow(8, SOL, 1)]).await;
    assert_eq!(window.rows().await.len(), 1);
}

#[tokio::test]
async fn the_ledger_counts_a_reservation_until_its_window_passes() {
    let window = Window::open("sqlite::memory:").await;
    window.signed(1, vec![flow(7, SOL, 60)]).await;
    window.slot.store(1_049, Ordering::Relaxed);
    window.refuses(2, vec![flow(7, SOL, 41)]).await;
    window.signed(3, vec![flow(8, SOL, CAP)]).await;
    window.slot.store(1_050, Ordering::Relaxed);
    window.signed(4, vec![flow(7, SOL, CAP)]).await;
}

#[tokio::test]
async fn windows_stay_apart_per_owner_and_per_asset() {
    let window = Window::open("sqlite::memory:").await;
    window.signed(1, vec![flow(7, SOL, CAP)]).await;
    window.refuses(2, vec![flow(7, SOL, 1)]).await;
    window.signed(3, vec![flow(8, SOL, CAP)]).await;
    window.signed(4, vec![flow(7, USDC, CAP)]).await;
}

#[tokio::test]
async fn one_over_cap_owner_refuses_the_transfer_and_reserves_no_other_owner() {
    let window = Window::open("sqlite::memory:").await;
    window
        .refuses(1, vec![flow(7, SOL, 40), flow(8, SOL, CAP + 1)])
        .await;
    assert_eq!(window.rows().await, []);
    window.signed(2, vec![flow(7, SOL, CAP)]).await;
}

#[tokio::test]
async fn a_repeated_message_keeps_its_first_slot_and_figures() {
    let window = Window::open("sqlite::memory:").await;
    let first = window.signed(1, vec![flow(7, SOL, 60)]).await;
    window.slot.store(START_SLOT + 10, Ordering::Relaxed);
    assert_eq!(window.signed(1, vec![flow(7, SOL, 60)]).await, first);
    let start_slot = i64::try_from(START_SLOT).expect("slot");
    assert_eq!(window.rows().await, [(7, start_slot, 60)]);
}

#[tokio::test]
async fn a_frame_read_past_a_repeated_message_never_moves_its_rows() {
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let window = Window::over(store, vec![flow(7, SOL, 60)]);
    let framed = || CoSignRequest {
        ring: RING,
        message: message(1),
        flows: CoSignFlows::Frame,
    };
    let first = window.co_signer.decide(&framed()).await.expect("first");
    assert!(matches!(first, CoSignDecision::Signed(_)));
    assert_eq!(
        window.co_signer.decide(&framed()).await.expect("retry"),
        first
    );
    assert_eq!(
        window.co_signer.limits.frame_reads.load(Ordering::Relaxed),
        2
    );
    assert_eq!(window.rows().await.len(), 1);
}

async fn assert_concurrent_retries_reserve_one_row_set(url: &str) {
    let window = Arc::new(Window::open(url).await);
    let other = Arc::new(Window::open(url).await);
    let mut retries = tokio::task::JoinSet::new();
    for attempt in 0..16usize {
        let window = match attempt % 2 {
            0 => window.clone(),
            _ => other.clone(),
        };
        retries.spawn(async move {
            window
                .co_signer
                .decide(&request(1, vec![flow(7, SOL, 10), flow(8, SOL, 20)]))
                .await
        });
    }
    let mut signatures = BTreeSet::new();
    while let Some(decision) = retries.join_next().await {
        match decision.expect("task").expect("decision") {
            CoSignDecision::Signed(signature) => signatures.insert(signature),
            refused => panic!("one message within the cap, got {refused:?}"),
        };
    }
    assert_eq!(signatures.len(), 1);
    assert_eq!(window.rows().await.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_retries_of_one_message_reserve_one_row_set_on_sqlite() {
    let file = StoreFile::new("retries");
    assert_concurrent_retries_reserve_one_row_set(&file.url()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs RING_RPC_TEST_POSTGRES_URL"]
async fn concurrent_retries_of_one_message_reserve_one_row_set_on_postgres() {
    let url = std::env::var("RING_RPC_TEST_POSTGRES_URL").expect("postgres url");
    let store = Store::open(&url, 1).await.expect("store");
    store
        .connection()
        .execute_unprepared("DELETE FROM cosign_usage")
        .await
        .expect("empty usage");
    assert_concurrent_retries_reserve_one_row_set(&url).await;
}

#[tokio::test]
async fn a_settlement_touches_only_its_own_message() {
    let window = Window::open("sqlite::memory:").await;
    let first = window.signed(1, vec![flow(7, SOL, 30)]).await;
    window.signed(2, vec![flow(7, SOL, 40)]).await;
    window
        .co_signer
        .settle(CoSignSettlement::Failed(first))
        .await
        .expect("settle");
    let start_slot = i64::try_from(START_SLOT).expect("slot");
    assert_eq!(window.rows().await, [(7, start_slot, 40)]);
    window
        .co_signer
        .settle(CoSignSettlement::Failed(Signature::from([0x42; 64])))
        .await
        .expect("an unknown signature frees nothing");
    assert_eq!(window.rows().await.len(), 1);
}

#[tokio::test]
async fn a_restart_keeps_every_reservation_and_a_retry_adds_none() {
    let file = StoreFile::new("restart");
    let flows = vec![flow(7, SOL, 60), flow(8, SOL, 30)];
    let first = Window::open(&file.url())
        .await
        .signed(1, flows.clone())
        .await;

    let restarted = Window::open(&file.url()).await;
    assert_eq!(restarted.rows().await.len(), 2);
    restarted.refuses(2, vec![flow(7, SOL, 41)]).await;
    assert_eq!(restarted.signed(1, flows).await, first);
    assert_eq!(restarted.rows().await.len(), 2);
    restarted.signed(3, vec![flow(7, SOL, 40)]).await;

    restarted
        .co_signer
        .settle(CoSignSettlement::Failed(first))
        .await
        .expect("settle");
    assert_eq!(restarted.rows().await.len(), 1);
    restarted.signed(4, vec![flow(7, SOL, 60)]).await;
}

#[tokio::test]
async fn a_restart_keeps_a_confirmed_reservation_through_a_late_failure() {
    let file = StoreFile::new("confirmed");
    let window = Window::open(&file.url()).await;
    let confirmed = window.signed(1, vec![flow(7, SOL, CAP)]).await;
    window
        .co_signer
        .settle(CoSignSettlement::Confirmed(confirmed))
        .await
        .expect("confirm");

    let restarted = Window::open(&file.url()).await;
    restarted
        .co_signer
        .settle(CoSignSettlement::Failed(confirmed))
        .await
        .expect("late failure");
    restarted.refuses(2, vec![flow(7, SOL, 1)]).await;
}
