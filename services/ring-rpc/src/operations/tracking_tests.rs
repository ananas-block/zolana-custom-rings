use std::sync::Mutex;

use spr_keypair::NullifierKey;

use super::{
    fixture::{Enrollment, TrackingLedger},
    *,
};
use crate::{
    database::Store,
    hub::Clock,
    projection_lease::LeaseClaim,
    projection_reads::EnrollmentKey,
    spent_index::{NoteSeal, ProjectionWriter},
    utxos::Backing,
};

const RING: Address = Address::new_from_array([8; 32]);

/// Serves the ledger, `tamper` edits each page before the scan reads it.
struct Served {
    ledger: TrackingLedger,
    tamper: Mutex<Option<fn(&mut GetTrackingRecordsResponse)>>,
}

impl TrackingSource for Served {
    async fn root(&self, _ring: Address) -> Result<Option<TrackingRoot>, ClientError> {
        Ok(self.ledger.root())
    }

    async fn records(
        &self,
        request: GetTrackingRecordsRequest,
    ) -> Result<GetTrackingRecordsResponse, RingIndexerError> {
        let mut page = self.ledger.page(&request);
        if let Some(tamper) = *self.tamper.lock().expect("tamper") {
            tamper(&mut page);
        }
        Ok(page)
    }
}

fn owner(seed: u8) -> Address {
    Address::new_from_array([seed; 32])
}

/// Byte 0 is the seal's pad, a canonical salt leaves it zero.
fn list_salt(seed: u8) -> [u8; 32] {
    let mut salt = [seed; 32];
    salt[0] = 0;
    salt
}

fn served(auditor: &X25519Keypair, owners: &[u8]) -> (Served, Vec<HeldEnrollment>) {
    let ledger = TrackingLedger::default();
    let held = owners
        .iter()
        .map(|seed| {
            ledger.enroll(Enrollment {
                owner: owner(*seed),
                key: &NullifierKey::from_secret([*seed; 31]),
                list_salt: list_salt(*seed),
                auditor: &auditor.pubkey(),
            })
        })
        .collect();
    let served = Served {
        ledger,
        tamper: Mutex::new(None),
    };
    (served, held)
}

async fn scan(
    served: &Served,
    auditor: &X25519Keypair,
    store: &AuditStore,
    cursor: &mut TrackingCursor,
) -> Result<ScanEnd, RingRpcError> {
    TrackingScan {
        ring: RING,
        auditor,
        source: served,
        store,
        durable: None,
    }
    .run(cursor)
    .await
}

async fn enrollment(store: &AuditStore, member: &[u8; 32]) -> Option<HeldEnrollment> {
    store
        .enrollment(EnrollmentKey::Member, member)
        .await
        .expect("lookup")
}

#[tokio::test]
async fn a_scan_holds_every_enrolled_owner_and_completes_at_the_next_index() {
    let auditor = X25519Keypair::new();
    let (served, held) = served(&auditor, &[1, 2, 3]);
    let store = AuditStore::default();
    let mut cursor = TrackingCursor::default();
    let end = scan(&served, &auditor, &store, &mut cursor)
        .await
        .expect("scan");
    assert_eq!(end, ScanEnd::Complete);
    assert_eq!(cursor.next_leaf(), 4, "past the sentinel and three rows");
    for held in held {
        assert_eq!(enrollment(&store, &held.member).await, Some(held));
        let secrets = held.secrets(&auditor).expect("opens");
        assert_eq!(
            secrets.nullifier_key.pubkey().expect("pk"),
            held.nullifier_pk
        );
    }
}

#[tokio::test]
async fn a_page_skipping_a_leaf_holds_nothing_and_keeps_the_cursor() {
    let auditor = X25519Keypair::new();
    let (served, held) = served(&auditor, &[1, 2]);
    *served.tamper.lock().expect("tamper") = Some(|page| {
        page.records.remove(1);
    });
    let store = AuditStore::default();
    let mut cursor = TrackingCursor::default();
    let refused = scan(&served, &auditor, &store, &mut cursor).await;
    assert!(matches!(
        refused,
        Err(RingRpcError::Tracking(TrackingRefusal::PageShape))
    ));
    assert_eq!(cursor, TrackingCursor::default());
    assert_eq!(enrollment(&store, &held[1].member).await, None);
}

#[tokio::test]
async fn a_row_sealed_to_another_auditor_is_refused() {
    let auditor = X25519Keypair::new();
    let (served, _) = served(&X25519Keypair::new(), &[1]);
    let store = AuditStore::default();
    let mut cursor = TrackingCursor::default();
    let refused = scan(&served, &auditor, &store, &mut cursor).await;
    assert!(matches!(
        refused,
        Err(RingRpcError::Tracking(TrackingRefusal::Sealed))
    ));
    assert_eq!(cursor, TrackingCursor::default());
}

#[tokio::test]
async fn a_bounded_enrollment_cache_holds_its_bound_and_storage_answers_an_evicted_row() {
    const NOW: u64 = 1_000;
    let auditor = X25519Keypair::new();
    let seal = || NoteSeal::derive(&auditor, RING).expect("seal");
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let store = AuditStore::new(Backing::Database {
        store: database.clone(),
        ring: RING,
        seal: Box::new(seal()),
        capacity: 2,
    });
    let writer_seal = seal();
    let writer = ProjectionWriter {
        db: database.connection(),
        ring: RING,
        seal: &writer_seal,
        lease: LeaseClaim {
            db: database.connection(),
            ring: RING,
            holder: database.lease_holder(),
            now: NOW,
        }
        .claim()
        .await
        .expect("claim")
        .expect("held"),
        clock: Clock::Fixed(NOW),
    };
    let rows: Vec<HeldEnrollment> = (1..=5)
        .map(|seed| {
            HeldEnrollment::unsealed(
                owner(seed).to_bytes(),
                &NullifierKey::from_secret([seed; 31]),
            )
        })
        .collect();
    // One page per row, as a scan admits them, each committed before the cache takes it.
    for row in &rows {
        let admission = store
            .enrollment_admission(vec![*row])
            .await
            .expect("admission");
        writer
            .commit_enrollments(admission.rows(), TrackingCursor::default())
            .await
            .expect("commit");
        store.admit_enrollments(admission);
    }
    assert!(store
        .cached_enrollments()
        .iter()
        .all(|entries| *entries <= 2));

    // 1. The evicted first row answers by each key it is read by, from storage.
    let first = rows[0];
    for (key, value) in [
        (EnrollmentKey::Member, first.member),
        (EnrollmentKey::OwnerHash, first.owner_hash),
        (EnrollmentKey::ListKey, first.list_key),
    ] {
        assert_eq!(
            store.enrollment(key, &value).await.expect("lookup"),
            Some(first)
        );
    }
    // 2. A page naming the evicted member with other key fields still refuses.
    let conflicting = HeldEnrollment {
        nullifier_pk: [9; 32],
        ..first
    };
    assert!(matches!(
        store.enrollment_admission(vec![conflicting]).await,
        Err(RingRpcError::Tracking(TrackingRefusal::Conflict))
    ));
}
