use std::sync::Mutex;

use spr_keypair::NullifierKey;

use super::{
    fixture::{Enrollment, TrackingLedger},
    *,
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
    cursor: &mut u64,
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

#[tokio::test]
async fn a_scan_holds_every_enrolled_owner_and_completes_at_the_next_index() {
    let auditor = X25519Keypair::new();
    let (served, held) = served(&auditor, &[1, 2, 3]);
    let store = AuditStore::default();
    let mut cursor = 0;
    let end = scan(&served, &auditor, &store, &mut cursor)
        .await
        .expect("scan");
    assert_eq!(end, ScanEnd::Complete);
    assert_eq!(cursor, 4, "the sentinel and three rows");
    for held in held {
        assert_eq!(store.enrollment(&held.member), Some(held));
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
    let mut cursor = 0;
    let refused = scan(&served, &auditor, &store, &mut cursor).await;
    assert!(matches!(
        refused,
        Err(RingRpcError::Tracking(TrackingRefusal::PageShape))
    ));
    assert_eq!(cursor, 0);
    assert_eq!(store.enrollment(&held[1].member), None);
}

#[tokio::test]
async fn a_row_sealed_to_another_auditor_is_refused() {
    let auditor = X25519Keypair::new();
    let (served, _) = served(&X25519Keypair::new(), &[1]);
    let store = AuditStore::default();
    let mut cursor = 0;
    let refused = scan(&served, &auditor, &store, &mut cursor).await;
    assert!(matches!(
        refused,
        Err(RingRpcError::Tracking(TrackingRefusal::Sealed))
    ));
    assert_eq!(cursor, 0);
}
