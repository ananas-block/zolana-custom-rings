use spr_keypair::NullifierKey;

use super::*;
use crate::{
    database::Store,
    projection_lease::{LeaseClaim, PROJECTION_LEASE_TTL},
    spend_machine::{InputRead, Observation},
    utxos::{AuditStore, PageWork},
};

const RING: Address = Address::new_from_array([8; 32]);
const NOW: u64 = 1_000;

/// A file every replica of one test opens, so reads and writes take separate connections.
fn shared_file(name: &str) -> String {
    let directory = std::env::temp_dir().join(format!("projection-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("directory");
    format!(
        "sqlite://{}?mode=rwc",
        directory.join("ring.sqlite").display()
    )
}

fn seal() -> NoteSeal {
    NoteSeal::derive(&X25519Keypair::from_bytes(&[0x41; 32]), RING).expect("seal")
}

async fn claim(store: &Store, now: u64) -> Option<ProjectionLease> {
    LeaseClaim {
        db: store.connection(),
        ring: RING,
        holder: store.replica(),
        now,
    }
    .claim()
    .await
    .expect("claim")
}

/// A page through `slot`, spending `nullifier` when one is named.
fn page(slot: u64, nullifier: Option<[u8; 32]>) -> PageDelta {
    let book = AuditStore::default();
    let opener = |_: &[u8; 32]| -> Option<NullifierKey> { None };
    let mut work = PageWork::new(&book, &opener);
    if let Some(nullifier) = nullifier {
        work.observe(Observation {
            nullifier,
            frame: CreatedIn {
                slot,
                tx_signature: Signature::from([0x51; 64]),
                event_index: 0,
            },
            position: 0,
            read: InputRead::Real,
            hit: None,
        });
    }
    work.checkpoint(
        HistoryPosition::after_slot(slot),
        Some(Context {
            slot,
            block_time: 0,
        }),
    );
    work.finish()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spend_committed_between_two_reads_shows_in_neither() {
    let store = Store::open(&shared_file("snapshot"), 2)
        .await
        .expect("store");
    let seal = seal();
    let writer = ProjectionWriter {
        db: store.connection(),
        ring: RING,
        seal: &seal,
        lease: claim(&store, NOW).await.expect("held"),
        clock: Clock::Fixed(NOW),
    };
    writer
        .commit_page(&page(5, None))
        .await
        .expect("first page");
    let tables = LoadSpends {
        db: store.connection(),
        ring: RING,
        seal: &seal,
    };

    let snapshot = read_snapshot(store.connection()).await.expect("snapshot");
    let first = tables.read(&snapshot).await.expect("first read");
    writer
        .commit_page(&page(9, Some([0x33; 32])))
        .await
        .expect("a spend between the reads");
    let second = tables.read(&snapshot).await.expect("second read");
    snapshot.commit().await.expect("end");

    assert_eq!(
        second, first,
        "the spend and its checkpoint stay out together"
    );
    assert!(first.spends.rows.is_empty());
    let later = tables.load().await.expect("later load");
    assert_eq!(later.spends.rows.len(), 1);
    assert_eq!(later.spends.checkpoint.through.slot, 9);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_replica_is_refused_and_a_taken_lease_fences_the_first() {
    let url = shared_file("lease");
    let first = Store::open(&url, 2).await.expect("first replica");
    let second = Store::open(&url, 2).await.expect("second replica");
    let seal = seal();
    let held = claim(&first, NOW).await.expect("the first replica holds");
    assert_eq!(claim(&second, NOW + 1).await, None, "a live lease refuses");

    let expired = NOW + PROJECTION_LEASE_TTL;
    let taken = claim(&second, expired).await.expect("taken after expiry");
    assert_ne!(taken, held);
    // The stale writer's clock still reads its lease as live, the moved token refuses it.
    let stale = ProjectionWriter {
        db: first.connection(),
        ring: RING,
        seal: &seal,
        lease: held,
        clock: Clock::Fixed(NOW + 1),
    };
    assert!(stale.commit_page(&page(5, Some([0x33; 32]))).await.is_err());
    ProjectionWriter {
        db: second.connection(),
        ring: RING,
        seal: &seal,
        lease: taken,
        clock: Clock::Fixed(expired),
    }
    .commit_page(&page(7, None))
    .await
    .expect("the holder commits");

    let loaded = LoadSpends {
        db: first.connection(),
        ring: RING,
        seal: &seal,
    }
    .load()
    .await
    .expect("load");
    assert!(
        loaded.spends.rows.is_empty(),
        "the fenced page wrote nothing"
    );
    assert_eq!(loaded.spends.checkpoint.through.slot, 7);
}
