use std::{collections::HashMap, sync::Mutex};

use sea_orm::ConnectionTrait;
use spr_hasher::primitives::solana_owner_identity;
use spr_keypair::NullifierKey;
use zolana_ring_client::{rpc::WalletNoteStatus, CreatedUtxo, KnownUtxo, UtxoOwner};

use super::*;
use crate::{
    database::Store,
    spend_machine::{InputRead, Observation},
    spent_index::{LoadSpends, NoteSeal, PageCommit},
};

const RING: Address = Address::new_from_array([8; 32]);
const ASSET: [u8; 32] = [4; 32];

/// A real Ed25519 point, `Address::is_on_curve` holds.
fn wallet(seed: u8) -> Address {
    use solana_signer::Signer;
    solana_keypair::Keypair::new_from_array([seed; 32]).pubkey()
}

fn secret(seed: u8) -> NullifierKey {
    NullifierKey::from_secret([seed; 31])
}

fn frame(slot: u64) -> CreatedIn {
    CreatedIn {
        slot,
        tx_signature: Signature::from([slot as u8; 64]),
        event_index: 0,
    }
}

fn note(owner: Address, key: &NullifierKey, commitment: u8, amount: u64) -> CreatedUtxo {
    CreatedUtxo {
        commitment: [commitment; 32],
        slot_index: 0,
        leaf_index: u64::from(commitment),
        utxo: KnownUtxo {
            owner_key: owner.to_bytes(),
            owner: UtxoOwner::Keyed {
                nullifier_pk: key.pubkey().expect("key"),
            },
            asset: ASSET,
            mint: None,
            amount,
            blinding: [commitment.wrapping_add(1); 32],
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
            tree_id: 1,
        },
        ring_note: true,
    }
}

fn nullifier_of(created: &CreatedUtxo, key: &NullifierKey) -> [u8; 32] {
    key.nullifier(&created.commitment, &created.utxo.blinding)
        .expect("nullifier")
}

struct Keys(Mutex<HashMap<[u8; 32], [u8; 31]>>);

impl Keys {
    fn none() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    fn with(owner: Address, seed: u8) -> Self {
        let keys = Self::none();
        keys.grant(owner, seed);
        keys
    }

    fn grant(&self, owner: Address, seed: u8) {
        self.0
            .lock()
            .expect("keys")
            .insert(owner.to_bytes(), [seed; 31]);
    }

    fn open(&self, owner: &[u8; 32]) -> Option<NullifierKey> {
        self.0
            .lock()
            .expect("keys")
            .get(owner)
            .map(|secret| NullifierKey::from_secret(*secret))
    }
}

fn apply(store: &AuditStore, keys: &Keys, page: impl FnOnce(&mut PageWork<'_>)) {
    let opener = |owner: &[u8; 32]| keys.open(owner);
    let mut work = PageWork::new(store, &opener);
    page(&mut work);
    store.commit(work.finish());
}

fn real(nullifier: [u8; 32], at: CreatedIn, position: u16) -> Observation {
    Observation {
        nullifier,
        frame: at,
        position,
        read: InputRead::Real { evidence: None },
        hit: None,
    }
}

fn through(store: &AuditStore, keys: &Keys, slot: u64) {
    apply(store, keys, |work| {
        work.checkpoint(
            HistoryPosition::after_slot(slot),
            Some(Context {
                slot,
                block_time: 1,
            }),
        );
    });
}

fn status_of(store: &AuditStore, owner: Address) -> GetWalletStatusResponse {
    store.wallet_status(WalletStatusQuery {
        enrollment: WalletEnrollment::NotEnrolled,
        wallet: owner,
        after: None,
        limit: 100,
    })
}

fn balance(response: &GetWalletStatusResponse) -> u64 {
    response.balances.iter().map(|entry| entry.amount).sum()
}

fn statuses(response: &GetWalletStatusResponse) -> Vec<WalletNoteStatus> {
    response.notes.iter().map(|note| note.status).collect()
}

#[test]
fn a_note_reads_unspent_then_spent_from_its_own_nullifier() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let created = note(owner, &secret(7), 0x10, 50);
    apply(&store, &keys, |work| work.open(frame(5), [created]));
    through(&store, &keys, 10);
    let read = status_of(&store, owner);
    assert_eq!(statuses(&read), [WalletNoteStatus::Unspent]);
    assert_eq!(balance(&read), 50);
    apply(&store, &keys, |work| {
        work.observe(real(nullifier_of(&created, &secret(7)), frame(11), 0));
    });
    through(&store, &keys, 12);
    let read = status_of(&store, owner);
    assert_eq!(statuses(&read), [WalletNoteStatus::Spent]);
    assert_eq!(balance(&read), 0);
}

#[test]
fn a_note_with_no_readable_secret_is_unknown_and_never_counts() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::none();
    let created = note(owner, &secret(7), 0x10, 50);
    apply(&store, &keys, |work| work.open(frame(5), [created]));
    through(&store, &keys, 10);
    let read = status_of(&store, owner);
    assert_eq!(statuses(&read), [WalletNoteStatus::Unknown]);
    assert_eq!(balance(&read), 0);
}

#[test]
fn a_late_key_recomputes_the_owners_notes_and_resolves_their_rows() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::none();
    let created = note(owner, &secret(7), 0x10, 50);
    let nullifier = nullifier_of(&created, &secret(7));
    apply(&store, &keys, |work| {
        work.open(frame(5), [created]);
        work.observe(real(nullifier, frame(6), 0));
    });
    assert!(matches!(
        store.row_state(&nullifier),
        Some(SpendState::UnresolvedReal { .. })
    ));
    keys.grant(owner, 7);
    store
        .late_owners
        .write()
        .expect("late")
        .insert(owner.to_bytes());
    apply(&store, &keys, |work| work.late_keys());
    assert_eq!(
        store.row_state(&nullifier),
        Some(SpendState::Resolved {
            note: created.commitment
        })
    );
    assert!(store.late_owners.read().expect("late").is_empty());
    through(&store, &keys, 10);
    assert_eq!(
        statuses(&status_of(&store, owner)),
        [WalletNoteStatus::Spent]
    );
}

#[test]
fn a_spend_of_an_unknown_note_stays_unresolved_then_resolves_when_it_opens() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let created = note(owner, &secret(7), 0x10, 50);
    let nullifier = nullifier_of(&created, &secret(7));
    apply(&store, &keys, |work| {
        work.observe(real(nullifier, frame(6), 0));
    });
    let coverage = store.spend_coverage();
    assert_eq!(coverage.unresolved_real.len(), 1);
    assert_eq!(coverage.padding, 0);
    apply(&store, &keys, |work| work.open(frame(5), [created]));
    assert_eq!(
        store.row_state(&nullifier),
        Some(SpendState::Resolved {
            note: created.commitment
        })
    );
    let coverage = store.spend_coverage();
    assert!(coverage.unresolved_real.is_empty());
    assert_eq!(coverage.resolved, 1);
}

/// Replays give the same state, and no step lists the spent inputs beside their merge.
#[test]
fn notes_merged_with_a_late_read_never_count_twice() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let first = note(owner, &secret(7), 0x10, 50);
    let second = note(owner, &secret(7), 0x11, 50);
    let merged = note(owner, &secret(7), 0x12, 100);
    apply(&store, &keys, |work| work.open(frame(2), [first, second]));
    through(&store, &keys, 3);
    assert_eq!(balance(&status_of(&store, owner)), 100);
    // The merge at slot 4 is unreadable, its output has not opened.
    let merge_frame = frame(4);
    let spends = [
        nullifier_of(&first, &secret(7)),
        nullifier_of(&second, &secret(7)),
    ];
    let unreadable = |work: &mut PageWork<'_>| {
        for (position, nullifier) in spends.iter().enumerate() {
            work.observe(Observation {
                read: InputRead::Unreadable,
                ..real(*nullifier, merge_frame, position as u16)
            });
        }
        work.mark_unread(merge_frame);
    };
    apply(&store, &keys, unreadable);
    through(&store, &keys, 9);
    let held = status_of(&store, owner);
    assert_eq!(held.history_through, 3);
    assert_eq!(balance(&held), 100, "as of the slot before the gap");
    let late_read = |work: &mut PageWork<'_>| {
        work.open(merge_frame, [merged]);
        for (position, nullifier) in spends.iter().enumerate() {
            work.observe(real(*nullifier, merge_frame, position as u16));
        }
        work.mark_read(merge_frame);
    };
    apply(&store, &keys, late_read);
    let read = status_of(&store, owner);
    assert_eq!(read.history_through, 9);
    assert_eq!(balance(&read), 100);
    let dump = store.dump();
    apply(&store, &keys, late_read);
    assert_eq!(store.dump(), dump, "a replay changes nothing");
}

#[test]
fn another_wallets_unresolved_spend_leaves_a_wallet_read_byte_equal() {
    let read_with = |stranger_row: bool| {
        let store = AuditStore::default();
        let owner = wallet(1);
        let keys = Keys::with(owner, 7);
        let created = note(owner, &secret(7), 0x10, 50);
        apply(&store, &keys, |work| work.open(frame(5), [created]));
        if stranger_row {
            apply(&store, &keys, |work| {
                work.observe(real([0xee; 32], frame(6), 0));
            });
        }
        through(&store, &keys, 10);
        serde_json::to_vec(&status_of(&store, owner)).expect("json")
    };
    assert_eq!(read_with(true), read_with(false));
}

#[test]
fn only_an_unreadable_frame_holds_the_history_slot() {
    let store = AuditStore::default();
    let keys = Keys::none();
    through(&store, &keys, 100);
    apply(&store, &keys, |work| {
        work.observe(real([1; 32], frame(50), 0));
    });
    assert_eq!(store.spend_coverage().history_through, 100);
    apply(&store, &keys, |work| work.mark_unread(frame(60)));
    let coverage = store.spend_coverage();
    assert_eq!(coverage.history_through, 59);
    assert_eq!(coverage.unreadable.len(), 1);
    apply(&store, &keys, |work| work.mark_read(frame(60)));
    assert_eq!(store.spend_coverage().history_through, 100);
}

#[test]
fn a_note_past_the_history_slot_stays_out_so_input_and_change_never_both_count() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let input = note(owner, &secret(7), 0x10, 50);
    let change = note(owner, &secret(7), 0x11, 50);
    apply(&store, &keys, |work| work.open(frame(2), [input]));
    through(&store, &keys, 3);
    apply(&store, &keys, |work| {
        work.open(frame(5), [change]);
        work.observe(real(nullifier_of(&input, &secret(7)), frame(5), 0));
    });
    let read = status_of(&store, owner);
    assert_eq!(read.history_through, 3);
    assert_eq!(statuses(&read), [WalletNoteStatus::Unspent]);
    assert_eq!(balance(&read), 50);
}

#[test]
fn padding_and_external_add_no_unresolved_state() {
    let store = AuditStore::default();
    let keys = Keys::none();
    apply(&store, &keys, |work| {
        work.observe(Observation {
            read: InputRead::Padding,
            ..real([1; 32], frame(5), 1)
        });
        work.observe(Observation {
            read: InputRead::External,
            ..real([2; 32], frame(5), 0)
        });
    });
    let coverage = store.spend_coverage();
    assert!(coverage.unresolved_real.is_empty());
    assert_eq!((coverage.padding, coverage.external), (1, 1));
}

#[test]
fn a_duplicate_nullifier_is_surfaced_and_the_first_state_stays() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let created = note(owner, &secret(7), 0x10, 50);
    let nullifier = nullifier_of(&created, &secret(7));
    apply(&store, &keys, |work| {
        work.open(frame(2), [created]);
        work.observe(real(nullifier, frame(3), 0));
    });
    let before = store.row_state(&nullifier);
    apply(&store, &keys, |work| {
        work.observe(real(nullifier, frame(4), 0));
    });
    assert_eq!(store.row_state(&nullifier), before);
    let faults = store.spend_coverage().integrity_faults;
    assert_eq!(faults.len(), 1);
    assert_eq!(faults[0].frame.slot, 4);
}

#[test]
fn a_zero_key_note_of_a_wallet_is_exposed_and_a_pda_note_is_not() {
    let store = AuditStore::default();
    let keys = Keys::none();
    let zero = NullifierKey::from_secret([0; 31]);
    assert_eq!(zero.pubkey().expect("zero"), ZERO_NULLIFIER_PUBKEY);
    let owner = wallet(1);
    let exposed = note(owner, &zero, 0x10, 50);
    let (program, _) = Address::find_program_address(&[b"vault"], &RING);
    assert!(!program.is_on_curve());
    let vault = note(program, &zero, 0x11, 70);
    apply(&store, &keys, |work| {
        work.open(frame(2), [exposed, vault]);
    });
    through(&store, &keys, 3);
    let read = status_of(&store, owner);
    assert_eq!(statuses(&read), [WalletNoteStatus::ExposedIfSpent]);
    assert_eq!(balance(&read), 0, "outside the balance");
    let read = status_of(&store, program);
    assert_eq!(statuses(&read), [WalletNoteStatus::Unspent]);
    assert_eq!(balance(&read), 70);
    // Spent takes precedence, the zero secret needs no tracked key.
    apply(&store, &keys, |work| {
        work.observe(real(nullifier_of(&exposed, &zero), frame(4), 0));
    });
    through(&store, &keys, 5);
    assert_eq!(
        statuses(&status_of(&store, owner)),
        [WalletNoteStatus::Spent]
    );
}

#[test]
fn a_frames_evidence_resolves_its_note_and_a_later_opening_settles_an_unseen_one() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::none();
    let seen = note(owner, &secret(7), 0x10, 50);
    let unseen = note(owner, &secret(7), 0x11, 20);
    let named = |nullifier, commitment, position| Observation {
        read: InputRead::Real {
            evidence: Some(commitment),
        },
        ..real(nullifier, frame(6), position)
    };
    apply(&store, &keys, |work| {
        work.open(frame(5), [seen]);
        work.observe(named([1; 32], seen.commitment, 0));
        work.observe(named([2; 32], unseen.commitment, 1));
    });
    assert_eq!(
        store.row_state(&[1; 32]),
        Some(SpendState::Resolved {
            note: seen.commitment
        })
    );
    assert_eq!(
        store.row_state(&[2; 32]),
        Some(SpendState::UnresolvedReal {
            evidence: Some(unseen.commitment)
        })
    );
    apply(&store, &keys, |work| work.open(frame(5), [unseen]));
    assert_eq!(
        store.row_state(&[2; 32]),
        Some(SpendState::Resolved {
            note: unseen.commitment
        })
    );
    through(&store, &keys, 7);
    assert_eq!(
        statuses(&status_of(&store, owner)),
        [WalletNoteStatus::Spent, WalletNoteStatus::Spent]
    );
}

#[test]
fn merge_selection_skips_a_published_nullifier_and_ignores_an_unrelated_row() {
    let store = AuditStore::default();
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let mint = Address::new_from_array([6; 32]);
    let named = |commitment, amount| {
        let mut created = note(owner, &secret(7), commitment, amount);
        created.utxo.mint = Some(mint);
        created
    };
    let (spent, kept) = (named(0x10, 50), named(0x11, 20));
    apply(&store, &keys, |work| {
        work.open(frame(2), [spent, kept]);
        work.observe(real(nullifier_of(&spent, &secret(7)), frame(3), 0));
        work.observe(real([0xee; 32], frame(3), 1));
    });
    let key = secret(7);
    let selected = store
        .spendable(SpendableNotes {
            ring: RING,
            owner_key: owner.to_bytes(),
            mint: Mint::new(mint, 6),
            nullifier_key: &key,
        })
        .expect("selection");
    let hashes: Vec<[u8; 32]> = selected.iter().map(|note| note.utxo_hash).collect();
    assert_eq!(hashes, [kept.commitment]);
}

/// One scripted run, each page a closure over the overlay.
fn script<'a>(
    created: &'a [CreatedUtxo; 2],
    key: &'a NullifierKey,
) -> Vec<Box<dyn Fn(&mut PageWork<'_>) + 'a>> {
    vec![
        Box::new(move |work| {
            work.open(frame(2), [created[0]]);
            work.observe(Observation {
                read: InputRead::Padding,
                ..real([3; 32], frame(2), 1)
            });
            work.mark_unread(frame(2));
            work.checkpoint(
                HistoryPosition::after_slot(2),
                Some(Context {
                    slot: 2,
                    block_time: 7,
                }),
            );
        }),
        Box::new(move |work| {
            work.open(frame(3), [created[1]]);
            work.observe(real(nullifier_of(&created[0], key), frame(3), 0));
            work.observe(real([9; 32], frame(3), 1));
            work.observe(real([9; 32], frame(4), 0));
            work.mark_read(frame(2));
            work.checkpoint(
                HistoryPosition::after_slot(5),
                Some(Context {
                    slot: 5,
                    block_time: 8,
                }),
            );
        }),
    ]
}

async fn commit_page(
    store: &Store,
    book: &AuditStore,
    seal: &NoteSeal,
    keys: &Keys,
    page: &dyn Fn(&mut PageWork<'_>),
) -> Result<(), sea_orm::DbErr> {
    let opener = |owner: &[u8; 32]| keys.open(owner);
    let mut work = PageWork::new(book, &opener);
    page(&mut work);
    let delta = work.finish();
    PageCommit {
        db: store.connection(),
        ring: RING,
        seal,
        delta: &delta,
    }
    .commit()
    .await?;
    book.commit(delta);
    Ok(())
}

async fn restart(store: &Store, seal: &NoteSeal) -> AuditStore {
    let book = AuditStore::default();
    book.seed(
        LoadSpends {
            db: store.connection(),
            ring: RING,
            seal,
        }
        .load()
        .await
        .expect("load"),
    );
    book
}

fn seal() -> NoteSeal {
    NoteSeal::derive(&spr_keypair::X25519Keypair::from_bytes(&[0x41; 32]), RING).expect("seal")
}

#[tokio::test]
async fn a_kill_at_any_checkpoint_step_replays_to_the_uninterrupted_state() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let key = secret(7);
    let created = [note(owner, &key, 0x10, 50), note(owner, &key, 0x11, 20)];
    let pages = script(&created, &key);
    let seal = seal();

    let clean = Store::open("sqlite::memory:", 1).await.expect("store");
    let uninterrupted = AuditStore::default();
    for page in &pages {
        commit_page(&clean, &uninterrupted, &seal, &keys, page)
            .await
            .expect("page");
    }
    let expected = uninterrupted.dump();
    assert_eq!(restart(&clean, &seal).await.dump(), expected);

    for table in [
        "finalized_notes",
        "finalized_spent_nullifiers",
        "spend_integrity_faults",
        "spend_unread_frames",
        "spend_checkpoints",
    ] {
        for failing in 0..pages.len() {
            let store = Store::open("sqlite::memory:", 1).await.expect("store");
            let mut book = AuditStore::default();
            for page in &pages[..failing] {
                commit_page(&store, &book, &seal, &keys, page)
                    .await
                    .expect("page");
            }
            let before = book.dump();
            let rename = |from: &str, to: &str| format!("ALTER TABLE {from} RENAME TO {to}");
            store
                .connection()
                .execute_unprepared(&rename(table, "parked"))
                .await
                .expect("park");
            let refused = commit_page(&store, &book, &seal, &keys, pages[failing].as_ref()).await;
            store
                .connection()
                .execute_unprepared(&rename("parked", table))
                .await
                .expect("restore");
            // A table the page leaves alone does not fail the page.
            if refused.is_err() {
                assert_eq!(book.dump(), before, "the mirror follows the commit");
                assert_eq!(
                    restart(&store, &seal).await.dump(),
                    before,
                    "a failed page writes nothing"
                );
            }
            book = restart(&store, &seal).await;
            // A restart replays the failed page and every later one.
            let start = if refused.is_err() {
                failing
            } else {
                failing + 1
            };
            for page in &pages[start..] {
                commit_page(&store, &book, &seal, &keys, page)
                    .await
                    .expect("replay");
            }
            assert_eq!(book.dump(), expected);
            assert_eq!(restart(&store, &seal).await.dump(), expected);
        }
    }
}

#[tokio::test]
async fn a_replayed_page_changes_no_row() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let key = secret(7);
    let created = [note(owner, &key, 0x10, 50), note(owner, &key, 0x11, 20)];
    let pages = script(&created, &key);
    let seal = seal();
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = AuditStore::default();
    for page in &pages {
        commit_page(&store, &book, &seal, &keys, page)
            .await
            .expect("page");
    }
    let expected = book.dump();
    let replayed = restart(&store, &seal).await;
    for page in &pages {
        commit_page(&store, &replayed, &seal, &keys, page)
            .await
            .expect("replay");
    }
    let mut dump = replayed.dump();
    dump.position_slot = expected.position_slot;
    dump.context = expected.context;
    assert_eq!(dump, expected);
}

#[tokio::test]
async fn a_note_row_opens_only_under_the_auditor_key_and_holds_no_plaintext() {
    let owner = wallet(1);
    let keys = Keys::with(owner, 7);
    let key = secret(7);
    let created = [note(owner, &key, 0x10, 50), note(owner, &key, 0x11, 20)];
    let pages = script(&created, &key);
    let seal = seal();
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let book = AuditStore::default();
    commit_page(&store, &book, &seal, &keys, pages[0].as_ref())
        .await
        .expect("page");
    let other =
        NoteSeal::derive(&spr_keypair::X25519Keypair::from_bytes(&[0x42; 32]), RING).expect("seal");
    assert!(LoadSpends {
        db: store.connection(),
        ring: RING,
        seal: &other,
    }
    .load()
    .await
    .is_err());
    let row = store
        .connection()
        .query_one(sea_orm::Statement::from_string(
            store.connection().get_database_backend(),
            "SELECT sealed FROM finalized_notes LIMIT 1",
        ))
        .await
        .expect("query")
        .expect("row");
    let sealed: Vec<u8> = row.try_get("", "sealed").expect("sealed");
    let identity = solana_owner_identity(owner.as_array()).expect("identity");
    for secret_field in [owner.to_bytes(), identity, created[0].utxo.blinding] {
        assert!(!sealed.windows(32).any(|window| window == secret_field));
    }
}
