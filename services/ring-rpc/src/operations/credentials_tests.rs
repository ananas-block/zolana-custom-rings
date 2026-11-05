use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_indexer_api::{Context, PaginationToken, TransactionEvents};

use super::{fixture::Enrollment, *};
use crate::{
    database::Store,
    hub::Clock,
    projection_lease::LeaseClaim,
    spent_index::{HistoryScope, LoadSpends, NoteSeal},
};

const RING: Address = Address::new_from_array([8; 32]);
const PAYER: Address = Address::new_from_array([2; 32]);
/// A field element, the sealed salt's first byte is zero padding.
const SALT: [u8; 32] = {
    let mut salt = [7; 32];
    salt[0] = 0;
    salt
};
const CONTEXT: u64 = 100_000;

type Row = TransactionEvents<ShieldedTransaction, Signature>;
type Tamper = Box<dyn FnOnce(&mut GetShieldedTransactionsByTagsResponse) + Send>;
type Forge = Box<dyn Fn(&mut Chain)>;

/// Pages the way the finalized history does, a queued tamper rewrites the next page once.
#[derive(Default)]
struct Chain {
    rows: Vec<Row>,
    accounts: HashMap<Signature, Vec<Address>>,
    tampers: Mutex<VecDeque<Tamper>>,
    /// The position of every page read.
    requests: Mutex<Vec<HistoryPosition>>,
}

struct Owner {
    wallet: Keypair,
    key: NullifierKey,
}

impl CredentialSource for Chain {
    async fn credential_page(
        &self,
        request: TransactionPage,
    ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
        self.requests
            .lock()
            .expect("requests")
            .push(request.position);
        let filters = request.position.filters();
        let token = request.position.token();
        let after: Vec<&Row> = self
            .rows
            .iter()
            .filter(|row| {
                filters.slot.contains(row.slot)
                    && token
                        .is_none_or(|token| PaginationToken::new(row.slot, row.signature) > token)
            })
            .collect();
        let limit = request.limit.get() as usize;
        let data: Vec<Row> = after.iter().take(limit).map(|row| (*row).clone()).collect();
        let pagination_token = (after.len() > limit)
            .then(|| {
                data.last()
                    .map(|row| PaginationToken::new(row.slot, row.signature))
            })
            .flatten();
        let mut response = GetShieldedTransactionsByTagsResponse {
            context: Context {
                slot: CONTEXT,
                block_time: 0,
            },
            output_tree_id: None,
            data,
            pagination_token,
        };
        if let Some(tamper) = self.tampers.lock().expect("tampers").pop_front() {
            tamper(&mut response);
        }
        Ok(response)
    }

    async fn transaction_accounts(
        &self,
        signature: Signature,
    ) -> Result<Vec<Address>, ClientError> {
        Ok(self.accounts.get(&signature).cloned().unwrap_or_default())
    }
}

impl Owner {
    fn new(seed: u8) -> Self {
        Self {
            wallet: Keypair::new_from_array([seed; 32]),
            key: NullifierKey::from_secret([seed; 31]),
        }
    }

    fn enrollment<'a>(&'a self, auditor: &'a X25519Pubkey, slot: u64) -> Enrollment<'a> {
        Enrollment {
            ring: RING,
            owner: self.wallet.pubkey(),
            key: &self.key,
            list_salt: SALT,
            auditor,
            signature: signature(slot),
            slot,
        }
    }

    fn member(&self) -> [u8; 32] {
        *Member::owner_tag(self.wallet.pubkey().as_array())
            .expect("member")
            .as_bytes()
    }
}

impl Chain {
    /// One row per slot from 1 to `rows`, each enrolled owner in the row of its slot.
    fn with_rows(rows: u64, enrolled: &[(&Owner, u64)], auditor: &X25519Pubkey) -> Self {
        let mut chain = Self::default();
        for slot in 1..=rows {
            let events = enrolled
                .iter()
                .filter(|(_, at)| *at == slot)
                .map(|(owner, _)| {
                    let enrollment = owner.enrollment(auditor, slot);
                    enrollment.event_of(&enrollment.credential())
                })
                .collect();
            chain.rows.push(Row {
                slot,
                signature: signature(slot),
                events,
            });
        }
        for (owner, slot) in enrolled {
            chain
                .accounts
                .insert(signature(*slot), vec![PAYER, owner.wallet.pubkey()]);
        }
        chain
    }

    fn tamper(
        &self,
        tamper: impl FnOnce(&mut GetShieldedTransactionsByTagsResponse) + Send + 'static,
    ) {
        self.tampers
            .lock()
            .expect("tampers")
            .push_back(Box::new(tamper));
    }
}

fn signature(slot: u64) -> Signature {
    let mut bytes = [0; 64];
    bytes[..8].copy_from_slice(&slot.to_be_bytes());
    Signature::from(bytes)
}

async fn scan(
    chain: &Chain,
    auditor: &X25519Keypair,
    store: &AuditStore,
    position: &mut HistoryPosition,
) -> Result<ScanEnd, RingRpcError> {
    CredentialScan {
        ring: RING,
        auditor,
        source: chain,
        store,
        durable: None,
    }
    .run(position)
    .await
}

fn refusal(result: Result<ScanEnd, RingRpcError>) -> CredentialRefusal {
    match result {
        Err(RingRpcError::Credential(refusal)) => refusal,
        other => panic!("expected a credential refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_complete_scan_holds_every_credential_across_pages() {
    let auditor = X25519Keypair::new();
    let (first, second) = (Owner::new(11), Owner::new(12));
    let chain = Chain::with_rows(150, &[(&first, 3), (&second, 140)], &auditor.pubkey());
    let store = AuditStore::default();
    let mut position = HistoryPosition::default();

    let end = scan(&chain, &auditor, &store, &mut position)
        .await
        .expect("scan");

    assert_eq!(end, ScanEnd::Complete);
    for owner in [&first, &second] {
        let held = store.credential(&owner.member()).expect("held");
        assert_eq!(held.owner_key, owner.wallet.pubkey().to_bytes());
        let opened = held.secrets(&auditor).expect("opens");
        assert_eq!(opened.nullifier_key.secret(), owner.key.secret());
        assert_eq!(opened.list_salt, SALT);
        let list_key = Member::salted(&Member::from_bytes(owner.member()).expect("member"), &SALT)
            .expect("list key");
        assert_eq!(
            store.credential_by_list_key(list_key.as_bytes()),
            Some(held)
        );
    }
    assert_eq!(position, HistoryPosition::after_slot(CONTEXT));
}

#[tokio::test]
async fn a_partial_scan_reads_unknown_and_the_next_refresh_completes() {
    let auditor = X25519Keypair::new();
    let late = Owner::new(13);
    let rows = (MAX_CREDENTIAL_PAGES as u64) * u64::from(CREDENTIAL_PAGE_ROWS.get()) + 5;
    let chain = Chain::with_rows(rows, &[(&late, rows)], &auditor.pubkey());
    let store = AuditStore::default();
    let mut position = HistoryPosition::default();

    let first = scan(&chain, &auditor, &store, &mut position)
        .await
        .expect("scan");
    assert_eq!(first, ScanEnd::Partial);
    assert_eq!(store.credential(&late.member()), None);

    let second = scan(&chain, &auditor, &store, &mut position)
        .await
        .expect("scan");
    assert_eq!(second, ScanEnd::Complete);
    assert!(store.credential(&late.member()).is_some());
}

#[tokio::test]
async fn a_malformed_page_keeps_the_held_credentials_and_a_retry_completes() {
    let auditor = X25519Keypair::new();
    let (held, next) = (Owner::new(14), Owner::new(15));
    let chain = Chain::with_rows(250, &[(&held, 2), (&next, 120)], &auditor.pubkey());
    let store = AuditStore::default();
    let mut position = HistoryPosition::default();
    // Each case applies the first page untouched and refuses the second.
    let empty: Tamper = Box::new(|page| page.data.clear());
    let truncated: Tamper = Box::new(|page| {
        page.data.pop();
        page.pagination_token = page
            .data
            .last()
            .map(|row| PaginationToken::new(row.slot, row.signature));
    });
    let repeated: Tamper = Box::new(|page| {
        let first = page.data[0].clone();
        page.data[1] = first;
    });
    let skipped: Tamper = Box::new(|page| {
        page.data.pop();
    });
    let foreign_row: Tamper = Box::new(|page| {
        let event = page.data[19].events[0].clone();
        page.data[18].events.push(event);
    });
    for (name, tamper) in [
        ("empty", empty),
        ("truncated", truncated),
        ("repeated", repeated),
        ("skipped", skipped),
        ("foreign row", foreign_row),
    ] {
        let mut resumed = position;
        chain.tamper(|_| {});
        chain.tampers.lock().expect("tampers").push_back(tamper);
        let refused = scan(&chain, &auditor, &store, &mut resumed).await;
        assert_eq!(refusal(refused), CredentialRefusal::PageShape, "{name}");
        assert!(store.credential(&held.member()).is_some(), "{name}");
        assert_eq!(store.credential(&next.member()), None, "{name}");
        chain.tampers.lock().expect("tampers").clear();
    }

    let end = scan(&chain, &auditor, &store, &mut position)
        .await
        .expect("retry");
    assert_eq!(end, ScanEnd::Complete);
    assert!(store.credential(&next.member()).is_some());
}

#[tokio::test]
async fn a_restart_recovers_every_key_from_the_retained_ciphertext() {
    let auditor = X25519Keypair::new();
    let owners = [Owner::new(16), Owner::new(17)];
    let chain = Chain::with_rows(40, &[(&owners[0], 5), (&owners[1], 30)], &auditor.pubkey());
    let before = AuditStore::default();
    scan(&chain, &auditor, &before, &mut HistoryPosition::default())
        .await
        .expect("scan");

    // A restart keeps only the auditor key, the chain still holds every sealed credential.
    let restarted = AuditStore::default();
    let end = scan(
        &chain,
        &auditor,
        &restarted,
        &mut HistoryPosition::default(),
    )
    .await
    .expect("rescan");

    assert_eq!(end, ScanEnd::Complete);
    for owner in &owners {
        let recovered = restarted.credential(&owner.member()).expect("recovered");
        assert_eq!(Some(recovered), before.credential(&owner.member()));
        assert_eq!(
            recovered
                .secrets(&auditor)
                .expect("opens")
                .nullifier_key
                .secret(),
            owner.key.secret()
        );
    }
}

#[tokio::test]
async fn a_second_credential_for_a_held_member_refuses_its_page() {
    let auditor = X25519Keypair::new();
    let owner = Owner::new(18);
    let mut chain = Chain::with_rows(3, &[(&owner, 1)], &auditor.pubkey());
    let store = AuditStore::default();
    let mut position = HistoryPosition::default();
    scan(&chain, &auditor, &store, &mut position)
        .await
        .expect("scan");
    let held = store.credential(&owner.member()).expect("held");

    let rotated = Owner {
        wallet: Keypair::new_from_array([18; 32]),
        key: NullifierKey::from_secret([19; 31]),
    };
    let auditor_pubkey = auditor.pubkey();
    let enrollment = rotated.enrollment(&auditor_pubkey, CONTEXT + 1);
    chain.rows.push(Row {
        slot: CONTEXT + 1,
        signature: signature(CONTEXT + 1),
        events: vec![enrollment.event_of(&enrollment.credential())],
    });
    chain
        .accounts
        .insert(signature(CONTEXT + 1), vec![rotated.wallet.pubkey()]);
    chain.tamper(|page| page.context.slot = CONTEXT + 1);

    let refused = scan(&chain, &auditor, &store, &mut position).await;
    assert_eq!(refusal(refused), CredentialRefusal::Conflict);
    assert_eq!(store.credential(&owner.member()), Some(held));
}

#[tokio::test]
async fn a_forged_output_a_foreign_auditor_and_an_unnamed_owner_are_refused() {
    let auditor = X25519Keypair::new();
    let owner = Owner::new(20);
    let cases: [(&str, Forge, CredentialRefusal); 3] = [
        (
            "forged payload",
            Box::new(|chain| {
                let payload = &mut chain.rows[0].events[0].output_slots[0].payload;
                let last = payload.len() - 1;
                payload[last] ^= 1;
            }),
            CredentialRefusal::OutputMismatch,
        ),
        (
            "foreign auditor",
            Box::new(|chain| {
                let other = X25519Keypair::new().pubkey();
                let enrollment = Owner::new(20);
                let enrollment = enrollment.enrollment(&other, 1);
                chain.rows[0].events = vec![enrollment.event_of(&enrollment.credential())];
            }),
            CredentialRefusal::ForeignAuditor,
        ),
        (
            "unnamed owner",
            Box::new(|chain| {
                chain.accounts.insert(signature(1), vec![PAYER]);
            }),
            CredentialRefusal::OwnerUnresolved,
        ),
    ];
    for (name, forge, expected) in cases {
        let mut chain = Chain::with_rows(2, &[(&owner, 1)], &auditor.pubkey());
        forge(&mut chain);
        let store = AuditStore::default();
        let mut position = HistoryPosition::default();
        let refused = scan(&chain, &auditor, &store, &mut position).await;
        assert_eq!(refusal(refused), expected, "{name}");
        assert_eq!(store.credential(&owner.member()), None, "{name}");
        assert_eq!(position, HistoryPosition::default(), "{name}");
    }
}

#[tokio::test]
async fn a_restart_resumes_the_scan_after_its_last_committed_page() {
    let auditor = X25519Keypair::new();
    let owners = [Owner::new(18), Owner::new(19)];
    let chain = Chain::with_rows(
        250,
        &[(&owners[0], 5), (&owners[1], 230)],
        &auditor.pubkey(),
    );
    let database = Store::open("sqlite::memory:", 1).await.expect("store");
    let seal = NoteSeal::derive(&auditor, RING).expect("seal");
    let lease = LeaseClaim {
        db: database.connection(),
        ring: RING,
        holder: database.lease_holder(),
        now: 1_000,
    }
    .claim()
    .await
    .expect("claim")
    .expect("held");
    let writer = ProjectionWriter {
        db: database.connection(),
        ring: RING,
        seal: &seal,
        lease,
        clock: Clock::Fixed(1_000),
    };
    // 1. The first page commits, a truncated second page stops the scan.
    chain.tamper(|_| {});
    chain.tamper(|page| {
        page.data.pop();
    });
    let mut position = HistoryPosition::default();
    let stopped = CredentialScan {
        ring: RING,
        auditor: &auditor,
        source: &chain,
        store: &AuditStore::default(),
        durable: Some(&writer),
    }
    .run(&mut position)
    .await;
    assert_eq!(refusal(stopped), CredentialRefusal::PageShape);

    // 2. A restart holds the first page's credential and reads on from the page after it.
    let loaded = LoadSpends {
        db: database.connection(),
        ring: RING,
        seal: &seal,
        scope: HistoryScope::Everything,
    }
    .load()
    .await
    .expect("load");
    assert_eq!(loaded.credential_position, position);
    let restarted = AuditStore::default();
    restarted
        .admit_credentials(loaded.credentials)
        .expect("admit");
    assert!(restarted.credential(&owners[0].member()).is_some());
    chain.requests.lock().expect("requests").clear();
    let mut resumed = loaded.credential_position;
    let end = scan(&chain, &auditor, &restarted, &mut resumed)
        .await
        .expect("resume");

    assert_eq!(end, ScanEnd::Complete);
    let requests = chain.requests.lock().expect("requests").clone();
    assert_eq!(requests.len(), 2, "the pages after the commit and no other");
    assert_eq!(requests[0], position);
    assert!(restarted.credential(&owners[1].member()).is_some());
}
