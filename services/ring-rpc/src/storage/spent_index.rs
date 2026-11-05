//! A ring's durable projection, what its auditor opened and the frames it could not read.
//!
//! The lease holder writes it, each commit fenced by the lease. Every replica reads it from one
//! snapshot, so a load never pairs a newer checkpoint with an older spend. Read after
//! `storage/projection_lease.rs`.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use borsh::BorshDeserialize;
use custom_ring_interface::AuditCredential;
use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr,
    IsolationLevel, QueryResult, Statement, TransactionTrait, Value,
};
use sha2::Sha256;
use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::{Context, PaginationToken};
use spr_keypair::X25519Keypair;
use zolana_ring_client::{history::HistoryPosition, KnownUtxo, UtxoOwner};

use crate::{
    credentials::{CredentialLeaf, HeldCredential},
    frame_repairs::RepairAttempt,
    hub::Clock,
    projection_lease::ProjectionLease,
    spend_machine::{SpendRow, SpendState},
    utxos::{CreatedIn, PageDelta, StoredUtxo},
};

const NOTE_SEAL_INFO: &[u8] = b"zolana/ring-rpc-note-seal";
const NONCE_LEN: usize = 12;
const NOTE_BODY_LEN: usize =
    32 + 1 + 32 + 32 + 1 + 32 + 8 + 32 + 32 + 32 + 2 + 1 + 8 + 64 + 2 + 4 + 8 + 1 + 32;

/// Keys the note rows of one ring, a stolen database opens no note.
pub(crate) struct NoteSeal {
    cipher: Aes256Gcm,
    ring: Address,
}

/// The durable resume point, the history slot moves only at a terminal page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Checkpoint {
    pub position: HistoryPosition,
    pub through: Context,
}

/// The repair schedule lists only frames that failed a repair.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LoadedProjection {
    pub spends: LoadedSpends,
    pub repairs: Vec<(CreatedIn, RepairAttempt)>,
    pub credentials: Vec<HeldCredential>,
    pub credential_position: HistoryPosition,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LoadedSpends {
    pub checkpoint: Checkpoint,
    pub notes: Vec<([u8; 32], StoredUtxo)>,
    pub rows: Vec<SpendRow>,
    pub unread: Vec<CreatedIn>,
    pub faults: Vec<SpendRow>,
}

impl NoteSeal {
    pub(crate) fn derive(auditor: &X25519Keypair, ring: Address) -> Result<Self, DbErr> {
        let unusable = || DbErr::Custom("note seal key is unusable".into());
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<Sha256>::new(None, auditor.secret_bytes().as_slice())
            .expand(NOTE_SEAL_INFO, key.as_mut_slice())
            .map_err(|_| unusable())?;
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| unusable())?,
            ring,
        })
    }

    /// The ring and the row key bind the body, a row moved to another key fails to open.
    fn seal(&self, row_key: &[u8; 32], body: &[u8]) -> Result<Vec<u8>, DbErr> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = [self.ring.as_ref(), row_key.as_slice()].concat();
        let sealed = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: body,
                    aad: &aad,
                },
            )
            .map_err(|_| DbErr::Custom("note row failed to seal".into()))?;
        Ok([nonce.as_slice(), &sealed].concat())
    }

    fn open(&self, row_key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, DbErr> {
        let refused = || DbErr::Custom("note row does not open under the auditor key".into());
        let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN).ok_or_else(refused)?;
        let aad = [self.ring.as_ref(), row_key.as_slice()].concat();
        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| refused())
    }
}

/// The one layout of a sealed note.
fn note_body(note: &StoredUtxo) -> Vec<u8> {
    let utxo = &note.utxo;
    let (owner_kind, owner_field) = match utxo.owner {
        UtxoOwner::Keyed { nullifier_pk } => (0u8, nullifier_pk),
        UtxoOwner::Deposited { owner_hash } => (1u8, owner_hash),
    };
    let mint = utxo.mint.map_or([0; 32], |mint| mint.to_bytes());
    let nullifier = note.nullifier.unwrap_or_default();
    [
        utxo.owner_key.as_slice(),
        &[owner_kind],
        &owner_field,
        &utxo.asset,
        &[u8::from(utxo.mint.is_some())],
        &mint,
        &utxo.amount.to_be_bytes(),
        &utxo.blinding,
        &utxo.data_hash,
        &utxo.ring_data_hash,
        &utxo.tree_id.to_be_bytes(),
        &[u8::from(note.ring_note)],
        &note.created_in.slot.to_be_bytes(),
        note.created_in.tx_signature.as_ref(),
        &note.created_in.event_index.to_be_bytes(),
        &note.slot_index.to_be_bytes(),
        &note.leaf_index.to_be_bytes(),
        &[u8::from(note.nullifier.is_some())],
        &nullifier,
    ]
    .concat()
}

fn note_from_body(body: &[u8]) -> Result<StoredUtxo, DbErr> {
    let malformed = || DbErr::Custom("note body has another layout".into());
    if body.len() != NOTE_BODY_LEN {
        return Err(malformed());
    }
    let mut rest = body;
    let mut take = |len: usize| {
        let (taken, tail) = rest.split_at(len);
        rest = tail;
        taken
    };
    fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        out
    }
    let owner_key = array(take(32));
    let owner_kind = take(1)[0];
    let owner_field: [u8; 32] = array(take(32));
    let owner = match owner_kind {
        0 => UtxoOwner::Keyed {
            nullifier_pk: owner_field,
        },
        1 => UtxoOwner::Deposited {
            owner_hash: owner_field,
        },
        _ => return Err(malformed()),
    };
    let asset = array(take(32));
    let has_mint = take(1)[0] == 1;
    let mint_bytes: [u8; 32] = array(take(32));
    let amount = u64::from_be_bytes(array(take(8)));
    let blinding = array(take(32));
    let data_hash = array(take(32));
    let ring_data_hash = array(take(32));
    let tree_id = u16::from_be_bytes(array(take(2)));
    let ring_note = take(1)[0] == 1;
    let slot = u64::from_be_bytes(array(take(8)));
    let tx_signature = Signature::from(array::<64>(take(64)));
    let event_index = u16::from_be_bytes(array(take(2)));
    let slot_index = u32::from_be_bytes(array(take(4)));
    let leaf_index = u64::from_be_bytes(array(take(8)));
    let has_nullifier = take(1)[0] == 1;
    let nullifier: [u8; 32] = array(take(32));
    Ok(StoredUtxo {
        utxo: KnownUtxo {
            owner_key,
            owner,
            asset,
            mint: has_mint.then(|| Address::new_from_array(mint_bytes)),
            amount,
            blinding,
            data_hash,
            ring_data_hash,
            tree_id,
        },
        created_in: CreatedIn {
            slot,
            tx_signature,
            event_index,
        },
        slot_index,
        leaf_index,
        ring_note,
        nullifier: has_nullifier.then_some(nullifier),
    })
}

fn state_name(state: SpendState) -> &'static str {
    match state {
        SpendState::Observed => "observed",
        SpendState::Padding => "padding",
        SpendState::Address => "address",
        SpendState::External => "external",
        SpendState::Resolved { .. } => "resolved",
        SpendState::UnresolvedReal => "unresolved",
    }
}

fn state_of(name: &str, link: Option<[u8; 32]>) -> Result<SpendState, DbErr> {
    match (name, link) {
        ("observed", None) => Ok(SpendState::Observed),
        ("padding", None) => Ok(SpendState::Padding),
        ("address", None) => Ok(SpendState::Address),
        ("external", None) => Ok(SpendState::External),
        ("resolved", Some(note)) => Ok(SpendState::Resolved { note }),
        ("unresolved", None) => Ok(SpendState::UnresolvedReal),
        _ => Err(DbErr::Custom(format!("unknown spend state {name}"))),
    }
}

fn state_link(state: SpendState) -> Option<[u8; 32]> {
    match state {
        SpendState::Resolved { note } => Some(note),
        SpendState::UnresolvedReal
        | SpendState::Observed
        | SpendState::Padding
        | SpendState::Address
        | SpendState::External => None,
    }
}

fn slot_value(slot: u64) -> Result<Value, DbErr> {
    i64::try_from(slot)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("spend slot exceeds the column range".into()))
}

fn frame_values(ring: &Address, frame: &CreatedIn) -> Result<Vec<Value>, DbErr> {
    Ok(vec![
        ring.as_ref().to_vec().into(),
        slot_value(frame.slot)?,
        frame.tx_signature.as_ref().to_vec().into(),
        i32::from(frame.event_index).into(),
    ])
}

fn read_bytes<const N: usize>(row: &QueryResult, column: &str) -> Result<[u8; N], DbErr> {
    <[u8; N]>::try_from(row.try_get::<Vec<u8>>("", column)?)
        .map_err(|_| DbErr::Custom(format!("spend column {column} has another length")))
}

fn read_frame(row: &QueryResult) -> Result<CreatedIn, DbErr> {
    Ok(CreatedIn {
        slot: u64::try_from(row.try_get::<i64>("", "slot")?)
            .map_err(|_| DbErr::Custom("negative spend slot".into()))?,
        tx_signature: Signature::from(read_bytes::<64>(row, "tx_signature")?),
        event_index: u16::try_from(row.try_get::<i32>("", "event_index")?)
            .map_err(|_| DbErr::Custom("spend event index out of range".into()))?,
    })
}

fn position_values(position: &HistoryPosition) -> Result<[Value; 2], DbErr> {
    Ok([
        Value::BigInt(
            position
                .checkpoint()
                .map(i64::try_from)
                .transpose()
                .map_err(|_| DbErr::Custom("position exceeds the column range".into()))?,
        ),
        Value::String(position.token().map(|token| Box::new(token.to_string()))),
    ])
}

/// A token resumes inside a slot, `after_slot` alone resumes past a terminal page.
fn read_position(row: &QueryResult) -> Result<HistoryPosition, DbErr> {
    Ok(match row.try_get::<Option<String>>("", "token")? {
        Some(token) => HistoryPosition::resume(
            token
                .parse::<PaginationToken>()
                .map_err(|_| DbErr::Custom("checkpoint token does not parse".into()))?,
        ),
        None => row
            .try_get::<Option<i64>>("", "after_slot")?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| DbErr::Custom("negative checkpoint slot".into()))?
            .map_or_else(HistoryPosition::default, HistoryPosition::after_slot),
    })
}

/// The one layout of a sealed credential, the Borsh credential last.
fn credential_body(held: &HeldCredential) -> Result<Vec<u8>, DbErr> {
    let credential = borsh::to_vec(&held.credential)
        .map_err(|_| DbErr::Custom("credential does not encode".into()))?;
    Ok([
        held.owner_key.as_slice(),
        &held.owner_hash,
        &held.address,
        &held.leaf.utxo_hash,
        &held.leaf.tree_id.to_be_bytes(),
        &held.leaf.leaf_index.to_be_bytes(),
        &held.list_key,
        &credential,
    ]
    .concat())
}

fn credential_from_body(body: &[u8]) -> Result<HeldCredential, DbErr> {
    let malformed = || DbErr::Custom("credential body has another layout".into());
    let (owner_key, rest) = body.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (owner_hash, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (address, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (utxo_hash, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    let (tree_id, rest) = rest.split_first_chunk::<2>().ok_or_else(malformed)?;
    let (leaf_index, rest) = rest.split_first_chunk::<8>().ok_or_else(malformed)?;
    let (list_key, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
    Ok(HeldCredential {
        owner_key: *owner_key,
        owner_hash: *owner_hash,
        address: *address,
        credential: AuditCredential::try_from_slice(rest).map_err(|_| malformed())?,
        leaf: CredentialLeaf {
            utxo_hash: *utxo_hash,
            tree_id: u16::from_be_bytes(*tree_id),
            leaf_index: u64::from_be_bytes(*leaf_index),
        },
        list_key: *list_key,
    })
}

/// The lease holder's writes, each transaction fenced by the lease before its first row.
pub(crate) struct ProjectionWriter<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub seal: &'a NoteSeal,
    pub lease: ProjectionLease,
    pub clock: Clock,
}

impl ProjectionWriter<'_> {
    async fn begin(&self) -> Result<DatabaseTransaction, DbErr> {
        let now = self
            .clock
            .now()
            .map_err(|_| DbErr::Custom("the clock is unreadable".into()))?;
        let transaction = self.db.begin().await?;
        self.lease.fence(&transaction, now).await?;
        Ok(transaction)
    }

    fn ring_value(&self) -> Value {
        Value::from(self.ring.as_ref().to_vec())
    }

    /// Every write of one page commits together, or none does.
    pub(crate) async fn commit_page(&self, delta: &PageDelta) -> Result<(), DbErr> {
        let Self { ring, seal, .. } = self;
        let transaction = self.begin().await?;
        let backend = transaction.get_database_backend();
        let run =
            |sql: &str, values: Vec<Value>| Statement::from_sql_and_values(backend, sql, values);
        for (commitment, note) in delta.notes() {
            let sealed = seal.seal(commitment, &note_body(note))?;
            transaction
                .execute(run(
                    "INSERT INTO finalized_notes(ring,commitment,sealed) VALUES($1,$2,$3) \
                     ON CONFLICT(ring,commitment) DO UPDATE SET sealed=excluded.sealed",
                    vec![self.ring_value(), commitment.to_vec().into(), sealed.into()],
                ))
                .await?;
        }
        for row in delta.rows() {
            let link = state_link(row.state)
                .map(|note| seal.seal(&row.nullifier, &note))
                .transpose()?;
            let mut values = vec![self.ring_value(), row.nullifier.to_vec().into()];
            values.extend([
                slot_value(row.frame.slot)?,
                row.frame.tx_signature.as_ref().to_vec().into(),
                i32::from(row.frame.event_index).into(),
                i32::from(row.position).into(),
                state_name(row.state).into(),
                Value::Bytes(link.map(Box::new)),
            ]);
            transaction
                .execute(run(
                    "INSERT INTO finalized_spent_nullifiers(ring,nullifier,slot,tx_signature, \
                     event_index,position,state,sealed_note) VALUES($1,$2,$3,$4,$5,$6,$7,$8) \
                     ON CONFLICT(ring,nullifier) DO UPDATE SET state=excluded.state, \
                     sealed_note=excluded.sealed_note",
                    values,
                ))
                .await?;
        }
        for fault in delta.faults() {
            let mut values = frame_values(ring, &fault.frame)?;
            values.push(fault.nullifier.to_vec().into());
            transaction
                .execute(run(
                    "INSERT INTO spend_integrity_faults(ring,slot,tx_signature,event_index, \
                     nullifier) VALUES($1,$2,$3,$4,$5) \
                     ON CONFLICT(ring,nullifier,tx_signature,event_index) DO NOTHING",
                    values,
                ))
                .await?;
        }
        for frame in delta.read_frames() {
            transaction
                .execute(run(
                    "DELETE FROM spend_unread_frames WHERE ring=$1 AND tx_signature=$2 \
                     AND event_index=$3",
                    vec![
                        self.ring_value(),
                        frame.tx_signature.as_ref().to_vec().into(),
                        i32::from(frame.event_index).into(),
                    ],
                ))
                .await?;
        }
        // A frame unread again keeps its attempt count, the repair schedule owns it.
        for frame in delta.unread_frames() {
            transaction
                .execute(run(
                    "INSERT INTO spend_unread_frames(ring,slot,tx_signature,event_index) \
                     VALUES($1,$2,$3,$4) ON CONFLICT(ring,tx_signature,event_index) DO NOTHING",
                    frame_values(ring, frame)?,
                ))
                .await?;
        }
        if let Some(checkpoint) = delta.checkpoint() {
            let [after_slot, token] = position_values(&checkpoint.position)?;
            transaction
                .execute(run(
                    "INSERT INTO spend_checkpoints(ring,after_slot,token,through_slot,block_time) \
                     VALUES($1,$2,$3,$4,$5) ON CONFLICT(ring) DO UPDATE SET \
                     after_slot=excluded.after_slot,token=excluded.token, \
                     through_slot=excluded.through_slot,block_time=excluded.block_time",
                    vec![
                        self.ring_value(),
                        after_slot,
                        token,
                        slot_value(checkpoint.through.slot)?,
                        checkpoint.through.block_time.into(),
                    ],
                ))
                .await?;
        }
        transaction.commit().await
    }

    /// A page's credentials and the scan position past it commit together.
    pub(crate) async fn commit_credentials(
        &self,
        held: &[HeldCredential],
        position: &HistoryPosition,
    ) -> Result<(), DbErr> {
        let transaction = self.begin().await?;
        let backend = transaction.get_database_backend();
        for credential in held {
            let member = credential.member();
            let sealed = self.seal.seal(&member, &credential_body(credential)?)?;
            transaction
                .execute(Statement::from_sql_and_values(
                    backend,
                    "INSERT INTO held_credentials(ring,member,sealed) VALUES($1,$2,$3) \
                     ON CONFLICT(ring,member) DO NOTHING",
                    vec![self.ring_value(), member.to_vec().into(), sealed.into()],
                ))
                .await?;
        }
        let [after_slot, token] = position_values(position)?;
        transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO credential_checkpoints(ring,after_slot,token) VALUES($1,$2,$3) \
                 ON CONFLICT(ring) DO UPDATE SET after_slot=excluded.after_slot, \
                 token=excluded.token",
                vec![self.ring_value(), after_slot, token],
            ))
            .await?;
        transaction.commit().await
    }

    pub(crate) async fn record_attempts(
        &self,
        attempts: &[(CreatedIn, RepairAttempt)],
    ) -> Result<(), DbErr> {
        let transaction = self.begin().await?;
        for (frame, attempt) in attempts {
            transaction
                .execute(Statement::from_sql_and_values(
                    transaction.get_database_backend(),
                    "UPDATE spend_unread_frames SET attempts=$1,retry_after=$2 WHERE ring=$3 \
                     AND tx_signature=$4 AND event_index=$5",
                    vec![
                        i64::from(attempt.attempts).into(),
                        slot_value(attempt.retry_after)?,
                        self.ring_value(),
                        frame.tx_signature.as_ref().to_vec().into(),
                        i32::from(frame.event_index).into(),
                    ],
                ))
                .await?;
        }
        transaction.commit().await
    }
}

/// Reads every row of one ring from one snapshot, a commit between two reads shows in neither.
#[must_use]
pub(crate) struct LoadSpends<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub seal: &'a NoteSeal,
}

impl LoadSpends<'_> {
    pub(crate) async fn load(self) -> Result<LoadedProjection, DbErr> {
        let snapshot = read_snapshot(self.db).await?;
        let loaded = self.read(&snapshot).await?;
        snapshot.commit().await?;
        Ok(loaded)
    }

    async fn read(&self, snapshot: &DatabaseTransaction) -> Result<LoadedProjection, DbErr> {
        let Self { ring, seal, .. } = self;
        let query = |sql: &str| {
            Statement::from_sql_and_values(
                snapshot.get_database_backend(),
                sql,
                vec![Value::from(ring.as_ref().to_vec())],
            )
        };
        let mut loaded = LoadedProjection::default();
        let spends = &mut loaded.spends;
        for row in snapshot
            .query_all(query(
                "SELECT commitment,sealed FROM finalized_notes WHERE ring=$1",
            ))
            .await?
        {
            let commitment: [u8; 32] = read_bytes(&row, "commitment")?;
            let body = seal.open(&commitment, &row.try_get::<Vec<u8>>("", "sealed")?)?;
            spends.notes.push((commitment, note_from_body(&body)?));
        }
        for row in snapshot
            .query_all(query(
                "SELECT nullifier,slot,tx_signature,event_index,position,state,sealed_note \
                 FROM finalized_spent_nullifiers WHERE ring=$1",
            ))
            .await?
        {
            let nullifier: [u8; 32] = read_bytes(&row, "nullifier")?;
            let link = row
                .try_get::<Option<Vec<u8>>>("", "sealed_note")?
                .map(|sealed| {
                    let opened = seal.open(&nullifier, &sealed)?;
                    <[u8; 32]>::try_from(opened)
                        .map_err(|_| DbErr::Custom("spend link has another length".into()))
                })
                .transpose()?;
            spends.rows.push(SpendRow {
                nullifier,
                frame: read_frame(&row)?,
                position: u16::try_from(row.try_get::<i32>("", "position")?)
                    .map_err(|_| DbErr::Custom("spend position out of range".into()))?,
                state: state_of(&row.try_get::<String>("", "state")?, link)?,
            });
        }
        for row in snapshot
            .query_all(query(
                "SELECT slot,tx_signature,event_index,attempts,retry_after FROM \
                 spend_unread_frames WHERE ring=$1",
            ))
            .await?
        {
            let frame = read_frame(&row)?;
            let attempt = RepairAttempt {
                attempts: u32::try_from(row.try_get::<i64>("", "attempts")?)
                    .map_err(|_| DbErr::Custom("repair attempts out of range".into()))?,
                retry_after: u64::try_from(row.try_get::<i64>("", "retry_after")?)
                    .map_err(|_| DbErr::Custom("negative repair time".into()))?,
            };
            spends.unread.push(frame);
            if attempt.attempts > 0 {
                loaded.repairs.push((frame, attempt));
            }
        }
        for row in snapshot
            .query_all(query(
                "SELECT nullifier,slot,tx_signature,event_index FROM spend_integrity_faults \
                 WHERE ring=$1",
            ))
            .await?
        {
            spends.faults.push(SpendRow {
                nullifier: read_bytes(&row, "nullifier")?,
                frame: read_frame(&row)?,
                position: 0,
                state: SpendState::Observed,
            });
        }
        if let Some(row) = snapshot
            .query_one(query(
                "SELECT after_slot,token,through_slot,block_time FROM spend_checkpoints \
                 WHERE ring=$1",
            ))
            .await?
        {
            spends.checkpoint = Checkpoint {
                position: read_position(&row)?,
                through: Context {
                    slot: u64::try_from(row.try_get::<i64>("", "through_slot")?)
                        .map_err(|_| DbErr::Custom("negative checkpoint slot".into()))?,
                    block_time: row.try_get("", "block_time")?,
                },
            };
        }
        for row in snapshot
            .query_all(query(
                "SELECT member,sealed FROM held_credentials WHERE ring=$1",
            ))
            .await?
        {
            let member: [u8; 32] = read_bytes(&row, "member")?;
            let body = seal.open(&member, &row.try_get::<Vec<u8>>("", "sealed")?)?;
            let held = credential_from_body(&body)?;
            if held.member() != member {
                return Err(DbErr::Custom("credential row names another member".into()));
            }
            loaded.credentials.push(held);
        }
        if let Some(row) = snapshot
            .query_one(query(
                "SELECT after_slot,token FROM credential_checkpoints WHERE ring=$1",
            ))
            .await?
        {
            loaded.credential_position = read_position(&row)?;
        }
        Ok(loaded)
    }
}

/// Postgres pins one snapshot for the transaction, a SQLite read transaction pins it at its
/// first read.
async fn read_snapshot(db: &DatabaseConnection) -> Result<DatabaseTransaction, DbErr> {
    match db.get_database_backend() {
        DatabaseBackend::Postgres => {
            db.begin_with_config(
                Some(IsolationLevel::RepeatableRead),
                Some(AccessMode::ReadOnly),
            )
            .await
        }
        DatabaseBackend::Sqlite | DatabaseBackend::MySql => db.begin().await,
    }
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod projection_tests;
