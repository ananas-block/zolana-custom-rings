//! Finalized spend rows and durable notes, one database transaction per page.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbErr, QueryResult, Statement, TransactionTrait, Value,
};
use sha2::Sha256;
use solana_address::Address;
use solana_signature::Signature;
use spr_indexer_api::{Context, PaginationToken};
use spr_keypair::X25519Keypair;
use zolana_ring_client::{history::HistoryPosition, KnownUtxo, UtxoOwner};

use crate::{
    spend_machine::{SpendRow, SpendState},
    utxos::{CreatedIn, PageDelta, StoredUtxo},
};

const NOTE_SEAL_INFO: &[u8] = b"zolana/ring-rpc-note-seal/v1";
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
        SpendState::External => "external",
        SpendState::Resolved { .. } => "resolved",
        SpendState::UnresolvedReal { .. } => "unresolved",
    }
}

fn state_of(name: &str, link: Option<[u8; 32]>) -> Result<SpendState, DbErr> {
    match (name, link) {
        ("observed", None) => Ok(SpendState::Observed),
        ("padding", None) => Ok(SpendState::Padding),
        ("external", None) => Ok(SpendState::External),
        ("resolved", Some(note)) => Ok(SpendState::Resolved { note }),
        ("unresolved", evidence) => Ok(SpendState::UnresolvedReal { evidence }),
        _ => Err(DbErr::Custom(format!("unknown spend state {name}"))),
    }
}

fn state_link(state: SpendState) -> Option<[u8; 32]> {
    match state {
        SpendState::Resolved { note } => Some(note),
        SpendState::UnresolvedReal { evidence } => evidence,
        SpendState::Observed | SpendState::Padding | SpendState::External => None,
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

/// Every write of one page commits together, or none does.
#[must_use]
pub(crate) struct PageCommit<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub seal: &'a NoteSeal,
    pub delta: &'a PageDelta,
}

impl PageCommit<'_> {
    pub(crate) async fn commit(self) -> Result<(), DbErr> {
        let Self {
            db,
            ring,
            seal,
            delta,
        } = self;
        let transaction = db.begin().await?;
        let backend = transaction.get_database_backend();
        let run =
            |sql: &str, values: Vec<Value>| Statement::from_sql_and_values(backend, sql, values);
        let ring_value = || Value::from(ring.as_ref().to_vec());
        for (commitment, note) in delta.notes() {
            let sealed = seal.seal(commitment, &note_body(note))?;
            transaction
                .execute(run(
                    "INSERT INTO finalized_notes(ring,commitment,sealed) VALUES($1,$2,$3)                      ON CONFLICT(ring,commitment) DO UPDATE SET sealed=excluded.sealed",
                    vec![ring_value(), commitment.to_vec().into(), sealed.into()],
                ))
                .await?;
        }
        for row in delta.rows() {
            let link = state_link(row.state)
                .map(|note| seal.seal(&row.nullifier, &note))
                .transpose()?;
            let mut values = vec![ring_value(), row.nullifier.to_vec().into()];
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
                    "INSERT INTO finalized_spent_nullifiers(ring,nullifier,slot,tx_signature,                     event_index,position,state,sealed_note) VALUES($1,$2,$3,$4,$5,$6,$7,$8)                      ON CONFLICT(ring,nullifier) DO UPDATE SET state=excluded.state,                     sealed_note=excluded.sealed_note",
                    values,
                ))
                .await?;
        }
        for fault in delta.faults() {
            let mut values = frame_values(&ring, &fault.frame)?;
            values.push(fault.nullifier.to_vec().into());
            transaction
                .execute(run(
                    "INSERT INTO spend_integrity_faults(ring,slot,tx_signature,event_index,                     nullifier) VALUES($1,$2,$3,$4,$5)                      ON CONFLICT(ring,nullifier,tx_signature,event_index) DO NOTHING",
                    values,
                ))
                .await?;
        }
        for frame in delta.read_frames() {
            transaction
                .execute(run(
                    "DELETE FROM spend_unread_frames WHERE ring=$1 AND tx_signature=$2                      AND event_index=$3",
                    vec![
                        ring_value(),
                        frame.tx_signature.as_ref().to_vec().into(),
                        i32::from(frame.event_index).into(),
                    ],
                ))
                .await?;
        }
        for frame in delta.unread_frames() {
            transaction
                .execute(run(
                    "INSERT INTO spend_unread_frames(ring,slot,tx_signature,event_index)                      VALUES($1,$2,$3,$4) ON CONFLICT(ring,tx_signature,event_index) DO NOTHING",
                    frame_values(&ring, frame)?,
                ))
                .await?;
        }
        if !delta.historical().is_empty() {
            SpentIndex { conn: &transaction }
                .record(delta.historical())
                .await?;
        }
        if let Some(checkpoint) = delta.checkpoint() {
            let values = vec![
                ring_value(),
                Value::BigInt(
                    checkpoint
                        .position
                        .checkpoint()
                        .map(i64::try_from)
                        .transpose()
                        .map_err(|_| DbErr::Custom("position exceeds the column range".into()))?,
                ),
                Value::String(
                    checkpoint
                        .position
                        .token()
                        .map(|token| Box::new(token.to_string())),
                ),
                slot_value(checkpoint.through.slot)?,
                checkpoint.through.block_time.into(),
            ];
            transaction
                .execute(run(
                    "INSERT INTO spend_checkpoints(ring,after_slot,token,through_slot,block_time)                      VALUES($1,$2,$3,$4,$5) ON CONFLICT(ring) DO UPDATE SET                      after_slot=excluded.after_slot,token=excluded.token,                     through_slot=excluded.through_slot,block_time=excluded.block_time",
                    values,
                ))
                .await?;
        }
        transaction.commit().await
    }
}

/// Reads every row of one ring, the store mirrors them across a restart.
#[must_use]
pub(crate) struct LoadSpends<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub seal: &'a NoteSeal,
}

impl LoadSpends<'_> {
    pub(crate) async fn load(self) -> Result<LoadedSpends, DbErr> {
        let Self { db, ring, seal } = self;
        let query = |sql: &str| {
            Statement::from_sql_and_values(
                db.get_database_backend(),
                sql,
                vec![Value::from(ring.as_ref().to_vec())],
            )
        };
        let mut loaded = LoadedSpends::default();
        for row in db
            .query_all(query(
                "SELECT commitment,sealed FROM finalized_notes WHERE ring=$1",
            ))
            .await?
        {
            let commitment: [u8; 32] = read_bytes(&row, "commitment")?;
            let body = seal.open(&commitment, &row.try_get::<Vec<u8>>("", "sealed")?)?;
            loaded.notes.push((commitment, note_from_body(&body)?));
        }
        for row in db
            .query_all(query(
                "SELECT nullifier,slot,tx_signature,event_index,position,state,sealed_note                  FROM finalized_spent_nullifiers WHERE ring=$1",
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
            loaded.rows.push(SpendRow {
                nullifier,
                frame: read_frame(&row)?,
                position: u16::try_from(row.try_get::<i32>("", "position")?)
                    .map_err(|_| DbErr::Custom("spend position out of range".into()))?,
                state: state_of(&row.try_get::<String>("", "state")?, link)?,
            });
        }
        for row in db
            .query_all(query(
                "SELECT slot,tx_signature,event_index FROM spend_unread_frames WHERE ring=$1",
            ))
            .await?
        {
            loaded.unread.push(read_frame(&row)?);
        }
        for row in db
            .query_all(query(
                "SELECT nullifier,slot,tx_signature,event_index FROM spend_integrity_faults                  WHERE ring=$1",
            ))
            .await?
        {
            loaded.faults.push(SpendRow {
                nullifier: read_bytes(&row, "nullifier")?,
                frame: read_frame(&row)?,
                position: 0,
                state: SpendState::Observed,
            });
        }
        if let Some(row) = db
            .query_one(query(
                "SELECT after_slot,token,through_slot,block_time FROM spend_checkpoints                  WHERE ring=$1",
            ))
            .await?
        {
            let position = match row.try_get::<Option<String>>("", "token")? {
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
            };
            loaded.checkpoint = Checkpoint {
                position,
                through: Context {
                    slot: u64::try_from(row.try_get::<i64>("", "through_slot")?)
                        .map_err(|_| DbErr::Custom("negative checkpoint slot".into()))?,
                    block_time: row.try_get("", "block_time")?,
                },
            };
        }
        Ok(loaded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpentSource {
    Transfer,
    Merge,
    Historical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpentCommitment {
    pub utxo_hash: [u8; 32],
    pub slot: u64,
    pub tx_signature: Signature,
    pub event_index: u16,
    pub first_nullifier: [u8; 32],
    pub source: SpentSource,
}

pub(crate) struct SpentIndex<'a, C> {
    pub conn: &'a C,
}

impl SpentSource {
    const fn name(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Merge => "merge",
            Self::Historical => "historical",
        }
    }

    fn of_name(name: &str) -> Result<Self, DbErr> {
        match name {
            "transfer" => Ok(Self::Transfer),
            "merge" => Ok(Self::Merge),
            "historical" => Ok(Self::Historical),
            _ => Err(DbErr::Custom(format!("unknown spent source {name}"))),
        }
    }
}

impl<C: ConnectionTrait> SpentIndex<'_, C> {
    /// The first event that names a commitment holds its row, a replay changes nothing.
    pub async fn record(&self, rows: &[SpentCommitment]) -> Result<(), DbErr> {
        let sql =
            "INSERT INTO finalized_spent_commitments(utxo_hash,slot,tx_signature,event_index,\
                   first_nullifier,source) VALUES($1,$2,$3,$4,$5,$6) \
                   ON CONFLICT(utxo_hash) DO NOTHING";
        for row in rows {
            let slot = i64::try_from(row.slot)
                .map_err(|_| DbErr::Custom("spent slot exceeds the column range".into()))?;
            let values: Vec<Value> = vec![
                row.utxo_hash.to_vec().into(),
                slot.into(),
                row.tx_signature.as_ref().to_vec().into(),
                i32::from(row.event_index).into(),
                row.first_nullifier.to_vec().into(),
                row.source.name().into(),
            ];
            self.conn
                .execute(Statement::from_sql_and_values(
                    self.conn.get_database_backend(),
                    sql,
                    values,
                ))
                .await?;
        }
        Ok(())
    }

    /// Every row, the store mirrors them across a restart.
    pub async fn rows(&self) -> Result<Vec<SpentCommitment>, DbErr> {
        let sql = "SELECT utxo_hash,slot,tx_signature,event_index,first_nullifier,source \
                   FROM finalized_spent_commitments";
        self.conn
            .query_all(Statement::from_string(
                self.conn.get_database_backend(),
                sql,
            ))
            .await?
            .iter()
            .map(spent_row)
            .collect()
    }
}

fn spent_row(row: &QueryResult) -> Result<SpentCommitment, DbErr> {
    let hash = |column| {
        <[u8; 32]>::try_from(row.try_get::<Vec<u8>>("", column)?)
            .map_err(|_| DbErr::Custom(format!("spent column {column} has another length")))
    };
    let signature = <[u8; 64]>::try_from(row.try_get::<Vec<u8>>("", "tx_signature")?)
        .map_err(|_| DbErr::Custom("spent signature has another length".into()))?;
    Ok(SpentCommitment {
        utxo_hash: hash("utxo_hash")?,
        slot: u64::try_from(row.try_get::<i64>("", "slot")?)
            .map_err(|_| DbErr::Custom("negative spent slot".into()))?,
        tx_signature: Signature::from(signature),
        event_index: u16::try_from(row.try_get::<i32>("", "event_index")?)
            .map_err(|_| DbErr::Custom("spent event index out of range".into()))?,
        first_nullifier: hash("first_nullifier")?,
        source: SpentSource::of_name(&row.try_get::<String>("", "source")?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Store;

    fn row(hash: u8, slot: u64, source: SpentSource) -> SpentCommitment {
        SpentCommitment {
            utxo_hash: [hash; 32],
            slot,
            tx_signature: Signature::from([hash; 64]),
            event_index: 3,
            first_nullifier: [9; 32],
            source,
        }
    }

    #[tokio::test]
    async fn a_replayed_row_keeps_the_first_event_that_named_it() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let index = SpentIndex {
            conn: store.connection(),
        };
        let first = row(1, 10, SpentSource::Merge);
        index.record(&[first]).await.expect("first");
        index
            .record(&[row(1, 20, SpentSource::Transfer)])
            .await
            .expect("replay");
        assert_eq!(index.rows().await.expect("rows"), [first]);
    }

    #[tokio::test]
    async fn every_source_reads_back_as_written() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let index = SpentIndex {
            conn: store.connection(),
        };
        let rows = [
            row(1, 1, SpentSource::Transfer),
            row(2, 2, SpentSource::Merge),
            row(3, 3, SpentSource::Historical),
        ];
        index.record(&rows).await.expect("record");
        let mut read = index.rows().await.expect("rows");
        read.sort_by_key(|row| row.slot);
        assert_eq!(read, rows);
    }

    #[tokio::test]
    async fn finalized_rows_survive_restart_without_loading_confirmed_rows() {
        let path = std::env::temp_dir().join(format!(
            "finalized-spent-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let store = Store::open(&url, 1).await.expect("store");
        store
            .connection()
            .execute_unprepared(
                "INSERT INTO spent_commitments VALUES(zeroblob(32),1,zeroblob(64),0,\
                 zeroblob(32),'transfer')",
            )
            .await
            .expect("confirmed row");
        let index = SpentIndex {
            conn: store.connection(),
        };
        assert!(index.rows().await.expect("empty index").is_empty());
        let finalized = row(3, 4, SpentSource::Merge);
        index.record(&[finalized]).await.expect("finalized row");
        store
            .connection()
            .execute_unprepared("INSERT INTO relay_relays VALUES(zeroblob(32),'confirmed','{}')")
            .await
            .expect("finalized relay");
        drop(store);

        let restarted = Store::open(&url, 1).await.expect("restart");
        let index = SpentIndex {
            conn: restarted.connection(),
        };
        assert_eq!(index.rows().await.expect("finalized rows"), [finalized]);
        let confirmed = restarted
            .connection()
            .query_one(Statement::from_string(
                restarted.connection().get_database_backend(),
                "SELECT COUNT(*) AS count FROM spent_commitments".to_owned(),
            ))
            .await
            .expect("confirmed query")
            .expect("confirmed count");
        assert_eq!(confirmed.try_get::<i64>("", "count").expect("count"), 1);
    }
}
