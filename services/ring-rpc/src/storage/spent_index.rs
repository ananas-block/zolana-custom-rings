//! Finalized spend rows are isolated from confirmed history.

use sea_orm::{ConnectionTrait, DbErr, QueryResult, Statement, Value};
use solana_signature::Signature;

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
