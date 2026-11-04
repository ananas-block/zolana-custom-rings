//! Lamports the relay may yet spend for a signed request, one row per frame or enrollment.

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbErr, QueryResult, Statement, TransactionTrait, Value,
};
use solana_address::Address;
use zolana_ring_client::rpc::RelayId;

const TOTAL_SCOPE: [u8; 32] = [0; 32];

/// Zero funds nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayBudget {
    /// Reserved and spent over the store's life, only the operator raises it.
    pub total_lamports: u64,
    /// Outstanding at once under one key.
    pub signer_lamports: u64,
}

/// The account whose rent returns on release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReservedBuffer {
    pub ring: Address,
    pub buffer: Address,
}

#[must_use]
pub(crate) struct Reserve<'a> {
    pub key: [u8; 32],
    pub relay_id: &'a RelayId,
    pub signer: Address,
    pub lamports: u64,
    /// Rent the relay never recovers once its transaction lands.
    pub landing_rent: u64,
    pub buffer: Option<ReservedBuffer>,
    /// The proven frame, a retry of the request proves nothing again.
    pub proven: Option<String>,
    pub slot: u64,
    pub budget: RelayBudget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reservation {
    pub key: [u8; 32],
    pub relay_id: RelayId,
    pub signer: Address,
    pub lamports: u64,
    pub landing_rent: u64,
    pub buffer: Option<ReservedBuffer>,
    /// Frame writes landed, a retry resumes past them.
    pub uploaded: usize,
    pub proven: Option<String>,
}

#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReserveOutcome {
    Held(Box<Reservation>),
    OverTotal,
    OverSigner,
}

pub(crate) struct RelayReservations<'a> {
    db: &'a DatabaseConnection,
}

fn value(bytes: &[u8]) -> Value {
    bytes.to_vec().into()
}

fn lamports_value(lamports: u64) -> Result<Value, DbErr> {
    i64::try_from(lamports)
        .map(Into::into)
        .map_err(|_| DbErr::Custom("lamports out of range".into()))
}

fn read_reservation(row: &QueryResult) -> Result<Reservation, DbErr> {
    let bytes32 = |column: &str| -> Result<[u8; 32], DbErr> {
        <[u8; 32]>::try_from(row.try_get::<Vec<u8>>("", column)?)
            .map_err(|_| DbErr::Custom(format!("{column} has another length")))
    };
    let optional = |column: &str| -> Result<Option<Address>, DbErr> {
        row.try_get::<Option<Vec<u8>>>("", column)?
            .map(|bytes| {
                <[u8; 32]>::try_from(bytes)
                    .map(Address::new_from_array)
                    .map_err(|_| DbErr::Custom(format!("{column} has another length")))
            })
            .transpose()
    };
    let buffer = optional("ring")?
        .zip(optional("buffer")?)
        .map(|(ring, buffer)| ReservedBuffer { ring, buffer });
    let number = |column: &str| -> Result<u64, DbErr> {
        u64::try_from(row.try_get::<i64>("", column)?)
            .map_err(|_| DbErr::Custom(format!("{column} out of range")))
    };
    Ok(Reservation {
        key: bytes32("key")?,
        relay_id: RelayId(spr_indexer_api::Hash(bytes32("relay_id")?)),
        signer: Address::new_from_array(bytes32("signer")?),
        lamports: number("lamports")?,
        landing_rent: number("landing_rent")?,
        buffer,
        uploaded: usize::try_from(number("uploaded")?)
            .map_err(|_| DbErr::Custom("uploaded out of range".into()))?,
        proven: row.try_get("", "proven")?,
    })
}

const COLUMNS: &str = "key,relay_id,signer,lamports,landing_rent,ring,buffer,uploaded,proven";

impl<'a> RelayReservations<'a> {
    pub fn new(db: &'a DatabaseConnection) -> Self {
        Self { db }
    }

    /// A held key costs nothing again, the counters and the row commit together or not at all.
    pub async fn reserve(&self, reserve: Reserve<'_>) -> Result<ReserveOutcome, DbErr> {
        if let Some(held) = self.touch(&reserve).await? {
            return Ok(ReserveOutcome::Held(Box::new(held)));
        }
        let Reserve {
            key,
            relay_id,
            signer,
            lamports,
            landing_rent,
            buffer,
            proven,
            slot,
            budget,
        } = &reserve;
        let backend = self.db.get_database_backend();
        let transaction = self.db.begin().await?;
        let raise = |scope: &[u8; 32], bound: u64| -> Result<Statement, DbErr> {
            Ok(Statement::from_sql_and_values(
                backend,
                "INSERT INTO relay_reserved(scope,committed) SELECT $1,$2 WHERE $2 <= $3 \
                 ON CONFLICT(scope) DO UPDATE SET committed = relay_reserved.committed + $2 \
                 WHERE relay_reserved.committed + $2 <= $3",
                vec![
                    value(scope),
                    lamports_value(*lamports)?,
                    lamports_value(bound)?,
                ],
            ))
        };
        if transaction
            .execute(raise(&TOTAL_SCOPE, budget.total_lamports)?)
            .await?
            .rows_affected()
            == 0
        {
            transaction.rollback().await?;
            return Ok(ReserveOutcome::OverTotal);
        }
        if transaction
            .execute(raise(signer.as_array(), budget.signer_lamports)?)
            .await?
            .rows_affected()
            == 0
        {
            transaction.rollback().await?;
            return Ok(ReserveOutcome::OverSigner);
        }
        let inserted = transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO relay_reservations(key,relay_id,signer,lamports,landing_rent,ring,\
                 buffer,uploaded,spent,proven,touched_slot) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,0,0,$8,$9) ON CONFLICT(key) DO NOTHING",
                vec![
                    value(key),
                    value(&relay_id.0 .0),
                    value(signer.as_ref()),
                    lamports_value(*lamports)?,
                    lamports_value(*landing_rent)?,
                    Value::Bytes(buffer.map(|held| Box::new(held.ring.as_ref().to_vec()))),
                    Value::Bytes(buffer.map(|held| Box::new(held.buffer.as_ref().to_vec()))),
                    Value::String(proven.clone().map(Box::new)),
                    lamports_value(*slot)?,
                ],
            ))
            .await?
            .rows_affected();
        // A concurrent reserve won the key, its row carries the charge.
        if inserted == 0 {
            transaction.rollback().await?;
            return self
                .touch(&reserve)
                .await?
                .map(|held| ReserveOutcome::Held(Box::new(held)))
                .ok_or_else(|| DbErr::Custom("a reservation vanished".into()));
        }
        transaction.commit().await?;
        self.get(key)
            .await?
            .map(|held| ReserveOutcome::Held(Box::new(held)))
            .ok_or_else(|| DbErr::Custom("a reservation vanished".into()))
    }

    pub async fn by_relay(&self, relay_id: &RelayId) -> Result<Option<Reservation>, DbErr> {
        let row = self
            .db
            .query_one(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                format!("SELECT {COLUMNS} FROM relay_reservations WHERE relay_id=$1"),
                vec![value(&relay_id.0 .0)],
            ))
            .await?;
        row.as_ref().map(read_reservation).transpose()
    }

    /// Each landed write refreshes the window, a slow upload is no abandoned one.
    pub async fn uploaded(&self, key: &[u8; 32], count: usize, slot: u64) -> Result<(), DbErr> {
        let count = u64::try_from(count).map_err(|_| DbErr::Custom("count range".into()))?;
        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                "UPDATE relay_reservations SET uploaded=$2, touched_slot=$3 WHERE key=$1",
                vec![value(key), lamports_value(count)?, lamports_value(slot)?],
            ))
            .await?;
        Ok(())
    }

    /// Counted ahead of its send, a crash never hides a landed fee.
    pub async fn charge(&self, key: &[u8; 32], lamports: u64) -> Result<(), DbErr> {
        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                "UPDATE relay_reservations SET spent = spent + $2 WHERE key=$1",
                vec![value(key), lamports_value(lamports)?],
            ))
            .await?;
        Ok(())
    }

    /// Oldest first, untouched since `before_slot`.
    pub async fn abandoned(&self, before_slot: u64, limit: u64) -> Result<Vec<Reservation>, DbErr> {
        self.db
            .query_all(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                format!(
                    "SELECT {COLUMNS} FROM relay_reservations WHERE touched_slot < $1 \
                     ORDER BY touched_slot LIMIT $2"
                ),
                vec![lamports_value(before_slot)?, lamports_value(limit)?],
            ))
            .await?
            .iter()
            .map(read_reservation)
            .collect()
    }

    /// The signer's share returns whole, the total keeps the charged fees and `landed` for good.
    pub async fn release(&self, held: &Reservation, landed: u64) -> Result<(), DbErr> {
        let backend = self.db.get_database_backend();
        let transaction = self.db.begin().await?;
        let spent = transaction
            .query_one(Statement::from_sql_and_values(
                backend,
                "SELECT spent FROM relay_reservations WHERE key=$1",
                vec![value(&held.key)],
            ))
            .await?;
        let deleted = transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "DELETE FROM relay_reservations WHERE key=$1",
                vec![value(&held.key)],
            ))
            .await?
            .rows_affected();
        let Some(spent) = spent.filter(|_| deleted != 0) else {
            return transaction.commit().await;
        };
        let spent: i64 = spent.try_get("", "spent")?;
        let returned = i128::from(held.lamports) - i128::from(spent) - i128::from(landed);
        let returned = i64::try_from(returned)
            .map_err(|_| DbErr::Custom("returned lamports out of range".into()))?;
        let lower = |scope: &[u8; 32], lamports: i64| {
            Statement::from_sql_and_values(
                backend,
                "UPDATE relay_reserved SET committed = committed - $2 WHERE scope=$1",
                vec![value(scope), lamports.into()],
            )
        };
        transaction.execute(lower(&TOTAL_SCOPE, returned)).await?;
        let share = i64::try_from(held.lamports)
            .map_err(|_| DbErr::Custom("lamports out of range".into()))?;
        transaction
            .execute(lower(held.signer.as_array(), share))
            .await?;
        // Fresh keys leave no counter row behind.
        transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "DELETE FROM relay_reserved WHERE scope=$1 AND committed=0",
                vec![value(held.signer.as_array())],
            ))
            .await?;
        transaction.commit().await
    }

    async fn get(&self, key: &[u8; 32]) -> Result<Option<Reservation>, DbErr> {
        let row = self
            .db
            .query_one(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                format!("SELECT {COLUMNS} FROM relay_reservations WHERE key=$1"),
                vec![value(key)],
            ))
            .await?;
        row.as_ref().map(read_reservation).transpose()
    }

    /// A retry under a fresh quote names the newest relay.
    async fn touch(&self, reserve: &Reserve<'_>) -> Result<Option<Reservation>, DbErr> {
        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                "UPDATE relay_reservations SET relay_id=$2, touched_slot=$3 WHERE key=$1",
                vec![
                    value(&reserve.key),
                    value(&reserve.relay_id.0 .0),
                    lamports_value(reserve.slot)?,
                ],
            ))
            .await?;
        self.get(&reserve.key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Store;

    const BUDGET: RelayBudget = RelayBudget {
        total_lamports: 100,
        signer_lamports: 60,
    };

    fn relay_id(byte: u8) -> RelayId {
        RelayId(spr_indexer_api::Hash([byte; 32]))
    }

    fn signer(byte: u8) -> Address {
        Address::new_from_array([byte; 32])
    }

    async fn reserve(
        store: &RelayReservations<'_>,
        key: u8,
        who: Address,
        lamports: u64,
    ) -> ReserveOutcome {
        let id = relay_id(key);
        store
            .reserve(Reserve {
                key: [key; 32],
                relay_id: &id,
                signer: who,
                lamports,
                landing_rent: 0,
                buffer: None,
                proven: None,
                slot: u64::from(key),
                budget: BUDGET,
            })
            .await
            .expect("reserve")
    }

    #[tokio::test]
    async fn the_bounds_refuse_before_a_row_and_a_release_returns_the_charge_once() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let ReserveOutcome::Held(first) = reserve(&store, 1, signer(1), 60).await else {
            panic!("within both bounds");
        };
        assert_eq!(
            reserve(&store, 2, signer(1), 1).await,
            ReserveOutcome::OverSigner
        );
        assert_eq!(store.by_relay(&relay_id(2)).await.expect("read"), None);
        assert!(matches!(
            reserve(&store, 3, signer(2), 40).await,
            ReserveOutcome::Held(_)
        ));
        assert_eq!(
            reserve(&store, 4, signer(3), 1).await,
            ReserveOutcome::OverTotal
        );
        store.release(&first, 0).await.expect("release");
        store.release(&first, 0).await.expect("repeat");
        assert!(matches!(
            reserve(&store, 6, signer(3), 60).await,
            ReserveOutcome::Held(_)
        ));
        assert_eq!(
            reserve(&store, 7, signer(4), 1).await,
            ReserveOutcome::OverTotal
        );
    }

    #[tokio::test]
    async fn a_held_key_is_charged_once_and_keeps_its_upload_progress() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let ReserveOutcome::Held(first) = reserve(&store, 1, signer(1), 60).await else {
            panic!("within both bounds");
        };
        store.uploaded(&first.key, 3, 9).await.expect("uploaded");
        let again = relay_id(9);
        let ReserveOutcome::Held(retried) = store
            .reserve(Reserve {
                key: first.key,
                relay_id: &again,
                signer: signer(1),
                lamports: 60,
                landing_rent: 0,
                buffer: None,
                proven: None,
                slot: 10,
                budget: BUDGET,
            })
            .await
            .expect("retry")
        else {
            panic!("the held reservation");
        };
        assert_eq!(retried.uploaded, 3);
        assert_eq!(retried.relay_id, again);
        assert!(store.abandoned(10, 8).await.expect("read").is_empty());
        assert_eq!(store.abandoned(11, 8).await.expect("read").len(), 1);
    }

    #[tokio::test]
    async fn the_total_keeps_charged_fees_and_landed_rent_and_the_signer_share_returns() {
        let database = Store::open("sqlite::memory:", 1).await.expect("store");
        let store = RelayReservations::new(database.connection());
        let ReserveOutcome::Held(first) = reserve(&store, 1, signer(1), 60).await else {
            panic!("within both bounds");
        };
        store.charge(&first.key, 5).await.expect("charge");
        store.release(&first, 15).await.expect("release");
        // The total holds 20 of 100 and the signer holds none of 60.
        assert!(matches!(
            reserve(&store, 2, signer(1), 60).await,
            ReserveOutcome::Held(_)
        ));
        assert_eq!(
            reserve(&store, 3, signer(2), 21).await,
            ReserveOutcome::OverTotal
        );
        assert!(matches!(
            reserve(&store, 4, signer(2), 20).await,
            ReserveOutcome::Held(_)
        ));
    }
}
