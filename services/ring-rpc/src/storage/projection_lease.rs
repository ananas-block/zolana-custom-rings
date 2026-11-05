//! One replica writes a ring's projection, every other replica reloads what it committed.
//!
//! A claim takes the lease row when its holder renews it or its expiry passed, and a new holder
//! moves the fencing token. Every projection transaction first renews the row by holder and token.
//! The row lock orders that write against a concurrent claim, so a writer whose token moved
//! commits nothing. Read before `storage/spent_index.rs`.

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbErr, Statement, TransactionTrait,
    Value,
};
use solana_address::Address;

/// Seconds a lease outlives its last claim or commit, a few backfill intervals.
pub(crate) const PROJECTION_LEASE_TTL: u64 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProjectionLease {
    ring: Address,
    holder: [u8; 16],
    token: i64,
}

#[must_use]
pub(crate) struct LeaseClaim<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub holder: [u8; 16],
    /// Unix seconds.
    pub now: u64,
}

impl LeaseClaim<'_> {
    /// `None` while another holder's lease has not expired.
    pub(crate) async fn claim(self) -> Result<Option<ProjectionLease>, DbErr> {
        let Self {
            db,
            ring,
            holder,
            now,
        } = self;
        let transaction = db.begin().await?;
        let backend = transaction.get_database_backend();
        // 1. The holder renews in place, a taker after expiry bumps the token every older commit names.
        transaction
            .execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO projection_leases(ring,holder,token,expires_at) VALUES($1,$2,1,$3) \
                 ON CONFLICT(ring) DO UPDATE SET holder=excluded.holder, \
                 token=CASE WHEN projection_leases.holder=excluded.holder \
                 THEN projection_leases.token ELSE projection_leases.token+1 END, \
                 expires_at=excluded.expires_at \
                 WHERE projection_leases.holder=excluded.holder OR projection_leases.expires_at<=$4",
                vec![
                    ring.as_ref().to_vec().into(),
                    holder.to_vec().into(),
                    seconds(now.saturating_add(PROJECTION_LEASE_TTL))?,
                    seconds(now)?,
                ],
            ))
            .await?;
        // 2. The row read back names the holder, a refused update leaves the other holder in it.
        let row = transaction
            .query_one(Statement::from_sql_and_values(
                backend,
                "SELECT holder,token FROM projection_leases WHERE ring=$1",
                vec![ring.as_ref().to_vec().into()],
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("projection lease row is missing".into()))?;
        transaction.commit().await?;
        let held = row.try_get::<Vec<u8>>("", "holder")? == holder;
        Ok(held.then_some(ProjectionLease {
            ring,
            holder,
            token: row.try_get("", "token")?,
        }))
    }
}

impl ProjectionLease {
    /// The first write of every projection transaction, it renews the lease or refuses the commit.
    pub(crate) async fn fence(
        &self,
        transaction: &DatabaseTransaction,
        now: u64,
    ) -> Result<(), DbErr> {
        let renewed = transaction
            .execute(Statement::from_sql_and_values(
                transaction.get_database_backend(),
                "UPDATE projection_leases SET expires_at=$1 WHERE ring=$2 AND holder=$3 \
                 AND token=$4 AND expires_at>$5",
                vec![
                    seconds(now.saturating_add(PROJECTION_LEASE_TTL))?,
                    self.ring.as_ref().to_vec().into(),
                    self.holder.to_vec().into(),
                    self.token.into(),
                    seconds(now)?,
                ],
            ))
            .await?
            .rows_affected();
        if renewed != 1 {
            return Err(DbErr::Custom(
                "the projection lease expired or moved to another replica".into(),
            ));
        }
        Ok(())
    }
}

fn seconds(unix: u64) -> Result<Value, DbErr> {
    i64::try_from(unix)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("lease time exceeds the column range".into()))
}
