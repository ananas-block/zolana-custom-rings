//! Co-sign window usage, one row per signature, owner and asset, summed in SQL per cap.
//!
//! Every read and reservation runs under the `cosign_admission` row lock of its ring and asset.
//! A measure stores capped at 2^64 as two 32 bit halves in signed `BIGINT` columns, so SQL sums
//! them exactly, and any total past `u64::MAX` reads past every cap.
//!
//! Read after `services/ring-rpc/src/operations/cosign_limits.rs`.

use std::collections::HashMap;

use sea_orm::{ConnectionTrait, DbErr, QueryResult, Statement, Value};
use solana_address::Address;
use solana_signature::Signature;

use crate::cosign::{AssetFlow, OwnerFlow};

/// One past every u64 cap, the order of a capped total against a cap stays the order of the true total.
const MEASURE_CEILING: u128 = 1 << 64;

/// The quantity a cap bounds, each read from the stored halves of its columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Measure {
    Outflow,
    Volume,
    Deposited,
    Withdrawn,
}

/// Rows of one ring and asset with a slot past `after_slot`.
#[derive(Clone, Copy)]
pub(crate) struct WindowSum<'a> {
    pub ring: &'a Address,
    pub asset: &'a Address,
    pub measure: Measure,
    /// Negative counts every row.
    pub after_slot: i64,
}

pub(crate) struct Reserve<'a> {
    pub signature: &'a Signature,
    pub ring: &'a Address,
    pub slot: u64,
    pub flows: &'a [OwnerFlow],
}

pub(crate) struct UsageLedger<'a, C> {
    pub conn: &'a C,
}

impl Measure {
    /// `None` past `u128::MAX`, an overflowing measure lies past every cap.
    pub fn of(self, flow: &AssetFlow) -> Option<u128> {
        match self {
            Self::Outflow => Some(flow.charged_outflow),
            Self::Volume => flow.charged_outflow.checked_add(flow.deposited),
            Self::Deposited => Some(flow.deposited),
            Self::Withdrawn => Some(flow.withdrawn),
        }
    }

    /// Volume adds two capped columns, a sum at or past 2^64 still reads past every cap.
    fn halves(self) -> (&'static str, &'static str) {
        match self {
            Self::Outflow => ("outflow_hi", "outflow_lo"),
            Self::Volume => ("outflow_hi+deposited_hi", "outflow_lo+deposited_lo"),
            Self::Deposited => ("deposited_hi", "deposited_lo"),
            Self::Withdrawn => ("withdrawn_hi", "withdrawn_lo"),
        }
    }
}

impl<C: ConnectionTrait> UsageLedger<'_, C> {
    /// The no-op update locks each row until the transaction ends, in address order.
    pub async fn admit(&self, ring: &Address, assets: &[Address]) -> Result<(), DbErr> {
        let sql = "INSERT INTO cosign_admission(ring,asset) VALUES($1,$2) \
                   ON CONFLICT(ring,asset) DO UPDATE SET asset=excluded.asset";
        let mut ordered = assets.to_vec();
        ordered.sort_unstable();
        for asset in &ordered {
            let values = vec![address_value(ring), address_value(asset)];
            self.conn.execute(self.statement(sql, values)).await?;
        }
        Ok(())
    }

    pub async fn reserved(&self, signature: &Signature) -> Result<bool, DbErr> {
        let sql = "SELECT 1 AS reserved FROM cosign_usage WHERE signature=$1";
        let row = self
            .conn
            .query_one(self.statement(sql, vec![signature_value(signature)]))
            .await?;
        Ok(row.is_some())
    }

    /// Every owner's rows of the window, a ring cap bounds them together.
    pub async fn ring_total(&self, sum: WindowSum<'_>) -> Result<u128, DbErr> {
        let (hi, lo) = sum.measure.halves();
        let sql = format!(
            "SELECT {} FROM cosign_usage WHERE ring=$1 AND asset=$2 AND slot>$3",
            summed(hi, lo)
        );
        let row = self
            .conn
            .query_one(self.statement(&sql, sum.values()))
            .await?
            .ok_or_else(|| DbErr::Custom("an aggregate returned no row".into()))?;
        total(&row)
    }

    /// Each named owner's rows of the window, an owner with none reads zero.
    pub async fn owner_totals(
        &self,
        sum: WindowSum<'_>,
        owners: &[[u8; 32]],
    ) -> Result<HashMap<[u8; 32], u128>, DbErr> {
        if owners.is_empty() {
            return Ok(HashMap::new());
        }
        let (hi, lo) = sum.measure.halves();
        let named = (0..owners.len())
            .map(|index| format!("${}", index + 4))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT owner, {} FROM cosign_usage WHERE ring=$1 AND asset=$2 AND slot>$3 \
             AND owner IN ({named}) GROUP BY owner",
            summed(hi, lo)
        );
        let mut values = sum.values();
        values.extend(owners.iter().map(|owner| Value::from(owner.to_vec())));
        let mut totals: HashMap<_, _> = owners.iter().map(|owner| (*owner, 0)).collect();
        for row in self.conn.query_all(self.statement(&sql, values)).await? {
            totals.insert(bytes(&row, "owner")?, total(&row)?);
        }
        Ok(totals)
    }

    pub async fn reserve(&self, reserve: Reserve<'_>) -> Result<(), DbErr> {
        let sql = "INSERT INTO cosign_usage(signature,asset,ring,owner,slot,outflow_hi,outflow_lo,\
                   deposited_hi,deposited_lo,withdrawn_hi,withdrawn_lo,confirmed) \
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)";
        for OwnerFlow { owner, flow } in reserve.flows {
            let mut values = vec![
                signature_value(reserve.signature),
                address_value(&flow.asset),
                address_value(reserve.ring),
                Value::from(owner.as_bytes().to_vec()),
                slot_value(reserve.slot)?,
            ];
            for amount in [flow.charged_outflow, flow.deposited, flow.withdrawn] {
                values.extend(halves(amount));
            }
            values.push(Value::from(false));
            self.conn.execute(self.statement(sql, values)).await?;
        }
        Ok(())
    }

    pub async fn confirm(&self, signature: &Signature) -> Result<(), DbErr> {
        let sql = "UPDATE cosign_usage SET confirmed=$2 WHERE signature=$1";
        let values = vec![signature_value(signature), Value::from(true)];
        self.conn.execute(self.statement(sql, values)).await?;
        Ok(())
    }

    /// A confirmed transaction keeps its usage.
    pub async fn free(&self, signature: &Signature) -> Result<(), DbErr> {
        let sql = "DELETE FROM cosign_usage WHERE signature=$1 AND confirmed=$2";
        let values = vec![signature_value(signature), Value::from(false)];
        self.conn.execute(self.statement(sql, values)).await?;
        Ok(())
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.conn.get_database_backend(), sql, values)
    }
}

impl WindowSum<'_> {
    fn values(&self) -> Vec<Value> {
        vec![
            address_value(self.ring),
            address_value(self.asset),
            Value::from(self.after_slot),
        ]
    }
}

/// A half is below 2^33 per row, the cast refuses a sum past `i64::MAX` rather than wrap.
fn summed(hi: &str, lo: &str) -> String {
    format!(
        "CAST(COALESCE(SUM({hi}),0) AS BIGINT) AS hi, CAST(COALESCE(SUM({lo}),0) AS BIGINT) AS lo"
    )
}

fn total(row: &QueryResult) -> Result<u128, DbErr> {
    let half = |column| {
        let sum = row.try_get::<i64>("", column)?;
        u128::try_from(sum).map_err(|_| DbErr::Custom("negative usage sum".into()))
    };
    Ok((half("hi")? << 32) + half("lo")?)
}

fn halves(amount: u128) -> [Value; 2] {
    let capped = amount.min(MEASURE_CEILING);
    let half = |value: u128| Value::from(value as i64);
    [half(capped >> 32), half(capped & u128::from(u32::MAX))]
}

fn bytes<const N: usize>(row: &QueryResult, column: &str) -> Result<[u8; N], DbErr> {
    row.try_get::<Vec<u8>>("", column)?
        .try_into()
        .map_err(|_| DbErr::Custom(format!("usage column {column} has another length")))
}

fn signature_value(signature: &Signature) -> Value {
    Value::from(signature.as_ref().to_vec())
}

fn address_value(address: &Address) -> Value {
    Value::from(address.as_ref().to_vec())
}

fn slot_value(slot: u64) -> Result<Value, DbErr> {
    i64::try_from(slot)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("usage slot exceeds the column range".into()))
}
