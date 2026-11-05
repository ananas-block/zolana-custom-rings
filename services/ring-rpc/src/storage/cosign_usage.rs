use sea_orm::{ConnectionTrait, DbErr, QueryResult, Statement, Value};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_signature::Signature;

use crate::cosign::{AssetFlow, OwnerFlow};

/// Counts until its window passes or every approver of an unconfirmed message frees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    pub owner: [u8; 32],
    pub slot: u64,
    pub flow: AssetFlow,
}

/// The one identity of a transaction across the separate signatures of its approvers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MessageDigest([u8; 32]);

pub(crate) struct UsageWindow<'a> {
    pub ring: &'a Address,
    pub assets: &'a [Address],
    pub since_slot: u64,
    /// Left out of the window, the decision adds its flows once itself.
    pub message: &'a MessageDigest,
}

/// One row per approver, owner and asset, the window counts a message once across approvers.
pub(crate) struct Reserve<'a> {
    pub signature: &'a Signature,
    pub message: &'a MessageDigest,
    pub ring: &'a Address,
    pub slot: u64,
    pub flows: &'a [OwnerFlow],
}

pub(crate) struct UsageLedger<'a, C> {
    pub conn: &'a C,
}

impl MessageDigest {
    pub fn of(message: &[u8]) -> Self {
        Self(Sha256::digest(message).into())
    }

    fn value(&self) -> Value {
        Value::from(self.0.to_vec())
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

    /// Approvers of one message hold separate rows, each frees only its own, so usage outlives
    /// a failure one relay reports while another still holds a stored `Sent` of the message.
    /// Grouping on the digest counts those rows once, the latest approver's slot holds the
    /// window. Rows of one message that disagree on an amount stay separate and all count,
    /// a disagreement never lowers the total.
    pub async fn window(&self, window: UsageWindow<'_>) -> Result<Vec<Reservation>, DbErr> {
        let sql = "SELECT asset, owner, MAX(slot) AS slot, outflow, deposited, withdrawn \
                   FROM cosign_usage \
                   WHERE ring=$1 AND asset=$2 AND slot>=$3 AND message_digest<>$4 \
                   GROUP BY message_digest, asset, owner, outflow, deposited, withdrawn";
        let mut reservations = Vec::new();
        for asset in window.assets {
            let values = vec![
                address_value(window.ring),
                address_value(asset),
                slot_value(window.since_slot)?,
                window.message.value(),
            ];
            for row in self.conn.query_all(self.statement(sql, values)).await? {
                reservations.push(reservation(&row)?);
            }
        }
        Ok(reservations)
    }

    pub async fn reserve(&self, reserve: Reserve<'_>) -> Result<(), DbErr> {
        let sql = "INSERT INTO cosign_usage(signature,asset,ring,owner,slot,outflow,deposited,\
                   withdrawn,confirmed,message_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)";
        for OwnerFlow { owner, flow } in reserve.flows {
            let values = vec![
                signature_value(reserve.signature),
                address_value(&flow.asset),
                address_value(reserve.ring),
                Value::from(owner.as_bytes().to_vec()),
                slot_value(reserve.slot)?,
                amount_value(flow.outflow),
                amount_value(flow.deposited),
                amount_value(flow.withdrawn),
                Value::from(false),
                reserve.message.value(),
            ];
            self.conn.execute(self.statement(sql, values)).await?;
        }
        Ok(())
    }

    /// One statement over every approver's rows of the message, no row settles alone.
    pub async fn confirm(&self, signature: &Signature) -> Result<(), DbErr> {
        let sql = "UPDATE cosign_usage SET confirmed=$2 WHERE message_digest IN \
                   (SELECT message_digest FROM cosign_usage WHERE signature=$1)";
        let values = vec![signature_value(signature), Value::from(true)];
        self.conn.execute(self.statement(sql, values)).await?;
        Ok(())
    }

    /// One statement over the rows of one approver, a confirmed transaction keeps its usage.
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

fn reservation(row: &QueryResult) -> Result<Reservation, DbErr> {
    let amount = |column| bytes::<16>(row, column).map(u128::from_be_bytes);
    let slot = row.try_get::<i64>("", "slot")?;
    Ok(Reservation {
        owner: bytes(row, "owner")?,
        slot: u64::try_from(slot).map_err(|_| DbErr::Custom("negative usage slot".into()))?,
        flow: AssetFlow {
            asset: Address::new_from_array(bytes(row, "asset")?),
            outflow: amount("outflow")?,
            deposited: amount("deposited")?,
            withdrawn: amount("withdrawn")?,
        },
    })
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

fn amount_value(amount: u128) -> Value {
    Value::from(amount.to_be_bytes().to_vec())
}

fn slot_value(slot: u64) -> Result<Value, DbErr> {
    i64::try_from(slot)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("usage slot exceeds the column range".into()))
}
