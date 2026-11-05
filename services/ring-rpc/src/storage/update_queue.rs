use custom_ring_interface::{RecordWriteData, APPLY_BATCH};
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbErr, QueryResult, Statement, TransactionTrait, Value,
};
use solana_address::Address;
use solana_signature::Signature;
use zolana_ring_client::rpc::{RecordUpdateStatus, SubmitRecordUpdateRequest};
use zolana_ring_policy::ListSet;

use crate::{
    landing::Attempt,
    record_update::{
        authority_batch, AuthorityHead, CheckedUpdate, PendingApproval, QueuedUpdate,
        RecordUpdateRefusal, UpdateSigner, WalletBatch, MAX_BATCH_ATTEMPTS,
    },
};

/// Held off chain for list approval, never in a batch until an approval joins it.
const PENDING_APPROVAL: &str = "pending_approval";
const QUEUED: &str = "queued";
const SUBMITTED: &str = "submitted";
const APPLIED: &str = "applied";
const REFUSED: &str = "refused";
const FAILED: &str = "failed";
const PENDING_APPROVAL_COLUMNS: &str = "id, signer, member, writes, awaited, valid_until_slot";
const HEAD_COLUMNS: &str = "u.seq, u.id, u.ring, u.writes, u.signer, u.role, u.queued_slot, \
                            u.valid_until_slot";
/// Keys bound into one delete, under every backend's parameter ceiling.
const KEYS_PER_DELETE: usize = 256;
/// One update past a full batch, the planner reads whether more wallet updates wait behind it.
const OLDEST_HEADS: usize = APPLY_BATCH + 1;
const WALLET_ROLE: &str = "wallet";
const POLICY_ROLE: &str = "policy";

/// Every update keyed by its statement hash.
pub(crate) struct UpdateQueue<'a> {
    db: &'a DatabaseConnection,
    #[cfg(test)]
    read: std::sync::atomic::AtomicUsize,
}

#[must_use]
pub(crate) struct NewUpdate<'a> {
    pub request: &'a SubmitRecordUpdateRequest,
    pub update: &'a CheckedUpdate,
    pub queued_slot: u64,
    /// Updates pending list approval the update approves, they queue joined to it.
    pub approves: &'a [[u8; 32]],
}

/// Recorded and not yet settled, its updates wait on its signature.
pub(crate) struct OpenBatch {
    pub id: i64,
    pub attempt: Attempt,
}

#[must_use]
pub(crate) struct NewBatch<'a> {
    pub registry: Address,
    pub attempt: Attempt,
    /// The registry revision the `Update` names.
    pub revision: u64,
    pub updates: &'a [QueuedUpdate],
}

/// `cursor` names any update of the ring, the page starts after it in submit order.
pub(crate) struct PendingApprovalPage {
    pub ring: Address,
    pub cursor: Option<[u8; 32]>,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchOutcome {
    Applied,
    /// The transaction failed or can no longer land, its updates queue again until `MAX_BATCH_ATTEMPTS`.
    Requeued,
}

impl<'a> UpdateQueue<'a> {
    pub fn new(db: &'a DatabaseConnection) -> Self {
        Self {
            db,
            #[cfg(test)]
            read: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub async fn contains(&self, id: &[u8; 32]) -> Result<bool, DbErr> {
        let sql = "SELECT 1 AS found FROM records_updates WHERE id=$1";
        Ok(self.query_one(sql, vec![bytes(id)]).await?.is_some())
    }

    /// A resubmitted update keeps its first row.
    pub async fn insert(&self, new: NewUpdate<'_>) -> Result<(), DbErr> {
        let request =
            serde_json::to_string(new.request).map_err(|error| DbErr::Custom(error.to_string()))?;
        let id = bytes(&new.update.id.0 .0);
        let (status, awaited, member) = match new.update.awaited {
            Some(awaited) => (
                PENDING_APPROVAL,
                awaited.lists.record_bits(),
                bytes(&awaited.member),
            ),
            None => (QUEUED, 0, Value::Bytes(None)),
        };
        let transaction = self.db.begin().await?;
        let sql = "INSERT INTO records_updates(id,registry,ring,request,writes,signer,role,\
                   queued_slot,valid_until_slot,status,awaited,member) \
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
                   ON CONFLICT(id) DO NOTHING RETURNING seq";
        let registry = bytes(new.request.registry.0.as_array());
        let values = vec![
            id.clone(),
            registry.clone(),
            bytes(new.request.update.ring.0.as_array()),
            request.into(),
            bytemuck::cast_slice::<RecordWriteData, u8>(&new.update.writes)
                .to_vec()
                .into(),
            bytes(new.update.signer.address().as_array()),
            role(new.update.signer).into(),
            integer(new.queued_slot)?,
            integer(new.request.update.valid_until_slot)?,
            status.into(),
            integer(awaited)?,
            member,
        ];
        let inserted: Option<i64> = transaction
            .query_one(statement(&transaction, sql, values))
            .await?
            .map(|row| row.try_get("", "seq"))
            .transpose()?;
        // A resubmit that lost the insert race joins nothing.
        let Some(seq) = inserted else {
            return transaction.commit().await;
        };
        // 1. Each record the update writes, the planner finds an earlier update on it by index.
        let members = new
            .update
            .written_members()
            .map_err(|refusal| DbErr::Custom(refusal.to_string()))?;
        for member in &members {
            let sql = "INSERT INTO records_update_members(seq,registry,member) VALUES($1,$2,$3)";
            transaction
                .execute(statement(
                    &transaction,
                    sql,
                    vec![seq.into(), registry.clone(), bytes(member)],
                ))
                .await?;
        }
        let approves = new.approves;
        for pending in approves {
            let sql = "UPDATE records_updates SET status=$1, joined=$2 WHERE id=$3 AND status=$4";
            let values = vec![
                QUEUED.into(),
                id.clone(),
                bytes(pending),
                PENDING_APPROVAL.into(),
            ];
            transaction
                .execute(statement(&transaction, sql, values))
                .await?;
        }
        // 2. An approval expires with the earliest update it joined, so expiry reads one column.
        if !approves.is_empty() {
            let sql = "UPDATE records_updates SET valid_until_slot=(SELECT MIN(valid_until_slot) \
                       FROM records_updates WHERE id=$1 OR joined=$1) WHERE id=$1";
            transaction
                .execute(statement(&transaction, sql, vec![id]))
                .await?;
        }
        transaction.commit().await
    }

    pub async fn status(&self, id: &[u8; 32]) -> Result<Option<RecordUpdateStatus>, DbErr> {
        let sql = "SELECT u.status, u.reason, b.signature, b.revision FROM records_updates AS u \
                   LEFT JOIN records_batches AS b ON b.id = u.batch WHERE u.id=$1";
        let Some(row) = self.query_one(sql, vec![bytes(id)]).await? else {
            return Ok(None);
        };
        let status = row.try_get::<String>("", "status")?;
        Ok(Some(match status.as_str() {
            PENDING_APPROVAL => RecordUpdateStatus::PendingListApproval,
            QUEUED => RecordUpdateStatus::Queued,
            SUBMITTED => RecordUpdateStatus::Submitted {
                signature: signature(&row)?.into(),
            },
            APPLIED => RecordUpdateStatus::Applied {
                signature: signature(&row)?.into(),
                revision: unsigned(&row, "revision")?
                    .checked_add(1)
                    .ok_or_else(|| corrupt("revision"))?,
            },
            REFUSED => RecordUpdateStatus::Refused {
                reason: row
                    .try_get::<Option<String>>("", "reason")?
                    .unwrap_or_default(),
            },
            _ => return Err(corrupt("status")),
        }))
    }

    /// Every registry with an update pending list approval, a queued update or an open batch.
    pub async fn registries(&self) -> Result<Vec<Address>, DbErr> {
        let sql = "SELECT DISTINCT registry FROM records_updates WHERE status IN ($1,$2,$3)";
        self.query_all(
            sql,
            vec![PENDING_APPROVAL.into(), QUEUED.into(), SUBMITTED.into()],
        )
        .await?
        .iter()
        .map(|row| address(row, "registry"))
        .collect()
    }

    pub async fn open_batch(&self, registry: Address) -> Result<Option<OpenBatch>, DbErr> {
        let sql = "SELECT id, signature, last_valid_block_height FROM records_batches \
                   WHERE registry=$1 AND status=$2";
        let values = vec![bytes(registry.as_array()), SUBMITTED.into()];
        let Some(row) = self.query_one(sql, values).await? else {
            return Ok(None);
        };
        Ok(Some(OpenBatch {
            id: row.try_get("", "id")?,
            attempt: Attempt {
                signature: signature(&row)?,
                last_valid_block_height: unsigned(&row, "last_valid_block_height")?,
            },
        }))
    }

    /// Authority updates first, wallet ones otherwise, read from the oldest queued heads alone.
    pub async fn plan(
        &self,
        registry: Address,
        slot: u64,
    ) -> Result<Option<Vec<QueuedUpdate>>, DbErr> {
        let authority = self.authority_heads(registry).await?;
        let blocking = !authority.is_empty();
        let batch = authority_batch(authority);
        if !batch.is_empty() {
            return Ok(Some(batch));
        }
        let oldest = self.oldest_heads(registry).await?;
        Ok(WalletBatch {
            oldest,
            blocking,
            slot,
        }
        .decide())
    }

    /// The oldest authority updates, each marked when an earlier queued wallet update writes one of
    /// its records, its joined updates' records included.
    async fn authority_heads(&self, registry: Address) -> Result<Vec<AuthorityHead>, DbErr> {
        let sql = format!(
            "SELECT {HEAD_COLUMNS}, EXISTS(SELECT 1 FROM records_updates AS j \
             JOIN records_update_members AS m ON m.seq = j.seq \
             JOIN records_update_members AS w ON w.registry = m.registry AND w.member = m.member \
             AND w.seq < u.seq \
             JOIN records_updates AS h ON h.seq = w.seq \
             WHERE (j.seq = u.seq OR j.joined = u.id) AND h.status = $2 AND h.role = $3 \
             AND h.joined IS NULL) AS blocked \
             FROM records_updates AS u WHERE u.registry=$1 AND u.role=$4 AND u.status=$2 \
             ORDER BY u.seq LIMIT $5"
        );
        let values = vec![
            bytes(registry.as_array()),
            QUEUED.into(),
            WALLET_ROLE.into(),
            POLICY_ROLE.into(),
            count(APPLY_BATCH)?,
        ];
        let rows = self.query_all(&sql, values).await?;
        let blocked = rows
            .iter()
            .map(|row| row.try_get::<bool>("", "blocked"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .heads(&rows)
            .await?
            .into_iter()
            .zip(blocked)
            .map(|(update, blocked)| AuthorityHead { update, blocked })
            .collect())
    }

    /// The oldest updates of either role, one past a full batch.
    async fn oldest_heads(&self, registry: Address) -> Result<Vec<QueuedUpdate>, DbErr> {
        let sql = format!(
            "SELECT {HEAD_COLUMNS} FROM records_updates AS u WHERE u.registry=$1 AND u.status=$2 \
             AND u.joined IS NULL ORDER BY u.seq LIMIT $3"
        );
        let values = vec![
            bytes(registry.as_array()),
            QUEUED.into(),
            count(OLDEST_HEADS)?,
        ];
        let rows = self.query_all(&sql, values).await?;
        self.heads(&rows).await
    }

    /// Each joined update's writes ahead of the approval it joined, in submit order.
    async fn heads(&self, rows: &[QueryResult]) -> Result<Vec<QueuedUpdate>, DbErr> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let ids = rows
            .iter()
            .map(|row| column_bytes(row, "id"))
            .collect::<Result<Vec<_>, _>>()?;
        let sql = format!(
            "SELECT joined, writes FROM records_updates WHERE status=$1 AND joined IN ({}) \
             ORDER BY seq",
            placeholders(2, ids.len())
        );
        let values = std::iter::once(QUEUED.into())
            .chain(ids.iter().map(bytes))
            .collect();
        let joined = self.query_all(&sql, values).await?;
        rows.iter()
            .zip(ids)
            .map(|(row, id)| {
                let mut writes = Vec::new();
                for joined in &joined {
                    if column_bytes(joined, "joined")? == id {
                        writes.extend(stored_writes(joined)?);
                    }
                }
                writes.extend(stored_writes(row)?);
                Ok(QueuedUpdate {
                    id,
                    ring: address(row, "ring")?,
                    writes,
                    signer: update_signer(row)?,
                    queued_slot: unsigned(row, "queued_slot")?,
                    valid_until_slot: unsigned(row, "valid_until_slot")?,
                })
            })
            .collect()
    }

    /// Oldest first.
    pub async fn pending_approvals(
        &self,
        ring: Address,
        members: &[[u8; 32]],
    ) -> Result<Vec<PendingApproval>, DbErr> {
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {PENDING_APPROVAL_COLUMNS} FROM records_updates \
             WHERE ring=$1 AND status=$2 AND member IN ({}) ORDER BY seq",
            placeholders(3, members.len())
        );
        let values = [bytes(ring.as_array()), PENDING_APPROVAL.into()]
            .into_iter()
            .chain(members.iter().map(bytes))
            .collect();
        self.query_all(&sql, values)
            .await?
            .iter()
            .map(pending_approval)
            .collect()
    }

    /// `None` when `cursor` names no update of the ring.
    pub async fn pending_approval_page(
        &self,
        page: PendingApprovalPage,
    ) -> Result<Option<Vec<PendingApproval>>, DbErr> {
        let ring = bytes(page.ring.as_array());
        let after = match page.cursor {
            None => 0,
            Some(cursor) => {
                let sql = "SELECT seq FROM records_updates WHERE id=$1 AND ring=$2";
                match self
                    .query_one(sql, vec![bytes(&cursor), ring.clone()])
                    .await?
                {
                    Some(row) => row.try_get::<i64>("", "seq")?,
                    None => return Ok(None),
                }
            }
        };
        let limit = i64::try_from(page.limit)
            .map_err(|_| DbErr::Custom("page limit exceeds the store integer range".to_owned()))?;
        let sql = format!(
            "SELECT {PENDING_APPROVAL_COLUMNS} FROM records_updates \
             WHERE ring=$1 AND status=$2 AND seq>$3 ORDER BY seq LIMIT $4"
        );
        let values = vec![ring, PENDING_APPROVAL.into(), after.into(), limit.into()];
        self.query_all(&sql, values)
            .await?
            .iter()
            .map(pending_approval)
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// `false` when no update of `ring` is pending list approval under `id`.
    pub async fn refuse_pending_approval(
        &self,
        ring: Address,
        id: &[u8; 32],
    ) -> Result<bool, DbErr> {
        let sql = "UPDATE records_updates SET status=$1, reason=$2 \
                   WHERE id=$3 AND ring=$4 AND status=$5";
        let values = vec![
            REFUSED.into(),
            RecordUpdateRefusal::ListApprovalRefused.to_string().into(),
            bytes(id),
            bytes(ring.as_array()),
            PENDING_APPROVAL.into(),
        ];
        let transaction = self.db.begin().await?;
        let refused = finish_updates(&transaction, sql, values).await?;
        transaction.commit().await?;
        Ok(refused == 1)
    }

    /// An update past its valid until slot turns refused, an expired approval takes its joined
    /// updates with it.
    pub async fn expire(&self, registry: Address, slot: u64) -> Result<(), DbErr> {
        let sql = "UPDATE records_updates SET status=$1, reason=$2 \
                   WHERE registry=$3 AND status IN ($4,$5) AND (valid_until_slot<$6 \
                   OR joined IN (SELECT id FROM records_updates WHERE registry=$3 \
                   AND status=$5 AND valid_until_slot<$6))";
        let values = vec![
            REFUSED.into(),
            RecordUpdateRefusal::Expired.to_string().into(),
            bytes(registry.as_array()),
            PENDING_APPROVAL.into(),
            QUEUED.into(),
            integer(slot)?,
        ];
        let transaction = self.db.begin().await?;
        finish_updates(&transaction, sql, values).await?;
        transaction.commit().await
    }

    /// The updates joined to `id` share its refusal, or turn pending list approval again when its approver lost the policy role.
    pub async fn refuse(&self, id: &[u8; 32], refusal: RecordUpdateRefusal) -> Result<(), DbErr> {
        let transaction = self.db.begin().await?;
        if refusal == RecordUpdateRefusal::AuthorityLapsed {
            let sql =
                "UPDATE records_updates SET status=$1, joined=NULL WHERE joined=$2 AND status=$3";
            let values = vec![PENDING_APPROVAL.into(), bytes(id), QUEUED.into()];
            transaction
                .execute(statement(&transaction, sql, values))
                .await?;
        }
        let sql = "UPDATE records_updates SET status=$2, reason=$3 \
                   WHERE (id=$1 OR joined=$1) AND status=$4";
        let values = vec![
            bytes(id),
            REFUSED.into(),
            refusal.to_string().into(),
            QUEUED.into(),
        ];
        finish_updates(&transaction, sql, values).await?;
        transaction.commit().await
    }

    /// Recorded before the transaction is sent, a restart settles it by its signature.
    pub async fn record_batch(&self, batch: NewBatch<'_>) -> Result<(), DbErr> {
        let transaction = self.db.begin().await?;
        let sql =
            "INSERT INTO records_batches(registry,signature,revision,last_valid_block_height,\
                   status) VALUES($1,$2,$3,$4,$5) RETURNING id";
        let values = vec![
            bytes(batch.registry.as_array()),
            batch.attempt.signature.as_ref().to_vec().into(),
            integer(batch.revision)?,
            integer(batch.attempt.last_valid_block_height)?,
            SUBMITTED.into(),
        ];
        let id: i64 = transaction
            .query_one(statement(&transaction, sql, values))
            .await?
            .ok_or_else(|| corrupt("batch id"))?
            .try_get("", "id")?;
        for update in batch.updates {
            let sql = "UPDATE records_updates SET status=$1, batch=$2 \
                       WHERE (id=$3 OR joined=$3) AND status=$4";
            let values = vec![
                SUBMITTED.into(),
                id.into(),
                bytes(&update.id),
                QUEUED.into(),
            ];
            transaction
                .execute(statement(&transaction, sql, values))
                .await?;
        }
        transaction.commit().await
    }

    pub async fn settle(&self, batch: i64, outcome: BatchOutcome) -> Result<(), DbErr> {
        let batch_status = match outcome {
            BatchOutcome::Applied => APPLIED,
            BatchOutcome::Requeued => FAILED,
        };
        let transaction = self.db.begin().await?;
        let sql = "UPDATE records_batches SET status=$1 WHERE id=$2";
        transaction
            .execute(statement(
                &transaction,
                sql,
                vec![batch_status.into(), batch.into()],
            ))
            .await?;
        match outcome {
            BatchOutcome::Applied => {
                let sql = "UPDATE records_updates SET status=$1 WHERE batch=$2";
                finish_updates(&transaction, sql, vec![APPLIED.into(), batch.into()]).await?;
            }
            BatchOutcome::Requeued => {
                let sql = "UPDATE records_updates SET status=$1, reason=$2, batch=NULL, \
                           attempts=attempts+1 WHERE batch=$3 AND attempts+1>=$4";
                let values = vec![
                    REFUSED.into(),
                    RecordUpdateRefusal::BatchFailed.to_string().into(),
                    batch.into(),
                    integer(MAX_BATCH_ATTEMPTS)?,
                ];
                finish_updates(&transaction, sql, values).await?;
                let sql = "UPDATE records_updates SET status=$1, batch=NULL, \
                           attempts=attempts+1 WHERE batch=$2";
                transaction
                    .execute(statement(
                        &transaction,
                        sql,
                        vec![QUEUED.into(), batch.into()],
                    ))
                    .await?;
            }
        }
        transaction.commit().await
    }

    async fn query_one(&self, sql: &str, values: Vec<Value>) -> Result<Option<QueryResult>, DbErr> {
        self.db.query_one(statement(self.db, sql, values)).await
    }

    async fn query_all(&self, sql: &str, values: Vec<Value>) -> Result<Vec<QueryResult>, DbErr> {
        let rows = self.db.query_all(statement(self.db, sql, values)).await?;
        #[cfg(test)]
        self.read
            .fetch_add(rows.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(rows)
    }
}

/// Runs `sql`, which moves updates to applied or refused, and drops their member rows in the same
/// transaction, so the blocking check reads the live queue alone. Returns the updates it moved.
async fn finish_updates<C: ConnectionTrait>(
    connection: &C,
    sql: &str,
    values: Vec<Value>,
) -> Result<usize, DbErr> {
    let finished = connection
        .query_all(statement(
            connection,
            &format!("{sql} RETURNING seq"),
            values,
        ))
        .await?;
    let seqs = finished
        .iter()
        .map(|row| row.try_get::<i64>("", "seq"))
        .collect::<Result<Vec<_>, _>>()?;
    for chunk in seqs.chunks(KEYS_PER_DELETE) {
        let sql = format!(
            "DELETE FROM records_update_members WHERE seq IN ({})",
            placeholders(1, chunk.len())
        );
        let values = chunk.iter().map(|seq| Value::from(*seq)).collect();
        connection
            .execute(statement(connection, &sql, values))
            .await?;
    }
    Ok(seqs.len())
}

/// `$first` onward, NULL for none so an empty list matches no row.
fn placeholders(first: usize, count: usize) -> String {
    match count {
        0 => "NULL".to_owned(),
        _ => (first..first + count)
            .map(|index| format!("${index}"))
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn pending_approval(row: &QueryResult) -> Result<PendingApproval, DbErr> {
    let lists =
        ListSet::from_record_bits(unsigned(row, "awaited")?).ok_or_else(|| corrupt("awaited"))?;
    Ok(PendingApproval {
        id: column_bytes(row, "id")?,
        wallet: address(row, "signer")?,
        member: column_bytes(row, "member")?,
        lists,
        writes: stored_writes(row)?.len(),
        valid_until_slot: unsigned(row, "valid_until_slot")?,
    })
}

pub(crate) fn role(signer: UpdateSigner) -> &'static str {
    match signer {
        UpdateSigner::Wallet(_) => WALLET_ROLE,
        UpdateSigner::PolicyAuthority(_) => POLICY_ROLE,
    }
}

fn update_signer(row: &QueryResult) -> Result<UpdateSigner, DbErr> {
    let signer = address(row, "signer")?;
    match row.try_get::<String>("", "role")?.as_str() {
        WALLET_ROLE => Ok(UpdateSigner::Wallet(signer)),
        POLICY_ROLE => Ok(UpdateSigner::PolicyAuthority(signer)),
        _ => Err(corrupt("role")),
    }
}

fn statement<C: ConnectionTrait>(connection: &C, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(connection.get_database_backend(), sql, values)
}

fn bytes(value: &[u8; 32]) -> Value {
    value.to_vec().into()
}

fn count(value: usize) -> Result<Value, DbErr> {
    i64::try_from(value)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("count exceeds the store integer range".to_owned()))
}

fn integer(value: u64) -> Result<Value, DbErr> {
    i64::try_from(value)
        .map(Value::from)
        .map_err(|_| DbErr::Custom("value exceeds the store integer range".to_owned()))
}

fn column_bytes(row: &QueryResult, column: &str) -> Result<[u8; 32], DbErr> {
    row.try_get::<Vec<u8>>("", column)?
        .try_into()
        .map_err(|_| corrupt(column))
}

fn stored_writes(row: &QueryResult) -> Result<Vec<RecordWriteData>, DbErr> {
    bytemuck::try_cast_slice::<u8, RecordWriteData>(&row.try_get::<Vec<u8>>("", "writes")?)
        .map(<[RecordWriteData]>::to_vec)
        .map_err(|_| corrupt("writes"))
}

fn address(row: &QueryResult, column: &str) -> Result<Address, DbErr> {
    column_bytes(row, column).map(Address::new_from_array)
}

fn unsigned(row: &QueryResult, column: &str) -> Result<u64, DbErr> {
    u64::try_from(row.try_get::<i64>("", column)?).map_err(|_| corrupt(column))
}

fn signature(row: &QueryResult) -> Result<Signature, DbErr> {
    Signature::try_from(row.try_get::<Vec<u8>>("", "signature")?.as_slice())
        .map_err(|_| corrupt("signature"))
}

fn corrupt(column: &str) -> DbErr {
    DbErr::Custom(format!("stored record update {column} is invalid"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use spr_indexer_api::Hash;
    use zolana_ring_client::rpc::{RecordUpdate, RecordUpdateId};

    use super::*;
    use crate::database::Store;

    const REGISTRY: Address = Address::new_from_array([0x52; 32]);
    const RING: Address = Address::new_from_array([8; 32]);
    const UPDATES: u32 = 5_000;

    fn member(index: u32) -> [u8; 32] {
        let mut member = [0; 32];
        member[..4].copy_from_slice(&index.to_be_bytes());
        member
    }

    /// One update writing `member(index)`, its id unique per role and index.
    async fn insert(queue: &UpdateQueue<'_>, index: u32, signer: UpdateSigner) {
        let mut id = member(index);
        id[31] = u8::from(signer.is_authority()) + 1;
        let request = SubmitRecordUpdateRequest {
            registry: REGISTRY.into(),
            update: RecordUpdate {
                genesis_hash: Hash([0; 32]),
                ring: RING.into(),
                entries: Vec::new(),
                valid_until_slot: u64::from(u32::MAX),
                awaited_lists: 0,
            },
            signer: signer.address().into(),
            signature: Signature::default().into(),
        };
        let update = CheckedUpdate {
            id: RecordUpdateId(Hash(id)),
            writes: vec![RecordWriteData {
                member: member(index),
                ..RecordWriteData::default()
            }],
            entries: Vec::new(),
            signer,
            awaited: None,
        };
        queue
            .insert(NewUpdate {
                request: &request,
                update: &update,
                queued_slot: 0,
                approves: &[],
            })
            .await
            .expect("insert");
    }

    #[tokio::test]
    async fn a_ten_thousand_update_queue_plans_each_flush_from_a_bounded_read() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        plans_from_a_bounded_read(&store).await;
    }

    #[tokio::test]
    #[ignore = "needs RING_RPC_TEST_POSTGRES_URL"]
    async fn a_ten_thousand_update_queue_plans_each_flush_from_a_bounded_read_on_postgres() {
        let url = std::env::var("RING_RPC_TEST_POSTGRES_URL").expect("postgres url");
        let store = Store::open(&url, 1).await.expect("store");
        plans_from_a_bounded_read(&store).await;
    }

    async fn member_rows(queue: &UpdateQueue<'_>) -> i64 {
        queue
            .query_one(
                "SELECT COUNT(*) AS rows FROM records_update_members",
                Vec::new(),
            )
            .await
            .expect("count")
            .expect("row")
            .try_get("", "rows")
            .expect("rows")
    }

    async fn plans_from_a_bounded_read(store: &Store) {
        let queue = UpdateQueue::new(store.connection());
        let wallet = UpdateSigner::Wallet(Address::new_from_array([1; 32]));
        let authority = UpdateSigner::PolicyAuthority(Address::new_from_array([2; 32]));
        for index in 0..UPDATES {
            insert(&queue, index, wallet).await;
        }
        for index in 0..UPDATES {
            insert(&queue, index, authority).await;
        }

        // Each authority batch waits for the wallet batch on its records, then goes before the next.
        for flush in 0..4 {
            queue.read.store(0, Ordering::Relaxed);
            let batch = queue
                .plan(REGISTRY, 0)
                .await
                .expect("plan")
                .expect("a batch");
            let read = queue.read.load(Ordering::Relaxed);
            assert!(
                read <= APPLY_BATCH + OLDEST_HEADS,
                "flush {flush} read {read} rows"
            );
            let first = u32::try_from(flush / 2 * APPLY_BATCH).expect("index");
            let members: Vec<[u8; 32]> =
                batch.iter().map(|update| update.writes[0].member).collect();
            assert_eq!(
                members,
                (first..first + APPLY_BATCH as u32)
                    .map(member)
                    .collect::<Vec<_>>()
            );
            assert!(batch
                .iter()
                .all(|update| update.signer.is_authority() == (flush % 2 == 1)));
            queue
                .record_batch(NewBatch {
                    registry: REGISTRY,
                    attempt: Attempt {
                        signature: Signature::default(),
                        last_valid_block_height: 0,
                    },
                    revision: 0,
                    updates: &batch,
                })
                .await
                .expect("batch");
            let open = queue
                .open_batch(REGISTRY)
                .await
                .expect("open")
                .expect("a batch");
            queue
                .settle(open.id, BatchOutcome::Applied)
                .await
                .expect("settle");
            // Each update writes one record, an applied update keeps no member row.
            let queued = 2 * UPDATES as usize - (flush + 1) * APPLY_BATCH;
            assert_eq!(
                member_rows(&queue).await,
                i64::try_from(queued).expect("count")
            );
        }
    }
}
