use anyhow::{bail, Context, Result};
use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction,
    IsolationLevel, Statement, TransactionTrait, Value,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use solana_address::Address;
use thiserror::Error;
use zolana_indexer_api::Hash;
use zolana_ring_indexer::key_registry::MemberKey;

use crate::{block::BlockMetadata, spend_record::SpendUndo, tree::RegistryTree};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RingRoot {
    pub program: [u8; 32],
    pub address: [u8; 32],
    pub root: [u8; 32],
    pub next_index: u64,
    /// Cleared only by a rollback.
    pub fault: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RingCursor {
    pub start_slot: u64,
    pub scanned_slot: u64,
    pub tip: Option<BlockMetadata>,
    ready: bool,
}

impl RingCursor {
    pub fn new(start_slot: u64) -> Self {
        Self {
            start_slot,
            scanned_slot: start_slot,
            tip: None,
            ready: false,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub async fn suspend<C: ConnectionTrait>(&mut self, conn: &C) -> Result<()> {
        self.ready = false;
        save_cursor(conn, self).await
    }

    pub async fn resume<C: ConnectionTrait>(&mut self, conn: &C) -> Result<()> {
        self.ready = true;
        save_cursor(conn, self).await
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LeafWrite {
    pub index: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MemberRestore {
    pub member: [u8; 32],
    pub before: Option<MemberKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Undo {
    pub program: [u8; 32],
    pub before: Option<RingRoot>,
    pub members: Vec<MemberRestore>,
    pub leaves: Vec<LeafWrite>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct BlockUndo {
    pub spend_records: Vec<SpendUndo>,
    pub key_registry: Vec<Undo>,
}

impl BlockUndo {
    pub fn extend(&mut self, other: Self) {
        self.spend_records.extend(other.spend_records);
        self.key_registry.extend(other.key_registry);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BlockJournal {
    pub metadata: BlockMetadata,
    pub previous_tip: Option<BlockMetadata>,
    pub undo: BlockUndo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PendingRing {
    pub program: [u8; 32],
    pub slot: u64,
    pub blockhash: Hash,
    /// Last historical block committed with the ring's index changes.
    pub replayed_tip: Option<BlockMetadata>,
}

#[derive(Debug, Error)]
pub(crate) enum PredecessorError {
    #[error("member is not absent")]
    NotAbsent,
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
}

const CURSOR_TABLE: &str = "ring_cursor";
const JOURNAL_TABLE: &str = "ring_blocks";
const PENDING_TABLE: &str = "ring_pending";
const ROOTS_TABLE: &str = "ring_registry_roots";
const MEMBERS_TABLE: &str = "ring_registry_members";

/// Lookups read every table from one Postgres snapshot.
pub(crate) async fn begin_read(
    db: &DatabaseConnection,
) -> Result<DatabaseTransaction, sea_orm::DbErr> {
    match db.get_database_backend() {
        DatabaseBackend::Postgres => {
            db.begin_with_config(
                Some(IsolationLevel::RepeatableRead),
                Some(AccessMode::ReadOnly),
            )
            .await
        }
        _ => db.begin().await,
    }
}

pub(crate) async fn save_pending<C: ConnectionTrait>(conn: &C, value: &PendingRing) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!(
            "INSERT INTO {PENDING_TABLE}(program,slot,state) VALUES($1,$2,$3) \
             ON CONFLICT(program) DO NOTHING"
        ),
        vec![
            value.program.to_vec().into(),
            i64::try_from(value.slot)?.into(),
            serde_json::to_string(value)?.into(),
        ],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn pending<C: ConnectionTrait>(conn: &C) -> Result<Vec<PendingRing>> {
    read_all(
        conn,
        &format!("SELECT state FROM {PENDING_TABLE} ORDER BY slot"),
        vec![],
    )
    .await
}

pub(crate) async fn pending_ring<C: ConnectionTrait>(
    conn: &C,
    program: &[u8; 32],
) -> Result<Option<PendingRing>> {
    read_json(
        conn,
        &format!("SELECT state FROM {PENDING_TABLE} WHERE program=$1"),
        vec![program.to_vec().into()],
    )
    .await
}

pub(crate) async fn checkpoint_pending<C: ConnectionTrait>(
    conn: &C,
    pending: &PendingRing,
) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!("UPDATE {PENDING_TABLE} SET state=$2 WHERE program=$1"),
        vec![
            pending.program.to_vec().into(),
            serde_json::to_string(pending)?.into(),
        ],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn delete_pending<C: ConnectionTrait>(conn: &C, program: &[u8; 32]) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!("DELETE FROM {PENDING_TABLE} WHERE program=$1"),
        vec![program.to_vec().into()],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn cursor<C: ConnectionTrait>(conn: &C) -> Result<Option<RingCursor>> {
    read_json(
        conn,
        &format!("SELECT state FROM {CURSOR_TABLE} WHERE id=1"),
        vec![],
    )
    .await
}

pub(crate) async fn save_cursor<C: ConnectionTrait>(conn: &C, value: &RingCursor) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!(
            "INSERT INTO {CURSOR_TABLE}(id,state) VALUES(1,$1) \
             ON CONFLICT(id) DO UPDATE SET state=excluded.state"
        ),
        vec![serde_json::to_string(value)?.into()],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn journal<C: ConnectionTrait>(
    conn: &C,
    slot: u64,
) -> Result<Option<BlockJournal>> {
    read_json(
        conn,
        &format!("SELECT state FROM {JOURNAL_TABLE} WHERE slot=$1"),
        vec![i64::try_from(slot)?.into()],
    )
    .await
}

pub(crate) async fn save_journal<C: ConnectionTrait>(
    conn: &C,
    journal: &BlockJournal,
) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!(
            "INSERT INTO {JOURNAL_TABLE}(slot,state) VALUES($1,$2) \
             ON CONFLICT(slot) DO UPDATE SET state=excluded.state"
        ),
        vec![
            i64::try_from(journal.metadata.slot)?.into(),
            serde_json::to_string(journal)?.into(),
        ],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn prune_journal<C: ConnectionTrait>(conn: &C, below: u64) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!("DELETE FROM {JOURNAL_TABLE} WHERE slot<$1"),
        vec![i64::try_from(below)?.into()],
    ))
    .await?;
    Ok(())
}

async fn delete_journal<C: ConnectionTrait>(conn: &C, slot: u64) -> Result<()> {
    conn.execute(statement(
        conn,
        &format!("DELETE FROM {JOURNAL_TABLE} WHERE slot=$1"),
        vec![i64::try_from(slot)?.into()],
    ))
    .await?;
    Ok(())
}

pub(crate) async fn roots<C: ConnectionTrait>(conn: &C) -> Result<Vec<RingRoot>> {
    read_all(
        conn,
        &format!("SELECT state FROM {ROOTS_TABLE} ORDER BY program"),
        vec![],
    )
    .await
}

pub(crate) async fn rollback(tx: &DatabaseTransaction, cursor: &mut RingCursor) -> Result<()> {
    let tip = cursor
        .tip
        .as_ref()
        .context("cannot rewind before the ring index start")?;
    let journal = journal(tx, tip.slot).await?.context("ring journal gap")?;
    tx.execute(statement(
        tx,
        &format!("DELETE FROM {PENDING_TABLE} WHERE slot=$1"),
        vec![i64::try_from(journal.metadata.slot)?.into()],
    ))
    .await?;
    crate::spend_record::restore(tx, &journal.undo.spend_records).await?;
    restore(tx, &journal.undo.key_registry).await?;
    // Partial replay must rewind with the block that advanced it.
    for mut candidate in pending(tx).await? {
        if candidate
            .replayed_tip
            .as_ref()
            .is_some_and(|tip| tip.slot == journal.metadata.slot)
        {
            candidate.replayed_tip = journal
                .previous_tip
                .clone()
                .filter(|tip| tip.slot >= candidate.slot);
            checkpoint_pending(tx, &candidate).await?;
        }
    }
    delete_journal(tx, journal.metadata.slot).await?;
    cursor.tip = journal.previous_tip;
    cursor.scanned_slot = cursor
        .tip
        .as_ref()
        .map_or(cursor.start_slot, |tip| tip.slot);
    cursor.suspend(tx).await
}

async fn restore(tx: &DatabaseTransaction, undos: &[Undo]) -> Result<()> {
    for undo in undos.iter().rev() {
        let store = RingStore::new(tx, undo.program);
        match &undo.before {
            Some(before) => {
                if !undo.leaves.is_empty() && store.tree().write(&undo.leaves).await? != before.root
                {
                    bail!("key registry rollback root mismatch");
                }
                store.save_root(before).await?;
                for restore in &undo.members {
                    match &restore.before {
                        Some(leaf) => store.save_member(leaf).await?,
                        None => store.delete_member(&restore.member).await?,
                    }
                }
            }
            None => {
                store
                    .root()
                    .await?
                    .context("created key registry missing on rollback")?;
                store.tree().delete().await?;
                store.delete_members().await?;
                store.delete_root().await?;
            }
        }
    }
    Ok(())
}

pub(crate) struct RingStore<'c, C> {
    conn: &'c C,
    program: [u8; 32],
}

impl<'c, C: ConnectionTrait> RingStore<'c, C> {
    pub fn new(conn: &'c C, program: [u8; 32]) -> Self {
        Self { conn, program }
    }

    pub fn program(&self) -> [u8; 32] {
        self.program
    }

    pub fn tree(&self) -> RegistryTree<'c, C> {
        RegistryTree::new(self.conn, self.program)
    }

    pub async fn root(&self) -> Result<Option<RingRoot>> {
        read_json(
            self.conn,
            &format!("SELECT state FROM {ROOTS_TABLE} WHERE program=$1"),
            vec![self.program.to_vec().into()],
        )
        .await
    }

    pub async fn save_root(&self, root: &RingRoot) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!(
                    "INSERT INTO {ROOTS_TABLE}(program,state) VALUES($1,$2) \
                     ON CONFLICT(program) DO UPDATE SET state=excluded.state"
                ),
                vec![
                    self.program.to_vec().into(),
                    serde_json::to_string(root)?.into(),
                ],
            ))
            .await?;
        Ok(())
    }

    pub async fn quarantine(&self, root: RingRoot, reason: String) -> Result<Undo> {
        log::warn!(
            "key registry of ring {} quarantined ({reason})",
            Address::new_from_array(self.program)
        );
        self.save_root(&RingRoot {
            fault: Some(reason),
            ..root.clone()
        })
        .await?;
        Ok(Undo {
            program: root.program,
            before: Some(root),
            members: vec![],
            leaves: vec![],
        })
    }

    pub async fn delete_root(&self) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!("DELETE FROM {ROOTS_TABLE} WHERE program=$1"),
                vec![self.program.to_vec().into()],
            ))
            .await?;
        Ok(())
    }

    pub async fn member(&self, member: &[u8; 32]) -> Result<Option<MemberKey>> {
        read_json(
            self.conn,
            &format!("SELECT state FROM {MEMBERS_TABLE} WHERE program=$1 AND member=$2"),
            vec![self.program.to_vec().into(), member.to_vec().into()],
        )
        .await
    }

    pub async fn predecessor(&self, member: &[u8; 32]) -> Result<MemberKey, PredecessorError> {
        let low: MemberKey = read_json(
            self.conn,
            &format!(
                "SELECT state FROM {MEMBERS_TABLE} WHERE program=$1 AND member<$2 \
                 ORDER BY member DESC LIMIT 1"
            ),
            vec![self.program.to_vec().into(), member.to_vec().into()],
        )
        .await?
        .context("no covering predecessor")?;
        if !(low.member < *member && *member < low.next) {
            return Err(PredecessorError::NotAbsent);
        }
        Ok(low)
    }

    pub async fn save_member(&self, leaf: &MemberKey) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!(
                    "INSERT INTO {MEMBERS_TABLE}(program,member,leaf_index,state) \
                     VALUES($1,$2,$3,$4) ON CONFLICT(program,member) \
                     DO UPDATE SET leaf_index=excluded.leaf_index,state=excluded.state"
                ),
                vec![
                    self.program.to_vec().into(),
                    leaf.member.to_vec().into(),
                    i64::try_from(leaf.index)?.into(),
                    serde_json::to_string(leaf)?.into(),
                ],
            ))
            .await?;
        Ok(())
    }

    pub async fn delete_member(&self, member: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!("DELETE FROM {MEMBERS_TABLE} WHERE program=$1 AND member=$2"),
                vec![self.program.to_vec().into(), member.to_vec().into()],
            ))
            .await?;
        Ok(())
    }

    pub async fn delete_members(&self) -> Result<()> {
        self.conn
            .execute(statement(
                self.conn,
                &format!("DELETE FROM {MEMBERS_TABLE} WHERE program=$1"),
                vec![self.program.to_vec().into()],
            ))
            .await?;
        Ok(())
    }
}

pub(crate) fn statement<C: ConnectionTrait>(conn: &C, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(conn.get_database_backend(), sql, values)
}

async fn read_json<T: DeserializeOwned, C: ConnectionTrait>(
    conn: &C,
    sql: &str,
    values: Vec<Value>,
) -> Result<Option<T>> {
    conn.query_one(statement(conn, sql, values))
        .await?
        .map(|row| {
            let state: String = row.try_get("", "state")?;
            Ok(serde_json::from_str(&state)?)
        })
        .transpose()
}

async fn read_all<T: DeserializeOwned, C: ConnectionTrait>(
    conn: &C,
    sql: &str,
    values: Vec<Value>,
) -> Result<Vec<T>> {
    conn.query_all(statement(conn, sql, values))
        .await?
        .into_iter()
        .map(|row| {
            let state: String = row.try_get("", "state")?;
            Ok(serde_json::from_str(&state)?)
        })
        .collect()
}
