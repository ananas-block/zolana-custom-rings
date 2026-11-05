//! Point reads of a ring's projection, where every miss of the bounded mirror lands.
//!
//! Each read sees committed rows only. The mirror never caches what these return, so a read racing
//! a commit cannot leave a stale entry behind. Read after `storage/spent_index.rs`.

use std::collections::HashMap;

use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, Statement, Value};
use solana_address::Address;

use crate::{
    spend_machine::{SpendRow, SpendState},
    spent_index::{
        read_enrollment, read_note, read_spend_row, state_name, NoteSeal, ENROLLMENT_COLUMNS,
        NOTE_COLUMNS, ROW_COLUMNS,
    },
    tracking::HeldEnrollment,
    utxos::StoredUtxo,
};

/// The key an enrollment lookup names, each read through its own column.
#[derive(Clone, Copy, Debug)]
pub(crate) enum EnrollmentKey {
    Member,
    /// Tagged on disk, the column names no owner hash.
    OwnerHash,
    /// Tagged on disk, the column names no list key.
    ListKey,
}

/// Keys bound into one statement, under every backend's parameter ceiling.
const KEYS_PER_READ: usize = 256;

#[must_use]
pub(crate) struct ProjectionReads<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub seal: &'a NoteSeal,
}

impl ProjectionReads<'_> {
    pub(crate) async fn notes(
        &self,
        commitments: &[[u8; 32]],
    ) -> Result<Vec<([u8; 32], StoredUtxo)>, DbErr> {
        let mut notes = Vec::new();
        for chunk in commitments.chunks(KEYS_PER_READ) {
            for row in self
                .keyed(
                    &format!("SELECT {NOTE_COLUMNS} FROM finalized_notes"),
                    "commitment",
                    chunk,
                )
                .await?
            {
                notes.push(read_note(&row, self.seal)?);
            }
        }
        Ok(notes)
    }

    /// A row found by tag counts only when its sealed body names the asked nullifier.
    pub(crate) async fn notes_by_nullifier(
        &self,
        nullifiers: &[[u8; 32]],
    ) -> Result<Vec<([u8; 32], StoredUtxo)>, DbErr> {
        let mut notes = Vec::new();
        for chunk in nullifiers.chunks(KEYS_PER_READ) {
            let tags = chunk
                .iter()
                .map(|nullifier| self.seal.tags.nullifier_tag(nullifier))
                .collect::<Result<Vec<_>, _>>()?;
            for row in self
                .keyed(
                    &format!("SELECT {NOTE_COLUMNS} FROM finalized_notes"),
                    "nullifier_tag",
                    &tags,
                )
                .await?
            {
                let (commitment, note) = read_note(&row, self.seal)?;
                if !note
                    .nullifier
                    .is_some_and(|nullifier| chunk.contains(&nullifier))
                {
                    return Err(DbErr::Custom("note row names another nullifier".into()));
                }
                notes.push((commitment, note));
            }
        }
        Ok(notes)
    }

    pub(crate) async fn rows(&self, nullifiers: &[[u8; 32]]) -> Result<Vec<SpendRow>, DbErr> {
        let mut rows = Vec::new();
        for chunk in nullifiers.chunks(KEYS_PER_READ) {
            for row in self
                .keyed(
                    &format!("SELECT {ROW_COLUMNS} FROM finalized_spent_nullifiers"),
                    "nullifier",
                    chunk,
                )
                .await?
            {
                rows.push(read_spend_row(&row, self.seal)?);
            }
        }
        Ok(rows)
    }

    pub(crate) async fn state_counts(&self) -> Result<HashMap<String, u64>, DbErr> {
        self.db
            .query_all(
                self.statement(
                    "SELECT state,COUNT(*) AS rows FROM finalized_spent_nullifiers WHERE ring=$1 \
                 GROUP BY state"
                        .to_owned(),
                    Vec::new(),
                ),
            )
            .await?
            .iter()
            .map(|row| {
                let count = u64::try_from(row.try_get::<i64>("", "rows")?)
                    .map_err(|_| DbErr::Custom("negative row count".into()))?;
                Ok((row.try_get::<String>("", "state")?, count))
            })
            .collect()
    }

    /// A row found by a tag counts only when its sealed body names the asked key.
    pub(crate) async fn enrollments(
        &self,
        key: EnrollmentKey,
        values: &[[u8; 32]],
    ) -> Result<Vec<HeldEnrollment>, DbErr> {
        let tags = &self.seal.tags;
        let column = match key {
            EnrollmentKey::Member => "member",
            EnrollmentKey::OwnerHash => "owner_hash_tag",
            EnrollmentKey::ListKey => "list_key_tag",
        };
        let mut found = Vec::new();
        for chunk in values.chunks(KEYS_PER_READ) {
            let stored = chunk
                .iter()
                .map(|value| match key {
                    EnrollmentKey::Member => Ok(*value),
                    EnrollmentKey::OwnerHash => tags.owner_hash_tag(value),
                    EnrollmentKey::ListKey => tags.list_key_tag(value),
                })
                .collect::<Result<Vec<_>, _>>()?;
            for row in self
                .keyed(
                    &format!("SELECT {ENROLLMENT_COLUMNS} FROM held_enrollments"),
                    column,
                    &stored,
                )
                .await?
            {
                let held = read_enrollment(&row, self.seal)?;
                if !chunk.contains(&key.of(&held)) {
                    return Err(DbErr::Custom("enrollment row names another key".into()));
                }
                found.push(held);
            }
        }
        Ok(found)
    }

    pub(crate) async fn unresolved(&self) -> Result<Vec<SpendRow>, DbErr> {
        self.db
            .query_all(self.statement(
                format!(
                    "SELECT {ROW_COLUMNS} FROM finalized_spent_nullifiers WHERE ring=$1 \
                     AND state=$2"
                ),
                vec![state_name(SpendState::UnresolvedReal).into()],
            ))
            .await?
            .iter()
            .map(|row| read_spend_row(row, self.seal))
            .collect()
    }

    async fn keyed(
        &self,
        select: &str,
        column: &str,
        keys: &[[u8; 32]],
    ) -> Result<Vec<sea_orm::QueryResult>, DbErr> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders: Vec<String> = (0..keys.len())
            .map(|index| format!("${}", index + 2))
            .collect();
        self.db
            .query_all(self.statement(
                format!(
                    "{select} WHERE ring=$1 AND {column} IN ({})",
                    placeholders.join(",")
                ),
                keys.iter().map(|key| key.to_vec().into()).collect(),
            ))
            .await
    }

    fn statement(&self, sql: String, values: Vec<Value>) -> Statement {
        let mut bound = vec![Value::from(self.ring.as_ref().to_vec())];
        bound.extend(values);
        Statement::from_sql_and_values(self.db.get_database_backend(), sql, bound)
    }
}

impl EnrollmentKey {
    pub(crate) const fn of(self, held: &HeldEnrollment) -> [u8; 32] {
        match self {
            Self::Member => held.member,
            Self::OwnerHash => held.owner_hash,
            Self::ListKey => held.list_key,
        }
    }
}
