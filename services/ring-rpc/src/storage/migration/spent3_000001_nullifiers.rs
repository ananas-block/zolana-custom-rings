use sea_orm::{DatabaseBackend, TransactionTrait};
use sea_orm_migration::prelude::*;

use super::spent2_000001_finalized::require_fresh_operations;

/// Notes and their links stay sealed under the auditor key at rest.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        require_fresh_operations(manager).await?;
        let blob = match manager.get_database_backend() {
            DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        let transaction = manager.get_connection().begin().await?;
        for sql in [
            format!(
                "CREATE TABLE finalized_spent_nullifiers (ring {blob} NOT NULL, \
                 nullifier {blob} NOT NULL, slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, \
                 event_index INTEGER NOT NULL, position INTEGER NOT NULL, \
                 state VARCHAR(16) NOT NULL, sealed_note {blob}, PRIMARY KEY(ring, nullifier))"
            ),
            format!(
                "CREATE TABLE finalized_notes (ring {blob} NOT NULL, commitment {blob} NOT NULL, \
                 sealed {blob} NOT NULL, PRIMARY KEY(ring, commitment))"
            ),
            format!(
                "CREATE TABLE spend_unread_frames (ring {blob} NOT NULL, slot BIGINT NOT NULL, \
                 tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, \
                 PRIMARY KEY(ring, tx_signature, event_index))"
            ),
            format!(
                "CREATE TABLE spend_integrity_faults (ring {blob} NOT NULL, \
                 nullifier {blob} NOT NULL, slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, \
                 event_index INTEGER NOT NULL, \
                 PRIMARY KEY(ring, nullifier, tx_signature, event_index))"
            ),
            format!(
                "CREATE TABLE spend_checkpoints (ring {blob} NOT NULL PRIMARY KEY, \
                 after_slot BIGINT, token VARCHAR(256), through_slot BIGINT NOT NULL, \
                 block_time BIGINT NOT NULL)"
            ),
        ] {
            transaction.execute_unprepared(&sql).await?;
        }
        transaction.commit().await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            "spend_checkpoints",
            "spend_integrity_faults",
            "spend_unread_frames",
            "finalized_notes",
            "finalized_spent_nullifiers",
        ] {
            manager
                .get_connection()
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        Ok(())
    }
}
