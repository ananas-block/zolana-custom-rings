use sea_orm::{DatabaseBackend, TransactionTrait};
use sea_orm_migration::prelude::*;

/// Earlier reservations are dropped, their debits leave any open window.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = match manager.get_database_backend() {
            DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        // One connection, a pooled one prepares `CREATE INDEX` against its stale schema.
        let transaction = manager.get_connection().begin().await?;
        for sql in [
            "DROP TABLE cosign_usage".to_string(),
            format!(
                "CREATE TABLE cosign_usage (signature {blob} NOT NULL, ring {blob} NOT NULL, \
                 owner {blob} NOT NULL, asset {blob} NOT NULL, slot BIGINT NOT NULL, \
                 debit {blob} NOT NULL, deposited {blob} NOT NULL, withdrawn {blob} NOT NULL, \
                 confirmed BOOLEAN NOT NULL, PRIMARY KEY(signature, owner, asset))"
            ),
            "CREATE INDEX cosign_usage_window ON cosign_usage(ring, asset, slot)".to_string(),
        ] {
            transaction.execute_unprepared(&sql).await?;
        }
        transaction.commit().await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE cosign_usage")
            .await?;
        Ok(())
    }
}
