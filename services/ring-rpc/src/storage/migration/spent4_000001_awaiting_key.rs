use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

/// The owner stays sealed under the auditor key at rest.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = match manager.get_database_backend() {
            DatabaseBackend::Postgres => "BYTEA",
            _ => "BLOB",
        };
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "CREATE TABLE spend_awaiting_key (ring {blob} NOT NULL, commitment {blob} NOT NULL, \
                 slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, \
                 sealed_owner {blob} NOT NULL, PRIMARY KEY(ring, commitment))"
            ))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE spend_awaiting_key")
            .await?;
        Ok(())
    }
}
