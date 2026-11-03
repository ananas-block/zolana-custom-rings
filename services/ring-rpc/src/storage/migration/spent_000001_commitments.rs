use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

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
                "CREATE TABLE spent_commitments (utxo_hash {blob} NOT NULL PRIMARY KEY, \
                 slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, \
                 first_nullifier {blob} NOT NULL, source VARCHAR(16) NOT NULL)"
            ))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE spent_commitments")
            .await?;
        Ok(())
    }
}
