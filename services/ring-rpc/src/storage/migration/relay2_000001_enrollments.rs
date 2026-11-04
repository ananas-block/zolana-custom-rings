use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

/// One row per relay the fee payer funds an enrollment for, the operator's budget counts them.
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
                "CREATE TABLE relay_enrollments (relay_id {blob} NOT NULL PRIMARY KEY)"
            ))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE relay_enrollments")
            .await?;
        Ok(())
    }
}
