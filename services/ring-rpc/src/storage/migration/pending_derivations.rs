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
        manager.get_connection().execute_unprepared(&format!(
            "CREATE TABLE pending_derivations (ring {blob} NOT NULL, member {blob} NOT NULL, PRIMARY KEY(ring,member))"
        )).await?;
        manager.get_connection().execute_unprepared(
            "INSERT INTO pending_derivations(ring,member) SELECT ring,member FROM held_enrollments"
        ).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE pending_derivations")
            .await?;
        Ok(())
    }
}
