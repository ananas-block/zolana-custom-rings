use sea_orm_migration::prelude::*;

/// Reservations count what caps compare, a fresh store holds no earlier row.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE cosign_usage RENAME COLUMN debit TO outflow")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE cosign_usage RENAME COLUMN outflow TO debit")
            .await?;
        Ok(())
    }
}
