use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in ["ring_records", "ring_record_queue"] {
            manager
                .get_connection()
                .execute_unprepared(&format!("ALTER TABLE {table} ADD COLUMN mint_policy TEXT"))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in ["ring_records", "ring_record_queue"] {
            manager
                .get_connection()
                .execute_unprepared(&format!("ALTER TABLE {table} DROP COLUMN mint_policy"))
                .await?;
        }
        Ok(())
    }
}
