use sea_orm::Statement;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        require_fresh_operations(manager).await?;
        super::create_spent_table(manager, "finalized_spent_commitments").await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE finalized_spent_commitments")
            .await?;
        Ok(())
    }
}

pub(super) async fn require_fresh_operations(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    for table in [
        "relay_relays",
        "cosign_usage",
        "records_batches",
        "records_updates",
    ] {
        if manager.has_table(table).await?
            && manager
                .get_connection()
                .query_one(Statement::from_string(
                    manager.get_database_backend(),
                    format!("SELECT 1 FROM {table} LIMIT 1"),
                ))
                .await?
                .is_some()
        {
            return Err(DbErr::Custom(format!(
                "nonempty {table} requires a fresh RPC database for finalized operations"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectOptions, Database, DatabaseConnection};

    async fn prior_schema() -> DatabaseConnection {
        let connection = Database::connect(
            ConnectOptions::new("sqlite::memory:")
                .max_connections(1)
                .to_owned(),
        )
        .await
        .expect("database");
        let manager = SchemaManager::new(&connection);
        for migration in super::super::Migrator::migrations() {
            if migration.name() == Migration.name() {
                break;
            }
            migration.up(&manager).await.expect("prior migration");
        }
        connection
    }

    #[tokio::test]
    async fn migration_preserves_confirmed_rows_without_promoting_them() {
        let connection = prior_schema().await;
        let manager = SchemaManager::new(&connection);
        connection
            .execute_unprepared(
                "INSERT INTO spent_commitments VALUES(zeroblob(32),1,zeroblob(64),0,\
                 zeroblob(32),'transfer')",
            )
            .await
            .expect("confirmed row");
        Migration.up(&manager).await.expect("finalized schema");
        for (table, expected) in [("spent_commitments", 1), ("finalized_spent_commitments", 0)] {
            let row = connection
                .query_one(Statement::from_string(
                    connection.get_database_backend(),
                    format!("SELECT COUNT(*) AS count FROM {table}"),
                ))
                .await
                .expect("row count")
                .expect("count row");
            assert_eq!(row.try_get::<i64>("", "count").expect("count"), expected);
        }
    }

    #[tokio::test]
    async fn migration_refuses_each_retained_operation_table_without_writes() {
        for (table, insert) in [
            (
                "relay_relays",
                "INSERT INTO relay_relays VALUES(zeroblob(32),'confirmed','{}')",
            ),
            (
                "cosign_usage",
                "INSERT INTO cosign_usage VALUES(zeroblob(64),zeroblob(32),zeroblob(32),\
                 zeroblob(32),1,zeroblob(8),zeroblob(8),zeroblob(8),1)",
            ),
            (
                "records_batches",
                "INSERT INTO records_batches(registry,signature,revision,last_valid_block_height,\
                 status) VALUES(zeroblob(32),zeroblob(64),1,1,'applied')",
            ),
            (
                "records_updates",
                "INSERT INTO records_updates(id,registry,ring,request,writes,queued_slot,\
                 valid_until_slot,status) VALUES(zeroblob(32),zeroblob(32),zeroblob(32),'{}',\
                 zeroblob(1),1,1,'applied')",
            ),
        ] {
            let connection = prior_schema().await;
            let manager = SchemaManager::new(&connection);
            connection
                .execute_unprepared(insert)
                .await
                .expect("retained row");
            let refusal = Migration
                .up(&manager)
                .await
                .expect_err("fresh state required");
            assert!(refusal.to_string().contains(table));
            assert!(!manager
                .has_table("finalized_spent_commitments")
                .await
                .expect("schema"));
            assert!(connection
                .query_one(Statement::from_string(
                    connection.get_database_backend(),
                    format!("SELECT 1 FROM {table}"),
                ))
                .await
                .expect("retained row")
                .is_some());
        }
    }
}
