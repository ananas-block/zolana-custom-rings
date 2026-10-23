use photon_indexer::migration::{MigrationTrait, MigratorTrait, RingsMigrator};

mod m20260923_000001_ring_projection;
mod m20261017_000001_custom_ring_tables;

pub struct CustomRingMigrator;

#[async_trait::async_trait]
impl MigratorTrait for CustomRingMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        let mut migrations = RingsMigrator::migrations();
        migrations.push(Box::new(m20260923_000001_ring_projection::Migration));
        migrations.push(Box::new(m20261017_000001_custom_ring_tables::Migration));
        migrations
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};

    use super::*;

    const RING_TABLES: [&str; 7] = [
        "custom_ring_cursor",
        "custom_ring_blocks",
        "custom_ring_pending",
        "ring_key_registry_roots",
        "ring_key_registry_members",
        "ring_spend_record_rings",
        "ring_spend_records",
    ];

    async fn tables(db: &DatabaseConnection) -> Vec<String> {
        db.query_all(Statement::from_string(
            db.get_database_backend(),
            "SELECT name FROM sqlite_master WHERE type = 'table'",
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.try_get("", "name").unwrap())
        .collect()
    }

    #[tokio::test]
    async fn ring_tables_migrate_after_photon_and_roll_back_first() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        CustomRingMigrator::up(&db, None).await.unwrap();
        let migrated = tables(&db).await;
        assert!(migrated.iter().any(|name| name == "state_trees"));
        assert!(RING_TABLES
            .iter()
            .all(|table| migrated.iter().any(|name| name == table)));
        CustomRingMigrator::down(&db, Some(2)).await.unwrap();
        let photon = tables(&db).await;
        assert!(photon.iter().any(|name| name == "state_trees"));
        assert!(!RING_TABLES
            .iter()
            .any(|table| photon.iter().any(|name| name == table)));
    }
}
