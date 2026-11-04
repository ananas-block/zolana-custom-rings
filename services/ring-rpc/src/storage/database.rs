use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

use crate::{error::RingRpcError, migration::Migrator};

/// One flush at a time, the rest serve submits and status reads.
pub const STORE_CONNECTIONS: u32 = 4;

/// Migrated when opened, clones share one pool.
#[derive(Clone)]
pub struct Store {
    db: DatabaseConnection,
}

impl Store {
    /// `url` is a `postgres://` or `sqlite://` URL.
    pub async fn open(url: &str, max_connections: u32) -> Result<Self, RingRpcError> {
        let db = Database::connect(
            ConnectOptions::new(url)
                .max_connections(max_connections)
                .sqlx_logging(false)
                .to_owned(),
        )
        .await?;
        Migrator::check_finality_upgrade(&db).await?;
        if db.get_database_backend() == DatabaseBackend::Sqlite {
            // Readers run beside the writer.
            db.execute_unprepared("PRAGMA journal_mode=WAL").await?;
        }
        Migrator::up(&db, None).await?;
        Ok(Self { db })
    }

    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Statement;
    use sea_orm_migration::SchemaManager;

    /// Each connection of the pool can hold an older schema when a later migration runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fresh_file_migrates_through_a_pool_and_reopens() {
        let directory = std::env::temp_dir().join(format!("store-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("directory");
        for attempt in 0..32 {
            let path = directory.join(format!("{attempt}.sqlite"));
            let url = format!("sqlite://{}?mode=rwc", path.display());
            Store::open(&url, STORE_CONNECTIONS).await.expect("fresh");
            Store::open(&url, STORE_CONNECTIONS).await.expect("restart");
        }
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn a_finality_upgrade_refuses_reservations_before_prior_migrations_change_them() {
        let path = std::env::temp_dir().join(format!(
            "finality-upgrade-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let connection = Database::connect(ConnectOptions::new(&url).max_connections(1).to_owned())
            .await
            .expect("database");
        let steps = Migrator::migrations()
            .iter()
            .position(|migration| migration.name() == "cosign4_000001_owner_debits")
            .expect("reservation migration");
        Migrator::up(&connection, Some(steps.try_into().expect("steps")))
            .await
            .expect("prior migrations");
        connection
            .execute_unprepared(
                "INSERT INTO cosign_usage VALUES(zeroblob(64),zeroblob(32),zeroblob(32),\
                 zeroblob(32),1,zeroblob(8),zeroblob(8),zeroblob(8),1)",
            )
            .await
            .expect("reservation");

        let Err(refusal) = Store::open(&url, 1).await else {
            panic!("fresh state required");
        };
        assert!(refusal.to_string().contains("cosign_usage"));
        let manager = SchemaManager::new(&connection);
        assert!(manager
            .has_column("cosign_usage", "sender")
            .await
            .expect("old column"));
        assert!(!manager
            .has_column("cosign_usage", "owner")
            .await
            .expect("new column"));
        assert!(!manager
            .has_table("finalized_spent_commitments")
            .await
            .expect("finalized schema"));
        let row = connection
            .query_one(Statement::from_string(
                connection.get_database_backend(),
                "SELECT COUNT(*) AS count FROM cosign_usage".to_owned(),
            ))
            .await
            .expect("reservation count")
            .expect("count row");
        assert_eq!(row.try_get::<i64>("", "count").expect("count"), 1);
    }
}
