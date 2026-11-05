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
}
