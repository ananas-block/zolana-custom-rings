use sea_orm::{DatabaseBackend, DatabaseConnection, EntityTrait};
use sea_orm_migration::prelude::*;

mod cosign3_000001_admission;
mod cosign4_000001_owner_debits;
mod cosign5_000001_outflow;
mod cosign_m20261029_000001_usage;
mod grants;
mod merge2_000001_inputs;
mod merge_0001_settings;
mod records2_000001_attempts;
mod records3_000001_enrolments;
mod records4_000001_signers;
mod records_000001_queue;
mod relay2_000001_enrollments;
mod relay_000001_relays;
mod replay_000001_nonces;
mod spent2_000001_finalized;
mod spent3_000001_nullifiers;
mod spent_000001_commitments;

pub struct Migrator;

impl Migrator {
    pub(crate) async fn check_finality_upgrade(db: &DatabaseConnection) -> Result<(), DbErr> {
        let manager = SchemaManager::new(db);
        let applied = manager
            .has_table(Self::migration_table_name().to_string())
            .await?
            && sea_orm_migration::seaql_migrations::Entity::find_by_id(
                spent3_000001_nullifiers::Migration.name(),
            )
            .one(db)
            .await?
            .is_some();
        if !applied {
            spent2_000001_finalized::require_fresh_operations(&manager).await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(records_000001_queue::Migration),
            Box::new(grants::Migration),
            Box::new(relay_000001_relays::Migration),
            Box::new(cosign_m20261029_000001_usage::Migration),
            Box::new(merge_0001_settings::Migration),
            Box::new(records2_000001_attempts::Migration),
            Box::new(records3_000001_enrolments::Migration),
            Box::new(cosign3_000001_admission::Migration),
            Box::new(merge2_000001_inputs::Migration),
            Box::new(records4_000001_signers::Migration),
            Box::new(replay_000001_nonces::Migration),
            Box::new(spent_000001_commitments::Migration),
            Box::new(cosign4_000001_owner_debits::Migration),
            Box::new(spent2_000001_finalized::Migration),
            Box::new(spent3_000001_nullifiers::Migration),
            Box::new(cosign5_000001_outflow::Migration),
            Box::new(relay2_000001_enrollments::Migration),
        ]
    }
}

async fn create_spent_table(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    let blob = match manager.get_database_backend() {
        DatabaseBackend::Postgres => "BYTEA",
        _ => "BLOB",
    };
    manager
        .get_connection()
        .execute_unprepared(&format!(
            "CREATE TABLE {table} (utxo_hash {blob} NOT NULL PRIMARY KEY, \
             slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, \
             first_nullifier {blob} NOT NULL, source VARCHAR(16) NOT NULL)"
        ))
        .await?;
    Ok(())
}
