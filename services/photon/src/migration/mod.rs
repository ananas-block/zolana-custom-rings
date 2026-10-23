//! The pinned SPP and ring migrations, then the member registry ones.

use photon_indexer::migration::{MigrationTrait, MigratorTrait, RingsMigrator};

mod m20261016_000001_drop_ring_spend_records;
mod m20261017_000001_member_registry;
mod m20261021_000001_record_tree;

pub struct CustomRingMigrator;

#[async_trait::async_trait]
impl MigratorTrait for CustomRingMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        let mut migrations = RingsMigrator::migrations();
        migrations.extend([
            Box::new(m20261016_000001_drop_ring_spend_records::Migration)
                as Box<dyn MigrationTrait>,
            Box::new(m20261017_000001_member_registry::Migration),
            Box::new(m20261021_000001_record_tree::Migration),
        ]);
        migrations
    }
}
