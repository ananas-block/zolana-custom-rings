use sea_orm_migration::prelude::*;

use super::m20261024_000002_record_tree::{blob, execute, rewind_cursor};

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Leaf hashes change, so every registry reindexes on a fresh deployment.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = blob(manager);
        let mut statements = cleared_rows();
        statements.extend(record_table(
            blob,
            &format!(
                "address_hash {blob} NOT NULL, address_ring_id {blob}, \
             address_nullifier_pk {blob}, address_viewing_u {blob}, address_revision BIGINT, "
            ),
        ));
        statements.extend([
            format!(
                "CREATE TABLE storage_address_enrollments (registry {blob} NOT NULL, \
                 member {blob} NOT NULL, address_revision BIGINT NOT NULL, ring_id {blob} NOT NULL, \
                 nullifier_pk {blob} NOT NULL, viewing_u {blob} NOT NULL, slot BIGINT NOT NULL, \
                 PRIMARY KEY(registry, member, address_revision))"
            ),
            "CREATE INDEX storage_address_enrollments_slot ON storage_address_enrollments(slot)"
                .into(),
        ]);
        execute(manager, statements).await?;
        rewind_cursor(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut statements = cleared_rows();
        statements.push("DROP TABLE storage_address_enrollments".into());
        statements.extend(record_table(blob(manager), ""));
        execute(manager, statements).await?;
        rewind_cursor(manager).await
    }
}

fn cleared_rows() -> Vec<String> {
    [
        "ring_blocks",
        "ring_record_nodes",
        "storage_roots",
        "storage_registries",
    ]
    .map(|table| format!("DELETE FROM {table}"))
    .to_vec()
}

fn record_table(blob: &str, address_columns: &str) -> Vec<String> {
    vec![
        "DROP TABLE ring_records".into(),
        format!(
            "CREATE TABLE ring_records (program {blob} NOT NULL, leaf_index BIGINT NOT NULL, \
             applied BIGINT NOT NULL, member {blob} NOT NULL, next_member {blob} NOT NULL, \
             lists BIGINT NOT NULL, escrow_key {blob} NOT NULL, seal TEXT, mint_policy TEXT, \
             {address_columns}PRIMARY KEY(program, leaf_index, applied))"
        ),
        "CREATE INDEX ring_records_member ON ring_records(program, member, applied)".into(),
        "CREATE INDEX ring_records_applied ON ring_records(program, applied)".into(),
    ]
}
