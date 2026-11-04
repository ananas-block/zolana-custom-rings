use sea_orm_migration::prelude::*;

use super::m20261024_000002_record_tree::{blob, execute, rewind_cursor};

#[derive(DeriveMigrationName)]
pub struct Migration;

const CLEARED_TABLES: [&str; 5] = [
    "ring_blocks",
    "ring_records",
    "ring_record_nodes",
    "storage_roots",
    "storage_registries",
];

/// An older index skipped every enrollment, so each registry reindexes from the start slot.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = blob(manager);
        let mut statements = cleared_rows();
        statements.extend([
            format!(
                "CREATE TABLE tracking_registries (registry {blob} PRIMARY KEY, \
                 state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE tracking_records (registry {blob} NOT NULL, \
                 leaf_index BIGINT NOT NULL, applied BIGINT NOT NULL, member {blob} NOT NULL, \
                 next_member {blob} NOT NULL, nullifier_pk {blob} NOT NULL, \
                 ct_hash {blob} NOT NULL, viewing_u {blob} NOT NULL, revision BIGINT NOT NULL, \
                 list_tag {blob} NOT NULL, PRIMARY KEY(registry, leaf_index, applied))"
            ),
            "CREATE INDEX tracking_records_member ON tracking_records(registry, member, applied)"
                .into(),
            "CREATE INDEX tracking_records_applied ON tracking_records(registry, applied)".into(),
            format!(
                "CREATE TABLE tracking_authorizations (registry {blob} NOT NULL, \
                 owner {blob} NOT NULL, member {blob} NOT NULL, nullifier_pk {blob} NOT NULL, \
                 ct_hash {blob} NOT NULL, list_tag {blob} NOT NULL, eph_u {blob} NOT NULL, \
                 ciphertext {blob} NOT NULL, slot BIGINT NOT NULL, \
                 PRIMARY KEY(registry, owner))"
            ),
            "CREATE INDEX tracking_authorizations_member \
             ON tracking_authorizations(registry, member)"
                .into(),
            "CREATE INDEX tracking_authorizations_slot ON tracking_authorizations(slot)".into(),
            format!(
                "CREATE TABLE tracking_enrollments (registry {blob} NOT NULL, \
                 owner {blob} NOT NULL, revision BIGINT NOT NULL, viewing_u {blob} NOT NULL, \
                 slot BIGINT NOT NULL, applied_slot BIGINT, \
                 PRIMARY KEY(registry, owner, revision))"
            ),
            "CREATE INDEX tracking_enrollments_slot ON tracking_enrollments(slot)".into(),
            "CREATE INDEX tracking_enrollments_applied_slot \
             ON tracking_enrollments(applied_slot)"
                .into(),
        ]);
        execute(manager, statements).await?;
        rewind_cursor(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut statements = cleared_rows();
        statements.extend(
            [
                "tracking_enrollments",
                "tracking_authorizations",
                "tracking_records",
                "tracking_registries",
            ]
            .map(|table| format!("DROP TABLE {table}")),
        );
        execute(manager, statements).await?;
        rewind_cursor(manager).await
    }
}

fn cleared_rows() -> Vec<String> {
    CLEARED_TABLES
        .map(|table| format!("DELETE FROM {table}"))
        .to_vec()
}
