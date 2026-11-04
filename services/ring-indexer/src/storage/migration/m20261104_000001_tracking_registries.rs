use sea_orm_migration::prelude::*;

use super::m20261024_000002_record_tree::{blob, execute, rewind_cursor};

#[derive(DeriveMigrationName)]
pub struct Migration;

const CLEARED_TABLES: [&str; 4] = [
    "ring_blocks",
    "ring_record_nodes",
    "storage_roots",
    "storage_registries",
];

/// Policy leaves change and an older index skipped every enrollment.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let blob = blob(manager);
        let mut statements = cleared_rows();
        statements.push("DROP TABLE storage_address_enrollments".into());
        statements.extend(record_table(blob, ""));
        statements.extend([
            format!(
                "CREATE TABLE tracking_registries (registry {blob} PRIMARY KEY, \
                 state TEXT NOT NULL)"
            ),
            format!(
                "CREATE TABLE tracking_records (program {blob} NOT NULL, \
                 leaf_index BIGINT NOT NULL, applied BIGINT NOT NULL, member {blob} NOT NULL, \
                 next_member {blob} NOT NULL, nullifier_pk {blob} NOT NULL, \
                 ct_hash {blob} NOT NULL, viewing_u {blob} NOT NULL, revision BIGINT NOT NULL, \
                 list_tag {blob} NOT NULL, PRIMARY KEY(program, leaf_index, applied))"
            ),
            "CREATE INDEX tracking_records_member ON tracking_records(program, member, applied)"
                .into(),
            "CREATE INDEX tracking_records_applied ON tracking_records(program, applied)".into(),
            format!(
                "CREATE TABLE tracking_authorizations (registry {blob} NOT NULL, \
                 owner {blob} NOT NULL, authorization_account {blob} NOT NULL, member {blob} NOT NULL, \
                 nullifier_pk {blob} NOT NULL, \
                 ct_hash {blob} NOT NULL, list_tag {blob} NOT NULL, eph_u {blob} NOT NULL, \
                 ciphertext {blob} NOT NULL, slot BIGINT NOT NULL, \
                 PRIMARY KEY(registry, owner))"
            ),
            "CREATE INDEX tracking_authorizations_account \
             ON tracking_authorizations(registry, authorization_account)"
                .into(),
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
        let blob = blob(manager);
        let mut statements = cleared_rows();
        statements.extend(record_table(
            blob,
            &format!(
                "escrow_key {blob} NOT NULL, seal TEXT, address_hash {blob} NOT NULL, \
                 address_ring_id {blob}, address_nullifier_pk {blob}, \
                 address_viewing_u {blob}, address_revision BIGINT, "
            ),
        ));
        statements.push(format!(
            "CREATE TABLE storage_address_enrollments (registry {blob} NOT NULL, \
             member {blob} NOT NULL, address_revision BIGINT NOT NULL, ring_id {blob} NOT NULL, \
             nullifier_pk {blob} NOT NULL, viewing_u {blob} NOT NULL, slot BIGINT NOT NULL, \
             PRIMARY KEY(registry, member, address_revision))"
        ));
        statements.push(
            "CREATE INDEX storage_address_enrollments_slot ON storage_address_enrollments(slot)"
                .into(),
        );
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

fn record_table(blob: &str, retired_columns: &str) -> Vec<String> {
    vec![
        "DROP TABLE ring_records".into(),
        format!(
            "CREATE TABLE ring_records (program {blob} NOT NULL, leaf_index BIGINT NOT NULL, \
             applied BIGINT NOT NULL, member {blob} NOT NULL, next_member {blob} NOT NULL, \
             lists BIGINT NOT NULL, mint_policy TEXT, {retired_columns}\
             PRIMARY KEY(program, leaf_index, applied))"
        ),
        "CREATE INDEX ring_records_member ON ring_records(program, member, applied)".into(),
        "CREATE INDEX ring_records_applied ON ring_records(program, applied)".into(),
    ]
}
