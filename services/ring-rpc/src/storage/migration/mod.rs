use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(Schema)]
    }
}

#[derive(DeriveMigrationName)]
struct Schema;

const TABLES: [&str; 15] = [
    "spend_unread_frames",
    "spend_integrity_faults",
    "spend_checkpoints",
    "replay_nonces",
    "relay_relays",
    "relay_enrollments",
    "records_updates",
    "merge_settings",
    "merge_inputs",
    "grants",
    "finalized_spent_nullifiers",
    "finalized_notes",
    "cosign_usage",
    "cosign_admission",
    "records_batches",
];

#[async_trait::async_trait]
impl MigrationTrait for Schema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let (blob, serial) = match manager.get_database_backend() {
            DatabaseBackend::Postgres => ("BYTEA", "BIGSERIAL PRIMARY KEY"),
            _ => ("BLOB", "INTEGER PRIMARY KEY AUTOINCREMENT"),
        };
        for sql in [
            format!("CREATE TABLE records_batches (id {serial}, registry {blob} NOT NULL, signature {blob} NOT NULL, revision BIGINT NOT NULL, last_valid_block_height BIGINT NOT NULL, status TEXT NOT NULL)"),
            format!("CREATE TABLE cosign_admission (ring {blob} NOT NULL, asset {blob} NOT NULL, PRIMARY KEY(ring, asset))"),
            format!("CREATE TABLE cosign_usage (signature {blob} NOT NULL, ring {blob} NOT NULL, owner {blob} NOT NULL, asset {blob} NOT NULL, slot BIGINT NOT NULL, outflow {blob} NOT NULL, deposited {blob} NOT NULL, withdrawn {blob} NOT NULL, confirmed BOOLEAN NOT NULL, PRIMARY KEY(signature, owner, asset))"),
            format!("CREATE TABLE finalized_notes (ring {blob} NOT NULL, commitment {blob} NOT NULL, sealed {blob} NOT NULL, PRIMARY KEY(ring, commitment))"),
            format!("CREATE TABLE finalized_spent_nullifiers (ring {blob} NOT NULL, nullifier {blob} NOT NULL, slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, position INTEGER NOT NULL, state VARCHAR(16) NOT NULL, sealed_note {blob}, PRIMARY KEY(ring, nullifier))"),
            format!("CREATE TABLE grants (id {serial}, reader {blob} NOT NULL, sealed {blob} NOT NULL)"),
            format!("CREATE TABLE merge_inputs (nullifier {blob} PRIMARY KEY, ring {blob} NOT NULL, relay_id {blob} NOT NULL)"),
            format!("CREATE TABLE merge_settings (ring {blob} NOT NULL, owner {blob} NOT NULL, mint {blob} NOT NULL, target_note_count BIGINT NOT NULL, min_average_amount {blob} NOT NULL, signed_at BIGINT NOT NULL, PRIMARY KEY(ring, owner, mint))"),
            format!("CREATE TABLE records_updates (seq {serial}, id {blob} NOT NULL UNIQUE, registry {blob} NOT NULL, ring {blob} NOT NULL, request TEXT NOT NULL, writes {blob} NOT NULL, queued_slot BIGINT NOT NULL, valid_until_slot BIGINT NOT NULL, status TEXT NOT NULL, batch BIGINT REFERENCES records_batches(id), reason TEXT, attempts BIGINT NOT NULL DEFAULT 0, awaited BIGINT NOT NULL DEFAULT 0, joined {blob}, member {blob}, signer {blob}, role TEXT)"),
            format!("CREATE TABLE relay_enrollments (relay_id {blob} NOT NULL PRIMARY KEY)"),
            format!("CREATE TABLE relay_relays (relay_id {blob} PRIMARY KEY, status TEXT NOT NULL, state TEXT NOT NULL)"),
            format!("CREATE TABLE replay_nonces (ring {blob} NOT NULL, nonce {blob} NOT NULL, signed_at BIGINT NOT NULL, PRIMARY KEY(ring, nonce))"),
            format!("CREATE TABLE spend_checkpoints (ring {blob} NOT NULL PRIMARY KEY, after_slot BIGINT, token VARCHAR(256), through_slot BIGINT NOT NULL, block_time BIGINT NOT NULL)"),
            format!("CREATE TABLE spend_integrity_faults (ring {blob} NOT NULL, nullifier {blob} NOT NULL, slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, PRIMARY KEY(ring, nullifier, tx_signature, event_index))"),
            format!("CREATE TABLE spend_unread_frames (ring {blob} NOT NULL, slot BIGINT NOT NULL, tx_signature {blob} NOT NULL, event_index INTEGER NOT NULL, PRIMARY KEY(ring, tx_signature, event_index))"),
            "CREATE INDEX cosign_usage_window ON cosign_usage(ring, asset, slot)".to_owned(),
            "CREATE INDEX grants_reader ON grants(reader)".to_owned(),
            "CREATE INDEX merge_inputs_ring ON merge_inputs(ring)".to_owned(),
            "CREATE INDEX records_updates_joined ON records_updates(joined)".to_owned(),
            "CREATE INDEX records_updates_member ON records_updates(ring, member)".to_owned(),
            "CREATE INDEX records_updates_queue ON records_updates(registry, status, seq)".to_owned(),
            "CREATE INDEX records_updates_ring ON records_updates(ring, status, seq)".to_owned(),
            "CREATE INDEX relay_relays_status ON relay_relays(status)".to_owned(),
            "CREATE INDEX replay_nonces_signed_at ON replay_nonces(signed_at)".to_owned(),
            "CREATE UNIQUE INDEX records_batches_open ON records_batches(registry) WHERE status = 'submitted'".to_owned(),
        ] {
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in TABLES {
            manager
                .get_connection()
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        Ok(())
    }
}
