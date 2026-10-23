use custom_ring_photon::CustomRingMigrator;
use photon_indexer::migration::cli;

#[tokio::main]
async fn main() {
    cli::main::<CustomRingMigrator>().await
}
