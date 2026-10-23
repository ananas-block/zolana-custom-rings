use photon_indexer::migration::{cli, RingsMigrator};

#[tokio::main]
async fn main() {
    cli::main::<RingsMigrator>().await
}
