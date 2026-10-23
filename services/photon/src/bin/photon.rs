use anyhow::Result;
use clap::Parser;
use custom_ring_photon::CustomRings;
use photon_indexer::{migration::RingsMigrator, Extension, PhotonArgs};

/// Photon: the Rings indexer, with the custom ring indexer
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(flatten)]
    photon: PhotonArgs,

    /// Run without the custom ring indexer and its RPC methods.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    disable_custom_rings: bool,

    /// First indexed custom ring slot, the SPP indexer's last indexed slot by
    /// default.
    #[arg(long, conflicts_with = "disable_custom_rings")]
    custom_rings_start_slot: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let extensions: Vec<Box<dyn Extension>> = if cli.disable_custom_rings {
        Vec::new()
    } else {
        vec![Box::new(CustomRings {
            start_slot: cli.custom_rings_start_slot,
        })]
    };
    photon_indexer::run::<RingsMigrator>(cli.photon, &extensions).await
}
