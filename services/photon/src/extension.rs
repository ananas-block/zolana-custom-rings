use std::sync::Arc;

use jsonrpsee::{core::RegisterMethodError, types::ErrorObjectOwned, Methods, RpcModule};
use photon_indexer::{
    migration::sea_orm::DatabaseConnection, rpc::RpcClient, Extension, IndexerContext,
};
use tokio::task::JoinHandle;
use zolana_indexer_api::RpcMethod;
use zolana_ring_indexer::rpc::method::{
    GetRingKeyRegistryEntry, GetRingKeyRegistryRegisterProof, GetRingSpendRecord,
};

use crate::{key_registry, spend_record, CustomRingIndexer, StartSlot};

pub struct CustomRings {
    /// First indexed custom ring slot, the SPP indexer's last indexed slot by
    /// default.
    pub start_slot: Option<u64>,
}

struct Lookups {
    db: Arc<DatabaseConnection>,
    rpc: Arc<RpcClient>,
}

impl Extension for CustomRings {
    fn spawn_indexer(&self, context: IndexerContext) -> JoinHandle<()> {
        // Blocks before an explicit index start are not linkable. Without
        // one the index starts where SPP indexing starts or resumes, so
        // rings created earlier need the explicit slot.
        let start = match self.start_slot {
            Some(slot) => StartSlot::Explicit(slot.saturating_sub(1)),
            None => StartSlot::Derived(context.last_indexed_slot),
        };
        CustomRingIndexer {
            db: context.db,
            rpc: context.rpc,
            start,
            block_fetches: context.block_fetches,
        }
        .spawn()
    }

    fn rpc_methods(
        &self,
        db: Arc<DatabaseConnection>,
        rpc: Arc<RpcClient>,
    ) -> Result<Methods, RegisterMethodError> {
        let mut module = RpcModule::new(Lookups { db, rpc });
        module.register_async_method(
            GetRingKeyRegistryEntry::NAME,
            |params, lookups, _| async move {
                key_registry::lookup(&lookups.db, &lookups.rpc, params.parse()?)
                    .await
                    .map_err(ErrorObjectOwned::from)
            },
        )?;
        module.register_async_method(
            GetRingKeyRegistryRegisterProof::NAME,
            |params, lookups, _| async move {
                key_registry::register(&lookups.db, &lookups.rpc, params.parse()?)
                    .await
                    .map_err(ErrorObjectOwned::from)
            },
        )?;
        module.register_async_method(
            GetRingSpendRecord::NAME,
            |params, lookups, _| async move {
                spend_record::lookup(&lookups.db, &lookups.rpc, params.parse()?)
                    .await
                    .map_err(ErrorObjectOwned::from)
            },
        )?;
        Ok(module.into())
    }
}
