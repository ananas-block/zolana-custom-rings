use std::sync::Arc;

use jsonrpsee::{core::RegisterMethodError, types::ErrorObjectOwned, Methods, RpcModule};
use photon_indexer::{
    migration::sea_orm::DatabaseConnection, rpc::RpcClient, Extension, IndexerContext,
};
use tokio::task::JoinHandle;
use zolana_indexer_api::RpcMethod;
use zolana_ring_indexer::rpc::method::{
    GetRingApplyProofInputs, GetRingMemberOpenings, GetRingMemberRecord, GetRingMemberRecords,
    GetRingMemberRegistryRoot, GetRingRecordQueue,
};

use crate::{member_registry, member_registry::CachedChain, CustomRingIndexer, StartSlot};

pub struct CustomRings {
    /// First indexed custom ring slot, the SPP indexer's last indexed slot by
    /// default.
    pub start_slot: Option<u64>,
}

struct Lookups {
    db: Arc<DatabaseConnection>,
    chain: CachedChain,
}

macro_rules! register {
    ($module:ident, $($method:ty => $read:path,)+) => {
        $($module.register_async_method(<$method>::NAME, |params, lookups, _| async move {
            $read(&lookups.db, &lookups.chain, params.parse()?)
                .await
                .map_err(ErrorObjectOwned::from)
        })?;)+
    };
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
        let mut module = RpcModule::new(Lookups {
            db,
            chain: CachedChain::new(rpc),
        });
        register!(
            module,
            GetRingMemberRecord => member_registry::member_record,
            GetRingMemberRecords => member_registry::member_records,
            GetRingMemberOpenings => member_registry::member_openings,
            GetRingMemberRegistryRoot => member_registry::registry_root,
            GetRingRecordQueue => member_registry::record_queue,
            GetRingApplyProofInputs => member_registry::apply_proof_inputs,
        );
        Ok(module.into())
    }
}
