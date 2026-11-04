use serde::{Deserialize, Serialize};
use spr_indexer_api::{Context, Hash, RpcMethod, SerializablePubkey};

use crate::rpc::StorageRootView;

pub mod method {
    use super::*;

    pub struct GetPrivateListWrites;

    impl RpcMethod for GetPrivateListWrites {
        const NAME: &'static str = "getPrivateListWrites";
        type Request = GetPrivateListWritesRequest;
        type Response = GetPrivateListWritesResponse;
    }
}

/// A private source's published writes up to `expected_root`, a reader rebuilds the sparse tree from them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetPrivateListWritesRequest {
    pub registry: SerializablePubkey,
    pub expected_root: Hash,
    /// Zero opens the first write of the source.
    pub start: u64,
    pub limit: u64,
}

/// Public by design, it holds no salt and no list bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingPublishedListWriteView {
    pub position: Hash,
    pub leaf: Hash,
    pub write_counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetPrivateListWritesResponse {
    pub context: Context,
    pub root: StorageRootView,
    /// In chain order.
    pub writes: Vec<RingPublishedListWriteView>,
    pub next_start: Option<u64>,
}
