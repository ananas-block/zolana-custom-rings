use sea_orm::DatabaseConnection;
use spr_indexer_api::Hash;
use zolana_ring_indexer::{
    private_list::{
        GetPrivateListWritesRequest, GetPrivateListWritesResponse, RingPublishedListWriteView,
    },
    rpc::MAX_RING_MEMBER_PAGE_LIMIT,
};

use super::{internal, storage_root_view, validation, ChainSource, Served, Snapshot};
use crate::{error::RingApiError, storage::StorageState};

/// Serves only what each write published, the index holds no salt and no list bits.
pub(crate) async fn private_list_writes(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetPrivateListWritesRequest,
) -> Result<GetPrivateListWritesResponse, RingApiError> {
    if request.limit == 0 || request.limit > MAX_RING_MEMBER_PAGE_LIMIT {
        return Err(validation("invalid list write page limit"));
    }
    let snapshot = Snapshot::<StorageState>::registry(db, &request.registry).await?;
    if !snapshot.state.account.is_private() {
        return Err(validation("a public source has no list writes"));
    }
    let read = snapshot.at_root(&request.expected_root.0).await?;
    let root = read.root;
    let rows = read
        .snapshot
        .store()
        .list_writes(request.start, request.limit, root.revision)
        .await
        .map_err(internal)?;
    let context = read.snapshot.confirm(chain, Served::Root(&root)).await?;
    let next_start = (rows.len() as u64 == request.limit).then(|| request.start + request.limit);
    Ok(GetPrivateListWritesResponse {
        context,
        root: storage_root_view(&root),
        writes: rows
            .iter()
            .map(|row| RingPublishedListWriteView {
                position: Hash(row.position),
                leaf: Hash(row.leaf),
                write_counter: row.write_counter,
            })
            .collect(),
        next_start,
    })
}
