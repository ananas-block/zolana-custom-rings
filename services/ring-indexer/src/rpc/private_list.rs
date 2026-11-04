use sea_orm::DatabaseConnection;
use spr_indexer_api::Hash;
use zolana_ring_indexer::private_list::{
    GetPrivateListWritesRequest, GetPrivateListWritesResponse, RingPublishedListWriteView,
};

use super::{
    check_page_limit, internal, storage_root_view, validation, ChainSource, Served, Snapshot,
};
use crate::{
    error::RingApiError,
    storage::{ListWritePage, StorageState},
};

pub(crate) async fn private_list_writes(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetPrivateListWritesRequest,
) -> Result<GetPrivateListWritesResponse, RingApiError> {
    check_page_limit(request.limit)?;
    let snapshot = Snapshot::<StorageState>::registry(db, &request.registry).await?;
    if !snapshot.state.account.is_private() {
        return Err(validation("a public source has no list writes"));
    }
    let read = snapshot.at_root(&request.expected_root.0).await?;
    let root = read.root;
    let rows = read
        .snapshot
        .store()
        .list_writes(ListWritePage {
            start: request.start,
            limit: request.limit,
            revision: root.revision,
        })
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
