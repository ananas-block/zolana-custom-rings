use custom_ring_interface::tracking::TrackingRegistry;
use sea_orm::DatabaseConnection;
use solana_address::Address;
use spr_indexer_api::Hash;
use zolana_ring_indexer::{
    rpc::MAX_RING_MEMBER_PAGE_LIMIT,
    tracking::{
        GetPendingEnrollmentsRequest, GetPendingEnrollmentsResponse, RingPendingEnrollmentView,
    },
};

use super::{internal, validation, ChainSource, Served, Snapshot};
use crate::{
    error::RingApiError,
    storage::{Enrollment, RegistryState},
};

/// Serves an applier the accounts to name, pending state grants nothing.
pub(crate) async fn pending_enrollments(
    db: &DatabaseConnection,
    chain: &impl ChainSource,
    request: GetPendingEnrollmentsRequest,
) -> Result<GetPendingEnrollmentsResponse, RingApiError> {
    if request.limit == 0 || request.limit > MAX_RING_MEMBER_PAGE_LIMIT {
        return Err(validation("invalid enrollment page limit"));
    }
    let snapshot =
        Snapshot::<RegistryState<TrackingRegistry>>::registry(db, &request.registry).await?;
    let after = request.after.map(|owner| owner.0.to_bytes());
    let rows = snapshot
        .store()
        .pending(after.as_ref(), request.limit)
        .await
        .map_err(internal)?;
    let context = snapshot.confirm(chain, Served::Tip).await?;
    let next_after = rows
        .last()
        .filter(|_| rows.len() as u64 == request.limit)
        .map(|row| Address::new_from_array(row.owner).into());
    Ok(GetPendingEnrollmentsResponse {
        context,
        enrollments: rows.iter().map(pending_view).collect(),
        next_after,
    })
}

fn pending_view(row: &Enrollment) -> RingPendingEnrollmentView {
    RingPendingEnrollmentView {
        owner: Address::new_from_array(row.owner).into(),
        member: Hash(row.member),
        nullifier_pk: Hash(row.nullifier_pk),
        ct_hash: Hash(row.ct_hash),
        viewing_u: Hash(row.viewing_u),
        revision: row.revision,
        applied_revision: row.applied_revision,
        list_tag: Hash(row.list_tag),
    }
}
