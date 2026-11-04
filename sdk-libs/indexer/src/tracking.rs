use serde::{Deserialize, Serialize};
use spr_indexer_api::{Base64String, Context, Hash, RpcMethod, SerializablePubkey};

use crate::rpc::{RingRecordPathView, StorageRootView};

pub mod method {
    use super::*;

    pub struct GetTrackingOpenings;
    pub struct GetTrackingRecords;
    pub struct GetTrackingRecordPool;
    pub struct GetPendingEnrollments;
    pub struct GetTrackingApplyProofInputs;

    impl RpcMethod for GetTrackingOpenings {
        const NAME: &'static str = "getTrackingOpenings";
        type Request = GetTrackingOpeningsRequest;
        type Response = GetTrackingOpeningsResponse;
    }

    impl RpcMethod for GetTrackingRecords {
        const NAME: &'static str = "getTrackingRecords";
        type Request = GetTrackingRecordsRequest;
        type Response = GetTrackingRecordsResponse;
    }

    impl RpcMethod for GetTrackingRecordPool {
        const NAME: &'static str = "getTrackingRecordPool";
        type Request = GetTrackingRecordPoolRequest;
        type Response = GetTrackingRecordPoolResponse;
    }

    impl RpcMethod for GetPendingEnrollments {
        const NAME: &'static str = "getPendingEnrollments";
        type Request = GetPendingEnrollmentsRequest;
        type Response = GetPendingEnrollmentsResponse;
    }

    impl RpcMethod for GetTrackingApplyProofInputs {
        const NAME: &'static str = "getTrackingApplyProofInputs";
        type Request = GetTrackingApplyProofInputsRequest;
        type Response = GetTrackingApplyProofInputsResponse;
    }
}

/// One tracking leaf, `viewing_u` splits into the leaf's two view fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingTrackingRecordView {
    pub member: Hash,
    pub next: Hash,
    pub nullifier_pk: Hash,
    pub ct_hash: Hash,
    pub viewing_u: Hash,
    pub revision: u64,
    pub list_tag: Hash,
    /// Absent on the sentinel alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<RingTrackingSealView>,
}

/// What `TrackingAuthorization` retains, `ciphertext` hashes to the leaf's `ct_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingTrackingSealView {
    /// Its owner tag is the leaf's `member`.
    pub owner: SerializablePubkey,
    /// Tagged X25519, 33 bytes.
    pub eph_pk: Base64String,
    /// 32 bytes.
    pub ciphertext: Base64String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingTrackingOpening {
    /// False proves the member holds no tracking row under `root`.
    pub present: bool,
    /// An absent member opens its low record.
    pub record: RingTrackingRecordView,
    pub path: RingRecordPathView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingIndexedTrackingRecordView {
    pub record: RingTrackingRecordView,
    pub path: RingRecordPathView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetTrackingOpeningsRequest {
    /// A `TrackingRegistry` account.
    pub registry: SerializablePubkey,
    pub members: Vec<Hash>,
    pub expected_root: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetTrackingOpeningsResponse {
    pub context: Context,
    pub root: StorageRootView,
    /// In request order.
    pub openings: Vec<RingTrackingOpening>,
}

/// Leaves from `start_index` under one root the registry serves, leaf 0 the sentinel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetTrackingRecordsRequest {
    pub registry: SerializablePubkey,
    pub expected_root: Hash,
    pub start_index: u64,
    pub limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetTrackingRecordsResponse {
    pub context: Context,
    pub root: StorageRootView,
    pub records: Vec<RingIndexedTrackingRecordView>,
    pub next_leaf_index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetTrackingRecordPoolRequest {
    pub registry: SerializablePubkey,
    pub members: Vec<Hash>,
    pub expected_root: Hash,
    pub openings: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetTrackingRecordPoolResponse {
    pub context: Context,
    pub root: StorageRootView,
    /// Distinct leaves in first use order.
    pub records: Vec<RingIndexedTrackingRecordView>,
    /// The narrowest tree level at least `openings` nodes wide.
    pub canopy: Vec<Hash>,
    /// The `records` index opening each requested member, in request order.
    pub subjects: Vec<u32>,
}

/// Authorizations with `revision` past `applied_revision`, ascending by owner after `after`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetPendingEnrollmentsRequest {
    pub registry: SerializablePubkey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<SerializablePubkey>,
    pub limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingPendingEnrollmentView {
    pub owner: SerializablePubkey,
    pub member: Hash,
    pub nullifier_pk: Hash,
    pub ct_hash: Hash,
    pub viewing_u: Hash,
    pub revision: u64,
    pub applied_revision: u64,
    pub list_tag: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetPendingEnrollmentsResponse {
    pub context: Context,
    /// Pending state grants nothing, every check reads a root.
    pub enrollments: Vec<RingPendingEnrollmentView>,
    pub next_after: Option<SerializablePubkey>,
}

/// The authorizations one `ApplyEnrollments` names, applied in order from the current root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetTrackingApplyProofInputsRequest {
    pub registry: SerializablePubkey,
    pub owners: Vec<SerializablePubkey>,
}

/// Paths are under the root the preceding writes reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingTrackingWriteView {
    pub member: Hash,
    pub nullifier_pk: Hash,
    pub ct_hash: Hash,
    pub viewing_u: Hash,
    pub revision: u64,
    pub list_tag: Hash,
    pub exists: bool,
    /// A rotation's old leaf, an insert reads its low record's `next` and nothing else.
    pub old: RingTrackingRecordView,
    /// The member's leaf, for an absent member the append leaf after its low record relinks.
    pub slot: RingRecordPathView,
    /// An absent member's low record, empty for a present member.
    pub low: RingTrackingRecordView,
    pub low_path: RingRecordPathView,
}

/// `chain_start` binds the registry and `revision`, the revision `ApplyEnrollments` names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetTrackingApplyProofInputsResponse {
    pub context: Context,
    pub revision: u64,
    pub old_root: Hash,
    pub new_root: Hash,
    pub old_next_index: u64,
    pub new_next_index: u64,
    pub chain_start: Hash,
    pub chain_end: Hash,
    /// In request order.
    pub writes: Vec<RingTrackingWriteView>,
}
