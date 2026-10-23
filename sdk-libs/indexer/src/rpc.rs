use serde::{Deserialize, Serialize};
use thiserror::Error;
use zolana_indexer_api::{
    Base64String, Context, Hash, RpcMethod, SerializablePubkey, ShieldedTransaction,
};

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum RingRpcError {
    #[error("the ring key-registry indexer is catching up or recovering")]
    KeyRegistryOutOfSync = -32070,
    #[error("the ring key-registry root has changed")]
    KeyRegistryRootChanged = -32071,
    #[error("the member has not registered a nullifier key")]
    MemberUnregistered = -32072,
    #[error("the member already registered a nullifier key")]
    MemberAlreadyRegistered = -32073,
    #[error("the ring spend-record indexer is catching up or recovering")]
    SpendRecordOutOfSync = -32074,
}

impl RingRpcError {
    pub const ALL: [Self; 5] = [
        Self::KeyRegistryOutOfSync,
        Self::KeyRegistryRootChanged,
        Self::MemberUnregistered,
        Self::MemberAlreadyRegistered,
        Self::SpendRecordOutOfSync,
    ];

    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn from_code(code: i64) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|error| i64::from(error.code()) == code)
    }
}

pub mod method {
    use super::*;

    pub struct GetRingKeyRegistryEntry;
    pub struct GetRingKeyRegistryRegisterProof;
    pub struct GetRingSpendRecord;

    impl RpcMethod for GetRingKeyRegistryEntry {
        const NAME: &'static str = "getRingKeyRegistryEntry";
        type Request = RingMemberProofRequest;
        type Response = GetRingKeyRegistryEntryResponse;
    }

    impl RpcMethod for GetRingKeyRegistryRegisterProof {
        const NAME: &'static str = "getRingKeyRegistryRegisterProof";
        type Request = RingMemberProofRequest;
        type Response = GetRingKeyRegistryRegisterProofResponse;
    }

    impl RpcMethod for GetRingSpendRecord {
        const NAME: &'static str = "getRingSpendRecord";
        type Request = RingSpendRecordRequest;
        type Response = GetRingSpendRecordResponse;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingMemberProofRequest {
    pub ring_program_id: SerializablePubkey,
    pub member: Hash,
    pub expected_root: Hash,
    pub expected_next_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingKeyRegistryEntryResponse {
    pub context: Context,
    pub root: Hash,
    pub next_index: u64,
    pub member: Hash,
    pub next: Hash,
    pub index: u64,
    pub eph_pk: Base64String,
    pub ciphertext: Base64String,
    pub proof: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingKeyRegistryRegisterProofResponse {
    pub context: Context,
    pub root: Hash,
    pub next_index: u64,
    pub member: Hash,
    pub low_member: Hash,
    pub low_next: Hash,
    pub low_key_hash: Hash,
    pub low_index: u64,
    pub low_proof: Vec<Hash>,
    /// Computed after the predecessor update.
    pub new_proof: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingSpendRecordRequest {
    pub ring_program_id: SerializablePubkey,
    pub member: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RingSpendRecord {
    pub transaction: ShieldedTransaction,
    pub output_index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetRingSpendRecordResponse {
    pub context: Context,
    /// `None` until the member registers.
    pub record: Option<RingSpendRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            RingRpcError::ALL.map(RingRpcError::code),
            [-32070, -32071, -32072, -32073, -32074]
        );
        for error in RingRpcError::ALL {
            assert_eq!(
                RingRpcError::from_code(i64::from(error.code())),
                Some(error)
            );
        }
        assert_eq!(RingRpcError::from_code(-32603), None);
    }
}
