use jsonrpsee::types::ErrorObjectOwned;
use photon_indexer::api::error::PhotonApiError;
use thiserror::Error;
use zolana_ring_indexer::rpc::RingRpcError;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum RingApiError {
    #[error("key registry is out of sync ({0})")]
    OutOfSync(String),
    #[error("key registry root changed")]
    RootChanged,
    #[error("member is not registered in the key registry")]
    MemberUnregistered,
    #[error("member is already registered in the key registry")]
    MemberAlreadyRegistered,
    #[error("spend records are out of sync ({0})")]
    SpendRecordOutOfSync(String),
    #[error(transparent)]
    Photon(#[from] PhotonApiError),
}

impl From<sea_orm::DbErr> for RingApiError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Photon(error.into())
    }
}

impl From<RingApiError> for ErrorObjectOwned {
    fn from(error: RingApiError) -> Self {
        let refusal = match error {
            RingApiError::Photon(error) => return error.into(),
            RingApiError::OutOfSync(_) => RingRpcError::KeyRegistryOutOfSync,
            RingApiError::RootChanged => RingRpcError::KeyRegistryRootChanged,
            RingApiError::MemberUnregistered => RingRpcError::MemberUnregistered,
            RingApiError::MemberAlreadyRegistered => RingRpcError::MemberAlreadyRegistered,
            RingApiError::SpendRecordOutOfSync(_) => RingRpcError::SpendRecordOutOfSync,
        };
        ErrorObjectOwned::owned(refusal.code(), error.to_string(), None::<()>)
    }
}
