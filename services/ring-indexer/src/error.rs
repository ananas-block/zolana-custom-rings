use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
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
    #[error("invalid request ({0})")]
    InvalidRequest(String),
    #[error("internal error ({0})")]
    Internal(String),
}

impl From<sea_orm::DbErr> for RingApiError {
    fn from(error: sea_orm::DbErr) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<RingApiError> for ErrorObjectOwned {
    fn from(error: RingApiError) -> Self {
        let refusal = match &error {
            RingApiError::OutOfSync(_) => RingRpcError::KeyRegistryOutOfSync,
            RingApiError::RootChanged => RingRpcError::KeyRegistryRootChanged,
            RingApiError::MemberUnregistered => RingRpcError::MemberUnregistered,
            RingApiError::MemberAlreadyRegistered => RingRpcError::MemberAlreadyRegistered,
            RingApiError::SpendRecordOutOfSync(_) => RingRpcError::SpendRecordOutOfSync,
            RingApiError::InvalidRequest(_) => {
                return Self::owned(
                    ErrorCode::InvalidRequest.code(),
                    error.to_string(),
                    None::<()>,
                )
            }
            RingApiError::Internal(reason) => {
                log::error!("ring lookup failed ({reason})");
                return Self::owned(
                    ErrorCode::InternalError.code(),
                    "internal server error",
                    None::<()>,
                );
            }
        };
        Self::owned(refusal.code(), error.to_string(), None::<()>)
    }
}
