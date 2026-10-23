use jsonrpsee::types::ErrorObjectOwned;
use photon_indexer::api::error::PhotonApiError;
use thiserror::Error;
use zolana_ring_indexer::rpc::RingRpcError;

#[derive(Error, Clone, Debug, PartialEq, Eq)]
pub enum RingRefusal {
    #[error("member registry is out of sync ({0})")]
    OutOfSync(String),
    #[error("member registry root changed")]
    RootChanged,
    #[error("member has no record in the member registry")]
    MemberUnregistered,
    #[error("member registry page has an index gap or inconsistent leaf")]
    PageGap,
    #[error("record queue moved under the request")]
    QueueChanged,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum RingApiError {
    #[error(transparent)]
    Refused(#[from] RingRefusal),
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
        let refused = match error {
            RingApiError::Photon(error) => return error.into(),
            RingApiError::Refused(refused) => refused,
        };
        let code = match refused {
            RingRefusal::OutOfSync(_) => RingRpcError::RegistryOutOfSync,
            RingRefusal::RootChanged => RingRpcError::RegistryRootChanged,
            RingRefusal::MemberUnregistered => RingRpcError::MemberUnregistered,
            RingRefusal::PageGap => RingRpcError::RegistryPageGap,
            RingRefusal::QueueChanged => RingRpcError::RecordQueueChanged,
        };
        ErrorObjectOwned::owned(code.code(), refused.to_string(), None::<()>)
    }
}
