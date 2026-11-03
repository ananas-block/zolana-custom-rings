use async_trait::async_trait;
use jsonrpsee::types::ErrorObjectOwned;
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use thiserror::Error;
use zolana_ring_policy::Member;

use crate::error::RingRpcError;

pub struct CoSignRequest {
    pub ring: Address,
    pub message: VersionedMessage,
    pub flows: CoSignFlows,
}

/// A caller names no transfer debit, the co-signer reads each from the frame it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoSignFlows {
    Frame,
    /// A deposit's public leg, or nothing on a merge.
    Published(Vec<OwnerFlow>),
}

/// One reservation row, each owner and asset once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerFlow {
    pub owner: Member,
    pub flow: AssetFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetFlow {
    pub asset: Address,
    /// `zolana_ring_policy::owner_debits`, what the owner's ring balance lost.
    pub debit: u64,
    pub deposited: u64,
    pub withdrawn: u64,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoSignDecision {
    /// Over `CoSignRequest::message`.
    Signed(Signature),
    Refused(CoSignRefusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoSignRefusal {
    Disabled,
    OverLimit,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum CoSignError {
    #[error("co-signing is disabled")]
    Disabled = -32160,
    #[error("the transaction exceeds a co-signer limit")]
    OverLimit = -32161,
    #[error("the co-sign flows name an owner and asset twice")]
    RepeatedAsset = -32162,
    #[error("the asset limits or an input opening are unreadable")]
    LimitsUnavailable = -32163,
    #[error("the message holds anything but one ring transfer the co-signer can read")]
    MessageScope = -32164,
    #[error("the co-sign request names an asset with no record")]
    UnrecordedAsset = -32296,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoSignSettlement {
    Confirmed(Signature),
    Failed(Signature),
}

impl CoSignError {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl From<CoSignRefusal> for CoSignError {
    fn from(refusal: CoSignRefusal) -> Self {
        match refusal {
            CoSignRefusal::Disabled => Self::Disabled,
            CoSignRefusal::OverLimit => Self::OverLimit,
        }
    }
}

impl From<CoSignError> for ErrorObjectOwned {
    fn from(error: CoSignError) -> Self {
        Self::owned(error.code(), error.to_string(), None::<()>)
    }
}

#[async_trait]
pub trait CoSignPolicy: Send + Sync {
    /// `None` when the policy never signs.
    fn signer(&self) -> Option<Address>;

    async fn decide(&self, request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError>;

    /// Keeps or frees the usage `decide` reserved for the transaction.
    async fn settle(&self, settlement: CoSignSettlement) -> Result<(), RingRpcError>;
}

impl dyn CoSignPolicy + '_ {
    /// `None` unless the policy signs as the co-signer the proof names.
    pub(crate) fn signer_named(&self, named: Address) -> Option<Address> {
        self.signer().filter(|signer| *signer == named)
    }
}

pub struct RefusingCoSigner;

#[async_trait]
impl CoSignPolicy for RefusingCoSigner {
    fn signer(&self) -> Option<Address> {
        None
    }

    async fn decide(&self, _request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError> {
        Ok(CoSignDecision::Refused(CoSignRefusal::Disabled))
    }

    async fn settle(&self, _settlement: CoSignSettlement) -> Result<(), RingRpcError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosign_error_codes_are_stable() {
        use CoSignError::*;
        for (error, code) in [
            (Disabled, -32160),
            (OverLimit, -32161),
            (RepeatedAsset, -32162),
            (LimitsUnavailable, -32163),
            (MessageScope, -32164),
            (UnrecordedAsset, -32296),
        ] {
            assert_eq!(ErrorObjectOwned::from(error).code(), code);
        }
    }
}
