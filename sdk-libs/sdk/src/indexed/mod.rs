mod deposit;
mod policy;

pub use deposit::IndexedDepositRequest;
pub use policy::{IndexedPolicyData, IndexedPolicyLookup, IndexedPolicyRequest, IndexedRegistry};

use zolana_client::ClientError;

pub(crate) const REGISTRY_MEMBER_MISSING: &str = "registry_member_missing";

fn invalid() -> ClientError {
    ClientError::InvalidIndexedRequest
}
