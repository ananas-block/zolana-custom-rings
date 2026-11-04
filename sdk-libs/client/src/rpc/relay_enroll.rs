use sha2::{Digest, Sha256};
use solana_address::Address;
use wincode::{SchemaRead, SchemaWrite};

use super::RelayProofInputsError;

/// `Enroll` data as the wallet built it, its proof proven and its owner's signature still due.
#[derive(Clone, Debug, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct RelayEnrollInputs {
    pub ring_program_id: Address,
    pub owner: Address,
    pub tracking_registry: Address,
    /// Tag 6 first, the program holds every field to the owner's signature and proof.
    pub instruction_data: Vec<u8>,
}

const ENROLL_REQUEST_DOMAIN: &[u8] = b"zolana/ring-rpc-relay-enroll";

impl RelayEnrollInputs {
    /// The owner's signature over it spends the relay's budget, it names no quote so a retry keeps it.
    pub fn request_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(ENROLL_REQUEST_DOMAIN)
            .chain_update(self.ring_program_id.as_ref())
            .chain_update(self.owner.as_ref())
            .chain_update(self.tracking_registry.as_ref())
            .chain_update(&self.instruction_data)
            .finalize()
            .into()
    }

    pub fn encode(&self) -> Result<Vec<u8>, RelayProofInputsError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelayProofInputsError> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
