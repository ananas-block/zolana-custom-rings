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

impl RelayEnrollInputs {
    pub fn encode(&self) -> Result<Vec<u8>, RelayProofInputsError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelayProofInputsError> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
