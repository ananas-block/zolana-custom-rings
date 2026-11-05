//! Storage registry builders and the apply proof of a public record batch.
//!
//! A private write needs a credential write proof under tree 0 address inclusion, which Photon does
//! not serve yet. Only public batches prove here, the statement then carries empty credential roots.
//!
//! Read after `program-libs/interface/src/instructions/storage.rs` and
//! `program-libs/member-registry/src/record.rs`. Read before `programs/storage/src/instructions/update.rs`.

use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage::{RegistryId, StorageRegistry},
    storage_instruction::{tag, AssetWrite, InitializeIxData, StorageUpdateIxData},
    ApplyRecordsIxData, GRACE_SLOTS, STORAGE_PROGRAM_ID, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_client::AsyncRpc;
use zolana_ring_member_registry::{ApplyProofInputs, RecordCredentials, RecordStatementContext};

use crate::{
    client::{RingClient, RingIndexerBackend},
    prover::{to_instruction_proof, RingRequest},
    request::{ApplyRecords, RecordWriteProofInputRequest, StateRootRequest},
    CustomRing, RingError,
};

#[cfg(test)]
#[path = "../tests/operations/storage.rs"]
mod tests;

/// The creator signs and becomes the authority, the payer funds the account.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitializeStorage {
    pub payer: Address,
    pub creator: Address,
    pub registry_id: RegistryId,
    pub grace_slots: u64,
    /// `ring_id_field` of the ring it serves, immutable, zero serves as a curator only.
    pub ring_id: [u8; 32],
    /// Nonzero lets salted writes prove credentials of that ring, immutable.
    pub private_ring_id: [u8; 32],
}

/// A public batch, its data carries the empty credential read.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateStorage<'a> {
    pub authority: Address,
    pub registry: Address,
    pub data: StorageUpdateIxData<'a>,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateStorageAuthority {
    pub authority: Address,
    pub new_authority: Address,
    pub registry: Address,
}

/// Proves a public batch with the apply key of its write count, padded with empty writes.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct StorageApplyProof<'a> {
    pub inputs: &'a ApplyProofInputs,
    /// The registry as read, its root and cursor must equal the inputs' old state.
    pub registry: &'a StorageRegistry,
    /// The mint preimages of private asset writes.
    pub asset_writes: &'a [AssetWrite],
}

impl InitializeStorage {
    /// The ring's records, keyed by the ring program id under the creator who pays.
    ///
    /// The private ring id is immutable and a later policy can serve a private list from these
    /// records, so every ring binds its own credentials at creation. A source without one refuses
    /// every frame reading a private list.
    pub fn records(ring: CustomRing, creator: Address) -> Self {
        let ring_id = ring.ring_id().unwrap_or_default();
        Self {
            payer: creator,
            creator,
            registry_id: RegistryId(ring.program_id().to_bytes()),
            grace_slots: GRACE_SLOTS,
            ring_id,
            private_ring_id: ring_id,
        }
    }

    pub fn registry(&self) -> Address {
        StorageRegistry::find_address(&self.creator, &self.registry_id).0
    }

    pub fn instruction(self) -> Instruction {
        let data = InitializeIxData {
            registry_id: self.registry_id,
            grace_slots: self.grace_slots.to_le_bytes(),
            ring_id: self.ring_id,
            private_ring_id: self.private_ring_id,
        };
        storage_ix(
            vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.creator, true),
                AccountMeta::new(self.registry(), false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            [&[tag::INITIALIZE], bytemuck::bytes_of(&data)].concat(),
        )
    }
}

impl UpdateStorage<'_> {
    /// `encode` refuses a private write without its credential read.
    pub fn instruction(self) -> Result<Instruction, RingError> {
        Ok(storage_ix(
            vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new(self.registry, false),
            ],
            [vec![tag::UPDATE], self.data.encode()?].concat(),
        ))
    }
}

impl UpdateStorageAuthority {
    pub fn instruction(self) -> Instruction {
        storage_ix(
            vec![
                AccountMeta::new_readonly(self.authority, true),
                AccountMeta::new_readonly(self.new_authority, true),
                AccountMeta::new(self.registry, false),
            ],
            vec![tag::UPDATE_AUTHORITY],
        )
    }
}

impl StorageApplyProof<'_> {
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<R, I>,
    ) -> Result<ApplyRecordsIxData, RingError> {
        let statement = self.inputs.statement(RecordStatementContext {
            registry: self.registry,
            asset_writes: self.asset_writes,
            credentials: RecordCredentials::Public,
        })?;
        let circuit = RingCircuit::apply_records(statement.count);
        let RingCircuit::ApplyRecords { writes: batch } = circuit else {
            return Err(RingError::UnpinnedProvingKey(circuit));
        };
        let public_input_hash = statement.hash()?;
        let mut writes: Vec<Option<RecordWriteProofInputRequest>> = self
            .inputs
            .writes
            .iter()
            .map(|write| Some(write.into()))
            .collect();
        writes.resize(usize::from(batch), None);
        let body = ApplyRecords {
            public_input_hash,
            old_root: statement.old_root,
            new_root: statement.new_root,
            old_next_index: statement.old_next_index,
            new_next_index: statement.new_next_index,
            chain_start: statement.chain_start,
            chain_end: statement.chain_end,
            count: u8::try_from(statement.count).map_err(|_| RingError::RecordProjectionStale)?,
            writes,
            credential_writes: u64::from(statement.credential_writes),
            private_ring_id: statement.private_ring_id,
            credential_owner: *statement.credentials.owner_hash(),
            address_root: *statement.credentials.address_root(),
            state_roots: statement
                .credentials
                .state_roots()
                .iter()
                .map(StateRootRequest::from)
                .collect(),
            credentials: vec![(); usize::from(batch)],
        };
        let proof = RingRequest::new(circuit, &body)?
            .prove(client, public_input_hash)
            .await?;
        Ok(ApplyRecordsIxData {
            proof: to_instruction_proof(proof)?,
            new_root: statement.new_root,
            new_next_index: statement.new_next_index.to_le_bytes(),
        })
    }
}

pub(crate) fn storage_ix(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: STORAGE_PROGRAM_ID,
        accounts,
        data,
    }
}
