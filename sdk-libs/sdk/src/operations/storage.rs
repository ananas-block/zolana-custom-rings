use custom_ring_interface::{
    key_catalog::RingCircuit,
    member_registry::APPLY_BATCH,
    storage::{RegistryId, Revision, StorageRegistry},
    storage_instruction::{tag, ApplyEnrollmentsIxData, InitializeIxData, StorageUpdateIxData},
    tracking::{TrackingAuthorization, TrackingEntry},
    ApplyRecordsIxData, GRACE_SLOTS, STORAGE_PROGRAM_ID, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_client::AsyncRpc;
use zolana_ring_client::{records::path_of, resolver::tracking_record, AsyncRingIndexer};
use zolana_ring_indexer::tracking::{
    GetPendingEnrollmentsRequest, GetTrackingApplyProofInputsRequest,
    GetTrackingApplyProofInputsResponse,
};
use zolana_ring_member_registry::{ApplyProofInputs, TrackingWriteProofInput};

use crate::{
    client::{RingClient, RingIndexerBackend},
    prover::{to_instruction_proof, RingRequest},
    request::{ApplyEnrollments as ApplyEnrollmentsBody, ApplyRecords, RecordWrite},
    CustomRing, RingError,
};

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
    /// Nonzero creates a private source paired with the named tracking registry.
    pub tracking_registry: Address,
}

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

/// Proves `inputs` with the apply key of their write count, the batch padded with empty writes.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct StorageApplyProof<'a> {
    pub inputs: &'a ApplyProofInputs,
}

impl InitializeStorage {
    /// The ring's records, keyed by the ring program id under the creator who pays.
    pub fn records(ring: CustomRing, creator: Address) -> Self {
        Self {
            payer: creator,
            creator,
            registry_id: RegistryId(ring.program_id().to_bytes()),
            grace_slots: GRACE_SLOTS,
            ring_id: ring.ring_id().unwrap_or_default(),
            tracking_registry: Address::default(),
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
            tracking_registry: self.tracking_registry,
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
        let statement = self.inputs.statement()?;
        let circuit = RingCircuit::apply_records(statement.count);
        let RingCircuit::ApplyRecords { writes: batch } = circuit else {
            return Err(RingError::UnpinnedProvingKey(circuit));
        };
        let public_input_hash = statement.hash()?;
        let mut writes: Vec<Option<RecordWrite>> = self
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

/// Anyone may send it.
#[must_use]
pub struct ApplyEnrollments<'a> {
    pub tracking_registry: Address,
    /// The registry revision `chain_start` binds.
    pub revision: Revision,
    /// In chain order.
    pub owners: &'a [Address],
    pub inputs: &'a ApplyProofInputs<TrackingWriteProofInput>,
}

impl ApplyEnrollments<'_> {
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<R, I>,
    ) -> Result<Instruction, RingError> {
        let statement = self.inputs.statement()?;
        let circuit = RingCircuit::apply_enrollments(statement.count);
        let RingCircuit::ApplyEnrollments { writes: batch } = circuit else {
            return Err(RingError::UnpinnedProvingKey(circuit));
        };
        let public_input_hash = statement.hash()?;
        let mut writes: Vec<_> = self
            .inputs
            .writes
            .iter()
            .map(|write| Some(write.into()))
            .collect();
        writes.resize_with(usize::from(batch), || None);
        let body = ApplyEnrollmentsBody {
            public_input_hash,
            old_root: statement.old_root,
            new_root: statement.new_root,
            old_next_index: statement.old_next_index,
            new_next_index: statement.new_next_index,
            chain_start: statement.chain_start,
            chain_end: statement.chain_end,
            count: u8::try_from(statement.count).map_err(|_| RingError::RecordProjectionStale)?,
            writes,
        };
        let proof = RingRequest::new(circuit, &body)?
            .prove(client, public_input_hash)
            .await?;
        let data = ApplyEnrollmentsIxData {
            revision: self.revision,
            apply: ApplyRecordsIxData {
                proof: to_instruction_proof(proof)?,
                new_root: statement.new_root,
                new_next_index: statement.new_next_index.to_le_bytes(),
            },
        };
        let mut accounts = vec![AccountMeta::new(self.tracking_registry, false)];
        accounts.extend(self.owners.iter().map(|owner| {
            let (authorization, _) =
                TrackingAuthorization::find_address(&self.tracking_registry, owner);
            AccountMeta::new(authorization, false)
        }));
        Ok(storage_ix(
            accounts,
            [&[tag::APPLY_ENROLLMENTS][..], bytemuck::bytes_of(&data)].concat(),
        ))
    }
}

/// Oldest first, up to one apply key's batch.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollPending {
    pub ring: CustomRing,
}

impl EnrollPending {
    /// `None` when nothing is pending, a pending enrollment grants nothing until its root lands.
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<R, I>,
    ) -> Result<Option<Instruction>, RingError> {
        let policy = self.ring.require_policy(client.zolana()).await?;
        let registry = policy.tracking;
        let pending = client
            .zolana()
            .get_pending_enrollments(GetPendingEnrollmentsRequest {
                registry: registry.into(),
                after: None,
                limit: u64::from(APPLY_BATCH as u32),
            })
            .await?;
        if pending.enrollments.is_empty() {
            return Ok(None);
        }
        let owners: Vec<Address> = pending
            .enrollments
            .iter()
            .map(|enrollment| enrollment.owner.0)
            .collect();
        let response = client
            .zolana()
            .get_tracking_apply_proof_inputs(GetTrackingApplyProofInputsRequest {
                registry: registry.into(),
                owners: owners.iter().copied().map(Into::into).collect(),
            })
            .await?;
        let inputs = tracking_apply_inputs(&response)?;
        let instruction = ApplyEnrollments {
            tracking_registry: registry,
            revision: Revision(response.revision.to_le_bytes()),
            owners: &owners,
            inputs: &inputs,
        }
        .prove(client)
        .await?;
        Ok(Some(instruction))
    }
}

pub fn tracking_apply_inputs(
    response: &GetTrackingApplyProofInputsResponse,
) -> Result<ApplyProofInputs<TrackingWriteProofInput>, RingError> {
    let writes = response
        .writes
        .iter()
        .map(|write| {
            Ok(TrackingWriteProofInput {
                entry: TrackingEntry {
                    member: write.member.0,
                    nullifier_pk: write.nullifier_pk.0,
                    ct_hash: write.ct_hash.0,
                    viewing_u: write.viewing_u.0,
                    revision: write.revision,
                    list_tag: write.list_tag.0,
                },
                exists: write.exists,
                old: tracking_record(&write.old),
                slot: path_of(&write.slot)?,
                low: tracking_record(&write.low),
                low_path: path_of(&write.low_path)?,
            })
        })
        .collect::<Result<_, RingError>>()?;
    Ok(ApplyProofInputs {
        old_root: response.old_root.0,
        new_root: response.new_root.0,
        old_next_index: response.old_next_index,
        new_next_index: response.new_next_index,
        chain_start: response.chain_start.0,
        chain_end: response.chain_end.0,
        writes,
    })
}

pub(crate) fn storage_ix(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: STORAGE_PROGRAM_ID,
        accounts,
        data,
    }
}
