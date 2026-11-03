use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage::{AddressAuthorization, RegistryId, StorageRegistry},
    storage_instruction::{
        tag, EnrollAddressIxData, InitializeIxData, StorageUpdateIxData, StorageWriteData,
        UpdateMode,
    },
    ApplyRecordsIxData, GRACE_SLOTS, STORAGE_PROGRAM_ID, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_client::AsyncRpc;
use zolana_ring_client::{records::MemberOpeningRead, AsyncRingIndexer};
use zolana_ring_member_registry::{ApplyProofInputs, RecordOpening};
use zolana_ring_policy::Member;

use crate::{
    client::{RingClient, RingIndexerBackend},
    prover::{to_instruction_proof, RingRequest},
    records::MemberRead,
    request::{ApplyRecords, RecordWrite},
    submission::BoundRoot,
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
}

/// The owner signs, a wallet with its key and a PDA through its program's `invoke_signed`.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollAddress {
    pub payer: Address,
    pub owner: Address,
    pub registry: Address,
    /// Fixed after the first enrollment.
    pub nullifier_pk: [u8; 32],
    pub viewing_u: [u8; 32],
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateStorage<'a> {
    pub authority: Address,
    pub registry: Address,
    pub mode: UpdateMode,
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

impl EnrollAddress {
    /// The owner's authorization account, every apply of its address reads it.
    pub fn authorization(&self) -> Address {
        AddressAuthorization::find_address(&self.registry, &self.owner).0
    }

    /// The instruction cannot read a leaf, the first key is permanent and ApplyRecords enforces it.
    pub async fn checked_instruction(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<Instruction, RingError> {
        let read = MemberRead {
            root: BoundRoot::newest_of(self.registry, rpc).await?,
            member: *Member::owner_tag(self.owner.as_array())?.as_bytes(),
        }
        .read(rpc)
        .await?;
        self.check_record(&read)?;
        Ok(self.instruction())
    }

    /// A record that withholds its escrow preimage refuses, its key is not known to agree.
    fn check_record(&self, read: &MemberOpeningRead) -> Result<(), RingError> {
        let RecordOpening::Present { record, .. } = &read.opening else {
            return Ok(());
        };
        let escrow_agrees =
            record.escrow_key == [0; 32] || read.escrowed(&self.nullifier_pk)?.is_some();
        let address_agrees = read
            .address
            .is_none_or(|address| address.nullifier_pk == self.nullifier_pk);
        match escrow_agrees && address_agrees {
            true => Ok(()),
            false => Err(RingError::EnrollmentKeyMismatch),
        }
    }

    pub fn instruction(self) -> Instruction {
        let data = EnrollAddressIxData {
            nullifier_pk: self.nullifier_pk,
            viewing_u: self.viewing_u,
        };
        storage_ix(
            vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.owner, true),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.authorization(), false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            [&[tag::ENROLL_ADDRESS], bytemuck::bytes_of(&data)].concat(),
        )
    }
}

impl UpdateStorage<'_> {
    /// One writable authorization per address write follows the registry, in write order.
    pub fn instruction(self) -> Result<Instruction, RingError> {
        let mut accounts = vec![
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(self.registry, false),
        ];
        accounts.extend(self.data.writes.iter().filter_map(|write| match write {
            StorageWriteData::Address(address) => Some(AccountMeta::new(
                AddressAuthorization::find_address(&self.registry, &address.owner).0,
                false,
            )),
            StorageWriteData::Record(_) | StorageWriteData::Escrow(_) => None,
        }));
        Ok(storage_ix(
            accounts,
            [vec![self.mode.tag()], self.data.encode()?].concat(),
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

fn storage_ix(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: STORAGE_PROGRAM_ID,
        accounts,
        data,
    }
}
