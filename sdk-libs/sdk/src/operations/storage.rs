//! Storage registry builders and the apply proof of a record batch.
//!
//! A public batch proves with empty credential roots. A batch with salted owner writes proves, for
//! each one, the owner's credential in a state tree, its address applied in tree 0 and the written
//! key `ListKey(member, salt)` under the credential's list tag. All addresses share one tree 0 root.
//! The update names that root's sequence, Storage compares it to tree 0 and raises the absence floor
//! in the same instruction. An owner whose address is still queued is refused before any proof.
//!
//! Read after `program-libs/interface/src/instructions/storage.rs`,
//! `program-libs/member-registry/src/record.rs` and `sdk-libs/client/src/operations/address_inclusion.rs`.
//! Read before `programs/storage/src/instructions/update.rs`.

use std::collections::BTreeMap;

use custom_ring_interface::{
    credential::owner_member,
    domain,
    key_catalog::RingCircuit,
    storage::{RegistryId, StorageError, StorageRegistry},
    storage_instruction::{
        tag, AssetWrite, InitializeIxData, PrivateWriteCheckpoint, RecordWriteClassification,
        StorageUpdateIxData,
    },
    ApplyRecordsIxData, ApplyRecordsStatement, CredentialRead, CredentialRootSelection,
    CredentialStateRoot, CustomRingError, GRACE_SLOTS, STORAGE_PROGRAM_ID, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_client::AsyncRpc;
use zolana_ring_client::{
    AddressActivation, AddressInclusion, AddressInclusions, CredentialError, CredentialOpening,
    CredentialReads,
};
use zolana_ring_member_registry::{ApplyProofInputs, RecordCredentials, RecordStatementContext};
use zolana_ring_policy::Member;

use crate::{
    client::{RingClient, RingIndexerBackend},
    credentials::credential_leaf,
    prover::{to_instruction_proof, RingRequest},
    request::{
        ApplyRecords, CredentialWriteRequest, RecordWriteProofInputRequest, StateRootRequest,
    },
    CredentialTrees, CustomRing, RingError,
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

/// `credential_trees` names tree 0 and each state tree a private write reads, `None` for a public batch.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateStorage<'a> {
    pub authority: Address,
    pub registry: Address,
    pub data: StorageUpdateIxData<'a>,
    pub credential_trees: Option<CredentialTrees>,
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

/// The owner and list salt behind the salted key at `write_index`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SaltedOwnerWrite {
    pub write_index: u8,
    pub owner: Address,
    pub list_salt: [u8; 32],
}

/// Proves a batch with salted owner writes, one per private write without a mint preimage.
#[must_use]
#[derive(Clone, Copy)]
pub struct PrivateStorageWrite<'a> {
    pub ring: CustomRing,
    pub inputs: &'a ApplyProofInputs,
    /// The registry as read, its root and cursor must equal the inputs' old state.
    pub registry: &'a StorageRegistry,
    /// The mint preimages of private asset writes.
    pub asset_writes: &'a [AssetWrite],
    pub owners: &'a [SaltedOwnerWrite],
}

/// The proof and the credential section the update carries beside its writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenPrivateWrite {
    pub apply: ApplyRecordsIxData,
    pub credential_read: CredentialRead,
    pub private_write: PrivateWriteCheckpoint,
    pub credential_trees: CredentialTrees,
}

/// Everything ahead of the prover, a refusal here sends no request.
pub(crate) struct PrivateWritePlan {
    pub circuit: RingCircuit,
    pub statement: ApplyRecordsStatement,
    pub body: ApplyRecords,
    pub credential_read: CredentialRead,
    pub private_write: PrivateWriteCheckpoint,
    pub credential_trees: CredentialTrees,
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
        let data = [vec![tag::UPDATE], self.data.encode()?].concat();
        // Storage reads tree 0 and one tree per state root index, a public batch reads none.
        let trees: Vec<AccountMeta> = self
            .credential_trees
            .iter()
            .flat_map(CredentialTrees::metas)
            .collect();
        let expected = match self.data.private_write {
            Some(_) => 1 + self.data.credential_read.state_root_indexes().len(),
            None => 0,
        };
        if trees.len() != expected {
            return Err(StorageError::InvalidCredentialRead.into());
        }
        let accounts = [
            AccountMeta::new_readonly(self.authority, true),
            AccountMeta::new(self.registry, false),
        ]
        .into_iter()
        .chain(trees)
        .collect();
        Ok(storage_ix(accounts, data))
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
        let key = ApplyKey::of(self.inputs)?;
        let body = key.body(self.inputs, &statement, Vec::new())?;
        prove_apply(client, key.circuit, &statement, &body).await
    }
}

impl PrivateStorageWrite<'_> {
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<R, I>,
    ) -> Result<ProvenPrivateWrite, RingError> {
        let plan = self.plan(client.zolana()).await?;
        Ok(ProvenPrivateWrite {
            apply: prove_apply(client, plan.circuit, &plan.statement, &plan.body).await?,
            credential_read: plan.credential_read,
            private_write: plan.private_write,
            credential_trees: plan.credential_trees,
        })
    }

    pub(crate) async fn plan<R: AsyncRpc>(self, rpc: &R) -> Result<PrivateWritePlan, RingError> {
        // 1. The salted owners must name exactly the writes Storage classifies as credential writes,
        //    and each written key must be its owner's list key, so a wrong salt fails before any read.
        let key = ApplyKey::of(self.inputs)?;
        let width = key.width;
        let credential_writes = RecordWriteClassification {
            entries: self
                .inputs
                .writes
                .iter()
                .map(|write| Ok::<_, CustomRingError>(write.entry)),
            asset_writes: self.asset_writes,
        }
        .credential_writes()?;
        let owners = self
            .owners
            .iter()
            .map(BoundOwner::bind(self.inputs))
            .collect::<Result<Vec<_>, _>>()?;
        let named = owners.iter().try_fold(0u16, |mask, owner| {
            1u16.checked_shl(u32::from(owner.write.write_index))
                .filter(|bit| mask & bit == 0)
                .map(|bit| mask | bit)
                .ok_or(CredentialError::CredentialWritesMismatch)
        })?;
        if named != credential_writes || named == 0 {
            return Err(CredentialError::CredentialWritesMismatch.into());
        }
        // 2. One snapshot proves every credential in its state tree, an absent owner cannot write.
        let mut members: Vec<[u8; 32]> = owners.iter().map(|owner| owner.member).collect();
        members.sort_unstable();
        members.dedup();
        let snapshot = CredentialReads {
            ring: self.ring.program_id(),
            members: &members,
        }
        .read(rpc, rpc)
        .await?;
        let mut present = BTreeMap::new();
        for (member, opening) in members.iter().zip(&snapshot.openings) {
            let CredentialOpening::Present(credential) = opening else {
                let owner = owners.iter().find(|owner| owner.member == *member);
                return Err(CredentialError::WriteOwnerNotEnrolled {
                    write_index: owner.map_or(0, |owner| owner.write.write_index),
                }
                .into());
            };
            present.insert(*member, &**credential);
        }
        for owner in &owners {
            if domain::list_tag(&owner.write.list_salt)?
                != present[&owner.member].credential.list_tag
            {
                return Err(CredentialError::ListTagMismatch.into());
            }
        }
        // 3. Every address applied under one tree 0 root, a queued one refuses before any proof.
        //    The root's history index fixes the sequence Storage compares and records as the floor.
        let addresses: Vec<[u8; 32]> = present
            .values()
            .map(|credential| credential.address)
            .collect();
        let activation = AddressInclusions {
            addresses: &addresses,
        }
        .read(rpc, rpc)
        .await?;
        let (root, checkpoint, inclusions) = match activation {
            AddressActivation::Active {
                root,
                checkpoint,
                inclusions,
            } => (root, checkpoint, inclusions),
            AddressActivation::Queued { address } => {
                let write_index = owners
                    .iter()
                    .filter(|owner| present[&owner.member].address == address)
                    .map(|owner| owner.write.write_index)
                    .min()
                    .ok_or(CredentialError::MalformedProof)?;
                return Err(CredentialError::AddressQueued {
                    address,
                    write_index,
                }
                .into());
            }
        };
        // 4. The statement takes the authenticated checkpoint and the snapshot's state roots,
        //    the frame names the same roots by index.
        let state_roots: Vec<CredentialStateRoot> = snapshot
            .state_roots
            .iter()
            .map(|tree| CredentialStateRoot {
                tree_id: tree.tree_id,
                root: tree.root.root,
            })
            .collect();
        let state_indexes: Vec<u16> = snapshot
            .state_roots
            .iter()
            .map(|tree| tree.root.root_index)
            .collect();
        let credential_read = CredentialRead::new(root.root_index, &state_indexes)?;
        let credential_trees =
            CredentialTrees::new(snapshot.state_roots.iter().map(|tree| tree.tree_id), width)?;
        let statement = self.inputs.statement(RecordStatementContext {
            registry: self.registry,
            asset_writes: self.asset_writes,
            credentials: RecordCredentials::Private(CredentialRootSelection {
                ring_program: &self.ring.program_id(),
                address_checkpoint: checkpoint,
                state_roots: &state_roots,
                capacity: width,
            }),
        })?;
        // 5. Each salted write opens its owner's leaf at its tree's table slot and its address leaf.
        let inclusions: BTreeMap<&[u8; 32], &AddressInclusion> =
            present.keys().zip(&inclusions).collect();
        let mut credentials = vec![None; width];
        for owner in &owners {
            let credential = present[&owner.member];
            let inclusion = inclusions[&owner.member];
            let tree_slot = state_roots
                .iter()
                .position(|root| root.tree_id == credential.tree_id)
                .ok_or(RingError::CredentialNotRead)?;
            credentials[usize::from(owner.write.write_index)] = Some(CredentialWriteRequest {
                member: owner.member,
                list_salt: owner.write.list_salt,
                leaf: credential_leaf(credential, tree_slot)?,
                address_next: inclusion.next,
                address_index: inclusion.index,
                address_path: inclusion.path.to_vec(),
            });
        }
        let body = key.body(self.inputs, &statement, credentials)?;
        Ok(PrivateWritePlan {
            circuit: key.circuit,
            statement,
            body,
            credential_read,
            private_write: PrivateWriteCheckpoint {
                ring_program: self.ring.program_id(),
                sequence: checkpoint.sequence(),
            },
            credential_trees,
        })
    }
}

/// A salted owner write with its owner's member, its written key checked.
struct BoundOwner {
    write: SaltedOwnerWrite,
    member: [u8; 32],
}

impl BoundOwner {
    fn bind(
        inputs: &ApplyProofInputs,
    ) -> impl Fn(&SaltedOwnerWrite) -> Result<Self, RingError> + '_ {
        move |write| {
            let member = owner_member(&write.owner)?;
            let key = Member::salted(&Member::from_bytes(member)?, &write.list_salt)?;
            match inputs.writes.get(usize::from(write.write_index)) {
                Some(written) if written.entry.member == *key.as_bytes() => Ok(Self {
                    write: *write,
                    member,
                }),
                _ => Err(CredentialError::ListKeyMismatch {
                    write_index: write.write_index,
                }
                .into()),
            }
        }
    }
}

/// The apply key of a batch, writes past the batch pad to `width`.
struct ApplyKey {
    circuit: RingCircuit,
    width: usize,
}

impl ApplyKey {
    fn of(inputs: &ApplyProofInputs) -> Result<Self, RingError> {
        let circuit = RingCircuit::apply_records(inputs.writes.len() as u64);
        match circuit {
            RingCircuit::ApplyRecords { writes } => Ok(Self {
                circuit,
                width: usize::from(writes),
            }),
            _ => Err(RingError::UnpinnedProvingKey(circuit)),
        }
    }

    /// Writes and credentials past the batch assign zeros.
    fn body(
        &self,
        inputs: &ApplyProofInputs,
        statement: &ApplyRecordsStatement,
        mut credentials: Vec<Option<CredentialWriteRequest>>,
    ) -> Result<ApplyRecords, RingError> {
        let mut writes: Vec<Option<RecordWriteProofInputRequest>> = inputs
            .writes
            .iter()
            .map(|write| Some(write.into()))
            .collect();
        writes.resize(self.width, None);
        credentials.resize(self.width, None);
        Ok(ApplyRecords {
            public_input_hash: statement.hash()?,
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
            credentials,
        })
    }
}

async fn prove_apply<R: AsyncRpc, I: RingIndexerBackend>(
    client: &RingClient<R, I>,
    circuit: RingCircuit,
    statement: &ApplyRecordsStatement,
    body: &ApplyRecords,
) -> Result<ApplyRecordsIxData, RingError> {
    let proof = RingRequest::new(circuit, body)?
        .prove(client, body.public_input_hash)
        .await?;
    Ok(ApplyRecordsIxData {
        proof: to_instruction_proof(proof)?,
        new_root: statement.new_root,
        new_next_index: statement.new_next_index.to_le_bytes(),
    })
}

pub(crate) fn storage_ix(accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id: STORAGE_PROGRAM_ID,
        accounts,
        data,
    }
}
