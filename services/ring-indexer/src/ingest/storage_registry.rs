use custom_ring_interface::{
    storage::{chain_start, PrivateRootUpdate, RootUpdate, StorageError, StorageRegistry},
    storage_instruction::{tag, InitializeIxData, PrivateUpdateIxData, StorageUpdateIxData},
    QUAD_HEIGHT,
};
use sea_orm::ConnectionTrait;
use solana_address::Address;
use spr_indexer_api::Hash;

use crate::{
    block::Instruction,
    indexer::{fault, from_storage, ApplyError},
    member_registry::{plant_tree, LoadedRegistry, TreeRead},
    storage::{StorageRoot, StorageState, StorageStore},
};

pub(crate) enum StorageCall<'a> {
    Initialize(StorageInit<'a>),
    Update(StorageUpdate<'a>),
    UpdatePrivate(PrivateUpdate<'a>),
    UpdateAuthority {
        authority: Address,
        new_authority: Address,
    },
}

pub(crate) struct StorageInit<'a> {
    pub creator: Address,
    pub data: &'a InitializeIxData,
}

pub(crate) struct StorageUpdate<'a> {
    pub authority: Address,
    pub data: StorageUpdateIxData<'a>,
}

pub(crate) struct PrivateUpdate<'a> {
    pub authority: Address,
    pub tracking_registry: Address,
    pub data: PrivateUpdateIxData<'a>,
}

/// `call` fails on data the program refuses.
pub(crate) struct StorageInstruction<'a> {
    pub registry: Address,
    pub call: Result<StorageCall<'a>, StorageError>,
}

/// Account order of the `custom_ring_sdk` storage builders.
pub(crate) fn decode(instruction: &Instruction) -> Option<StorageInstruction<'_>> {
    let (&tag, data) = instruction.data.split_first()?;
    let account = |index: usize| {
        instruction
            .accounts
            .get(index)
            .copied()
            .ok_or(StorageError::MissingAccounts)
    };
    let registry = |index: usize| account(index).ok();
    let instruction = match tag {
        tag::INITIALIZE => StorageInstruction {
            registry: registry(2)?,
            call: account(1).and_then(|creator| {
                let data = bytemuck::try_from_bytes(data)
                    .map_err(|_| StorageError::InvalidInstructionData)?;
                Ok(StorageCall::Initialize(StorageInit { creator, data }))
            }),
        },
        tag::UPDATE => StorageInstruction {
            registry: registry(1)?,
            call: account(0).and_then(|authority| {
                Ok(StorageCall::Update(StorageUpdate {
                    authority,
                    data: StorageUpdateIxData::parse(data)?,
                }))
            }),
        },
        tag::UPDATE_PRIVATE => StorageInstruction {
            registry: registry(1)?,
            call: account(0).and_then(|authority| {
                Ok(StorageCall::UpdatePrivate(PrivateUpdate {
                    authority,
                    tracking_registry: account(2)?,
                    data: PrivateUpdateIxData::parse(data)?,
                }))
            }),
        },
        tag::UPDATE_AUTHORITY => StorageInstruction {
            registry: registry(2)?,
            call: account(0).and_then(|authority| {
                Ok(StorageCall::UpdateAuthority {
                    authority,
                    new_authority: account(1)?,
                })
            }),
        },
        _ => return None,
    };
    Some(instruction)
}

impl StorageInit<'_> {
    /// `None` off the canonical registry address, the program refuses it.
    pub fn state(&self, registry: Address) -> Option<StorageState> {
        let (canonical, _) = StorageRegistry::find_address(&self.creator, &self.data.registry_id);
        (canonical == registry).then(|| StorageState {
            registry: registry.to_bytes(),
            account: Box::new(StorageRegistry::new(self.creator, self.data)),
            fault: None,
        })
    }
}

pub(crate) async fn create<C: ConnectionTrait>(
    store: &StorageStore<'_, C>,
    state: &StorageState,
) -> anyhow::Result<()> {
    // A private source opens through its published writes, it has no policy leaves.
    if !state.account.is_private() {
        plant_tree::<_, _, QUAD_HEIGHT>(store.tree()).await?;
    }
    store
        .save_root(&StorageRoot::current(&*state.account))
        .await?;
    store.save_state(state).await
}

pub(crate) struct StorageProjection<'p, 'c, C> {
    pub store: &'p StorageStore<'c, C>,
    pub state: &'p mut StorageState,
    pub slot: u64,
}

impl<C: ConnectionTrait> StorageProjection<'_, '_, C> {
    /// A refusal of the program's own checks means the projection drifted.
    pub async fn project(self, call: StorageCall<'_>) -> Result<(), ApplyError> {
        match call {
            StorageCall::Initialize(_) => Err(fault("initialized twice")),
            StorageCall::Update(update) => self.update(update).await,
            StorageCall::UpdatePrivate(update) => self.update_private(update).await,
            StorageCall::UpdateAuthority {
                authority,
                new_authority,
            } => {
                self.authorize(&authority)?;
                self.state.account.authority = new_authority;
                Ok(())
            }
        }
    }

    async fn update(self, update: StorageUpdate<'_>) -> Result<(), ApplyError> {
        let StorageUpdate { authority, data } = update;
        // 1. The program admits the update at the projected revision.
        self.authorize(&authority)?;
        let account = &*self.state.account;
        let mut rotated = *account;
        rotated
            .update(RootUpdate {
                slot: self.slot,
                data: &data,
            })
            .map_err(|error| fault(format!("update refused ({error})")))?;
        let revision = rotated.roots[0].revision.value();
        // 2. The writes reach the root the program recorded.
        let entries = data
            .writes
            .iter()
            .map(|write| {
                write
                    .storage_entry()
                    .map_err(|error| fault(format!("storage write refused ({error})")))
            })
            .collect::<Result<Vec<_>, ApplyError>>()?;
        let registry = Address::new_from_array(self.state.registry);
        let chain_start = chain_start(&registry, data.revision)
            .map_err(|error| fault(format!("chain start failed ({error})")))?;
        let loaded: LoadedRegistry =
            TreeRead::batch::<QUAD_HEIGHT>(StorageRoot::current(account).tree(), &entries)
                .load(self.store.tree())
                .await
                .map_err(from_storage)?;
        let batch = loaded
            .tree
            .apply_batch(chain_start, &entries)
            .map_err(|error| fault(format!("records do not apply ({error})")))?;
        let inputs = &batch.inputs;
        let recorded_next_index = u64::from(data.apply.new_next_index());
        if inputs.new_root != data.apply.new_root || inputs.new_next_index != recorded_next_index {
            return Err(fault(format!(
                "applied root mismatch at revision {revision}, projected {} at {}, program {} at {}",
                Hash(inputs.new_root),
                inputs.new_next_index,
                Hash(data.apply.new_root),
                recorded_next_index
            )));
        }
        // 3. Rows at the new revision hold the new tree.
        let records = batch.rows.records.values().copied().collect::<Vec<_>>();
        self.store.tree().save_records(&records, revision).await?;
        self.store
            .tree()
            .save_nodes(&batch.rows.nodes, revision)
            .await?;
        // 4. The roots rotate as the program rotates them.
        *self.state.account = rotated;
        self.store
            .save_root(&StorageRoot::current(&rotated))
            .await?;
        Ok(())
    }

    /// The proof binds the writes' chain to the root, the index keeps only what they publish.
    async fn update_private(self, update: PrivateUpdate<'_>) -> Result<(), ApplyError> {
        let PrivateUpdate {
            authority,
            tracking_registry,
            data,
        } = update;
        self.authorize(&authority)?;
        if tracking_registry != self.state.account.tracking_registry {
            return Err(fault("the update names another tracking registry"));
        }
        let tracking = self
            .store
            .tracking_state(tracking_registry.to_bytes())
            .await
            .map_err(from_storage)?
            .ok_or_else(|| fault("the paired tracking registry has not been indexed"))?;
        let mut rotated = *self.state.account;
        rotated
            .update_private(PrivateRootUpdate {
                revision: data.revision,
                restrictive: data.restrictive,
                slot: self.slot,
                new_root: data.apply.new_root,
                tracking_revision: tracking.account.newest().revision,
            })
            .map_err(|error| fault(format!("update refused ({error})")))?;
        for write in &data.writes {
            rotated
                .advance_write_counter(write.published().write_counter)
                .map_err(|error| fault(format!("update refused ({error})")))?;
        }
        self.store
            .save_list_writes(&data.writes, rotated.newest().revision.value())
            .await?;
        *self.state.account = rotated;
        self.store
            .save_root(&StorageRoot::current(&rotated))
            .await?;
        Ok(())
    }

    fn authorize(&self, signer: &Address) -> Result<(), ApplyError> {
        if *signer == self.state.account.authority {
            Ok(())
        } else {
            Err(fault("signer is not the registry authority"))
        }
    }
}
