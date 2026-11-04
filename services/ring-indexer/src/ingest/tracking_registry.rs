use custom_ring_interface::{
    storage::StorageError,
    storage_instruction::{tag, ApplyEnrollmentsIxData, EnrollRequest, InitializeTrackingIxData},
    tracking::{
        tracking_chain_start, EnrollmentRotation, TrackingAuthorization, TrackingEntry,
        TrackingRegistry, TrackingRootUpdate, TRACKING_QUAD_HEIGHT,
    },
};
use sea_orm::ConnectionTrait;
use solana_address::Address;
use spr_indexer_api::Hash;
use zolana_ring_indexer::tree::TrackingRecord;

use crate::{
    block::Instruction,
    indexer::{fault, from_storage, ApplyError},
    member_registry::{plant_tree, LoadedRegistry, TreeRead},
    rpc::SolanaRpc,
    storage::{Enrollment, StorageRoot, TrackingState, TrackingStore},
};

pub(crate) enum TrackingCall<'a> {
    Initialize(TrackingInit<'a>),
    Enroll(EnrollCall<'a>),
    Apply(ApplyCall<'a>),
}

pub(crate) struct TrackingInit<'a> {
    pub creator: Address,
    pub data: &'a InitializeTrackingIxData,
}

pub(crate) struct EnrollCall<'a> {
    pub owner: Address,
    pub authorization: Address,
    pub request: EnrollRequest<'a>,
}

pub(crate) struct ApplyCall<'a> {
    pub data: &'a ApplyEnrollmentsIxData,
    /// In chain order.
    pub authorizations: &'a [Address],
}

/// `call` fails on data the program refuses.
pub(crate) struct TrackingInstruction<'a> {
    pub registry: Address,
    pub call: Result<TrackingCall<'a>, StorageError>,
}

/// Account order of the `custom_ring_sdk` tracking builders.
pub(crate) fn decode(instruction: &Instruction) -> Option<TrackingInstruction<'_>> {
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
        tag::INITIALIZE_TRACKING => TrackingInstruction {
            registry: registry(2)?,
            call: account(1).and_then(|creator| {
                let data = bytemuck::try_from_bytes(data)
                    .map_err(|_| StorageError::InvalidInstructionData)?;
                Ok(TrackingCall::Initialize(TrackingInit { creator, data }))
            }),
        },
        tag::ENROLL => TrackingInstruction {
            registry: registry(2)?,
            call: account(1).and_then(|owner| {
                Ok(TrackingCall::Enroll(EnrollCall {
                    owner,
                    authorization: account(3)?,
                    request: EnrollRequest::parse(data)?,
                }))
            }),
        },
        tag::APPLY_ENROLLMENTS => TrackingInstruction {
            registry: registry(0)?,
            call: bytemuck::try_from_bytes(data)
                .map_err(|_| StorageError::InvalidInstructionData)
                .and_then(|data| {
                    let authorizations = &instruction.accounts[1..];
                    ApplyEnrollmentsIxData::check_count(authorizations.len())?;
                    Ok(TrackingCall::Apply(ApplyCall {
                        data,
                        authorizations,
                    }))
                }),
        },
        _ => return None,
    };
    Some(instruction)
}

impl TrackingInit<'_> {
    /// `None` off the canonical registry address, the program refuses it.
    pub fn state(&self, registry: Address) -> Option<TrackingState> {
        let (canonical, bump) = TrackingRegistry::find_address(&self.creator, &self.data.ring_id);
        (canonical == registry).then(|| TrackingState {
            registry: registry.to_bytes(),
            account: Box::new(TrackingRegistry::new(bump, self.data)),
            fault: None,
        })
    }
}

pub(crate) struct TrackingProjection<'p, 'c, C> {
    pub store: &'p TrackingStore<'c, C>,
    pub state: &'p mut TrackingState,
    pub slot: u64,
    pub rpc: &'p SolanaRpc,
}

impl<C: ConnectionTrait> TrackingProjection<'_, '_, C> {
    /// A refusal of the program's own checks means the projection drifted.
    pub async fn project(self, call: TrackingCall<'_>) -> Result<(), ApplyError> {
        match call {
            TrackingCall::Initialize(_) => Err(fault("initialized twice")),
            TrackingCall::Enroll(enroll) => self.enroll(enroll).await,
            TrackingCall::Apply(apply) => self.apply(apply).await,
        }
    }

    async fn enroll(self, call: EnrollCall<'_>) -> Result<(), ApplyError> {
        let held = self
            .store
            .enrollment(&call.owner.to_bytes())
            .await
            .map_err(from_storage)?;
        match held {
            None => self.first_enrollment(call).await,
            Some(held) => self.rotation(call, held).await,
        }
    }

    /// Final fields come from the account, so a late replay reads them unchanged.
    async fn first_enrollment(self, call: EnrollCall<'_>) -> Result<(), ApplyError> {
        let EnrollCall {
            owner,
            authorization,
            request,
        } = call;
        if request.proof.is_none() {
            return Err(fault("a first enrollment carries no proof"));
        }
        self.state
            .account
            .reserve_leaf()
            .map_err(|error| fault(format!("enrollment refused ({error})")))?;
        let held = self.authorization(&authorization).await?;
        if held.registry.to_bytes() != self.state.registry || held.owner != owner {
            return Err(fault("the authorization names another owner"));
        }
        let entry = held
            .entry()
            .map_err(|error| fault(format!("entry hash failed ({error})")))?;
        let first = Enrollment {
            owner: owner.to_bytes(),
            authorization: authorization.to_bytes(),
            member: entry.member,
            nullifier_pk: held.nullifier_pk,
            ct_hash: entry.ct_hash,
            list_tag: held.list_tag,
            eph_u: held.eph_u,
            ciphertext: held.ciphertext,
            // The account may hold a later rotation, the instruction holds this enrollment's key.
            viewing_u: request.ix.viewing_u,
            revision: 1,
            applied_revision: 0,
            last_enroll_slot: self.slot,
        };
        self.store
            .save_first(&first, self.slot)
            .await
            .map_err(from_storage)
    }

    async fn rotation(self, call: EnrollCall<'_>, held: Enrollment) -> Result<(), ApplyError> {
        let EnrollCall { request, .. } = call;
        if request.proof.is_some() {
            return Err(fault("a rotation carries a proof"));
        }
        let mut account = held.account(self.state.registry);
        account
            .rotate(EnrollmentRotation {
                slot: self.slot,
                ix: request.ix,
            })
            .map_err(|error| fault(format!("rotation refused ({error})")))?;
        self.store
            .save_revision(
                &held.owner,
                &account.viewing_u,
                account.revision(),
                self.slot,
            )
            .await
            .map_err(from_storage)
    }

    /// An absent account is a read behind this block or a fork, both retry.
    async fn authorization(&self, address: &Address) -> Result<TrackingAuthorization, ApplyError> {
        self.rpc
            .get_multiple_accounts_from_slot(&[*address], self.slot)
            .await?
            .into_iter()
            .flatten()
            .next()
            .and_then(|account| TrackingAuthorization::decode(&account.owner, &account.data))
            .ok_or_else(|| {
                ApplyError::Retry(anyhow::anyhow!("no tracking authorization at {address}"))
            })
    }

    async fn apply(self, call: ApplyCall<'_>) -> Result<(), ApplyError> {
        let ApplyCall {
            data,
            authorizations,
        } = call;
        // 1. The program admits the apply at the projected revision.
        let root = StorageRoot::current(&*self.state.account);
        let mut rotated = *self.state.account;
        rotated
            .update(TrackingRootUpdate {
                revision: data.revision,
                slot: self.slot,
                new_root: data.apply.new_root,
                new_next_index: data.apply.new_next_index(),
            })
            .map_err(|error| fault(format!("apply refused ({error})")))?;
        let revision = rotated.newest().revision.value();
        // 2. The entries reach the root the program recorded.
        let entries = self.applied_entries(authorizations).await?;
        let registry = Address::new_from_array(self.state.registry);
        let chain_start = tracking_chain_start(&registry, data.revision)
            .map_err(|error| fault(format!("chain start failed ({error})")))?;
        let loaded: LoadedRegistry<TrackingRecord, TRACKING_QUAD_HEIGHT> =
            TreeRead::batch::<TRACKING_QUAD_HEIGHT>(root.tree(), &entries)
                .load(self.store.tree())
                .await
                .map_err(from_storage)?;
        let batch = loaded
            .tree
            .apply_batch(chain_start, &entries)
            .map_err(|error| fault(format!("entries do not apply ({error})")))?;
        let recorded_next_index = u64::from(data.apply.new_next_index());
        if batch.inputs.new_root != data.apply.new_root
            || batch.inputs.new_next_index != recorded_next_index
        {
            return Err(fault(format!(
                "applied root mismatch at revision {revision}, projected {} at {}, program {} at {}",
                Hash(batch.inputs.new_root),
                batch.inputs.new_next_index,
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

    /// Each owner's newest enrollment before this apply, older rotations never reach a leaf.
    async fn applied_entries(
        &self,
        authorizations: &[Address],
    ) -> Result<Vec<TrackingEntry>, ApplyError> {
        let mut entries = Vec::with_capacity(authorizations.len());
        for authorization in authorizations {
            let held = self
                .store
                .enrollment_at(&authorization.to_bytes())
                .await
                .map_err(from_storage)?
                .ok_or_else(|| fault("an apply names no enrollment"))?;
            let entry = held
                .account(self.state.registry)
                .apply()
                .map_err(|error| fault(format!("apply refused ({error})")))?;
            self.store
                .mark_applied(&held.owner, held.revision, self.slot)
                .await
                .map_err(from_storage)?;
            entries.push(entry);
        }
        Ok(entries)
    }
}

pub(crate) async fn create<C: ConnectionTrait>(
    store: &TrackingStore<'_, C>,
    state: &TrackingState,
) -> anyhow::Result<()> {
    plant_tree::<_, _, TRACKING_QUAD_HEIGHT>(store.tree()).await?;
    store
        .save_root(&StorageRoot::current(&*state.account))
        .await?;
    store.save_state(state).await
}
