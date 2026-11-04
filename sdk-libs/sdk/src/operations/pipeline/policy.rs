//! The policy section of a ring transfer, every record read under a root the statement binds.

use custom_ring_interface::{
    cosign::ApprovalMask,
    key_catalog::{RecordPools as PoolWidths, RingCircuit, TransferShape, TransferSpend},
    CustomRingError, PolicyWithdrawal, PublicSlots, RingRail, RootRead, TransferRoots,
};
use solana_address::Address;
use spr_client::AsyncRpc;
use spr_hasher::primitives::right_align;
use spr_interface::{N_PUBLIC_SLOTS, ZERO_NULLIFIER_PUBKEY};
use spr_transaction::instructions::transact::SppProofInputs;
use zolana_ring_client::{records::RecordPoolRead, AsyncRingIndexer};
use zolana_ring_member_registry::RecordPool;
use zolana_ring_policy::{
    ApprovalInputs, EncodedRuleTable, Member, MintPolicy, OutputSubjects, PublicGross, RecordLists,
    SourceMap, TransferSubjects,
};

use super::audit::is_default_ring;
use crate::{
    limits::Outflows,
    records::{check_output_key, PoolRead, TrackingPoolRead, TrackingRead},
    request::{
        PolicyParams, PolicyTable, PolicyWithdrawalRequest, PoolEntry, RecordPools, TrackingParams,
    },
    submission::BoundRoot,
    CustomRingConfig, PinnedPolicy, RingError,
};

pub(super) struct PolicyInputs {
    circuit: RingCircuit,
    widths: PoolWidths,
    pub read: RootRead,
    /// The key opens its full owner rows.
    pub wide_owners: bool,
    /// The key's `S` rows, ascending with zero rows last.
    pub rows: Vec<[u8; 32]>,
    pub spl_withdrawal_owners: Vec<[u8; 32]>,
    withdrawals: Vec<PolicyWithdrawal>,
    rules: EncodedRuleTable,
    sources: SourceMap,
    /// Zero off a policy, the gate of every rule.
    pub policy_hash: [u8; 32],
    /// Every rail reads it.
    pub tracking: BoundRoot,
    tracking_pool: TrackingPoolRead,
    row_entries: Vec<u32>,
    output_entries: Vec<u32>,
    /// Bound on a ring with own records off the delegate rails, `None` leaves the own root zero.
    pub own: Option<BoundRoot>,
    pub curator: Option<BoundRoot>,
    /// `None` is the unopened pool of a key whose queries are all off.
    own_pool: Option<RecordPoolRead>,
    curator_pool: Option<RecordPoolRead>,
    /// `S` entries in row order.
    sender_entries: Vec<PoolEntry>,
    owner_entries: Vec<PoolEntry>,
    asset_entries: Vec<PoolEntry>,
    public_asset_entries: Vec<u32>,
    pub approval: ApprovalMask,
}

pub(super) struct PolicyRead<'a> {
    pub token_owner_hint: Option<Address>,
    pub config: &'a CustomRingConfig,
    pub rail: RingRail,
    pub inputs: &'a SppProofInputs,
    /// The spent notes, every input but the compact ones.
    pub published_inputs: usize,
    pub spends_default_ring: bool,
    pub has_data: bool,
    pub n_out: u8,
    pub public: &'a PublicSlots,
}

impl PolicyRead<'_> {
    pub async fn read<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        self,
        client: &R,
    ) -> Result<PolicyInputs, RingError> {
        let n_out = usize::from(self.n_out);
        let policy = self.config.account();
        let read = RootRead::transfer(policy, self.rail.is_delegate());
        let (withdrawals, spl_withdrawal_owners) = match read {
            RootRead::None => (Vec::new(), Vec::new()),
            RootRead::Own | RootRead::Policy => {
                read_withdrawals(
                    client,
                    &self.inputs.external_data.interface_transfers,
                    self.token_owner_hint,
                )
                .await?
            }
        };
        let live_rows = self.owner_rows()?;
        let spend = TransferSpend {
            rail: self.rail,
            inputs: self.published_inputs,
            outputs: n_out,
            spends_default_ring: self.spends_default_ring,
            legs: withdrawals.len(),
            owners: live_rows.len(),
            has_data: self.has_data,
            private_source: read == RootRead::Policy && !policy.salted().is_empty(),
        };
        let unkeyed = || RingError::ShapeUnkeyed { rail: self.rail };
        let circuit = RingCircuit::transfer(spend).ok_or_else(unkeyed)?;
        let shape = TransferShape::family(self.rail, self.spends_default_ring)
            .and_then(|family| TransferShape::of(family, n_out))
            .ok_or_else(unkeyed)?;
        let widths = circuit
            .record_pools()
            .ok_or(RingError::UnpinnedProvingKey(circuit))?;
        let capacity = circuit.owners().map_or(0, usize::from);
        let mut rows = live_rows;
        rows.resize(capacity, [0; 32]);
        let tracking = BoundRoot::tracking(policy, client).await?;
        let (tracking_pool, row_entries, output_entries) =
            self.read_tracking(client, tracking, &rows, widths).await?;
        let mut inputs = PolicyInputs {
            circuit,
            widths,
            read,
            wide_owners: circuit.owners() == Some(shape.owners[1]),
            rows,
            spl_withdrawal_owners,
            withdrawals,
            rules: EncodedRuleTable::default(),
            sources: SourceMap::default(),
            policy_hash: [0; 32],
            tracking,
            tracking_pool,
            row_entries,
            output_entries,
            own: None,
            curator: None,
            own_pool: None,
            curator_pool: None,
            sender_entries: vec![PoolEntry::default(); capacity],
            owner_entries: Vec::new(),
            asset_entries: Vec::new(),
            public_asset_entries: vec![0; N_PUBLIC_SLOTS],
            approval: ApprovalMask::default(),
        };
        if read != RootRead::None {
            self.read_records(client, &mut inputs).await?;
        }
        Ok(inputs)
    }

    /// The distinct live input owners ascending, the delegate moves a zero-key note with no row.
    fn owner_rows(&self) -> Result<Vec<[u8; 32]>, RingError> {
        let delegate = self.rail.is_delegate();
        let mut rows = self
            .inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_dummy() && !input.is_address())
            .filter(|input| !(delegate && input.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY))
            .map(|input| Ok(input.utxo.owner.owner_proof_input_hash()?))
            .collect::<Result<Vec<_>, RingError>>()?;
        rows.sort_unstable();
        rows.dedup();
        Ok(rows)
    }

    /// Every row and live ring output opens under the frame's tracking root.
    async fn read_tracking<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        &self,
        client: &R,
        root: BoundRoot,
        rows: &[[u8; 32]],
        widths: PoolWidths,
    ) -> Result<(TrackingPoolRead, Vec<u32>, Vec<u32>), RingError> {
        let mut subjects = PoolSubjects::default();
        let row_entries = rows
            .iter()
            .map(|row| subjects.index((*row != [0; 32]).then_some(*row)))
            .collect();
        let ring_owners = self
            .inputs
            .output_utxos
            .iter()
            .map(|output| {
                output
                    .owner_address
                    .filter(|_| output.ring_program_id.is_some() && !output.is_dummy())
                    .map(|owner| owner.signing_pubkey.owner_proof_input_hash())
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let output_entries = ring_owners
            .iter()
            .map(|owner| subjects.index(*owner))
            .collect();
        let pool = TrackingRead {
            root,
            members: subjects.opened(),
            openings: widths.tracking,
        }
        .read(client)
        .await?;
        self.check_input_keys(&pool)?;
        self.check_output_keys(&pool, &ring_owners)?;
        Ok((pool, row_entries, output_entries))
    }

    /// A keyed ring note spends under its owner's enrolled key, a zero key waives the equality alone.
    fn check_input_keys(&self, pool: &TrackingPoolRead) -> Result<(), RingError> {
        for (index, input) in self.inputs.input_utxos.iter().enumerate() {
            if input.is_dummy()
                || is_default_ring(input)
                || input.nullifier_pubkey == ZERO_NULLIFIER_PUBKEY
            {
                continue;
            }
            let member = input.utxo.owner.owner_proof_input_hash()?;
            if pool
                .record(&member)
                .is_none_or(|record| record.nullifier_pk != input.nullifier_pubkey)
            {
                return Err(RingError::InputKeyNotEnrolled { index });
            }
        }
        Ok(())
    }

    fn check_output_keys(
        &self,
        pool: &TrackingPoolRead,
        owners: &[Option<[u8; 32]>],
    ) -> Result<(), RingError> {
        for (slot_index, (output, owner)) in self.inputs.output_utxos.iter().zip(owners).enumerate()
        {
            let (Some(address), Some(member)) = (output.owner_address, owner) else {
                continue;
            };
            check_output_key(pool.record(member), &address.nullifier_pubkey, slot_index)?;
        }
        Ok(())
    }

    /// The thresholds read the own root on every read, the rules only under a policy.
    async fn read_records<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        &self,
        client: &R,
        inputs: &mut PolicyInputs,
    ) -> Result<(), RingError> {
        let policy = self.config.account();
        let screened = inputs.read == RootRead::Policy;
        let own = BoundRoot::own(policy, client).await?;
        let curator = match screened {
            true => BoundRoot::curator(policy, client).await?,
            false => None,
        };
        let outputs = &self.inputs.output_utxos;
        let owners = outputs
            .iter()
            .map(|output| {
                output
                    .owner_address
                    .filter(|_| !output.is_dummy())
                    .map(|owner| owner.signing_pubkey.owner_proof_input_hash())
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let assets = outputs
            .iter()
            .map(|output| match output.is_dummy() {
                false => Ok(Some(*Member::asset(&output.asset.asset)?.as_bytes())),
                true => Ok(None),
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let mut subjects = PoolSubjects::default();
        let entry = |index: u32| PoolEntry {
            own: index,
            curator: [match curator {
                Some(_) => index,
                None => 0,
            }],
        };
        inputs.sender_entries = inputs
            .rows
            .iter()
            .map(|row| entry(subjects.index((screened && *row != [0; 32]).then_some(*row))))
            .collect();
        let payments = owners
            .iter()
            .zip(&assets)
            .map(|(owner, asset)| (*owner, *asset))
            .chain(
                inputs
                    .withdrawals
                    .iter()
                    .map(|w| (Some(w.owner), Some(w.asset))),
            );
        let (mut owner_entries, mut asset_entries) = (Vec::new(), Vec::new());
        for (owner, asset) in payments {
            owner_entries.push(entry(subjects.index(owner.filter(|_| screened))));
            asset_entries.push(entry(subjects.index(asset)));
        }
        // Public assets resolve in the own pool alone.
        let curator_members = subjects.opened().to_vec();
        let public_assets = self.public.asset_fields()?;
        inputs.public_asset_entries = public_assets
            .iter()
            .map(|asset| subjects.index((*asset != [0; 32]).then_some(*asset)))
            .collect();
        let own_pool = PoolRead {
            root: own,
            members: subjects.opened(),
            openings: inputs.widths.own,
        }
        .read(client)
        .await?;
        let curator_pool = match curator {
            Some(curator) => Some(
                PoolRead {
                    root: curator,
                    members: &curator_members,
                    openings: inputs.widths.curator,
                }
                .read(client)
                .await?,
            ),
            None => None,
        };
        let mint_policy = |asset: &[u8; 32]| {
            own_pool
                .record(asset)
                .map_or(MintPolicy::EMPTY, |record| record.mint_policy)
        };
        let outflows = Outflows {
            senders: &inputs.rows,
            inputs: &self.inputs.input_utxos,
            outputs,
            public_assets: &public_assets,
            public_gross: &self.public.gross(),
        };
        if screened {
            let pinned = PinnedPolicy::of(policy)?;
            let lists = |member: [u8; 32]| {
                let on =
                    |pool: &RecordPoolRead| pool.record(&member).map_or(0, |record| record.lists);
                RecordLists {
                    own: on(&own_pool),
                    curator: curator_pool.as_ref().map_or(0, on),
                    private: 0,
                }
            };
            let subject =
                |ring: bool, owner: [u8; 32], asset: [u8; 32], amount: u64| OutputSubjects {
                    ring,
                    owner,
                    asset,
                    amount,
                    owner_lists: lists(owner),
                    asset_lists: lists(asset),
                    mint_policy: mint_policy(&asset),
                };
            let mut transfer_subjects = outputs
                .iter()
                .zip(owners.iter().zip(&assets))
                .filter_map(|(output, (owner, asset))| {
                    Some(subject(
                        output.ring_program_id.is_some(),
                        (*owner)?,
                        (*asset)?,
                        output.amount,
                    ))
                })
                .collect::<Vec<_>>();
            transfer_subjects.extend(
                inputs
                    .withdrawals
                    .iter()
                    .map(|w| subject(false, w.owner, w.asset, w.amount)),
            );
            let ring_inputs = outflows.ring_inputs()?;
            // Every row passes the sender rules, a co-owner who receives nothing is screened.
            for sender in inputs.rows.iter().filter(|sender| **sender != [0; 32]) {
                pinned.table.admit(
                    &pinned.sources,
                    &TransferSubjects {
                        sender: lists(*sender),
                        ring_inputs: &ring_inputs,
                        outputs: &transfer_subjects,
                    },
                )?;
            }
            inputs.rules = policy.rules;
            inputs.sources = pinned.sources;
            inputs.policy_hash = pinned.policy_hash;
        }
        let flows = outflows.flows()?;
        Outflows::check_caps(&flows, mint_policy)?;
        let public_gross: Vec<PublicGross> = public_assets
            .iter()
            .zip(self.public.gross())
            .filter(|(asset, _)| **asset != [0; 32])
            .map(|(asset, gross)| PublicGross {
                asset: *asset,
                gross,
            })
            .collect();
        inputs.approval = ApprovalMask::new(
            ApprovalInputs {
                flows: &flows,
                public_gross: &public_gross,
            }
            .mask(mint_policy)
            .bits(),
        )
        .ok_or(CustomRingError::FlagNotAllowed)?;
        inputs.own = Some(own);
        inputs.curator = curator;
        inputs.own_pool = Some(own_pool);
        inputs.curator_pool = curator_pool;
        inputs.owner_entries = owner_entries;
        inputs.asset_entries = asset_entries;
        Ok(())
    }
}

/// Distinct pool members in first use order, an absent subject takes index 0.
#[derive(Default)]
struct PoolSubjects {
    members: Vec<[u8; 32]>,
}

/// A read with no subject still opens one path, the proof folds every pool slot under the root.
const NO_SUBJECT: [[u8; 32]; 1] = [right_align_one()];

const fn right_align_one() -> [u8; 32] {
    let mut member = [0; 32];
    member[31] = 1;
    member
}

impl PoolSubjects {
    fn opened(&self) -> &[[u8; 32]] {
        match self.members.is_empty() {
            true => &NO_SUBJECT,
            false => &self.members,
        }
    }

    fn index(&mut self, member: Option<[u8; 32]>) -> u32 {
        let Some(member) = member else {
            return 0;
        };
        let index = match self.members.iter().position(|known| *known == member) {
            Some(index) => index,
            None => {
                self.members.push(member);
                self.members.len() - 1
            }
        };
        // At most `MAX_RING_MEMBER_PAGE_LIMIT` members, the pool read refuses more.
        index as u32
    }
}

pub(super) struct PolicyProving<'a> {
    pub ring_id: [u8; 32],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amounts: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_gross: &'a [[u8; 32]; N_PUBLIC_SLOTS],
}

impl PolicyInputs {
    pub fn circuit(&self) -> RingCircuit {
        self.circuit
    }

    pub fn screened(&self) -> bool {
        self.policy_hash != [0; 32]
    }

    pub fn roots(&self) -> TransferRoots {
        TransferRoots {
            policy_hash: self.policy_hash,
            own_root: self.own.map_or([0; 32], |own| own.root),
            curator_root: self.curator.map_or([0; 32], |curator| curator.root),
            tracking_root: self.tracking.root,
            private_root: [0; 32],
        }
    }

    pub fn withdrawal_hash(&self) -> Result<[u8; 32], RingError> {
        Ok(custom_ring_interface::policy_withdrawal_hash(
            &self.withdrawals,
        )?)
    }

    pub fn tracking_params(&self) -> Result<TrackingParams, RingError> {
        Ok(TrackingParams {
            tracking_root: self.tracking.root,
            pool: self
                .tracking_pool
                .pool()
                .clone()
                .padded(self.widths.tracking)?,
            row_entries: self.row_entries.clone(),
            output_entries: self.output_entries.clone(),
        })
    }

    pub fn params(&self, proving: &PolicyProving<'_>) -> Result<PolicyParams<'_>, RingError> {
        let capacity = usize::from(
            self.circuit
                .withdrawals()
                .ok_or(RingError::UncataloguedCircuit(self.circuit))?,
        );
        let outputs = self.output_entries.len();
        let roots = self.roots();
        let mut withdrawals = self.withdrawals.clone();
        withdrawals.resize(capacity, PolicyWithdrawal::default());
        let mut owner_entries = self.owner_entries.clone();
        let mut asset_entries = self.asset_entries.clone();
        owner_entries.resize(outputs + capacity, PoolEntry::default());
        asset_entries.resize(outputs + capacity, PoolEntry::default());
        let pool = |read: &Option<RecordPoolRead>, width: usize| match read {
            Some(read) => read.pool().clone().padded(width),
            None => RecordPool::unopened(width),
        };
        Ok(PolicyParams {
            withdrawal_count: self.withdrawals.len() as u8,
            withdrawal_hash: self.withdrawal_hash()?,
            withdrawals: withdrawals
                .iter()
                .map(|w| PolicyWithdrawalRequest {
                    owner: w.owner,
                    asset: w.asset,
                    amount: right_align(&w.amount.to_be_bytes()),
                })
                .collect(),
            policy_hash: self.policy_hash,
            ring_id: proving.ring_id,
            own_root: roots.own_root,
            curator_root: roots.curator_root,
            private_root: roots.private_root,
            public_assets: proving.public_assets.to_vec(),
            public_amounts: proving.public_amounts.to_vec(),
            public_gross: proving.public_gross.to_vec(),
            table: PolicyTable {
                rules: &self.rules,
                sources: &self.sources,
            },
            pools: RecordPools {
                own: pool(&self.own_pool, self.widths.own)?,
                curator: pool(&self.curator_pool, self.widths.curator)?,
            },
            sender_entries: self.sender_entries.clone(),
            owner_entries,
            asset_entries,
            public_asset_entries: self.public_asset_entries.clone(),
        })
    }
}

/// Resolve token owners once; the program checks the snapshot again at execution.
async fn read_withdrawals<R: AsyncRpc + ?Sized>(
    client: &R,
    transfers: &[spr_transaction::instructions::transact::SettlementTransfer],
    hint: Option<Address>,
) -> Result<(Vec<PolicyWithdrawal>, Vec<[u8; 32]>), RingError> {
    use spr_interface::{SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};
    use spr_transaction::instructions::transact::SettlementTransfer;
    let mut payments = Vec::new();
    let mut owners = Vec::new();
    for transfer in transfers.iter().filter(|t| !t.is_deposit()) {
        let payment = match *transfer {
            SettlementTransfer::Sol {
                user_sol_account,
                amount,
                ..
            } => PolicyWithdrawal::new(user_sol_account.as_array(), None, amount)?,
            SettlementTransfer::Spl {
                mint,
                user_spl_token,
                amount,
                ..
            } => {
                let invalid = || RingError::AnonymousExitTokenAccountInvalid(user_spl_token);
                let owner = match client.get_account(user_spl_token).await? {
                    Some(account) => {
                        if ![SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID]
                            .contains(account.owner.as_array())
                        {
                            return Err(invalid());
                        }
                        let token =
                            custom_ring_interface::TokenAccountState::unpack(&account.data)?;
                        if token.mint != mint.to_bytes() {
                            return Err(invalid());
                        }
                        *token.control.owner()
                    }
                    None => {
                        let owner = hint.ok_or_else(invalid)?;
                        let program = client
                            .get_account(mint)
                            .await?
                            .map(|a| a.owner)
                            .ok_or_else(invalid)?;
                        if ![SPL_TOKEN_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID]
                            .contains(program.as_array())
                            || spr_interface::pda::associated_token_address_with_program(
                                &owner, &mint, &program,
                            ) != user_spl_token
                        {
                            return Err(invalid());
                        }
                        owner.to_bytes()
                    }
                };
                owners.push(owner);
                PolicyWithdrawal::new(&owner, Some(mint.as_array()), amount)?
            }
        };
        payments.push(payment);
    }
    Ok((payments, owners))
}
