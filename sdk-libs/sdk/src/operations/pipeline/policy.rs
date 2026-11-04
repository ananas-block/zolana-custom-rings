//! The policy section of a ring transfer, every record read under a root the statement binds.

use std::collections::BTreeSet;

use custom_ring_interface::{
    cosign::CoSignDemand,
    key_catalog::{
        RecordPools as PoolWidths, RingCircuit, TransferSpend, SCREENED_ENTRY_OWNERS,
        SCREENED_OWNERS,
    },
    member_registry::AuthorizedAddress,
    CustomRingError, PolicyWithdrawal, PublicSlots, RingMode, RingRail, TransferRoots,
};
use solana_address::Address;
use spr_client::AsyncRpc;
use spr_hasher::primitives::{right_align, solana_owner_identity};
use spr_interface::{N_PUBLIC_SLOTS, ZERO_NULLIFIER_PUBKEY};
use spr_keypair::ShieldedAddress;
use spr_transaction::instructions::transact::SppProofInputs;
use zolana_ring_client::{records::RecordPoolRead, AsyncRingIndexer};
use zolana_ring_member_registry::RecordPool;
use zolana_ring_policy::{
    EncodedRuleTable, Member, OutputSubjects, RecordLists, SourceMap, TransferSubjects,
};

use super::{
    audit::SlotAddress,
    withdrawals::{thresholds_cover, waives_co_signer},
};
use crate::{
    limits::Outflows,
    records::PoolRead,
    request::{PolicyParams, PolicyTable, PolicyWithdrawalRequest, PoolEntry, RecordPools},
    submission::BoundRoot,
    CustomRing, CustomRingConfig, PinnedPolicy, RingError,
};

#[derive(Clone, Copy)]
struct OutputOwner {
    member: [u8; 32],
    nullifier_pk: [u8; 32],
}

pub(super) struct PolicyInputs {
    circuit: RingCircuit,
    widths: PoolWidths,
    pub spl_withdrawal_owners: Vec<[u8; 32]>,
    withdrawals: Vec<PolicyWithdrawal>,
    rules: EncodedRuleTable,
    sources: SourceMap,
    /// Zero off a policy, the gate of every rule.
    pub policy_hash: [u8; 32],
    /// Bound under a policy or an exemption, `None` leaves the own root zero.
    pub own: Option<BoundRoot>,
    pub curator: Option<BoundRoot>,
    /// `None` is the unopened pool of a key whose queries are all off.
    own_pool: Option<RecordPoolRead>,
    curator_pool: Option<RecordPoolRead>,
    /// `Q` entries in subject order.
    sender_entries: Vec<PoolEntry>,
    /// The sender's bound address, set on the anonymous rail.
    pub sender_address: Option<AuthorizedAddress>,
    /// One per output slot, default off a recipient.
    pub slot_addresses: Vec<SlotAddress>,
    owner_entries: Vec<PoolEntry>,
    asset_entries: Vec<PoolEntry>,
    public_asset_entries: Vec<u32>,
    /// One per output slot, zero without key escrow.
    ct_hashes: Vec<[u8; 32]>,
    /// One per output slot, zero on a dummy, off a policy and on the anonymous rail.
    pub recipients: Vec<[u8; 32]>,
    pub approval_required: bool,
    pub key_escrow: bool,
    pub exempt: bool,
}

pub(super) struct PolicyRead<'a> {
    pub token_owner_hint: Option<Address>,
    pub ring: CustomRing,
    pub config: &'a CustomRingConfig,
    pub rail: RingRail,
    pub inputs: &'a SppProofInputs,
    /// The spent notes, every input but the compact ones.
    pub published_inputs: usize,
    pub spends_default_ring: bool,
    pub n_out: u8,
    /// The owner identity the rules read as the sender.
    pub sender: [u8; 32],
    pub sender_address: &'a ShieldedAddress,
    pub in_proof: bool,
    /// The transaction's owner run, public co-owners on the anonymous rail.
    pub owner_signers: &'a [Address],
    pub public: &'a PublicSlots,
}

impl PolicyRead<'_> {
    pub async fn read<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        self,
        client: &R,
    ) -> Result<PolicyInputs, RingError> {
        Outflows {
            senders: &[],
            inputs: &self.inputs.input_utxos,
            outputs: &self.inputs.output_utxos,
            public_assets: &self.public.asset_fields()?,
            public_amounts: &self.public.amounts(),
        }
        .check_deposits()?;
        let n_out = usize::from(self.n_out);
        let (withdrawals, spl_withdrawal_owners) = match self.config.has_policy {
            true => {
                read_withdrawals(
                    client,
                    &self.inputs.external_data.interface_transfers,
                    self.token_owner_hint,
                )
                .await?
            }
            false => (Vec::new(), Vec::new()),
        };
        let circuit = RingCircuit::transfer(TransferSpend {
            rail: self.rail,
            inputs: self.published_inputs,
            outputs: n_out,
            spends_default_ring: self.spends_default_ring,
            legs: withdrawals.len(),
        })
        .ok_or(RingError::ShapeUnkeyed { rail: self.rail })?;
        let widths = circuit
            .record_pools()
            .ok_or(RingError::UnpinnedProvingKey(circuit))?;
        let mut inputs = PolicyInputs {
            circuit,
            widths,
            spl_withdrawal_owners,
            withdrawals,
            rules: EncodedRuleTable::default(),
            sources: SourceMap::default(),
            policy_hash: [0; 32],
            own: None,
            curator: None,
            own_pool: None,
            curator_pool: None,
            sender_entries: vec![PoolEntry::default(); self.screened_owners()],
            sender_address: None,
            slot_addresses: Vec::new(),
            owner_entries: Vec::new(),
            asset_entries: Vec::new(),
            public_asset_entries: vec![0; N_PUBLIC_SLOTS],
            ct_hashes: vec![[0; 32]; n_out],
            recipients: vec![[0; 32]; n_out],
            approval_required: false,
            key_escrow: self.config.mode == RingMode::ConfidentialEscrow,
            exempt: false,
        };
        if self.config.has_policy {
            self.screen(client, &mut inputs).await?;
        } else if self.rail == RingRail::Anonymous {
            self.deliver(client, &mut inputs).await?;
        }
        Ok(inputs)
    }

    const fn screened_owners(&self) -> usize {
        match self.spends_default_ring {
            true => SCREENED_ENTRY_OWNERS,
            false => SCREENED_OWNERS,
        }
    }

    /// The deterministic sender subjects of the rail, never a witness.
    fn senders(&self) -> Result<Vec<[u8; 32]>, RingError> {
        let identities = self
            .owner_signers
            .iter()
            .map(|owner| Ok(solana_owner_identity(owner.as_array())?))
            .collect::<Result<Vec<_>, RingError>>()?;
        let q = self.screened_owners();
        let mut senders = match self.rail {
            RingRail::Confidential if !self.in_proof => identities,
            RingRail::Confidential | RingRail::Delegate => vec![self.sender],
            RingRail::Anonymous => core::iter::once(self.sender).chain(identities).collect(),
        };
        if senders.len() > q {
            return Err(CustomRingError::OwnerSignerCount.into());
        }
        senders.resize(q, [0; 32]);
        Ok(senders)
    }

    /// An audit-only anonymous ring loads its own root for delivery alone, no rule reads it.
    async fn deliver<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        &self,
        client: &R,
        inputs: &mut PolicyInputs,
    ) -> Result<(), RingError> {
        let own = BoundRoot::own(self.config.account(), client).await?;
        let mut subjects = PoolSubjects::default();
        let entry = |index: u32| PoolEntry {
            own: index,
            curator: [0],
        };
        // Delivery reads the first sender alone, a public co-owner carries no rule off a policy.
        inputs.sender_entries[0] = entry(subjects.index(Some(self.sender)));
        for output in &self.inputs.output_utxos {
            let owner = output
                .owner_address
                .map(|owner| owner.signing_pubkey.owner_proof_input_hash())
                .transpose()?;
            inputs.owner_entries.push(entry(subjects.index(owner)));
        }
        let own_pool = PoolRead {
            root: own,
            members: &subjects.members,
            openings: inputs.widths.own,
        }
        .read(client)
        .await?;
        self.bind_addresses(&own_pool, inputs)?;
        inputs.own = Some(own);
        inputs.own_pool = Some(own_pool);
        Ok(())
    }

    /// The sender and every live recipient hold the enrolled address the proof opens.
    fn bind_addresses(
        &self,
        pool: &RecordPoolRead,
        inputs: &mut PolicyInputs,
    ) -> Result<(), RingError> {
        let ring_id = self.ring.ring_id()?;
        let sender_address = pool
            .address(&self.sender)
            .filter(|address| address.ring_id == ring_id)
            .ok_or(RingError::SenderNotEnrolled)?;
        if !self.binds(sender_address, self.sender_address) {
            return Err(RingError::SenderAddressMismatch);
        }
        inputs.sender_address = Some(*sender_address);
        inputs.slot_addresses = self
            .inputs
            .output_utxos
            .iter()
            .enumerate()
            .map(|(slot_index, output)| {
                let Some(owner) = output
                    .owner_address
                    .filter(|_| output.ring_program_id.is_some())
                else {
                    return Ok(SlotAddress::default());
                };
                let member = owner.signing_pubkey.owner_proof_input_hash()?;
                let address = pool
                    .address(&member)
                    .filter(|address| address.ring_id == ring_id)
                    .ok_or(RingError::RecipientNotEnrolled { slot_index })?;
                if !self.binds(address, &owner) {
                    return Err(RingError::RecipientAddressMismatch { slot_index });
                }
                Ok(SlotAddress {
                    viewing_u: address.viewing_u,
                    revision: address.address_revision,
                })
            })
            .collect::<Result<_, RingError>>()?;
        Ok(())
    }

    fn binds(&self, address: &AuthorizedAddress, owner: &ShieldedAddress) -> bool {
        address.nullifier_pk == owner.nullifier_pubkey
            && address.viewing_u == owner.viewing_pubkey.u()
    }

    async fn screen<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        &self,
        client: &R,
        inputs: &mut PolicyInputs,
    ) -> Result<(), RingError> {
        let policy = self.config.account();
        let pinned = PinnedPolicy::of(policy)?;
        let own = BoundRoot::own(policy, client).await?;
        let curator = BoundRoot::curator(policy, client).await?;
        let outputs = &self.inputs.output_utxos;
        let owners = outputs
            .iter()
            .map(|output| {
                output
                    .owner_address
                    .map(|owner| {
                        Ok::<_, RingError>(OutputOwner {
                            member: owner.signing_pubkey.owner_proof_input_hash()?,
                            nullifier_pk: owner.nullifier_pubkey,
                        })
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let assets = outputs
            .iter()
            .map(|output| match output.is_dummy() {
                false => Ok(Some(*Member::asset(&output.asset.asset)?.as_bytes())),
                _ => Ok(None),
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let publishes = self.rail.publishes_recipients();
        inputs.recipients = owners
            .iter()
            .map(|owner| match owner {
                Some(owner) if publishes => owner.member,
                _ => [0; 32],
            })
            .collect();
        let mut subjects = PoolSubjects::default();
        let entry = |index: u32| PoolEntry {
            own: index,
            curator: [match curator {
                Some(_) => index,
                None => 0,
            }],
        };
        let senders = self.senders()?;
        inputs.sender_entries = senders
            .iter()
            .map(|sender| entry(subjects.index((*sender != [0; 32]).then_some(*sender))))
            .collect();
        let withdrawals = &inputs.withdrawals;
        let payments = owners
            .iter()
            .zip(&assets)
            .map(|(owner, asset)| (owner.map(|owner| owner.member), *asset))
            .chain(withdrawals.iter().map(|w| (Some(w.owner), Some(w.asset))));
        let (mut owner_entries, mut asset_entries) = (Vec::new(), Vec::new());
        for (owner, asset) in payments {
            owner_entries.push(entry(subjects.index(owner)));
            asset_entries.push(entry(subjects.index(asset)));
        }
        // Public assets resolve in the own pool alone.
        let curator_members = subjects.members.clone();
        let public_assets = self.public.asset_fields()?;
        inputs.public_asset_entries = public_assets
            .iter()
            .map(|asset| subjects.index((*asset != [0; 32]).then_some(*asset)))
            .collect();
        let own_pool = PoolRead {
            root: own,
            members: &subjects.members,
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
        let lists = |member: [u8; 32]| {
            let on = |pool: &RecordPoolRead| pool.record(&member).map_or(0, |record| record.lists);
            RecordLists {
                own: on(&own_pool),
                curator: curator_pool.as_ref().map_or(0, on),
            }
        };
        let mint_policy = |asset: &[u8; 32]| {
            own_pool
                .record(asset)
                .map_or(zolana_ring_policy::MintPolicy::EMPTY, |record| {
                    record.mint_policy
                })
        };
        let mut transfer_subjects = outputs
            .iter()
            .zip(&owners)
            .filter_map(|(output, owner)| owner.map(|owner| (output, owner)))
            .map(|(output, owner)| {
                let asset = *Member::asset(&output.asset.asset)?.as_bytes();
                Ok(OutputSubjects {
                    owner: owner.member,
                    asset,
                    amount: output.amount,
                    owner_lists: lists(owner.member),
                    asset_lists: lists(asset),
                    mint_policy: mint_policy(&asset),
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        transfer_subjects.extend(withdrawals.iter().map(|w| OutputSubjects {
            owner: w.owner,
            asset: w.asset,
            amount: w.amount,
            owner_lists: lists(w.owner),
            asset_lists: lists(w.asset),
            mint_policy: mint_policy(&w.asset),
        }));
        // Every sender passes the sender rules, a co-owner who receives nothing is screened.
        for sender in senders.iter().filter(|sender| **sender != [0; 32]) {
            pinned.table.admit(
                &pinned.sources,
                &TransferSubjects {
                    sender: lists(*sender),
                    outputs: &transfer_subjects,
                },
            )?;
        }
        if self.rail == RingRail::Anonymous {
            self.bind_addresses(&own_pool, inputs)?;
        }
        let key_escrow = inputs.key_escrow;
        for (ct_hash, owner) in inputs.ct_hashes.iter_mut().zip(&owners) {
            // A zero secret owner owes no escrow.
            if let (true, Some(owner)) = (key_escrow, owner) {
                if owner.nullifier_pk == ZERO_NULLIFIER_PUBKEY {
                    continue;
                }
                *ct_hash = own_pool
                    .escrowed_ct_hash(&owner.member, &owner.nullifier_pk)?
                    .ok_or(RingError::UnregisteredOutputKey {
                        owner: Member::from_bytes(owner.member)?,
                    })?;
            }
        }
        let limit_assets: BTreeSet<_> = assets
            .iter()
            .flatten()
            .copied()
            .chain(
                public_assets
                    .iter()
                    .copied()
                    .filter(|asset| *asset != [0; 32]),
            )
            .collect();
        let limits = limit_assets
            .iter()
            .filter_map(|asset| {
                let policy = mint_policy(asset);
                (policy.cap != 0 || policy.cosign_above != 0).then(|| {
                    let member = Member::from_bytes(*asset).expect("verified record member");
                    zolana_ring_policy::OutflowLimit::of(&member)
                        .with_cap(policy.cap)
                        .with_cosign_above(policy.cosign_above)
                })
            })
            .collect::<Vec<_>>();
        let outflows = Outflows {
            senders: &senders,
            inputs: &self.inputs.input_utxos,
            outputs,
            public_assets: &public_assets,
            public_amounts: &self.public.amounts(),
        };
        inputs.approval_required = match self.rail {
            RingRail::Delegate => false,
            RingRail::Confidential | RingRail::Anonymous => outflows.approval_required(&limits)?,
        };
        inputs.rules = policy.rules;
        inputs.sources = pinned.sources;
        inputs.policy_hash = pinned.policy_hash;
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

impl PoolSubjects {
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
        }
    }

    pub fn withdrawal_hash(&self) -> Result<[u8; 32], RingError> {
        Ok(custom_ring_interface::policy_withdrawal_hash(
            &self.withdrawals,
        )?)
    }

    /// A no-op when the waiver removes no co-signer or a threshold is short.
    pub async fn exempt_withdrawals<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        &mut self,
        config: &CustomRingConfig,
        demand: &CoSignDemand,
        public: &PublicSlots,
        client: &R,
    ) -> Result<(), RingError> {
        if !waives_co_signer(config.account(), demand)? {
            return Ok(());
        }
        let (assets, gross) = (public.asset_fields()?, public.gross());
        match &self.own_pool {
            Some(pool) => {
                if !thresholds_cover(pool, &assets, &gross) {
                    return Ok(());
                }
            }
            None => {
                if config.account().records == Address::default() {
                    return Ok(());
                }
                let own = BoundRoot::own(config.account(), client).await?;
                let members: Vec<_> = assets
                    .iter()
                    .copied()
                    .filter(|asset| *asset != [0; 32])
                    .collect();
                let pool = PoolRead {
                    root: own,
                    members: &members,
                    openings: self.widths.own,
                }
                .read(client)
                .await?;
                if !thresholds_cover(&pool, &assets, &gross) {
                    return Ok(());
                }
                self.public_asset_entries = assets
                    .iter()
                    .map(|asset| {
                        members
                            .iter()
                            .position(|member| member == asset)
                            .map_or(0, |index| index as u32)
                    })
                    .collect();
                self.own = Some(own);
                self.own_pool = Some(pool);
            }
        }
        self.exempt = true;
        Ok(())
    }

    pub fn params(&self, proving: &PolicyProving<'_>) -> Result<PolicyParams<'_>, RingError> {
        let capacity = usize::from(
            self.circuit
                .withdrawals()
                .ok_or(RingError::UncataloguedCircuit(self.circuit))?,
        );
        let outputs = self.ct_hashes.len();
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
            public_assets: proving.public_assets.to_vec(),
            public_amounts: proving.public_amounts.to_vec(),
            public_gross: proving.public_gross.to_vec(),
            table: PolicyTable {
                rules: &self.rules,
                sources: &self.sources,
            },
            ct_hashes: self.ct_hashes.clone(),
            recipients: &self.recipients,
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
