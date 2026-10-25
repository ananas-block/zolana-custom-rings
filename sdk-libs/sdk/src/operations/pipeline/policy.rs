//! The policy half of a ring transfer, every record read under a root the statement binds.

use std::collections::BTreeSet;

use custom_ring_interface::{
    key_catalog::RingCircuit, MemberRegistry, PolicyKey, PolicyStatement, RingAccount, RingMode,
    RingRail,
};
use solana_address::Address;
use zolana_client::AsyncRpc;
use zolana_hasher::hash_chain::create_nonzero_hash_chain_from_slice;
use zolana_interface::N_PUBLIC_SLOTS;
use zolana_ring_client::{records::MemberOpeningRead, AsyncRingIndexer};
use zolana_ring_policy::{
    EncodedRuleTable, Member, OutputSubjects, RecordLists, SourceMap, TransferSubjects,
};
use zolana_transaction::instructions::transact::SppProofInputs;

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    limits::Outflows,
    prover::{to_instruction_proof, RingRequest},
    records::{OpeningsByMember, OwnerRead, RecordReads},
    request::{
        DelegatePolicy, Entry, MemberOpening, MemberPolicy, Opening, OutputOpening, PolicyParams,
        PolicyTable,
    },
    submission::BoundRoot,
    CustomRing, CustomRingConfig, PinnedPolicy, RingError,
};

#[derive(Clone, Copy)]
struct OutputOwner {
    member: [u8; 32],
    nullifier_pk: [u8; 32],
}

pub(super) struct PolicyInputs {
    pub spl_withdrawal_owners: Vec<[u8; 32]>,
    withdrawals: Vec<custom_ring_interface::PolicyWithdrawal>,
    rules: EncodedRuleTable,
    sources: SourceMap,
    pub policy_hash: [u8; 32],
    pub own: BoundRoot,
    pub curator: Option<BoundCurator>,
    sender_entry: Entry,
    owner_entries: Vec<Entry>,
    asset_entries: Vec<Entry>,
    public_asset_entries: Vec<Option<MemberOpening>>,
    /// The escrowed key ciphertext hash of every UTXO output's owner, under key escrow.
    ct_hashes: Vec<Option<[u8; 32]>>,
    pub approval_required: bool,
    pub key_escrow: bool,
}

#[derive(Clone, Copy)]
pub(super) struct BoundCurator {
    pub address: Address,
    pub root: BoundRoot,
}

pub(super) struct PolicyRead<'a> {
    pub token_owner_hint: Option<Address>,
    pub ring: CustomRing,
    pub config: &'a CustomRingConfig,
    pub rail: RingRail,
    pub inputs: &'a SppProofInputs,
    /// The owner identity the rules read as the sender.
    pub sender: [u8; 32],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amounts: &'a [i128; N_PUBLIC_SLOTS],
}

impl PolicyRead<'_> {
    pub async fn read<R: AsyncRpc + AsyncRingIndexer + ?Sized>(
        self,
        client: &R,
    ) -> Result<PolicyInputs, RingError> {
        let registry = self.ring.require_registry(client).await?;
        let pinned = PinnedPolicy::of(&registry)?;
        let own = BoundRoot::current(self.ring, &registry);
        let curator = match pinned.curator {
            Some(address) => Some(BoundCurator::read(client, address).await?),
            None => None,
        };
        let (withdrawals, spl_withdrawal_owners) = read_withdrawals(
            client,
            &self.inputs.external_data.interface_transfers,
            self.token_owner_hint,
        )
        .await?;
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
        let members: BTreeSet<[u8; 32]> = core::iter::once(self.sender)
            .chain(owners.iter().flatten().map(|owner| owner.member))
            .chain(assets.iter().flatten().copied())
            .chain(withdrawals.iter().map(|w| w.owner))
            .chain(withdrawals.iter().map(|w| w.asset))
            .chain(
                self.public_assets
                    .iter()
                    .copied()
                    .filter(|asset| *asset != [0; 32]),
            )
            .collect();
        let members: Vec<[u8; 32]> = members.into_iter().collect();
        let own_reads = RecordReads {
            root: own,
            members: &members,
        }
        .read_keyed(client)
        .await?;
        let curator_reads = match curator {
            Some(curator) => Some(
                RecordReads {
                    root: curator.root,
                    members: &members,
                }
                .read_keyed(client)
                .await?,
            ),
            None => None,
        };
        let lists = |member: [u8; 32]| {
            let on = |reads: &OpeningsByMember| {
                reads
                    .get(&member)
                    .and_then(MemberOpeningRead::record)
                    .map_or(0, |record| record.lists)
            };
            RecordLists {
                own: on(&own_reads),
                curator: curator_reads.as_ref().map_or(0, on),
            }
        };
        let mint_policy = |asset: &[u8; 32]| {
            own_reads
                .get(asset)
                .and_then(MemberOpeningRead::record)
                .map_or(zolana_ring_policy::MintPolicy::EMPTY, |record| {
                    record.mint_policy
                })
        };
        let mut subjects = outputs
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
        subjects.extend(withdrawals.iter().map(|w| OutputSubjects {
            owner: w.owner,
            asset: w.asset,
            amount: w.amount,
            owner_lists: lists(w.owner),
            asset_lists: lists(w.asset),
            mint_policy: mint_policy(&w.asset),
        }));
        pinned.table.admit(
            &pinned.sources,
            &TransferSubjects {
                sender: lists(self.sender),
                outputs: &subjects,
            },
        )?;
        let entry = |member: Option<[u8; 32]>| -> Entry {
            let Some(member) = member else {
                return Entry::default();
            };
            let find = |reads: &OpeningsByMember| {
                reads
                    .get(&member)
                    .map(|read| MemberOpening::from(&read.opening))
            };
            Entry {
                own: find(&own_reads),
                curator: curator_reads.as_ref().and_then(find),
            }
        };
        let key_escrow = self.config.mode == RingMode::ConfidentialEscrow;
        let ct_hashes = owners
            .iter()
            .map(|owner| {
                owner
                    .filter(|_| key_escrow)
                    .map(|owner| -> Result<[u8; 32], RingError> {
                        let read = own_reads
                            .get(&owner.member)
                            .ok_or(RingError::InvalidRecordOpening)?;
                        let read = OwnerRead {
                            owner: owner.member,
                            read,
                        };
                        Ok(read.escrowed(&owner.nullifier_pk)?.ct_hash()?)
                    })
                    .transpose()
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let limit_assets: BTreeSet<_> = assets
            .iter()
            .flatten()
            .copied()
            .chain(
                self.public_assets
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
        let approval_required = match self.rail {
            RingRail::Delegate => false,
            RingRail::Confidential | RingRail::Anonymous => Outflows {
                sender: self.sender,
                ring: self.ring.program_id(),
                outputs,
                public_assets: self.public_assets,
                public_amounts: self.public_amounts,
            }
            .approval_required(&limits)?,
        };
        let mut owner_entries: Vec<_> = owners
            .iter()
            .map(|owner| entry(owner.map(|owner| owner.member)))
            .collect();
        let mut asset_entries: Vec<_> = assets.iter().map(|asset| entry(*asset)).collect();
        owner_entries.extend(withdrawals.iter().map(|w| entry(Some(w.owner))));
        asset_entries.extend(withdrawals.iter().map(|w| entry(Some(w.asset))));
        Ok(PolicyInputs {
            withdrawals,
            spl_withdrawal_owners,
            rules: registry.rules,
            sources: pinned.sources,
            policy_hash: pinned.policy_hash,
            own,
            curator,
            sender_entry: entry(Some(self.sender)),
            owner_entries,
            asset_entries,
            public_asset_entries: self
                .public_assets
                .iter()
                .map(|asset| entry((*asset != [0; 32]).then_some(*asset)).own)
                .collect(),
            ct_hashes,
            approval_required,
            key_escrow,
        })
    }
}

pub(super) struct PolicyProving<'a> {
    pub ring_id: [u8; 32],
    pub rail: RingRail,
    pub inputs: &'a SppProofInputs,
    pub n_in: u8,
    pub n_out: u8,
    pub private_tx_hash: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    /// The owner identity, the anonymous rail's sender commitment, zero on the delegate rail.
    pub sender: [u8; 32],
    pub sender_pk_hash: [u8; 32],
    pub public_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    pub public_amount_fields: [[u8; 32]; N_PUBLIC_SLOTS],
}

impl PolicyInputs {
    pub fn curator_root(&self) -> [u8; 32] {
        self.curator.map_or([0; 32], |curator| curator.root.root)
    }

    pub fn statement(&self, proving: &PolicyProving<'_>) -> Result<[u8; 32], RingError> {
        let key = proving.rail.policy_key();
        let delegate = key == PolicyKey::Delegate;
        Ok(PolicyStatement {
            withdrawal_hash: &custom_ring_interface::policy_withdrawal_hash(&self.withdrawals)?,
            key,
            private_tx_hash: &proving.private_tx_hash,
            policy_hash: &self.policy_hash,
            ring_id: &proving.ring_id,
            approval_required: self.approval_required,
            key_escrow: delegate || self.key_escrow,
            own_root: &self.own.root,
            curator_root: &self.curator_root(),
            sender: &proving.sender,
            public_assets: &proving.public_assets,
            public_amounts: &proving.public_amount_fields,
        }
        .hash()?)
    }

    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        proving: &PolicyProving<'_>,
    ) -> Result<custom_ring_interface::CustomRingProof, RingError> {
        let inputs = proving.inputs;
        let circuit = RingCircuit::policy(
            proving.rail,
            proving.n_in,
            proving.n_out,
            self.withdrawals.len() as u8,
            self.curator.is_none(),
        );
        let public_input_hash = self.statement(proving)?;
        let outputs = inputs
            .output_utxos
            .iter()
            .zip(&self.ct_hashes)
            .map(|(output, ct_hash)| {
                Ok(OutputOpening {
                    opening: Opening::output(output, inputs.output_tree_id)?,
                    ct_hash: *ct_hash,
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let address_nullifiers: Vec<[u8; 32]> = inputs
            .input_utxos
            .iter()
            .map(|input| input.private_tx_address_nullifier())
            .collect();
        let capacity = usize::from(custom_ring_interface::key_catalog::withdrawal_capacity(
            self.withdrawals.len() as u8,
        ));
        let mut withdrawals = self.withdrawals.clone();
        withdrawals.resize(capacity, custom_ring_interface::PolicyWithdrawal::default());
        let mut owner_entries = self.owner_entries.clone();
        let mut asset_entries = self.asset_entries.clone();
        owner_entries.resize(outputs.len() + capacity, Entry::default());
        asset_entries.resize(outputs.len() + capacity, Entry::default());
        let params = PolicyParams {
            withdrawal_count: self.withdrawals.len() as u8,
            withdrawal_hash: custom_ring_interface::policy_withdrawal_hash(&self.withdrawals)?,
            withdrawals: withdrawals
                .iter()
                .map(|w| crate::request::PolicyWithdrawalRequest {
                    owner: w.owner,
                    asset: w.asset,
                    amount: zolana_hasher::primitives::right_align(&w.amount.to_be_bytes()),
                })
                .collect(),
            private_tx_hash: proving.private_tx_hash,
            policy_hash: self.policy_hash,
            ring_id: proving.ring_id,
            own_root: self.own.root,
            curator_root: self.curator_root(),
            public_assets: proving.public_assets.to_vec(),
            public_amounts: proving.public_amount_fields.to_vec(),
            table: PolicyTable {
                rules: &self.rules,
                sources: &self.sources,
            },
            address_chain: create_nonzero_hash_chain_from_slice(&address_nullifiers)?,
            private_tx_blinding: proving.private_tx_blinding,
            outputs,
            sender_pk_hash: proving.sender_pk_hash,
            sender_entry: self.sender_entry.clone(),
            owner_entries,
            asset_entries,
            public_asset_entries: self.public_asset_entries.clone(),
        };
        let proof = match proving.rail {
            RingRail::Delegate => {
                let body = DelegatePolicy {
                    public_input_hash,
                    inputs: inputs
                        .input_utxos
                        .iter()
                        .map(Opening::input)
                        .collect::<Result<_, _>>()?,
                    policy: params,
                };
                RingRequest::new(circuit, &body)?
                    .prove(client, public_input_hash)
                    .await?
            }
            RingRail::Confidential | RingRail::Anonymous => {
                let input_hashes: Vec<[u8; 32]> = inputs
                    .input_utxos
                    .iter()
                    .map(|input| input.private_tx_input_hash())
                    .collect();
                let body = MemberPolicy {
                    public_input_hash,
                    anonymous: proving.rail == RingRail::Anonymous,
                    approval_required: self.approval_required,
                    key_escrow: self.key_escrow,
                    sender: proving.sender,
                    input_chain: create_nonzero_hash_chain_from_slice(&input_hashes)?,
                    policy: params,
                };
                RingRequest::new(circuit, &body)?
                    .prove(client, public_input_hash)
                    .await?
            }
        };
        to_instruction_proof(proof)
    }
}

impl BoundCurator {
    async fn read<R: AsyncRpc + ?Sized>(client: &R, address: Address) -> Result<Self, RingError> {
        let account = client
            .get_account(address)
            .await?
            .ok_or(RingError::InvalidCuratorRegistry { address })?;
        let registry = MemberRegistry::from_data(&account.data)
            .ok_or(RingError::InvalidCuratorRegistry { address })?;
        Ok(Self {
            address,
            root: BoundRoot::current(CustomRing::new(account.owner), registry),
        })
    }
}

/// Resolve token owners once; the program checks the snapshot again at execution.
async fn read_withdrawals<R: AsyncRpc + ?Sized>(
    client: &R,
    transfers: &[zolana_transaction::instructions::transact::SettlementTransfer],
    hint: Option<Address>,
) -> Result<(Vec<custom_ring_interface::PolicyWithdrawal>, Vec<[u8; 32]>), RingError> {
    use zolana_interface::{SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID};
    use zolana_transaction::instructions::transact::SettlementTransfer;
    let mut payments = Vec::new();
    let mut owners = Vec::new();
    for transfer in transfers.iter().filter(|t| !t.is_deposit()) {
        let payment = match *transfer {
            SettlementTransfer::Sol {
                user_sol_account,
                amount,
                ..
            } => custom_ring_interface::PolicyWithdrawal::new(
                user_sol_account.as_array(),
                None,
                amount,
            )?,
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
                            || zolana_interface::pda::associated_token_address_with_program(
                                &owner, &mint, &program,
                            ) != user_spl_token
                        {
                            return Err(invalid());
                        }
                        owner.to_bytes()
                    }
                };
                owners.push(owner);
                custom_ring_interface::PolicyWithdrawal::new(&owner, Some(mint.as_array()), amount)?
            }
        };
        payments.push(payment);
    }
    Ok((payments, owners))
}
