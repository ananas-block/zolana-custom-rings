//! Member list writes and governed transfers shared by the policy suites, and
//! the tables they pin.

use anyhow::{anyhow, Result};
use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use custom_ring_cli::{wait_for, Probe, Zolana};
use custom_ring_interface::{
    mint_policy_write,
    storage::Revision,
    storage_instruction::{AddressWriteData, StorageUpdateIxData, StorageWriteData, UpdateMode},
    AuthorizedAddress, QueueEntry, RecordWriteData, RingPolicy, WriteRecordsIxData,
};
use custom_ring_sdk::{
    address_enrollment, CustomRing, CustomRingTransfer, CustomRingTransferInput, DepositAsset,
    DepositRecipient, EnrollAddress, InitializeStorage, ProvenRingTransfer, RingDeposit,
    RingDepositReceipt, RingError, StorageApplyProof, UpdateStorage,
};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{prover::indexed::ProofDataSource, AsyncProverClient};
use spr_keypair::{ShieldedKeypair, X25519Keypair};
use spr_test_utils::test_validator_asserts::wait_for_merkle_proof;
use spr_transaction::{instructions::transact::ConfidentialTransaction, Utxo};
use zolana_ring_client::{records::storage_apply_proof_inputs, RingIndexer, ViewingHistory};
use zolana_ring_indexer::rpc::{GetStorageApplyProofInputsRequest, StorageWriteView};
use zolana_ring_policy::{
    ListChange, ListId, ListSet, Member, MintPolicy, Rule, RuleTable, Subject,
};

use crate::shared::{
    custom_ring_program_id, send, setup_with_extra_rings, RegisterRing, SendAs, TestEnv, Tier,
};

pub const DEPOSIT: u64 = 1_000_000_000;
pub const TRANSFER_AMOUNT: u64 = 250_000_000;

pub const EMPTY: RuleTable = RuleTable::empty();

pub const RELEASED: RuleTable = RuleTable::builder()
    .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
    .rule(Rule::require(Subject::Sender, ListId::Allow))
    .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
    .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
    .build();

pub const BLOCK_ONLY: RuleTable = RuleTable::builder()
    .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
    .build();

pub const LIMIT_CAP: u64 = 650_000_000;
pub const LIMIT_COSIGN_ABOVE: u64 = 300_000_000;

/// Approval or no Block admits an output owner.
pub const APPROVAL_OR_UNBLOCKED: RuleTable = RuleTable::builder()
    .rule(Rule::any_of(
        Subject::OutputOwner,
        ListSet::single(ListId::Approval),
        ListSet::single(ListId::Block),
    ))
    .build();

pub fn owner_member(owner: &ShieldedKeypair) -> Result<Member> {
    Ok(Member::owner_tag(
        &owner.signing_pubkey().confidential_view_tag()?,
    )?)
}

pub fn policy_registry(ring: CustomRing, env: &TestEnv) -> Result<Box<RingPolicy>> {
    Ok(env.run(ring.require_policy(env.client.as_async()))?)
}

pub struct CuratedRings {
    pub env: TestEnv,
    pub curator: CustomRing,
    pub subscriber: CustomRing,
}

impl CuratedRings {
    /// The curator pins and registers under the payer, the subscriber stays unconfigured.
    pub fn setup() -> Result<Self> {
        let curator_program = Keypair::new().pubkey();
        let env = setup_with_extra_rings(&[curator_program])?;
        let curator = CustomRing::new(curator_program);
        RegisterRing {
            ring: curator,
            payer: &env.payer,
            auditor_pubkey: X25519Keypair::new().pubkey(),
            tier: Tier::policy(&BLOCK_ONLY),
        }
        .send(&env.client)?;
        Ok(Self {
            env,
            curator,
            subscriber: CustomRing::new(custom_ring_program_id()?),
        })
    }
}

/// Ring SOL notes of `owner`, each provable through the indexer on return.
pub struct RingNotes<'a> {
    pub ring: CustomRing,
    pub owner: &'a ShieldedKeypair,
    pub amount: u64,
    pub asset: DepositAsset,
    pub count: usize,
    pub env: &'a TestEnv,
}

impl RingNotes<'_> {
    pub fn deposit(self) -> Result<Vec<Utxo>> {
        let payer = self.owner;
        self.deposit_from(payer)
    }

    /// A separate depositor keeps an anonymous owner out of public signatures.
    pub fn deposit_from(self, payer: &(dyn Signer + Sync)) -> Result<Vec<Utxo>> {
        let recipient = DepositRecipient::Confidential(self.owner.shielded_address()?);
        self.deposit_to(recipient, payer)
    }

    /// Notes of the owner's hidden identity on an anonymous ring, each under the next sender tag.
    pub fn deposit_hidden_from(self, payer: &(dyn Signer + Sync)) -> Result<Vec<Utxo>> {
        let owner = self.owner;
        let mut history = ViewingHistory::new(owner.viewing_pubkey(), 0);
        let mut utxos = Vec::with_capacity(self.count);
        for _ in 0..self.count {
            let recipient = DepositRecipient::Anonymous {
                keys: owner,
                history: &history,
            };
            let deposit = self.deposit_with(recipient, payer);
            let next = deposit
                .viewing_history()?
                .ok_or_else(|| anyhow!("an anonymous deposit advances its history"))?;
            utxos.push(self.land(&deposit)?);
            history = next;
        }
        Ok(utxos)
    }

    fn deposit_to(
        self,
        recipient: DepositRecipient<'_>,
        payer: &(dyn Signer + Sync),
    ) -> Result<Vec<Utxo>> {
        (0..self.count)
            .map(|_| self.land(&self.deposit_with(recipient, payer)))
            .collect()
    }

    fn deposit_with<'d>(
        &self,
        recipient: DepositRecipient<'d>,
        payer: &'d (dyn Signer + Sync),
    ) -> RingDeposit<'d> {
        RingDeposit {
            ring: self.ring,
            payer,
            recipient,
            tree: self.env.tree,
            asset: self.asset,
            amount: self.amount,
            cosigner: None,
        }
    }

    fn land(&self, deposit: &RingDeposit<'_>) -> Result<Utxo> {
        let env = self.env;
        let RingDepositReceipt { utxo, .. } = env.run(deposit.send(env.client.ring_client()))?;
        let tree_id = env.tree_id(env.tree)?;
        let leaf = utxo.hash(
            &self.owner.nullifier_key.pubkey()?,
            &[0; 32],
            &[0; 32],
            tree_id,
        )?;
        wait_for_merkle_proof(env.client.indexer(), env.tree, leaf);
        Ok(utxo)
    }
}

/// One 1-in 2-out ring transfer of `amount` to the recipient.
pub struct PolicyTransfer<'a> {
    pub ring: CustomRing,
    pub sender: &'a ShieldedKeypair,
    pub recipient: &'a ShieldedKeypair,
    pub note: Utxo,
    pub amount: u64,
    pub env: &'a TestEnv,
}

impl PolicyTransfer<'_> {
    pub fn prove(self, client: &Zolana) -> Result<ProvenRingTransfer, RingError> {
        let tree_id = self
            .env
            .run(custom_ring_sdk::tree_id(client.as_async(), self.env.tree))?;
        let hash = self.note.hash(
            &self.sender.nullifier_key.pubkey()?,
            &[0; 32],
            &[0; 32],
            tree_id,
        )?;
        let state = wait_for_merkle_proof(self.env.client.indexer(), self.env.tree, hash);
        let note = spr_test_utils::utxo::wallet(
            self.note,
            &self.sender.nullifier_key,
            tree_id,
            state.leaf_index,
            None,
            None,
        )
        .map_err(|error| spr_client::ClientError::Rpc(error.to_string()))?;
        let mut transfer = ConfidentialTransaction::new_with_ring(
            vec![note],
            self.sender.pubkey(),
            self.ring.program_id(),
        )?
        .with_output_tree_id(tree_id)?;
        transfer.transfer_sol(&self.recipient.shielded_address()?, self.amount)?;
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction: transfer,
        });
        client.block_on(transfer.prove(client.ring_client()))
    }

    /// Refused before proving, the unreachable prover is never asked.
    pub fn expect_refusal(self) -> Result<()> {
        let unreachable = self.env.client_with(|| {
            AsyncProverClient::new("http://127.0.0.1:1".to_string())
                .with_proof_data_source(ProofDataSource::Client)
        });
        match self.prove(&unreachable) {
            Err(RingError::PolicyRuleUnsatisfied(_)) => Ok(()),
            Err(other) => Err(anyhow!("expected PolicyRuleUnsatisfied, got {other}")),
            Ok(_) => Err(anyhow!(
                "expected PolicyRuleUnsatisfied, the transfer was proven"
            )),
        }
    }

    /// Returns once photon serves the first output leaf, the next proof sees a synced index.
    pub fn land(self) -> Result<Signature> {
        let env = self.env;
        let payer = self.sender;
        let proven = self
            .prove(&env.client)
            .map_err(|error| anyhow!("transfer proof failed {error}"))?;
        let landed = proven
            .outputs
            .first()
            .ok_or_else(|| anyhow!("transfer output"))?
            .hash(env.tree_id(env.tree)?)?;
        let signature = send(env.client.rpc(), payer, &[proven.instruction()?])?;
        wait_for_merkle_proof(env.client.indexer(), env.tree, landed);
        Ok(signature)
    }
}

const INDEXING_TIMEOUT: Duration = Duration::from_secs(90);

/// Polls the indexer until `member`'s record in `ring` carries `list_id` as `present`.
pub fn wait_for_list(
    env: &TestEnv,
    ring: CustomRing,
    list_id: ListId,
    member: Member,
    present: bool,
) -> Result<()> {
    let deadline = Instant::now() + INDEXING_TIMEOUT;
    loop {
        match env.member_record(ring, member) {
            Ok(read) if read.listed(list_id) == present => return Ok(()),
            _ if Instant::now() > deadline => {
                return Err(anyhow!(
                    "{list_id:?} of {member:?} not indexed as {present}"
                ))
            }
            _ => sleep(Duration::from_millis(500)),
        }
    }
}

/// One authority list write, readable through the indexer on return.
pub struct RegistryWrite<'a> {
    pub ring: CustomRing,
    pub list_id: ListId,
    pub member: Member,
    pub present: bool,
    pub env: &'a TestEnv,
}

impl RegistryWrite<'_> {
    pub fn send(self) -> Result<()> {
        let env = self.env;
        let list = ListSet::single(self.list_id);
        let lists = match self.present {
            true => ListChange {
                set: list,
                clear: ListSet::EMPTY,
            },
            false => ListChange {
                set: ListSet::EMPTY,
                clear: list,
            },
        }
        .check()?;
        let write = StorageWriteData::Record(RecordWriteData {
            member: *self.member.as_bytes(),
            lists: WriteRecordsIxData::new(lists),
            mint_policy: mint_policy_write(None),
        });
        StorageRecords {
            ring: self.ring,
            writes: vec![write],
            env,
        }
        .send()?;
        wait_for_list(env, self.ring, self.list_id, self.member, self.present)
    }
}

/// Each owner's address, signed by the owner, applied and indexed on return, an anonymous sender or recipient needs one.
pub struct EnrollAddresses<'a> {
    pub ring: CustomRing,
    pub owners: &'a [&'a ShieldedKeypair],
    pub env: &'a TestEnv,
}

impl EnrollAddresses<'_> {
    pub fn send(self) -> Result<()> {
        let env = self.env;
        let payer = env.payer.pubkey();
        let registry = InitializeStorage::records(self.ring, payer).registry();
        let mut writes = Vec::with_capacity(self.owners.len());
        for owner in self.owners {
            let address = owner.shielded_address()?;
            let enrollment = EnrollAddress {
                payer,
                owner: owner.pubkey(),
                registry,
                nullifier_pk: address.nullifier_pubkey,
                viewing_u: address.viewing_pubkey.u(),
            };
            SendAs {
                rpc: env.client.rpc(),
                payer: &env.payer,
                holder: *owner,
            }
            .send(&[enrollment.instruction()])?;
            let enrolled = env.run(address_enrollment(
                env.client.as_async(),
                registry,
                owner.pubkey(),
            ))?;
            writes.push(StorageWriteData::Address(AddressWriteData {
                owner: owner.pubkey(),
                address_revision: enrolled.address_revision.to_le_bytes(),
            }));
        }
        StorageRecords {
            ring: self.ring,
            writes,
            env,
        }
        .send()?;
        let deadline = Instant::now() + INDEXING_TIMEOUT;
        for owner in self.owners {
            let member = owner_member(owner)?;
            while !env
                .member_record(self.ring, member)
                .is_ok_and(|read| read.address.is_some())
            {
                if Instant::now() > deadline {
                    return Err(anyhow!("the address of {member:?} not indexed"));
                }
                sleep(Duration::from_millis(500));
            }
        }
        Ok(())
    }
}

/// Needs the payer as storage authority of the ring's records.
pub struct StorageRecords<'a> {
    pub ring: CustomRing,
    pub writes: Vec<StorageWriteData>,
    pub env: &'a TestEnv,
}

impl StorageRecords<'_> {
    /// Replaces every mint setting of `member`.
    pub fn mint_policy(
        ring: CustomRing,
        member: Member,
        policy: MintPolicy,
        env: &TestEnv,
    ) -> StorageRecords<'_> {
        StorageRecords {
            ring,
            writes: vec![StorageWriteData::Record(RecordWriteData {
                member: *member.as_bytes(),
                mint_policy: mint_policy_write(Some(policy)),
                ..RecordWriteData::default()
            })],
            env,
        }
    }

    /// An address write reads its hash from the owner's authorization.
    fn entry(&self, registry: Address, write: &StorageWriteData) -> Result<QueueEntry> {
        let StorageWriteData::Address(address) = write else {
            return Ok(write.entry()?);
        };
        let enrolled = self.env.run(address_enrollment(
            self.env.client.as_async(),
            registry,
            address.owner,
        ))?;
        Ok(address.entry(&AuthorizedAddress {
            ring_id: enrolled.ring_id.0,
            nullifier_pk: enrolled.nullifier_pk.0,
            viewing_u: enrolled.viewing_u.0,
            address_revision: enrolled.address_revision,
        })?)
    }

    pub fn send(self) -> Result<Signature> {
        let env = self.env;
        let authority = env.payer.pubkey();
        let registry = InitializeStorage::records(self.ring, authority).registry();
        let writes = self
            .writes
            .iter()
            .map(|write| Ok(StorageWriteView::from(&self.entry(registry, write)?)))
            .collect::<Result<Vec<_>>>()?;
        let request = GetStorageApplyProofInputsRequest {
            registry: registry.into(),
            writes,
        };
        let response = wait_for("the storage apply proof inputs", || {
            match env
                .client
                .indexer()
                .get_storage_apply_proof_inputs(request.clone())
            {
                Ok(response) => Ok(Probe::Ready(response)),
                Err(error) => {
                    let error = RingError::from(error);
                    let pending_enrollment = self
                        .writes
                        .iter()
                        .any(|write| matches!(write, StorageWriteData::Address(_)))
                        && (error
                            .to_string()
                            .contains("an address write has no enrollment")
                            || error
                                .to_string()
                                .contains("an address write names no newest enrollment"));
                    if error.is_projection_lag() || pending_enrollment {
                        Ok(Probe::Retry(error.into()))
                    } else {
                        Err(error.into())
                    }
                }
            }
        })?;
        let inputs = storage_apply_proof_inputs(&response)?;
        let apply =
            env.run(StorageApplyProof { inputs: &inputs }.prove(env.client.ring_client()))?;
        let update = UpdateStorage {
            authority,
            registry,
            mode: UpdateMode::Graced,
            data: StorageUpdateIxData {
                revision: Revision::from(response.revision),
                writes: self.writes,
                apply: &apply,
            },
        };
        let instruction = update.clone().instruction()?;
        let mut altered_apply = apply;
        altered_apply.new_root[31] ^= 1;
        let altered = UpdateStorage {
            data: StorageUpdateIxData {
                apply: &altered_apply,
                ..update.data
            },
            ..update
        }
        .instruction()?;
        let before =
            spr_test_utils::test_validator_asserts::fetch_account(env.client.rpc(), &registry)?;
        let rejection =
            crate::shared::send_expecting_rejection(env.client.rpc(), &env.payer, altered)?;
        spr_program_test::Rejection::custom(
            custom_ring_interface::storage::StorageError::ProofVerificationFailed as u32,
        )
        .at(0)
        .assert_client(&rejection);
        spr_test_utils::test_validator_asserts::assert_account_unchanged(
            env.client.rpc(),
            &registry,
            &before,
        )?;
        let signature = send(env.client.rpc(), &env.payer, &[instruction])?;
        println!(
            "RING_APPLY_KEY writes={} mutation_refused=true settled=true",
            inputs.writes.len()
        );
        Ok(signature)
    }
}
