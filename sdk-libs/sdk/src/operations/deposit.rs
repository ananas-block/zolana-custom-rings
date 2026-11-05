//! One SPP deposit of one to eight ring notes under one proof of the narrowest deposit key holding them.
//!
//! The proof binds the SPP data, each owner's tracking row and any screened record. Every note of a batch
//! settles in the one SPP deposit or none does. A key's slots bound the notes and its pools bound the
//! records, every distinct recipient, asset and salted key takes one.
//!
//! Read after `program-libs/interface/src/instructions/deposit.rs`. Read before
//! `programs/custom-ring/src/instructions/settlement/deposit_audit.rs`, `prover/circuits/deposit.go`.

use std::sync::atomic::{AtomicBool, Ordering};

use custom_ring_interface::{
    cosign::CoSignDemand, domain::deposit_blinding, key_catalog::RingCircuit, ring_deposit_assets,
    tag, AuditRecord, CustomRingError, CustomRingProof, DepositContext, DepositPrefix,
    DepositPublicInput, DepositRegistry, DepositSubjects, DepositedAsset, InstructionTag,
    OpeningRecord, RecordKind, RingDepositAuditCapsule, RingMode,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{AsyncRpc, ClientError};
use spr_hasher::primitives::{pack_be, right_align};
use spr_indexer_api::SerializablePubkey;
use spr_interface::{
    instruction::instruction_data::deposit::RingDepositIxDataRef, pda, state::SplAssetRegistry,
    N_PUBLIC_SLOTS, PROGRAM_ID_PUBKEY,
};
use spr_keypair::{
    random_blinding, viewing_key::ViewTag, ShieldedAddress, X25519Keypair, X25519Pubkey,
};
use spr_program::instruction::{DepositAsset, RingAssetDeposit};
use spr_transaction::{owner_utxo_hash, Data, Mint, Utxo, SOL_ASSET_ID, SOL_MINT};
use zeroize::Zeroizing;
use zolana_ring_client::{
    records::RecordPoolRead,
    rpc::{
        PrepareRelayRequest, ProofInputBytes, RelayDepositInputs, RelayIntent, RelayQuote,
        SubjectListSalt,
    },
    seal_deposits, AdvancedTag, AsyncRingIndexer, DepositEncryption, ViewingHistory,
};
use zolana_ring_keys::RingAddress;
use zolana_ring_policy::{EncodedRuleTable, SourceMap};
use zolana_ring_transaction::RingDepositPlaintext;

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    co_signer::CoSignerChoice,
    pipeline::{
        pool_at_width, HiddenOwner, KnownSalts, OwnerQuery, PoolSubjects, RecordPlan, RingSender,
        SourceGates,
    },
    projection::retry_projection_lag,
    prover::{to_instruction_proof, RingRequest},
    records::{
        OutputKey, PoolRead, RecipientViewingKeys, SealedOutput, TrackingPoolRead, TrackingRead,
    },
    relay_message::{ExpectedDeposit, ExpectedMessage},
    request::{
        self, DepositRequest, MintChunks, OwnerEntry, PolicyParams, PolicyTable, PoolEntry,
        RecordPools, TrackingParams,
    },
    submission::{check_transaction_size, send_budget, BoundPolicy, BoundRoot},
    CustomRing, CustomRingConfig, PinnedPolicy, PreparedRelay, RingError, RingSubmission,
    SettledSubmission,
};

#[cfg(test)]
#[path = "../tests/operations/deposit.rs"]
mod tests;

#[derive(Clone, Copy)]
pub enum DepositRecipient<'a> {
    /// The member finds the note under its viewing key's tag.
    Confidential(ShieldedAddress),
    /// The depositor's own hidden identity on an anonymous ring, under its next sender tag.
    Anonymous {
        keys: &'a dyn RingSender,
        history: &'a ViewingHistory,
    },
    /// Another member of an anonymous ring, under its request's tag.
    AnonymousPayment {
        to: &'a RingAddress,
        deposit_tag: Option<ViewTag>,
    },
}

struct TaggedRecipient {
    address: ShieldedAddress,
    view_tag: [u8; 32],
    history: Option<ViewingHistory>,
    list_salt: Option<[u8; 32]>,
}

impl DepositRecipient<'_> {
    /// An own note takes the next tag of `advanced`, the history the previous own note of the batch left.
    fn tagged(
        &self,
        ring: CustomRing,
        advanced: Option<&ViewingHistory>,
    ) -> Result<TaggedRecipient, RingError> {
        Ok(match *self {
            Self::Confidential(address) => TaggedRecipient {
                address,
                view_tag: address.viewing_pubkey.u(),
                history: None,
                list_salt: None,
            },
            Self::Anonymous { keys, history } => {
                let AdvancedTag { tag, history } = advanced.unwrap_or(history).sender_tag(keys)?;
                TaggedRecipient {
                    address: keys.address()?,
                    view_tag: tag,
                    history: Some(history),
                    list_salt: None,
                }
            }
            Self::AnonymousPayment { to, deposit_tag } => {
                if to.ring_program_id != ring.program_id() {
                    return Err(RingError::ForeignRingAddress {
                        address: to.ring_program_id,
                        ring: ring.program_id(),
                    });
                }
                TaggedRecipient {
                    address: to.recipient,
                    // The viewing key as a tag would link every deposit to one recipient.
                    view_tag: deposit_tag.ok_or(RingError::DepositBootstrapTag)?,
                    history: None,
                    list_salt: Some(to.list_salt),
                }
            }
        })
    }
}

#[derive(Clone, Copy)]
pub struct DepositOutput<'a> {
    pub recipient: DepositRecipient<'a>,
    pub asset: DepositAsset,
    pub amount: u64,
    /// A salted list refuses an enrolled recipient with none.
    pub list_salt: Option<[u8; 32]>,
}

#[must_use]
pub struct RingDeposit<'a> {
    pub ring: CustomRing,
    /// Lamport source for Sol, the user token's authority for Spl.
    pub payer: &'a (dyn Signer + Sync),
    pub recipient: DepositRecipient<'a>,
    pub tree: Address,
    pub asset: DepositAsset,
    pub amount: u64,
    /// Signs when a record covers deposits, the record must be its own.
    pub cosigner: Option<&'a (dyn Signer + Sync)>,
    /// A salted list refuses an enrolled recipient with none.
    pub list_salt: Option<[u8; 32]>,
}

#[must_use]
pub struct RingDepositBatch<'a> {
    pub ring: CustomRing,
    /// Lamport source for Sol, the user token's authority for Spl.
    pub payer: &'a (dyn Signer + Sync),
    pub tree: Address,
    /// In slot order, an own note past the first takes the next sender tag and ignores its own history.
    pub outputs: Vec<DepositOutput<'a>>,
    /// Signs when a record covers deposits, the record must be its own.
    pub cosigner: Option<&'a (dyn Signer + Sync)>,
}

pub struct RingDepositReceipt {
    pub signature: Signature,
    pub utxo: Utxo,
}

pub struct RingDepositBatchReceipt {
    pub signature: Signature,
    /// In slot order.
    pub utxos: Vec<Utxo>,
}

/// One deposit frame proves once, a deposit has no nullifier and a resent note would stay unspendable.
#[must_use]
pub struct PreparedRingDeposit {
    ring: CustomRing,
    spp: Instruction,
    depositor: Address,
    cosigner: Option<Address>,
    utxos: Vec<Utxo>,
    disclosure: DepositDisclosure,
    viewing_history: Option<ViewingHistory>,
    priority_fee: Option<u64>,
    proved: AtomicBool,
    /// `None` on a relayed deposit, only its depositor draws a new secret.
    reseal: Option<DepositReseal>,
}

/// What a retry keeps, everything else of each note is drawn again.
#[derive(Clone)]
struct DepositReseal {
    terms: Vec<NoteTerms>,
    tree: Address,
    auditor: X25519Pubkey,
}

#[derive(Clone, Copy)]
struct NoteTerms {
    address: ShieldedAddress,
    owner: DisclosedOwner,
    list_salt: [u8; 32],
    view_tag: [u8; 32],
    asset: DepositAsset,
    amount: u64,
}

pub(crate) struct BoundDeposit {
    pub instruction: Instruction,
    /// The tracking root, a policy ring's own and curator roots beside it.
    pub roots: Vec<BoundRoot>,
    pub policy: Option<BoundPolicy>,
}

/// The proof binds the key's Solana owner identity into the owner hash.
#[derive(Clone, Copy)]
enum DisclosedOwner {
    Confidential([u8; 32]),
    /// No public signer may name it.
    Anonymous([u8; 32]),
}

struct DepositDisclosure {
    context_hash: [u8; 32],
    /// One stream for the batch, the program refuses a capsule under another ephemeral key.
    encryption: DepositEncryption,
    auditor: X25519Pubkey,
    /// In slot order.
    slots: Vec<SlotDisclosure>,
}

struct SlotDisclosure {
    owner: DisclosedOwner,
    owner_utxo_hash: [u8; 32],
    owner_pk_hash: [u8; 32],
    nullifier_pk: [u8; 32],
    viewing_u: [u8; 32],
    /// Zero when unknown.
    list_salt: [u8; 32],
    blinding_secret: Zeroizing<[u8; 32]>,
    mint: [u8; 32],
    asset: DepositedAsset,
}

/// Every per slot column already padded to the key's slots.
struct DepositRecords {
    ring_id: [u8; 32],
    tracking: BoundRoot,
    tracking_pool: TrackingPoolRead,
    key_capacity: u8,
    output_entries: Vec<u32>,
    owner_entries: Vec<OwnerEntry>,
    asset_entries: Vec<PoolEntry>,
    rules: EncodedRuleTable,
    sources: SourceMap,
    policy: Option<DepositScreen>,
}

struct DepositScreen {
    root: BoundRoot,
    pool: RecordPoolRead,
    policy_hash: [u8; 32],
    /// `None` without a curator source.
    curator: Option<CuratorScreen>,
}

struct CuratorScreen {
    root: BoundRoot,
    pool: RecordPoolRead,
}

impl<'a> RingDeposit<'a> {
    fn batch(&self) -> RingDepositBatch<'a> {
        RingDepositBatch {
            ring: self.ring,
            payer: self.payer,
            tree: self.tree,
            outputs: vec![DepositOutput {
                recipient: self.recipient,
                asset: self.asset,
                amount: self.amount,
                list_salt: self.list_salt,
            }],
            cosigner: self.cosigner,
        }
    }

    /// The depositor's viewing history past the deposit's tag, stored before it is sent.
    pub fn viewing_history(&self) -> Result<Option<ViewingHistory>, RingError> {
        self.batch().viewing_history()
    }

    /// Fixes the note of one attempt, [`RingSubmission`] draws a new one for each retry.
    pub async fn prepare(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        self.batch().prepare(rpc).await
    }

    /// The depositor signs the message Ring RPC answers with, the relay carries one note.
    pub async fn prepare_relay(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        let SealedDeposit {
            notes: SealedNotes { notes, encryption },
            ..
        } = self.batch().seal(rpc).await?;
        let [note] = &notes[..] else {
            return Err(CustomRingError::InvalidDepositData.into());
        };
        let depositor = self.payer.pubkey();
        let fee_payer = quote.fee_payer.0;
        note.owner.check_signers([depositor, fee_payer])?;
        let expected = ExpectedDeposit {
            ring: self.ring,
            fee_payer,
            depositor,
            spp: spr_program::instruction::RingDeposit {
                tree: self.tree,
                depositor,
                ring_program_id: self.ring.program_id(),
                deposits: vec![note.deposit.clone()],
            }
            .instruction()?,
        };
        let proof_inputs = RelayDepositInputs {
            ring_program_id: self.ring.program_id(),
            tree: self.tree,
            depositor,
            recipient: note.address,
            list_salt: note.list_salt,
            asset: note.deposit.asset,
            amount: note.deposit.amount,
            view_tag: note.deposit.view_tag,
            encrypted: note.deposit.encrypted.clone(),
            blinding_secret: note.blinding_secret.clone(),
            audit_ephemeral_key: encryption.ephemeral_sk.clone(),
        }
        .encode()?;
        let proof_inputs = ProofInputBytes::new(proof_inputs);
        let depositor_signature = self
            .payer
            .try_sign_message(&proof_inputs.deposit_request_digest())?
            .into();
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: SerializablePubkey(self.ring.program_id()),
            quote,
            intent: RelayIntent::Deposit {
                proof_inputs,
                depositor_signature,
            },
            co_signers: Vec::new(),
        })
        .expecting(ExpectedMessage::Deposit(expected)))
    }

    pub async fn send<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<RingDepositReceipt, RingError> {
        self.send_with_fee_payer(client, self.payer).await
    }

    /// Sponsors transaction fees while the deposit source still authorizes its funds.
    pub async fn send_with_fee_payer<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        fee_payer: &(dyn Signer + Sync),
    ) -> Result<RingDepositReceipt, RingError> {
        let RingDepositBatchReceipt { signature, utxos } =
            self.batch().send_with_fee_payer(client, fee_payer).await?;
        let [utxo] = <[Utxo; 1]>::try_from(utxos)
            .map_err(|_| RingError::Program(CustomRingError::InvalidDepositData))?;
        Ok(RingDepositReceipt { signature, utxo })
    }
}

impl<'a> RingDepositBatch<'a> {
    /// The depositor's viewing history past the batch's last own tag, stored before it is sent.
    pub fn viewing_history(&self) -> Result<Option<ViewingHistory>, RingError> {
        Ok(self.tagged()?.history)
    }

    /// Fixes the notes of one attempt, [`RingSubmission`] draws new ones for each retry.
    pub async fn prepare(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        let SealedDeposit {
            config,
            notes,
            viewing_history,
        } = self.seal(rpc).await?;
        DepositAssembly {
            ring: self.ring,
            config: &config,
            tree: self.tree,
            depositor: self.payer.pubkey(),
            public_signers: core::iter::once(self.payer.pubkey())
                .chain(self.cosigner.map(|signer| signer.pubkey()))
                .collect(),
            co_signer: self.cosigner.map(|signer| signer.pubkey()),
            notes,
            viewing_history,
            reseal: true,
        }
        .assemble(rpc)
        .await
    }

    pub async fn send<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<RingDepositBatchReceipt, RingError> {
        self.send_with_fee_payer(client, self.payer).await
    }

    /// Sponsors transaction fees while the deposit source still authorizes its funds.
    pub async fn send_with_fee_payer<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        fee_payer: &(dyn Signer + Sync),
    ) -> Result<RingDepositBatchReceipt, RingError> {
        let prepared = self.prepare(client.zolana()).await?;
        let signers = self.signers(&prepared);
        let mut submission = RingSubmission::new(prepared);
        match submission
            .send_until_settled(client, fee_payer, &signers)
            .await?
        {
            SettledSubmission::Confirmed { signature, .. } => Ok(RingDepositBatchReceipt {
                signature,
                utxos: submission
                    .deposit_utxos()
                    .ok_or(RingError::DepositFrameReused)?
                    .to_vec(),
            }),
            SettledSubmission::Failed { signature, error } => {
                Err(RingError::Rejected { signature, error })
            }
        }
    }

    /// A co-signer the ring does not demand is no account of the deposit and cannot sign it.
    pub(crate) fn signers(&self, prepared: &PreparedRingDeposit) -> Vec<&'a (dyn Signer + Sync)> {
        core::iter::once(self.payer)
            .chain(self.cosigner.filter(|_| prepared.cosigner.is_some()))
            .collect()
    }

    /// Each own note advances the history the previous one left, two notes under one tag would collide.
    fn tagged(&self) -> Result<TaggedOutputs, RingError> {
        let mut history = None;
        let mut recipients = Vec::with_capacity(self.outputs.len());
        for output in &self.outputs {
            let tagged = output.recipient.tagged(self.ring, history.as_ref())?;
            if tagged.history.is_some() {
                history.clone_from(&tagged.history);
            }
            recipients.push(tagged);
        }
        Ok(TaggedOutputs {
            recipients,
            history,
        })
    }

    async fn seal(&self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<SealedDeposit, RingError> {
        // 1. No key holds more slots than the widest one, refused before a secret is drawn or an account read.
        u8::try_from(self.outputs.len())
            .ok()
            .and_then(|slots| {
                DepositSubjects {
                    slots,
                    recipients: 0,
                    assets: 0,
                    salted_keys: 0,
                }
                .key_capacity()
            })
            .ok_or(RingError::DepositUnkeyed)?;
        // 2. The ring's mode decides every note's tag, a viewing key tag on an anonymous ring links its deposits to one recipient.
        let config = self.ring.require_config(rpc).await?;
        self.ring.require_active(rpc).await?;
        let anonymous = config.mode == RingMode::Anonymous;
        if self.outputs.iter().any(|output| {
            anonymous == matches!(output.recipient, DepositRecipient::Confidential(_))
        }) {
            return Err(match anonymous {
                true => RingError::AnonymousDepositUntagged,
                false => RingError::NotAnonymousRing,
            });
        }
        // 3. Every note is sealed together, the auditor opens the batch from one stream.
        let TaggedOutputs {
            recipients,
            history,
        } = self.tagged()?;
        let terms = self
            .outputs
            .iter()
            .zip(recipients)
            .map(|(output, tagged)| {
                Ok(NoteTerms {
                    owner: disclosed_owner(config.mode, &tagged.address)?,
                    list_salt: tagged.list_salt.or(output.list_salt).unwrap_or_default(),
                    address: tagged.address,
                    view_tag: tagged.view_tag,
                    asset: output.asset,
                    amount: output.amount,
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let notes = seal_notes(&terms, &config.auditor_pubkey)?;
        Ok(SealedDeposit {
            config,
            notes,
            viewing_history: history,
        })
    }
}

struct TaggedOutputs {
    recipients: Vec<TaggedRecipient>,
    /// Past the last own note's tag.
    history: Option<ViewingHistory>,
}

impl NoteTerms {
    /// Draws the blinding secret, the note and its recipient ciphertext.
    fn draw(self) -> Result<SealedNote, RingError> {
        let blinding_secret = Zeroizing::new(random_blinding());
        let blinding = deposit_blinding(&blinding_secret)?;
        let owner_hash = self.address.owner_hash()?;
        Ok(SealedNote {
            address: self.address,
            owner: self.owner,
            list_salt: self.list_salt,
            blinding_secret,
            blinding,
            deposit: RingAssetDeposit {
                asset: self.asset,
                view_tag: self.view_tag,
                owner_utxo_hash: owner_utxo_hash(&owner_hash, &blinding)?,
                amount: self.amount,
                ring_data_hash: [0; 32],
                encrypted: RingDepositPlaintext {
                    blinding,
                    utxo_data: None,
                    memo: None,
                    ring_data: Vec::new(),
                }
                .encrypt(&self.address.viewing_pubkey)?,
            },
        })
    }
}

/// Draws each note, then seals every opening record in one auditor stream.
fn seal_notes(terms: &[NoteTerms], auditor: &X25519Pubkey) -> Result<SealedNotes, RingError> {
    let mut notes = terms
        .iter()
        .map(|terms| terms.draw())
        .collect::<Result<Vec<_>, RingError>>()?;
    let openings: Vec<_> = notes.iter().map(SealedNote::opening).collect();
    let encryption = seal_deposits(&openings, auditor)?;
    // The program refuses a capsule at another index than its note's slot.
    for ((slot, note), ciphertext) in notes.iter_mut().enumerate().zip(&encryption.ciphertexts) {
        note.deposit.encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: u8::try_from(slot).map_err(|_| RingError::DepositUnkeyed)?,
            eph_pk: encryption.ephemeral_pk.as_bytes(),
            ciphertext,
            recipient_ciphertext: &note.deposit.encrypted.ciphertext,
        }
        .encode();
    }
    Ok(SealedNotes { notes, encryption })
}

impl PreparedRingDeposit {
    /// The same deposit under new blinding secrets, nothing here reads a chain value.
    pub fn fresh_attempt(&self) -> Result<Self, RingError> {
        let reseal = self.reseal.as_ref().ok_or(RingError::DepositFrameReused)?;
        let notes = seal_notes(&reseal.terms, &reseal.auditor)?;
        let utxos = self
            .utxos
            .iter()
            .zip(&notes.notes)
            .map(|(utxo, note)| Utxo {
                blinding: note.blinding,
                ..utxo.clone()
            })
            .collect();
        let DisclosedDeposit { spp, disclosure } = SealedBatch {
            ring: self.ring,
            tree: reseal.tree,
            depositor: self.depositor,
            auditor: reseal.auditor,
            notes,
        }
        .disclose()?;
        Ok(Self {
            ring: self.ring,
            depositor: self.depositor,
            cosigner: self.cosigner,
            utxos,
            disclosure,
            spp,
            viewing_history: self.viewing_history.clone(),
            priority_fee: self.priority_fee,
            proved: AtomicBool::new(false),
            reseal: Some(reseal.clone()),
        })
    }

    /// Lamports the v1 header carries, the size check measures the header it adds.
    pub fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.priority_fee = Some(lamports);
        self
    }

    pub(crate) fn check_public_signers(
        &self,
        signers: impl IntoIterator<Item = Address>,
    ) -> Result<(), RingError> {
        let signers: Vec<Address> = signers.into_iter().collect();
        self.disclosure
            .slots
            .iter()
            .try_for_each(|slot| slot.owner.check_signers(signers.iter().copied()))
    }

    /// In slot order.
    pub fn utxos(&self) -> &[Utxo] {
        &self.utxos
    }

    /// Signs the funding transfer.
    pub fn depositor(&self) -> Address {
        self.depositor
    }

    /// `Some` when a record covers deposits.
    pub fn co_signer(&self) -> Option<Address> {
        self.cosigner
    }

    pub fn co_sign_demand(&self) -> CoSignDemand {
        CoSignDemand::DEPOSIT
    }

    pub fn viewing_history(&self) -> Option<&ViewingHistory> {
        self.viewing_history.as_ref()
    }

    /// A second proof of the frame is refused, a retry starts from [`Self::fresh_attempt`].
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<Instruction, RingError> {
        Ok(self.prove_bound(client).await?.instruction)
    }

    pub(crate) async fn prove_bound<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<BoundDeposit, RingError> {
        if self.proved.swap(true, Ordering::AcqRel) {
            return Err(RingError::DepositFrameReused);
        }
        let disclosure = &self.disclosure;
        retry_projection_lag(|| async {
            let records = disclosure.records(self.ring, client.zolana()).await?;
            let body = disclosure.body(&records)?;
            let roots = records.roots();
            let frame = DepositFrame {
                roots,
                key_capacity: records.key_capacity,
            };
            self.check_size(frame)?;
            let circuit = RingCircuit::Deposit {
                capacity: frame.key_capacity,
            };
            let proof = RingRequest::new(circuit, &*body)?
                .prove(client, body.public_input_hash)
                .await?;
            Ok(BoundDeposit {
                instruction: self.instruction(to_instruction_proof(proof)?, frame)?,
                roots: roots.bound().collect(),
                policy: records.policy.as_ref().map(|policy| BoundPolicy {
                    ring: self.ring,
                    hash: policy.policy_hash,
                }),
            })
        })
        .await
    }

    /// Sized as the proven instruction, the proof is of fixed width.
    fn check_size(&self, frame: DepositFrame) -> Result<(), RingError> {
        let payer = self
            .spp
            .accounts
            .first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        check_transaction_size(
            &payer.pubkey,
            &self.instruction(bytemuck::Zeroable::zeroed(), frame)?,
            send_budget(InstructionTag::Deposit, self.priority_fee),
        )
    }

    /// `[policy, registries, co-signer?]`, then SPP's deposit list.
    fn instruction(
        &self,
        proof: CustomRingProof,
        frame: DepositFrame,
    ) -> Result<Instruction, RingError> {
        let DepositFrame {
            roots,
            key_capacity,
        } = frame;
        let mut instruction = self.spp.clone();
        let prefix = DepositPrefix {
            tag: tag::DEPOSIT,
            key_capacity,
            proof,
            tracking_revision: roots.tracking.revision,
            own_revision: roots.own.map_or_else(Default::default, |own| own.revision),
            curator_revision: roots
                .curator
                .map_or_else(Default::default, |curator| curator.revision),
        };
        instruction.data = [bytemuck::bytes_of(&prefix), &instruction.data].concat();
        let mut accounts = vec![AccountMeta::new_readonly(self.ring.policy_pda(), false)];
        accounts.extend(
            roots
                .bound()
                .map(|root| AccountMeta::new_readonly(root.registry, false)),
        );
        accounts.extend(
            self.cosigner
                .into_iter()
                .flat_map(|cosigner| self.ring.co_signer_metas(cosigner)),
        );
        instruction.accounts.splice(0..0, accounts);
        Ok(instruction)
    }
}

#[derive(Clone, Copy)]
struct DepositFrame {
    roots: DepositRoots,
    key_capacity: u8,
}

#[derive(Clone, Copy)]
pub(crate) struct DepositRoots {
    pub tracking: BoundRoot,
    pub own: Option<BoundRoot>,
    pub curator: Option<BoundRoot>,
}

impl DepositRoots {
    /// The program's account order, `RingPolicy::root_registries`.
    fn bound(self) -> impl Iterator<Item = BoundRoot> {
        self.own
            .into_iter()
            .chain(self.curator)
            .chain([self.tracking])
    }
}

impl DepositRecords {
    fn roots(&self) -> DepositRoots {
        DepositRoots {
            tracking: self.tracking,
            own: self.policy.as_ref().map(|policy| policy.root),
            curator: self.curator().map(|curator| curator.root),
        }
    }

    fn curator(&self) -> Option<&CuratorScreen> {
        self.policy
            .as_ref()
            .and_then(|policy| policy.curator.as_ref())
    }
}

#[must_use]
pub struct RelayedDeposit<'a> {
    pub ring: CustomRing,
    pub inputs: &'a RelayDepositInputs,
    pub fee_payer: Address,
    /// Read only when a record covers deposits.
    pub co_signer: Option<Address>,
}

struct SealedDeposit {
    config: CustomRingConfig,
    notes: SealedNotes,
    viewing_history: Option<ViewingHistory>,
}

struct SealedNotes {
    /// In slot order.
    notes: Vec<SealedNote>,
    encryption: DepositEncryption,
}

struct SealedNote {
    address: ShieldedAddress,
    owner: DisclosedOwner,
    list_salt: [u8; 32],
    blinding_secret: Zeroizing<[u8; 32]>,
    blinding: [u8; 32],
    deposit: RingAssetDeposit,
}

impl SealedNote {
    fn opening(&self) -> OpeningRecord {
        OpeningRecord {
            record: AuditRecord {
                kind: RecordKind::Ring,
                amount: self.deposit.amount,
                owner_key: self.owner.key(),
                mint: self.deposit.asset.mint().to_bytes(),
                nullifier_pk: self.address.nullifier_pubkey,
            },
            secret: self.blinding,
        }
    }

    fn terms(&self) -> NoteTerms {
        NoteTerms {
            address: self.address,
            owner: self.owner,
            list_salt: self.list_salt,
            view_tag: self.deposit.view_tag,
            asset: self.deposit.asset,
            amount: self.deposit.amount,
        }
    }
}

#[must_use]
struct DepositAssembly<'a> {
    ring: CustomRing,
    config: &'a CustomRingConfig,
    tree: Address,
    depositor: Address,
    /// Every transaction signer, none may name an anonymous owner.
    public_signers: Vec<Address>,
    co_signer: Option<Address>,
    notes: SealedNotes,
    viewing_history: Option<ViewingHistory>,
    /// Whether the running process drew the notes' blinding secrets.
    reseal: bool,
}

#[must_use]
struct SealedBatch {
    ring: CustomRing,
    tree: Address,
    depositor: Address,
    auditor: X25519Pubkey,
    notes: SealedNotes,
}

struct DisclosedDeposit {
    spp: Instruction,
    disclosure: DepositDisclosure,
}

impl RelayedDeposit<'_> {
    /// The proof binds every ciphertext the wallet sealed.
    pub async fn prepare(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        let inputs = self.inputs;
        if inputs.ring_program_id != self.ring.program_id() {
            return Err(RingError::ForeignRing(inputs.ring_program_id));
        }
        let config = self.ring.require_config(rpc).await?;
        self.ring.require_active(rpc).await?;
        let address = inputs.recipient;
        let owner = disclosed_owner(config.mode, &address)?;
        let blinding = deposit_blinding(&inputs.blinding_secret)?;
        let capsule = RingDepositAuditCapsule::parse(&inputs.encrypted.ciphertext)
            .map_err(|_| RingError::RelayDepositCapsule)?
            .filter(|capsule| capsule.slot_index == 0)
            .ok_or(RingError::RelayDepositCapsule)?;
        let ephemeral_pk = X25519Keypair::from_bytes(&inputs.audit_ephemeral_key).pubkey();
        if ephemeral_pk.as_bytes() != capsule.eph_pk {
            return Err(RingError::RelayAuditKeyMismatch);
        }
        let encryption = DepositEncryption {
            ephemeral_sk: inputs.audit_ephemeral_key.clone(),
            ephemeral_pk,
            ciphertexts: vec![*capsule.ciphertext],
        };
        let note = SealedNote {
            address,
            owner,
            list_salt: inputs.list_salt,
            blinding_secret: inputs.blinding_secret.clone(),
            blinding,
            deposit: RingAssetDeposit {
                asset: inputs.asset,
                view_tag: inputs.view_tag,
                owner_utxo_hash: owner_utxo_hash(&address.owner_hash()?, &blinding)?,
                amount: inputs.amount,
                ring_data_hash: [0; 32],
                encrypted: inputs.encrypted.clone(),
            },
        };
        DepositAssembly {
            ring: self.ring,
            config: &config,
            tree: inputs.tree,
            depositor: inputs.depositor,
            public_signers: [self.fee_payer, inputs.depositor]
                .into_iter()
                .chain(self.co_signer)
                .collect(),
            co_signer: self.co_signer,
            notes: SealedNotes {
                notes: vec![note],
                encryption,
            },
            viewing_history: None,
            reseal: false,
        }
        .assemble(rpc)
        .await
    }
}

impl DisclosedOwner {
    fn key(self) -> [u8; 32] {
        match self {
            Self::Confidential(key) | Self::Anonymous(key) => key,
        }
    }

    fn check_signers(self, signers: impl IntoIterator<Item = Address>) -> Result<(), RingError> {
        match self {
            Self::Anonymous(key) => {
                HiddenOwner(Address::new_from_array(key)).check_signers(signers)
            }
            Self::Confidential(_) => Ok(()),
        }
    }
}

impl DepositAssembly<'_> {
    async fn assemble(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        let Self {
            ring,
            config,
            tree,
            depositor,
            public_signers,
            co_signer,
            notes,
            viewing_history,
            reseal,
        } = self;
        for note in &notes.notes {
            note.owner.check_signers(public_signers.iter().copied())?;
        }
        let reseal = reseal.then(|| DepositReseal {
            terms: notes.notes.iter().map(SealedNote::terms).collect(),
            tree,
            auditor: config.auditor_pubkey,
        });
        let mut utxos = Vec::with_capacity(notes.notes.len());
        for note in &notes.notes {
            let mint = note.deposit.asset.mint();
            utxos.push(Utxo {
                owner: note.address.signing_pubkey,
                asset: Mint::new(mint, fetch_asset_id_async(rpc, mint).await?),
                amount: note.deposit.amount,
                blinding: note.blinding,
                ring_program_id: Some(ring.program_id()),
                data: Data::default(),
            });
        }
        let DisclosedDeposit { spp, disclosure } = SealedBatch {
            ring,
            tree,
            depositor,
            auditor: config.auditor_pubkey,
            notes,
        }
        .disclose()?;
        let cosigner = CoSignerChoice {
            ring,
            config,
            demand: CoSignDemand::DEPOSIT,
            supplied: co_signer.into_iter().collect(),
        }
        .resolve(rpc)
        .await?
        .into_iter()
        .next();
        Ok(PreparedRingDeposit {
            priority_fee: None,
            ring,
            cosigner,
            utxos,
            disclosure,
            depositor,
            spp,
            viewing_history,
            proved: AtomicBool::new(false),
            reseal,
        })
    }
}

impl SealedBatch {
    /// The proof binds the ring, the tree and the exact forwarded SPP bytes.
    fn disclose(self) -> Result<DisclosedDeposit, RingError> {
        let Self {
            ring,
            tree,
            depositor,
            auditor,
            notes: SealedNotes { notes, encryption },
        } = self;
        let spp = spr_program::instruction::RingDeposit {
            tree,
            depositor,
            ring_program_id: ring.program_id(),
            deposits: notes.iter().map(|note| note.deposit.clone()).collect(),
        }
        .instruction()?;
        // The program reads each slot's asset cell from SPP's groups, the statement takes the same cells.
        let deposit_data = RingDepositIxDataRef::from_bytes(spp.data.get(1..).unwrap_or_default())
            .map_err(|_| CustomRingError::InvalidDepositData)?;
        let assets = ring_deposit_assets(&deposit_data, |index| {
            spp.accounts.get(index).map(|meta| meta.pubkey.to_bytes())
        })?;
        if assets.len() != notes.len() {
            return Err(CustomRingError::InvalidDepositData.into());
        }
        let context_hash = DepositContext {
            program_id: ring.program_id().as_array(),
            tree: tree.as_array(),
            spp_data: &spp.data,
        }
        .hash()?;
        let slots = notes
            .into_iter()
            .zip(assets)
            .map(|(note, asset)| {
                Ok(SlotDisclosure {
                    owner: note.owner,
                    owner_utxo_hash: note.deposit.owner_utxo_hash,
                    owner_pk_hash: note.address.signing_pubkey.owner_proof_input_hash()?,
                    nullifier_pk: note.address.nullifier_pubkey,
                    viewing_u: note.address.viewing_pubkey.u(),
                    list_salt: note.list_salt,
                    blinding_secret: note.blinding_secret,
                    mint: note.deposit.asset.mint().to_bytes(),
                    asset,
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        Ok(DisclosedDeposit {
            spp,
            disclosure: DepositDisclosure {
                context_hash,
                encryption,
                auditor,
                slots,
            },
        })
    }
}

/// A deposit proves no signature, a PDA owner spends on the public owner rail of either mode.
fn disclosed_owner(mode: RingMode, address: &ShieldedAddress) -> Result<DisclosedOwner, RingError> {
    let key = request::owner_key(&address.signing_pubkey)?;
    Ok(match mode {
        RingMode::Anonymous => DisclosedOwner::Anonymous(key),
        RingMode::Confidential => DisclosedOwner::Confidential(key),
    })
}

impl DepositDisclosure {
    async fn records(
        &self,
        ring: CustomRing,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<DepositRecords, RingError> {
        let policy = ring.require_policy(rpc).await?;
        let tracking = BoundRoot::tracking(&policy, rpc).await?;
        // 1. Each distinct recipient opens one tracking row, a slot points at its recipient's row. A note
        // sealed to a viewing key the owner's authorization no longer holds stays unread.
        let mut tracked = PoolSubjects::default();
        let mut output_entries: Vec<u32> = self
            .slots
            .iter()
            .map(|slot| tracked.index(Some(slot.owner_pk_hash)))
            .collect();
        let members = tracked.opened();
        let rows = TrackingRead {
            root: tracking,
            members,
            openings: members.len(),
        }
        .read(rpc)
        .await?;
        let pinned = match policy.written_policy_hash() {
            Some(_) => Some(PinnedPolicy::of(&policy)?),
            None => None,
        };
        let gates = pinned.as_ref().map_or_else(SourceGates::default, |pinned| {
            SourceGates::of(&pinned.sources)
        });
        let mut sealed = Vec::new();
        for (slot_index, slot) in self.slots.iter().enumerate() {
            let row = rows.record(&slot.owner_pk_hash);
            OutputKey {
                row,
                nullifier_pk: &slot.nullifier_pk,
                slot_index,
                gates,
            }
            .check()?;
            if row.is_some() {
                sealed.push(SealedOutput {
                    slot_index,
                    owner: Address::new_from_array(slot.owner.key()),
                    viewing_u: slot.viewing_u,
                });
            }
        }
        RecipientViewingKeys {
            registry: tracking.registry,
            outputs: &sealed,
        }
        .check(rpc)
        .await?;
        // 2. Every distinct recipient and asset takes a pool record and an enrolled recipient on a salted
        // list one more under its salted key, only the rows read above show who is enrolled.
        let salts = KnownSalts::new(
            self.slots
                .iter()
                .map(|slot| SubjectListSalt {
                    member: slot.owner_pk_hash,
                    list_salt: slot.list_salt,
                })
                .collect(),
        );
        let mut plan = RecordPlan::new(gates);
        let mut assets: Vec<[u8; 32]> = Vec::new();
        let mut owner_entries = Vec::with_capacity(self.slots.len());
        let mut asset_entries = Vec::with_capacity(self.slots.len());
        for (slot, &tracking_entry) in self.slots.iter().zip(&output_entries) {
            let salted = match gates.any_salted() {
                true => salts.salted_key(&slot.owner_pk_hash, rows.record(&slot.owner_pk_hash))?,
                false => None,
            };
            if !assets.contains(&slot.asset.asset) {
                assets.push(slot.asset.asset);
            }
            if pinned.is_some() {
                owner_entries.push(plan.owner(OwnerQuery {
                    member: slot.owner_pk_hash,
                    tracking: tracking_entry,
                    salted,
                }));
                asset_entries.push(plan.asset(slot.asset.asset));
            }
        }
        let key_capacity = DepositSubjects {
            slots: u8::try_from(self.slots.len()).map_err(|_| RingError::DepositUnkeyed)?,
            recipients: tracked.len(),
            assets: assets.len(),
            salted_keys: plan.salted_key_count(),
        }
        .key_capacity()
        .ok_or(RingError::DepositUnkeyed)?;
        let capacity = usize::from(key_capacity);
        let width = DepositSubjects::pool_width(key_capacity);
        output_entries.resize(capacity, 0);
        owner_entries.resize(capacity, OwnerEntry::default());
        asset_entries.resize(capacity, PoolEntry::default());
        let screen = match &pinned {
            Some(pinned) => {
                let root = BoundRoot::own(&policy, rpc).await?;
                let pool = PoolRead {
                    root,
                    members: plan.own.opened(),
                    openings: width,
                }
                .read(rpc)
                .await?;
                let curator = match BoundRoot::curator(&policy, rpc).await? {
                    Some(root) => Some(CuratorScreen {
                        root,
                        pool: PoolRead {
                            root,
                            members: plan.curator.opened(),
                            openings: width,
                        }
                        .read(rpc)
                        .await?,
                    }),
                    None => None,
                };
                Some(DepositScreen {
                    root,
                    pool,
                    policy_hash: pinned.policy_hash,
                    curator,
                })
            }
            None => None,
        };
        // 3. The circuit opens one tracking path per slot of the key, the read's canopy covers only its openings.
        let tracking_pool = match capacity == members.len() {
            true => rows,
            false => {
                TrackingRead {
                    root: tracking,
                    members,
                    openings: capacity,
                }
                .read(rpc)
                .await?
            }
        };
        Ok(DepositRecords {
            ring_id: ring.ring_id()?,
            tracking,
            tracking_pool,
            key_capacity,
            output_entries,
            owner_entries,
            asset_entries,
            rules: match screen {
                Some(_) => policy.rules,
                None => EncodedRuleTable::default(),
            },
            sources: pinned.map_or_else(SourceMap::default, |pinned| pinned.sources),
            policy: screen,
        })
    }

    fn body<'a>(&self, records: &'a DepositRecords) -> Result<Box<DepositRequest<'a>>, RingError> {
        let policy = records.policy.as_ref();
        let curator = records.curator();
        let owner_utxo_hashes: Vec<_> =
            self.slots.iter().map(|slot| slot.owner_utxo_hash).collect();
        let assets: Vec<_> = self.slots.iter().map(|slot| slot.asset).collect();
        let public_input_hash = DepositPublicInput {
            context_hash: &self.context_hash,
            key_capacity: records.key_capacity,
            owner_utxo_hashes: &owner_utxo_hashes,
            ciphertexts: &self.encryption.ciphertexts,
            assets: &assets,
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: self.encryption.ephemeral_pk.as_bytes(),
            tracking_root: &records.tracking.root,
            registry: policy.map(|policy| DepositRegistry {
                own_root: &policy.root.root,
                curator_root: curator.map(|curator| &curator.root.root),
                policy_hash: &policy.policy_hash,
            }),
        }
        .hash()?;
        let capacity = usize::from(records.key_capacity);
        let width = DepositSubjects::pool_width(records.key_capacity);
        let mut mint_chunks: Vec<_> = self
            .slots
            .iter()
            .map(|slot| MintChunks(pack_be::<32, 2>(&slot.mint)))
            .collect();
        mint_chunks.resize(capacity, MintChunks(pack_be::<32, 2>(&[0; 32])));
        Ok(Box::new(DepositRequest {
            public_input_hash,
            context_hash: self.context_hash,
            count: u32::try_from(self.slots.len()).map_err(|_| RingError::DepositUnkeyed)?,
            owner_pk_hashes: self.slotted(capacity, |slot| slot.owner_pk_hash),
            owner_keys: self.slotted(capacity, |slot| slot.owner.key()),
            nullifier_pks: self.slotted(capacity, |slot| slot.nullifier_pk),
            blinding_secrets: Zeroizing::new(self.slotted(capacity, |slot| *slot.blinding_secret)),
            eph_sk: self.encryption.ephemeral_sk.clone(),
            auditor_pk: self.auditor,
            assets: self.slotted(capacity, |slot| slot.asset.asset),
            amounts: self.slotted(capacity, |slot| {
                right_align(&slot.asset.amount.to_be_bytes())
            }),
            mint_chunks,
            tracking: TrackingParams {
                tracking_root: records.tracking.root,
                pool: records.tracking_pool.pool().clone().padded(capacity)?,
                row_entries: Vec::new(),
                output_entries: records.output_entries.clone(),
            },
            policy: PolicyParams {
                withdrawal_count: 0,
                withdrawal_hash: [0; 32],
                withdrawals: Vec::new(),
                policy_hash: policy.map_or([0; 32], |policy| policy.policy_hash),
                ring_id: records.ring_id,
                own_root: policy.map_or([0; 32], |policy| policy.root.root),
                curator_root: curator.map_or([0; 32], |curator| curator.root.root),
                public_assets: vec![[0; 32]; N_PUBLIC_SLOTS],
                public_amounts: vec![[0; 32]; N_PUBLIC_SLOTS],
                public_gross: vec![[0; 32]; N_PUBLIC_SLOTS],
                table: PolicyTable {
                    rules: &records.rules,
                    sources: &records.sources,
                },
                pools: RecordPools {
                    own: pool_at_width(policy.map(|policy| &policy.pool), width)?,
                    curator: pool_at_width(curator.map(|curator| &curator.pool), width)?,
                },
                sender_entries: Vec::new(),
                owner_entries: records.owner_entries.clone(),
                asset_entries: records.asset_entries.clone(),
                public_asset_entries: Vec::new(),
            },
        }))
    }

    /// Padding slots read zero, the capacity reserved up front so a secret column never reallocates.
    fn slotted(
        &self,
        capacity: usize,
        cell: impl Fn(&SlotDisclosure) -> [u8; 32],
    ) -> Vec<[u8; 32]> {
        let mut column = Vec::with_capacity(capacity);
        column.extend(self.slots.iter().map(cell));
        column.resize(capacity, [0; 32]);
        column
    }
}

/// The asset id SPP keys `asset` by, SOL without a read, an SPL mint from its registry account.
pub async fn fetch_asset_id_async<R: AsyncRpc + ?Sized>(
    rpc: &R,
    asset: Address,
) -> Result<u64, ClientError> {
    if asset == SOL_MINT {
        return Ok(SOL_ASSET_ID);
    }
    let not_registered = || ClientError::SplAssetNotRegistered { mint: asset };
    let account = rpc
        .get_account(pda::spl_asset_registry(&asset))
        .await?
        .ok_or_else(not_registered)?;
    // Any other owner means lamports were sent there, not that the mint was registered.
    if account.owner != PROGRAM_ID_PUBKEY {
        return Err(not_registered());
    }
    let invalid = || ClientError::InvalidSplAssetRegistry { mint: asset };
    let registry = SplAssetRegistry::from_account_bytes(&account.data).map_err(|_| invalid())?;
    if registry.mint != asset {
        return Err(invalid());
    }
    Ok(registry.asset_id)
}
