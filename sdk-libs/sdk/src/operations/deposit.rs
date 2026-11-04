//! Deposits whose proof binds the SPP data, the owner's tracking row and any screened record.

use std::sync::atomic::{AtomicBool, Ordering};

use custom_ring_interface::{
    cosign::CoSignDemand, domain::deposit_blinding, key_catalog::RingCircuit, ring_deposit_assets,
    tag, AuditRecord, CustomRingError, CustomRingProof, DepositContext, DepositPrefix,
    DepositPublicInput, DepositRegistry, DepositedAsset, InstructionTag, OpeningRecord, RecordKind,
    RingDepositAuditCapsule, RingMode, RingPolicy,
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
    PROGRAM_ID_PUBKEY,
};
use spr_keypair::{
    random_blinding, viewing_key::ViewTag, Curve, ShieldedAddress, X25519Keypair, X25519Pubkey,
};
use spr_program::instruction::{DepositAsset, RingAssetDeposit};
use spr_transaction::{owner_utxo_hash, Data, Mint, Utxo, SOL_ASSET_ID, SOL_MINT};
use zeroize::Zeroizing;
use zolana_ring_client::{
    rpc::{PrepareRelayRequest, ProofInputBytes, RelayDepositInputs, RelayIntent, RelayQuote},
    seal_deposits, AdvancedTag, AsyncRingIndexer, DepositEncryption, ViewingHistory,
};
use zolana_ring_keys::RingAddress;
use zolana_ring_member_registry::TrackingOpening;
use zolana_ring_policy::SourceMap;
use zolana_ring_transaction::RingDepositPlaintext;

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    co_signer::CoSignerChoice,
    pipeline::{HiddenOwner, RingSender},
    projection::retry_projection_lag,
    prover::{to_instruction_proof, RingRequest},
    records::{check_output_key, MemberRead, TrackingMemberRead},
    relay_message::{ExpectedDeposit, ExpectedMessage},
    request::{self, DepositRequest, MemberOpening, MintChunks, PolicyTable},
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
}

impl DepositRecipient<'_> {
    fn tagged(&self, ring: CustomRing) -> Result<TaggedRecipient, RingError> {
        Ok(match *self {
            Self::Confidential(address) => TaggedRecipient {
                address,
                view_tag: address.viewing_pubkey.u(),
                history: None,
            },
            Self::Anonymous { keys, history } => {
                let AdvancedTag { tag, history } = history.sender_tag(keys)?;
                TaggedRecipient {
                    address: keys.address()?,
                    view_tag: tag,
                    history: Some(history),
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
                }
            }
        })
    }
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
}

pub struct RingDepositReceipt {
    pub signature: Signature,
    pub utxo: Utxo,
}

/// One deposit frame proves once, a deposit has no nullifier and a resent note would stay unspendable.
#[must_use]
pub struct PreparedRingDeposit {
    ring: CustomRing,
    spp: Instruction,
    depositor: Address,
    cosigner: Option<Address>,
    utxo: Utxo,
    disclosure: DepositDisclosure,
    viewing_history: Option<ViewingHistory>,
    priority_fee: Option<u64>,
    proved: AtomicBool,
    /// `None` on a relayed deposit, only its depositor draws a new secret.
    reseal: Option<DepositReseal>,
}

/// What a retry keeps, everything else of the note is drawn again.
#[derive(Clone, Copy)]
struct DepositReseal {
    terms: NoteTerms,
    tree: Address,
    auditor: X25519Pubkey,
}

#[derive(Clone, Copy)]
struct NoteTerms {
    address: ShieldedAddress,
    owner: DisclosedOwner,
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
    owner: DisclosedOwner,
    context_hash: [u8; 32],
    owner_utxo_hash: [u8; 32],
    owner_pk_hash: [u8; 32],
    nullifier_pk: [u8; 32],
    blinding_secret: Zeroizing<[u8; 32]>,
    encryption: DepositEncryption,
    auditor: X25519Pubkey,
    /// The raw mint the record names.
    mint: [u8; 32],
    asset: DepositedAsset,
}

struct DepositRecords {
    tracking: BoundRoot,
    /// The owner's row, or its absence under a zero key.
    row: TrackingOpening,
    policy: Option<DepositScreen>,
}

struct DepositScreen {
    root: BoundRoot,
    policy: Box<RingPolicy>,
    sources: SourceMap,
    policy_hash: [u8; 32],
    asset: MemberOpening,
    owner: MemberOpening,
    /// `None` without a curator source.
    curator: Option<CuratorScreen>,
}

struct CuratorScreen {
    root: BoundRoot,
    asset: MemberOpening,
    owner: MemberOpening,
}

impl RingDeposit<'_> {
    /// The depositor's viewing history past the deposit's tag, stored before it is sent.
    pub fn viewing_history(&self) -> Result<Option<ViewingHistory>, RingError> {
        Ok(self.recipient.tagged(self.ring)?.history)
    }

    /// Fixes the note of one attempt, [`RingSubmission`] draws a new one for each retry.
    pub async fn prepare(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<PreparedRingDeposit, RingError> {
        let SealedDeposit {
            config,
            note,
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
            note,
            viewing_history,
            reseal: true,
        }
        .assemble(rpc)
        .await
    }

    /// The depositor signs the message Ring RPC answers with.
    pub async fn prepare_relay(
        &self,
        rpc: &(impl AsyncRpc + ?Sized),
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        let SealedDeposit { note, .. } = self.seal(rpc).await?;
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
            asset: note.deposit.asset,
            amount: note.deposit.amount,
            view_tag: note.deposit.view_tag,
            encrypted: note.deposit.encrypted.clone(),
            blinding_secret: note.blinding_secret.clone(),
            audit_ephemeral_key: note.encryption.ephemeral_sk.clone(),
        }
        .encode()?;
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: SerializablePubkey(self.ring.program_id()),
            quote,
            intent: RelayIntent::Deposit {
                proof_inputs: ProofInputBytes::new(proof_inputs),
            },
        })
        .expecting(ExpectedMessage::Deposit(expected)))
    }

    async fn seal(&self, rpc: &(impl AsyncRpc + ?Sized)) -> Result<SealedDeposit, RingError> {
        let config = self.ring.require_config(rpc).await?;
        self.ring.require_active(rpc).await?;
        let anonymous = config.mode == RingMode::Anonymous;
        if anonymous == matches!(self.recipient, DepositRecipient::Confidential(_)) {
            return Err(match anonymous {
                true => RingError::AnonymousDepositUntagged,
                false => RingError::NotAnonymousRing,
            });
        }
        let TaggedRecipient {
            address,
            view_tag,
            history,
        } = self.recipient.tagged(self.ring)?;
        let note = NoteTerms {
            owner: disclosed_owner(config.mode, &address)?,
            address,
            view_tag,
            asset: self.asset,
            amount: self.amount,
        }
        .seal(&config.auditor_pubkey)?;
        Ok(SealedDeposit {
            config,
            note,
            viewing_history: history,
        })
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
        let prepared = self.prepare(client.zolana()).await?;
        let signers = self.signers(&prepared);
        let mut submission = RingSubmission::new(prepared);
        match submission
            .send_until_settled(client, fee_payer, &signers)
            .await?
        {
            SettledSubmission::Confirmed { signature, .. } => Ok(RingDepositReceipt {
                signature,
                utxo: submission
                    .deposit_utxo()
                    .ok_or(RingError::DepositFrameReused)?
                    .clone(),
            }),
            SettledSubmission::Failed { signature, error } => {
                Err(RingError::Rejected { signature, error })
            }
        }
    }

    /// A co-signer the ring does not demand is no account of the deposit and cannot sign it.
    pub(crate) fn signers(&self, prepared: &PreparedRingDeposit) -> Vec<&(dyn Signer + Sync)> {
        core::iter::once(self.payer)
            .chain(self.cosigner.filter(|_| prepared.cosigner.is_some()))
            .collect()
    }
}

impl NoteTerms {
    /// Draws the blinding secret, the note and its auditor ciphertext.
    fn seal(self, auditor: &X25519Pubkey) -> Result<SealedNote, RingError> {
        let blinding_secret = Zeroizing::new(random_blinding());
        let blinding = deposit_blinding(&blinding_secret)?;
        let owner_hash = self.address.owner_hash()?;
        let mut deposit = RingAssetDeposit {
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
        };
        let encryption = seal_deposits(
            &[OpeningRecord {
                record: AuditRecord {
                    kind: RecordKind::Ring,
                    amount: self.amount,
                    owner_key: self.owner.key(),
                    mint: self.asset.mint().to_bytes(),
                    nullifier_pk: self.address.nullifier_pubkey,
                },
                secret: blinding,
            }],
            auditor,
        )?;
        deposit.encrypted.ciphertext = RingDepositAuditCapsule {
            slot_index: 0,
            eph_pk: encryption.ephemeral_pk.as_bytes(),
            ciphertext: &encryption.ciphertexts[0],
            recipient_ciphertext: &deposit.encrypted.ciphertext,
        }
        .encode();
        Ok(SealedNote {
            address: self.address,
            owner: self.owner,
            blinding_secret,
            blinding,
            deposit,
            encryption,
        })
    }
}

impl PreparedRingDeposit {
    /// The same deposit under a new blinding secret, nothing here reads a chain value.
    pub fn fresh_attempt(&self) -> Result<Self, RingError> {
        let reseal = self.reseal.ok_or(RingError::DepositFrameReused)?;
        let note = reseal.terms.seal(&reseal.auditor)?;
        let spp = spr_program::instruction::RingDeposit {
            tree: reseal.tree,
            depositor: self.depositor,
            ring_program_id: self.ring.program_id(),
            deposits: vec![note.deposit.clone()],
        }
        .instruction()?;
        Ok(Self {
            ring: self.ring,
            depositor: self.depositor,
            cosigner: self.cosigner,
            utxo: Utxo {
                blinding: note.blinding,
                ..self.utxo.clone()
            },
            disclosure: DepositDisclosure {
                context_hash: DepositContext {
                    program_id: self.ring.program_id().as_array(),
                    tree: reseal.tree.as_array(),
                    spp_data: &spp.data,
                }
                .hash()?,
                owner_utxo_hash: note.deposit.owner_utxo_hash,
                blinding_secret: note.blinding_secret,
                encryption: note.encryption,
                owner: self.disclosure.owner,
                owner_pk_hash: self.disclosure.owner_pk_hash,
                nullifier_pk: self.disclosure.nullifier_pk,
                auditor: self.disclosure.auditor,
                mint: self.disclosure.mint,
                asset: self.disclosure.asset,
            },
            spp,
            viewing_history: self.viewing_history.clone(),
            priority_fee: self.priority_fee,
            proved: AtomicBool::new(false),
            reseal: self.reseal,
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
        self.disclosure.owner.check_signers(signers)
    }

    pub fn utxo(&self) -> &Utxo {
        &self.utxo
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

    /// A second proof of this frame is refused, a retry starts from [`Self::fresh_attempt`].
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
            self.check_size(roots)?;
            let proof = RingRequest::new(RingCircuit::deposit(body.count as u8), &*body)?
                .prove(client, body.public_input_hash)
                .await?;
            Ok(BoundDeposit {
                instruction: self.instruction(to_instruction_proof(proof)?, roots)?,
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
    fn check_size(&self, roots: DepositRoots) -> Result<(), RingError> {
        let payer = self
            .spp
            .accounts
            .first()
            .ok_or(CustomRingError::InvalidInstructionData)?;
        check_transaction_size(
            &payer.pubkey,
            &self.instruction(bytemuck::Zeroable::zeroed(), roots)?,
            send_budget(InstructionTag::Deposit, self.priority_fee),
        )
    }

    /// `[config, registries?, co-signer?]`, then SPP's deposit list.
    fn instruction(
        &self,
        proof: CustomRingProof,
        roots: DepositRoots,
    ) -> Result<Instruction, RingError> {
        let mut instruction = self.spp.clone();
        let prefix = DepositPrefix {
            tag: tag::DEPOSIT,
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
struct DepositRoots {
    tracking: BoundRoot,
    own: Option<BoundRoot>,
    curator: Option<BoundRoot>,
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
    note: SealedNote,
    viewing_history: Option<ViewingHistory>,
}

struct SealedNote {
    address: ShieldedAddress,
    owner: DisclosedOwner,
    blinding_secret: Zeroizing<[u8; 32]>,
    blinding: [u8; 32],
    deposit: RingAssetDeposit,
    encryption: DepositEncryption,
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
    note: SealedNote,
    viewing_history: Option<ViewingHistory>,
    /// Whether this process drew the note's blinding secret.
    reseal: bool,
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
            encryption,
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
            note,
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

    fn is_anonymous(self) -> bool {
        matches!(self, Self::Anonymous(_))
    }
}

impl DepositAssembly<'_> {
    /// The proof binds the ring, the tree and the exact forwarded SPP bytes.
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
            note,
            viewing_history,
            reseal,
        } = self;
        note.owner.check_signers(public_signers)?;
        let reseal = reseal.then_some(DepositReseal {
            terms: NoteTerms {
                address: note.address,
                owner: note.owner,
                view_tag: note.deposit.view_tag,
                asset: note.deposit.asset,
                amount: note.deposit.amount,
            },
            tree,
            auditor: config.auditor_pubkey,
        });
        let mint = note.deposit.asset.mint();
        let mint = Mint::new(mint, fetch_asset_id_async(rpc, mint).await?);
        let spp = spr_program::instruction::RingDeposit {
            tree,
            depositor,
            ring_program_id: ring.program_id(),
            deposits: vec![note.deposit.clone()],
        }
        .instruction()?;
        let deposit_data = RingDepositIxDataRef::from_bytes(spp.data.get(1..).unwrap_or_default())
            .map_err(|_| CustomRingError::InvalidDepositData)?;
        let [asset] = ring_deposit_assets(&deposit_data, |index| {
            spp.accounts.get(index).map(|meta| meta.pubkey.to_bytes())
        })?[..] else {
            return Err(CustomRingError::InvalidDepositData.into());
        };
        let supplied: Vec<Address> = co_signer.into_iter().collect();
        let cosigner = CoSignerChoice {
            ring,
            config,
            demand: CoSignDemand::DEPOSIT,
            supplied: &supplied,
        }
        .resolve(rpc)
        .await?
        .pop();
        let address = note.address;
        Ok(PreparedRingDeposit {
            priority_fee: None,
            ring,
            cosigner,
            utxo: Utxo {
                owner: address.signing_pubkey,
                asset: mint,
                amount: note.deposit.amount,
                blinding: note.blinding,
                ring_program_id: Some(ring.program_id()),
                data: Data::default(),
            },
            disclosure: DepositDisclosure {
                owner: note.owner,
                context_hash: DepositContext {
                    program_id: ring.program_id().as_array(),
                    tree: tree.as_array(),
                    spp_data: &spp.data,
                }
                .hash()?,
                owner_utxo_hash: note.deposit.owner_utxo_hash,
                owner_pk_hash: address.signing_pubkey.owner_proof_input_hash()?,
                nullifier_pk: address.nullifier_pubkey,
                blinding_secret: note.blinding_secret,
                encryption: note.encryption,
                auditor: config.auditor_pubkey,
                mint: note.deposit.asset.mint().to_bytes(),
                asset,
            },
            depositor,
            spp,
            viewing_history,
            proved: AtomicBool::new(false),
            reseal,
        })
    }
}

/// An anonymous ring spends only through the hidden Ed25519 proof.
fn disclosed_owner(mode: RingMode, address: &ShieldedAddress) -> Result<DisclosedOwner, RingError> {
    let owner = &address.signing_pubkey;
    match mode {
        RingMode::Anonymous if owner.curve()? != Curve::Ed25519 => {
            Err(RingError::AnonymousRecipient)
        }
        RingMode::Anonymous => Ok(DisclosedOwner::Anonymous(owner.as_ed25519()?)),
        RingMode::Confidential => Ok(DisclosedOwner::Confidential(request::owner_key(owner)?)),
    }
}

impl DepositDisclosure {
    async fn records(
        &self,
        ring: CustomRing,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<DepositRecords, RingError> {
        let policy = ring.require_policy(rpc).await?;
        let tracking = BoundRoot::tracking(&policy, rpc).await?;
        let row = TrackingMemberRead {
            root: tracking,
            member: self.owner_pk_hash,
        }
        .read(rpc)
        .await?;
        let enrolled = match &row {
            TrackingOpening::Present { record, .. } => Some(record),
            TrackingOpening::Absent { .. } => None,
        };
        check_output_key(enrolled, &self.nullifier_pk, 0)?;
        let screen = match policy.written_policy_hash() {
            Some(_) => {
                let root = BoundRoot::own(&policy, rpc).await?;
                let pinned = PinnedPolicy::of(&policy)?;
                let asset = self.member_opening(rpc, root, self.asset.asset).await?;
                let owner = self.member_opening(rpc, root, self.owner_pk_hash).await?;
                let curator = match BoundRoot::curator(&policy, rpc).await? {
                    Some(root) => Some(CuratorScreen {
                        root,
                        asset: self.member_opening(rpc, root, self.asset.asset).await?,
                        owner: self.member_opening(rpc, root, self.owner_pk_hash).await?,
                    }),
                    None => None,
                };
                Some(DepositScreen {
                    root,
                    sources: pinned.sources,
                    policy_hash: pinned.policy_hash,
                    asset,
                    owner,
                    curator,
                    policy,
                })
            }
            None => None,
        };
        Ok(DepositRecords {
            tracking,
            row,
            policy: screen,
        })
    }

    async fn member_opening(
        &self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
        root: BoundRoot,
        member: [u8; 32],
    ) -> Result<MemberOpening, RingError> {
        let read = MemberRead { root, member }.read(rpc).await?;
        Ok(MemberOpening::from(&read.opening))
    }

    fn body<'a>(&self, records: &'a DepositRecords) -> Result<Box<DepositRequest<'a>>, RingError> {
        let policy = records.policy.as_ref();
        let curator = records.curator();
        let public_input_hash = DepositPublicInput {
            context_hash: &self.context_hash,
            anonymous: self.owner.is_anonymous(),
            owner_utxo_hashes: &[self.owner_utxo_hash],
            ciphertexts: &self.encryption.ciphertexts,
            assets: &[self.asset],
            auditor_pk: self.auditor.as_bytes(),
            eph_pk: self.encryption.ephemeral_pk.as_bytes(),
            tracking_root: &records.tracking.root,
            registry: policy.map(|policy| DepositRegistry {
                own_root: &policy.root.root,
                curator_root: curator.map(|curator| &curator.root.root),
                policy_hash: Some(&policy.policy_hash),
            }),
        }
        .hash()?;
        let first = |value: [u8; 32]| [value];
        Ok(Box::new(DepositRequest {
            public_input_hash,
            context_hash: self.context_hash,
            count: 1,
            anonymous: self.owner.is_anonymous(),
            owner_pk_hashes: first(self.owner_pk_hash),
            owner_keys: first(self.owner.key()),
            nullifier_pks: first(self.nullifier_pk),
            blinding_secrets: Zeroizing::new(first(*self.blinding_secret)),
            eph_sk: self.encryption.ephemeral_sk.clone(),
            auditor_pk: self.auditor,
            tracking_root: records.tracking.root,
            tracking: [Some((&records.row).into())],
            own_root: policy.map_or([0; 32], |policy| policy.root.root),
            curator_root: curator.map_or([0; 32], |curator| curator.root.root),
            policy_hash: policy.map_or([0; 32], |policy| policy.policy_hash),
            assets: first(self.asset.asset),
            amounts: first(right_align(&self.asset.amount.to_be_bytes())),
            mint_chunks: [MintChunks(pack_be::<32, 2>(&self.mint))],
            table: policy.map(|policy| PolicyTable {
                rules: &policy.policy.rules,
                sources: &policy.sources,
            }),
            asset_records: [policy.map(|policy| policy.asset.clone())],
            owner_records: [policy.map(|policy| policy.owner.clone())],
            curator_asset_records: [curator.map(|curator| curator.asset.clone())],
            curator_owner_records: [curator.map(|curator| curator.owner.clone())],
        }))
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
