//! One transfer pipeline for every rail, a rail only stages the transfer and seals its outputs.

mod anonymous;
mod audit;
mod compact;
mod delegate;
mod owner;
mod policy;
mod proof;
mod public_owners;
mod relay;
mod relayed;
mod selection;
mod spp;
#[cfg(test)]
#[path = "../../tests/operations/pipeline.rs"]
mod tests;
mod withdrawals;

use custom_ring_interface::{
    cosign::CoSignDemand,
    key_catalog::{RingCircuit, TransferSpend},
    CustomRingError, CustomRingProof, FramedSenderBundle, InputTrees, InstructionTag,
    ParsedTransact, PlainGroth16Proof, PublicLeg, PublicSlots, RingMode, RingPolicy, RingRail,
    Settlement, SignerSet, TransferBinding, DELIVERED_AUDIT_CAPACITIES,
};
use solana_address::Address;
use solana_instruction::Instruction;
use spr_client::{AsyncRpc, ClientError, OwnerAuthorization, ProofAuthority, Shape, TransferInput};
use spr_event::is_confidential_encrypted_output;
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::{instruction::TreeContext, N_PUBLIC_SLOTS};
use spr_keypair::{NullifierKey, ShieldedAddress, ViewingKey, X25519Pubkey};
use spr_program::instruction::TransactInterfaceTransferAccounts;
use spr_transaction::{
    instructions::transact::{
        ConfidentialTransaction, SettlementTransfer, SppProofInputs, SppProofOutputUtxo,
    },
    utxo::SppProofInputUtxo,
    ShieldedKeys, TransactionError,
};
use zolana_ring_keys::RingKeys;
use zolana_ring_transaction::{PublishedSlot, RingDelivery, RingOutputRail};

pub use self::{
    anonymous::{
        Anonymous, AnonymousMove, AnonymousPayment, AnonymousTransfer, CoOwner, EntrySpend,
        RingPayment,
    },
    delegate::{
        DelegateMove, DelegateOutput, DelegatePayment, DelegateTransfer, DelegateTransferInput,
        Delegated,
    },
    owner::{CustomRingTransfer, CustomRingTransferInput, Owner},
    public_owners::{PublicOwnerTransfer, PublicOwners},
    relayed::{Relayed, RelayedTransfer, RelayedTransferInput},
};

pub(crate) use self::anonymous::HiddenOwner;

use self::{
    anonymous::AnonymousSpend,
    audit::{AuditSeal, PresealedAudit, SealedAudit},
    compact::{
        OwnedInProofOwner, OwnedOutput, OwnedPolicyProof, OwnedRecipients, OwnedSenderBundle,
        TransactAccounts, TransactParts,
    },
    policy::{PolicyInputs, PolicyRead},
    spp::{Spp, SppRail, SppWitness},
};
use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    co_signer::CoSignerChoice,
    heap::boxed,
    projection::retry_projection_lag,
    submission::{check_transaction_size, send_budget, BoundPolicy, BoundState},
    trees::{spend_trees, SpendTrees},
    CustomRing, CustomRingConfig, RingError,
};

mod sealed {
    pub trait Sealed {}
}

pub trait RingSender: ShieldedKeys + RingKeys + Send + Sync {}

impl<T: ShieldedKeys + RingKeys + Send + Sync + ?Sized> RingSender for T {}

/// Who authorizes the spends, the owner, the hidden owner or the delegate.
pub trait Rail: sealed::Sealed + Send + Sync {
    #[doc(hidden)]
    fn kind(&self) -> RailKind<'_>;
}

#[doc(hidden)]
pub enum RailKind<'a> {
    Owner(&'a Owner<'a>),
    Anonymous(&'a Anonymous<'a>),
    Delegated(&'a Delegated<'a>),
    Relayed(&'a Relayed<'a>),
    PublicOwners(&'a PublicOwners<'a>),
}

#[must_use = "prove or discard the transfer explicitly"]
pub struct RingTransfer<R: Rail> {
    ring: CustomRing,
    rail: R,
    co_signer: Option<Address>,
    priority_fee: Option<u64>,
}

#[must_use = "build or submit the proven transfer"]
pub struct ProvenRingTransfer {
    ring: CustomRing,
    config: Box<RingPolicy>,
    parts: TransactParts,
    accounts: TransactAccounts,
    bound: BoundState,
    pub tx_viewing_key: ViewingKey,
    /// Padding included.
    pub outputs: Vec<SppProofOutputUtxo>,
    /// The supplied co-signer when the ring demands one, it signs the transaction.
    pub co_signer: Option<Address>,
    pub co_sign_demand: CoSignDemand,
}

/// A transfer past its outputs' sealing, ready for its statements.
pub(crate) struct Staged<'a> {
    pub proof_inputs: SppProofInputs,
    pub rail: RingOutputRail,
    pub sender: ShieldedAddress,
    pub authority: TransferAuthority,
    pub owner_signers: Vec<Address>,
    pub interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub spend: Spend<'a>,
    /// Set when the wallet sealed the auditor message the owner signed over.
    pub presealed: Option<PresealedAudit>,
}

pub(crate) enum Spend<'a> {
    Owner,
    /// The confidential rail's owner signs inside the SPP proof, no owner signs the transaction.
    InProofOwner(OwnerAuthorization<'a>),
    Anonymous(Box<AnonymousSpend<'a>>),
    /// An anonymous ring's frame with no hidden sender, its owners are the published signers.
    PublicOwners,
    Delegate {
        delegate: Address,
    },
}

impl Spend<'_> {
    /// The in-proof and authority rails bind count zero and chain zero.
    fn names_no_owner_run(&self) -> bool {
        matches!(self, Self::InProofOwner(_) | Self::Delegate { .. })
    }

    fn rail(&self) -> RingRail {
        match self {
            Self::Owner | Self::InProofOwner(_) => RingRail::Confidential,
            Self::Anonymous(_) | Self::PublicOwners => RingRail::Anonymous,
            Self::Delegate { .. } => RingRail::Delegate,
        }
    }

    fn spp_rail(&self) -> SppRail<'_> {
        match self {
            Self::Owner | Self::PublicOwners => SppRail::OwnerSigners,
            Self::InProofOwner(owner) => SppRail::Anonymous(*owner),
            Self::Anonymous(anonymous) => SppRail::Anonymous(anonymous.signer),
            Self::Delegate { .. } => SppRail::Delegate,
        }
    }

    fn in_proof_owner(&self) -> Result<Option<[u8; 32]>, RingError> {
        match self {
            Self::InProofOwner(owner) => Ok(Some(owner.public_key().as_ed25519()?)),
            Self::Owner | Self::Anonymous(_) | Self::PublicOwners | Self::Delegate { .. } => {
                Ok(None)
            }
        }
    }
}

/// One public co-owner's nullifier key, one prover holds every owner's secret.
pub(crate) struct CoOwnerKey {
    /// `owner_proof_input_hash`, the field a proof input carries.
    pub owner_pk_hash: [u8; 32],
    pub key: NullifierKey,
}

/// `owner` is `None` only when every input is padding.
pub(crate) struct TransferAuthority {
    pub owner: Option<NullifierKey>,
    pub co_owners: Vec<CoOwnerKey>,
}

impl ProofAuthority for TransferAuthority {
    fn complete_inputs(&self, inputs: &mut [TransferInput]) -> Result<(), ClientError> {
        let zero_key = NullifierKey::from_secret([0; 31]);
        for input in inputs {
            if input.nullifier_secret.is_some() {
                continue;
            }
            let owner_pk_hash = input.owner_pk_hash.to_bytes_be();
            let co_owner = self
                .co_owners
                .iter()
                .find(|co_owner| trailing_eq(&co_owner.owner_pk_hash, &owner_pk_hash));
            let zero_nullifier = zero_key.nullifier(&input.utxo.hash()?, &input.utxo.blinding)?;
            // One owner holds keyed and zero-key notes, each input's own nullifier picks its secret.
            let key = match trailing_eq(&zero_nullifier, &input.nullifier.to_bytes_be()) {
                true => Some(&zero_key),
                false => co_owner
                    .map(|co_owner| &co_owner.key)
                    .or(self.owner.as_ref()),
            };
            if let Some(key) = key {
                key.complete_inputs(core::slice::from_mut(input))?;
            }
        }
        Ok(())
    }
}

/// A big endian integer drops its leading zeros.
fn trailing_eq(field: &[u8; 32], integer: &[u8]) -> bool {
    field
        .iter()
        .rev()
        .zip(integer.iter().rev().chain(core::iter::repeat(&0)))
        .all(|(left, right)| left == right)
}

impl<R: Rail> RingTransfer<R> {
    pub fn ring(&self) -> CustomRing {
        self.ring
    }

    /// Read only when the ring demands a co-signer, its record must cover the demand.
    #[must_use = "use the updated transfer"]
    pub fn with_co_signer(mut self, signer: Address) -> Self {
        self.co_signer = Some(signer);
        self
    }

    /// Lamports the v1 header carries, the size check measures the header it adds.
    #[must_use = "use the updated transfer"]
    pub const fn with_priority_fee(mut self, lamports: u64) -> Self {
        self.priority_fee = Some(lamports);
        self
    }

    pub async fn prove<P: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<P, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        retry_projection_lag(|| async {
            let assembled = boxed(|| self.assemble(client)).await?;
            boxed(|| assembled.prove(client)).await
        })
        .await
    }

    /// Every chain value is read once.
    pub(crate) async fn assemble<P: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<P, I>,
    ) -> Result<Assembled, RingError> {
        let framed = boxed(|| self.frame(client)).await?;
        boxed(|| framed.witness(client)).await
    }

    /// The refusals of an assembly without its SPP witness, anchor path or signature.
    async fn measure<P: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<P, I>,
    ) -> Result<(), RingError> {
        boxed(|| self.frame(client)).await.map(drop)
    }

    async fn frame<P: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<P, I>,
    ) -> Result<Unwitnessed<'_>, RingError> {
        let sealed = boxed(|| self.seal(client.zolana())).await?;
        boxed(|| sealed.frame(client)).await
    }

    /// Reads accounts only, no Merkle path and no record.
    async fn seal<C: AsyncRpc + ?Sized>(&self, client: &C) -> Result<Sealed<'_>, RingError> {
        let config = self.ring.require_config(client).await?;
        self.ring.require_active(client).await?;
        let staged = match self.rail.kind() {
            RailKind::Owner(owner) => boxed(|| owner.stage(self.ring, client, &config)).await?,
            RailKind::Anonymous(rail) => boxed(|| rail.stage(self.ring, client, &config)).await?,
            RailKind::Delegated(delegated) => {
                boxed(|| delegated.stage(self.ring, client, &config)).await?
            }
            RailKind::Relayed(relayed) => {
                boxed(|| relayed.stage(self.ring, client, &config)).await?
            }
            RailKind::PublicOwners(public) => boxed(|| public.stage(self.ring, &config)).await?,
        };
        check_ring_output_markers(&staged.proof_inputs)?;
        boxed(|| {
            Pipeline {
                ring: self.ring,
                config,
                staged,
                co_signer: self.co_signer,
                priority_fee: self.priority_fee,
            }
            .seal(client)
        })
        .await
    }
}

struct Pipeline<'a> {
    ring: CustomRing,
    config: CustomRingConfig,
    staged: Staged<'a>,
    co_signer: Option<Address>,
    priority_fee: Option<u64>,
}

struct Frame {
    ring: CustomRing,
    ring_id: [u8; 32],
    proof_inputs: SppProofInputs,
    rail: RingOutputRail,
    sender: ShieldedAddress,
    sealed: SealedAudit,
    published_inputs: usize,
    policy: PolicyInputs,
    private_tx_blinding: [u8; 32],
    sender_pk_hash: [u8; 32],
    public_assets: [[u8; 32]; N_PUBLIC_SLOTS],
    public_amount_fields: [[u8; 32]; N_PUBLIC_SLOTS],
    public_gross: [[u8; 32]; N_PUBLIC_SLOTS],
    parts: TransactParts,
    accounts: TransactAccounts,
    co_signer: Option<Address>,
    co_sign_demand: CoSignDemand,
}

struct Unwitnessed<'a> {
    frame: Frame,
    config: CustomRingConfig,
    authority: TransferAuthority,
    spend: Spend<'a>,
    trees: SpendTrees,
    priority_fee: Option<u64>,
}

/// A transfer whose external data is final, before any record read.
struct Sealed<'a> {
    pipeline: Pipeline<'a>,
    sealed: SealedAudit,
    trees: SpendTrees,
    preview: Preview,
    published_inputs: usize,
}

#[derive(Clone, Copy)]
struct Preview {
    rail: RingRail,
    in_proof_owner: Option<[u8; 32]>,
    key_escrow: bool,
    n_in: u8,
    n_out: u8,
    trees: usize,
    expiry_unix_ts: u32,
}

impl Preview {
    fn parts(
        self,
        inputs: &SppProofInputs,
        rail: &RingOutputRail,
        sender: &ShieldedAddress,
    ) -> Result<TransactParts, RingError> {
        Ok(preview_parts(PreviewParts {
            rail: self.rail,
            in_proof_owner: self.in_proof_owner,
            key_escrow: self.key_escrow,
            n_in: self.n_in,
            n_out: self.n_out,
            inputs,
            published: &rail.published_slots(inputs, sender)?,
            sender_bundle: rail.published_sender(inputs, &sender.viewing_pubkey)?,
            trees: self.trees,
            expiry_unix_ts: self.expiry_unix_ts,
            tx_viewing_u: rail.tx_viewing_key().pubkey().u(),
        }))
    }
}

/// A transfer whose compact data is final but for its proofs.
pub(crate) struct Assembled {
    frame: Frame,
    config: Box<RingPolicy>,
    auditor: X25519Pubkey,
    spp: Spp,
    /// Hashed as the program rebuilds it.
    public_input_hash: [u8; 32],
    /// Zero off the anonymous rail.
    party_identities: [[u8; 32]; 3],
    /// The statement's sender identity, zero where the rail names none.
    sender: [u8; 32],
    bound: BoundState,
}

impl<'a> Pipeline<'a> {
    /// The external data is final after the seal, the owner signs its message hash.
    async fn seal<R: AsyncRpc + ?Sized>(self, client: &R) -> Result<Sealed<'a>, RingError> {
        let Staged {
            mut proof_inputs,
            rail,
            sender,
            authority,
            owner_signers,
            interface_transfer_accounts,
            spend,
            presealed,
        } = self.staged;
        let config = &self.config;
        let program = self.ring.program_id();
        let ring_rail = spend.rail();
        // The compact data carries a u32 expiry, an unbounded one keeps its farthest value.
        let expiry_unix_ts =
            u32::try_from(proof_inputs.external_data.expiry_unix_ts).unwrap_or(u32::MAX);
        proof_inputs.external_data.expiry_unix_ts = u64::from(expiry_unix_ts);
        check_distinct(&proof_inputs.input_utxos)?;
        if matches!(spend, Spend::InProofOwner(_)) {
            if let Some(index) = default_ring_input(&proof_inputs.input_utxos) {
                return Err(RingError::InProofDefaultRingInput { index });
            }
        }
        check_membership(
            program,
            &proof_inputs.input_utxos,
            &proof_inputs.output_utxos,
        )?;
        let trees = spend_trees(
            client,
            &proof_inputs.input_utxos,
            proof_inputs.output_tree_id,
        )
        .await?;
        let shape = proof_inputs.check_shape()?;
        let n_in = shape_byte(shape.n_inputs(), ring_rail)?;
        let n_out = shape_byte(shape.n_outputs(), ring_rail)?;
        let published_inputs = proof_inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_compact())
            .count();
        let auditor = config.auditor_pubkey;
        let preview = Preview {
            rail: ring_rail,
            in_proof_owner: spend.in_proof_owner()?,
            key_escrow: config.mode == RingMode::ConfidentialEscrow,
            n_in,
            n_out,
            trees: trees.inputs.len(),
            expiry_unix_ts,
        };

        // The auditor message precedes every hash over the external data.
        let unsealed = preview.parts(&proof_inputs, &rail, &sender)?;
        let (layout, flags) = (
            unsealed.data().audit_stream()?,
            unsealed.data().audit_layout(),
        );
        let sealed = match presealed {
            Some(presealed) => presealed.open(layout, flags, &auditor)?,
            None => AuditSeal {
                rail: &rail,
                layout,
                flags,
                published: &rail.published_slots(&proof_inputs, &sender)?,
                inputs: &proof_inputs,
                sender: &sender,
                auditor: &auditor,
            }
            .seal()?,
        };
        proof_inputs
            .external_data
            .messages
            .push(sealed.message(&auditor));
        proof_inputs.external_data.instruction_discriminator = ring_rail.spp_tag();

        Ok(Sealed {
            pipeline: Pipeline {
                priority_fee: self.priority_fee,
                ring: self.ring,
                config: self.config,
                co_signer: self.co_signer,
                staged: Staged {
                    proof_inputs,
                    rail,
                    sender,
                    authority,
                    owner_signers,
                    interface_transfer_accounts,
                    spend,
                    presealed: None,
                },
            },
            sealed,
            trees,
            preview,
            published_inputs,
        })
    }
}

impl<'a> Sealed<'a> {
    async fn frame<P: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<P, I>,
    ) -> Result<Unwitnessed<'a>, RingError> {
        let Sealed {
            pipeline:
                Pipeline {
                    ring,
                    config: ring_config,
                    staged,
                    co_signer: supplied_co_signer,
                    priority_fee,
                },
            sealed,
            trees,
            preview,
            published_inputs,
        } = self;
        let Staged {
            proof_inputs,
            rail,
            sender,
            authority,
            owner_signers,
            interface_transfer_accounts,
            spend,
            presealed: _,
        } = staged;
        let config = &ring_config;
        let ring_rail = preview.rail;
        let n_out = preview.n_out;
        let ring_id = ring.ring_id()?;
        let public = public_slots(&proof_inputs.external_data.interface_transfers)?;
        let public_assets = public.asset_fields()?;
        let public_amount_fields = public.amount_fields()?;
        let public_gross = public.gross_fields();
        let private_tx_blinding = proof_inputs.private_tx_blinding()?;
        let sender_pk_hash = sender.signing_pubkey.owner_proof_input_hash()?;
        let mut policy = PolicyRead {
            token_owner_hint: match &spend {
                Spend::Anonymous(a) => a.token_owner,
                _ => None,
            },
            ring,
            config,
            rail: ring_rail,
            inputs: &proof_inputs,
            published_inputs,
            spends_default_ring: ring_rail == RingRail::Anonymous
                && spends_default_ring(&proof_inputs.input_utxos),
            n_out,
            sender: sender_pk_hash,
            sender_address: &sender,
            in_proof: preview.in_proof_owner.is_some(),
            owner_signers: &owner_signers,
            public: &public,
        }
        .read(client.zolana())
        .await?;
        let transfers = &proof_inputs.external_data.interface_transfers;
        let demand = CoSignDemand::transact(policy.approval_required, &public);
        policy
            .exempt_withdrawals(config, &demand, &public, client.zolana())
            .await?;
        let demand = match policy.exempt {
            true => demand.exempt_withdrawals(),
            false => demand,
        };
        let co_signer = CoSignerChoice {
            ring,
            config,
            demand: &demand,
            supplied: supplied_co_signer,
        }
        .resolve(client.zolana())
        .await?;
        let in_proof_owner = preview.in_proof_owner.map(Address::new_from_array);
        if co_signer.is_some_and(|co_signer| {
            owner_signers.contains(&co_signer) || in_proof_owner == Some(co_signer)
        }) {
            return Err(CustomRingError::CoSignerIsOwner.into());
        }
        let delegate = match spend {
            Spend::Delegate { delegate } => Some(delegate),
            Spend::Owner | Spend::InProofOwner(_) | Spend::Anonymous(_) | Spend::PublicOwners => {
                None
            }
        };
        if co_signer.is_some() && co_signer == delegate {
            return Err(CustomRingError::CoSignerIsDelegate.into());
        }
        let anonymous = match &spend {
            Spend::Anonymous(anonymous) => Some(anonymous),
            Spend::Owner | Spend::InProofOwner(_) | Spend::PublicOwners | Spend::Delegate { .. } => {
                None
            }
        };
        let accounts = TransactAccounts {
            payer: proof_inputs.payer,
            input_trees: trees.inputs.clone(),
            output_tree: trees.output,
            owner_signers,
            interface_transfer_accounts,
            co_signer,
            delegate,
        };
        let mut parts = preview.parts(&proof_inputs, &rail, &sender)?;
        parts.seal_audit(sealed.eph_u, sealed.envelope.clone(), &sealed.records);
        parts.approval_required = policy.approval_required;
        parts.exempt = policy.exempt;
        parts.own_revision = policy.own.map(|own| own.revision);
        parts.policy = policy.screened().then(|| OwnedPolicyProof {
            spl_withdrawal_owners: policy.spl_withdrawal_owners.clone(),
            curator_revision: policy.curator.map(|curator| curator.revision),
            recipients: match ring_rail.publishes_recipients() {
                false => OwnedRecipients::Hidden,
                // An omitted slot's recipient leaves the frame.
                true => OwnedRecipients::Framed(policy.recipients[..parts.outputs.len()].to_vec()),
            },
        });
        if anonymous.is_some() {
            parts.anonymous = Some(compact::OwnedAnonymousProofData {
                commitment: [0; 32],
                commitment_pok: [0; 32],
                // SPP publishes the hidden owner's key exactly when it spends a default-ring note.
                default_owner_tag: parts
                    .full_openings
                    .then(|| sender.signing_pubkey.as_ed25519())
                    .transpose()?,
            });
        }
        let settlements: Vec<_> = transfers
            .iter()
            .map(|transfer| transfer.settlement_accounts())
            .collect();
        let settlement_views: Vec<Settlement<'_>> = settlements
            .iter()
            .map(|[asset_account, user_account]| Settlement {
                asset_account,
                user_account,
            })
            .collect();
        if parts
            .data()
            .external_data_hash(config.account(), &settlement_views)?
            != proof_inputs.external_data.hash()?
        {
            return Err(RingError::ExternalDataMismatch);
        }
        let unwitnessed = Unwitnessed {
            frame: Frame {
                ring,
                ring_id,
                proof_inputs,
                rail,
                sender,
                sealed,
                published_inputs,
                policy,
                private_tx_blinding,
                sender_pk_hash,
                public_assets,
                public_amount_fields,
                public_gross,
                parts,
                accounts,
                co_signer,
                co_sign_demand: demand,
            },
            config: ring_config,
            authority,
            spend,
            trees,
            priority_fee,
        };
        unwitnessed.check_size()?;
        Ok(unwitnessed)
    }
}

impl Unwitnessed<'_> {
    fn check_size(&self) -> Result<(), RingError> {
        let proof_inputs = &self.frame.proof_inputs;
        let budget = send_budget(
            match self.spend.rail() {
                RingRail::Delegate => InstructionTag::AuthorityTransfer,
                RingRail::Confidential | RingRail::Anonymous => InstructionTag::Transfer,
            },
            self.priority_fee,
        );
        match check_transaction_size(&proof_inputs.payer, &self.instruction()?, budget) {
            Err(RingError::TransactionTooLarge { bytes, limit }) => {
                let shape = proof_inputs.check_shape()?;
                Err(RingError::TransferTooWide {
                    inputs: shape.n_inputs(),
                    outputs: shape.n_outputs(),
                    bytes,
                    limit,
                })
            }
            checked => checked,
        }
    }

    /// Sized as the proven instruction, the witness and the proofs fill fields of fixed width.
    fn instruction(&self) -> Result<Instruction, RingError> {
        let frame = &self.frame;
        frame
            .accounts
            .instruction(frame.ring, self.config.account(), &frame.parts)
    }

    async fn witness<P: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<P, I>,
    ) -> Result<Assembled, RingError> {
        let Self {
            mut frame,
            config,
            authority,
            spend,
            trees,
            ..
        } = self;
        let ring = frame.ring;
        let anonymous = match &spend {
            Spend::Anonymous(anonymous) => Some(anonymous),
            Spend::Owner | Spend::InProofOwner(_) | Spend::PublicOwners | Spend::Delegate { .. } => {
                None
            }
        };
        let party_identities = anonymous
            .map(|anonymous| anonymous.party_identities(frame.co_signer))
            .transpose()?
            .unwrap_or_default();
        let spp = SppWitness {
            ring: ring.program_id(),
            rail: spend.spp_rail(),
            owner_signers: &frame.accounts.owner_signers,
            inputs: &frame.proof_inputs,
            trees: &trees,
            authority: &authority,
        }
        .build(client)
        .await?;
        let private_tx_hash = spp.private_tx_hash();
        frame.parts.private_tx_hash = private_tx_hash;
        let auditor = config.auditor_pubkey;
        // Only the in-proof owner is named, the signer set carries the signer rail's owners.
        let sender = match frame.parts.in_proof_owner.is_some() {
            true => frame.sender_pk_hash,
            false => [0; 32],
        };
        let parsed = ParsedTransact::new(frame.parts.data())?;
        let recipients = parsed.data().recipients();
        let signers = match frame.parts.full_openings || spend.names_no_owner_run() {
            true => SignerSet::default(),
            false => SignerSet::new(
                frame.accounts.owner_signers.iter().map(Address::as_array),
                parsed.audit_stream().key.signer_slots(),
            )?,
        };
        let public_input_hash = parsed
            .transfer_statement(TransferBinding {
                ring_id: &frame.ring_id,
                auditor_pubkey: auditor.as_bytes(),
                key_escrow: frame.parts.key_escrow,
                sender: &sender,
                signers,
                party_identities: &party_identities,
                recipients: &recipients,
                roots: &frame.policy.roots(),
                public_assets: &frame.public_assets,
                public_amounts: &frame.public_amount_fields,
                public_gross: &frame.public_gross,
                withdrawal_hash: &frame.policy.withdrawal_hash()?,
            })?
            .hash()?;
        let bound = BoundState {
            roots: frame
                .policy
                .own
                .into_iter()
                .chain(frame.policy.curator)
                .collect(),
            policy: frame.policy.screened().then_some(BoundPolicy {
                ring,
                hash: frame.policy.policy_hash,
            }),
        };
        Ok(Assembled {
            frame,
            config: Box::new(*config.account()),
            auditor,
            spp,
            public_input_hash,
            party_identities,
            sender,
            bound,
        })
    }
}

impl Assembled {
    async fn prove<P: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<P, I>,
    ) -> Result<ProvenRingTransfer, RingError> {
        let (proven_spp, proof) = {
            let request = self.request()?;
            // Neither proof is an input to the other.
            futures::try_join!(
                boxed(|| self.spp.prove(client, self.frame.published_inputs)),
                boxed(|| request.prove(client)),
            )?
        };
        let Frame {
            ring,
            proof_inputs,
            rail,
            mut parts,
            accounts,
            co_signer,
            co_sign_demand,
            ..
        } = self.frame;
        parts.proof = proof;
        parts.spp_proof = proven_spp.proof;
        parts.nullifiers = proven_spp.nullifiers;
        parts.input_trees = proven_spp.input_trees;
        let commitment = proven_spp.commitment;
        if let Some(anonymous) = parts.anonymous.as_mut() {
            let commitment = commitment.ok_or(RingError::IncompleteProofSet)?;
            *anonymous = compact::OwnedAnonymousProofData {
                commitment: commitment.commitment,
                commitment_pok: commitment.commitment_pok,
                default_owner_tag: proven_spp.default_owner_tag,
            };
        }
        if let Some(owner) = parts.in_proof_owner.as_mut() {
            let commitment = commitment.ok_or(RingError::IncompleteProofSet)?;
            owner.commitment = commitment.commitment;
            owner.commitment_pok = commitment.commitment_pok;
        }
        Ok(ProvenRingTransfer {
            ring,
            config: self.config,
            bound: self.bound,
            parts,
            accounts,
            tx_viewing_key: rail.tx_viewing_key().clone(),
            outputs: proof_inputs.output_utxos,
            co_signer,
            co_sign_demand,
        })
    }
}

impl ProvenRingTransfer {
    pub(crate) fn bound(&self) -> BoundState {
        self.bound.clone()
    }

    pub fn instruction(&self) -> Result<Instruction, RingError> {
        self.accounts
            .instruction(self.ring, &self.config, &self.parts)
    }

    /// The owners who sign the transaction in public, none on the anonymous and in-proof owner rails.
    pub fn owner_signers(&self) -> &[Address] {
        &self.accounts.owner_signers
    }
}

/// Whether `rail` keys a transfer of `shape` publishing every input, none a default-ring UTXO.
pub fn shape_keyed(rail: RingRail, shape: Shape) -> bool {
    keyed(rail, shape, false)
}

fn keyed(rail: RingRail, shape: Shape, spends_default_ring: bool) -> bool {
    rail.supports(shape)
        && RingCircuit::transfer(TransferSpend {
            rail,
            inputs: shape.n_inputs(),
            outputs: shape.n_outputs(),
            spends_default_ring,
            legs: 0,
            owners: 0,
            has_data: false,
        })
        .is_some()
}

/// The compact data before any proof, sized and hashed as the proven one.
struct PreviewParts<'a> {
    rail: RingRail,
    in_proof_owner: Option<[u8; 32]>,
    key_escrow: bool,
    n_in: u8,
    n_out: u8,
    inputs: &'a SppProofInputs,
    published: &'a [PublishedSlot<'a>],
    sender_bundle: Option<FramedSenderBundle<'a>>,
    trees: usize,
    expiry_unix_ts: u32,
    tx_viewing_u: [u8; 32],
}

fn preview_parts(preview: PreviewParts<'_>) -> TransactParts {
    let external = &preview.inputs.external_data;
    let nullifiers = preview
        .inputs
        .input_utxos
        .iter()
        .filter(|input| !input.is_compact())
        .map(SppProofInputUtxo::nullifier)
        .collect();
    let context = TreeContext {
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
    };
    TransactParts {
        rail: preview.rail,
        n_in: preview.n_in,
        n_out: preview.n_out,
        proof: zeroed_proof(),
        own_revision: None,
        policy: None,
        exempt: false,
        approval_required: false,
        expiry_unix_ts: preview.expiry_unix_ts,
        tx_viewing_u: preview.tx_viewing_u,
        salt: external.salt,
        interface_transfers: external
            .interface_transfers
            .iter()
            .map(|transfer| transfer.interface_transfer())
            .collect(),
        key_escrow: preview.key_escrow,
        full_openings: preview.rail == RingRail::Anonymous
            && spends_default_ring(&preview.inputs.input_utxos),
        outputs: preview
            .published
            .iter()
            .map(|slot| OwnedOutput::of(slot.wire))
            .collect(),
        replies: owned_replies(preview.published),
        sender: preview.sender_bundle.map(OwnedSenderBundle::of),
        eph_u: [0; 32],
        envelope: Vec::new(),
        private_tx_hash: [0; 32],
        anonymous: None,
        in_proof_owner: preview.in_proof_owner.map(|owner| OwnedInProofOwner {
            owner,
            commitment: [0; 32],
            commitment_pok: [0; 32],
        }),
        spp_proof: PlainGroth16Proof {
            proof_a: [0; 32],
            proof_b: [0; 64],
            proof_c: [0; 32],
        },
        nullifiers,
        input_trees: match preview.trees {
            1 => InputTrees::One(context),
            _ => InputTrees::Two {
                first: context,
                second: context,
                second_inputs: 0,
            },
        },
    }
}

/// One length per frame, `None` without reply metadata.
fn owned_replies(published: &[PublishedSlot<'_>]) -> Option<(u16, Vec<u8>)> {
    let len = published.iter().map(|slot| slot.reply.len()).max()?;
    let region = published
        .iter()
        .flat_map(|slot| slot.reply)
        .copied()
        .collect();
    u16::try_from(len)
        .ok()
        .filter(|len| *len != 0)
        .map(|len| (len, region))
}

fn zeroed_proof() -> CustomRingProof {
    bytemuck::Zeroable::zeroed()
}

fn spends_default_ring(inputs: &[SppProofInputUtxo]) -> bool {
    default_ring_input(inputs).is_some()
}

/// SPP's anonymous rail publishes the hidden owner of a default-ring input.
fn default_ring_input(inputs: &[SppProofInputUtxo]) -> Option<usize> {
    inputs
        .iter()
        .position(|input| !input.is_dummy() && input.utxo.ring_program_id.is_none())
}

struct DeliveredRail {
    outputs: usize,
    rail: RingRail,
    mode: RingMode,
}

impl DeliveredRail {
    fn delivery(self) -> Result<RingDelivery, RingError> {
        match DELIVERED_AUDIT_CAPACITIES.contains(&self.outputs) {
            true => Ok(RingDelivery::Delivered {
                key_escrow: self.mode == RingMode::ConfidentialEscrow,
            }),
            false => Err(RingError::ShapeUnkeyed { rail: self.rail }),
        }
    }
}

fn shape_byte(count: usize, rail: RingRail) -> Result<u8, RingError> {
    u8::try_from(count).map_err(|_| RingError::ShapeUnkeyed { rail })
}

/// Each real input spends once, a repeated nullifier fails on chain after proving.
fn check_distinct(inputs: &[SppProofInputUtxo]) -> Result<(), RingError> {
    let real: Vec<_> = inputs.iter().filter(|input| !input.is_dummy()).collect();
    match real.iter().enumerate().find(|(index, input)| {
        real[..*index]
            .iter()
            .any(|earlier| earlier.nullifier == input.nullifier)
    }) {
        Some((_, input)) => Err(RingError::DuplicateInput {
            nullifier: input.nullifier,
        }),
        None => Ok(()),
    }
}

/// Every ring field names the transfer's ring, only a ring note carries ring data.
pub(crate) fn check_membership(
    program: Address,
    inputs: &[SppProofInputUtxo],
    outputs: &[SppProofOutputUtxo],
) -> Result<(), RingError> {
    let slots = inputs
        .iter()
        .map(|input| (input.utxo.ring_program_id, input.ring_data_hash))
        .chain(
            outputs
                .iter()
                .map(|output| (output.ring_program_id, output.ring_data_hash)),
        );
    for (ring, data) in slots {
        match ring {
            Some(ring) if ring != program => return Err(RingError::ForeignRing(ring)),
            None if data.is_some() => return Err(RingError::RingDataOutsideRing),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn transaction_key(
    sender: &dyn RingSender,
    first_nullifier: [u8; 32],
) -> Result<ViewingKey, RingError> {
    let keys = sender.transaction_keys(&[spr_transaction::TransactionKeyRequest {
        viewing_pubkey: sender.address()?.viewing_pubkey,
        first_nullifier,
    }])?;
    Ok(zolana_ring_client::exactly_one(keys)?)
}

pub(crate) fn public_leg(transfer: &SettlementTransfer) -> PublicLeg {
    PublicLeg {
        transfer: transfer.interface_transfer(),
        mint: match transfer {
            SettlementTransfer::Spl { mint, .. } => Some(mint.to_bytes()),
            SettlementTransfer::Sol { .. } => None,
        },
    }
}

pub(crate) fn public_slots(transfers: &[SettlementTransfer]) -> Result<PublicSlots, RingError> {
    PublicSlots::fold(transfers.iter().map(|transfer| Ok(public_leg(transfer))))
}

/// A default-ring exit publishes its actual owner, the ring circuit burns an unmarked one.
fn check_ring_output_markers(inputs: &SppProofInputs) -> Result<(), RingError> {
    let external = &inputs.external_data;
    for (index, output) in inputs.output_utxos.iter().enumerate() {
        let Some(owner) = &output.owner_address else {
            continue;
        };
        let marked = external
            .outputs
            .get(index)
            .and_then(|slot| slot.data.as_deref())
            .is_some_and(is_confidential_encrypted_output);
        match (output.ring_program_id.is_some(), marked) {
            (true, false) => {}
            (false, true) => {
                let tag = external
                    .resolved_owner_tags
                    .get(index)
                    .ok_or(TransactionError::OwnerTagMismatch { slot_index: index })?;
                if solana_owner_identity(tag)? != owner.signing_pubkey.owner_proof_input_hash()? {
                    return Err(TransactionError::OwnerTagMismatch { slot_index: index }.into());
                }
            }
            _ => return Err(RingError::RingOutputMarkerMismatch { index }),
        }
    }
    Ok(())
}

/// The shape SPP's own finalization pads to.
pub(crate) fn canonical_shape(
    transaction: &ConfidentialTransaction,
    sender: &ShieldedAddress,
) -> Result<Shape, RingError> {
    let finalized = transaction.clone().finalize(sender)?;
    Ok(Shape::new(
        finalized.input_utxos().len(),
        finalized.output_utxos().len(),
    ))
}

/// The blinding seed is fixed once padded, the rail's goes in first.
pub(crate) fn pad_under_rail(
    transaction: ConfidentialTransaction,
    rail: &RingOutputRail,
    shape: Shape,
    sender: &ShieldedAddress,
) -> Result<ConfidentialTransaction, RingError> {
    let mut transaction = transaction.with_blinding_seed(rail.blinding_seed()?)?;
    transaction.pad_utxos(shape, sender)?;
    Ok(transaction)
}
