use std::collections::BTreeSet;

use custom_ring_interface::{RingMode, RingRail};
use solana_address::Address;
use spr_client::AsyncRpc;
use spr_interface::shape::{Shape, RING_AUTHORITY_WIDTHS};
use spr_keypair::{NullifierKey, PublicKey, ShieldedAddress, ViewingKey};
use spr_transaction::{
    instructions::transact::{ConfidentialTransaction, SppProofOutputUtxo},
    AssetRegistry, TransactionError, WalletUtxo,
};
use zolana_ring_transaction::{AnonymousPlan, RingDelivery, RingOutputRail};

use super::{
    anonymous::{SenderChange, WideFrames},
    canonical_shape, pad_under_rail, sealed,
    selection::{payment_total, widest, Funding},
    shape_keyed, CoOwner, CoOwnerKey, DeliveredRail, Rail, RailKind, RingTransfer, Spend, Staged,
    TransferAuthority,
};
use crate::client::{RingClient, RingIndexerBackend};
use crate::{CustomRing, CustomRingConfig, RingError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegateOutput {
    pub recipient: ShieldedAddress,
    pub asset: Address,
    pub amount: u64,
}

/// A deposit leg would bring an unlisted asset in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegateWithdrawal {
    pub asset: Address,
    pub amount: u64,
    pub recipient: Address,
    /// `None` on SOL, the mint's token program on an SPL asset.
    pub token_program: Option<Address>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegatePayment {
    pub recipient: ShieldedAddress,
    pub amount: u64,
}

#[must_use = "select the inputs of the move"]
pub struct DelegateMove<'a> {
    pub ring: CustomRing,
    pub delegate: Address,
    pub payer: Address,
    /// The delegate's own notes and several members' stand alike.
    pub sources: Vec<DelegateSource<'a>>,
    pub mint: Address,
    /// The change returns to the owner of the last note spent.
    pub payments: Vec<DelegatePayment>,
    pub assets: &'a AssetRegistry,
    pub wide_frames: WideFrames,
    /// A relayed delegate names it, its wallet then reads the proven records.
    pub tx_viewing_key: ViewingKey,
}

#[derive(Clone, Copy)]
pub struct DelegateSource<'a> {
    pub address: ShieldedAddress,
    /// Recovered from escrow, the proof spends the member's notes with it.
    pub nullifier_key: &'a NullifierKey,
    /// The source's UTXOs on any tree.
    pub utxos: &'a [WalletUtxo],
}

/// The delegate moves a member's notes with the recovered key, the member does not sign.
pub struct Delegated<'a> {
    pub(super) delegate: Address,
    payer: Address,
    source: ShieldedAddress,
    pub(super) source_key: NullifierKey,
    /// Owners of the inputs `source` does not own.
    co_sources: Vec<CoOwner<'a>>,
    inputs: Vec<WalletUtxo>,
    outputs: Vec<DelegateOutput>,
    exits: Vec<DelegateOutput>,
    withdrawals: Vec<DelegateWithdrawal>,
    output_tree_id: Option<u16>,
    shape: Option<Shape>,
    assets: Option<&'a AssetRegistry>,
    tx_viewing_key: ViewingKey,
}

pub struct DelegateTransferInput<'a> {
    pub ring: CustomRing,
    /// Signs the transaction beside the payer.
    pub delegate: Address,
    pub payer: Address,
    /// The member whose notes move, its change returns to it.
    pub source: ShieldedAddress,
    /// Recovered from escrow, the proof spends the member's notes with it.
    pub source_nullifier_key: &'a NullifierKey,
    pub inputs: Vec<WalletUtxo>,
    pub outputs: Vec<DelegateOutput>,
}

pub type DelegateTransfer<'a> = RingTransfer<Delegated<'a>>;

impl sealed::Sealed for Delegated<'_> {}

impl Rail for Delegated<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Delegated(self)
    }
}

impl<'a> RingTransfer<Delegated<'a>> {
    pub fn new(input: DelegateTransferInput<'_>) -> Self {
        Self {
            ring: input.ring,
            co_signers: Vec::new(),
            priority_fee: None,
            buffered: false,
            rail: Delegated {
                delegate: input.delegate,
                payer: input.payer,
                source: input.source,
                source_key: input.source_nullifier_key.clone(),
                co_sources: Vec::new(),
                inputs: input.inputs,
                outputs: input.outputs,
                exits: Vec::new(),
                withdrawals: Vec::new(),
                output_tree_id: None,
                shape: None,
                assets: None,
                tx_viewing_key: ViewingKey::new(),
            },
            list_salts: Vec::new(),
        }
    }

    #[must_use = "use the updated move"]
    pub fn with_co_source(mut self, co_source: CoOwner<'a>) -> Self {
        self.rail.co_sources.push(co_source);
        self
    }

    #[must_use = "use the updated move"]
    pub fn with_tx_viewing_key(mut self, key: ViewingKey) -> Self {
        self.rail.tx_viewing_key = key;
        self
    }

    /// The proof settles on `ring_authority_exit` and publishes the output's owner tag.
    #[must_use = "use the updated move"]
    pub fn with_exit(mut self, exit: DelegateOutput) -> Self {
        self.rail.exits.push(exit);
        self
    }

    #[must_use = "use the updated move"]
    pub fn with_withdrawal(mut self, withdrawal: DelegateWithdrawal) -> Self {
        self.rail.withdrawals.push(withdrawal);
        self
    }

    /// Unset, the first input's `latest_tree_id` takes the outputs, else tree 0.
    #[must_use = "use the updated move"]
    pub fn with_output_tree_id(mut self, tree_id: u16) -> Self {
        self.rail.output_tree_id = Some(tree_id);
        self
    }

    #[must_use = "use the updated move"]
    pub fn with_assets(mut self, assets: &'a AssetRegistry) -> Self {
        self.rail.assets = Some(assets);
        self
    }

    /// Unset, staging pads to the cheapest supported shape.
    pub fn with_shape(mut self, shape: Shape) -> Result<Self, RingError> {
        if !shape.is_ring_authority() {
            return Err(RingError::ShapeUnkeyed {
                rail: RingRail::Delegate,
            });
        }
        self.rail.shape = Some(shape);
        Ok(self)
    }
}

impl<'a> DelegateMove<'a> {
    /// The fewest UTXOs of one tree funding the payments whose move fits one transaction.
    pub async fn select<P: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<P, I>,
    ) -> Result<DelegateTransfer<'a>, RingError> {
        let amount = payment_total(self.payments.iter().map(|payment| payment.amount))?;
        let mut named = BTreeSet::new();
        if !self
            .sources
            .iter()
            .all(|source| named.insert(source.address.to_bytes()))
        {
            return Err(RingError::RepeatedDelegateSource);
        }
        let utxos: Vec<WalletUtxo> = self
            .sources
            .iter()
            .flat_map(|source| source.utxos.iter().filter(|utxo| self.spends(source, utxo)))
            .cloned()
            .collect();
        let payments = self.payments.len();
        let keyed = |shape| shape_keyed(RingRail::Delegate, shape);
        let unkeyed = || RingError::ShapeUnkeyed {
            rail: RingRail::Delegate,
        };
        let max_inputs = widest(payments, keyed).ok_or_else(unkeyed)?;
        let funding = Funding {
            utxos: &utxos,
            asset: self.mint,
            amount,
            max_inputs,
        };
        let attempts = funding
            .candidates(|_| true)
            .into_iter()
            .map(|candidate| {
                let shape = candidate.shape(payments, keyed).ok_or_else(unkeyed)?;
                self.transfer(candidate.utxos)?
                    .with_shape(shape)
                    .map(|transfer| match self.wide_frames {
                        WideFrames::Buffer => transfer.with_buffered_settlement(),
                        WideFrames::Refuse => transfer,
                    })
            })
            .collect();
        funding.first_fit(attempts, client).await
    }

    fn spends(&self, source: &DelegateSource<'_>, utxo: &WalletUtxo) -> bool {
        utxo.utxo.owner == source.address.signing_pubkey
            && utxo.utxo.ring_program_id == Some(self.ring.program_id())
    }

    /// Every note but the last is spent whole, so the change is its owner's.
    fn transfer(&self, utxos: Vec<WalletUtxo>) -> Result<DelegateTransfer<'a>, RingError> {
        let owner_of = |utxo: &WalletUtxo| {
            self.sources
                .iter()
                .find(|source| source.address.signing_pubkey == utxo.utxo.owner)
                .copied()
                .ok_or(TransactionError::NoInputs)
        };
        let change = owner_of(utxos.last().ok_or(TransactionError::NoInputs)?)?;
        let mut co_sources: Vec<CoOwner<'a>> = Vec::new();
        for utxo in &utxos {
            let source = owner_of(utxo)?;
            let owner = source.address.solana_address()?;
            if source.address != change.address
                && !co_sources.iter().any(|held| held.owner == owner)
            {
                co_sources.push(CoOwner {
                    owner,
                    nullifier_key: source.nullifier_key,
                });
            }
        }
        let transfer = DelegateTransfer::new(DelegateTransferInput {
            ring: self.ring,
            delegate: self.delegate,
            payer: self.payer,
            source: change.address,
            source_nullifier_key: change.nullifier_key,
            inputs: utxos,
            outputs: self
                .payments
                .iter()
                .map(|payment| DelegateOutput {
                    recipient: payment.recipient,
                    asset: self.mint,
                    amount: payment.amount,
                })
                .collect(),
        })
        .with_assets(self.assets)
        .with_tx_viewing_key(self.tx_viewing_key.clone());
        Ok(co_sources
            .into_iter()
            .fold(transfer, DelegateTransfer::with_co_source))
    }
}

/// An anonymous ring keeps the victim and recipients hidden.
pub(crate) const fn delegate_rail(mode: RingMode) -> RingRail {
    match mode {
        RingMode::Anonymous => RingRail::AnonymousDelegate,
        RingMode::Confidential => RingRail::Delegate,
    }
}

impl Delegated<'_> {
    pub(super) async fn stage<R: AsyncRpc + ?Sized>(
        &self,
        ring: CustomRing,
        _client: &R,
        config: &CustomRingConfig,
    ) -> Result<Staged<'_>, RingError> {
        match config.delegate {
            None => return Err(RingError::MissingDelegate),
            Some(stored) if stored != self.delegate => {
                return Err(custom_ring_interface::CustomRingError::UnauthorizedDelegate.into())
            }
            Some(_) => {}
        }
        if self.source_key.pubkey()? != self.source.nullifier_pubkey {
            return Err(RingError::NullifierKeyMismatch);
        }
        let named = self
            .co_sources
            .iter()
            .map(|co_source| Ok(PublicKey::from_ed25519(co_source.owner.as_array())))
            .collect::<Result<Vec<_>, RingError>>()?;
        if let Some(index) = self.inputs.iter().position(|input| {
            input.utxo.owner != self.source.signing_pubkey && !named.contains(&input.utxo.owner)
        }) {
            return Err(RingError::MixedOwners { index });
        }
        let assets = self.assets.ok_or(RingError::MissingAssetRegistry)?;
        let program = ring.program_id();
        let mut transaction =
            ConfidentialTransaction::new_with_ring(self.inputs.clone(), self.payer, program)?;
        if let Some(tree_id) = self.output_tree_id {
            transaction = transaction.with_output_tree_id(tree_id)?;
        }
        for output in &self.outputs {
            transaction.add_output_utxo(
                SppProofOutputUtxo::new(
                    assets.mint(&output.asset)?,
                    output.amount,
                    output.recipient,
                )?
                .with_ring_program_id(program),
            )?;
        }
        for exit in &self.exits {
            transaction.transfer_with_ring(
                &exit.recipient,
                assets.mint(&exit.asset)?,
                exit.amount,
                None,
            )?;
        }
        let interface_transfer_accounts = self
            .withdrawals
            .iter()
            .map(|leg| {
                transaction.withdraw_to(leg.asset, leg.amount, leg.recipient, leg.token_program)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let shape = match self.shape {
            Some(shape) => shape,
            None => {
                let needed = canonical_shape(&transaction, &self.source)?;
                RING_AUTHORITY_WIDTHS
                    .into_iter()
                    .find(|&width| width >= needed.n_inputs() && width >= needed.n_outputs())
                    .map(|width| Shape::new(width, width))
                    .ok_or(RingError::ShapeUnkeyed {
                        rail: delegate_rail(config.mode),
                    })?
            }
        };
        let ring_rail = delegate_rail(config.mode);
        // The anonymous frame's sender bundle reads output 0 as the source's change.
        let transaction = match ring_rail.anonymous_frame() {
            true => SenderChange {
                shape: self.shape,
                sender: &self.source,
                ring: program,
            }
            .ensure(transaction)?,
            false => transaction,
        };
        let delivery = match ring_rail.anonymous_frame() {
            true => RingDelivery::Anonymous(Box::new(
                self.outputs
                    .iter()
                    .fold(AnonymousPlan::new(), |plan, output| {
                        plan.with_payment(output.recipient.viewing_pubkey)
                    }),
            )),
            false => DeliveredRail {
                outputs: shape.n_outputs(),
                rail: ring_rail,
            }
            .delivery()?,
        };
        let rail = RingOutputRail::new(self.tx_viewing_key.clone(), delivery);
        let transaction = pad_under_rail(transaction, &rail, shape, &self.source)?;
        let proof_inputs = rail.encrypt(transaction, &self.source)?;
        let shape = Shape::new(
            proof_inputs.input_utxos.len(),
            proof_inputs.output_utxos.len(),
        );
        if !shape.is_ring_authority() {
            return Err(RingError::ShapeUnkeyed { rail: ring_rail });
        }
        Ok(Staged {
            proof_inputs,
            rail,
            sender: self.source,
            authority: TransferAuthority {
                co_owners: self
                    .co_sources
                    .iter()
                    .map(CoOwnerKey::of)
                    .collect::<Result<_, RingError>>()?,
                owner: Some(self.source_key.clone()),
            },
            owner_signers: Vec::new(),
            interface_transfer_accounts,
            spend: Spend::Delegate {
                delegate: self.delegate,
                rail: ring_rail,
            },
            presealed: None,
            list_salts: Vec::new(),
        })
    }
}
