//! The confidential rail.

use custom_ring_interface::{CustomRingError, RingMode, RingRail};
use spr_client::{AsyncRpc, OwnerAuthorization, SettlementAccountValidation};
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::shape::Shape;
use spr_keypair::{NullifierKey, ShieldedAddress, SigningKey};
use spr_program::instruction::TransactInterfaceTransferAccounts;
use spr_transaction::instructions::transact::ConfidentialTransaction;
use zolana_ring_client::rpc::TokenAccountSetup;
use zolana_ring_transaction::RingOutputRail;

use super::{
    anonymous::CoOwner, canonical_shape, pad_under_rail, public_owners::check_zero_key_inputs,
    sealed, shape_keyed, transaction_key, CoOwnerKey, DeliveredRail, Rail, RailKind, RingSender,
    RingTransfer, Spend, Staged, TransferAuthority,
};
use crate::{CustomRing, CustomRingConfig, RingError};

/// The sender's spends, it signs the assembled Solana transaction itself or inside the proof.
pub struct Owner<'a> {
    pub(super) sender: &'a dyn RingSender,
    pub(super) nullifier_key: Option<&'a NullifierKey>,
    pub(super) transaction: ConfidentialTransaction,
    pub(super) interface_transfer_accounts: Vec<TransactInterfaceTransferAccounts>,
    pub(super) shape: Option<Shape>,
    pub(super) in_proof_owner: Option<&'a SigningKey>,
    pub(super) token_account_setup: Vec<TokenAccountSetup>,
    /// The other owners of a signer rail spend, each signs the transaction.
    pub(super) co_owners: Vec<CoOwner<'a>>,
}

pub struct CustomRingTransferInput<'a> {
    pub ring: CustomRing,
    /// Only transaction keys and the address are read, the signing key may live elsewhere.
    pub sender: &'a dyn RingSender,
    /// Completes the real inputs, `None` only for an all-padding transfer.
    pub nullifier_key: Option<&'a NullifierKey>,
    pub transaction: ConfidentialTransaction,
}

pub type CustomRingTransfer<'a> = RingTransfer<Owner<'a>>;

impl sealed::Sealed for Owner<'_> {}

impl Rail for Owner<'_> {
    fn kind(&self) -> RailKind<'_> {
        RailKind::Owner(self)
    }
}

impl<'a> RingTransfer<Owner<'a>> {
    pub fn new(input: CustomRingTransferInput<'a>) -> Self {
        Self {
            ring: input.ring,
            co_signers: Vec::new(),
            priority_fee: None,
            rail: Owner {
                sender: input.sender,
                nullifier_key: input.nullifier_key,
                transaction: input.transaction,
                interface_transfer_accounts: Vec::new(),
                shape: None,
                in_proof_owner: None,
                token_account_setup: Vec::new(),
                co_owners: Vec::new(),
            },
        }
    }

    /// Another owner of the spent notes, it signs the transaction and one prover holds its secret.
    #[must_use = "use the updated transfer"]
    pub fn with_co_owner(mut self, co_owner: CoOwner<'a>) -> Self {
        self.rail.co_owners.push(co_owner);
        self
    }

    /// The sender's signing key signs inside the proof, any fee payer sends the transaction.
    #[must_use = "use the updated transfer"]
    pub fn with_in_proof_owner(mut self, signer: &'a SigningKey) -> Self {
        self.rail.in_proof_owner = Some(signer);
        self
    }

    /// Ring RPC creates each account before a relayed withdrawal pays it.
    #[must_use = "use the updated transfer"]
    pub fn with_token_account_setup(mut self, setup: Vec<TokenAccountSetup>) -> Self {
        self.rail.token_account_setup = setup;
        self
    }

    #[must_use = "use the updated transfer"]
    pub fn with_interface_transfer_accounts(
        mut self,
        accounts: Vec<TransactInterfaceTransferAccounts>,
    ) -> Self {
        self.rail.interface_transfer_accounts = accounts;
        self
    }

    /// Unset, staging pads to the smallest supported shape.
    pub fn with_shape(mut self, shape: Shape) -> Result<Self, RingError> {
        if !shape_keyed(RingRail::Confidential, shape) {
            return Err(RingError::ShapeUnkeyed {
                rail: RingRail::Confidential,
            });
        }
        self.rail.shape = Some(shape);
        Ok(self)
    }
}

impl Owner<'_> {
    /// The rail pads under its own blinding seed, a caller never pads.
    pub(super) fn shape(&self, sender: &ShieldedAddress) -> Result<Shape, RingError> {
        match self.shape {
            Some(shape) => Ok(shape),
            None => canonical_shape(&self.transaction, sender),
        }
    }

    pub(super) fn check_settlement_accounts(&self) -> Result<(), RingError> {
        let transfers: Vec<_> = self
            .transaction
            .interface_transfers()?
            .into_iter()
            .map(|transfer| transfer.interface_transfer())
            .collect();
        SettlementAccountValidation {
            transfers: &transfers,
            accounts: &self.interface_transfer_accounts,
        }
        .validate()?;
        Ok(())
    }

    /// The anonymous rail takes no SPP signer but the payer.
    pub(super) fn check_payer_funds_deposits(&self) -> Result<(), RingError> {
        let payer = self.transaction.payer();
        let transfers = self.transaction.interface_transfers()?;
        let mut funders = transfers
            .iter()
            .zip(&self.interface_transfer_accounts)
            .filter_map(|(transfer, accounts)| match accounts {
                TransactInterfaceTransferAccounts::Sol(sol) => {
                    transfer.is_deposit().then_some(sol.recipient)
                }
                TransactInterfaceTransferAccounts::SplDeposit(spl) => Some(spl.token_authority),
                TransactInterfaceTransferAccounts::SplWithdrawal(_) => None,
            });
        match funders.any(|funder| funder != payer) {
            true => Err(CustomRingError::InvalidAnonymousSigner.into()),
            false => Ok(()),
        }
    }

    pub(super) async fn stage<R: AsyncRpc + ?Sized>(
        &self,
        _ring: CustomRing,
        _client: &R,
        config: &CustomRingConfig,
    ) -> Result<Staged<'_>, RingError> {
        if config.mode == RingMode::Anonymous {
            return Err(RingError::MissingAnonymousSigner);
        }
        check_zero_key_inputs(
            self.transaction.inputs(),
            &self.sender.address()?.signing_pubkey,
        )?;
        self.stage_signers()
    }

    /// The signer rail, zero-key notes admitted by the caller.
    pub(super) fn stage_signers(&self) -> Result<Staged<'_>, RingError> {
        let sender = self.sender.address()?;
        self.check_settlement_accounts()?;
        let shape = self.shape(&sender)?;
        let transaction = self.transaction.clone();
        let delivery = DeliveredRail {
            outputs: shape.n_outputs(),
            rail: RingRail::Confidential,
        }
        .delivery()?;
        let first_nullifier = *transaction.first_nullifier();
        let rail = RingOutputRail::new(transaction_key(self.sender, first_nullifier)?, delivery);
        let transaction = pad_under_rail(transaction, &rail, shape, &sender)?;
        let proof_inputs = rail.encrypt(transaction, &sender)?;
        let (owner_signers, spend) = match self.in_proof_owner {
            Some(signer) => {
                if signer.pubkey() != sender.signing_pubkey {
                    return Err(RingError::InProofOwnerMismatch);
                }
                // Co-owners beside the in-proof owner sign in public, SPP allows the mix.
                let in_proof = signer.pubkey().as_ed25519()?;
                let co_owners = proof_inputs
                    .owner_signer_pubkeys()?
                    .into_iter()
                    .filter(|owner| owner.to_bytes() != in_proof)
                    .collect();
                (
                    co_owners,
                    Spend::InProofOwner(OwnerAuthorization::SigningKey(signer)),
                )
            }
            None => (proof_inputs.owner_signer_pubkeys()?, Spend::Owner),
        };
        Ok(Staged {
            authority: self.authority()?,
            owner_signers,
            proof_inputs,
            rail,
            sender,
            interface_transfer_accounts: self.interface_transfer_accounts.clone(),
            spend,
            presealed: None,
        })
    }

    pub(super) fn authority(&self) -> Result<TransferAuthority, RingError> {
        Ok(TransferAuthority {
            owner: self.nullifier_key.cloned(),
            co_owners: self
                .co_owners
                .iter()
                .map(|co_owner| {
                    Ok(CoOwnerKey {
                        owner_pk_hash: solana_owner_identity(co_owner.owner.as_array())?,
                        key: co_owner.nullifier_key.clone(),
                    })
                })
                .collect::<Result<_, RingError>>()?,
        })
    }
}
