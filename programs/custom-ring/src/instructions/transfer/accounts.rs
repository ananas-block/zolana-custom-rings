use custom_ring_interface::{
    cosign::{CoSignDemand, CoSignOperation},
    funder_account_position, AnonymousParties, CustomRingError, ParsedTransact, PublicSlots,
    RailSigner, RingPolicy, RootRead, SignerSet, TransferRoots, ANONYMOUS_PARTIES,
    RING_TRANSACT_RING_CONFIG_INDEX, TRANSACT_PAYER_INDEX,
};
use pinocchio::{error::ProgramError, AccountView, Address};
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::instruction::instruction_data::settlement_accounts;

use crate::instructions::{
    instruction_runtime::{PlacedRingAuth, RingAuth},
    loader::{check_funding_signer, load_anonymous_exit, CoSigners, RegistrySlots},
    public_legs::public_slots,
};

const RING_INDEX: usize = 0;

pub(super) struct TransactAccounts {
    pub roots: TransferRoots,
    /// The in-proof owner's identity, zero otherwise.
    pub sender: [u8; 32],
    /// SPP's owner signer run, default on the authority rails.
    pub signers: SignerSet,
    /// Zeros off the anonymous frame.
    pub party_identities: [[u8; 32]; ANONYMOUS_PARTIES],
    pub public_slots: PublicSlots,
    /// Empty without own records and on the authority rails, no rule screens them.
    pub withdrawals: Vec<custom_ring_interface::PolicyWithdrawal>,
    /// Index of the first forwarded SPP account.
    pub spp: usize,
    pub ring_auth: PlacedRingAuth,
}

#[must_use]
pub(super) struct TransactCheck<'a> {
    pub program_id: &'a Address,
    pub ring: &'a RingPolicy,
    pub transfer: &'a ParsedTransact<'a>,
    pub signer: RailSigner,
    pub slot: u64,
}

impl TransactCheck<'_> {
    #[inline(never)]
    pub fn validate(self, accounts: &[AccountView]) -> Result<TransactAccounts, ProgramError> {
        let (ring, data) = (self.ring, self.transfer.data());
        let delegate_rail = data.rail.is_delegate();
        let read = RootRead::transfer(ring, delegate_rail);
        let registries = RegistrySlots { ring, read }.load({
            let mut after_ring = accounts.iter().skip(RING_INDEX + 1);
            move || after_ring.next().ok_or(ProgramError::NotEnoughAccountKeys)
        })?;
        let bound = data.roots(ring, &registries.roots(self.slot))?;
        let window = settlement_accounts(&data.interface_transfers, data.circuit(), accounts)
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        let public_slots = public_slots(&data.interface_transfers, window)?;
        let demand = match delegate_rail {
            true => CoSignDemand::NONE,
            false => CoSignOperation {
                spends_note: !data.no_spend,
                public_legs: public_slots.classes(),
                approval: data.approval,
            }
            .demand(),
        };
        let co_signers_start = RING_INDEX + 1 + registries.len;
        let co_signers = CoSigners::verify(
            self.program_id,
            accounts
                .get(co_signers_start..)
                .ok_or(ProgramError::NotEnoughAccountKeys)?,
            demand.requirement(ring),
        )?;
        let delegate_slot = co_signers_start + co_signers.accounts();
        let spp_start = match self.signer {
            RailSigner::Delegate { .. } => delegate_slot + 1,
            RailSigner::Owners | RailSigner::Payer => delegate_slot,
        };
        let spp = accounts
            .get(spp_start..)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let ring_auth =
            RingAuth::derive(self.program_id)?.check_slot(spp, RING_TRANSACT_RING_CONFIG_INDEX)?;
        let payer = check_funding_signer(spp, TRANSACT_PAYER_INDEX)?;
        let slots = self.transfer.audit_stream().key.signer_slots();
        let (sender, signers) = match self.signer {
            RailSigner::Payer => {
                let owners = data.owner_signers(spp, window.len())?;
                check_owner_run(owners, &co_signers)?;
                if data.public_owners && !data.no_spend && owners.is_empty() {
                    return Err(CustomRingError::OwnerSignerCount.into());
                }
                if spp.iter().any(|account| {
                    account.is_signer()
                        && account.address() != payer.address()
                        && !co_signers.contains(account.address())
                        && !owners
                            .iter()
                            .any(|owner| owner.address() == account.address())
                }) {
                    return Err(CustomRingError::InvalidAnonymousSigner.into());
                }
                ([0; 32], signer_set(owners, slots)?)
            }
            RailSigner::Owners => {
                let owners = data.owner_signers(spp, window.len())?;
                check_owner_run(owners, &co_signers)?;
                let sender = match data.in_proof_owner {
                    Some(owner) => {
                        let owner = Address::new_from_array(*owner.owner);
                        if co_signers.contains(&owner) {
                            return Err(CustomRingError::CoSignerIsOwner.into());
                        }
                        solana_owner_identity(owner.as_array()).map_err(CustomRingError::from)?
                    }
                    None if !data.no_spend && owners.is_empty() => {
                        return Err(CustomRingError::OwnerSignerCount.into());
                    }
                    None => [0; 32],
                };
                (sender, signer_set(owners, slots)?)
            }
            RailSigner::Delegate { delegate, .. } => {
                // A deposit leg would bring an unlisted asset in.
                if data
                    .interface_transfers
                    .iter()
                    .any(|transfer| transfer.is_deposit())
                {
                    return Err(CustomRingError::DelegatePublicLeg.into());
                }
                let signer = account_at(accounts, delegate_slot)?;
                if !signer.is_signer() || signer.address() != &delegate {
                    return Err(CustomRingError::UnauthorizedDelegate.into());
                }
                ([0; 32], SignerSet::default())
            }
        };

        let mut groups = window;
        for transfer in &data.interface_transfers {
            let (group, rest) = groups
                .split_at_checked(transfer.settlement_account_count())
                .ok_or(CustomRingError::InvalidSettlementAccounts)?;
            groups = rest;
            if let Some(funder) = funder_account_position(transfer) {
                check_funding_signer(group, funder)?;
            }
        }
        let withdrawals = match read {
            RootRead::None => Vec::new(),
            RootRead::Own | RootRead::Policy => custom_ring_interface::policy_withdrawals(
                &data.interface_transfers,
                &window
                    .iter()
                    .map(crate::instructions::loader::LoadedSettlement)
                    .collect::<Vec<_>>(),
                data.spl_withdrawal_owners,
            )?,
        };
        let party_identities = match data.rail.anonymous_frame() {
            true => {
                // SPP settles any exit, only a hidden sender needs a destination that names one key.
                let exit = match self.signer == RailSigner::Payer && !data.public_owners {
                    true => load_anonymous_exit(&data.interface_transfers, window)?,
                    false => None,
                };
                AnonymousParties {
                    payer: payer.address().as_array(),
                    co_signers: co_signers.as_slice(),
                    exit_destination: exit.as_ref(),
                }
                .identities()
                .map_err(CustomRingError::from)?
            }
            false => [[0; 32]; ANONYMOUS_PARTIES],
        };

        Ok(TransactAccounts {
            roots: bound,
            sender,
            signers,
            party_identities,
            public_slots,
            withdrawals,
            spp: spp_start,
            ring_auth,
        })
    }
}

fn account_at(accounts: &[AccountView], index: usize) -> Result<&AccountView, ProgramError> {
    accounts
        .get(index)
        .ok_or(ProgramError::NotEnoughAccountKeys)
}

fn check_owner_run(owners: &[AccountView], co_signers: &CoSigners) -> Result<(), CustomRingError> {
    if owners.iter().any(|owner| !owner.is_signer()) {
        return Err(CustomRingError::MissingOwnerSigner);
    }
    if owners
        .iter()
        .any(|owner| co_signers.contains(owner.address()))
    {
        return Err(CustomRingError::CoSignerIsOwner);
    }
    Ok(())
}

fn signer_set(owners: &[AccountView], slots: usize) -> Result<SignerSet, CustomRingError> {
    SignerSet::new(owners.iter().map(|owner| owner.address().as_array()), slots)
}
