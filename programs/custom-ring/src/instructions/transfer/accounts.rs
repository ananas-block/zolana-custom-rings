use custom_ring_interface::{
    cosign::{CoSignDemand, CoSignRequirement},
    funder_account_position, AnonymousParties, CustomRingError, PublicSlots, RailSigner,
    RingPolicy, RingTransactData, RootRead, TransferRoots, ANONYMOUS_PARTIES,
    RING_TRANSACT_RING_CONFIG_INDEX, TRANSACT_PAYER_INDEX,
};
use pinocchio::{error::ProgramError, AccountView, Address};
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::instruction::instruction_data::settlement_accounts;

use crate::instructions::{
    instruction_runtime::{PlacedRingAuth, RingAuth},
    loader::{check_funding_signer, load_anonymous_exit, CoSignerSlot, RegistrySlots},
    public_legs::PublicLegs,
};

const RING_INDEX: usize = 0;

pub(super) struct TransactAccounts {
    pub roots: TransferRoots,
    /// The in-proof owner's identity, the sole owner signer's under a policy, zero otherwise.
    pub sender: [u8; 32],
    /// The anonymous rail's party identities, zeros on the other rails.
    pub party_identities: [[u8; 32]; ANONYMOUS_PARTIES],
    pub public_slots: PublicSlots,
    /// Empty off a policy.
    pub withdrawals: Vec<custom_ring_interface::PolicyWithdrawal>,
    /// Index of the first forwarded SPP account.
    pub spp: usize,
    pub ring_auth: PlacedRingAuth,
}

#[must_use]
pub(super) struct TransactCheck<'a> {
    pub program_id: &'a Address,
    pub ring: &'a RingPolicy,
    pub data: &'a RingTransactData<'a>,
    pub signer: RailSigner,
    pub slot: u64,
}

impl<'a> TransactCheck<'a> {
    /// The co-signer demand comes first, its slot moves the SPP list.
    #[inline(never)]
    pub fn validate(self, accounts: &[AccountView]) -> Result<TransactAccounts, ProgramError> {
        let (ring, data) = (self.ring, self.data);
        let registries = RegistrySlots {
            ring,
            read: RootRead::transfer(ring, data.exempt),
        }
        .load({
            let mut after_ring = accounts.iter().skip(RING_INDEX + 1);
            move || after_ring.next().ok_or(ProgramError::NotEnoughAccountKeys)
        })?;
        let roots = registries.roots(self.slot);
        let window = settlement_accounts(&data.interface_transfers, data.circuit(), accounts)
            .ok_or(CustomRingError::InvalidSettlementAccounts)?;
        let legs = PublicLegs::new(&data.interface_transfers, window)?;
        let demand = CoSignDemand::transact(data.approval_required, legs.legs());
        // The exempt bit is unverified here, the statement binds it and the gross per slot.
        let demand = match data.exempt {
            true => demand.exempt_withdrawals(),
            false => demand,
        };
        let requirement = demand.requirement(ring);
        let bound = data.roots(Some(ring).filter(|ring| ring.has_policy()), &roots)?;
        let prefix = self.prefix(
            RING_INDEX + 1 + registries.len,
            requirement.as_ref().ok().copied().flatten(),
        );

        let co_signer = prefix
            .co_signer
            .as_ref()
            .map(|slot| slot.signer(self.program_id, accounts))
            .transpose()?;
        let spp = accounts
            .get(prefix.spp..)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let ring_auth =
            RingAuth::derive(self.program_id)?.check_slot(spp, RING_TRANSACT_RING_CONFIG_INDEX)?;
        let payer = check_funding_signer(spp, TRANSACT_PAYER_INDEX)?;
        let sender = match prefix.signer {
            SignerSlot::Payer => {
                if spp
                    .iter()
                    .any(|account| account.is_signer() && account.address() != payer.address())
                {
                    return Err(CustomRingError::InvalidAnonymousSigner.into());
                }
                [0; 32]
            }
            SignerSlot::InProofOwner(owner) => {
                // The proof holds every spent note to the statement's sender, the framed owner names it on every ring.
                if !data.owner_signers(spp, window.len())?.is_empty() {
                    return Err(CustomRingError::OwnerSignerOnInProofRail.into());
                }
                if co_signer == Some(owner) {
                    return Err(CustomRingError::CoSignerIsOwner.into());
                }
                solana_owner_identity(owner.as_array()).map_err(CustomRingError::from)?
            }
            SignerSlot::Owners => {
                let owners = data.owner_signers(spp, window.len())?;
                if owners.iter().any(|owner| !owner.is_signer()) {
                    return Err(CustomRingError::MissingOwnerSigner.into());
                }
                let sender = match data.policy {
                    Some(_) => solana_owner_identity(sole_owner(owners)?.as_array())
                        .map_err(CustomRingError::from)?,
                    None => [0; 32],
                };
                if co_signer.is_some_and(|co_signer| {
                    owners.iter().any(|owner| owner.address() == &co_signer)
                }) {
                    return Err(CustomRingError::CoSignerIsOwner.into());
                }
                sender
            }
            SignerSlot::Delegate(slot) => {
                if !data.interface_transfers.is_empty() {
                    return Err(CustomRingError::DelegatePublicLeg.into());
                }
                let delegate = account_at(accounts, slot.index)?;
                if !delegate.is_signer() || delegate.address() != &slot.expected {
                    return Err(CustomRingError::UnauthorizedDelegate.into());
                }
                if co_signer == Some(slot.expected) {
                    return Err(CustomRingError::CoSignerIsDelegate.into());
                }
                [0; 32]
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
        let public_slots = legs.slots()?;
        let withdrawals = match data.policy {
            Some(policy) => custom_ring_interface::policy_withdrawals(
                &data.interface_transfers,
                &window
                    .iter()
                    .map(crate::instructions::loader::LoadedSettlement)
                    .collect::<Vec<_>>(),
                policy.spl_withdrawal_owners,
            )?,
            None => Vec::new(),
        };
        // SPP settles any exit, the anonymous rail leaves only to a destination that names one key.
        let party_identities = match self.signer {
            RailSigner::Payer => {
                let exit = load_anonymous_exit(&data.interface_transfers, window)?;
                let parties = AnonymousParties {
                    payer: payer.address().as_array(),
                    cosigner: co_signer.as_ref().map(Address::as_array),
                    exit_destination: exit.as_ref(),
                };
                parties.identities().map_err(CustomRingError::from)?
            }
            RailSigner::Owners | RailSigner::Delegate(_) => [[0; 32]; ANONYMOUS_PARTIES],
        };

        requirement?;
        Ok(TransactAccounts {
            roots: bound,
            sender,
            party_identities,
            public_slots,
            withdrawals,
            spp: prefix.spp,
            ring_auth,
        })
    }

    /// `first` follows the ring account and its registries.
    fn prefix(&self, first: usize, co_signer: Option<CoSignRequirement>) -> Prefix {
        let mut next = Cursor(first);
        let co_signer = co_signer.map(|requirement| next.pair(requirement));
        let signer = match (self.signer, self.data.in_proof_owner) {
            (RailSigner::Owners, Some(owner)) => {
                SignerSlot::InProofOwner(Address::new_from_array(*owner.owner))
            }
            (RailSigner::Owners, None) => SignerSlot::Owners,
            (RailSigner::Payer, _) => SignerSlot::Payer,
            (RailSigner::Delegate(expected), _) => SignerSlot::Delegate(next.slot(expected)),
        };
        Prefix {
            co_signer,
            signer,
            spp: next.0,
        }
    }
}

struct Slot<T> {
    index: usize,
    expected: T,
}

impl Slot<CoSignRequirement> {
    fn signer(
        &self,
        program_id: &Address,
        accounts: &[AccountView],
    ) -> Result<Address, ProgramError> {
        CoSignerSlot {
            program_id,
            record: account_at(accounts, self.index)?,
            signer: account_at(accounts, self.index + 1)?,
        }
        .verify(self.expected)
    }
}

enum SignerSlot {
    Owners,
    InProofOwner(Address),
    Payer,
    Delegate(Slot<Address>),
}

struct Prefix {
    /// The record, its signer next.
    co_signer: Option<Slot<CoSignRequirement>>,
    signer: SignerSlot,
    spp: usize,
}

struct Cursor(usize);

impl Cursor {
    fn slot<T>(&mut self, expected: T) -> Slot<T> {
        self.0 += 1;
        Slot {
            index: self.0 - 1,
            expected,
        }
    }

    fn pair<T>(&mut self, expected: T) -> Slot<T> {
        let slot = self.slot(expected);
        self.0 += 1;
        slot
    }
}

fn account_at(accounts: &[AccountView], index: usize) -> Result<&AccountView, ProgramError> {
    accounts
        .get(index)
        .ok_or(ProgramError::NotEnoughAccountKeys)
}

/// A policy transfer spends for exactly one owner, repeats of it are one signer.
fn sole_owner(owners: &[AccountView]) -> Result<&Address, CustomRingError> {
    let (first, rest) = owners
        .split_first()
        .ok_or(CustomRingError::OwnerSignerCount)?;
    if rest.iter().any(|owner| owner.address() != first.address()) {
        return Err(CustomRingError::OwnerSignerCount);
    }
    Ok(first.address())
}
