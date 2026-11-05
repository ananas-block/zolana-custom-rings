//! Account access of the Storage program, each account an instruction reads or writes loads here.
//!
//! Read after `programs/storage/src/lib.rs`, `program-libs/interface/src/accounts/storage.rs`,
//! `program-libs/interface/src/accounts/owner_grant.rs`. Read before
//! `programs/storage/src/instructions/update.rs`, `programs/storage/src/instructions/owner_grant.rs`.
//!
//! Guarantees:
//! 1. A registry or grant loads only when the program owns it, at its exact size and under its discriminator.
//! 2. A created account takes its canonical bump from the derivation, never from instruction data.
//!
//! Relies on:
//! 1. The processor checks the signature of each creator or owner a seed names, ahead of its `init` or `write`.

use custom_ring_interface::{
    owner_grant::OwnerGrant,
    storage::{StorageError, StorageRegistry},
    storage_instruction::{InitializeIxData, OwnerGrantIxData},
};
use pinocchio::{
    account::RefMut,
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};

/// Seeds of the longest PDA here and its bump.
const MAX_SIGNER_SEEDS: usize = 6;

#[must_use]
pub struct RegistryInit<'a> {
    pub program_id: &'a Address,
    pub payer: &'a AccountView,
    pub creator: &'a Address,
    pub ix: &'a InitializeIxData,
}

impl RegistryInit<'_> {
    #[inline(always)]
    pub fn init(self, account: &mut AccountView) -> ProgramResult {
        let seeds = StorageRegistry::seeds(self.creator, &self.ix.registry_id);
        let (address, bump) = Address::derive_program_address(&seeds, self.program_id)
            .ok_or(StorageError::InvalidRegistry)?;
        if account.address() != &address {
            return Err(StorageError::InvalidRegistry.into());
        }
        check_writable(account)?;
        if account.data_len() != 0 {
            return Err(StorageError::AlreadyInitialized.into());
        }
        CanonicalPda {
            program_id: self.program_id,
            payer: self.payer,
            seeds: &seeds,
            bump,
            size: StorageRegistry::SIZE,
        }
        .create(account)?;
        account
            .try_borrow_mut()?
            .copy_from_slice(bytemuck::bytes_of(&StorageRegistry::new(
                *self.creator,
                self.ix,
            )));
        Ok(())
    }
}

/// One owner's consent to one reader, whose signature the processor checked.
#[must_use]
pub struct OwnerGrantWrite<'a> {
    pub program_id: &'a Address,
    pub payer: &'a AccountView,
    pub owner: &'a Address,
    pub ix: &'a OwnerGrantIxData,
}

impl OwnerGrantWrite<'_> {
    /// Creates the grant, a later call changes only whether it is active.
    #[inline(always)]
    pub fn write(self, account: &mut AccountView) -> ProgramResult {
        let seeds = OwnerGrant::seeds(&self.ix.ring_program, self.owner, &self.ix.reader);
        let (address, bump) = Address::derive_program_address(&seeds, self.program_id)
            .ok_or(StorageError::InvalidOwnerGrant)?;
        // The derivation names the owner, whose signature the processor checked.
        if account.address() != &address || !account.is_writable() {
            return Err(StorageError::InvalidOwnerGrant.into());
        }
        if account.data_len() != 0 {
            if !account.owned_by(self.program_id) {
                return Err(StorageError::InvalidOwnerGrant.into());
            }
            let mut grant =
                RefMut::filter_map(account.try_borrow_mut()?, OwnerGrant::from_data_mut)
                    .map_err(|_| StorageError::InvalidOwnerGrant)?;
            grant.active = self.ix.active;
            return Ok(());
        }
        CanonicalPda {
            program_id: self.program_id,
            payer: self.payer,
            seeds: &seeds,
            bump,
            size: OwnerGrant::SIZE,
        }
        .create(account)?;
        let grant = OwnerGrant {
            discriminator: OwnerGrant::DISCRIMINATOR,
            active: self.ix.active,
        };
        account
            .try_borrow_mut()?
            .copy_from_slice(bytemuck::bytes_of(&grant));
        Ok(())
    }
}

#[inline(always)]
pub fn load_registry_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, StorageRegistry>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(StorageError::InvalidRegistry.into());
    }
    check_writable(account)?;
    RefMut::filter_map(account.try_borrow_mut()?, StorageRegistry::from_data_mut)
        .map_err(|_| StorageError::InvalidRegistry.into())
}

#[inline(always)]
pub fn check_authority(registry: &StorageRegistry, authority: &AccountView) -> ProgramResult {
    if authority.address() != &registry.authority {
        return Err(StorageError::Unauthorized.into());
    }
    Ok(())
}

#[inline(always)]
pub fn check_signer(account: &AccountView) -> Result<(), StorageError> {
    match account.is_signer() {
        true => Ok(()),
        false => Err(StorageError::MissingSignature),
    }
}

#[inline(always)]
fn check_writable(account: &AccountView) -> Result<(), StorageError> {
    match account.is_writable() {
        true => Ok(()),
        false => Err(StorageError::ReadOnlyRegistry),
    }
}

/// Handles a donated balance, `seeds` and `bump` come from the caller's derivation.
#[must_use]
struct CanonicalPda<'a> {
    program_id: &'a Address,
    payer: &'a AccountView,
    seeds: &'a [&'a [u8]],
    bump: u8,
    size: usize,
}

impl CanonicalPda<'_> {
    #[inline(always)]
    fn create(self, account: &mut AccountView) -> ProgramResult {
        let bump = [self.bump];
        // The slot past the last seed keeps the bump, the slice below ends on it.
        let mut signer_seeds: [Seed; MAX_SIGNER_SEEDS] =
            core::array::from_fn(|_| Seed::from(&bump));
        for (slot, seed) in signer_seeds.iter_mut().zip(self.seeds) {
            *slot = Seed::from(*seed);
        }
        pinocchio_system::create_account_with_minimum_balance_signed(
            account,
            self.size,
            self.program_id,
            self.payer,
            None,
            &[Signer::from(&signer_seeds[..=self.seeds.len()])],
        )
    }
}
