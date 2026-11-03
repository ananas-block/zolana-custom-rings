use custom_ring_interface::{
    storage::{AddressAuthorization, FirstEnrollment, StorageError, StorageRegistry},
    storage_instruction::{EnrollAddressIxData, InitializeIxData},
};
use pinocchio::{
    account::{Ref, RefMut},
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};

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
        let bump = [bump];
        let [seed, creator, registry_id] = seeds;
        let signer_seeds = [
            Seed::from(seed),
            Seed::from(creator),
            Seed::from(registry_id),
            Seed::from(&bump),
        ];
        pinocchio_system::create_account_with_minimum_balance_signed(
            account,
            StorageRegistry::SIZE,
            self.program_id,
            self.payer,
            None,
            &[Signer::from(signer_seeds.as_slice())],
        )?;
        account
            .try_borrow_mut()?
            .copy_from_slice(bytemuck::bytes_of(&StorageRegistry::new(
                *self.creator,
                self.ix,
            )));
        Ok(())
    }
}

/// One enrollment of `owner`, whose signature the processor checked.
#[must_use]
pub struct AddressEnrollment<'a> {
    pub program_id: &'a Address,
    pub payer: &'a AccountView,
    pub owner: &'a Address,
    pub registry: &'a Address,
    pub ring_id: [u8; 32],
    pub ix: &'a EnrollAddressIxData,
}

impl AddressEnrollment<'_> {
    /// Creates the authorization at revision 1, a later call rotates its viewing key.
    #[inline(always)]
    pub fn write(self, account: &mut AccountView) -> ProgramResult {
        let seeds = AddressAuthorization::seeds(self.registry, self.owner);
        let (address, bump) = Address::derive_program_address(&seeds, self.program_id)
            .ok_or(StorageError::InvalidAddressAuthorization)?;
        if account.address() != &address || !account.is_writable() {
            return Err(StorageError::InvalidAddressAuthorization.into());
        }
        if account.data_len() != 0 {
            let mut existing = load_owned_authorization_mut(self.program_id, account)?;
            return existing.enroll(self.ix).map_err(Into::into);
        }
        let bump_seed = [bump];
        let [seed, registry, owner] = seeds;
        let signer_seeds = [
            Seed::from(seed),
            Seed::from(registry),
            Seed::from(owner),
            Seed::from(&bump_seed),
        ];
        pinocchio_system::create_account_with_minimum_balance_signed(
            account,
            AddressAuthorization::SIZE,
            self.program_id,
            self.payer,
            None,
            &[Signer::from(signer_seeds.as_slice())],
        )?;
        let first = FirstEnrollment {
            registry: *self.registry,
            owner: *self.owner,
            bump,
            ring_id: self.ring_id,
            ix: self.ix,
        }
        .account();
        account
            .try_borrow_mut()?
            .copy_from_slice(bytemuck::bytes_of(&first));
        Ok(())
    }
}

#[inline(always)]
pub fn load_registry<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, StorageRegistry>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(StorageError::InvalidRegistry.into());
    }
    Ref::filter_map(account.try_borrow()?, StorageRegistry::from_data)
        .map_err(|_| StorageError::InvalidRegistry.into())
}

/// `owner`'s authorization on `registry`, the derivation names both.
#[inline(always)]
pub fn load_authorization_mut<'a>(
    program_id: &Address,
    registry: &Address,
    owner: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, AddressAuthorization>, ProgramError> {
    let (address, _) =
        Address::derive_program_address(&AddressAuthorization::seeds(registry, owner), program_id)
            .ok_or(StorageError::InvalidAddressAuthorization)?;
    if account.address() != &address || !account.is_writable() {
        return Err(StorageError::InvalidAddressAuthorization.into());
    }
    load_owned_authorization_mut(program_id, account)
}

#[inline(always)]
fn load_owned_authorization_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, AddressAuthorization>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(StorageError::InvalidAddressAuthorization.into());
    }
    RefMut::filter_map(
        account.try_borrow_mut()?,
        AddressAuthorization::from_data_mut,
    )
    .map_err(|_| StorageError::InvalidAddressAuthorization.into())
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
