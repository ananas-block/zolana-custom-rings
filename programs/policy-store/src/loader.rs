use custom_ring_interface::policy_store::{PolicyStoreError, Registry};
use pinocchio::{
    account::{Ref, RefMut},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};

#[inline(always)]
pub fn init_registry(account: &mut AccountView, registry: &Registry) -> ProgramResult {
    let mut data = account.try_borrow_mut()?;
    if data.len() != Registry::SIZE {
        return Err(PolicyStoreError::InvalidRegistry.into());
    }
    data.copy_from_slice(bytemuck::bytes_of(registry));
    Ok(())
}

#[inline(always)]
pub fn load_registry<'a>(
    program_id: &Address,
    account: &'a AccountView,
) -> Result<Ref<'a, Registry>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(PolicyStoreError::InvalidRegistry.into());
    }
    Ref::filter_map(account.try_borrow()?, Registry::from_data)
        .map_err(|_| PolicyStoreError::InvalidRegistry.into())
}

#[inline(always)]
pub fn load_registry_mut<'a>(
    program_id: &Address,
    account: &'a mut AccountView,
) -> Result<RefMut<'a, Registry>, ProgramError> {
    if !account.owned_by(program_id) {
        return Err(PolicyStoreError::InvalidRegistry.into());
    }
    RefMut::filter_map(account.try_borrow_mut()?, Registry::from_data_mut)
        .map_err(|_| PolicyStoreError::InvalidRegistry.into())
}
