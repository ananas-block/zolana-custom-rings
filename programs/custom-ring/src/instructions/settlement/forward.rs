//! Verifies a ring deposit and forwards SPP's deposit data unchanged.
//!
//! SPP verifies no proof on a deposit. It appends the owner commitment the data names, whatever that
//! commitment opens to. The ring proof alone shows the auditor opens each commitment and its owner meets tracking and the rules.
//!
//! The instruction guarantees:
//!
//! 1. The statement covers the program id, the target tree, every SPP data byte and each deposited mint.
//! 2. The tracking root comes from the ring's pin, and a policy ring also binds its own root, its policy and any curator root.
//! 3. A record covering the deposit class signs when the ring configured one.
//! 4. `ring_auth` sits only in SPP's `ring_config` slot, and the depositor signs.
//!
//! The instruction relies on SPP for the debit, the settlement accounts of each asset group, and the
//! activation and pause of `RingConfig`.
//!
//! Read after `instructions/accounts/loader.rs`. Read before `instructions/settlement/deposit_audit.rs`.

use custom_ring_interface::{
    cosign::CoSignDemand, ring_deposit_assets, CustomRingError, DepositRegistry, RootRead,
    RING_DEPOSIT_DEPOSITOR_INDEX, RING_DEPOSIT_RING_CONFIG_INDEX,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use spr_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::instructions::{
    deposit_audit::{AuditedDeposit, DepositVerification},
    instruction_runtime::RingAuth,
    loader::{
        check_funding_signer, load_policy, validate_spp_program, CoSignerSlot, RegistrySlots,
    },
};

#[inline(never)]
pub fn process_deposit_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    // 1. The proof prefix leads SPP's own deposit data, forwarded unchanged.
    let audited = AuditedDeposit::parse(data)?;
    let deposit = RingDepositIxDataRef::from_bytes(audited.spp_data.get(1..).unwrap_or_default())
        .map_err(|_| CustomRingError::InvalidDepositData)?;

    let mut iter = AccountIterator::new(accounts);
    let ring = load_policy(program_id, iter.next_account("ring")?)?;
    let registries = RegistrySlots {
        ring: &ring,
        read: RootRead::deposit(&ring),
    }
    .load(|| Ok(iter.next_account("registry")?))?;
    let roots = registries.roots(Clock::get()?.slot);
    // 2. Every deposit binds the tracking root, a policy ring also its own root, its policy and any curator root.
    // A revision the ring does not read must be zero, a frame names no unbound registry.
    let tracking_root = roots.tracking(audited.tracking_revision)?;
    let own_root = roots.own_if_read(
        audited.own_revision,
        CustomRingError::UnexpectedMemberRegistryRoot,
    )?;
    let curator_root = roots.curator_if_read(
        audited.curator_revision,
        CustomRingError::UnexpectedCuratorRevision,
    )?;
    let registry = own_root
        .as_ref()
        .map(|own_root| {
            Ok::<_, CustomRingError>(DepositRegistry {
                own_root,
                curator_root: curator_root.as_ref(),
                policy_hash: ring.policy_hash()?,
            })
        })
        .transpose()?;
    // 3. One record covering the deposit class signs when the ring configured one.
    if let Some(requirement) = CoSignDemand::DEPOSIT.requirement(&ring) {
        let _one_class = CoSignerSlot {
            program_id,
            record: iter.next_account("co_signer_record")?,
            signer: iter.next_account("co_signer")?,
        }
        .verify(requirement)?;
    }
    let spp_accounts = iter.remaining()?;
    // 4. The ring PDA sits in its SPP slot alone and the depositor SPP debits signs.
    let ring_auth =
        RingAuth::derive(program_id)?.check_slot(spp_accounts, RING_DEPOSIT_RING_CONFIG_INDEX)?;
    check_funding_signer(spp_accounts, RING_DEPOSIT_DEPOSITOR_INDEX)?;

    // 5. The proof binds the SPP data, target tree and assets, the auditor opens every output.
    let tree = spp_accounts
        .first()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    // The mints come from SPP's list at SPP's stride, the circuit screens the assets SPP deposits.
    let assets = ring_deposit_assets(&deposit, |index| {
        spp_accounts
            .get(index)
            .map(|account| account.address().to_bytes())
    })?;
    DepositVerification {
        program_id,
        tree: tree.address(),
        auditor_pubkey: &ring.auditor_pubkey,
        tracking_root: &tracking_root,
        registry,
        assets: &assets,
        audited: &audited,
        deposit: &deposit,
    }
    .verify()?;
    // 6. SPP runs the deposit the proof bound, signed by the ring PDA.
    validate_spp_program(spp_accounts)?;
    ring_auth.invoke(spp_accounts, audited.spp_data)
}
