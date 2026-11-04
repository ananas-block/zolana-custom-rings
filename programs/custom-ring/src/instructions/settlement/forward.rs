use custom_ring_interface::{
    cosign::CoSignDemand, merge_ring_instruction_data, ring_deposit_assets, CustomRingError,
    CustomRingMergeIxDataRef, DepositRegistry, RingMode, RootRead, RING_DEPOSIT_DEPOSITOR_INDEX,
    RING_DEPOSIT_RING_CONFIG_INDEX, RING_MERGE_PAYER_INDEX, RING_MERGE_RING_CONFIG_INDEX,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;

use crate::instructions::{
    deposit_audit::{AuditedDeposit, DepositVerification},
    instruction_runtime::RingAuth,
    loader::{
        check_funding_signer, load_policy, validate_spp_program, CoSignerSlot, RegistrySlots,
    },
    merge_disclosure::MergeAudit,
};

#[inline(never)]
pub fn process_merge_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let request = CustomRingMergeIxDataRef::from_bytes(data)?;

    let mut iter = AccountIterator::new(accounts);
    let ring = load_policy(program_id, iter.next_account("ring")?)?;
    let mode = ring.mode()?;
    let registries = RegistrySlots {
        ring: &ring,
        read: RootRead::merge(),
    }
    .load(|| Ok(iter.next_account("registry")?))?;
    // 1. A merge runs no rules and binds no policy root.
    let root = registries.roots(Clock::get()?.slot).own_if_read(
        request.own_revision,
        CustomRingError::UnexpectedMemberRegistryRoot,
    )?;
    // 2. The ring PDA sits in its SPP slot alone and the payer SPP debits signs.
    let spp_accounts = iter.remaining()?;
    let ring_auth =
        RingAuth::derive(program_id)?.check_slot(spp_accounts, RING_MERGE_RING_CONFIG_INDEX)?;
    check_funding_signer(spp_accounts, RING_MERGE_PAYER_INDEX)?;

    // 3. A bad SPP proof point is refused before the disclosure pairing.
    let spp_body = request.spp_merge_body()?;
    // 4. The disclosure proves the input hashes to the auditor, a co-signer never stops a merge.
    let parties = [
        solana_owner_identity(spp_accounts[RING_MERGE_PAYER_INDEX].address().as_array())
            .map_err(CustomRingError::from)?,
        [0; 32],
        [0; 32],
    ];
    MergeAudit {
        party_identities: &parties,
        program_id,
        ring: &ring,
        anonymous: mode == RingMode::Anonymous,
        member_registry_root: root.as_ref(),
        output_ring_data_hash: request.output_ring_data_hash,
        disclosure: request.disclosure,
        spp_body: &spp_body,
    }
    .verify()?;
    // 5. SPP verifies its merge proof over the ring data hash the ring selects.
    let forwarded = merge_ring_instruction_data(request.output_ring_data_hash, &spp_body);
    validate_spp_program(spp_accounts)?;
    ring_auth.invoke(spp_accounts, &forwarded)
}

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
    let mode = ring.mode()?;
    let registries = RegistrySlots {
        ring: &ring,
        read: RootRead::deposit(&ring),
    }
    .load(|| Ok(iter.next_account("registry")?))?;
    let roots = registries.roots(Clock::get()?.slot);
    // 2. Every deposit binds the tracking root, a policy ring also its own root, its policy and any curator root.
    let tracking_root = roots.tracking(audited.tracking_revision)?;
    let own_root = roots.own_if_read(
        audited.own_revision,
        CustomRingError::UnexpectedMemberRegistryRoot,
    )?;
    let curator_root = roots.curator_if_read(
        audited.curator_revision,
        CustomRingError::UnexpectedCuratorRevision,
    )?;
    let registry = own_root.as_ref().map(|own_root| DepositRegistry {
        own_root,
        curator_root: curator_root.as_ref(),
        policy_hash: ring.written_policy_hash(),
    });
    // 3. One record covering the deposit class signs when the ring configured one.
    let requirement = CoSignDemand::DEPOSIT.requirement(&ring)?;
    if !requirement.is_satisfied() {
        CoSignerSlot {
            program_id,
            record: iter.next_account("co_signer_record")?,
            signer: iter.next_account("co_signer")?,
        }
        .verify(requirement)?
        .0
        .check_satisfied()?;
    }
    let spp_accounts = iter.remaining()?;
    let anonymous = mode == RingMode::Anonymous;
    // 4. The ring PDA sits in its SPP slot alone and the depositor SPP debits signs.
    let ring_auth =
        RingAuth::derive(program_id)?.check_slot(spp_accounts, RING_DEPOSIT_RING_CONFIG_INDEX)?;
    check_funding_signer(spp_accounts, RING_DEPOSIT_DEPOSITOR_INDEX)?;

    // 5. The proof binds the SPP data, target tree and assets, the auditor opens every output.
    let tree = spp_accounts
        .first()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let assets = ring_deposit_assets(&deposit, |index| {
        spp_accounts
            .get(index)
            .map(|account| account.address().to_bytes())
    })?;
    DepositVerification {
        program_id,
        tree: tree.address(),
        auditor_pubkey: &ring.auditor_pubkey,
        anonymous,
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
