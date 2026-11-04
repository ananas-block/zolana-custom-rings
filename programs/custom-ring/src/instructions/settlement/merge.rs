use custom_ring_interface::{
    key_catalog::RingCircuit, CustomRingError, CustomRingMergeIxDataRef, MergePublicInput,
    RootRead, RING_MERGE_OWNER_INDEX, RING_MERGE_PAYER_INDEX, RING_MERGE_RING_CONFIG_INDEX,
    VIEWING_PUBKEY_TAG,
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::instruction::instruction_data::{
    merge_ring::MergeRingAuthority, merge_transact::MergeTransactIxDataRef,
};
use zolana_ring_policy::ring_id_field;

use crate::instructions::{
    instruction_runtime::RingAuth,
    loader::{check_funding_signer, load_policy, validate_spp_program, RegistrySlots},
    verifier::{ring_key, RingProof},
};

/// SPP proves that owner, asset and sum stay unchanged, the ring proves the auditor opens the result.
#[inline(never)]
pub fn process_merge_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let request = CustomRingMergeIxDataRef::from_bytes(data)?;

    let mut iter = AccountIterator::new(accounts);
    let ring = load_policy(program_id, iter.next_account("ring")?)?;
    // 1. A merge runs no rules, a restrictive policy update cannot fail it.
    let registries = RegistrySlots {
        ring: &ring,
        read: RootRead::merge(),
    }
    .load(|| Ok(iter.next_account("registry")?))?;
    // 2. The ring PDA sits in its SPP slot alone and the payer SPP debits signs.
    let spp_accounts = iter.remaining()?;
    let ring_auth =
        RingAuth::derive(program_id)?.check_slot(spp_accounts, RING_MERGE_RING_CONFIG_INDEX)?;
    check_funding_signer(spp_accounts, RING_MERGE_PAYER_INDEX)?;
    if request.eph_pk[0] != VIEWING_PUBKEY_TAG {
        return Err(CustomRingError::InvalidMergeDisclosure.into());
    }
    // 3. A nonzero key reads its row, a zero key names the owner SPP makes sign.
    let (tracking_root, published_owner) = match request.authority {
        MergeRingAuthority::Ring => (
            registries
                .roots(Clock::get()?.slot)
                .tracking(request.tracking_revision)?,
            [0; 32],
        ),
        MergeRingAuthority::OwnerSigned => {
            let owner = spp_accounts
                .get(RING_MERGE_OWNER_INDEX)
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            let identity =
                solana_owner_identity(owner.address().as_array()).map_err(CustomRingError::from)?;
            ([0; 32], identity)
        }
    };
    // 4. A bad SPP proof point is refused before the record pairing.
    let spp_body = request.spp_merge_body()?;
    let merge = MergeTransactIxDataRef::from_bytes(&spp_body)
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    let first_nullifier = merge
        .nullifiers
        .first()
        .ok_or(CustomRingError::InvalidInstructionData)?;
    let payer = solana_owner_identity(spp_accounts[RING_MERGE_PAYER_INDEX].address().as_array())
        .map_err(CustomRingError::from)?;
    let statement = MergePublicInput {
        output_utxo_hash: merge.output_utxo_hash,
        first_nullifier,
        ring_id: &ring_id_field(program_id.as_array()).map_err(CustomRingError::from)?,
        auditor_pk: &ring.auditor_pubkey,
        eph_pk: request.eph_pk,
        ciphertext: request.ciphertext,
        payer: &payer,
        published_owner: &published_owner,
        tracking_root: &tracking_root,
    }
    .hash()
    .map_err(CustomRingError::from)?;
    RingProof {
        proof: request.proof,
        statement,
        key: ring_key(RingCircuit::Merge)?,
    }
    .verify()?;
    // 5. SPP's proof binds the output ciphertext, the ring data hash and the published owner.
    let forwarded = request.forwarded(&spp_body);
    validate_spp_program(spp_accounts)?;
    ring_auth.invoke(spp_accounts, &forwarded)
}
