//! Creates an immutable audit credential from the owner's verified auditor envelope.
//!
//! SPP authenticates compressed state ownership. RegisterKey binds the ring, member,
//! nullifier key and list tag to the exact envelope the auditor can open.
//! Only enrollment signs for the credential PDA, and it reserves the canonical address.
//! No instruction spends a credential, so state inclusion remains sufficient for later reads.
//!
//! Read after `program-libs/interface/src/accounts/credential.rs` and
//! `instructions/enrollment/loader.rs`.
//! Read before `prover/circuits/policy/credentials.go`.

use custom_ring_interface::{
    credential::{Enrollment, CREDENTIAL_PDA_SEED},
    enrollment::EnrollRequest,
    CustomRingError, RegisterKeyCheck,
};
use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, Address, ProgramResult,
};
use spr_interface::instruction::instruction_data::transact::{TreeContext, NO_UTXO_ROOT};
use spr_program::{
    cpi::SppTransactAccounts,
    program::{SppTransactCpi, UniqueDataUtxo},
};
use zolana_ring_policy::ring_id_field;

use super::loader::EnrollmentAccounts;

#[inline(never)]
pub fn process_enroll_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let request = EnrollRequest::parse(data)?;
    // 1. The owner authorizes enrollment, the payer only funds the address reservation.
    let accounts = EnrollmentAccounts::load(program_id, accounts)?;
    let ring_id = ring_id_field(program_id.as_array()).map_err(CustomRingError::from)?;
    // 2. The authenticated ring and owner supply the identity and auditor key to RegisterKey.
    let credential = Enrollment {
        ring_id: &ring_id,
        auditor_pubkey: &accounts.auditor_pubkey,
        owner: &accounts.owner,
        ix: request.ix,
    }
    .credential()?;
    RegisterKeyCheck {
        credential: &credential,
        proof: request.register_key,
    }
    .verify()?;
    // 3. CRCA binds the address to ring and member, CRCR binds the exact verified credential.
    let mut output = UniqueDataUtxo::new_init(
        &accounts.credential_owner,
        credential.seed()?,
        TreeContext {
            utxo_tree_root_index: NO_UTXO_ROOT,
            nullifier_tree_root_index: request.address_root_index,
        },
    )?;
    *output = credential;
    let transact = SppTransactCpi::new(request.transact).with_unique_data_utxo(output)?;
    // 4. SPP receives only the derived output, a failed proof reverts its address reservation.
    let signer_pdas = [accounts.credential_owner.pda()];
    let spp = SppTransactAccounts::new(accounts.transact, &signer_pdas)?;
    let bump = [accounts.credential_bump];
    let seeds = [Seed::from(CREDENTIAL_PDA_SEED), Seed::from(&bump)];
    transact.invoke::<7>(&spp, &[Signer::from(&seeds)])
}
