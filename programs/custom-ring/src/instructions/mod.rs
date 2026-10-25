mod apply_records;
mod authority_write_records;
mod create_config;
mod create_member_registry;
mod create_policy;
mod deposit_audit;
mod forward;
mod init_spp_ring_config;
mod insert_fee;
#[path = "runtime/instruction_runtime.rs"]
mod instruction_runtime;
#[path = "accounts/loader.rs"]
mod loader;
mod merge_disclosure;
#[path = "verification/policy_binding.rs"]
mod policy_binding;
#[path = "verification/public_legs.rs"]
mod public_legs;
mod read_access;
mod register_key;
mod set_authority;
mod set_cosigner;
mod set_delegate;
mod set_insert_fee;
mod set_paused;
mod set_policy_rules;
mod set_policy_source;
mod transact;
#[path = "verification/verifier.rs"]
mod verifier;
mod write_records;

pub(crate) use apply_records::process_apply_records_ix;
pub(crate) use authority_write_records::process_authority_write_records_ix;
pub(crate) use create_config::process_create_config_ix;
pub(crate) use create_member_registry::process_create_member_registry_ix;
pub(crate) use create_policy::process_create_policy_ix;
pub(crate) use forward::{process_audited_deposit_ix, process_merge_ix};
pub(crate) use init_spp_ring_config::process_init_spp_ring_config_ix;
pub(crate) use read_access::{process_grant_read_access_ix, process_revoke_read_access_ix};
pub(crate) use register_key::process_register_key_ix;
pub(crate) use set_authority::process_set_authority_ix;
pub(crate) use set_cosigner::{process_clear_cosigner_ix, process_set_cosigner_ix};
pub(crate) use set_delegate::process_set_delegate_ix;
pub(crate) use set_insert_fee::process_set_insert_fee_ix;
pub(crate) use set_paused::process_set_paused_ix;
pub(crate) use set_policy_rules::process_set_policy_rules_ix;
pub(crate) use set_policy_source::process_set_policy_source_ix;
pub(crate) use transact::process_transact_ix;
pub(crate) use write_records::process_write_records_ix;
