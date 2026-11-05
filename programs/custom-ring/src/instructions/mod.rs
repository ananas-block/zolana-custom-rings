//! The instruction processors, grouped on disk by layer under one flat module namespace.
//!
//! Read after `lib.rs`. Read before `instructions/transfer/processor.rs`.

#[path = "settlement/deposit_audit.rs"]
mod deposit_audit;
mod enrollment;
#[path = "settlement/forward.rs"]
mod forward;
#[path = "settlement/frame_buffer.rs"]
mod frame_buffer;
#[path = "configuration/setup/initialize.rs"]
mod initialize;
#[path = "runtime/instruction_runtime.rs"]
mod instruction_runtime;
#[path = "accounts/loader.rs"]
mod loader;
#[path = "settlement/merge.rs"]
mod merge;
#[path = "verification/policy_binding.rs"]
mod policy_binding;
#[path = "verification/public_legs.rs"]
mod public_legs;
#[path = "configuration/access/set_cosigner.rs"]
mod set_cosigner;
#[path = "configuration/access/set_delegate.rs"]
mod set_delegate;
#[path = "configuration/access/set_paused.rs"]
mod set_paused;
mod transfer;
#[path = "configuration/access/update_authority.rs"]
mod update_authority;
#[path = "configuration/policy/update_policy.rs"]
mod update_policy;
#[path = "verification/verifier.rs"]
mod verifier;

pub(crate) use enrollment::process_enroll_ix;
pub(crate) use forward::process_deposit_ix;
pub(crate) use frame_buffer::{
    process_close_frame_buffer_ix, process_settle_buffered_ix, process_write_frame_ix,
};
pub(crate) use initialize::process_initialize_ix;
pub(crate) use merge::process_merge_ix;
pub(crate) use set_cosigner::{process_clear_cosigner_ix, process_set_cosigner_ix};
pub(crate) use set_delegate::process_set_delegate_ix;
pub(crate) use set_paused::process_set_paused_ix;
pub(crate) use transfer::{process_transfer_ix, TransferRun};
pub(crate) use update_authority::process_update_authority_ix;
pub(crate) use update_policy::process_update_policy_ix;
