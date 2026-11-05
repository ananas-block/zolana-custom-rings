//! One processor per instruction tag of the Storage program.
//!
//! Read after `programs/storage/src/lib.rs`. Read before `programs/storage/src/instructions/update.rs`,
//! `programs/storage/src/instructions/owner_grant.rs`.

mod initialize;
mod owner_grant;
mod update;
mod update_authority;

pub use initialize::process_initialize_ix;
pub use owner_grant::process_owner_grant_ix;
pub use update::process_update_ix;
pub use update_authority::process_update_authority_ix;
