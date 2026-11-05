//! Permanent credentials enter SPP only through verified owner enrollment.
//!
//! Read after `instructions/accounts/loader.rs`.
//! Read before `instructions/enrollment/enroll.rs`.

mod enroll;
mod loader;

pub(crate) use enroll::process_enroll_ix;
