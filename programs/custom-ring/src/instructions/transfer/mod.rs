//! `Transfer` and `AuthorityTransfer`, each settled inline or from a buffer.
//!
//! Read after `lib.rs`. Read before `instructions/transfer/processor.rs`.

mod accounts;
mod processor;
mod verify;

pub(crate) use processor::{process_transfer_ix, TransferRun};
