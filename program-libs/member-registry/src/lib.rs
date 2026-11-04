//! The 4-ary indexed trees of a ring, one apply and one opening over any [`RecordStore`].

mod memory;
mod path;
mod record;
mod record_pool;
mod tracking;
mod tree;

use spr_hasher::HasherError;
use thiserror::Error;

pub use memory::{MemberRegistryTree, MemoryTree};
pub use path::{quad_node, NodePosition, QuadPath, QuadPathOf, TrackingPath, ZERO_SUBTREES};
pub use record::{MemberRecord, RecordWriteProofInput};
pub use record_pool::{Canopy, PoolSubject, RecordPool, RecordPoolOf, SharedPath, SharedProof};
pub use tracking::{
    TrackingOpening, TrackingPool, TrackingRecord, TrackingTree, TrackingWriteProofInput,
};
pub use tree::{
    ApplyProofInputs, IndexedLeaf, IndexedRecord, OpeningCheck, RecordOpening, RecordStore,
    RecordTree, WritableLeaf, WriteStep,
};

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RecordTreeError {
    #[error("record tree hashing failed")]
    Hashing,
    #[error("member lies outside the record range")]
    MemberOutOfRange,
    #[error("a queued list value leaves its mask")]
    ValueOutsideMask,
    #[error("the record tree is full")]
    Full,
    #[error("leaf index lies outside the tree")]
    IndexOutOfRange,
    #[error("the store holds no node at level {level} position {position}")]
    NodeMissing { level: usize, position: u64 },
    #[error("the store holds no record at index {0}")]
    RecordMissing(u64),
    #[error("the record at index {0} belongs to another member")]
    ForeignRecord(u64),
    #[error("the low record does not bracket the member")]
    NotBracketed,
    #[error("the path does not reach the root")]
    RootMismatch,
    #[error("the first record is not the sentinel")]
    MissingSentinel,
    #[error("a member holds two records")]
    DuplicateMember,
    #[error("the record pool exceeds its capacity")]
    PoolCapacity,
    #[error("the record pool proof has the wrong shape")]
    PoolShape,
    #[error("a tracking entry changes a final field or names a zero key")]
    TrackingKeyChanged,
}

impl From<HasherError> for RecordTreeError {
    fn from(_: HasherError) -> Self {
        Self::Hashing
    }
}
