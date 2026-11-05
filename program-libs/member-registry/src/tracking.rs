//! The tracking tree's leaf, one indexed tree per ring holding every enrolled key.
//!
//! Read after `program-libs/member-registry/src/tree.rs`, `program-libs/interface/src/accounts/tracking.rs`.
//! Read before `prover/circuits/registry/tracking.go`, `prover/circuits/registry/apply_enrollments.go`.
//!
//! Invariants, `ApplyEnrollmentsCircuit` holds each.
//! 1. A rotation keeps the row's nullifier key, ciphertext hash and list tag.
//! 2. An insert takes the next empty leaf, so a full tree refuses a new owner while rotations still apply.

use custom_ring_interface::{
    domain,
    tracking::{TrackingEntry, TRACKING_QUAD_HEIGHT},
    ApplyEnrollmentsStatement, FIELD_MAX,
};
use spr_hasher::{
    primitives::{pack_be, right_align},
    Hasher, HasherError, Poseidon,
};

use crate::{
    memory::MemoryTree,
    record::check_member,
    record_pool::RecordPoolOf,
    tree::{ApplyProofInputs, IndexedLeaf, RecordOpening, WritableLeaf, WriteStep},
    RecordTreeError, TrackingPath,
};

/// One enrolled owner, a zero `nullifier_pk` marks the sentinel and an unwritten leaf.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrackingRecord {
    pub member: [u8; 32],
    pub next: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub ct_hash: [u8; 32],
    pub viewing_u: [u8; 32],
    pub revision: u64,
    pub list_tag: [u8; 32],
}

pub type TrackingTree = MemoryTree<TrackingRecord, TRACKING_QUAD_HEIGHT>;
pub type TrackingOpening = RecordOpening<TrackingRecord, TRACKING_QUAD_HEIGHT>;
pub type TrackingPool = RecordPoolOf<TrackingRecord>;

/// One entry's proof input, mirror `EnrollmentWrite` of
/// `prover/circuits/registry/apply_enrollments.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackingWriteProofInput {
    pub entry: TrackingEntry,
    pub exists: bool,
    /// A rotation's old leaf, an insert reads its low record's `next` and nothing else.
    pub old: TrackingRecord,
    /// The owner's leaf, an insert's `next_index` leaf after the relink.
    pub slot: TrackingPath,
    /// An insert's low record and its path before the relink, empty for a rotation.
    pub low: TrackingRecord,
    pub low_path: TrackingPath,
}

impl TrackingRecord {
    /// Leaf 0, every member sorts strictly between it and `FIELD_MAX`.
    pub const SENTINEL: Self = Self {
        member: [0; 32],
        next: FIELD_MAX,
        nullifier_pk: [0; 32],
        ct_hash: [0; 32],
        viewing_u: [0; 32],
        revision: 0,
        list_tag: [0; 32],
    };

    /// `Poseidon(CRTK, member, next, nullifier_pk, ct_hash, view0, view1, revision, list_tag)`, mirror
    /// `prover/circuits/registry/tracking.go`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let [view0, view1] = pack_be(&self.viewing_u);
        Poseidon::hashv(&[
            &domain::field(domain::TRACKING_LEAF),
            &self.member,
            &self.next,
            &self.nullifier_pk,
            &self.ct_hash,
            &view0,
            &view1,
            &right_align(&self.revision.to_be_bytes()),
            &self.list_tag,
        ])
    }

    pub fn brackets(&self, member: &[u8; 32]) -> bool {
        self.member < *member && *member < self.next
    }
}

impl IndexedLeaf for TrackingRecord {
    const SENTINEL: Self = Self::SENTINEL;
    const HEIGHT: usize = TRACKING_QUAD_HEIGHT;

    fn member(&self) -> &[u8; 32] {
        &self.member
    }

    fn next(&self) -> &[u8; 32] {
        &self.next
    }

    fn relinked(self, next: [u8; 32]) -> Self {
        Self { next, ..self }
    }

    fn leaf_hash(&self) -> Result<[u8; 32], HasherError> {
        self.hash()
    }

    fn is_blank(&self) -> bool {
        self.nullifier_pk == [0; 32]
    }

    fn blank(member: [u8; 32], next: [u8; 32]) -> Self {
        Self {
            member,
            next,
            ..Self::default()
        }
    }
}

impl WritableLeaf<TRACKING_QUAD_HEIGHT> for TrackingRecord {
    type Entry = TrackingEntry;
    type WriteProof = TrackingWriteProofInput;

    fn entry_member(entry: &TrackingEntry) -> &[u8; 32] {
        &entry.member
    }

    fn check_entry(entry: &TrackingEntry) -> Result<(), RecordTreeError> {
        check_member(&entry.member)?;
        if entry.nullifier_pk == [0; 32] {
            return Err(RecordTreeError::TrackingKeyChanged);
        }
        Ok(())
    }

    fn chained(previous: &[u8; 32], entry: &TrackingEntry) -> Result<[u8; 32], HasherError> {
        entry.chained(previous)
    }

    /// The nullifier key, ciphertext hash and list tag are final, the apply circuit holds them.
    fn after(self, entry: &TrackingEntry) -> Result<Self, RecordTreeError> {
        if !self.is_blank()
            && (self.nullifier_pk != entry.nullifier_pk
                || self.ct_hash != entry.ct_hash
                || self.list_tag != entry.list_tag)
        {
            return Err(RecordTreeError::TrackingKeyChanged);
        }
        Ok(Self {
            nullifier_pk: entry.nullifier_pk,
            ct_hash: entry.ct_hash,
            viewing_u: entry.viewing_u,
            revision: entry.revision,
            list_tag: entry.list_tag,
            ..self
        })
    }

    fn write_proof(
        entry: TrackingEntry,
        step: WriteStep<Self, TRACKING_QUAD_HEIGHT>,
    ) -> TrackingWriteProofInput {
        match step {
            WriteStep::Present { old, slot } => TrackingWriteProofInput {
                entry,
                exists: true,
                old,
                slot,
                low: Self::default(),
                low_path: TrackingPath::default(),
            },
            WriteStep::Absent {
                low,
                low_path,
                slot,
            } => TrackingWriteProofInput {
                entry,
                exists: false,
                old: Self::blank(entry.member, low.next),
                slot,
                low,
                low_path,
            },
        }
    }
}

impl ApplyProofInputs<TrackingWriteProofInput> {
    pub fn statement(&self) -> ApplyEnrollmentsStatement {
        ApplyEnrollmentsStatement {
            old_root: self.old_root,
            new_root: self.new_root,
            old_next_index: self.old_next_index,
            new_next_index: self.new_next_index,
            chain_start: self.chain_start,
            chain_end: self.chain_end,
            count: self.writes.len() as u64,
        }
    }
}
