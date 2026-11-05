//! The policy tree's leaf, one member's list bits and mint settings, and the proof input of one write.
//!
//! Read after `program-libs/member-registry/src/tree.rs`, `program-libs/interface/src/accounts/member_registry.rs`.
//! Read before `prover/circuits/registry/apply_records.go`.
//!
//! Invariants, `ApplyRecordsCircuit` holds each.
//! 1. A write keeps every list bit outside its mask, and moves mint settings only under the entry's flag.
//! 2. A write that would leave a new member's record empty inserts nothing, the member stays absent and the root stays.

use custom_ring_interface::{
    write_chain, ApplyRecordsStatement, RecordWrite, FIELD_MAX, QUAD_HEIGHT,
};
use spr_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};
use zolana_ring_policy::MintPolicy;

use crate::{
    tree::{ApplyProofInputs, IndexedLeaf, WritableLeaf, WriteStep},
    QuadPath, RecordTreeError,
};

/// One authenticated leaf, including packed mint settings and its withdrawal threshold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberRecord {
    pub member: [u8; 32],
    pub next: [u8; 32],
    /// Bit `id - 1` marks list `id`.
    pub lists: u64,
    pub mint_policy: MintPolicy,
}

/// One write's proof input, mirror `RecordWriteProofInput` of
/// `prover/circuits/registry/apply_records.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordWriteProofInput {
    pub entry: RecordWrite,
    pub exists: bool,
    /// The old record's fields, an absent member reads its low record's `next` and nothing else.
    pub old_next: [u8; 32],
    pub old_lists: u64,
    pub old_mint_policy: MintPolicy,
    /// The record's leaf, an absent member's `next_index` leaf after the relink or low leaf when full.
    pub slot: QuadPath,
    /// An absent member's low record and its path before the relink, empty for a present member.
    pub low: MemberRecord,
    pub low_path: QuadPath,
}

impl MemberRecord {
    /// Leaf 0, every member sorts strictly between it and `FIELD_MAX`.
    pub const SENTINEL: Self = Self {
        member: [0; 32],
        next: FIELD_MAX,
        lists: 0,
        mint_policy: MintPolicy::EMPTY,
    };

    /// `Poseidon(member, next, lists, mint_policy, withdrawal_threshold, limits_0, limits_1, limits_2)`.
    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        let [limits_0, limits_1, limits_2] = self.mint_policy.limits.fields();
        Poseidon::hashv(&[
            &self.member,
            &self.next,
            &right_align(&self.lists.to_be_bytes()),
            &self.mint_policy.field(),
            &right_align(&self.mint_policy.withdrawal_threshold.to_be_bytes()),
            &limits_0,
            &limits_1,
            &limits_2,
        ])
    }

    /// List bits outside the mask keep their value.
    #[must_use]
    pub fn written(self, entry: &RecordWrite) -> Self {
        Self {
            lists: (self.lists & !entry.mask) | entry.value,
            mint_policy: entry.mint_policy.unwrap_or(self.mint_policy),
            ..self
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lists == 0 && self.mint_policy == MintPolicy::EMPTY
    }

    pub fn brackets(&self, member: &[u8; 32]) -> bool {
        self.member < *member && *member < self.next
    }
}

impl IndexedLeaf for MemberRecord {
    const SENTINEL: Self = Self::SENTINEL;
    const HEIGHT: usize = QUAD_HEIGHT;

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
        self.is_empty()
    }

    fn blank(member: [u8; 32], next: [u8; 32]) -> Self {
        Self {
            member,
            next,
            lists: 0,
            mint_policy: MintPolicy::EMPTY,
        }
    }
}

impl WritableLeaf<QUAD_HEIGHT> for MemberRecord {
    type Entry = RecordWrite;
    type WriteProof = RecordWriteProofInput;

    fn entry_member(entry: &RecordWrite) -> &[u8; 32] {
        &entry.member
    }

    fn check_entry(entry: &RecordWrite) -> Result<(), RecordTreeError> {
        check_member(&entry.member)?;
        if entry.value & !entry.mask != 0 {
            return Err(RecordTreeError::ValueOutsideMask);
        }
        Ok(())
    }

    fn chained(previous: &[u8; 32], entry: &RecordWrite) -> Result<[u8; 32], HasherError> {
        write_chain(previous, entry)
    }

    fn after(self, entry: &RecordWrite) -> Result<Self, RecordTreeError> {
        Ok(self.written(entry))
    }

    fn write_proof(
        entry: RecordWrite,
        step: WriteStep<Self, QUAD_HEIGHT>,
    ) -> RecordWriteProofInput {
        match step {
            WriteStep::Present { old, slot } => RecordWriteProofInput {
                entry,
                exists: true,
                old_next: old.next,
                old_lists: old.lists,
                old_mint_policy: old.mint_policy,
                slot,
                low: Self::default(),
                low_path: QuadPath::default(),
            },
            WriteStep::Absent {
                low,
                low_path,
                slot,
            } => RecordWriteProofInput {
                entry,
                exists: false,
                old_next: low.next,
                old_lists: 0,
                old_mint_policy: MintPolicy::EMPTY,
                slot,
                low,
                low_path,
            },
        }
    }
}

impl ApplyProofInputs<RecordWriteProofInput> {
    pub fn statement(&self) -> Result<ApplyRecordsStatement, RecordTreeError> {
        let index = |value: u64| u32::try_from(value).map_err(|_| RecordTreeError::IndexOutOfRange);
        Ok(ApplyRecordsStatement {
            old_root: self.old_root,
            new_root: self.new_root,
            old_next_index: index(self.old_next_index)?,
            new_next_index: index(self.new_next_index)?,
            chain_start: self.chain_start,
            chain_end: self.chain_end,
            count: self.writes.len() as u64,
        })
    }
}

pub(crate) fn check_member(member: &[u8; 32]) -> Result<(), RecordTreeError> {
    custom_ring_interface::check_member(member).map_err(|_| RecordTreeError::MemberOutOfRange)
}
