//! The `HashChain4` public input of the transfer, apply and register key proofs.

use spr_hasher::{
    hash_chain::{create_hash_chain_4, create_hash_chain_4_from_slice},
    primitives::{hash_bytes, pack_be, right_align, solana_owner_identity},
    Hasher, HasherError, Poseidon,
};
use spr_interface::N_PUBLIC_SLOTS;

use crate::{
    anonymous_exit::ANONYMOUS_PARTIES,
    cosign::ApprovalMask,
    disclosure::{pack_disclosure, AuditLayout},
    domain,
    error::CustomRingError,
    tagged_x25519,
    transact::RingOutput,
    REGISTER_KEY_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};

const ZERO_FIELD: [u8; 32] = [0; 32];

/// `[CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, envelope_digest, salt, layout]`.
pub const AUDIT_HEAD_ELEMENTS: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditHead<'a> {
    pub first_nullifier: &'a [u8; 32],
    /// `hash_bytes` of the ring program id.
    pub ring_id: &'a [u8; 32],
    pub tx_viewing_u: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub envelope: &'a [u8],
    pub salt: &'a [u8; 16],
    pub layout: AuditLayout,
}

impl AuditHead<'_> {
    fn elements_under(
        &self,
        statement: u32,
    ) -> Result<[[u8; 32]; AUDIT_HEAD_ELEMENTS], HasherError> {
        let [tx0, tx1] = pack_be(&tagged_x25519(self.tx_viewing_u));
        let [aud0, aud1] = pack_be(self.auditor_pubkey);
        Ok([
            domain::field(statement),
            *self.first_nullifier,
            *self.ring_id,
            tx0,
            tx1,
            aud0,
            aud1,
            ciphertext_digest(self.envelope)?,
            right_align(self.salt),
            right_align(&[self.layout.value()]),
        ])
    }
}

/// Zero past the last cell, the chain width stays the key's.
fn zero_filled_chain<'a>(
    cells: impl Iterator<Item = &'a [u8; 32]>,
    width: usize,
) -> Result<[u8; 32], HasherError> {
    create_hash_chain_4(cells.chain(core::iter::repeat(&ZERO_FIELD)).take(width))
}

fn output_chain(outputs: &[RingOutput<'_>], capacity: usize) -> Result<[u8; 32], HasherError> {
    zero_filled_chain(outputs.iter().map(|output| output.hash), capacity)
}

/// `Poseidon(u32 len(ct), HashChain4(pack_left31(ct)))`, without the tag trailing zeros collide.
pub fn ciphertext_digest(ciphertext: &[u8]) -> Result<[u8; 32], HasherError> {
    let chain = create_hash_chain_4_from_slice(&pack_disclosure(ciphertext))?;
    Poseidon::hashv(&[
        &right_align(&(ciphertext.len() as u32).to_be_bytes()),
        &chain,
    ])
}

/// `HashChain4(hash_bytes(record_i))`, untagged since every record is one length.
pub fn record_chain(outputs: &[RingOutput<'_>], capacity: usize) -> Result<[u8; 32], HasherError> {
    let mut hashes = Vec::with_capacity(outputs.len());
    for output in outputs {
        hashes.push(hash_bytes(output.record)?);
    }
    zero_filled_chain(hashes.iter(), capacity)
}

/// `HashChain4(hash_bytes(tail_i))`, zero while no slot carries a tail.
pub fn tail_chain(outputs: &[RingOutput<'_>], capacity: usize) -> Result<[u8; 32], HasherError> {
    let mut hashes = Vec::with_capacity(outputs.len());
    for tail in outputs.iter().filter_map(|output| output.tail) {
        hashes.push(hash_bytes(tail)?);
    }
    match hashes.is_empty() {
        true => Ok(ZERO_FIELD),
        false => zero_filled_chain(hashes.iter(), capacity),
    }
}

/// SPP's owner signer run, deduplicated by first occurrence, the order `fill_owner_signer_hashes` reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignerSet {
    pub count: usize,
    /// Zero on an empty set, the one encoding every rail binds.
    pub chain: [u8; 32],
}

impl SignerSet {
    /// `slots` is the key's `S`, a run wider than it refused.
    pub fn new<'a>(
        owners: impl Iterator<Item = &'a [u8; 32]>,
        slots: usize,
    ) -> Result<Self, CustomRingError> {
        let mut unique: Vec<&[u8; 32]> = Vec::with_capacity(slots);
        for owner in owners {
            if !unique.contains(&owner) {
                unique.push(owner);
            }
        }
        if unique.len() > slots {
            return Err(CustomRingError::OwnerSignerCount);
        }
        if unique.is_empty() {
            return Ok(Self::default());
        }
        let mut identities = Vec::with_capacity(unique.len());
        for owner in &unique {
            identities.push(solana_owner_identity(owner)?);
        }
        Ok(Self {
            count: unique.len(),
            chain: zero_filled_chain(identities.iter(), slots)?,
        })
    }
}

/// Per entry of the owner signer run, in the order [`SignerSet::chain`] binds, the live output slots
/// that signer owns with a nonzero `data_hash`. SPP accepts one signature for any number of such
/// slots, the proved count lets a signer's check notice a slot the sender left out of its terms.
/// Entry `k` holds bits `5k..5k + 5`, zero past the run, and no bit above the last entry is set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignerDataCounts(u64);

/// One live output slot as the count reads it, its owner identity is `solana_owner_identity`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveSlot<'a> {
    pub owner_identity: &'a [u8; 32],
    pub data_hash: &'a [u8; 32],
}

impl SignerDataCounts {
    /// `solana_message::v1::MAX_SIGNATURES`, a run has no more entries to count.
    pub const ENTRIES: usize = 12;
    pub const ENTRY_BITS: usize = 5;
    const ENTRY_MASK: u64 = (1 << Self::ENTRY_BITS) - 1;
    const USED_BITS: u64 = (1 << (Self::ENTRIES * Self::ENTRY_BITS)) - 1;

    pub const fn new(packed: u64) -> Result<Self, CustomRingError> {
        match packed & !Self::USED_BITS {
            0 => Ok(Self(packed)),
            _ => Err(CustomRingError::InvalidSignerDataCounts),
        }
    }

    /// `run` holds the signers' identities in run order, a slot with a zero `data_hash` never counts.
    pub fn of_run<'a>(
        run: &[[u8; 32]],
        live_slots: impl Iterator<Item = LiveSlot<'a>> + Clone,
    ) -> Result<Self, CustomRingError> {
        if run.len() > Self::ENTRIES {
            return Err(CustomRingError::OwnerSignerCount);
        }
        let mut packed = 0;
        for (entry, signer) in run.iter().enumerate() {
            let count = live_slots
                .clone()
                .filter(|slot| slot.owner_identity == signer && *slot.data_hash != ZERO_FIELD)
                .count() as u64;
            if count > Self::ENTRY_MASK {
                return Err(CustomRingError::InvalidSignerDataCounts);
            }
            packed |= count << (entry * Self::ENTRY_BITS);
        }
        Ok(Self(packed))
    }

    pub const fn packed(self) -> u64 {
        self.0
    }

    /// Zero past the run.
    pub const fn count(self, entry: usize) -> u8 {
        match entry < Self::ENTRIES {
            true => ((self.0 >> (entry * Self::ENTRY_BITS)) & Self::ENTRY_MASK) as u8,
            false => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfidentialSender<'a> {
    Signer,
    InProof(&'a [u8; 32]),
    Authority,
}

impl ConfidentialSender<'_> {
    /// Zero on the signer and authority rails.
    pub fn identity(&self) -> &[u8; 32] {
        match self {
            Self::InProof(identity) => identity,
            Self::Signer | Self::Authority => &ZERO_FIELD,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferFamily<'a> {
    /// The signer, in-proof and authority rails.
    Confidential { sender: ConfidentialSender<'a> },
    /// The anonymous rail, the head's layout picks the entry disclosure.
    Anonymous {
        /// `solana_owner_identity` of the payer, each co-signer and the withdrawal destination, zero when absent.
        party_identities: &'a [[u8; 32]; ANONYMOUS_PARTIES],
        /// No hidden sender exists, every live owner is a published signer.
        public_owners: bool,
        /// Set only under the authority tag.
        delegate: bool,
    },
}

/// One ring transfer's proof, mirror `prover/circuits/transfer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferStatement<'a> {
    pub head: AuditHead<'a>,
    pub family: TransferFamily<'a>,
    pub approval_mask: ApprovalMask,
    /// Zero unless the frame discloses totals to a co-signer.
    pub approval_totals: &'a [u8; 32],
    /// Zero unless a public signer owns a data-bearing output.
    pub signer_data_counts: SignerDataCounts,
    /// `R` is zero, the frame takes public funds alone.
    pub no_spend: bool,
    /// The `m` published slots.
    pub outputs: &'a [RingOutput<'a>],
    /// `N`, the key's output capacity.
    pub output_capacity: usize,
    /// `n`, the frame's nullifier count.
    pub input_count: usize,
    pub private_tx_hash: &'a [u8; 32],
    /// Default on the in-proof and authority rails and on an empty run.
    pub signers: SignerSet,
    pub roots: &'a TransferRoots,
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// SPP's signed nets, a withdrawal is `q - |amount|`.
    pub public_amounts: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// Gross withdrawals per slot as right-aligned u128.
    pub public_gross: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub withdrawal_hash: &'a [u8; 32],
}

/// Zero where the frame reads none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferRoots {
    pub policy_hash: [u8; 32],
    pub own_root: [u8; 32],
    pub curator_root: [u8; 32],
    pub tracking_root: [u8; 32],
}

/// Everything but the party cells, the public slots and the close.
const TRANSFER_FIXED_ELEMENTS: usize = AUDIT_HEAD_ELEMENTS + 3 + 4 + 4 + 2 + 1 + 2 + 4 + 1;

impl TransferFamily<'_> {
    /// `in_proof`, `hidden`, `delegate`, a clear set is the signer rail.
    fn rail_bits(&self) -> [bool; 3] {
        match self {
            Self::Confidential { sender } => [
                matches!(sender, ConfidentialSender::InProof(_)),
                false,
                matches!(sender, ConfidentialSender::Authority),
            ],
            Self::Anonymous {
                public_owners,
                delegate,
                ..
            } => [false, !public_owners && !delegate, *delegate],
        }
    }

    fn sender(&self) -> &[u8; 32] {
        match self {
            Self::Confidential { sender } => sender.identity(),
            Self::Anonymous { .. } => &ZERO_FIELD,
        }
    }

    fn parties(&self) -> [[u8; 32]; ANONYMOUS_PARTIES] {
        match self {
            Self::Confidential { .. } => [ZERO_FIELD; ANONYMOUS_PARTIES],
            Self::Anonymous {
                party_identities, ..
            } => **party_identities,
        }
    }
}

impl TransferStatement<'_> {
    pub const fn element_count(&self) -> usize {
        TRANSFER_FIXED_ELEMENTS + ANONYMOUS_PARTIES + 3 * N_PUBLIC_SLOTS + 1
    }

    pub fn elements(&self) -> Result<Vec<[u8; 32]>, HasherError> {
        let capacity = self.output_capacity;
        let mut elements = Vec::with_capacity(self.element_count());
        elements.extend(self.head.elements_under(domain::TRANSFER_STATEMENT)?);
        elements.extend(self.family.rail_bits().map(bit));
        elements.extend([
            right_align(&[self.approval_mask.bits()]),
            *self.approval_totals,
            right_align(&self.signer_data_counts.packed().to_be_bytes()),
            bit(self.no_spend),
            count(self.outputs.len()),
            output_chain(self.outputs, capacity)?,
            record_chain(self.outputs, capacity)?,
            tail_chain(self.outputs, capacity)?,
            count(self.input_count),
            *self.private_tx_hash,
            *self.family.sender(),
        ]);
        elements.extend(self.family.parties());
        elements.extend([
            count(self.signers.count),
            self.signers.chain,
            self.roots.policy_hash,
            self.roots.own_root,
            self.roots.curator_root,
            self.roots.tracking_root,
        ]);
        for (slot, asset) in self.public_assets.iter().enumerate() {
            elements.extend([*asset, self.public_amounts[slot], self.public_gross[slot]]);
        }
        elements.push(*self.withdrawal_hash);
        // The nonzero length counts itself and closes the chain, HashChain4 pads zeros.
        let length = (elements.len() + 1) as u64;
        elements.push(right_align(&length.to_be_bytes()));
        Ok(elements)
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements()?)
    }
}

/// An application of `count` queued writes, mirror `prover/circuits/registry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyRecordsStatement {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub old_next_index: u32,
    pub new_next_index: u32,
    /// `chain(head - 1)`.
    pub chain_start: [u8; 32],
    /// `chain(tail - 1)`.
    pub chain_end: [u8; 32],
    pub count: u64,
}

impl ApplyRecordsStatement {
    /// `[CRAP, old_root, new_root, old_next, new_next, chain_start, chain_end, count]`.
    pub fn elements(&self) -> [[u8; 32]; 8] {
        [
            domain::field(domain::APPLY_RECORDS),
            self.old_root,
            self.new_root,
            right_align(&self.old_next_index.to_be_bytes()),
            right_align(&self.new_next_index.to_be_bytes()),
            self.chain_start,
            self.chain_end,
            right_align(&self.count.to_be_bytes()),
        ]
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements())
    }
}

/// An application of `count` entries to the tracking tree, mirror
/// `prover/circuits/registry/apply_enrollments.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyEnrollmentsStatement {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub old_next_index: u32,
    pub new_next_index: u32,
    pub chain_start: [u8; 32],
    pub chain_end: [u8; 32],
    pub count: u64,
}

impl ApplyEnrollmentsStatement {
    /// `[CRTA, old_root, new_root, old_next, new_next, chain_start, chain_end, count]`.
    pub fn elements(&self) -> [[u8; 32]; 8] {
        [
            domain::field(domain::APPLY_ENROLLMENTS),
            self.old_root,
            self.new_root,
            right_align(&self.old_next_index.to_be_bytes()),
            right_align(&self.new_next_index.to_be_bytes()),
            self.chain_start,
            self.chain_end,
            right_align(&self.count.to_be_bytes()),
        ]
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements())
    }
}

/// The auditor envelope of an enrolled nullifier key, mirror
/// `prover/circuits/registry/register_key.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterKeyStatement<'a> {
    /// The tracking registry's, a proof for another ring fails.
    pub ring_id: &'a [u8; 32],
    /// The owner identity of the signing member.
    pub member: &'a [u8; 32],
    pub nullifier_pk: &'a [u8; 32],
    pub list_tag: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_u: &'a [u8; 32],
    pub ciphertext: &'a [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

impl RegisterKeyStatement<'_> {
    /// `[CRRG, ring_id, member, nullifier_pk, list_tag, aud0, aud1, eph0, eph1, hash_bytes(ciphertext)]`.
    pub fn elements(&self) -> Result<[[u8; 32]; 10], HasherError> {
        let [aud0, aud1] = pack_be(self.auditor_pubkey);
        let [eph0, eph1] = pack_be(&tagged_x25519(self.eph_u));
        Ok([
            domain::field(domain::REGISTER_KEY),
            *self.ring_id,
            *self.member,
            *self.nullifier_pk,
            *self.list_tag,
            aud0,
            aud1,
            eph0,
            eph1,
            hash_bytes(self.ciphertext)?,
        ])
    }

    pub fn hash(&self) -> Result<[u8; 32], HasherError> {
        create_hash_chain_4_from_slice(&self.elements()?)
    }
}

fn bit(value: bool) -> [u8; 32] {
    right_align(&[u8::from(value)])
}

fn count(value: usize) -> [u8; 32] {
    right_align(&(value as u64).to_be_bytes())
}

#[cfg(test)]
mod tests {
    use spr_interface::shape::SPP_SUPPORTED_SHAPES;

    use super::*;
    use crate::key_catalog::TRANSFER_SHAPES;

    /// A later signature or output limit past the encoding fails here, not in a proof.
    #[test]
    fn every_supported_limit_fits_the_encoding() {
        assert!(usize::from(solana_message::v1::MAX_SIGNATURES) <= SignerDataCounts::ENTRIES);
        assert!(SignerDataCounts::ENTRIES * SignerDataCounts::ENTRY_BITS <= u64::BITS as usize);
        let widest = 1 << SignerDataCounts::ENTRY_BITS;
        for shape in SPP_SUPPORTED_SHAPES {
            assert!(shape.n_outputs() < widest, "{shape:?}");
        }
        for shape in TRANSFER_SHAPES {
            assert!(usize::from(shape.outputs) < widest, "{shape:?}");
        }
    }

    const ALICE: [u8; 32] = [1; 32];
    const BOB: [u8; 32] = [2; 32];
    const DATA: [u8; 32] = [7; 32];

    fn slot<'a>(owner_identity: &'a [u8; 32], data_hash: &'a [u8; 32]) -> LiveSlot<'a> {
        LiveSlot {
            owner_identity,
            data_hash,
        }
    }

    #[test]
    fn each_run_entry_counts_its_own_data_bearing_slots() {
        let slots = [
            slot(&BOB, &DATA),
            slot(&ALICE, &ZERO_FIELD),
            slot(&BOB, &DATA),
            slot(&ALICE, &DATA),
            slot(&[3; 32], &DATA),
        ];
        let counts = SignerDataCounts::of_run(&[ALICE, BOB], slots.iter().copied()).unwrap();
        assert_eq!(counts.packed(), 1 | 2 << SignerDataCounts::ENTRY_BITS);
        assert_eq!(counts.count(0), 1);
        assert_eq!(counts.count(1), 2);
        assert_eq!(counts.count(2), 0);
        assert_eq!(counts.count(SignerDataCounts::ENTRIES), 0);
    }

    #[test]
    fn an_empty_run_counts_nothing() {
        let slots = [slot(&ALICE, &DATA)];
        assert_eq!(
            SignerDataCounts::of_run(&[], slots.iter().copied()),
            Ok(SignerDataCounts::default())
        );
    }

    #[test]
    fn bits_past_the_last_entry_are_refused() {
        let used = (1u64 << 60) - 1;
        assert_eq!(
            SignerDataCounts::new(used).map(SignerDataCounts::packed),
            Ok(used)
        );
        assert_eq!(
            SignerDataCounts::new(1 << 60),
            Err(CustomRingError::InvalidSignerDataCounts)
        );
    }

    #[test]
    fn a_run_past_the_entries_and_a_count_past_its_bits_are_refused() {
        let wide = [ALICE; SignerDataCounts::ENTRIES + 1];
        assert_eq!(
            SignerDataCounts::of_run(&wide, core::iter::empty()),
            Err(CustomRingError::OwnerSignerCount)
        );
        let slots = [slot(&ALICE, &DATA); 32];
        assert_eq!(
            SignerDataCounts::of_run(&[ALICE], slots.iter().copied()),
            Err(CustomRingError::InvalidSignerDataCounts)
        );
    }
}
