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

/// `[CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, envelope_digest, salt, layout]`.
pub const AUDIT_HEAD_ELEMENTS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditHead<'a> {
    pub first_nullifier: &'a [u8; 32],
    /// `hash_bytes` of the ring program id.
    pub ring_id: &'a [u8; 32],
    pub tx_viewing_u: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_u: &'a [u8; 32],
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
        let [eph0, eph1] = pack_be(&tagged_x25519(self.eph_u));
        Ok([
            domain::field(statement),
            *self.first_nullifier,
            *self.ring_id,
            tx0,
            tx1,
            aud0,
            aud1,
            eph0,
            eph1,
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
    pub private_root: [u8; 32],
}

/// Everything but the sender cells, the public slots and the close.
const TRANSFER_FIXED_ELEMENTS: usize = AUDIT_HEAD_ELEMENTS + 2 + 2 + 4 + 2 + 2 + 5 + 1;

impl TransferStatement<'_> {
    pub fn element_count(&self) -> usize {
        let sender_cells = match self.family {
            TransferFamily::Confidential { .. } => 1,
            TransferFamily::Anonymous { .. } => ANONYMOUS_PARTIES,
        };
        TRANSFER_FIXED_ELEMENTS + sender_cells + 3 * N_PUBLIC_SLOTS + 2
    }

    /// `head, rail bits, mask, no_spend, m, outputs, records, tails, n, private_tx_hash, sender or parties, signer count, signer chain, roots, public slots, withdrawals, length, version`.
    pub fn elements(&self) -> Result<Vec<[u8; 32]>, HasherError> {
        let capacity = self.output_capacity;
        let mut elements = Vec::with_capacity(self.element_count());
        elements.extend(self.head.elements_under(domain::TRANSFER_STATEMENT)?);
        match self.family {
            TransferFamily::Confidential { sender } => elements.extend([
                bit(matches!(sender, ConfidentialSender::InProof(_))),
                bit(matches!(sender, ConfidentialSender::Authority)),
            ]),
            TransferFamily::Anonymous {
                public_owners,
                delegate,
                ..
            } => elements.extend([bit(public_owners), bit(delegate)]),
        }
        elements.extend([
            right_align(&[self.approval_mask.bits()]),
            bit(self.no_spend),
            count(self.outputs.len()),
            output_chain(self.outputs, capacity)?,
            record_chain(self.outputs, capacity)?,
            tail_chain(self.outputs, capacity)?,
            count(self.input_count),
            *self.private_tx_hash,
        ]);
        match self.family {
            TransferFamily::Confidential { sender } => elements.push(*sender.identity()),
            TransferFamily::Anonymous {
                party_identities, ..
            } => elements.extend(*party_identities),
        }
        elements.extend([
            count(self.signers.count),
            self.signers.chain,
            self.roots.policy_hash,
            self.roots.own_root,
            self.roots.curator_root,
            self.roots.tracking_root,
            self.roots.private_root,
        ]);
        for (slot, asset) in self.public_assets.iter().enumerate() {
            elements.extend([*asset, self.public_amounts[slot], self.public_gross[slot]]);
        }
        elements.push(*self.withdrawal_hash);
        // The length counts itself and the version, both close the chain.
        let length = (elements.len() + 2) as u64;
        elements.extend([
            right_align(&length.to_be_bytes()),
            right_align(&[domain::TRANSFER_STATEMENT_VERSION]),
        ]);
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

/// The auditor envelope of a registered nullifier key, mirror
/// `prover/circuits/registry/register_key.go`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterKeyStatement<'a> {
    /// The owner identity of the signing member.
    pub member: &'a [u8; 32],
    pub nullifier_pk: &'a [u8; 32],
    pub auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
    pub eph_u: &'a [u8; 32],
    pub ciphertext: &'a [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

impl RegisterKeyStatement<'_> {
    /// `[CRRG, member, nullifier_pk, aud0, aud1, eph0, eph1, hash_bytes(ciphertext)]`.
    pub fn elements(&self) -> Result<[[u8; 32]; 8], HasherError> {
        let [aud0, aud1] = pack_be(self.auditor_pubkey);
        let [eph0, eph1] = pack_be(&tagged_x25519(self.eph_u));
        Ok([
            domain::field(domain::REGISTER_KEY),
            *self.member,
            *self.nullifier_pk,
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
