//! The `HashChain4` public input of the transfer, apply and register key proofs.

use spr_hasher::{
    hash_chain::{create_hash_chain_4, create_hash_chain_4_from_slice},
    primitives::{hash_bytes, pack_be, right_align, solana_owner_identity},
    Hasher, HasherError, Poseidon,
};
use spr_interface::N_PUBLIC_SLOTS;
use zolana_ring_policy::ListId;

use crate::{
    anonymous_exit::ANONYMOUS_PARTIES,
    audit_stream::{ANONYMOUS_RECORD_LEN, ESCROWED_EXIT_RECORD_LEN, EXIT_RECORD_LEN},
    cosign::ApprovalMask,
    disclosure::{pack_disclosure, AuditLayout},
    domain,
    error::CustomRingError,
    tagged_x25519,
    transact::{change_bitmap, exits_bitmap, FramedSenderBundle, RingOutput},
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
    zero_filled_chain(outputs.iter().map(RingOutput::hash), capacity)
}

/// `Poseidon(u32 len(ct), HashChain4(pack_left31(ct)))`, without the tag trailing zeros collide.
pub fn ciphertext_digest(ciphertext: &[u8]) -> Result<[u8; 32], HasherError> {
    let chain = create_hash_chain_4_from_slice(&pack_disclosure(ciphertext))?;
    Poseidon::hashv(&[
        &right_align(&(ciphertext.len() as u32).to_be_bytes()),
        &chain,
    ])
}

/// `HashChain4(hash_bytes(ct_i))`, untagged since the layout fixes every slot's length.
pub fn output_ciphertext_chain(
    outputs: &[RingOutput<'_>],
    capacity: usize,
) -> Result<[u8; 32], HasherError> {
    let mut hashes = Vec::with_capacity(outputs.len());
    for output in outputs {
        hashes.push(slot_ciphertext_hash(output.ciphertext())?);
    }
    zero_filled_chain(hashes.iter(), capacity)
}

/// `hash_bytes` at the three lengths a slot ciphertext has, any other is refused.
pub fn slot_ciphertext_hash(ciphertext: &[u8]) -> Result<[u8; 32], HasherError> {
    fn fixed<const N: usize>(ciphertext: &[u8]) -> Result<[u8; 32], HasherError> {
        let exact = <&[u8; N]>::try_from(ciphertext)
            .map_err(|_| HasherError::InvalidInputLength(N, ciphertext.len()))?;
        hash_bytes(exact)
    }
    match ciphertext.len() {
        ESCROWED_EXIT_RECORD_LEN => fixed::<ESCROWED_EXIT_RECORD_LEN>(ciphertext),
        EXIT_RECORD_LEN => fixed::<EXIT_RECORD_LEN>(ciphertext),
        ANONYMOUS_RECORD_LEN => fixed::<ANONYMOUS_RECORD_LEN>(ciphertext),
        len => Err(HasherError::InvalidInputLength(ANONYMOUS_RECORD_LEN, len)),
    }
}

fn recipient_key_chain(
    outputs: &[RingOutput<'_>],
    capacity: usize,
) -> Result<[u8; 32], HasherError> {
    let mut keys = Vec::with_capacity(2 * outputs.len());
    for output in outputs {
        keys.extend(output.recipient_key_fields());
    }
    zero_filled_chain(keys.iter(), 2 * capacity)
}

/// `HashChain4(hash_bytes(body_i))`, zero on a change or exit slot and past `m`.
fn recipient_body_chain(
    outputs: &[RingOutput<'_>],
    capacity: usize,
) -> Result<[u8; 32], HasherError> {
    let mut hashes = Vec::with_capacity(outputs.len());
    for output in outputs {
        hashes.push(output.recipient_body_hash()?);
    }
    zero_filled_chain(hashes.iter(), capacity)
}

/// `HashChain4` of each slot's proven tag cell at the key's width, then the bundle tag.
fn recipient_tag_chain(
    outputs: &[RingOutput<'_>],
    capacity: usize,
    bundle_tag: &[u8; 32],
) -> Result<[u8; 32], HasherError> {
    create_hash_chain_4(
        outputs
            .iter()
            .map(RingOutput::recipient_tag_cell)
            .chain(core::iter::repeat(&ZERO_FIELD))
            .take(capacity)
            .chain(core::iter::once(bundle_tag)),
    )
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
    Confidential {
        sender: ConfidentialSender<'a>,
        /// One owner identity per published slot, zero on a dummy and off a policy.
        recipients: &'a [[u8; 32]],
    },
    /// The anonymous rail, the head's layout picks the commitment or entry disclosure.
    Anonymous {
        /// `solana_owner_identity` of the payer, each co-signer and the withdrawal destination, zero when absent.
        party_identities: &'a [[u8; 32]; ANONYMOUS_PARTIES],
        /// The ciphertext the sender reads back under its proven tag, the length follows `m`.
        sender: FramedSenderBundle<'a>,
        /// Every reply in slot order, `None` without reply metadata.
        replies: Option<&'a [u8]>,
        /// No hidden sender, the owners are the published signer set.
        public_owners: bool,
        /// Set by the authority tag alone, a signer proof cannot claim the bypass.
        delegate: bool,
    },
}

/// One ring transfer's proof, mirror `prover/circuits/transfer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferStatement<'a> {
    pub head: AuditHead<'a>,
    pub family: TransferFamily<'a>,
    pub approval_mask: ApprovalMask,
    /// Equals `R == 0`, drops the transfers class.
    pub no_spend: bool,
    /// The `m` published slots.
    pub outputs: &'a [RingOutput<'a>],
    /// `N`, the key's output capacity.
    pub output_capacity: usize,
    /// `n`, the frame's nullifier count.
    pub input_count: usize,
    pub private_tx_hash: &'a [u8; 32],
    /// Default on the in-proof, authority and entry rails and on an empty run.
    pub signers: SignerSet,
    /// Zero on an audit-only ring.
    pub policy_hash: &'a [u8; 32],
    /// Zero when no registry is read.
    pub own_root: &'a [u8; 32],
    /// Zero without a curator source.
    pub curator_root: &'a [u8; 32],
    pub tracking_root: &'a [u8; 32],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// SPP's signed nets, a withdrawal is `q - |amount|`.
    pub public_amounts: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// Gross withdrawals per slot as right-aligned u128.
    pub public_gross: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub withdrawal_hash: &'a [u8; 32],
}

impl TransferStatement<'_> {
    pub fn element_count(&self) -> usize {
        match self.family {
            TransferFamily::Confidential { .. } => 42 + self.output_capacity,
            TransferFamily::Anonymous { .. } => 42 + ANONYMOUS_PARTIES + 3,
        }
    }

    pub fn elements(&self) -> Result<Vec<[u8; 32]>, HasherError> {
        let capacity = self.output_capacity;
        let mut elements = Vec::with_capacity(self.element_count());
        elements.extend(self.head.elements_under(domain::TRANSFER_STATEMENT)?);
        match self.family {
            TransferFamily::Confidential { sender, .. } => elements.extend([
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
            output_ciphertext_chain(self.outputs, capacity)?,
        ]);
        match self.family {
            TransferFamily::Confidential { .. } => {
                elements.push(recipient_key_chain(self.outputs, capacity)?);
            }
            TransferFamily::Anonymous { sender, .. } => elements.extend([
                recipient_body_chain(self.outputs, capacity)?,
                recipient_tag_chain(self.outputs, capacity, sender.tag)?,
                bitmap(change_bitmap(self.outputs)),
                ciphertext_digest(sender.body)?,
            ]),
        }
        elements.extend([
            count(self.input_count),
            bitmap(exits_bitmap(self.outputs)),
            *self.private_tx_hash,
        ]);
        match self.family {
            TransferFamily::Confidential { sender, .. } => elements.push(*sender.identity()),
            TransferFamily::Anonymous {
                party_identities, ..
            } => elements.extend(*party_identities),
        }
        elements.extend([
            count(self.signers.count),
            self.signers.chain,
            *self.policy_hash,
            *self.own_root,
            *self.curator_root,
            *self.tracking_root,
        ]);
        if let TransferFamily::Confidential { recipients, .. } = self.family {
            elements.extend(
                recipients
                    .iter()
                    .copied()
                    .chain(core::iter::repeat(ZERO_FIELD))
                    .take(capacity),
            );
        }
        for (slot, asset) in self.public_assets.iter().enumerate() {
            elements.extend([*asset, self.public_amounts[slot], self.public_gross[slot]]);
        }
        elements.push(*self.withdrawal_hash);
        if let TransferFamily::Anonymous { replies, .. } = self.family {
            elements.push(replies.map_or(Ok(ZERO_FIELD), ciphertext_digest)?);
        }
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

/// A write clears a grant list, sets a deny list or replaces mint settings, mirror
/// `registry.Restrictive`.
pub const fn restrictive_write(mask: u64, value: u64, replaces_mint_policy: bool) -> bool {
    const GRANT: u64 = ListId::Allow.record_bit() | ListId::Approval.record_bit();
    const DENY: u64 = ListId::Block.record_bit() | ListId::Frozen.record_bit();
    replaces_mint_policy || mask & GRANT & !value != 0 || value & DENY != 0
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
    /// The proof computes it, a wrong bit fails the statement.
    pub restrictive: bool,
}

impl ApplyRecordsStatement {
    /// `[CRAP, old_root, new_root, old_next, new_next, chain_start, chain_end, count, restrictive]`.
    pub fn elements(&self) -> [[u8; 32]; 9] {
        [
            domain::field(domain::APPLY_RECORDS),
            self.old_root,
            self.new_root,
            right_align(&self.old_next_index.to_be_bytes()),
            right_align(&self.new_next_index.to_be_bytes()),
            self.chain_start,
            self.chain_end,
            right_align(&self.count.to_be_bytes()),
            bit(self.restrictive),
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

fn bitmap(bits: u64) -> [u8; 32] {
    right_align(&bits.to_be_bytes())
}
