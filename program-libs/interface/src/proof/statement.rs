//! The `HashChain4` public input of the transfer, apply and register key proofs.

use spr_hasher::{
    hash_chain::{create_hash_chain_4, create_hash_chain_4_from_slice},
    primitives::{hash_bytes, pack_be, right_align},
    Hasher, HasherError, Poseidon,
};
use spr_interface::N_PUBLIC_SLOTS;

use crate::{
    audit_stream::{ANONYMOUS_RECORD_LEN, ESCROWED_EXIT_RECORD_LEN, EXIT_RECORD_LEN},
    disclosure::{pack_disclosure, AuditLayout},
    domain, tagged_x25519,
    transact::{exits_bitmap, RingOutput},
    REGISTER_KEY_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};

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

fn output_chain(outputs: &[RingOutput<'_>]) -> Result<[u8; 32], HasherError> {
    create_hash_chain_4(outputs.iter().map(RingOutput::hash))
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
pub fn output_ciphertext_chain(outputs: &[RingOutput<'_>]) -> Result<[u8; 32], HasherError> {
    let mut hashes = Vec::with_capacity(outputs.len());
    for output in outputs {
        hashes.push(slot_ciphertext_hash(output.ciphertext())?);
    }
    create_hash_chain_4_from_slice(&hashes)
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
        _ => fixed::<ANONYMOUS_RECORD_LEN>(ciphertext),
    }
}

fn recipient_key_chain(outputs: &[RingOutput<'_>]) -> Result<[u8; 32], HasherError> {
    let mut keys = Vec::with_capacity(2 * outputs.len());
    for output in outputs {
        keys.extend(output.recipient_key_fields());
    }
    create_hash_chain_4_from_slice(&keys)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfidentialSender<'a> {
    Signer(&'a [u8; 32]),
    InProof(&'a [u8; 32]),
    Authority,
}

impl ConfidentialSender<'_> {
    pub fn identity(&self) -> &[u8; 32] {
        match self {
            Self::Signer(identity) | Self::InProof(identity) => identity,
            Self::Authority => &[0; 32],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferFamily<'a> {
    /// The signer, in-proof and authority rails.
    Confidential {
        sender: ConfidentialSender<'a>,
        /// One owner identity per output slot, zero on a dummy and off a policy.
        recipients: &'a [[u8; 32]],
    },
    /// The anonymous rail, the head's layout picks the commitment or entry disclosure.
    Anonymous {
        /// `solana_owner_identity` of the payer, the signing co-signer and the withdrawal destination, zero when absent.
        party_identities: &'a [[u8; 32]; 3],
    },
}

/// One ring transfer's proof, mirror `prover/circuits/transfer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferStatement<'a> {
    pub head: AuditHead<'a>,
    pub family: TransferFamily<'a>,
    /// Every public slot's gross withdrawal stays at or below its record's threshold.
    pub exempt: bool,
    pub approval_required: bool,
    pub outputs: &'a [RingOutput<'a>],
    /// `n`, the frame's nullifier count.
    pub input_count: usize,
    pub private_tx_hash: &'a [u8; 32],
    /// Zero on an audit-only ring.
    pub policy_hash: &'a [u8; 32],
    /// Zero when no registry is read.
    pub own_root: &'a [u8; 32],
    /// Zero without a curator source.
    pub curator_root: &'a [u8; 32],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// SPP's signed nets, a withdrawal is `q - |amount|`.
    pub public_amounts: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// Gross withdrawals per slot as right-aligned u128.
    pub public_gross: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    pub withdrawal_hash: &'a [u8; 32],
}

impl TransferStatement<'_> {
    /// `elements().len()`, 38 + n_out on the confidential family and 37 on the anonymous family.
    pub fn element_count(&self) -> usize {
        let family = match self.family {
            TransferFamily::Confidential { recipients, .. } => 4 + recipients.len(),
            TransferFamily::Anonymous { .. } => 3,
        };
        AUDIT_HEAD_ELEMENTS + 3 + 1 + 3 + family + 3 + 3 * N_PUBLIC_SLOTS + 1 + 2
    }

    pub fn elements(&self) -> Result<Vec<[u8; 32]>, HasherError> {
        let mut elements = Vec::with_capacity(self.element_count());
        elements.extend(self.head.elements_under(domain::TRANSFER_STATEMENT)?);
        if let TransferFamily::Confidential { sender, .. } = self.family {
            elements.extend([
                bit(matches!(sender, ConfidentialSender::InProof(_))),
                bit(matches!(sender, ConfidentialSender::Authority)),
            ]);
        }
        elements.extend([
            bit(self.exempt),
            bit(self.approval_required),
            output_chain(self.outputs)?,
            output_ciphertext_chain(self.outputs)?,
        ]);
        if matches!(self.family, TransferFamily::Confidential { .. }) {
            elements.push(recipient_key_chain(self.outputs)?);
        }
        elements.extend([
            right_align(&(self.input_count as u64).to_be_bytes()),
            right_align(&exits_bitmap(self.outputs).to_be_bytes()),
            *self.private_tx_hash,
        ]);
        match self.family {
            TransferFamily::Confidential { sender, .. } => elements.push(*sender.identity()),
            TransferFamily::Anonymous { party_identities } => elements.extend(*party_identities),
        }
        elements.extend([*self.policy_hash, *self.own_root, *self.curator_root]);
        if let TransferFamily::Confidential { recipients, .. } = self.family {
            elements.extend_from_slice(recipients);
        }
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
