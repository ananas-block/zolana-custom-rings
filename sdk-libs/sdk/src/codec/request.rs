//! The ring prover's request bodies, field for field the Go `prover/custom_ring` params.

use custom_ring_interface::{QueueEntry, QUAD_ARITY};
use serde::{Serialize, Serializer};
use spr_hasher::primitives::{pack_be, right_align};
use spr_keypair::{PublicKey, X25519Pubkey};
use spr_transaction::{
    instructions::transact::SppProofOutputUtxo,
    utxo::{ProofInputUtxo, SppProofInputUtxo},
};
use zeroize::Zeroizing;
use zolana_ring_member_registry::{
    MemberRecord, QuadPath, RecordOpening, RecordPool, RecordWriteProofInput,
};
use zolana_ring_policy::{AssetLimits, EncodedRuleTable, SourceMap, MAX_SOURCES};

use crate::{prover::fe, RingError, REDACTED};

#[cfg(test)]
#[path = "../tests/rpc/request.rs"]
mod tests;

/// One transaction slot as SPP hashes it, its owner split into the identity and the nullifier key.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Opening {
    #[serde(with = "fe")]
    pub domain: [u8; 32],
    #[serde(with = "fe")]
    pub tree_id: [u8; 32],
    #[serde(with = "fe")]
    pub owner_pk_hash: [u8; 32],
    #[serde(with = "fe")]
    pub nullifier_pk: [u8; 32],
    #[serde(with = "fe")]
    pub asset: [u8; 32],
    #[serde(with = "fe")]
    pub amount: [u8; 32],
    #[serde(with = "fe")]
    pub blinding: [u8; 32],
    #[serde(with = "fe")]
    pub data_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_data_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_program_id: [u8; 32],
}

impl core::fmt::Debug for Opening {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            domain,
            tree_id,
            owner_pk_hash,
            nullifier_pk,
            asset,
            amount,
            blinding: _,
            data_hash,
            ring_data_hash,
            ring_program_id,
        } = self;
        f.debug_struct("Opening")
            .field("domain", domain)
            .field("tree_id", tree_id)
            .field("owner_pk_hash", owner_pk_hash)
            .field("nullifier_pk", nullifier_pk)
            .field("asset", asset)
            .field("amount", amount)
            .field("blinding", &REDACTED)
            .field("data_hash", data_hash)
            .field("ring_data_hash", ring_data_hash)
            .field("ring_program_id", ring_program_id)
            .finish()
    }
}

impl Opening {
    pub fn output(output: &SppProofOutputUtxo, tree_id: u16) -> Result<Self, RingError> {
        let owner = output.owner_address;
        Ok(Self::with_owner(
            ProofInputUtxo::try_from((output, tree_id))?,
            owner
                .map(|owner| owner.signing_pubkey.owner_proof_input_hash())
                .transpose()?
                .unwrap_or_default(),
            owner
                .map(|owner| owner.nullifier_pubkey)
                .unwrap_or_default(),
        ))
    }

    pub fn input(input: &SppProofInputUtxo) -> Result<Self, RingError> {
        let real = !input.is_dummy() && !input.is_address();
        Ok(Self::with_owner(
            ProofInputUtxo::try_from(input)?,
            match real {
                true => input.utxo.owner.owner_proof_input_hash()?,
                false => [0; 32],
            },
            match real {
                true => input.nullifier_pubkey,
                false => [0; 32],
            },
        ))
    }

    /// A slot past the spent notes, a zero domain opens neither a note nor a dummy.
    pub fn input_padding() -> Self {
        let mut domain = [0; 32];
        domain[30..].copy_from_slice(&spr_interface::DUMMY_DOMAIN.to_be_bytes());
        Self {
            domain,
            ..Self::default()
        }
    }

    fn with_owner(fields: ProofInputUtxo, owner_pk_hash: [u8; 32], nullifier_pk: [u8; 32]) -> Self {
        Self {
            domain: fields.domain,
            tree_id: fields.tree_id,
            owner_pk_hash,
            nullifier_pk,
            asset: fields.asset,
            amount: fields.amount,
            blinding: fields.blinding,
            data_hash: fields.data_hash,
            ring_data_hash: fields.ring_data_hash,
            ring_program_id: fields.ring_program_id,
        }
    }
}

/// The ring id sits in `PolicyParams`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuditParams {
    #[serde(with = "fe")]
    pub first_nullifier: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub tx_viewing_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
    #[serde(with = "fe")]
    pub salt: [u8; 16],
    /// The statement's layout flags.
    pub layout: u8,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeliveredOutput {
    pub output: Opening,
    #[serde(with = "fe")]
    pub recipient_key: [u8; 32],
    #[serde(with = "fe")]
    pub owner_key: [u8; 32],
    #[serde(with = "fe")]
    pub body: Vec<u8>,
}

/// The owner key and recipient key are bytes, never fields.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnonymousOutput {
    pub output: Opening,
    #[serde(with = "fe")]
    pub owner_key: [u8; 32],
    #[serde(with = "fe")]
    pub recipient_key: [u8; 32],
    pub address_revision: u64,
    #[serde(serialize_with = "fe::seq")]
    pub mint_chunks: [[u8; 32]; 2],
    /// Zero on change, exit and an omitted slot, the published bytes on a recipient or dummy.
    #[serde(with = "fe")]
    pub body: Vec<u8>,
    /// Zero on change, exit and an omitted slot.
    #[serde(with = "fe")]
    pub tag: [u8; 32],
    /// A published dummy's tag preimage, zero on every other slot.
    #[serde(with = "fe")]
    pub tag_preimage: [u8; 32],
}

/// A member's record, or the low record proving it absent, as one subject entry opens it.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemberOpening {
    pub present: bool,
    #[serde(with = "fe")]
    pub next: [u8; 32],
    pub lists: u64,
    #[serde(with = "fe")]
    pub escrow_key: [u8; 32],
    #[serde(with = "fe")]
    pub mint_policy: [u8; 32],
    #[serde(with = "fe")]
    pub withdrawal_threshold: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub asset_limits: [[u8; 32]; AssetLimits::FIELDS],
    #[serde(with = "fe")]
    pub address_hash: [u8; 32],
    pub index: u64,
    #[serde(serialize_with = "path")]
    pub path: QuadPath,
    #[serde(with = "fe")]
    pub low_member: [u8; 32],
    #[serde(with = "fe")]
    pub low_next: [u8; 32],
    pub low_lists: u64,
    #[serde(with = "fe")]
    pub low_escrow: [u8; 32],
    #[serde(with = "fe")]
    pub low_mint_policy: [u8; 32],
    #[serde(with = "fe")]
    pub low_withdrawal_threshold: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub low_asset_limits: [[u8; 32]; AssetLimits::FIELDS],
    #[serde(with = "fe")]
    pub low_address_hash: [u8; 32],
}

impl From<&RecordOpening> for MemberOpening {
    fn from(opening: &RecordOpening) -> Self {
        match opening {
            RecordOpening::Present { record, path } => Self {
                present: true,
                next: record.next,
                lists: record.lists,
                escrow_key: record.escrow_key,
                mint_policy: record.mint_policy.field(),
                withdrawal_threshold: right_align(
                    &record.mint_policy.withdrawal_threshold.to_be_bytes(),
                ),
                asset_limits: record.mint_policy.limits.fields(),
                address_hash: record.address_hash,
                index: path.index,
                path: *path,
                low_member: [0; 32],
                low_next: [0; 32],
                low_lists: 0,
                low_escrow: [0; 32],
                low_mint_policy: [0; 32],
                low_withdrawal_threshold: [0; 32],
                low_asset_limits: [[0; 32]; AssetLimits::FIELDS],
                low_address_hash: [0; 32],
            },
            RecordOpening::Absent { low, path } => Self {
                present: false,
                next: [0; 32],
                lists: 0,
                escrow_key: [0; 32],
                mint_policy: [0; 32],
                withdrawal_threshold: [0; 32],
                asset_limits: [[0; 32]; AssetLimits::FIELDS],
                address_hash: [0; 32],
                index: path.index,
                path: *path,
                low_member: low.member,
                low_next: low.next,
                low_lists: low.lists,
                low_escrow: low.escrow_key,
                low_mint_policy: low.mint_policy.field(),
                low_withdrawal_threshold: right_align(
                    &low.mint_policy.withdrawal_threshold.to_be_bytes(),
                ),
                low_asset_limits: low.mint_policy.limits.fields(),
                low_address_hash: low.address_hash,
            },
        }
    }
}

/// One subject's index in each pool, the curator index 0 without a curator registry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct PoolEntry {
    pub own: u32,
    pub curator: [u32; 1],
}

/// Both pools at the key's widths, an unopened pool where the key binds no root.
pub(crate) struct RecordPools {
    pub own: RecordPool,
    pub curator: RecordPool,
}

impl Serialize for RecordPools {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Record {
            #[serde(with = "fe")]
            member: [u8; 32],
            #[serde(with = "fe")]
            next: [u8; 32],
            lists: u64,
            #[serde(with = "fe")]
            escrow_key: [u8; 32],
            #[serde(with = "fe")]
            mint_policy: [u8; 32],
            #[serde(with = "fe")]
            withdrawal_threshold: [u8; 32],
            #[serde(serialize_with = "fe::seq")]
            asset_limits: [[u8; 32]; AssetLimits::FIELDS],
            #[serde(with = "fe")]
            address_hash: [u8; 32],
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Subject {
            #[serde(with = "fe")]
            member: [u8; 32],
            record_index: u32,
        }
        #[derive(Serialize)]
        struct Path<'a> {
            index: u64,
            #[serde(serialize_with = "levels")]
            siblings: &'a [[[u8; 32]; QUAD_ARITY - 1]],
        }
        #[derive(Serialize)]
        struct Proof<'a> {
            #[serde(serialize_with = "fe::seq")]
            canopy: &'a [[u8; 32]],
            paths: Vec<Path<'a>>,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Pools<'a> {
            own_records: Vec<Record>,
            curator_records: Vec<Record>,
            own_proof: Proof<'a>,
            curator_proof: Proof<'a>,
            own_subjects: Vec<Subject>,
            curator_subjects: Vec<Subject>,
        }
        let records = |pool: &RecordPool| {
            pool.records
                .iter()
                .map(|record| Record {
                    member: record.member,
                    next: record.next,
                    lists: record.lists,
                    escrow_key: record.escrow_key,
                    mint_policy: record.mint_policy.field(),
                    withdrawal_threshold: right_align(
                        &record.mint_policy.withdrawal_threshold.to_be_bytes(),
                    ),
                    asset_limits: record.mint_policy.limits.fields(),
                    address_hash: record.address_hash,
                })
                .collect()
        };
        fn proof(pool: &RecordPool) -> Proof<'_> {
            Proof {
                canopy: &pool.proof.canopy,
                paths: pool
                    .proof
                    .paths
                    .iter()
                    .map(|path| Path {
                        index: path.index,
                        siblings: &path.siblings,
                    })
                    .collect(),
            }
        }
        let subjects = |pool: &RecordPool| {
            pool.subjects
                .iter()
                .map(|subject| Subject {
                    member: subject.member,
                    record_index: subject.record_index,
                })
                .collect()
        };
        Pools {
            own_records: records(&self.own),
            curator_records: records(&self.curator),
            own_proof: proof(&self.own),
            curator_proof: proof(&self.curator),
            own_subjects: subjects(&self.own),
            curator_subjects: subjects(&self.curator),
        }
        .serialize(serializer)
    }
}

pub(crate) struct PolicyTable<'a> {
    pub rules: &'a EncodedRuleTable,
    pub sources: &'a SourceMap,
}

impl Serialize for PolicyTable<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Source {
            list_id: u8,
            #[serde(with = "fe")]
            registry: [u8; 32],
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Table<'a> {
            sources: [Source; MAX_SOURCES],
            policy_len: u8,
            #[serde(serialize_with = "fe::seq")]
            rules: &'a [[u8; 32]],
        }
        let rules = self.rules;
        let slots = self.sources.slots();
        Table {
            sources: core::array::from_fn(|i| Source {
                list_id: slots[i].list_id,
                registry: slots[i].registry,
            }),
            policy_len: rules.rule_count,
            rules: &rules.rules,
        }
        .serialize(serializer)
    }
}

/// The policy section as Go `PolicyParams` reads it, every list at the key's capacity.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyParams<'a> {
    pub withdrawal_count: u8,
    #[serde(with = "fe")]
    pub withdrawal_hash: [u8; 32],
    pub withdrawals: Vec<PolicyWithdrawalRequest>,
    #[serde(with = "fe")]
    pub policy_hash: [u8; 32],
    #[serde(with = "fe")]
    pub ring_id: [u8; 32],
    #[serde(with = "fe")]
    pub own_root: [u8; 32],
    #[serde(with = "fe")]
    pub curator_root: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub public_assets: Vec<[u8; 32]>,
    #[serde(serialize_with = "fe::seq")]
    pub public_amounts: Vec<[u8; 32]>,
    #[serde(serialize_with = "fe::seq")]
    pub public_gross: Vec<[u8; 32]>,
    #[serde(flatten)]
    pub table: PolicyTable<'a>,
    /// One per output slot, zero without key escrow.
    #[serde(serialize_with = "fe::seq")]
    pub ct_hashes: Vec<[u8; 32]>,
    #[serde(serialize_with = "fe::seq")]
    pub recipients: &'a [[u8; 32]],
    #[serde(flatten)]
    pub pools: RecordPools,
    /// `Q` entries, the key's screened owners in subject order.
    pub sender_entries: Vec<PoolEntry>,
    pub owner_entries: Vec<PoolEntry>,
    pub asset_entries: Vec<PoolEntry>,
    pub public_asset_entries: Vec<u32>,
}

/// Mirror Go `TransferParams`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferParams<'a> {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(flatten)]
    pub audit: AuditParams,
    pub exempt: bool,
    pub approval_required: bool,
    /// `m`, the published slots.
    pub output_count: u8,
    /// `n`, the frame's nullifier count.
    pub input_count: u8,
    /// The deduplicated owner run.
    pub signer_count: u8,
    #[serde(with = "fe")]
    pub private_tx_hash: [u8; 32],
    #[serde(with = "fe")]
    pub private_tx_blinding: [u8; 32],
    #[serde(flatten)]
    pub policy: PolicyParams<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfidentialTransfer<'a> {
    #[serde(flatten)]
    pub transfer: TransferParams<'a>,
    pub in_proof: bool,
    pub delegate: bool,
    pub outputs: Vec<DeliveredOutput>,
    /// The input class, the slots past the spent notes carry no UTXO.
    pub inputs: Vec<Opening>,
    /// The in-proof owner, zero on the signer and authority rails.
    #[serde(with = "fe")]
    pub sender: [u8; 32],
    /// The member an authority move spends.
    #[serde(with = "fe")]
    pub sender_pk_hash: [u8; 32],
    /// The input class, the owner run in its order and zero past `signer_count`.
    #[serde(serialize_with = "fe::seq")]
    pub signers: Vec<[u8; 32]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnonymousTransfer<'a> {
    #[serde(flatten)]
    pub transfer: TransferParams<'a>,
    pub outputs: Vec<AnonymousOutput>,
    /// The hidden owner's key on an entry key, absent on a commitment key.
    #[serde(with = "option_field", skip_serializing_if = "Option::is_none")]
    pub sender_key: Option<[u8; 32]>,
    /// The input class, slots past `input_count` zero.
    pub inputs: Vec<Opening>,
    #[serde(serialize_with = "fe::seq")]
    pub party_identities: [[u8; 32]; 3],
    /// The public co-owners, zero past `signer_count`, empty on an entry key.
    #[serde(serialize_with = "fe::seq")]
    pub signers: Vec<[u8; 32]>,
    #[serde(with = "fe")]
    pub sender_nullifier_pk: [u8; 32],
    #[serde(with = "fe")]
    pub sender_viewing_key: [u8; 32],
    pub sender_address_revision: u64,
    #[serde(with = "fe")]
    pub sender_bundle_tag: [u8; 32],
    /// The digest the program computes over the reply region, zero without one.
    #[serde(with = "fe")]
    pub reply_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordWrite {
    pub entry: QueueEntryRequest,
    pub exists: bool,
    #[serde(with = "fe")]
    pub old_next: [u8; 32],
    pub old_lists: u64,
    #[serde(with = "fe")]
    pub old_escrow: [u8; 32],
    #[serde(with = "fe")]
    pub old_mint_policy: [u8; 32],
    #[serde(with = "fe")]
    pub old_withdrawal_threshold: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub old_asset_limits: [[u8; 32]; AssetLimits::FIELDS],
    #[serde(with = "fe")]
    pub old_address_hash: [u8; 32],
    pub index: u64,
    #[serde(serialize_with = "path")]
    pub path: QuadPath,
    #[serde(with = "fe")]
    pub low_member: [u8; 32],
    #[serde(with = "fe")]
    pub low_next: [u8; 32],
    pub low_lists: u64,
    #[serde(with = "fe")]
    pub low_escrow: [u8; 32],
    #[serde(with = "fe")]
    pub low_mint_policy: [u8; 32],
    #[serde(with = "fe")]
    pub low_withdrawal_threshold: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub low_asset_limits: [[u8; 32]; AssetLimits::FIELDS],
    #[serde(with = "fe")]
    pub low_address_hash: [u8; 32],
    pub low_index: u64,
    #[serde(serialize_with = "path")]
    pub low_path: QuadPath,
    /// Zero unless the write binds the pair.
    #[serde(with = "fe")]
    pub nullifier_pk: [u8; 32],
    #[serde(with = "fe")]
    pub address_ring: [u8; 32],
    #[serde(with = "fe")]
    pub view0: [u8; 32],
    #[serde(with = "fe")]
    pub view1: [u8; 32],
    pub address_revision: u64,
    #[serde(with = "fe")]
    pub escrow_ct_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QueueEntryRequest {
    #[serde(with = "fe")]
    pub member: [u8; 32],
    pub mask: u64,
    pub value: u64,
    #[serde(with = "fe")]
    pub escrow_key: [u8; 32],
    #[serde(with = "fe")]
    pub mint_policy: [u8; 32],
    #[serde(with = "fe")]
    pub withdrawal_threshold: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub asset_limits: [[u8; 32]; AssetLimits::FIELDS],
    #[serde(with = "fe")]
    pub address_hash: [u8; 32],
}

impl From<&QueueEntry> for QueueEntryRequest {
    fn from(entry: &QueueEntry) -> Self {
        let policy = entry.mint_policy.unwrap_or_default();
        Self {
            member: entry.member,
            mask: entry.mask,
            value: entry.value,
            escrow_key: entry.escrow_key,
            mint_policy: entry.mint_policy_field(),
            withdrawal_threshold: right_align(&policy.withdrawal_threshold.to_be_bytes()),
            asset_limits: policy.limits.fields(),
            address_hash: entry.address_hash,
        }
    }
}

impl From<&RecordWriteProofInput> for RecordWrite {
    fn from(write: &RecordWriteProofInput) -> Self {
        let MemberRecord {
            member: low_member,
            next: low_next,
            lists: low_lists,
            escrow_key: low_escrow,
            mint_policy: low_mint_policy,
            address_hash: low_address_hash,
        } = write.low;
        let (nullifier_pk, address_ring, [view0, view1], address_revision, escrow_ct_hash) =
            match &write.pair {
                Some(pair) => (
                    pair.address.nullifier_pk,
                    pair.address.ring_id,
                    pack_be(&pair.address.viewing_u),
                    pair.address.address_revision,
                    pair.escrow_ciphertext_hash,
                ),
                None => ([0; 32], [0; 32], [[0; 32]; 2], 0, [0; 32]),
            };
        Self {
            entry: (&write.entry).into(),
            exists: write.exists,
            old_next: write.old_next,
            old_lists: write.old_lists,
            old_escrow: write.old_escrow,
            old_mint_policy: write.old_mint_policy.field(),
            old_withdrawal_threshold: right_align(
                &write.old_mint_policy.withdrawal_threshold.to_be_bytes(),
            ),
            old_asset_limits: write.old_mint_policy.limits.fields(),
            old_address_hash: write.old_address_hash,
            index: write.slot.index,
            path: write.slot,
            low_member,
            low_next,
            low_lists,
            low_escrow,
            low_mint_policy: low_mint_policy.field(),
            low_withdrawal_threshold: right_align(
                &low_mint_policy.withdrawal_threshold.to_be_bytes(),
            ),
            low_asset_limits: low_mint_policy.limits.fields(),
            low_address_hash,
            low_index: write.low_path.index,
            low_path: write.low_path,
            nullifier_pk,
            address_ring,
            view0,
            view1,
            address_revision,
            escrow_ct_hash,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApplyRecords {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub old_root: [u8; 32],
    #[serde(with = "fe")]
    pub new_root: [u8; 32],
    pub old_next_index: u32,
    pub new_next_index: u32,
    #[serde(with = "fe")]
    pub chain_start: [u8; 32],
    #[serde(with = "fe")]
    pub chain_end: [u8; 32],
    pub count: u8,
    /// The key's batch, writes past `count` assign zeros.
    pub writes: Vec<Option<RecordWrite>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyRegister {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub member: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub nullifier_secret: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MergeSlot {
    #[serde(with = "fe")]
    pub domain: [u8; 32],
    #[serde(with = "fe")]
    pub tree_id: [u8; 32],
    #[serde(with = "fe")]
    pub amount: [u8; 32],
    #[serde(with = "fe")]
    pub blinding: [u8; 32],
    #[serde(with = "fe")]
    pub ring_data_hash: [u8; 32],
}

impl core::fmt::Debug for MergeSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            domain,
            tree_id,
            amount,
            blinding: _,
            ring_data_hash,
        } = self;
        f.debug_struct("MergeSlot")
            .field("domain", domain)
            .field("tree_id", tree_id)
            .field("amount", amount)
            .field("blinding", &REDACTED)
            .field("ring_data_hash", ring_data_hash)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MergeRequest {
    #[serde(serialize_with = "fe::seq")]
    pub party_identities: [[u8; 32]; 3],
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub private_tx_hash: [u8; 32],
    #[serde(with = "fe")]
    pub output_utxo_hash: [u8; 32],
    #[serde(with = "fe")]
    pub first_nullifier: [u8; 32],
    #[serde(with = "fe")]
    pub ring_program_id: [u8; 32],
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
    /// The SPP output ciphertext salt right aligned.
    #[serde(with = "fe")]
    pub salt: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "fe::zeroizing")]
    pub disclosure_key: Zeroizing<[u8; 32]>,
    #[serde(with = "fe")]
    pub owner_key: [u8; 32],
    #[serde(serialize_with = "fe::zeroizing")]
    pub nullifier_secret: Zeroizing<[u8; 32]>,
    /// `hash_bytes(mint)`.
    #[serde(with = "fe")]
    pub asset: [u8; 32],
    /// `merge.nullifiers.len()`, a published slot may be a hidden dummy.
    pub input_count: u8,
    pub inputs: Vec<MergeSlot>,
    #[serde(with = "fe")]
    pub output_tree_id: [u8; 32],
    #[serde(with = "fe")]
    pub output_ring_data_hash: [u8; 32],
    pub key_escrow: bool,
    #[serde(with = "fe")]
    pub member_registry_root: [u8; 32],
    #[serde(with = "fe")]
    pub ct_hash: [u8; 32],
    /// `Some` on a key escrow ring alone.
    pub member: Option<RecordOpeningRequest>,
}

/// A present record as the deposit circuit opens it.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordOpeningRequest {
    #[serde(with = "fe")]
    pub next: [u8; 32],
    pub lists: u64,
    #[serde(with = "fe")]
    pub escrow_key: [u8; 32],
    #[serde(with = "fe")]
    pub mint_policy: [u8; 32],
    #[serde(with = "fe")]
    pub withdrawal_threshold: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub asset_limits: [[u8; 32]; AssetLimits::FIELDS],
    #[serde(with = "fe")]
    pub address_hash: [u8; 32],
    pub index: u64,
    #[serde(serialize_with = "path")]
    pub path: QuadPath,
}

impl RecordOpeningRequest {
    pub fn present(record: &MemberRecord, path: &QuadPath) -> Self {
        Self {
            next: record.next,
            lists: record.lists,
            escrow_key: record.escrow_key,
            mint_policy: record.mint_policy.field(),
            withdrawal_threshold: right_align(
                &record.mint_policy.withdrawal_threshold.to_be_bytes(),
            ),
            asset_limits: record.mint_policy.limits.fields(),
            address_hash: record.address_hash,
            index: path.index,
            path: *path,
        }
    }
}

/// The audited deposit's witness, one slot per deposited note.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DepositRequest<'a> {
    #[serde(with = "fe")]
    pub public_input_hash: [u8; 32],
    #[serde(with = "fe")]
    pub context_hash: [u8; 32],
    pub count: u32,
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    pub anonymous: bool,
    #[serde(serialize_with = "fe::seq")]
    pub owner_pk_hashes: [[u8; 32]; 1],
    #[serde(serialize_with = "fe::seq")]
    pub owner_keys: [[u8; 32]; 1],
    #[serde(serialize_with = "fe::seq")]
    pub nullifier_pks: [[u8; 32]; 1],
    #[serde(serialize_with = "zeroizing_seq")]
    pub blinding_secrets: Zeroizing<[[u8; 32]; 1]>,
    #[serde(serialize_with = "fe::seq")]
    pub ct_hashes: [[u8; 32]; 1],
    pub members: [Option<RecordOpeningRequest>; 1],
    #[serde(serialize_with = "fe::zeroizing")]
    pub eph_sk: Zeroizing<[u8; 32]>,
    #[serde(serialize_with = "coordinate")]
    pub auditor_pk: X25519Pubkey,
    pub key_escrow: bool,
    #[serde(with = "fe")]
    pub member_registry_root: [u8; 32],
    #[serde(with = "fe")]
    pub curator_root: [u8; 32],
    #[serde(with = "fe")]
    pub policy_hash: [u8; 32],
    #[serde(serialize_with = "fe::seq")]
    pub assets: [[u8; 32]; 1],
    #[serde(serialize_with = "fe::seq")]
    pub amounts: [[u8; 32]; 1],
    /// `None` without a written policy, `asset_records` then opens nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<PolicyTable<'a>>,
    pub asset_records: [Option<MemberOpening>; 1],
    /// `None` without a curator source.
    pub curator_asset_records: [Option<MemberOpening>; 1],
}

/// The Solana key an owner identity hashes, the disclosure names it.
pub(crate) fn owner_key(owner: &PublicKey) -> Result<[u8; 32], RingError> {
    Ok(owner.confidential_view_tag()?)
}

/// The circuits witness the untagged 32-byte coordinate.
fn coordinate<S: Serializer>(key: &X25519Pubkey, serializer: S) -> Result<S::Ok, S::Error> {
    fe::bytes(&key.u(), serializer)
}

fn levels<S: Serializer>(
    levels: &&[[[u8; 32]; QUAD_ARITY - 1]],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    struct Level<'a>(&'a [[u8; 32]; QUAD_ARITY - 1]);
    impl Serialize for Level<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            fe::seq(self.0, serializer)
        }
    }
    serializer.collect_seq(levels.iter().map(Level))
}

/// Every level's siblings from the leaf up, in child order.
fn path<S: Serializer>(path: &QuadPath, serializer: S) -> Result<S::Ok, S::Error> {
    let flat: Vec<[u8; 32]> = path
        .siblings
        .iter()
        .flat_map(|level: &[[u8; 32]; QUAD_ARITY - 1]| level.iter().copied())
        .collect();
    fe::seq(&flat, serializer)
}

fn zeroizing_seq<S: Serializer, const N: usize>(
    values: &Zeroizing<[[u8; 32]; N]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    fe::seq(values.as_slice(), serializer)
}

mod option_field {
    use serde::Serializer;

    use crate::prover::fe;

    pub(crate) fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => fe::bytes(value, serializer),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct PolicyWithdrawalRequest {
    #[serde(with = "fe")]
    pub owner: [u8; 32],
    #[serde(with = "fe")]
    pub asset: [u8; 32],
    #[serde(with = "fe")]
    pub amount: [u8; 32],
}
