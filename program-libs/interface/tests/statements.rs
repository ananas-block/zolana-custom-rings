//! Pins `test-vectors/proof/ring-statements.json` for the Go circuits and the TS SDK.

use custom_ring_interface::tracking::{TrackingEntry, TRACKING_EMPTY_ROOT};
use custom_ring_interface::{
    change_bitmap, ciphertext_digest, domain, exits_bitmap, output_ciphertext_chain,
    restrictive_write, sender_bundle_len, slot_ciphertext_hash, AnonymousAuditKey,
    ApplyEnrollmentsStatement, ApplyRecordsStatement, AuditHead, AuditKey, AuditLayout,
    AuditStreamLayout, ConfidentialSender, CustomRingError, DepositContext, DepositPublicInput,
    DepositRegistry, DepositedAsset, FramedSenderBundle, RegisterKeyStatement, RingOutput,
    SignerSet, TransferFamily, TransferStatement, ANONYMOUS_RECORD_LEN, AUDIT_HEAD_ELEMENTS,
    DELIVERED_BODY_LEN, DEPOSIT_PUBLIC_INPUT_ELEMENTS, ESCROWED_DELIVERED_BODY_LEN,
    ESCROWED_EXIT_RECORD_LEN, EXIT_RECORD_LEN, RECIPIENT_BODY_LEN,
};
use custom_ring_interface::{PublicLeg, PublicSlotError, PublicSlots, SOL_ASSET_ADDRESS};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_hasher::{
    hash_chain::create_hash_chain_4_from_slice,
    primitives::{hash_bytes, right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use spr_interface::instruction::InterfaceTransfer;
use zolana_ring_policy::{Member, OutflowLimit};

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/proof/ring-statements.json"
);
/// `q - 1200`, the amount field of a 1200 withdrawal.
const WITHDRAWAL_1200: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffb51";

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct StatementVectors {
    description: String,
    transfer: Vec<TransferCase>,
    apply_records: ApplyCase,
    restrictive: Vec<RestrictiveCase>,
    apply_enrollments: ApplyEnrollmentsCase,
    tracking: TrackingCase,
    register_key: RegisterKeyCase,
    deposit: DepositCase,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RestrictiveCase {
    mask: u64,
    value: u64,
    replaces_mint_policy: bool,
    restrictive: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ApplyEnrollmentsCase {
    old_root: String,
    new_root: String,
    old_next_index: u32,
    new_next_index: u32,
    chain_start: String,
    chain_end: String,
    count: u64,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct TrackingCase {
    empty_root: String,
    member: String,
    nullifier_pk: String,
    ct_hash: String,
    viewing_u: String,
    revision: u64,
    list_tag: String,
    entry_hash: String,
    chain_from_zero: String,
    nullifier_secret: String,
    list_salt: String,
    secret_list_tag: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct OutputCase {
    /// `delivered`, `anonymous` or `exit`.
    kind: String,
    hash: String,
    u: Option<String>,
    body: Option<String>,
    record: Option<String>,
    recipient_body: Option<String>,
    /// Null on change and exit.
    tag: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct TransferCase {
    /// `confidential` or `anonymous`.
    family: String,
    /// `signer`, `in_proof`, `delegate`, `anonymous` or `entry`.
    rail: String,
    in_proof: Option<bool>,
    delegate: Option<bool>,
    exempt: bool,
    approval_required: bool,
    first_nullifier: String,
    ring_id: String,
    tx_viewing_u: String,
    auditor_pubkey: String,
    eph_u: String,
    envelope: String,
    envelope_digest: String,
    salt: String,
    layout: u8,
    outputs: Vec<OutputCase>,
    output_capacity: usize,
    output_ciphertext_chain: String,
    input_count: usize,
    exits_bitmap: u64,
    change_bitmap: Option<u64>,
    sender_bundle: Option<String>,
    sender_bundle_tag: Option<String>,
    private_tx_hash: String,
    sender: Option<String>,
    party_identities: Option<Vec<String>>,
    signer_count: usize,
    signer_chain: String,
    replies: Option<String>,
    policy_hash: String,
    own_root: String,
    curator_root: String,
    recipients: Option<Vec<String>>,
    public_assets: Vec<String>,
    public_amounts: Vec<String>,
    public_gross: Vec<String>,
    withdrawal_hash: String,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ApplyCase {
    old_root: String,
    new_root: String,
    old_next_index: u32,
    new_next_index: u32,
    chain_start: String,
    chain_end: String,
    count: u64,
    restrictive: bool,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RegisterKeyCase {
    ring_id: String,
    member: String,
    nullifier_pk: String,
    list_tag: String,
    auditor_pubkey: String,
    eph_u: String,
    ciphertext: String,
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct DepositCase {
    program_id: String,
    tree: String,
    spp_data: String,
    context_hash: String,
    anonymous: bool,
    owner_utxo_hashes: Vec<String>,
    ciphertexts: Vec<String>,
    auditor_pubkey: String,
    eph_pk: String,
    assets: Vec<String>,
    amounts: Vec<u64>,
    key_escrow: bool,
    member_registry_root: Option<String>,
    curator_root: Option<String>,
    policy_hash: Option<String>,
    elements: Vec<String>,
    public_input_hash: String,
}

fn field(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0x1e;
    value
}

fn tagged(seed: u8) -> [u8; 33] {
    let mut key = [seed; 33];
    key[0] = 4;
    key
}

fn hexes(values: &[[u8; 32]]) -> Vec<String> {
    values.iter().map(hex::encode).collect()
}

struct Values {
    fields: Vec<[u8; 32]>,
    keys: Vec<[u8; 32]>,
    ciphertexts: [[u8; 104]; 8],
    envelope: Vec<u8>,
    tags: [[u8; 32]; 8],
    bodies: [[u8; RECIPIENT_BODY_LEN]; 8],
    bundle: Vec<u8>,
    replies: Vec<u8>,
    auditor_pubkey: [u8; 33],
    ring_id: [u8; 32],
    salt: [u8; 16],
}

impl Values {
    fn new() -> Self {
        Self {
            fields: (0..80).map(field).collect(),
            keys: (0..16).map(|seed| [0x60 + seed; 32]).collect(),
            ciphertexts: core::array::from_fn(|slot| [0x90 + slot as u8; 104]),
            envelope: (0..1024u32).map(|byte| byte as u8 ^ 0x93).collect(),
            tags: core::array::from_fn(|slot| field(0xb0 + slot as u8)),
            bodies: core::array::from_fn(|slot| [0xc0 + slot as u8; RECIPIENT_BODY_LEN]),
            bundle: (0..1024u32).map(|byte| byte as u8 ^ 0x2d).collect(),
            replies: (0..1024u32).map(|byte| byte as u8 ^ 0x17).collect(),
            auditor_pubkey: tagged(0xa1),
            ring_id: hash_bytes(&[0x77; 32]).unwrap(),
            salt: [0x5c; 16],
        }
    }

    fn head(&self, layout: AuditLayout, envelope: AuditStreamLayout) -> AuditHead<'_> {
        AuditHead {
            first_nullifier: &self.fields[1],
            ring_id: &self.ring_id,
            tx_viewing_u: &self.keys[0],
            auditor_pubkey: &self.auditor_pubkey,
            eph_u: &self.keys[1],
            envelope: &self.envelope[..envelope.envelope().len],
            salt: &self.salt,
            layout,
        }
    }

    fn exit(&self, slot: usize, record_len: usize) -> RingOutput<'_> {
        RingOutput::Exit {
            hash: &self.fields[20 + slot],
            owner_tag: &self.keys[8],
            payload: &[],
            record: &self.ciphertexts[slot][..record_len],
        }
    }

    fn delivered_outputs(
        &self,
        outputs: usize,
        exits: &[usize],
        key_escrow: bool,
    ) -> Vec<RingOutput<'_>> {
        let (body_len, record_len) = match key_escrow {
            true => (ESCROWED_DELIVERED_BODY_LEN, ESCROWED_EXIT_RECORD_LEN),
            false => (DELIVERED_BODY_LEN, EXIT_RECORD_LEN),
        };
        (0..outputs)
            .map(|slot| match exits.contains(&slot) {
                true => self.exit(slot, record_len),
                false => RingOutput::Delivered {
                    hash: &self.fields[20 + slot],
                    u: &self.keys[4 + slot % 4],
                    body: &self.ciphertexts[slot][..body_len],
                },
            })
            .collect()
    }

    fn anonymous_outputs(&self) -> Vec<RingOutput<'_>> {
        (0..4)
            .map(|slot| match slot {
                3 => self.exit(slot, EXIT_RECORD_LEN),
                _ => self.anonymous(slot, self.anonymous_body(slot)),
            })
            .collect()
    }

    fn anonymous<'a>(
        &'a self,
        slot: usize,
        body: Option<&'a [u8; RECIPIENT_BODY_LEN]>,
    ) -> RingOutput<'a> {
        RingOutput::Anonymous {
            hash: &self.fields[20 + slot],
            tag: if body.is_some() {
                &self.tags[slot]
            } else {
                &[0; 32]
            },
            body,
            record: &self.ciphertexts[slot][..ANONYMOUS_RECORD_LEN],
        }
    }

    /// Slot 0 is change, every other ring slot a recipient body.
    fn anonymous_body(&self, slot: usize) -> Option<&[u8; RECIPIENT_BODY_LEN]> {
        (slot != 0).then_some(&self.bodies[slot])
    }

    fn sender_bundle(&self, outputs: usize) -> FramedSenderBundle<'_> {
        FramedSenderBundle {
            tag: &self.tags[7],
            body: &self.bundle[..sender_bundle_len(outputs)],
        }
    }
}

/// The stream of a statement fixture, its exits read from the outputs.
fn stream(key: AuditKey, inputs: usize, outputs: &[RingOutput<'_>]) -> AuditStreamLayout {
    AuditStreamLayout {
        key,
        key_escrow: false,
        inputs,
        outputs: outputs.len(),
        capacity: outputs.len(),
        exits: exits_bitmap(outputs),
    }
}

fn output_case(output: &RingOutput<'_>) -> OutputCase {
    let (kind, u, body, record) = match output {
        RingOutput::Delivered { u, body, .. } => ("delivered", Some(*u), Some(*body), None),
        RingOutput::Anonymous { record, .. } => ("anonymous", None, None, Some(*record)),
        RingOutput::Exit { record, .. } => ("exit", None, None, Some(*record)),
    };
    let recipient_body = match output {
        RingOutput::Anonymous {
            body: Some(body), ..
        } => Some(hex::encode(body)),
        _ => None,
    };
    OutputCase {
        kind: kind.to_string(),
        hash: hex::encode(output.hash()),
        u: u.map(hex::encode),
        body: body.map(hex::encode),
        record: record.map(hex::encode),
        tag: recipient_body
            .is_some()
            .then(|| hex::encode(output.recipient_tag_cell())),
        recipient_body,
    }
}

fn transfer_case(statement: &TransferStatement<'_>) -> TransferCase {
    let head = statement.head;
    let confidential = match statement.family {
        TransferFamily::Confidential { sender, recipients } => Some((
            matches!(sender, ConfidentialSender::InProof(_)),
            matches!(sender, ConfidentialSender::Authority),
            *sender.identity(),
            recipients,
        )),
        TransferFamily::Anonymous { .. } => None,
    };
    let parties = match statement.family {
        TransferFamily::Anonymous {
            party_identities, ..
        } => Some(hexes(party_identities)),
        TransferFamily::Confidential { .. } => None,
    };
    let (sender_bundle, sender_bundle_tag, replies) = match statement.family {
        TransferFamily::Anonymous {
            sender, replies, ..
        } => (
            Some(hex::encode(sender.body)),
            Some(hex::encode(sender.tag)),
            replies.map(hex::encode),
        ),
        TransferFamily::Confidential { .. } => (None, None, None),
    };
    let rail = match (confidential, head.layout.full_openings) {
        (Some((true, _, _, _)), _) => "in_proof",
        (Some((_, true, _, _)), _) => "delegate",
        (Some(_), _) => "signer",
        (None, true) => "entry",
        (None, false) => "anonymous",
    };
    TransferCase {
        family: match confidential {
            Some(_) => "confidential",
            None => "anonymous",
        }
        .to_string(),
        rail: rail.to_string(),
        in_proof: confidential.map(|(in_proof, ..)| in_proof),
        delegate: confidential.map(|(_, delegate, ..)| delegate),
        exempt: statement.exempt,
        approval_required: statement.approval_required,
        first_nullifier: hex::encode(head.first_nullifier),
        ring_id: hex::encode(head.ring_id),
        tx_viewing_u: hex::encode(head.tx_viewing_u),
        auditor_pubkey: hex::encode(head.auditor_pubkey),
        eph_u: hex::encode(head.eph_u),
        envelope: hex::encode(head.envelope),
        envelope_digest: hex::encode(ciphertext_digest(head.envelope).unwrap()),
        salt: hex::encode(head.salt),
        layout: head.layout.value(),
        outputs: statement.outputs.iter().map(output_case).collect(),
        output_capacity: statement.output_capacity,
        output_ciphertext_chain: hex::encode(
            output_ciphertext_chain(statement.outputs, statement.output_capacity).unwrap(),
        ),
        input_count: statement.input_count,
        exits_bitmap: exits_bitmap(statement.outputs),
        change_bitmap: sender_bundle
            .is_some()
            .then(|| change_bitmap(statement.outputs)),
        sender_bundle,
        sender_bundle_tag,
        private_tx_hash: hex::encode(statement.private_tx_hash),
        sender: confidential.map(|(_, _, sender, _)| hex::encode(sender)),
        party_identities: parties,
        signer_count: statement.signers.count,
        signer_chain: hex::encode(statement.signers.chain),
        replies,
        policy_hash: hex::encode(statement.policy_hash),
        own_root: hex::encode(statement.own_root),
        curator_root: hex::encode(statement.curator_root),
        recipients: confidential.map(|(_, _, _, recipients)| hexes(recipients)),
        public_assets: hexes(statement.public_assets),
        public_amounts: hexes(statement.public_amounts),
        public_gross: hexes(statement.public_gross),
        withdrawal_hash: hex::encode(statement.withdrawal_hash),
        elements: hexes(&statement.elements().unwrap()),
        public_input_hash: hex::encode(statement.hash().unwrap()),
    }
}

fn compute_vectors() -> StatementVectors {
    let values = Values::new();
    let (escrowed, delivered, anonymous) = (
        values.delivered_outputs(2, &[1], true),
        values.delivered_outputs(8, &[2, 5], false),
        values.anonymous_outputs(),
    );
    let confidential_key = AuditKey::Confidential { class: 16 };
    let commitment_key = AuditKey::Anonymous(AnonymousAuditKey::Commitment { class: 16 });
    let entry_key = AuditKey::Anonymous(AnonymousAuditKey::Entry { class: 8 });
    let assets = [values.fields[60], values.fields[61], [0; 32]];
    let mut withdrawal = [0u8; 32];
    hex::decode_to_slice(WITHDRAWAL_1200, &mut withdrawal).unwrap();
    let amounts = [right_aligned(500), withdrawal, [0; 32]];
    let owner_signer = solana_owner_identity(&[0x42; 32]).unwrap();
    let zero = [0u8; 32];
    let gross = [zero, right_aligned(1200), zero];
    let no_withdrawals = custom_ring_interface::policy_withdrawal_hash(&[]).unwrap();
    let eight_recipients: [[u8; 32]; 8] = core::array::from_fn(|slot| values.fields[62 + slot]);
    let no_flags = AuditLayout::default();
    let signer_policy = TransferStatement {
        head: values.head(no_flags, stream(confidential_key, 2, &delivered)),
        family: TransferFamily::Confidential {
            sender: ConfidentialSender::Signer,
            recipients: &eight_recipients,
        },
        exempt: false,
        approval_required: true,
        outputs: &delivered,
        output_capacity: 8,
        input_count: 2,
        private_tx_hash: &values.fields[3],
        signers: SignerSet::new([[0x42; 32], [0x43; 32], [0x42; 32]].iter(), 16).unwrap(),
        policy_hash: &values.fields[6],
        own_root: &values.fields[7],
        curator_root: &values.fields[8],
        public_assets: &assets,
        public_amounts: &amounts,
        public_gross: &gross,
        withdrawal_hash: &no_withdrawals,
    };
    let signer_exempt = TransferStatement {
        family: TransferFamily::Confidential {
            sender: ConfidentialSender::Signer,
            recipients: &[zero; 8],
        },
        exempt: true,
        approval_required: false,
        policy_hash: &zero,
        curator_root: &zero,
        ..signer_policy
    };
    let in_proof_policy = TransferStatement {
        family: TransferFamily::Confidential {
            sender: ConfidentialSender::InProof(&owner_signer),
            recipients: &eight_recipients,
        },
        signers: SignerSet::default(),
        ..signer_policy
    };
    let no_slots = [zero; 3];
    let delegate_move = TransferStatement {
        head: values.head(
            AuditLayout {
                key_escrow: true,
                full_openings: false,
            },
            stream(confidential_key, 2, &escrowed),
        ),
        family: TransferFamily::Confidential {
            sender: ConfidentialSender::Authority,
            recipients: &[values.fields[62], values.fields[63]],
        },
        approval_required: false,
        outputs: &escrowed,
        output_capacity: 2,
        signers: SignerSet::default(),
        curator_root: &zero,
        public_assets: &no_slots,
        public_amounts: &no_slots,
        public_gross: &no_slots,
        ..signer_policy
    };
    let parties = [right_aligned(11), right_aligned(12), zero];
    let anonymous_policy_transfer = TransferStatement {
        head: values.head(no_flags, stream(commitment_key, 3, &anonymous)),
        family: TransferFamily::Anonymous {
            party_identities: &parties,
            sender: values.sender_bundle(4),
            replies: None,
        },
        approval_required: false,
        outputs: &anonymous,
        output_capacity: 4,
        input_count: 3,
        signers: SignerSet::new([[0x44; 32]].iter(), 16).unwrap(),
        ..signer_policy
    };
    let anonymous_exempt = TransferStatement {
        exempt: true,
        policy_hash: &zero,
        curator_root: &zero,
        signers: SignerSet::new([].iter(), 16).unwrap(),
        ..anonymous_policy_transfer
    };
    let anonymous_compact = TransferStatement {
        family: TransferFamily::Anonymous {
            party_identities: &parties,
            sender: values.sender_bundle(2),
            replies: Some(&values.replies[..97]),
        },
        outputs: &anonymous[..2],
        ..anonymous_policy_transfer
    };
    let entry = TransferStatement {
        head: values.head(
            AuditLayout {
                full_openings: true,
                ..no_flags
            },
            stream(entry_key, 3, &anonymous),
        ),
        policy_hash: &zero,
        curator_root: &zero,
        signers: SignerSet::default(),
        ..anonymous_policy_transfer
    };
    let confidential_compact = TransferStatement {
        family: TransferFamily::Confidential {
            sender: ConfidentialSender::Signer,
            recipients: &eight_recipients[..5],
        },
        outputs: &delivered[..5],
        ..signer_policy
    };
    let transfers = [
        signer_policy,
        signer_exempt,
        in_proof_policy,
        delegate_move,
        anonymous_policy_transfer,
        anonymous_exempt,
        entry,
        anonymous_compact,
        confidential_compact,
    ];
    let apply = ApplyRecordsStatement {
        old_root: values.fields[9],
        new_root: values.fields[10],
        old_next_index: 5,
        new_next_index: 17,
        chain_start: values.fields[11],
        chain_end: values.fields[12],
        count: 16,
        restrictive: true,
    };
    let apply_enrollments = ApplyEnrollmentsStatement {
        old_root: values.fields[11],
        new_root: values.fields[12],
        old_next_index: 7,
        new_next_index: 9,
        chain_start: values.fields[9],
        chain_end: values.fields[10],
        count: 2,
    };
    let tracking_entry = TrackingEntry {
        member: values.fields[14],
        nullifier_pk: values.fields[13],
        ct_hash: values.fields[15],
        viewing_u: values.keys[9],
        revision: 3,
        list_tag: values.fields[16],
    };
    let nullifier_secret = right_aligned(0x07);
    let list_salt = domain::list_salt(&nullifier_secret).unwrap();
    let ring_id = values.fields[17];
    let list_tag = values.fields[16];
    let register = RegisterKeyStatement {
        ring_id: &ring_id,
        member: &owner_signer,
        nullifier_pk: &values.fields[13],
        list_tag: &list_tag,
        auditor_pubkey: &values.auditor_pubkey,
        eph_u: &values.keys[9],
        ciphertext: &values.keys[10],
    };
    let program_id = [0x77; 32];
    let tree = [0x55; 32];
    let spp_data: Vec<u8> = (0..75u8).map(|byte| byte ^ 0x3c).collect();
    let context_hash = DepositContext {
        program_id: &program_id,
        tree: &tree,
        spp_data: &spp_data,
    }
    .hash()
    .unwrap();
    let owners = [values.fields[14], values.fields[15]];
    let ciphertexts = [[0x21; 96], [0x22; 96]];
    let eph_pk = tagged(0xa2);
    let deposited = [
        DepositedAsset {
            asset: values.fields[17],
            amount: 1_000,
        },
        DepositedAsset {
            asset: values.fields[18],
            amount: 2_000,
        },
    ];
    let deposit = DepositPublicInput {
        context_hash: &context_hash,
        anonymous: false,
        owner_utxo_hashes: &owners,
        ciphertexts: &ciphertexts,
        assets: &deposited,
        auditor_pk: &values.auditor_pubkey,
        eph_pk: &eph_pk,
        registry: Some(DepositRegistry {
            own_root: &values.fields[16],
            curator_root: Some(&values.fields[20]),
            key_escrow: true,
            policy_hash: Some(&values.fields[19]),
        }),
    };
    StatementVectors {
        description: "Every ring statement and its public input HashChain4(elements). The transfer \
                      head is [CRTX, n0, ring_id, pack_be(0x04 || tx_u), pack_be(auditor_pubkey), \
                      pack_be(0x04 || eph_u), digest(envelope), salt, layout] with the frame's \
                      random salt and layout = key_escrow << 1 | full_openings << 3. \
                      digest(ct) = Poseidon(u32 len(ct), HashChain4(pack_left31(ct))). Each \
                      envelope has the length of its stream layout, the delivered slots carry \
                      the body and the anonymous and exit slots the record the auditor message \
                      carries. The deposit statement is HashChain(elements) \
                      over CRDP, the context hash of the program id, tree and SPP data, the \
                      count, the anonymous flag, each owner hash with its capsule ciphertext hash \
                      zero padded to 8 slots, both tagged keys packed, the escrow flag, the \
                      registry root, the curator root, the policy hash and each asset hash with its amount zero \
                      padded to 8 slots. The transfer statements are version 3, HashChain4 over the \
                      audit head under CRTX. The confidential family then holds in_proof, delegate, \
                      exempt, approval_required, output_count, output_chain, \
                      output_ciphertext_chain HashChain4(hash_bytes(ct_i)), recipient_key_chain, \
                      input_count, exits_bitmap, private_tx_hash, sender, signer_count, \
                      signer_chain, policy_hash, own_root, curator_root, one recipient per capacity \
                      slot, asset, net and gross per public slot, withdrawal_hash, the element count \
                      and the version. The anonymous family holds exempt, approval_required, \
                      output_count, output_chain, output_ciphertext_chain, recipient_body_chain \
                      HashChain4(hash_bytes(body_i)), recipient_tag_chain, HashChain4 of the tag of \
                      each body-bearing slot, zero elsewhere, zero filled to the capacity, then \
                      the bundle tag, change_bitmap, digest(sender bundle), \
                      input_count, exits_bitmap, private_tx_hash, the three party identities, \
                      signer_count, signer_chain, policy_hash, own_root, curator_root, the public \
                      slots, withdrawal_hash, digest(replies) or zero, the element count and the \
                      version. Every per-slot chain is zero filled to the capacity. signer_chain is \
                      HashChain4 over the deduplicated owner identities zero filled to the key's S, \
                      and zero when signer_count is zero on every rail. Produced by \
                      program-libs/interface/tests/statements.rs."
            .to_string(),
        transfer: transfers.iter().map(transfer_case).collect(),
        apply_records: ApplyCase {
            old_root: hex::encode(apply.old_root),
            new_root: hex::encode(apply.new_root),
            old_next_index: apply.old_next_index,
            new_next_index: apply.new_next_index,
            chain_start: hex::encode(apply.chain_start),
            chain_end: hex::encode(apply.chain_end),
            count: apply.count,
            restrictive: apply.restrictive,
            elements: hexes(&apply.elements()),
            public_input_hash: hex::encode(apply.hash().unwrap()),
        },
        restrictive: restrictive_cases(),
        apply_enrollments: ApplyEnrollmentsCase {
            old_root: hex::encode(apply_enrollments.old_root),
            new_root: hex::encode(apply_enrollments.new_root),
            old_next_index: apply_enrollments.old_next_index,
            new_next_index: apply_enrollments.new_next_index,
            chain_start: hex::encode(apply_enrollments.chain_start),
            chain_end: hex::encode(apply_enrollments.chain_end),
            count: apply_enrollments.count,
            elements: hexes(&apply_enrollments.elements()),
            public_input_hash: hex::encode(apply_enrollments.hash().unwrap()),
        },
        tracking: TrackingCase {
            empty_root: hex::encode(TRACKING_EMPTY_ROOT),
            member: hex::encode(tracking_entry.member),
            nullifier_pk: hex::encode(tracking_entry.nullifier_pk),
            ct_hash: hex::encode(tracking_entry.ct_hash),
            viewing_u: hex::encode(tracking_entry.viewing_u),
            revision: tracking_entry.revision,
            list_tag: hex::encode(tracking_entry.list_tag),
            entry_hash: hex::encode(tracking_entry.hash().unwrap()),
            chain_from_zero: hex::encode(tracking_entry.chained(&[0; 32]).unwrap()),
            nullifier_secret: hex::encode(nullifier_secret),
            list_salt: hex::encode(list_salt),
            secret_list_tag: hex::encode(domain::list_tag(&list_salt).unwrap()),
        },
        register_key: RegisterKeyCase {
            ring_id: hex::encode(register.ring_id),
            member: hex::encode(register.member),
            nullifier_pk: hex::encode(register.nullifier_pk),
            list_tag: hex::encode(register.list_tag),
            auditor_pubkey: hex::encode(register.auditor_pubkey),
            eph_u: hex::encode(register.eph_u),
            ciphertext: hex::encode(register.ciphertext),
            elements: hexes(&register.elements().unwrap()),
            public_input_hash: hex::encode(register.hash().unwrap()),
        },
        deposit: DepositCase {
            program_id: hex::encode(program_id),
            tree: hex::encode(tree),
            spp_data: hex::encode(&spp_data),
            context_hash: hex::encode(context_hash),
            anonymous: deposit.anonymous,
            owner_utxo_hashes: hexes(&owners),
            ciphertexts: ciphertexts.iter().map(hex::encode).collect(),
            auditor_pubkey: hex::encode(deposit.auditor_pk),
            eph_pk: hex::encode(deposit.eph_pk),
            assets: deposited.iter().map(|value| hex::encode(value.asset)).collect(),
            amounts: deposited.iter().map(|value| value.amount).collect(),
            key_escrow: deposit.registry.is_some_and(|registry| registry.key_escrow),
            member_registry_root: deposit
                .registry
                .map(|registry| hex::encode(registry.own_root)),
            curator_root: deposit
                .registry
                .and_then(|registry| registry.curator_root)
                .map(hex::encode),
            policy_hash: deposit
                .registry
                .and_then(|registry| registry.policy_hash)
                .map(hex::encode),
            elements: hexes(&deposit.elements().unwrap()),
            public_input_hash: hex::encode(deposit.hash().unwrap()),
        },
    }
}

/// Every list direction, a neutral list and the mint settings, each alone and one mixed batch.
fn restrictive_cases() -> Vec<RestrictiveCase> {
    use zolana_ring_policy::ListId::{Allow, Approval, Block, Frozen, Reader};
    let set = |list: zolana_ring_policy::ListId| (list.record_bit(), list.record_bit(), false);
    let clear = |list: zolana_ring_policy::ListId| (list.record_bit(), 0, false);
    [
        set(Allow),
        clear(Allow),
        set(Approval),
        clear(Approval),
        set(Block),
        clear(Block),
        set(Frozen),
        clear(Frozen),
        set(Reader),
        clear(Reader),
        (0, 0, false),
        (0, 0, true),
        (
            Allow.record_bit() | Block.record_bit(),
            Allow.record_bit(),
            false,
        ),
        (
            Allow.record_bit() | Frozen.record_bit(),
            Allow.record_bit() | Frozen.record_bit(),
            false,
        ),
    ]
    .into_iter()
    .map(|(mask, value, replaces_mint_policy)| RestrictiveCase {
        mask,
        value,
        replaces_mint_policy,
        restrictive: restrictive_write(mask, value, replaces_mint_policy),
    })
    .collect()
}

fn right_aligned(amount: u64) -> [u8; 32] {
    spr_hasher::primitives::right_align(&amount.to_be_bytes())
}

#[test]
fn restrictive_write_follows_list_direction() {
    let flags: Vec<bool> = restrictive_cases()
        .iter()
        .map(|case| case.restrictive)
        .collect();
    assert_eq!(
        flags,
        [
            false, true, false, true, true, false, true, false, false, false, false, true, false,
            true
        ]
    );
}

#[test]
fn ring_statements_vector() {
    let committed: StatementVectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vectors());
    let transfer: Vec<usize> = committed
        .transfer
        .iter()
        .map(|case| case.elements.len())
        .collect();
    assert_eq!(transfer, [49, 49, 49, 43, 45, 45, 45, 45, 49]);
    assert_eq!(
        committed.deposit.elements.len(),
        DEPOSIT_PUBLIC_INPUT_ELEMENTS
    );
}

#[test]
#[ignore = "rewrites test-vectors/proof/ring-statements.json"]
fn write_ring_statements_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}

#[test]
fn anonymous_and_exit_slots_contribute_no_recipient_key() {
    let values = Values::new();
    for output in values.anonymous_outputs() {
        assert_eq!(output.recipient_key_fields(), [[0; 32]; 2]);
    }
}

#[test]
fn the_ciphertext_digest_tags_the_length_over_the_left_packed_chain() {
    let ciphertext: Vec<u8> = (1..=40).collect();
    let mut first = [0u8; 32];
    first[1..].copy_from_slice(&ciphertext[..31]);
    let mut second = [0u8; 32];
    second[1..10].copy_from_slice(&ciphertext[31..]);
    let chain = create_hash_chain_4_from_slice(&[first, second]).unwrap();
    assert_eq!(
        ciphertext_digest(&ciphertext).unwrap(),
        Poseidon::hashv(&[&right_align(&40u32.to_be_bytes()), &chain]).unwrap()
    );
    // Trailing zeros pack to the same chain, the length tag alone tells the two apart.
    let padded = [&ciphertext[..], &[0]].concat();
    assert_ne!(
        ciphertext_digest(&padded).unwrap(),
        ciphertext_digest(&ciphertext).unwrap()
    );
}

#[test]
fn the_output_ciphertext_chain_hashes_each_slot_at_its_length() {
    let values = Values::new();
    for outputs in [
        values.delivered_outputs(8, &[2, 5], false),
        values.delivered_outputs(2, &[1], true),
        values.anonymous_outputs(),
    ] {
        let hashes: Vec<[u8; 32]> = outputs
            .iter()
            .map(|output| slot_ciphertext_hash(output.ciphertext()).unwrap())
            .collect();
        assert_eq!(
            output_ciphertext_chain(&outputs, outputs.len()).unwrap(),
            create_hash_chain_4_from_slice(&hashes).unwrap()
        );
        // An omitted slot reads zero at the key's width.
        let last = outputs.len() - 1;
        let mut filled = hashes.clone();
        filled[last] = [0; 32];
        assert_eq!(
            output_ciphertext_chain(&outputs[..last], outputs.len()).unwrap(),
            create_hash_chain_4_from_slice(&filled).unwrap()
        );
    }
    assert_eq!(
        slot_ciphertext_hash(&[7; EXIT_RECORD_LEN]).unwrap(),
        hash_bytes(&[7; EXIT_RECORD_LEN]).unwrap()
    );
    assert!(slot_ciphertext_hash(&[7; 41]).is_err());
    assert!(slot_ciphertext_hash(&[7; 105]).is_err());
    assert!(slot_ciphertext_hash(&[]).is_err());
}

/// Repeats collapse in run order, only the run's owners count, a reorder moves the chain.
#[test]
fn the_signer_set_dedups_by_first_occurrence_and_fills_to_the_slots() {
    let (first, second) = ([0x41; 32], [0x42; 32]);
    let identity = |key| solana_owner_identity(key).unwrap();
    let set = SignerSet::new([first, second, first].iter(), 4).unwrap();
    assert_eq!(set.count, 2);
    assert_eq!(
        set.chain,
        create_hash_chain_4_from_slice(&[identity(&first), identity(&second), [0; 32], [0; 32]])
            .unwrap()
    );
    assert_ne!(
        set.chain,
        SignerSet::new([second, first].iter(), 4).unwrap().chain
    );
    assert_eq!(
        SignerSet::new([first, second].iter(), 1),
        Err(CustomRingError::OwnerSignerCount)
    );
    assert_eq!(
        SignerSet::new([first, first].iter(), 1).unwrap().count,
        1,
        "a repeat takes one slot"
    );
    for slots in [0, 2, 16] {
        assert_eq!(
            SignerSet::new(core::iter::empty(), slots),
            Ok(SignerSet::default())
        );
    }
    assert_eq!(SignerSet::default().chain, [0; 32]);
}

/// One statement of each family at every keyed output count, a compact frame keeps the key's width.
#[test]
fn the_element_count_is_forty_one_plus_capacity_or_forty_five() {
    let values = Values::new();
    let zero = [0u8; 32];
    let slots = [zero; 3];
    let parties = [zero; 3];
    let recipients = [zero; 8];
    let confidential = values.delivered_outputs(8, &[], false);
    for capacity in [2usize, 4, 8] {
        for published in [1, capacity] {
            let statement = TransferStatement {
                head: values.head(
                    AuditLayout::default(),
                    stream(
                        AuditKey::Confidential { class: 16 },
                        1,
                        &confidential[..published],
                    ),
                ),
                family: TransferFamily::Confidential {
                    sender: ConfidentialSender::Signer,
                    recipients: &recipients[..published],
                },
                exempt: false,
                approval_required: false,
                outputs: &confidential[..published],
                output_capacity: capacity,
                input_count: 1,
                private_tx_hash: &zero,
                signers: SignerSet::default(),
                policy_hash: &zero,
                own_root: &zero,
                curator_root: &zero,
                public_assets: &slots,
                public_amounts: &slots,
                public_gross: &slots,
                withdrawal_hash: &zero,
            };
            let expected = 41 + capacity;
            assert_eq!(statement.element_count(), expected);
            let elements = statement.elements().unwrap();
            assert_eq!(elements.len(), expected);
            assert_eq!(elements[16], right_aligned(published as u64));
            assert_eq!(elements[elements.len() - 2], right_aligned(expected as u64));
            assert_eq!(elements[elements.len() - 1], right_aligned(3));
            let anonymous = TransferStatement {
                family: TransferFamily::Anonymous {
                    party_identities: &parties,
                    sender: values.sender_bundle(published),
                    replies: None,
                },
                ..statement
            };
            assert_eq!(anonymous.element_count(), 45);
            let elements = anonymous.elements().unwrap();
            assert_eq!(elements.len(), 45);
            assert_eq!(elements[elements.len() - 2], right_aligned(45));
        }
    }
}

#[test]
fn the_anonymous_transfer_statement_follows_the_contract_order() {
    let values = Values::new();
    let outputs = values.anonymous_outputs();
    let parties = [field(70), field(71), field(72)];
    let key = AuditKey::Anonymous(AnonymousAuditKey::Commitment { class: 16 });
    let zero = [0u8; 32];
    let slots = [zero; 3];
    let signers = SignerSet::new([[0x44; 32]].iter(), 16).unwrap();
    let reply = &values.replies[..97];
    let bundle = values.sender_bundle(4);
    let statement = TransferStatement {
        head: values.head(AuditLayout::default(), stream(key, 3, &outputs)),
        family: TransferFamily::Anonymous {
            party_identities: &parties,
            sender: bundle,
            replies: Some(reply),
        },
        exempt: false,
        approval_required: true,
        outputs: &outputs,
        output_capacity: 4,
        input_count: 3,
        private_tx_hash: &values.fields[3],
        signers,
        policy_hash: &values.fields[6],
        own_root: &values.fields[7],
        curator_root: &zero,
        public_assets: &slots,
        public_amounts: &slots,
        public_gross: &slots,
        withdrawal_hash: &values.fields[8],
    };
    let elements = statement.elements().unwrap();
    assert_eq!(
        elements[9],
        ciphertext_digest(statement.head.envelope).unwrap()
    );
    let hashes: Vec<[u8; 32]> = outputs.iter().map(|output| *output.hash()).collect();
    let bodies: Vec<[u8; 32]> = outputs
        .iter()
        .map(|output| output.recipient_body_hash().unwrap())
        .collect();
    assert_eq!(bodies[0], zero, "change carries no body");
    assert_eq!(bodies[3], zero, "an exit carries no body");
    assert_eq!(bodies[1], hash_bytes(&values.bodies[1]).unwrap());
    // Change and exit read zero, the bundle tag closes the chain.
    let tag_chain = create_hash_chain_4_from_slice(&[
        [0; 32],
        values.tags[1],
        values.tags[2],
        [0; 32],
        *bundle.tag,
    ])
    .unwrap();
    let mut tail = vec![
        right_aligned(0),
        right_aligned(1),
        right_aligned(4),
        create_hash_chain_4_from_slice(&hashes).unwrap(),
        output_ciphertext_chain(&outputs, 4).unwrap(),
        create_hash_chain_4_from_slice(&bodies).unwrap(),
        tag_chain,
        right_aligned(0b0001),
        ciphertext_digest(bundle.body).unwrap(),
        right_aligned(3),
        right_aligned(0b1000),
        values.fields[3],
        parties[0],
        parties[1],
        parties[2],
        right_aligned(1),
        signers.chain,
        values.fields[6],
        values.fields[7],
        zero,
    ];
    tail.extend([zero; 9]);
    tail.extend([
        values.fields[8],
        ciphertext_digest(reply).unwrap(),
        right_aligned(45),
        right_aligned(3),
    ]);
    assert_eq!(elements.len(), AUDIT_HEAD_ELEMENTS + tail.len());
    assert_eq!(elements[AUDIT_HEAD_ELEMENTS..], tail);
    // A view tag enters the statement.
    let mut rewritten = outputs.clone();
    rewritten[1] = RingOutput::Anonymous {
        hash: outputs[1].hash(),
        tag: &values.tags[6],
        body: values.anonymous_body(1),
        record: outputs[1].ciphertext(),
    };
    let reworded = TransferStatement {
        outputs: &rewritten,
        ..statement
    };
    assert_ne!(reworded.hash().unwrap(), statement.hash().unwrap());
    // So does the bundle tag.
    let retagged = TransferStatement {
        family: TransferFamily::Anonymous {
            party_identities: &parties,
            sender: FramedSenderBundle {
                tag: &values.tags[6],
                ..bundle
            },
            replies: Some(reply),
        },
        ..statement
    };
    assert_ne!(retagged.hash().unwrap(), statement.hash().unwrap());
    // An exit's owner tag does not, scheme 3 reads it.
    let mut exit_tagged = outputs.clone();
    exit_tagged[3] = RingOutput::Exit {
        hash: outputs[3].hash(),
        owner_tag: &[0xff; 32],
        payload: &[],
        record: outputs[3].ciphertext(),
    };
    let moved_exit = TransferStatement {
        outputs: &exit_tagged,
        ..statement
    };
    assert_eq!(moved_exit.hash().unwrap(), statement.hash().unwrap());
    // A recipient body enters the statement.
    rewritten[1] = values.anonymous(1, Some(&values.bodies[6]));
    let reworded = TransferStatement {
        outputs: &rewritten,
        ..statement
    };
    assert_ne!(reworded.hash().unwrap(), statement.hash().unwrap());
    // Presence, length and bytes of the replies enter the statement.
    for replies in [None, Some(&values.replies[..98])] {
        let moved = TransferStatement {
            family: TransferFamily::Anonymous {
                party_identities: &parties,
                sender: bundle,
                replies,
            },
            ..statement
        };
        assert_ne!(moved.hash().unwrap(), statement.hash().unwrap());
    }
}

/// The policy circuit matches a limit row against the asset fields of the public slots.
#[test]
fn an_outflow_limit_carries_the_public_asset_field_of_its_mint() {
    let mint = [9u8; 32];
    let legs = [
        PublicLeg {
            transfer: InterfaceTransfer::SplWithdrawal {
                amount: 5,
                spl_interface_bump: 255,
            },
            mint: Some(mint),
        },
        PublicLeg {
            transfer: InterfaceTransfer::SolWithdrawal { amount: 7 },
            mint: None,
        },
    ];
    let fields = PublicSlots::fold(legs.map(Ok::<_, PublicSlotError>))
        .unwrap()
        .asset_fields()
        .unwrap();
    for (asset, field) in [mint, SOL_ASSET_ADDRESS].into_iter().zip(fields) {
        let limit = OutflowLimit::of(&Member::asset(&Address::new_from_array(asset)).unwrap());
        assert_eq!(*limit.asset(), field);
        assert_ne!(*limit.asset(), asset);
    }
}
