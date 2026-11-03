//! Pins `test-vectors/proof/ring-statements.json` for the Go circuits and the TS SDK.

use custom_ring_interface::{
    ciphertext_digest, exits_bitmap, output_ciphertext_chain, slot_ciphertext_hash,
    AnonymousAuditKey, ApplyRecordsStatement, AuditHead, AuditKey, AuditLayout, AuditStreamLayout,
    DepositContext, DepositPublicInput, DepositRegistry, DepositedAsset, RegisterKeyStatement,
    RingOutput, TransferFamily, TransferStatement, ANONYMOUS_RECORD_LEN, AUDIT_HEAD_ELEMENTS,
    DELIVERED_BODY_LEN, DEPOSIT_PUBLIC_INPUT_ELEMENTS, ESCROWED_DELIVERED_BODY_LEN,
    ESCROWED_EXIT_RECORD_LEN, EXIT_RECORD_LEN,
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
    register_key: RegisterKeyCase,
    deposit: DepositCase,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct OutputCase {
    /// `delivered`, `anonymous` or `exit`.
    kind: String,
    hash: String,
    u: Option<String>,
    body: Option<String>,
    record: Option<String>,
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
    output_ciphertext_chain: String,
    input_count: usize,
    exits_bitmap: u64,
    private_tx_hash: String,
    sender: Option<String>,
    party_identities: Option<Vec<String>>,
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
    elements: Vec<String>,
    public_input_hash: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct RegisterKeyCase {
    member: String,
    nullifier_pk: String,
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
            tags: core::array::from_fn(|slot| [0xb0 + slot as u8; 32]),
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

    fn anonymous<'a>(&'a self, slot: usize, body: Option<&'a [u8]>) -> RingOutput<'a> {
        RingOutput::Anonymous {
            hash: &self.fields[20 + slot],
            tag: &self.tags[slot],
            body,
            record: &self.ciphertexts[slot][..ANONYMOUS_RECORD_LEN],
        }
    }

    fn anonymous_body(&self, slot: usize) -> Option<&[u8]> {
        (slot != 1).then_some(&self.ciphertexts[slot][..40])
    }
}

/// The stream of a statement fixture, its exits read from the outputs.
fn stream(key: AuditKey, inputs: usize, outputs: &[RingOutput<'_>]) -> AuditStreamLayout {
    AuditStreamLayout {
        key,
        key_escrow: false,
        inputs,
        outputs: outputs.len(),
        exits: exits_bitmap(outputs),
    }
}

fn output_case(output: &RingOutput<'_>) -> OutputCase {
    let (kind, u, body, record) = match output {
        RingOutput::Delivered { u, body, .. } => ("delivered", Some(*u), Some(*body), None),
        RingOutput::Anonymous { record, .. } => ("anonymous", None, None, Some(*record)),
        RingOutput::Exit { record, .. } => ("exit", None, None, Some(*record)),
    };
    OutputCase {
        kind: kind.to_string(),
        hash: hex::encode(output.hash()),
        u: u.map(hex::encode),
        body: body.map(hex::encode),
        record: record.map(hex::encode),
    }
}

fn transfer_case(statement: &TransferStatement<'_>) -> TransferCase {
    let head = statement.head;
    let confidential = match statement.family {
        TransferFamily::Confidential {
            in_proof,
            delegate,
            sender,
            recipients,
        } => Some((in_proof, delegate, sender, recipients)),
        TransferFamily::Anonymous { .. } => None,
    };
    let parties = match statement.family {
        TransferFamily::Anonymous { party_identities } => Some(hexes(party_identities)),
        TransferFamily::Confidential { .. } => None,
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
        output_ciphertext_chain: hex::encode(output_ciphertext_chain(statement.outputs).unwrap()),
        input_count: statement.input_count,
        exits_bitmap: exits_bitmap(statement.outputs),
        private_tx_hash: hex::encode(statement.private_tx_hash),
        sender: confidential.map(|(_, _, sender, _)| hex::encode(sender)),
        party_identities: parties,
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
    let signer_key = AuditKey::Confidential {
        class: 16,
        input_prefixes: false,
    };
    let prefix_key = AuditKey::Confidential {
        class: 16,
        input_prefixes: true,
    };
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
        head: values.head(no_flags, stream(signer_key, 2, &delivered)),
        family: TransferFamily::Confidential {
            in_proof: false,
            delegate: false,
            sender: &owner_signer,
            recipients: &eight_recipients,
        },
        exempt: false,
        approval_required: true,
        outputs: &delivered,
        input_count: 2,
        private_tx_hash: &values.fields[3],
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
            in_proof: false,
            delegate: false,
            sender: &zero,
            recipients: &[zero; 8],
        },
        exempt: true,
        approval_required: false,
        policy_hash: &zero,
        curator_root: &zero,
        ..signer_policy
    };
    let in_proof_policy = TransferStatement {
        head: values.head(no_flags, stream(prefix_key, 2, &delivered)),
        family: TransferFamily::Confidential {
            in_proof: true,
            delegate: false,
            sender: &owner_signer,
            recipients: &eight_recipients,
        },
        ..signer_policy
    };
    let no_slots = [zero; 3];
    let delegate_move = TransferStatement {
        head: values.head(
            AuditLayout {
                key_escrow: true,
                full_openings: false,
            },
            stream(prefix_key, 2, &escrowed),
        ),
        family: TransferFamily::Confidential {
            in_proof: false,
            delegate: true,
            sender: &zero,
            recipients: &[values.fields[62], values.fields[63]],
        },
        approval_required: false,
        outputs: &escrowed,
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
        },
        approval_required: false,
        outputs: &anonymous,
        input_count: 3,
        ..signer_policy
    };
    let anonymous_exempt = TransferStatement {
        exempt: true,
        policy_hash: &zero,
        curator_root: &zero,
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
        ..anonymous_policy_transfer
    };
    let transfers = [
        signer_policy,
        signer_exempt,
        in_proof_policy,
        delegate_move,
        anonymous_policy_transfer,
        anonymous_exempt,
        entry,
    ];
    let apply = ApplyRecordsStatement {
        old_root: values.fields[9],
        new_root: values.fields[10],
        old_next_index: 5,
        new_next_index: 17,
        chain_start: values.fields[11],
        chain_end: values.fields[12],
        count: 16,
    };
    let register = RegisterKeyStatement {
        member: &owner_signer,
        nullifier_pk: &values.fields[13],
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
                      padded to 8 slots. The transfer statements are HashChain4 over the audit head under \
                      CRTX, on the confidential family in_proof and delegate, then exempt, \
                      approval_required, the output chain, the output ciphertext chain \
                      HashChain4(hash_bytes(ct_i)), on the confidential family the recipient key \
                      chain, input_count, exits_bitmap, private_tx_hash, the sender on the \
                      confidential family or the three party identities on the anonymous family, \
                      policy_hash, own_root, curator_root, one recipient per output on the confidential \
                      family, asset, net and gross per public slot, withdrawal_hash, the element \
                      count and the version. Produced by program-libs/interface/tests/statements.rs."
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
            elements: hexes(&apply.elements()),
            public_input_hash: hex::encode(apply.hash().unwrap()),
        },
        register_key: RegisterKeyCase {
            member: hex::encode(register.member),
            nullifier_pk: hex::encode(register.nullifier_pk),
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

fn right_aligned(amount: u64) -> [u8; 32] {
    spr_hasher::primitives::right_align(&amount.to_be_bytes())
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
    assert_eq!(transfer, [46, 46, 46, 40, 37, 37, 37]);
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
            output_ciphertext_chain(&outputs).unwrap(),
            create_hash_chain_4_from_slice(&hashes).unwrap()
        );
    }
    assert_eq!(
        slot_ciphertext_hash(&[7; EXIT_RECORD_LEN]).unwrap(),
        hash_bytes(&[7; EXIT_RECORD_LEN]).unwrap()
    );
    assert!(slot_ciphertext_hash(&[7; 41]).is_err());
}

/// One statement of each family at every keyed output count.
#[test]
fn the_element_count_is_thirty_eight_plus_outputs_or_thirty_seven() {
    let values = Values::new();
    let zero = [0u8; 32];
    let slots = [zero; 3];
    let parties = [zero; 3];
    let recipients = [zero; 8];
    let confidential = values.delivered_outputs(8, &[], false);
    for n_out in [2usize, 4, 8] {
        let statement = TransferStatement {
            head: values.head(
                AuditLayout::default(),
                stream(
                    AuditKey::Confidential {
                        class: 16,
                        input_prefixes: false,
                    },
                    1,
                    &confidential[..n_out],
                ),
            ),
            family: TransferFamily::Confidential {
                in_proof: false,
                delegate: false,
                sender: &zero,
                recipients: &recipients[..n_out],
            },
            exempt: false,
            approval_required: false,
            outputs: &confidential[..n_out],
            input_count: 1,
            private_tx_hash: &zero,
            policy_hash: &zero,
            own_root: &zero,
            curator_root: &zero,
            public_assets: &slots,
            public_amounts: &slots,
            public_gross: &slots,
            withdrawal_hash: &zero,
        };
        assert_eq!(statement.element_count(), 38 + n_out);
        let elements = statement.elements().unwrap();
        assert_eq!(elements.len(), 38 + n_out);
        assert_eq!(
            elements[elements.len() - 2],
            right_aligned(38 + n_out as u64)
        );
        assert_eq!(elements[elements.len() - 1], right_aligned(2));
        let anonymous = TransferStatement {
            family: TransferFamily::Anonymous {
                party_identities: &parties,
            },
            ..statement
        };
        assert_eq!(anonymous.element_count(), 37);
        let elements = anonymous.elements().unwrap();
        assert_eq!(elements.len(), 37);
        assert_eq!(elements[elements.len() - 2], right_aligned(37));
    }
}

#[test]
fn the_anonymous_transfer_statement_chains_outputs_ciphertexts_private_tx_and_parties() {
    let values = Values::new();
    let outputs = values.anonymous_outputs();
    let parties = [field(70), field(71), field(72)];
    let key = AuditKey::Anonymous(AnonymousAuditKey::Commitment { class: 16 });
    let zero = [0u8; 32];
    let slots = [zero; 3];
    let statement = TransferStatement {
        head: values.head(AuditLayout::default(), stream(key, 3, &outputs)),
        family: TransferFamily::Anonymous {
            party_identities: &parties,
        },
        exempt: false,
        approval_required: true,
        outputs: &outputs,
        input_count: 3,
        private_tx_hash: &values.fields[3],
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
    let mut tail = vec![
        right_aligned(0),
        right_aligned(1),
        create_hash_chain_4_from_slice(&hashes).unwrap(),
        output_ciphertext_chain(&outputs).unwrap(),
        right_aligned(3),
        right_aligned(0b1000),
        values.fields[3],
        parties[0],
        parties[1],
        parties[2],
        values.fields[6],
        values.fields[7],
        zero,
    ];
    tail.extend([zero; 9]);
    tail.extend([values.fields[8], right_aligned(37), right_aligned(2)]);
    assert_eq!(elements.len(), AUDIT_HEAD_ELEMENTS + tail.len());
    assert_eq!(elements[AUDIT_HEAD_ELEMENTS..], tail);
    // No tag or scheme 1 body enters the statement, a wallet picks both freely.
    let mut rewritten = outputs.clone();
    rewritten[0] = RingOutput::Anonymous {
        hash: outputs[0].hash(),
        tag: &[0xff; 32],
        body: Some(&values.ciphertexts[6]),
        record: outputs[0].ciphertext(),
    };
    rewritten[2] = RingOutput::Anonymous {
        hash: outputs[2].hash(),
        tag: &values.tags[2],
        body: None,
        record: outputs[2].ciphertext(),
    };
    let reworded = TransferStatement {
        outputs: &rewritten,
        ..statement
    };
    assert_eq!(reworded.hash().unwrap(), statement.hash().unwrap());
    // A record enters the statement.
    rewritten[1] = values.exit(1, EXIT_RECORD_LEN);
    let reworded = TransferStatement {
        outputs: &rewritten,
        ..statement
    };
    assert_ne!(reworded.hash().unwrap(), statement.hash().unwrap());
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
