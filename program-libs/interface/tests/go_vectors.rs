//! Reads the vectors `prover/circuits` writes from its solved witnesses, a mismatch names a statement the keys refuse.

use custom_ring_interface::{
    domain, key_catalog::RING_KEYS, AuditHead, AuditLayout, ConfidentialSender, FramedSenderBundle,
    MergePublicInput, RingOutput, SignerSet, TransferFamily, TransferStatement, RECIPIENT_BODY_LEN,
};
use serde::Deserialize;
use spr_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::right_align};

fn vector<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = format!("{}/../../test-vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value.trim_start_matches("0x")).unwrap()
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    bytes(value).try_into().unwrap()
}

fn arrays<const N: usize>(values: &[String]) -> Vec<[u8; N]> {
    values.iter().map(|value| array(value)).collect()
}

/// The vector holds identities where `SignerSet::new` takes addresses, the chain rule is one.
fn signer_chain(identities: &[[u8; 32]], slots: usize) -> [u8; 32] {
    if identities.is_empty() {
        return [0; 32];
    }
    let mut cells = identities.to_vec();
    cells.resize(slots, [0; 32]);
    create_hash_chain_4_from_slice(&cells).unwrap()
}

#[derive(Deserialize)]
struct OutputCase {
    kind: String,
    hash: String,
    u: Option<String>,
    body: Option<String>,
    record: Option<String>,
    recipient_body: Option<String>,
    #[serde(default)]
    tag: Option<String>,
}

#[derive(Deserialize)]
struct WithdrawalCase {
    owner: String,
    asset: String,
    amount: u64,
}

#[derive(Deserialize)]
struct TransferCase {
    name: String,
    family: String,
    in_proof: bool,
    delegate: bool,
    exempt: bool,
    approval_required: bool,
    first_nullifier: String,
    ring_id: String,
    tx_viewing_u: String,
    auditor_pubkey: String,
    eph_u: String,
    envelope: String,
    salt: String,
    layout: u8,
    output_capacity: usize,
    outputs: Vec<OutputCase>,
    input_count: usize,
    sender_bundle: Option<String>,
    #[serde(default)]
    sender_bundle_tag: Option<String>,
    replies: Option<String>,
    private_tx_hash: String,
    sender: Option<String>,
    party_identities: Option<Vec<String>>,
    #[serde(default)]
    signer_slots: usize,
    #[serde(default)]
    signers: Vec<String>,
    signer_count: usize,
    signer_chain: String,
    policy_hash: String,
    own_root: String,
    curator_root: String,
    recipients: Option<Vec<String>>,
    public_assets: Vec<String>,
    public_amounts: Vec<String>,
    public_gross: Vec<String>,
    #[serde(default)]
    withdrawals: Vec<WithdrawalCase>,
    withdrawal_hash: String,
    elements: Vec<String>,
    public_input_hash: String,
}

impl TransferCase {
    fn withdrawal_hash(&self) -> [u8; 32] {
        let mut fields = vec![
            domain::field(domain::WITHDRAWALS),
            right_align(&(self.withdrawals.len() as u64).to_be_bytes()),
        ];
        for leg in &self.withdrawals {
            fields.extend([
                array(&leg.owner),
                array(&leg.asset),
                right_align(&leg.amount.to_be_bytes()),
            ]);
        }
        create_hash_chain_4_from_slice(&fields).unwrap()
    }
}

/// Every position rebuilds from the preimages, through the final hash.
#[test]
fn transfer_statements_reach_the_go_public_inputs() {
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<TransferCase>,
    }
    let vector: Vector = vector("audit/transfer_statement_v3.json");
    assert_eq!(vector.cases.len(), 11);
    for case in &vector.cases {
        let hashes: Vec<[u8; 32]> = case.outputs.iter().map(|o| array(&o.hash)).collect();
        let keys: Vec<Option<[u8; 32]>> = case
            .outputs
            .iter()
            .map(|o| o.u.as_deref().map(array))
            .collect();
        let bodies: Vec<Vec<u8>> = case
            .outputs
            .iter()
            .map(|o| bytes(o.body.as_deref().unwrap_or_default()))
            .collect();
        let records: Vec<Vec<u8>> = case
            .outputs
            .iter()
            .map(|o| bytes(o.record.as_deref().unwrap_or_default()))
            .collect();
        let recipient_bodies: Vec<Option<[u8; RECIPIENT_BODY_LEN]>> = case
            .outputs
            .iter()
            .map(|o| o.recipient_body.as_deref().map(array))
            .collect();
        let zero_tag = [0u8; 32];
        let tags: Vec<[u8; 32]> = case
            .outputs
            .iter()
            .map(|o| o.tag.as_deref().map_or(zero_tag, array))
            .collect();
        let outputs: Vec<RingOutput<'_>> = case
            .outputs
            .iter()
            .enumerate()
            .map(|(slot, output)| match output.kind.as_str() {
                "delivered" => RingOutput::Delivered {
                    hash: &hashes[slot],
                    u: keys[slot].as_ref().unwrap(),
                    body: &bodies[slot],
                },
                "anonymous" => RingOutput::Anonymous {
                    hash: &hashes[slot],
                    tag: &tags[slot],
                    body: recipient_bodies[slot].as_ref(),
                    record: &records[slot],
                },
                "exit" => RingOutput::Exit {
                    hash: &hashes[slot],
                    owner_tag: &zero_tag,
                    payload: &[],
                    record: &records[slot],
                },
                kind => panic!("unknown slot kind {kind}"),
            })
            .collect();
        let signers = arrays::<32>(&case.signers);
        let run = SignerSet {
            count: signers.len(),
            chain: signer_chain(&signers, case.signer_slots),
        };
        assert_eq!(run.count, case.signer_count, "{}", case.name);
        assert_eq!(hex::encode(run.chain), case.signer_chain, "{}", case.name);
        assert_eq!(
            hex::encode(case.withdrawal_hash()),
            case.withdrawal_hash,
            "{}",
            case.name
        );
        let recipients = arrays::<32>(case.recipients.as_deref().unwrap_or_default());
        let parties: Option<[[u8; 32]; 3]> = case
            .party_identities
            .as_deref()
            .map(|parties| arrays::<32>(parties).try_into().unwrap());
        let bundle = bytes(case.sender_bundle.as_deref().unwrap_or_default());
        let bundle_tag: [u8; 32] = case.sender_bundle_tag.as_deref().map_or(zero_tag, array);
        let replies = case.replies.as_deref().map(bytes);
        let sender: [u8; 32] = case.sender.as_deref().map(array).unwrap_or_default();
        let family = match case.family.as_str() {
            "confidential" => TransferFamily::Confidential {
                sender: match (case.in_proof, case.delegate) {
                    (true, _) => ConfidentialSender::InProof(&sender),
                    (_, true) => ConfidentialSender::Authority,
                    _ => ConfidentialSender::Signer,
                },
                recipients: &recipients,
            },
            _ => TransferFamily::Anonymous {
                party_identities: parties.as_ref().unwrap(),
                sender: FramedSenderBundle {
                    tag: &bundle_tag,
                    body: &bundle,
                },
                replies: replies.as_deref(),
            },
        };
        let envelope = bytes(&case.envelope);
        let statement = TransferStatement {
            head: AuditHead {
                first_nullifier: &array(&case.first_nullifier),
                ring_id: &array(&case.ring_id),
                tx_viewing_u: &array(&case.tx_viewing_u),
                auditor_pubkey: &array(&case.auditor_pubkey),
                eph_u: &array(&case.eph_u),
                envelope: &envelope,
                salt: &array(&case.salt),
                layout: AuditLayout {
                    key_escrow: case.layout & 2 != 0,
                    full_openings: case.layout & 8 != 0,
                },
            },
            family,
            exempt: case.exempt,
            approval_required: case.approval_required,
            outputs: &outputs,
            output_capacity: case.output_capacity,
            input_count: case.input_count,
            private_tx_hash: &array(&case.private_tx_hash),
            signers: run,
            policy_hash: &array(&case.policy_hash),
            own_root: &array(&case.own_root),
            curator_root: &array(&case.curator_root),
            public_assets: &arrays::<32>(&case.public_assets).try_into().unwrap(),
            public_amounts: &arrays::<32>(&case.public_amounts).try_into().unwrap(),
            public_gross: &arrays::<32>(&case.public_gross).try_into().unwrap(),
            withdrawal_hash: &array(&case.withdrawal_hash),
        };
        let elements: Vec<String> = statement
            .elements()
            .unwrap()
            .iter()
            .map(hex::encode)
            .collect();
        assert_eq!(elements, case.elements, "{}", case.name);
        assert_eq!(
            hex::encode(statement.hash().unwrap()),
            case.public_input_hash,
            "{}",
            case.name
        );
    }
}

#[test]
fn merge_statement_reaches_the_go_public_input() {
    #[derive(Deserialize)]
    struct Request {
        #[serde(rename = "partyIdentities")]
        party_identities: Vec<String>,
        #[serde(rename = "privateTxHash")]
        private_tx_hash: String,
        #[serde(rename = "outputUtxoHash")]
        output_utxo_hash: String,
        #[serde(rename = "firstNullifier")]
        first_nullifier: String,
        #[serde(rename = "ringProgramId")]
        ring_id: String,
        #[serde(rename = "keyEscrow")]
        key_escrow: bool,
        #[serde(rename = "memberRegistryRoot")]
        member_registry_root: String,
    }
    #[derive(Deserialize)]
    struct Vector {
        auditor_pk: String,
        eph_pk: String,
        salt: String,
        input_count: usize,
        fields: Vec<String>,
        envelope_ciphertext: String,
        elements: Vec<String>,
        public_input_hash: String,
        request: Request,
    }
    let vector: Vector = vector("merge/merge_v2.json");
    let request = &vector.request;
    let root: [u8; 32] = array(&request.member_registry_root);
    let fields = arrays::<32>(&vector.fields);
    let statement = MergePublicInput {
        party_identities: &arrays::<32>(&request.party_identities).try_into().unwrap(),
        private_tx_hash: &array(&request.private_tx_hash),
        output_utxo_hash: &array(&request.output_utxo_hash),
        first_nullifier: &array(&request.first_nullifier),
        ring_id: &array(&request.ring_id),
        auditor_pk: &array(&vector.auditor_pk),
        eph_pk: &array(&vector.eph_pk),
        ciphertext: &array(&vector.envelope_ciphertext),
        salt: &array(&vector.salt),
        fields: &fields,
        input_count: vector.input_count,
        member_registry_root: request.key_escrow.then_some(&root),
    };
    let elements = statement.elements().unwrap();
    assert_eq!(arrays::<32>(&vector.elements), elements);
    assert_eq!(
        array::<32>(&vector.public_input_hash),
        statement.hash().unwrap()
    );
}

#[test]
fn signer_chains_match_the_go_run() {
    #[derive(Deserialize)]
    struct Case {
        name: String,
        slots: usize,
        signers: Vec<String>,
        signer_chain: String,
    }
    #[derive(Deserialize)]
    struct Vector {
        cases: Vec<Case>,
    }
    let vector: Vector = vector("audit/signer_set.json");
    for case in vector.cases {
        let signers = arrays::<32>(&case.signers);
        assert_eq!(
            hex::encode(signer_chain(&signers, case.slots)),
            case.signer_chain,
            "{}",
            case.name
        );
    }
}

#[test]
fn zero_nullifier_key_matches_the_go_twin() {
    #[derive(Deserialize)]
    struct Vector {
        nullifier_pk: String,
    }
    let vector: Vector = vector("registry/zero_nullifier.json");
    assert_eq!(
        array::<32>(&vector.nullifier_pk),
        spr_interface::ZERO_NULLIFIER_PUBKEY
    );
}

#[test]
fn record_pools_match_the_compiled_keys() {
    #[derive(Deserialize)]
    struct Key {
        key: String,
        own: usize,
        curator: usize,
    }
    #[derive(Deserialize)]
    struct Vector {
        keys: Vec<Key>,
    }
    let vector: Vector = vector("policy/pool_capacity.json");
    assert_eq!(vector.keys.len(), 15);
    for key in vector.keys {
        let name = key.key.replace('_', "-");
        let ring_key = RING_KEYS
            .iter()
            .find(|ring_key| ring_key.name == name)
            .unwrap_or_else(|| panic!("{name} is no catalog key"));
        let pools = ring_key.circuit.record_pools().unwrap();
        assert_eq!((pools.own, pools.curator), (key.own, key.curator), "{name}");
    }
}
