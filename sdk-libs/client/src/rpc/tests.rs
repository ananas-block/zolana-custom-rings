use solana_keypair::Keypair;
use spr_keypair::{ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey};
use spr_transaction::OutputContext;

use super::*;
use crate::{
    AuditedDefaultInput, InputOpening, OutputPayloadError,
    OutputPayloadErrorKind::{self, Commitment, Disclosure, Frame, RecipientKey},
};

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ring-rpc-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn deposits_request(limit: Option<u32>, cursor: Option<Vec<u8>>) -> RingDepositsRequest {
    RingDepositsRequest {
        ring_program_id: Address::new_from_array([5; 32]).to_bytes().into(),
        limit,
        cursor: cursor.map(Into::into),
    }
}

#[test]
fn auditor_key_request_attestation_is_stable() {
    let attestation = AuditorKeyAttestation {
        genesis_hash: [9; 32],
        ring: Address::new_from_array([5; 32]),
    }
    .message(1_700_000_000, &[7; 32]);
    assert_eq!(
        String::from_utf8(attestation).expect("utf8"),
        "zolana/ring-rpc-auditor-key-request/v1\n\
         genesis: cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN\n\
         ring: LbUiWL3xVV8hTFYBVdbTNrpDo41NKS6o3LHHuDzjfcY\n\
         timestamp: 1700000000\n\
         nonce: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
    );
}

/// The ring at `[7; 32]` behind the service `[2; 32]` on the cluster `[1; 32]`.
fn target() -> ReadTarget {
    ReadTarget {
        cluster: [1; 32],
        service: Address::new_from_array([2; 32]),
        ring: Address::new_from_array([7; 32]),
    }
}

#[test]
fn read_attestation_is_stable() {
    let message = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(),
        cursor: Some(vec![1, 2, 3].into()),
        limit: Some(Limit::new(5).expect("in range")),
        wallet: None,
    }
    .message(1_700_000_000, &[4; 32]);
    assert_eq!(
        String::from_utf8(message).expect("text"),
        "zolana/ring-rpc-read/v2\nmethod: getDecryptedTransactions\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nlimit: 5\ncursor: AQID"
    );
}

/// A reader's signature names its method, cluster, service and ring, each request a fresh nonce.
#[test]
fn a_signed_read_names_its_method_and_target_and_draws_its_own_nonce() {
    let reader = Keypair::new();
    let sign = |read: PagedRead| {
        read.request(target())
            .at(1_700_000_000)
            .sign(&reader)
            .unwrap()
    };
    let transfers = sign(PagedRead::DecryptedTransactions);
    let nonce: [u8; 32] = transfers.auth.nonce.0.clone().try_into().unwrap();
    let signature = Signature::try_from(transfers.auth.signature.0.as_slice()).unwrap();
    let attested = |read, target| {
        ReadAttestation {
            read,
            target,
            cursor: None,
            limit: None,
            wallet: None,
        }
        .message(1_700_000_000, &nonce)
    };
    assert!(signature.verify(
        reader.pubkey().as_ref(),
        &attested(PagedRead::DecryptedTransactions, target())
    ));
    let elsewhere = [
        ReadTarget {
            cluster: [9; 32],
            ..target()
        },
        ReadTarget {
            service: Address::new_from_array([9; 32]),
            ..target()
        },
    ];
    for other in elsewhere {
        assert!(!signature.verify(
            reader.pubkey().as_ref(),
            &attested(PagedRead::DecryptedTransactions, other)
        ));
    }
    assert!(!signature.verify(
        reader.pubkey().as_ref(),
        &attested(PagedRead::AuditedMerges, target())
    ));
    assert_ne!(
        sign(PagedRead::DecryptedTransactions).auth.nonce,
        transfers.auth.nonce
    );
}

#[test]
fn audited_utxos_attestation_is_stable() {
    let message = AuditedUtxosAttestation::new(target(), &[Hash([1; 32]), Hash([2; 32])])
        .message(1_700_000_000, &[4; 32]);
    assert_eq!(
        String::from_utf8(message).expect("text"),
        "zolana/ring-rpc-audited-utxos/v1\ncluster: 4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi\nservice: 8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR\nring: US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx\ntimestamp: 1700000000\nnonce: BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nutxos: +Biv03ptw7yS+0RzEBEncAbbTvpukCPNdGjAIzXSKk0="
    );
}

#[test]
fn a_signed_utxo_read_carries_the_hashes_it_signed() {
    let reader = Keypair::new();
    let ring = target().ring;
    let hashes = vec![Hash([1; 32]), Hash([2; 32])];
    let request = GetAuditedUtxosRequest::read(target(), hashes.clone())
        .expect("utxo read")
        .at(1_700_000_000)
        .sign(&reader)
        .expect("signed");
    assert_eq!(request.utxo_hashes, hashes);
    assert_eq!(request.ring_program_id, Some(ring.to_bytes().into()));
    let nonce = request.auth.nonce.0.clone().try_into().expect("nonce");
    let signature = Signature::try_from(request.auth.signature.0.as_slice()).expect("signature");
    let signed = |hashes: &[Hash]| {
        AuditedUtxosAttestation::new(target(), hashes).message(1_700_000_000, &nonce)
    };
    assert!(signature.verify(reader.pubkey().as_ref(), &signed(&hashes)));
    assert!(!signature.verify(
        reader.pubkey().as_ref(),
        &signed(&[Hash([2; 32]), Hash([1; 32])])
    ));
    for count in [0, AUDITED_UTXOS_LIMIT + 1] {
        assert!(matches!(
            GetAuditedUtxosRequest::read(target(), vec![Hash([1; 32]); count]),
            Err(ReadBuildError::UtxoHashes)
        ));
    }
}

/// `Limit` cannot hold zero, so the smallest audit page the wire carries is one.
#[test]
fn an_audit_page_holds_at_its_cursor_and_limit_bounds() {
    assert!(!cursor_in_bounds(&[]));
    assert!(cursor_in_bounds(&vec![1; AUDIT_CURSOR_LIMIT]));
    assert!(!cursor_in_bounds(&vec![1; AUDIT_CURSOR_LIMIT + 1]));
    assert!(limit_in_bounds(&Limit::new(1).expect("indexer limit")));
    assert!(limit_in_bounds(
        &Limit::new(AUDIT_PAGE_LIMIT).expect("indexer limit")
    ));
    assert!(!limit_in_bounds(
        &Limit::new(AUDIT_PAGE_LIMIT + 1).expect("indexer limit")
    ));
}

/// The deposits limit counts signatures examined, so it is clamped, never refused.
#[test]
fn a_deposits_page_clamps_its_limit_into_range() {
    for (limit, expected) in [
        (None, DEPOSITS_PAGE_LIMIT),
        (Some(0), 1),
        (Some(1), 1),
        (Some(MAX_DEPOSITS_PAGE_LIMIT), MAX_DEPOSITS_PAGE_LIMIT),
        (Some(MAX_DEPOSITS_PAGE_LIMIT + 1), MAX_DEPOSITS_PAGE_LIMIT),
        (Some(u32::MAX), MAX_DEPOSITS_PAGE_LIMIT),
    ] {
        assert_eq!(
            deposits_request(limit, None).page_limit(),
            expected as usize
        );
    }
}

/// The deposits cursor is a Solana signature, unlike the opaque audit cursor.
#[test]
fn a_deposits_cursor_is_exactly_one_signature() {
    assert_eq!(
        deposits_request(None, Some(vec![1; 64]))
            .before()
            .expect("cursor"),
        Some(Signature::from([1; 64]))
    );
    assert_eq!(
        deposits_request(None, None).before().expect("no cursor"),
        None
    );
    for length in [0, 63, 65, AUDIT_CURSOR_LIMIT] {
        assert!(matches!(
            deposits_request(None, Some(vec![1; length])).before(),
            Err(ReadBuildError::Cursor)
        ));
    }
}

fn utxo(seed: u8, mint: Option<Address>) -> AuditedUtxo {
    AuditedUtxo {
        owner_key: [seed; 32],
        nullifier_pk: [seed + 1; 32],
        asset: [seed + 2; 32],
        mint,
        amount: u64::from(seed),
        blinding: [seed + 3; 32],
        data_hash: [seed + 4; 32],
        ring_data_hash: [seed + 5; 32],
    }
}

fn output(slot_index: u32, opening: OutputOpening) -> AuditedOutput {
    AuditedOutput {
        slot_index,
        context: OutputContext {
            hash: [0x40 + slot_index as u8; 32],
            tree_id: 4,
            leaf_index: u64::from(slot_index) + 1,
        },
        opening,
    }
}

fn page(
    audited: AuditedTransaction,
    nullifiers: Vec<[u8; 32]>,
) -> GetDecryptedTransactionsResponse {
    let withdrawal = RingWithdrawal {
        screened_owner: None,
        recipient: Address::new_from_array([10; 32]),
        asset: Address::new_from_array([4; 32]),
        amount: 5,
    };
    GetDecryptedTransactionsResponse {
        context: Context {
            block_time: 1,
            slot: 43,
        },
        value: DecryptedTransactionsPage {
            items: vec![ConfirmedAudit {
                audited,
                event_index: 7,
                nullifiers,
                spenders: Vec::new(),
                signers: vec![Address::new_from_array([13; 32])],
                withdrawals: vec![withdrawal],
            }
            .into()],
            skipped: vec![SkippedTransaction {
                slot: 40,
                tx_signature: Signature::from([14; 64]).into(),
                event_index: 8,
                reason: SkippedReason::MissingAuditorMessage,
            }],
            cursor: Some(vec![15].into()),
        },
    }
}

fn delivered_audited() -> AuditedTransaction {
    AuditedTransaction {
        tx_signature: Signature::from([1; 64]),
        slot: 42,
        tx_viewing_pk: ViewingKey::from_bytes(&[3; 32]).pubkey(),
        outputs: vec![
            output(
                0,
                OutputOpening::Ring {
                    utxo: utxo(0x10, Some(Address::new_from_array([4; 32]))),
                    owner_tag: RingOwnerTag([6; 32]),
                },
            ),
            output(1, OutputOpening::Exit(utxo(0x20, None))),
            output(2, OutputOpening::Dummy),
        ],
        payload_errors: vec![OutputPayloadError {
            slot_index: 3,
            kind: Commitment,
        }],
        real_inputs: 0,
        inputs: Vec::new(),
    }
}

/// The JSON clients parse, pinned byte for byte.
#[test]
fn a_decrypted_page_keeps_its_wire_json() {
    let mut page = page(delivered_audited(), vec![[12; 32]]);
    page.value.items[0].spenders = vec![[13; 32].into()];
    let json = serde_json::to_string(&page).expect("json");
    assert_eq!(json, include_str!("decrypted_page.json").trim_end());
    assert_eq!(
        serde_json::from_str::<GetDecryptedTransactionsResponse>(&json).expect("parses"),
        page
    );
}

/// The TypeScript decoder reads the same page.
#[test]
fn a_real_input_reads_apart_from_a_dummy() {
    let real = AuditedInput {
        nullifier: [12; 32],
        opening: InputOpening::Real,
    };
    let dummy = AuditedInput {
        nullifier: [11; 32],
        opening: InputOpening::Dummy,
    };
    let page = in_proof_page(real.clone(), dummy);
    let json = serde_json::to_string(&page).expect("json");
    assert_eq!(
        json,
        include_str!("decrypted_in_proof_page.json").trim_end()
    );
    let parsed: GetDecryptedTransactionsResponse = serde_json::from_str(&json).expect("parses");
    assert_eq!(parsed, page);
    let [read_real, read_dummy] = parsed.value.items[0].inputs.as_slice() else {
        panic!("two inputs")
    };
    assert!(read_real.real);
    assert_eq!(read_real.default_input, None);
    assert!(!read_dummy.real);
    assert_ne!(
        DecryptedInput::from(real.clone()),
        DecryptedInput::from(AuditedInput {
            opening: InputOpening::Dummy,
            ..real
        })
    );
    let [transaction] = page.value.items.as_slice() else {
        panic!("one transaction")
    };
    let activity = WalletActivity::of(
        Address::new_from_array([13; 32]),
        transaction.clone(),
        |input| match input.real {
            true => InputParty::Own,
            false => InputParty::Padding,
        },
    )
    .expect("a spender");
    let read: WalletActivity =
        serde_json::from_str(&serde_json::to_string(&activity).expect("json")).expect("parses");
    assert_eq!(read, activity);
    let WalletView::Sender { inputs, .. } = read.view else {
        panic!("the spender's view")
    };
    assert_eq!(inputs.len(), 1, "padding never reaches a wallet");
}

fn in_proof_page(real: AuditedInput, dummy: AuditedInput) -> GetDecryptedTransactionsResponse {
    let mut page = page(
        AuditedTransaction {
            real_inputs: 1,
            inputs: vec![real, dummy],
            ..delivered_audited()
        },
        vec![[12; 32], [11; 32]],
    );
    page.value.items[0].spenders = vec![[13; 32].into()];
    page
}

fn two_owner_transaction(wallet: Address) -> DecryptedTransaction {
    let mint = Some(Address::new_from_array([4; 32]));
    let mut transaction = page(
        AuditedTransaction {
            outputs: vec![
                output(
                    0,
                    OutputOpening::Ring {
                        utxo: utxo(0x10, mint),
                        owner_tag: RingOwnerTag([9; 32]),
                    },
                ),
                output(
                    1,
                    OutputOpening::Ring {
                        utxo: utxo(0x50, mint),
                        owner_tag: RingOwnerTag([8; 32]),
                    },
                ),
            ],
            payload_errors: vec![OutputPayloadError {
                slot_index: 2,
                kind: OutputPayloadErrorKind::Commitment,
            }],
            inputs: Vec::new(),
            ..delivered_audited()
        },
        Vec::new(),
    )
    .value
    .items
    .remove(0);
    transaction.spenders = vec![wallet.to_bytes().into()];
    let input = |seed: u8| {
        DecryptedInput::from(AuditedInput {
            nullifier: [seed; 32],
            opening: InputOpening::Real,
        })
    };
    transaction.inputs = vec![input(1), input(2), input(3)];
    transaction
}

fn sender_slots(view: WalletView) -> (Vec<Hash>, Vec<u32>) {
    let WalletView::Sender {
        inputs, outputs, ..
    } = view
    else {
        panic!("the spender's view")
    };
    (
        inputs.into_iter().map(|input| input.nullifier).collect(),
        outputs.iter().map(|output| output.slot_index).collect(),
    )
}

/// A public co-owner beside another owner reads its own notes and no marker.
#[test]
fn a_co_owner_reads_its_own_notes_alone() {
    let co_owner = Address::new_from_array([0x10; 32]);
    let activity =
        WalletActivity::of(co_owner, two_owner_transaction(co_owner), |input| {
            match input.nullifier == Hash::from([1; 32]) {
                true => InputParty::Own,
                false => InputParty::Other,
            }
        })
        .expect("a spender");
    assert_eq!(
        sender_slots(activity.view),
        (vec![Hash::from([1; 32])], vec![0])
    );
}

/// Every output of a sole owner is its own payment, padding counts as no other owner.
#[test]
fn a_wallet_owning_every_input_keeps_all_outputs_without_a_marker() {
    let owner = Address::new_from_array([0x10; 32]);
    let activity = WalletActivity::of(owner, two_owner_transaction(owner), |input| {
        match input.nullifier == Hash::from([3; 32]) {
            true => InputParty::Padding,
            false => InputParty::Own,
        }
    })
    .expect("a spender");
    assert_eq!(
        sender_slots(activity.view),
        (vec![Hash::from([1; 32]), Hash::from([2; 32])], vec![0, 1])
    );
}

#[test]
fn a_wallet_with_no_spent_input_reads_only_its_own_outputs() {
    let transaction = two_owner_transaction(Address::new_from_array([0x77; 32]));
    let read = |wallet: u8| {
        WalletActivity::of(
            Address::new_from_array([wallet; 32]),
            transaction.clone(),
            |_| InputParty::Other,
        )
    };
    assert!(matches!(
        read(0x10).expect("the output's owner").view,
        WalletView::Recipient { .. }
    ));
    assert_eq!(read(0x60), None);
}

fn anonymous_audited() -> AuditedTransaction {
    AuditedTransaction {
        tx_signature: Signature::from([1; 64]),
        slot: 42,
        tx_viewing_pk: ViewingKey::from_bytes(&[2; 32]).pubkey(),
        outputs: vec![
            output(
                0,
                OutputOpening::Ring {
                    utxo: AuditedUtxo {
                        data_hash: [0; 32],
                        ring_data_hash: [0; 32],
                        ..utxo(0x10, Some(Address::new_from_array([4; 32])))
                    },
                    owner_tag: RingOwnerTag([0x31; 32]),
                },
            ),
            output(1, OutputOpening::Exit(utxo(0x20, None))),
            output(2, OutputOpening::Dummy),
        ],
        payload_errors: Vec::new(),
        real_inputs: 3,
        inputs: vec![
            AuditedInput {
                nullifier: [12; 32],
                opening: InputOpening::Real,
            },
            AuditedInput {
                nullifier: [11; 32],
                opening: InputOpening::External(Box::new(AuditedDefaultInput {
                    utxo: utxo(0x60, Some(Address::new_from_array([4; 32]))),
                    commitment: Some([0x62; 32]),
                })),
            },
            AuditedInput {
                nullifier: [10; 32],
                opening: InputOpening::External(Box::new(AuditedDefaultInput {
                    utxo: utxo(0x70, None),
                    commitment: None,
                })),
            },
            AuditedInput {
                nullifier: [9; 32],
                opening: InputOpening::Dummy,
            },
        ],
    }
}

fn anonymous_page() -> GetDecryptedTransactionsResponse {
    page(
        anonymous_audited(),
        vec![[12; 32], [11; 32], [10; 32], [9; 32]],
    )
}

/// The TypeScript decoder reads the same page.
#[test]
fn an_anonymous_decrypted_page_keeps_its_wire_json() {
    let page = anonymous_page();
    let json = serde_json::to_string(&page).expect("json");
    assert_eq!(
        json,
        include_str!("decrypted_anonymous_page.json").trim_end()
    );
    assert_eq!(
        serde_json::from_str::<GetDecryptedTransactionsResponse>(&json).expect("parses"),
        page
    );
}

/// The TypeScript decoder reads both views of the anonymous page.
#[test]
fn a_wallet_activity_page_keeps_its_wire_json() {
    let page = anonymous_page();
    let [transaction] = page.value.items.as_slice() else {
        panic!("one transaction")
    };
    let view = |wallet: u8| {
        WalletActivity::of(
            Address::new_from_array([wallet; 32]),
            transaction.clone(),
            |_| InputParty::Own,
        )
        .expect("a party")
    };
    let recipient = WalletActivity::of(
        Address::new_from_array([0x10; 32]),
        transaction.clone(),
        |_| InputParty::Other,
    )
    .expect("the output's owner");
    let activity = GetWalletActivityResponse {
        context: page.context,
        value: WalletActivityPage {
            items: vec![view(0x50), recipient],
            cursor: page.value.cursor.clone(),
        },
    };
    let json = serde_json::to_string(&activity).expect("json");
    assert_eq!(json, include_str!("wallet_activity_page.json").trim_end());
    assert_eq!(
        serde_json::from_str::<GetWalletActivityResponse>(&json).expect("parses"),
        activity
    );
}

/// The TypeScript decoder reads the same vector.
#[test]
fn payload_errors_keep_the_encoding_of_the_shared_vector() {
    #[derive(Deserialize)]
    struct Vector {
        kinds: serde_json::Value,
        foreign_body_and_low_order_key: serde_json::Value,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/ring_rpc_payload_errors.json"
    ))
    .expect("vector");
    // A new kind fails to compile here, `kinds` and the vector must then name it.
    let named = |kind: OutputPayloadErrorKind| match kind {
        Frame | Disclosure | RecipientKey | Commitment => kind,
    };
    let kinds = [Frame, Disclosure, RecipientKey, Commitment].map(named);
    assert_eq!(serde_json::to_value(kinds).unwrap(), vector.kinds);
    let slots = [(2, Commitment), (5, RecipientKey)]
        .map(|(slot_index, kind)| DecryptedPayloadError { slot_index, kind });
    assert_eq!(
        serde_json::to_value(slots).unwrap(),
        vector.foreign_body_and_low_order_key
    );
}

#[test]
fn a_signed_read_carries_the_reader_and_the_bounds_it_signed() {
    let reader = Keypair::new();
    let request = GetDecryptedTransactionsRequest::read(target())
        .with_cursor(vec![1].into())
        .expect("cursor")
        .with_limit(Limit::new(5).expect("limit"))
        .expect("limit")
        .at(1_700_000_000)
        .sign(&reader)
        .expect("signed");
    assert_eq!(
        request.auth.reader.0,
        ReaderKey::ed25519(reader.pubkey())
            .expect("reader")
            .to_bytes()
            .to_vec()
    );
    let message = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(),
        cursor: request.cursor.clone(),
        limit: request.limit.clone(),
        wallet: None,
    }
    .message(
        1_700_000_000,
        &request.auth.nonce.0.clone().try_into().expect("nonce"),
    );
    let signature = Signature::try_from(request.auth.signature.0.as_slice()).expect("signature");
    assert!(signature.verify(reader.pubkey().as_ref(), &message));
    assert!(matches!(
        GetDecryptedTransactionsRequest::read(target()).with_cursor(Vec::new().into()),
        Err(ReadBuildError::Cursor)
    ));
}

#[test]
fn keygen_writes_a_secret_the_loader_reads_and_a_matching_public_key() {
    let dir = temp_dir("keygen");
    let secret = dir.join("auditor.key");
    let key = write_auditor_key(&secret).expect("keygen");
    assert_eq!(
        read_auditor_key(&secret, Access::OwnerOnly)
            .expect("load")
            .pubkey(),
        key.pubkey()
    );
    let public_path = public_key_path(&secret).expect("public path");
    assert_eq!(
        std::fs::read_to_string(&public_path).expect("pub file"),
        hex::encode(key.pubkey().as_bytes())
    );
    assert_eq!(
        read_auditor_pubkey(&public_path).expect("pubkey"),
        key.pubkey()
    );
    assert!(matches!(
        write_auditor_key(&secret),
        Err(KeyFileError::File(SecretFileError::Write { .. }))
    ));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn public_key_files_round_trip_and_reject_other_lengths() {
    let dir = temp_dir("pubkey");
    let path = dir.join("nested").join("auditor.key.pub");
    let key = X25519Keypair::new();
    write_auditor_pubkey(&path, &key.pubkey()).expect("write");
    assert_eq!(read_auditor_pubkey(&path).expect("read"), key.pubkey());
    let short = dir.join("short.pub");
    std::fs::write(&short, "02ab").expect("short");
    assert!(matches!(
        read_auditor_pubkey(&short),
        Err(KeyFileError::PubkeyEncoding)
    ));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn malformed_and_zero_auditor_secrets_are_refused() {
    let dir = temp_dir("zero");
    let zero = dir.join("zero.key");
    create_new(&zero, "00".repeat(32).as_bytes(), Visibility::Secret).expect("zero");
    assert!(matches!(
        read_auditor_key(&zero, Access::OwnerOnly),
        Err(KeyFileError::ZeroAuditorKey)
    ));
    let upper = dir.join("upper.key");
    create_new(&upper, "AA".repeat(32).as_bytes(), Visibility::Secret).expect("upper");
    assert!(matches!(
        read_auditor_key(&upper, Access::OwnerOnly),
        Err(KeyFileError::File(SecretFileError::Hex))
    ));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

fn small_field(value: u8) -> [u8; 32] {
    let mut field = [0; 32];
    field[31] = value;
    field
}

/// An audited notes answer is used only where each opening rebuilds the hash it answers.
#[test]
fn audited_utxos_are_used_only_when_they_rebuild_their_hashes() {
    let ring = Address::new_from_array([7; 32]);
    let mint = Address::new_from_array([3; 32]);
    let keyed = KnownUtxo {
        owner_key: [0xa1; 32],
        owner: UtxoOwner::Keyed {
            nullifier_pk: small_field(5),
        },
        asset: spr_hasher::primitives::hash_bytes(mint.as_array()).unwrap(),
        mint: Some(mint),
        amount: 40,
        blinding: small_field(6),
        data_hash: [0; 32],
        ring_data_hash: [0; 32],
        tree_id: 3,
    };
    let deposited = KnownUtxo {
        owner: UtxoOwner::Deposited {
            owner_hash: small_field(9),
        },
        amount: 12,
        ..keyed
    };
    let hashes = [keyed, deposited].map(|utxo| utxo.commitment(Some(ring)).unwrap());
    let hash = |index: usize| Hash(hashes[index]);
    let view = |utxo: KnownUtxo, utxo_hash: Hash| AuditedUtxoView {
        utxo_hash,
        utxo: utxo.into(),
        slot: 1,
        tx_signature: Signature::default().into(),
        event_index: 0,
        slot_index: 0,
    };
    let answer = |utxos: Vec<Option<AuditedUtxoView>>| GetAuditedUtxosResponse {
        context: Context {
            slot: 1,
            block_time: 0,
        },
        value: AuditedUtxosPage { utxos },
    };
    let full = answer(vec![
        Some(view(keyed, hash(0))),
        Some(view(deposited, hash(1))),
        None,
    ]);
    let known = full
        .known_utxos(ring, &[hash(0), hash(1), Hash([4; 32])])
        .unwrap();
    assert_eq!(
        known,
        HashMap::from([(hashes[0], keyed), (hashes[1], deposited)])
    );
    let tampered = answer(vec![Some(view(
        KnownUtxo {
            amount: 41,
            ..keyed
        },
        hash(0),
    ))]);
    assert!(matches!(
        tampered.known_utxos(ring, &[hash(0)]),
        Err(AuditError::AuditedUtxoMismatch { .. })
    ));
    let pair = answer(vec![
        Some(view(keyed, hash(0))),
        Some(view(deposited, hash(1))),
    ]);
    assert!(matches!(
        pair.known_utxos(ring, &[hash(1), hash(0)]),
        Err(AuditError::AuditedUtxoMismatch { .. })
    ));
    let mut both = DecryptedKnownUtxo::from(keyed);
    both.owner_hash = Some(Hash(small_field(9)));
    let ambiguous = answer(vec![Some(AuditedUtxoView {
        utxo: both,
        ..view(keyed, hash(0))
    })]);
    assert!(matches!(
        ambiguous.known_utxos(ring, &[hash(0)]),
        Err(AuditError::AuditedUtxoOwner)
    ));
    assert!(matches!(
        full.known_utxos(ring, &[hash(0), hash(1)]),
        Err(AuditError::AuditedUtxosCount { got: 3, want: 2 })
    ));
}

/// The TypeScript encoder writes the same bytes.
#[test]
fn a_relay_request_serializes_to_the_shared_vector() {
    #[derive(Deserialize)]
    struct Vector {
        wire: String,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/relay_request.json"
    ))
    .expect("vector");
    let request = PrepareRelayRequest {
        ring: Address::new_from_array([1; 32]).into(),
        quote: RelayQuote {
            fee_payer: Address::new_from_array([2; 32]).into(),
            valid_until_slot: 4242,
        },
        intent: RelayIntent::Anonymous {
            proof_inputs: ProofInputBytes::new(zeroize::Zeroizing::new(vec![3, 4, 5])),
            owner_signature: Signature::from([7; 64]).into(),
            token_account_setup: Vec::new(),
        },
        co_signers: Vec::new(),
    };
    assert_eq!(serde_json::to_string(&request).expect("json"), vector.wire);
    let read: PrepareRelayRequest = serde_json::from_str(&vector.wire).expect("read");
    assert_eq!(read.intent.operation(), RelayOperation::Anonymous);
}

fn signed_wallet_update() -> SubmitRecordUpdateRequest {
    let wallet = Keypair::new_from_array([7; 32]);
    let identity = Hash(
        *zolana_ring_policy::Member::owner_tag(wallet.pubkey().as_array())
            .expect("wallet")
            .as_bytes(),
    );
    let reader = Hash(*passkey_reader().member().expect("reader").as_bytes());
    let bit = zolana_ring_policy::ListId::RingViewing.record_bit();
    RecordUpdate {
        genesis_hash: Hash([3; 32]),
        ring: Address::new_from_array([1; 32]).into(),
        entries: vec![
            RecordUpdateEntry::Write(zolana_ring_indexer::rpc::RingListWriteView {
                mint_policy: None,
                member: identity.clone(),
                mask: bit,
                value: bit,
            }),
            RecordUpdateEntry::WalletGrant(WalletGrant {
                wallet: identity,
                reader,
                access: ReaderAccess::Granted,
            }),
        ],
        valid_until_slot: 4242,
        awaited_lists: 0,
    }
    .sign(Address::new_from_array([2; 32]), &wallet)
    .expect("sign")
}

/// The TypeScript signer writes the same wire bytes.
#[test]
fn a_signed_wallet_update_verifies_from_the_shared_vector() {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        wire: String,
        update_id: RecordUpdateId,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/record_update.json"
    ))
    .expect("vector");
    let signed = signed_wallet_update();
    assert_eq!(serde_json::to_string(&signed).expect("json"), vector.wire);
    let read: SubmitRecordUpdateRequest = serde_json::from_str(&vector.wire).expect("read");
    assert_eq!(read.verify(), Ok(vector.update_id));
    // The signature covers the slot bound, a later one names another statement.
    let mut extended = read;
    extended.update.valid_until_slot += 1;
    assert_eq!(extended.verify(), Err(RecordUpdateError::Signature));
}

/// Keeps each description, regenerates what the signer writes.
#[test]
#[ignore]
fn write_record_update_vectors() {
    for (name, signed) in [
        ("record_update.json", signed_wallet_update()),
        ("enrolment_update.json", signed_enrolment()),
    ] {
        let path = format!(
            "{}/../../test-vectors/rpc/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut vector: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("vector");
        vector["wire"] = serde_json::to_string(&signed).expect("json").into();
        vector["updateId"] = serde_json::to_value(signed.verify().expect("verify")).expect("id");
        let json = serde_json::to_string_pretty(&vector).expect("json") + "\n";
        std::fs::write(&path, json).expect("write");
    }
}

fn relay_proof_inputs() -> RelayProofInputs {
    use spr_event::MessageData;
    use spr_instruction::instruction::{
        TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    };
    use spr_interface::{
        instruction::instruction_data::transact::{OwnerTag, TransactOutput},
        MAX_OUTPUTS,
    };
    use spr_keypair::{NullifierKey, ShieldedKeypair, SigningKey, X25519Keypair};
    use spr_transaction::{
        instructions::transact::{ExternalData, SettlementTransfer},
        utxo::SppProofInputUtxo,
        Data, Mint, SppProofOutputUtxo, Utxo,
    };
    use zolana_ring_transaction::AnonymousPlan;
    let owner =
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[5; 32])).expect("owner");
    let sender = owner.shielded_address().expect("address");
    let ring = Address::new_from_array([6; 32]);
    let utxo = Utxo {
        owner: sender.signing_pubkey,
        asset: Mint::SOL,
        amount: 900,
        blinding: [11; 32],
        ring_program_id: Some(ring),
        data: Data::default(),
    };
    let utxo_hash = utxo
        .hash(&sender.nullifier_pubkey, &[0; 32], &[0; 32], 4)
        .expect("hash");
    let spend = SppProofInputUtxo {
        address: false,
        nullifier: owner
            .nullifier_key
            .nullifier(&utxo_hash, &utxo.blinding)
            .expect("nullifier"),
        utxo,
        nullifier_pubkey: sender.nullifier_pubkey,
        utxo_hash,
        data_hash: None,
        ring_data_hash: None,
        tree_id: 4,
        leaf_index: 17,
        cache_slot: None,
        compact: false,
    };
    let change = SppProofOutputUtxo {
        asset: Mint::SOL,
        amount: 800,
        blinding: [12; 32],
        ring_program_id: Some(ring),
        owner_address: Some(sender),
        ..SppProofOutputUtxo::default()
    };
    let tx_viewing_key = ViewingKey::from_secret_key(X25519Keypair::from_bytes(&[13; 32]));
    let recipient = Address::new_from_array([14; 32]);
    let external_data = ExternalData {
        interface_transfers: vec![SettlementTransfer::Sol {
            is_deposit: false,
            amount: 100,
            user_sol_account: recipient,
        }],
        ..ExternalData::new(
            *tx_viewing_key.pubkey().as_bytes(),
            [15; 16],
            vec![TransactOutput {
                utxo_hash: [16; 32],
                owner_tag: OwnerTag::Inline([17; 32]),
                data: Some(vec![18, 19]),
            }],
            vec![[20; 32]],
            vec![MessageData {
                view_tag: [21; 32],
                data: vec![22],
            }],
        )
    };
    RelayProofInputs {
        rail: RelayRail::Anonymous {
            plan: Box::new(AnonymousPlan::from_parts(
                vec![owner.viewing_pubkey()],
                [[25; 32]; MAX_OUTPUTS],
            )),
            exit_token_owner: None,
        },
        ring_program_id: ring,
        nullifier_key: NullifierKey::from_secret(*owner.nullifier_key.secret()),
        sender,
        tx_viewing_key,
        inputs: vec![
            spend,
            SppProofInputUtxo::dummy_with_blinding([27; 32], 4).expect("dummy"),
        ],
        outputs: vec![change],
        external_data,
        interface_transfer_accounts: vec![TransactInterfaceTransferAccounts::Sol(
            TransactSolTransferAccounts { recipient },
        )],
        blinding_seed: [28; 32],
        output_tree_id: 4,
        list_salts: Vec::new(),
        co_owners: Vec::new(),
        wide_owners: false,
    }
}

/// `UPDATE_RING_VECTORS=1` rewrites the payload.
#[test]
fn relay_proof_inputs_encode_to_the_shared_vector() {
    let inputs = relay_proof_inputs();
    if std::env::var_os("UPDATE_RING_VECTORS").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/rpc/relay_proof_inputs.json"
        );
        let mut stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("vector")).expect("json");
        let encoded = Base64String::from(inputs.encode().expect("encode").to_vec());
        stored["proofInputs"] = serde_json::to_value(encoded).expect("base64");
        std::fs::write(
            path,
            serde_json::to_string_pretty(&stored).expect("json") + "\n",
        )
        .expect("vector");
    }
    let vector: PayloadVector = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/rpc/relay_proof_inputs.json"
        ))
        .expect("vector"),
    )
    .expect("vector");
    assert_eq!(*inputs.encode().expect("encode"), vector.proof_inputs.0);
    let read = RelayProofInputs::decode(&vector.proof_inputs.0).expect("decode");
    assert_eq!(read.inputs, inputs.inputs);
    assert_eq!(read.outputs, inputs.outputs);
    assert_eq!(read.external_data, inputs.external_data);
    assert_eq!(read.rail.operation(), RelayOperation::Anonymous);
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayloadVector {
    proof_inputs: Base64String,
}

fn shielded_address(seed: u8) -> ShieldedAddress {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[seed; 32]))
        .expect("keypair")
        .shielded_address()
        .expect("address")
}

/// The TypeScript encoder writes the same deposit payload.
#[test]
fn relay_deposit_inputs_encode_to_the_shared_vector() {
    use spr_event::EncryptedRingDepositData;
    use spr_instruction::instruction::{DepositAsset, DepositSplAccounts};
    let vector: PayloadVector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/relay_deposit_inputs.json"
    ))
    .expect("vector");
    let recipient = shielded_address(5);
    let inputs = RelayDepositInputs {
        ring_program_id: Address::new_from_array([6; 32]),
        tree: Address::new_from_array([42; 32]),
        depositor: Address::new_from_array([41; 32]),
        recipient,
        list_salt: [0; 32],
        asset: DepositAsset::Spl(DepositSplAccounts {
            mint: Address::new_from_array([48; 32]),
            user_token: Address::new_from_array([49; 32]),
            token_program: Address::new_from_array([50; 32]),
        }),
        amount: 700,
        view_tag: [43; 32],
        encrypted: EncryptedRingDepositData {
            tx_viewing_pk: [44; 33],
            salt: [45; 16],
            ciphertext: vec![46; 8],
        },
        blinding_secret: zeroize::Zeroizing::new([47; 32]),
        audit_ephemeral_key: zeroize::Zeroizing::new([51; 32]),
    };
    assert_eq!(*inputs.encode().expect("encode"), vector.proof_inputs.0);
    let read = RelayDepositInputs::decode(&vector.proof_inputs.0).expect("decode");
    assert_eq!(read.recipient, recipient);
    assert_eq!(*read.encode().expect("encode"), vector.proof_inputs.0);
}

/// The TypeScript encoder writes the same merge payload.
#[test]
fn relay_merge_inputs_encode_to_the_shared_vector() {
    let vector: PayloadVector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/relay_merge_inputs.json"
    ))
    .expect("vector");
    let spends = relay_proof_inputs();
    let spend = &spends.inputs[0];
    let inputs = RelayMergeInputs {
        ring_program_id: spends.ring_program_id,
        sender: spends.sender,
        nullifier_key: spends.nullifier_key.clone(),
        inputs: vec![spr_transaction::WalletUtxo {
            utxo: spend.utxo.clone(),
            nullifier_pubkey: spend.nullifier_pubkey,
            utxo_hash: spend.utxo_hash,
            nullifier: spend.nullifier,
            tx_viewing_key: None,
            data_hash: None,
            ring_data_hash: None,
            tree_id: spend.tree_id,
            leaf_index: spend.leaf_index,
            latest_tree_id: None,
            slot: 0,
            tx_signature: Signature::default(),
            slot_index: 0,
        }],
    };
    assert_eq!(*inputs.encode().expect("encode"), vector.proof_inputs.0);
    let read = RelayMergeInputs::decode(&vector.proof_inputs.0).expect("decode");
    assert_eq!(read.inputs[0].nullifier, spend.nullifier);
}

/// The TypeScript signer writes the same message and wire bytes.
#[test]
fn a_signed_authority_transfer_matches_the_shared_vector() {
    #[derive(Deserialize)]
    struct Vector {
        message: String,
        wire: String,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/authority_transfer.json"
    ))
    .expect("vector");
    let delegate = Keypair::new_from_array([8; 32]);
    let attestation = AuthorityTransferAttestation {
        target: target(),
        delegate: delegate.pubkey(),
        transfer: AuthorityTransfer {
            sources: vec![shielded_address(5).into()],
            mint: Address::new_from_array([3; 32]).into(),
            payments: vec![AuthorityPayment {
                recipient: shielded_address(9).into(),
                amount: 250,
            }],
        },
    };
    let message = attestation.message(1_700_000_000, &[4; 32]);
    assert_eq!(String::from_utf8(message).expect("utf8"), vector.message);
    let signed = SignedRequest {
        attestation,
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
    }
    .sign(&delegate, &spr_keypair::ViewingKey::from_bytes(&[6; 32]))
    .expect("sign");
    let wire = serde_json::to_string(&signed).expect("json");
    if std::env::var_os("UPDATE_RING_VECTORS").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/rpc/authority_transfer.json"
        );
        let mut stored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("vector")).expect("json");
        stored["wire"] = serde_json::Value::String(wire.clone());
        std::fs::write(
            path,
            serde_json::to_string_pretty(&stored).expect("json") + "\n",
        )
        .expect("vector");
        return;
    }
    assert_eq!(wire, vector.wire);
}

fn signed_enrolment() -> SubmitRecordUpdateRequest {
    let wallet = Keypair::new_from_array([7; 32]);
    let identity = Hash(
        *zolana_ring_policy::Member::owner_tag(wallet.pubkey().as_array())
            .expect("wallet")
            .as_bytes(),
    );
    let bit = zolana_ring_policy::ListId::RingViewing.record_bit();
    RecordUpdate {
        genesis_hash: Hash([3; 32]),
        ring: Address::new_from_array([1; 32]).into(),
        entries: vec![RecordUpdateEntry::Write(
            zolana_ring_indexer::rpc::RingListWriteView {
                mint_policy: None,
                member: identity,
                mask: bit,
                value: bit,
            },
        )],
        valid_until_slot: 4242,
        awaited_lists: zolana_ring_policy::ListId::Allow.record_bit(),
    }
    .sign(Address::new_from_array([2; 32]), &wallet)
    .expect("sign")
}

/// The TypeScript signer writes the same wire bytes.
#[test]
fn a_signed_enrolment_verifies_from_the_shared_vector() {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        wire: String,
        update_id: RecordUpdateId,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/enrolment_update.json"
    ))
    .expect("vector");
    let signed = signed_enrolment();
    assert_eq!(serde_json::to_string(&signed).expect("json"), vector.wire);
    let read: SubmitRecordUpdateRequest = serde_json::from_str(&vector.wire).expect("read");
    assert_eq!(read.verify(), Ok(vector.update_id));
    // An enrolment signature never verifies as a plain update.
    let mut plain = read;
    plain.update.awaited_lists = 0;
    assert_eq!(plain.verify(), Err(RecordUpdateError::Signature));
}

/// The TypeScript signers write the same messages and wire bytes.
#[test]
fn the_enrolment_requests_match_the_shared_vector() {
    #[derive(Deserialize)]
    struct Signed {
        message: String,
        wire: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Refuse {
        update_id: RecordUpdateId,
        message: String,
        wire: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        list: Signed,
        list_after: Signed,
        refuse: Refuse,
        create_records: Signed,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/enrolment_attestation.json"
    ))
    .expect("vector");
    let authority = Keypair::new_from_array([8; 32]);
    let list = EnrolmentAttestation {
        target: target(),
        authority: authority.pubkey(),
        action: ListEnrolments::default(),
    };
    let refuse = EnrolmentAttestation {
        target: target(),
        authority: authority.pubkey(),
        action: RefuseEnrolment(vector.refuse.update_id.clone()),
    };
    let list_after = GetPendingEnrolmentsRequest::read(target(), authority.pubkey())
        .with_cursor(vector.refuse.update_id.clone());
    let message = |bytes: Vec<u8>| String::from_utf8(bytes).expect("utf8");
    assert_eq!(
        message(list_after.attestation.message(1_700_000_000, &[4; 32])),
        vector.list_after.message
    );
    let list_after = SignedRequest {
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
        ..list_after
    }
    .sign(&authority)
    .expect("sign the second page");
    assert_eq!(
        serde_json::to_string(&list_after).expect("json"),
        vector.list_after.wire
    );
    assert_eq!(
        message(list.message(1_700_000_000, &[4; 32])),
        vector.list.message
    );
    assert_eq!(
        message(refuse.message(1_700_000_000, &[4; 32])),
        vector.refuse.message
    );
    let list = SignedRequest {
        attestation: list,
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
    }
    .sign(&authority)
    .expect("sign list");
    let refuse = SignedRequest {
        attestation: refuse,
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
    }
    .sign(&authority)
    .expect("sign refusal");
    assert_eq!(
        serde_json::to_string(&list).expect("json"),
        vector.list.wire
    );
    assert_eq!(
        serde_json::to_string(&refuse).expect("json"),
        vector.refuse.wire
    );
    let create_records = CreateRecordsRegistryRequest::create(target(), authority.pubkey());
    assert_eq!(
        message(create_records.attestation.message(1_700_000_000, &[4; 32])),
        vector.create_records.message
    );
    let create_records = SignedRequest {
        timestamp: Some(1_700_000_000),
        nonce: [4; 32],
        ..create_records
    }
    .sign(&authority)
    .expect("sign the records request");
    assert_eq!(
        serde_json::to_string(&create_records).expect("json"),
        vector.create_records.wire
    );
}

/// The P-256 generator, a passkey reader the shared vectors name.
fn passkey_reader() -> ReaderKey {
    let key = hex::decode("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        .expect("hex");
    ReaderKey::p256(
        crate::P256ReaderKey::from_bytes(key.try_into().expect("33 bytes")).expect("on curve"),
    )
    .expect("passkey")
}

/// The TypeScript signers write the same messages and wire bytes.
#[test]
fn the_reader_grants_and_wallet_reads_match_the_shared_vector() {
    #[derive(Deserialize)]
    struct Signed {
        message: String,
        wire: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        ring_wide: Signed,
        wallet: Signed,
        wallet_read: String,
        wallet_utxos: String,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/rpc/reader_grant.json"
    ))
    .expect("vector");
    let authority = Keypair::new_from_array([8; 32]);
    let wallet = Keypair::new_from_array([7; 32]);
    let reader = ReaderKey::ed25519(Keypair::new_from_array([9; 32]).pubkey()).expect("reader");
    let grants = [
        (
            &authority,
            None,
            reader,
            ReaderGrantAction::Grant,
            &vector.ring_wide,
        ),
        (
            &wallet,
            Some(wallet.pubkey()),
            passkey_reader(),
            ReaderGrantAction::Revoke,
            &vector.wallet,
        ),
    ];
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).expect("utf8");
    for (signer, wallet, reader, action, expected) in grants {
        let attestation = ReaderGrantAttestation {
            target: target(),
            wallet,
            reader,
            action,
        };
        let message = attestation.message(1_700_000_000, &[4; 32]);
        assert_eq!(text(message.clone()), expected.message);
        let signed = SignedRequest {
            attestation,
            timestamp: Some(1_700_000_000),
            nonce: [4; 32],
        }
        .sign(signer)
        .expect("sign");
        assert_eq!(serde_json::to_string(&signed).expect("json"), expected.wire);
        let read: SetReaderGrantRequest = serde_json::from_str(&expected.wire).expect("read");
        assert!(read.signature.0.verify(signer.pubkey().as_ref(), &message));
    }
    let read = ReadAttestation {
        read: PagedRead::DecryptedTransactions,
        target: target(),
        cursor: None,
        limit: None,
        wallet: Some(wallet.pubkey()),
    };
    assert_eq!(
        text(read.message(1_700_000_000, &[4; 32])),
        vector.wallet_read
    );
    let utxos = AuditedUtxosAttestation {
        wallet: Some(wallet.pubkey()),
        ..AuditedUtxosAttestation::new(target(), &[Hash([5; 32])])
    };
    assert_eq!(
        text(utxos.message(1_700_000_000, &[4; 32])),
        vector.wallet_utxos
    );
}

fn wallet_update_writes() -> Vec<custom_ring_interface::RecordWriteData> {
    use zolana_ring_policy::{AssetLimits, ListId, Member, MintPolicy};
    let wallet = Keypair::new_from_array([7; 32]);
    let identity = Member::owner_tag(wallet.pubkey().as_array()).expect("wallet");
    let bit = ListId::RingViewing.record_bit();
    [
        RecordUpdateEntry::Write(zolana_ring_indexer::rpc::RingListWriteView {
            mint_policy: Some(MintPolicy {
                threshold: 1,
                cap: 2,
                cosign_above: 3,
                withdrawal_threshold: 4,
                limits: AssetLimits {
                    sender_cap: 5,
                    sender_window_slots: 6,
                    volume_cap: 7,
                    volume_window_slots: 8,
                    deposit_cap: 9,
                    deposit_window_slots: 10,
                    withdrawal_cap: 11,
                    withdrawal_window_slots: 12,
                },
            }),
            member: Hash(*identity.as_bytes()),
            mask: bit,
            value: bit,
        }),
        RecordUpdateEntry::WalletGrant(WalletGrant {
            wallet: Hash(*identity.as_bytes()),
            reader: Hash(*passkey_reader().member().expect("member").as_bytes()),
            access: ReaderAccess::Granted,
        }),
    ]
    .iter()
    .map(|entry| entry.write().expect("write"))
    .collect()
}

/// The TypeScript codec writes and reads the same bytes.
#[test]
fn the_storage_writes_of_a_wallet_update_match_the_shared_vector() {
    use custom_ring_interface::{CustomRingError, RecordWriteData};
    #[derive(Deserialize)]
    struct Vector {
        writes: String,
    }
    let vector: Vector = serde_json::from_str(include_str!(
        "../../../../test-vectors/registry/storage_writes.json"
    ))
    .expect("vector");
    let writes = wallet_update_writes();
    let bytes: &[u8] = bytemuck::cast_slice(&writes);
    assert_eq!(hex::encode(bytes), vector.writes);
    let decoded = hex::decode(&vector.writes).expect("hex");
    assert_eq!(
        bytemuck::try_cast_slice::<u8, RecordWriteData>(&decoded).expect("whole writes"),
        writes
    );
    assert!(writes.iter().all(|write| write.storage_entry().is_ok()));
    let tag = core::mem::offset_of!(RecordWriteData, mint_policy);
    for refused in [2, 7] {
        let mut tampered = decoded.clone();
        tampered[tag] = refused;
        let write: &RecordWriteData = bytemuck::from_bytes(&tampered[..RecordWriteData::SIZE]);
        assert_eq!(
            write.storage_entry(),
            Err(CustomRingError::InvalidInstructionData)
        );
    }
}

#[test]
#[ignore = "rewrites test-vectors/registry/storage_writes.json"]
fn write_storage_writes_vector() {
    let writes = wallet_update_writes();
    let vector = serde_json::json!({
        "description": "The RecordWriteData bytes of two record update entries of the wallet of seed 0x07, each member || mask || value || mint_policy_write in little endian. The first sets the ring-viewing list on the wallet's own record and replaces its mint settings with the amounts 1 to 12 in field order. The second grants the passkey reader on the wallet grant record and keeps the mint settings. A mint_policy_write leading byte off 0 and 1 is refused.",
        "writes": hex::encode(bytemuck::cast_slice::<_, u8>(&writes)),
    });
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/registry/storage_writes.json"
    );
    std::fs::write(
        path,
        serde_json::to_string_pretty(&vector).expect("json") + "\n",
    )
    .expect("vector");
}

#[test]
#[ignore = "rewrites the decrypted page fixtures"]
fn write_decrypted_page_vectors() {
    let mut delivered = page(delivered_audited(), vec![[12; 32]]);
    delivered.value.items[0].spenders = vec![[13; 32].into()];
    let in_proof = in_proof_page(
        AuditedInput {
            nullifier: [12; 32],
            opening: InputOpening::Real,
        },
        AuditedInput {
            nullifier: [11; 32],
            opening: InputOpening::Dummy,
        },
    );
    let anonymous = anonymous_page();
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/src/rpc/");
    for (name, page) in [
        ("decrypted_page.json", &delivered),
        ("decrypted_in_proof_page.json", &in_proof),
        ("decrypted_anonymous_page.json", &anonymous),
    ] {
        let json = serde_json::to_string(page).expect("json") + "\n";
        std::fs::write(format!("{directory}{name}"), json).expect("vector");
    }
    let [transaction] = anonymous.value.items.as_slice() else {
        panic!("one transaction")
    };
    let of = |wallet: u8, party: InputParty| {
        WalletActivity::of(
            Address::new_from_array([wallet; 32]),
            transaction.clone(),
            |_| party,
        )
        .expect("a party")
    };
    let activity = GetWalletActivityResponse {
        context: anonymous.context,
        value: WalletActivityPage {
            items: vec![of(0x50, InputParty::Own), of(0x10, InputParty::Other)],
            cursor: anonymous.value.cursor.clone(),
        },
    };
    std::fs::write(
        format!("{directory}wallet_activity_page.json"),
        serde_json::to_string(&activity).expect("json") + "\n",
    )
    .expect("vector");
}
