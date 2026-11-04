//! Pins `test-vectors/proof/ring-transact-expansion.json` for the TS SDK and the ring program tests.

mod frames;

use frames::{config, spp_b, Fixture};

use bytemuck::Zeroable;
use custom_ring_interface::{
    encode_ring_recipient_output, encode_ring_sender_bundle_output,
    ring_confidential_delivered_output_body, ring_recipient_output_body,
    ring_sender_bundle_output_body, sender_bundle_len, CONFIDENTIAL_DATA_FREE_BODY_LEN,
    MIN_REPLY_LEN, OUTPUT_COUNT_BYTE, RING_RECIPIENT_SCHEME_TAG, RING_SENDER_BUNDLE_SCHEME_TAG,
};
use custom_ring_interface::{
    input_flag,
    key_catalog::RingCircuit,
    shape_flag,
    storage::{Revision, Root, StorageRegistry},
    storage_instruction::InitializeIxData as StorageInitialize,
    transact_flag, AnonymousAuditKey, AuditKey, AuditStreamLayout, AuditorMessage,
    ConfidentialSender, CustomRingError, FramedSenderBundle, InstructionTag, LiveRoots,
    ParsedTransact, PlainGroth16Proof, PolicyProof, RailSigner, Replies, RingMode, RingOutput,
    RingPolicy, RingRail, RingTransactData, RootRead, Settlement, SignerSet, SourceSlot,
    TransferBinding, TransferFamily, TransferRoots,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_event::{
    confidential_encrypted_output_body, OutputDataEncoding, CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
};
use spr_hasher::primitives::solana_owner_identity;
use spr_interface::{
    instruction::{CircuitId, InterfaceTransfer, OwnerTag},
    shape::{Shape, SPP_SUPPORTED_SHAPES},
};
use zolana_ring_policy::ListId;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/proof/ring-transact-expansion.json"
);

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct ExpansionVectors {
    description: String,
    auditor_pubkey: String,
    cases: Vec<Case>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Case {
    name: String,
    /// `confidential`, `anonymous` or `delegate`.
    rail: String,
    compact: String,
    /// Per public leg, the asset account then the user account.
    settlements: Vec<[String; 2]>,
    transact_ix_data: String,
    spp_instruction_data: String,
    external_data_hash: String,
}

/// A delegate move into eight delivered slots, a shape SPP keys no ring authority for.
fn delegate_delivered(fixture: &Fixture) -> RingTransactData<'_> {
    let mut data = fixture.base(RingRail::Delegate, 2, 8);
    data.key_escrow = true;
    data.own_revision = Some(Revision::from(0));
    data.policy = Some(fixture.delegate_policy(8));
    data.outputs = (0..8).map(|slot| fixture.delivered(slot)).collect();
    data
}

fn settlements(legs: usize) -> Vec<[[u8; 32]; 2]> {
    (0..legs)
        .map(|leg| [[0xe0 + leg as u8; 32], [0xf0 + leg as u8; 32]])
        .collect()
}

fn compute_vectors() -> ExpansionVectors {
    let fixture = Fixture::new();
    let config = config();
    let cases = fixture
        .cases()
        .into_iter()
        .map(|(name, data)| {
            let legs = settlements(data.interface_transfers.len());
            let borrowed: Vec<Settlement<'_>> = legs
                .iter()
                .map(|[asset_account, user_account]| Settlement {
                    asset_account,
                    user_account,
                })
                .collect();
            Case {
                name: name.to_string(),
                rail: data.rail.to_string(),
                compact: hex::encode(data.encode().unwrap()),
                settlements: legs.iter().map(|leg| leg.map(hex::encode)).collect(),
                transact_ix_data: hex::encode(data.expand(&config).unwrap().serialize().unwrap()),
                spp_instruction_data: hex::encode(data.spp_instruction_data(&config).unwrap()),
                external_data_hash: hex::encode(
                    data.external_data_hash(&config, &borrowed).unwrap(),
                ),
            }
        })
        .collect();
    ExpansionVectors {
        description: "Compact ring transact data of each rail and what the ring program forwards \
                      for it, the SPP TransactIxData, the SPP instruction data (tag 19 or 21 then the \
                      data) and the external data \
                      hash over the SPP tag, the data before private_tx_hash and two settlement \
                      accounts per leg. Byte 0 carries the policy, curator, approval, in-proof \
                      owner (bit 3), exempt (bit 4), second tree (bit 5) and reply metadata \
                      (bit 6) flags, the one ring proof follows the header, the own registry \
                      revision under the policy or exempt flag and always on the anonymous rail, \
                      the curator revision under the curator flag and one recipient per published \
                      slot under the policy flag on a publishing rail. Byte 1 indexes \
                      SPP_SUPPORTED_SHAPES below the default owner tag flag (bit 6), bit 7 refused. \
                      Byte 2 is the input count below the key escrow flag (bit 6) and the \
                      anonymous entry key flag (bit 7), byte 3 is m, the published slots. The \
                      expiry is a u32, exit_bits and on the anonymous rail change_bits take \
                      ceil(m / 8) bytes, exit payloads take 83 bytes without a u16 prefix, an \
                      anonymous slot is its hash, a 32-byte owner tag and the 72 byte scheme 11 \
                      body, no body on a change bit, a delivered slot is its hash, recipient key \
                      and the scheme 10 body of 72 bytes under key escrow and 104 otherwise. \
                      Under reply metadata a u16 little-endian reply_len follows the slots, then \
                      reply_len bytes per body-bearing slot, forwarded after that slot's body. \
                      The anonymous rail's scheme 12 sender bundle follows as a 32-byte tag and \
                      80 + 32 m bytes, then eph_u, the envelope and the records of the slots \
                      that have one in slot order, the lengths those of \
                      ring-disclosure-ranges.json, and the random 16-byte salt follows the \
                      transaction viewing key. The auditor message is 0x04 || eph_u || envelope \
                      || records. Under the in-proof owner flag (byte 0 bit 3) SPP proves the \
                      anonymous rail with no default owner tag, and the owner key, commitment \
                      and commitment pok follow private_tx_hash. Produced by \
                      program-libs/interface/tests/transact.rs."
            .to_string(),
        auditor_pubkey: hex::encode(config.auditor_pubkey),
        cases,
    }
}

fn rail(name: &str) -> RingRail {
    [
        RingRail::Confidential,
        RingRail::Anonymous,
        RingRail::Delegate,
    ]
    .into_iter()
    .find(|rail| rail.to_string() == name)
    .unwrap_or_else(|| panic!("unknown rail {name}"))
}

#[test]
fn ring_transact_expansion_vector() {
    let committed: ExpansionVectors =
        serde_json::from_str(&std::fs::read_to_string(VECTORS).expect("vector file"))
            .expect("vector json");
    assert_eq!(committed, compute_vectors());
    let config = config();
    for case in &committed.cases {
        let compact = hex::decode(&case.compact).unwrap();
        let data = RingTransactData::parse(&compact, rail(&case.rail))
            .unwrap()
            .into_data();
        assert_eq!(data.encode().unwrap(), compact, "{}", case.name);
        let spp = data.expand(&config).unwrap();
        assert_eq!(spp.proof.b, spp_b());
        assert_eq!(&spp.salt, data.salt, "{}", case.name);
        let (auditor, sender) = spp.messages.split_last().unwrap();
        assert_eq!(auditor.view_tag, config.auditor_pubkey[1..]);
        assert_eq!(auditor.data, data.auditor_message(), "{}", case.name);
        assert_eq!(auditor.data.capacity(), auditor.data.len(), "{}", case.name);
        let sender: Vec<_> = sender
            .iter()
            .map(|message| (message.view_tag, message.data.clone()))
            .collect();
        let expected: Vec<_> = data
            .sender
            .iter()
            .map(|bundle| {
                (
                    *bundle.tag,
                    encode_ring_sender_bundle_output(bundle.body).unwrap(),
                )
            })
            .collect();
        assert_eq!(sender, expected, "{}", case.name);
        for ((output, slot), reply) in spp
            .outputs
            .iter()
            .zip(&data.outputs)
            .zip(data.slot_replies())
        {
            match slot {
                RingOutput::Delivered { .. } => assert!(output
                    .data
                    .as_deref()
                    .and_then(ring_confidential_delivered_output_body)
                    .is_some()),
                RingOutput::Anonymous { tag, body, .. } => {
                    assert_eq!(output.owner_tag, OwnerTag::Inline(**tag));
                    assert_eq!(
                        output.data,
                        body.map(|body| encode_ring_recipient_output(body, reply).unwrap()),
                        "{}",
                        case.name
                    );
                }
                RingOutput::Exit { .. } => assert!(output
                    .data
                    .as_deref()
                    .and_then(confidential_encrypted_output_body)
                    .is_some()),
            }
        }
        let mut forwarded = vec![data.rail.spp_tag()];
        forwarded.extend(spp.serialize().unwrap());
        assert_eq!(hex::encode(forwarded), case.spp_instruction_data);
    }
}

#[test]
#[ignore = "rewrites test-vectors/proof/ring-transact-expansion.json"]
fn write_ring_transact_expansion_vector() {
    let json = serde_json::to_string_pretty(&compute_vectors()).expect("json");
    std::fs::write(VECTORS, json + "\n").expect("write vector file");
}

const FRAME_VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/settlement/frame_v3.hex"
);

fn frame_lines() -> String {
    Fixture::new()
        .cases()
        .iter()
        .map(|(_, data)| hex::encode(data.encode().unwrap()) + "\n")
        .collect()
}

#[test]
fn the_frames_are_the_shared_vector() {
    assert_eq!(
        std::fs::read_to_string(FRAME_VECTOR).expect("vector file"),
        frame_lines()
    );
}

#[test]
#[ignore = "rewrites test-vectors/settlement/frame_v3.hex"]
fn write_frame_vector() {
    std::fs::write(FRAME_VECTOR, frame_lines()).expect("write vector file");
}

#[test]
fn anonymous_and_exit_slots_keep_the_borsh_framing_at_exact_capacity() {
    let fixture = Fixture::new();
    let borsh_framing = |scheme: u8, payload: &[u8]| {
        borsh::to_vec(&OutputDataEncoding::Encrypted(
            [&[scheme][..], payload].concat(),
        ))
        .unwrap()
    };
    let reply = [0x77; MIN_REPLY_LEN];
    let body_and_reply = [&fixture.recipient_body[..], &reply].concat();
    for (data, scheme, payload) in [
        (
            fixture
                .tagged(1)
                .transact_output(&[])
                .unwrap()
                .data
                .unwrap(),
            RING_RECIPIENT_SCHEME_TAG,
            &fixture.recipient_body[..],
        ),
        (
            fixture
                .tagged(1)
                .transact_output(&reply)
                .unwrap()
                .data
                .unwrap(),
            RING_RECIPIENT_SCHEME_TAG,
            &body_and_reply[..],
        ),
        (
            encode_ring_sender_bundle_output(&fixture.sender_body).unwrap(),
            RING_SENDER_BUNDLE_SCHEME_TAG,
            &fixture.sender_body[..],
        ),
        (
            fixture
                .exit(1, &fixture.payload)
                .transact_output(&[])
                .unwrap()
                .data
                .unwrap(),
            CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
            &fixture.payload[..],
        ),
    ] {
        assert_eq!(data, borsh_framing(scheme, payload), "scheme {scheme}");
        assert_eq!(data.capacity(), data.len(), "scheme {scheme}");
    }
    let framed = fixture
        .tagged(1)
        .transact_output(&reply)
        .unwrap()
        .data
        .unwrap();
    assert_eq!(
        ring_recipient_output_body(&framed),
        Some((&fixture.recipient_body, &reply[..]))
    );
    let bundle = encode_ring_sender_bundle_output(&fixture.sender_body).unwrap();
    assert_eq!(
        ring_sender_bundle_output_body(&bundle),
        Some(&fixture.sender_body[..])
    );
    assert_eq!(ring_recipient_output_body(&bundle), None);
}

#[test]
fn the_counts_fix_every_length_and_trailing_bytes_are_refused() {
    let fixture = Fixture::new();
    for (name, data) in fixture.cases() {
        let mut compact = data.encode().unwrap();
        compact.push(0);
        assert_eq!(
            RingTransactData::parse(&compact, data.rail),
            Err(CustomRingError::RingTransactLength),
            "{name}"
        );
        compact.truncate(compact.len() - 2);
        assert_eq!(
            RingTransactData::parse(&compact, data.rail),
            Err(CustomRingError::RingTransactLength),
            "{name}"
        );
    }
}

#[test]
fn the_output_count_stays_between_one_and_the_capacity() {
    let fixture = Fixture::new();
    for data in [
        fixture.confidential_delivered(),
        fixture.anonymous(),
        fixture.delegate(),
    ] {
        let compact = data.encode().unwrap();
        for count in [0, data.n_out + 1] {
            let mut refused = compact.clone();
            refused[OUTPUT_COUNT_BYTE] = count;
            assert_eq!(
                RingTransactData::parse(&refused, data.rail),
                Err(CustomRingError::OutputCountOutOfRange),
                "{count}"
            );
        }
        let mut empty = data.clone();
        empty.outputs.clear();
        assert_eq!(empty.encode(), Err(CustomRingError::OutputCountOutOfRange));
    }
}

/// `m` moves the chains' prefix, never a slot's index, the suffix leaves the frame.
#[test]
fn a_compact_frame_omits_the_suffix_and_keeps_the_capacity() {
    let fixture = Fixture::new();
    let data = fixture.confidential_compact();
    let compact = data.encode().unwrap();
    assert_eq!(compact[OUTPUT_COUNT_BYTE], 5);
    let parsed = RingTransactData::parse(&compact, RingRail::Confidential).unwrap();
    let stream = parsed.audit_stream();
    assert_eq!((stream.outputs, stream.capacity), (5, 8));
    assert_eq!(parsed.data().outputs.len(), 5);
    assert_eq!(parsed.data().n_out, 8);
    let full = fixture.confidential_delivered().encode().unwrap();
    assert!(compact.len() < full.len());
    assert_eq!(
        data.transfer_circuit(0),
        fixture.confidential_delivered().transfer_circuit(0)
    );
    let spp = data.expand(&config()).unwrap();
    assert_eq!(spp.outputs.len(), 5);
    let CircuitId::ConfidentialRingEddsa(1, 8, _) = spp.circuit else {
        panic!("the shape keeps the capacity");
    };
}

#[test]
fn change_bits_are_a_prefix_of_at_most_two_slots_apart_from_exits() {
    let fixture = Fixture::new();
    let data = fixture.anonymous();
    let compact = data.encode().unwrap();
    let exit_bits = bits_offset(&data, &compact);
    assert_eq!(compact[exit_bits], 0b0100);
    assert_eq!(compact[exit_bits + 1], 0b0001);
    for (exits, changes, refusal) in [
        (0b0100, 0b0010, CustomRingError::InvalidChangeBits),
        (0b0100, 0b0100, CustomRingError::InvalidChangeBits),
        (0b0001, 0b0001, CustomRingError::InvalidChangeBits),
        (0b0000, 0b0111, CustomRingError::InvalidChangeBits),
        (0b0100, 1 << 4, CustomRingError::InvalidInstructionData),
        (1 << 4, 0b0001, CustomRingError::InvalidInstructionData),
    ] {
        let mut refused = compact.clone();
        refused[exit_bits] = exits;
        refused[exit_bits + 1] = changes;
        assert_eq!(
            RingTransactData::parse(&refused, RingRail::Anonymous),
            Err(refusal),
            "{exits:#b} {changes:#b}"
        );
    }
    let mut no_prefix = data.clone();
    no_prefix.outputs[3] = RingOutput::Anonymous {
        hash: &fixture.fields[13],
        tag: &fixture.tags[3],
        body: None,
        record: &fixture.ciphertexts[3],
    };
    assert_eq!(no_prefix.encode(), Err(CustomRingError::InvalidChangeBits));
}

/// The bitmaps follow the interface transfers, past the only field the frame repeats.
fn bits_offset(data: &RingTransactData<'_>, compact: &[u8]) -> usize {
    let first_hash = compact
        .windows(32)
        .position(|window| window == data.outputs[0].hash())
        .unwrap();
    let bitmaps = match data.rail {
        RingRail::Anonymous => 2,
        RingRail::Confidential | RingRail::Delegate => 1,
    };
    first_hash - bitmaps * data.outputs.len().div_ceil(8)
}

#[test]
fn a_change_slot_frames_no_body_and_an_anonymous_body_has_one_length() {
    let fixture = Fixture::new();
    let compact = fixture.anonymous_compact().encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Anonymous)
        .unwrap()
        .into_data();
    assert!(parsed.outputs[0].is_change());
    assert!(!parsed.outputs[1].is_change());
    let mut truncated = compact.clone();
    let body = compact
        .windows(fixture.recipient_body.len())
        .position(|window| window == fixture.recipient_body)
        .unwrap();
    truncated.remove(body);
    assert!(RingTransactData::parse(&truncated, RingRail::Anonymous).is_err());
    let spp = parsed.expand(&config()).unwrap();
    assert_eq!(spp.outputs[0].data, None);
    assert_eq!(
        spp.outputs[1].data,
        Some(encode_ring_recipient_output(&fixture.recipient_body, &[]).unwrap())
    );
    assert_eq!(
        parsed.sender.unwrap().body.len(),
        sender_bundle_len(parsed.outputs.len())
    );
}

#[test]
fn reply_metadata_is_one_length_on_the_anonymous_rail_alone() {
    let fixture = Fixture::new();
    let data = fixture.anonymous_replies(MIN_REPLY_LEN as u16);
    let compact = data.encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Anonymous)
        .unwrap()
        .into_data();
    assert_eq!(parsed, data);
    let spp = parsed.expand(&config()).unwrap();
    let replies: Vec<&[u8]> = parsed.slot_replies().collect();
    assert_eq!(
        replies,
        [
            &[][..],
            &fixture.replies[..MIN_REPLY_LEN],
            &[][..],
            &fixture.replies[MIN_REPLY_LEN..2 * MIN_REPLY_LEN],
        ]
    );
    // A reply follows the body it shares a secret with, a change and an exit carry none.
    assert_eq!(spp.outputs[0].data, None);
    assert_eq!(
        ring_recipient_output_body(spp.outputs[1].data.as_deref().unwrap()),
        Some((&fixture.recipient_body, replies[1]))
    );
    assert_eq!(
        ring_recipient_output_body(spp.outputs[3].data.as_deref().unwrap()),
        Some((&fixture.recipient_body, replies[3]))
    );
    let mut short = fixture.anonymous();
    short.replies = Some(Replies {
        len: MIN_REPLY_LEN as u16 - 1,
        region: &fixture.replies[..2 * (MIN_REPLY_LEN - 1)],
    });
    assert_eq!(short.encode(), Err(CustomRingError::ReplyLength));
    let mut uneven = fixture.anonymous();
    uneven.replies = Some(Replies {
        len: MIN_REPLY_LEN as u16,
        region: &fixture.replies[..MIN_REPLY_LEN],
    });
    assert_eq!(uneven.encode(), Err(CustomRingError::ReplyLength));
    let bare = fixture.anonymous().encode().unwrap();
    let mut claimed = bare.clone();
    claimed[transact_flag::BYTE] |= transact_flag::REPLY_METADATA;
    assert!(RingTransactData::parse(&claimed, RingRail::Anonymous).is_err());
    for (name, data) in fixture.cases() {
        if data.rail == RingRail::Anonymous {
            continue;
        }
        let mut foreign = data.encode().unwrap();
        foreign[transact_flag::BYTE] |= transact_flag::REPLY_METADATA;
        assert_eq!(
            RingTransactData::parse(&foreign, data.rail),
            Err(CustomRingError::FlagNotAllowed),
            "{name}"
        );
    }
}

fn shape_index(n_in: usize, n_out: usize) -> u8 {
    let shape = Shape::new(n_in, n_out);
    SPP_SUPPORTED_SHAPES
        .iter()
        .position(|supported| *supported == shape)
        .unwrap() as u8
}

#[test]
fn counts_outside_the_keyed_shapes_are_refused() {
    let fixture = Fixture::new();
    let policy = fixture.confidential_policy().encode().unwrap();
    let mut unindexed = policy.clone();
    unindexed[1] = SPP_SUPPORTED_SHAPES.len() as u8;
    assert_eq!(
        RingTransactData::parse(&unindexed, RingRail::Confidential),
        Err(CustomRingError::RingShapeUnkeyed)
    );
    let mut excess = policy;
    excess[2] = excess[2] & !0b0011_1111 | 3;
    assert_eq!(
        RingTransactData::parse(&excess, RingRail::Confidential),
        Err(CustomRingError::RingTransactLength)
    );
    let mut wide = fixture.anonymous().encode().unwrap();
    wide[1] = shape_index(2, 16) | (wide[1] & !0b0011_1111);
    assert_eq!(
        RingTransactData::parse(&wide, RingRail::Anonymous),
        Err(CustomRingError::RingShapeUnkeyed)
    );
}

#[test]
fn anonymous_header_flags_off_the_anonymous_rail_are_refused() {
    let fixture = Fixture::new();
    let mut entry = fixture.confidential_policy().encode().unwrap();
    entry[input_flag::BYTE] |= input_flag::FULL_OPENINGS;
    assert_eq!(
        RingTransactData::parse(&entry, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut owner_tag = fixture.confidential_policy().encode().unwrap();
    owner_tag[shape_flag::BYTE] |= shape_flag::DEFAULT_OWNER_TAG;
    assert_eq!(
        RingTransactData::parse(&owner_tag, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn flags_the_rail_forbids_are_refused() {
    let fixture = Fixture::new();
    let mut curator = fixture.confidential_delivered().encode().unwrap();
    curator[transact_flag::BYTE] |= transact_flag::CURATOR;
    assert_eq!(
        RingTransactData::parse(&curator, RingRail::Confidential),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut exit = fixture.delegate();
    exit.rail = RingRail::Confidential;
    exit.outputs[1] = fixture.exit(1, &fixture.payload);
    let compact = fixture.with_audit_stream(exit).encode().unwrap();
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Delegate),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn an_exit_payload_of_another_length_is_refused() {
    let fixture = Fixture::new();
    let long: Vec<u8> = (0..=CONFIDENTIAL_DATA_FREE_BODY_LEN as u8).collect();
    let mut data = fixture.confidential_delivered();
    data.outputs[3] = fixture.exit(3, &long);
    assert_eq!(data.encode(), Err(CustomRingError::DataFreeBodyLength));
}

#[test]
fn the_reserved_frame_bits_are_refused() {
    let fixture = Fixture::new();
    for (byte, bit) in [
        (transact_flag::BYTE, 1 << 6),
        (transact_flag::BYTE, 1 << 7),
        (shape_flag::BYTE, shape_flag::RESERVED),
    ] {
        let mut compact = fixture.delegate().encode().unwrap();
        compact[byte] |= bit;
        assert_eq!(
            RingTransactData::parse(&compact, RingRail::Delegate),
            Err(CustomRingError::FlagNotAllowed),
            "byte {byte} bit {bit:#x}"
        );
    }
}

#[test]
fn the_in_proof_owner_is_refused_off_the_confidential_rail() {
    let fixture = Fixture::new();
    for (name, data) in fixture.cases() {
        if data.rail == RingRail::Confidential {
            continue;
        }
        let mut compact = data.encode().unwrap();
        compact[transact_flag::BYTE] |= transact_flag::OWNER_IN_PROOF;
        assert_eq!(
            RingTransactData::parse(&compact, data.rail),
            Err(CustomRingError::FlagNotAllowed),
            "{name}"
        );
    }
}

#[test]
fn an_exempt_frame_needs_a_withdrawal_leg_and_the_own_revision_off_the_delegate_rail() {
    let fixture = Fixture::new();
    let exempt = fixture.confidential_exempt();
    let compact = exempt.encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Confidential)
        .unwrap()
        .into_data();
    assert!(parsed.exempt);
    assert_eq!(parsed.own_revision, Some(Revision::from(7)));
    assert_eq!(parsed.policy, None);
    assert_eq!(parsed.encode().unwrap(), compact);
    let mut deposit_only = exempt.clone();
    deposit_only.interface_transfers = vec![InterfaceTransfer::SolDeposit { amount: 2_500 }];
    assert_eq!(
        deposit_only.encode(),
        Err(CustomRingError::ExemptionWithoutWithdrawal)
    );
    let mut unrevised = exempt.clone();
    unrevised.own_revision = None;
    assert_eq!(unrevised.encode(), Err(CustomRingError::RingTransactLength));
    // The flag alone shifts every later field, the error varies.
    let mut claimed = fixture.confidential_delivered().encode().unwrap();
    claimed[transact_flag::BYTE] |= transact_flag::EXEMPT;
    assert!(RingTransactData::parse(&claimed, RingRail::Confidential).is_err());
    let mut delegate = fixture.delegate().encode().unwrap();
    delegate[transact_flag::BYTE] |= transact_flag::EXEMPT;
    assert_eq!(
        RingTransactData::parse(&delegate, RingRail::Delegate),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn a_mixed_anonymous_output_set_round_trips_and_frames_each_body() {
    let fixture = Fixture::new();
    let data = fixture.anonymous();
    let compact = data.encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Anonymous)
        .unwrap()
        .into_data();
    assert_eq!(parsed.outputs, data.outputs);
    assert_eq!(parsed.sender, data.sender);
    let framed = |scheme: u8, body: &[u8]| {
        Some(
            borsh::to_vec(&OutputDataEncoding::Encrypted(
                [&[scheme][..], body].concat(),
            ))
            .unwrap(),
        )
    };
    let expected = [
        ([0; 32], None),
        (
            fixture.tags[1],
            framed(RING_RECIPIENT_SCHEME_TAG, &fixture.recipient_body),
        ),
        (
            fixture.bytes[14],
            framed(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, &fixture.payload),
        ),
        (
            fixture.tags[3],
            framed(RING_RECIPIENT_SCHEME_TAG, &fixture.recipient_body),
        ),
    ];
    for (slot, (output, (owner_tag, data))) in parsed.outputs.iter().zip(expected).enumerate() {
        let spp = output.transact_output(&[]).unwrap();
        assert_eq!(spp.utxo_hash, fixture.fields[10 + slot], "slot {slot}");
        assert_eq!(spp.owner_tag, OwnerTag::Inline(owner_tag), "slot {slot}");
        assert_eq!(spp.data, data, "slot {slot}");
    }
}

fn tag_offset(data: &RingTransactData<'_>, compact: &[u8], slot: usize) -> usize {
    let hash = data.outputs[slot].hash();
    compact
        .windows(32)
        .position(|window| window == hash)
        .expect("the frame carries the hash")
        + 32
}

fn bundle_tag_offset(data: &RingTransactData<'_>, compact: &[u8]) -> usize {
    let tag = data.sender.unwrap().tag;
    compact
        .windows(32)
        .position(|window| window == tag)
        .expect("the frame carries the bundle tag")
}

#[test]
fn a_view_tag_at_or_above_the_modulus_is_refused() {
    let fixture = Fixture::new();
    let modulus = spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;
    let data = fixture.anonymous();
    let compact = data.encode().unwrap();
    for offset in [
        tag_offset(&data, &compact, 1),
        bundle_tag_offset(&data, &compact),
    ] {
        for tag in [modulus, [0xff; 32]] {
            let mut refused = compact.clone();
            refused[offset..offset + 32].copy_from_slice(&tag);
            assert_eq!(
                RingTransactData::parse(&refused, RingRail::Anonymous),
                Err(CustomRingError::ViewTagNotCanonical)
            );
        }
    }
    let mut slot = fixture.anonymous();
    slot.outputs[1] = RingOutput::Anonymous {
        hash: &fixture.fields[11],
        tag: &modulus,
        body: Some(&fixture.recipient_body),
        record: &fixture.ciphertexts[1],
    };
    assert_eq!(slot.encode(), Err(CustomRingError::ViewTagNotCanonical));
    let mut bundle = fixture.anonymous();
    bundle.sender = Some(FramedSenderBundle {
        tag: &modulus,
        body: data.sender.unwrap().body,
    });
    assert_eq!(bundle.encode(), Err(CustomRingError::ViewTagNotCanonical));
}

#[test]
fn a_change_slot_carries_a_zero_tag() {
    let fixture = Fixture::new();
    let data = fixture.anonymous();
    assert!(data.outputs[0].is_change());
    let compact = data.encode().unwrap();
    let offset = tag_offset(&data, &compact, 0);
    assert_eq!(compact[offset..offset + 32], [0; 32]);
    let mut refused = compact.clone();
    refused[offset + 31] = 1;
    assert_eq!(
        RingTransactData::parse(&refused, RingRail::Anonymous),
        Err(CustomRingError::ChangeTagNotZero)
    );
    let mut tagged = fixture.anonymous();
    tagged.outputs[0] = RingOutput::Anonymous {
        hash: &fixture.fields[10],
        tag: &fixture.tags[0],
        body: None,
        record: &fixture.ciphertexts[0],
    };
    assert_eq!(tagged.encode(), Err(CustomRingError::ChangeTagNotZero));
}

/// Scheme 3 reads the owner tag, the chain cell stays zero at any value.
#[test]
fn an_exit_keeps_its_owner_tag_unchecked() {
    let fixture = Fixture::new();
    let data = fixture.anonymous();
    assert!(!spr_hasher::primitives::is_canonical_bn254_scalar_be(
        data.outputs[2].owner_tag()
    ));
    assert_eq!(data.outputs[2].recipient_tag_cell(), &[0; 32]);
    let compact = data.encode().unwrap();
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Anonymous)
            .unwrap()
            .into_data(),
        data
    );
}

#[test]
fn the_sender_bundle_length_follows_the_output_count() {
    let fixture = Fixture::new();
    let mut data = fixture.anonymous();
    for len in [0, sender_bundle_len(3), sender_bundle_len(5)] {
        data.sender = Some(FramedSenderBundle {
            tag: &fixture.tags[0],
            body: &fixture.sender_body[..len],
        });
        assert_eq!(data.encode(), Err(CustomRingError::RingTransactLength));
    }
}

#[test]
fn the_sender_bundle_is_present_exactly_on_the_anonymous_rail() {
    let fixture = Fixture::new();
    let mut anonymous = fixture.anonymous();
    anonymous.sender = None;
    assert_eq!(anonymous.encode(), Err(CustomRingError::RingTransactLength));
    let mut unrevised = fixture.anonymous();
    unrevised.own_revision = None;
    assert_eq!(unrevised.encode(), Err(CustomRingError::RingTransactLength));
    let mut confidential = fixture.confidential_policy();
    confidential.sender = fixture.sender(2);
    assert_eq!(
        confidential.encode(),
        Err(CustomRingError::RingTransactLength)
    );
}

#[test]
fn bitmap_bits_past_the_count_are_refused() {
    let fixture = Fixture::new();
    let mut compact = fixture.confidential_policy().encode().unwrap();
    let tree_bitmap = compact.len() - 9;
    compact[tree_bitmap] |= 1 << 7;
    assert_eq!(
        RingTransactData::parse(&compact, RingRail::Confidential),
        Err(CustomRingError::InvalidInstructionData)
    );
}

#[test]
fn an_spp_point_off_the_curve_is_refused_at_expansion() {
    let fixture = Fixture::new();
    let off_curve = PlainGroth16Proof {
        proof_b: [0xff; 64],
        ..fixture.spp_proof
    };
    let mut data = fixture.delegate();
    data.spp_proof = &off_curve;
    let compact = data.encode().unwrap();
    let parsed = RingTransactData::parse(&compact, RingRail::Delegate).unwrap();
    assert_eq!(
        parsed.data().expand(&config()),
        Err(CustomRingError::InvalidSppProofPoint)
    );
}

#[test]
fn the_policy_proof_follows_the_ring_policy() {
    let fixture = Fixture::new();
    let policy = fixture.confidential_policy();
    let curator = Address::new_from_array([3; 32]);
    let mut ring_policy = config();
    let registry = |revision: u64, hash: u8| {
        let mut registry = StorageRegistry::new(Address::default(), &StorageInitialize::zeroed());
        registry.roots[0] = Root {
            hash: [hash; 32],
            revision: Revision::from(revision),
            expires_at: [0; 8],
        };
        registry
    };
    let (own, curated, replaced) = (registry(7, 7), registry(3, 3), registry(8, 8));
    let unpassed = LiveRoots {
        own: None,
        curator: None,
        slot: 0,
    };
    let live = LiveRoots {
        own: Some(&own),
        curator: Some(&curated),
        slot: 0,
    };
    assert_eq!(
        policy.roots(None, &live),
        Err(CustomRingError::UnexpectedPolicyProof)
    );
    assert_eq!(
        policy.roots(Some(&ring_policy), &live),
        Err(CustomRingError::FlagNotAllowed)
    );
    ring_policy.sources[0] = SourceSlot {
        list_id: ListId::Allow as u8,
        registry: curator,
    };
    let mut uncurated = policy.clone();
    uncurated.policy = uncurated.policy.map(|policy| PolicyProof {
        spl_withdrawal_owners: &[],
        curator_revision: None,
        ..policy
    });
    assert_eq!(
        uncurated.roots(Some(&ring_policy), &live),
        Err(CustomRingError::FlagNotAllowed)
    );
    assert_eq!(
        policy.roots(Some(&ring_policy), &live),
        Err(CustomRingError::PolicyNotSet)
    );
    ring_policy.policy_hash = [9; 32];
    assert_eq!(
        policy.roots(Some(&ring_policy), &unpassed),
        Err(CustomRingError::MissingRegistry)
    );
    assert_eq!(
        policy.roots(Some(&ring_policy), &live),
        Ok(TransferRoots {
            policy_hash: [9; 32],
            own_root: [7; 32],
            curator_root: [3; 32],
        })
    );
    assert_eq!(
        policy.roots(
            Some(&ring_policy),
            &LiveRoots {
                own: Some(&replaced),
                ..live
            }
        ),
        Err(CustomRingError::RootNotServed)
    );
    assert_eq!(
        fixture
            .confidential_delivered()
            .roots(Some(&ring_policy), &live),
        Err(CustomRingError::MissingPolicyProof)
    );
    assert_eq!(
        fixture.confidential_delivered().roots(None, &unpassed),
        Ok(TransferRoots::default())
    );
    assert_eq!(
        fixture.confidential_exempt().roots(None, &live),
        Ok(TransferRoots {
            own_root: [7; 32],
            ..TransferRoots::default()
        })
    );
    assert_eq!(
        fixture.confidential_exempt().roots(None, &unpassed),
        Err(CustomRingError::MissingRegistry)
    );
}

#[test]
fn every_rail_reads_its_audit_stream() {
    let fixture = Fixture::new();
    let confidential = |class| AuditKey::Confidential { class };
    for (data, key, key_escrow, inputs, outputs, exits) in [
        (
            fixture.confidential_policy(),
            confidential(24),
            true,
            2,
            2,
            0b10,
        ),
        (
            fixture.confidential_delivered(),
            confidential(16),
            false,
            1,
            8,
            0b100_1000,
        ),
        (
            fixture.confidential_in_proof_owner(),
            confidential(24),
            false,
            2,
            4,
            0b10,
        ),
        (fixture.delegate(), confidential(24), true, 2, 2, 0),
        (
            fixture.anonymous(),
            AuditKey::Anonymous(AnonymousAuditKey::Commitment { class: 16 }),
            false,
            3,
            4,
            0b100,
        ),
        (
            fixture.anonymous_entry(),
            AuditKey::Anonymous(AnonymousAuditKey::Entry { class: 8 }),
            false,
            2,
            2,
            0b10,
        ),
    ] {
        let expected = AuditStreamLayout {
            key,
            key_escrow,
            inputs,
            outputs,
            capacity: outputs,
            exits,
        };
        assert_eq!(data.audit_stream(), Ok(expected), "{key:?}");
        assert_eq!(expected.checked(), Ok(expected), "{key:?}");
        let compact = data.encode().unwrap();
        assert_eq!(
            RingTransactData::parse(&compact, data.rail)
                .unwrap()
                .audit_stream(),
            expected,
            "{key:?}"
        );
    }
    assert_eq!(
        delegate_delivered(&fixture).audit_stream(),
        Err(CustomRingError::RingShapeUnkeyed)
    );
}

fn encoded_cases(fixture: &Fixture) -> Vec<(&'static str, RingTransactData<'_>, Vec<u8>)> {
    fixture
        .cases()
        .into_iter()
        .map(|(name, data)| {
            let compact = data.encode().unwrap();
            (name, data, compact)
        })
        .collect()
}

#[test]
fn the_compact_data_reads_back_at_exact_capacity() {
    let fixture = Fixture::new();
    for (name, data, compact) in encoded_cases(&fixture) {
        assert_eq!(compact.capacity(), compact.len(), "{name}");
        let parsed = RingTransactData::parse(&compact, data.rail)
            .unwrap()
            .into_data();
        assert_eq!(parsed, data, "{name}");
    }
}

#[test]
fn a_truncated_or_appended_ciphertext_is_refused() {
    let fixture = Fixture::new();
    for (name, data, compact) in encoded_cases(&fixture) {
        let stream = data.audit_stream().unwrap();
        let envelope = stream.envelope().len;
        // The envelope and the records sit whole between eph_u and private_tx_hash.
        let start = compact
            .windows(data.eph_u.len())
            .position(|window| window == data.eph_u)
            .unwrap()
            + data.eph_u.len();
        let end = start + envelope + stream.records_len();
        assert_eq!(compact[start..start + envelope], *data.envelope, "{name}");
        assert_eq!(&compact[end..end + 32], data.private_tx_hash, "{name}");
        // A byte fewer or more shifts every later section.
        let mut truncated = compact.clone();
        truncated.remove(end - 1);
        let mut appended = compact.clone();
        appended.insert(end, 0x7a);
        for refused in [truncated, appended] {
            assert_eq!(
                RingTransactData::parse(&refused, data.rail),
                Err(CustomRingError::RingTransactLength),
                "{name}"
            );
        }
        for len in [envelope - 1, envelope + 1] {
            let mut resized = data.clone();
            resized.envelope = &fixture.envelope[..len];
            assert_eq!(
                resized.encode(),
                Err(CustomRingError::RingTransactLength),
                "{name}"
            );
        }
        let message = data.auditor_message();
        assert_eq!(message.len(), stream.message_len(), "{name}");
        let parsed = AuditorMessage::parse(&message, stream).unwrap();
        assert_eq!(parsed.envelope, data.envelope, "{name}");
        for (slot, output) in data.outputs.iter().enumerate() {
            assert_eq!(parsed.record(stream, slot), Some(output.record()), "{name}");
        }
        assert_eq!(
            AuditorMessage::parse(&message[..message.len() - 1], stream),
            None
        );
        let longer = [&message[..], &[0]].concat();
        assert_eq!(AuditorMessage::parse(&longer, stream), None);
        let mut untagged = message.clone();
        untagged[0] = 2;
        assert_eq!(AuditorMessage::parse(&untagged, stream), None);
    }
}

#[test]
fn a_slot_ciphertext_off_the_layout_is_refused_at_encoding() {
    let fixture = Fixture::new();
    let long = [0x11; 105];
    let mut delivered = fixture.confidential_delivered();
    delivered.outputs[0] = RingOutput::Delivered {
        hash: &fixture.fields[10],
        u: &fixture.bytes[3],
        body: &long[..72],
    };
    assert_eq!(delivered.encode(), Err(CustomRingError::RingTransactLength));
    let mut escrowed = fixture.confidential_policy();
    escrowed.outputs[0] = fixture.delivered(0);
    assert_eq!(escrowed.encode(), Err(CustomRingError::RingTransactLength));
    let mut record = fixture.anonymous();
    record.outputs[1] = RingOutput::Anonymous {
        hash: &fixture.fields[11],
        tag: &fixture.tags[1],
        body: None,
        record: &long,
    };
    assert_eq!(record.encode(), Err(CustomRingError::RingTransactLength));
    let mut exit = fixture.confidential_policy();
    exit.outputs[1] = fixture.exit(1, &fixture.payload);
    assert_eq!(exit.encode(), Err(CustomRingError::RingTransactLength));
}

#[test]
fn the_rail_follows_the_instruction_and_the_ring_mode() {
    use InstructionTag::{AuthorityTransfer, Transfer};
    let delegate = Address::new_from_array([0xd1; 32]);
    let ring = |mode: RingMode, has_policy: u8| {
        let mut config = config();
        config.mode = mode as u8;
        config.policy_hash = [has_policy; 32];
        if mode == RingMode::ConfidentialEscrow {
            config.delegate = delegate;
        }
        config
    };
    assert_eq!(
        RingRail::new(Transfer, &ring(RingMode::Confidential, 0)),
        Ok(RingRail::Confidential)
    );
    assert_eq!(
        RingRail::new(Transfer, &ring(RingMode::Anonymous, 1)),
        Ok(RingRail::Anonymous)
    );
    assert_eq!(
        RailSigner::new(AuthorityTransfer, &ring(RingMode::ConfidentialEscrow, 1)),
        Ok(RailSigner::Delegate(delegate))
    );
    assert_eq!(
        RingRail::new(AuthorityTransfer, &ring(RingMode::Anonymous, 1)),
        Err(CustomRingError::AnonymousRingRefused)
    );
    assert_eq!(
        RingRail::new(AuthorityTransfer, &ring(RingMode::Confidential, 1)),
        Err(CustomRingError::DelegateDisabled)
    );
    assert_eq!(
        RingRail::new(InstructionTag::Merge, &ring(RingMode::Confidential, 1)),
        Err(CustomRingError::InvalidInstructionData)
    );
    assert_eq!(
        RingRail::new(
            InstructionTag::HistoricalTransfer,
            &ring(RingMode::Anonymous, 1)
        ),
        Ok(RingRail::Anonymous)
    );
    assert_eq!(
        RingRail::new(
            InstructionTag::HistoricalAuthorityTransfer,
            &ring(RingMode::ConfidentialEscrow, 1)
        ),
        Ok(RingRail::Delegate)
    );
    let mut unknown = ring(RingMode::Confidential, 0);
    unknown.mode = RingMode::Anonymous as u8 + 1;
    assert_eq!(unknown.mode(), Err(CustomRingError::InvalidRingMode));
    assert_eq!(
        RingRail::new(Transfer, &unknown),
        Err(CustomRingError::InvalidRingMode)
    );
}

#[test]
fn the_in_proof_owner_proves_on_spp_anonymous_rail_under_the_sender_key() {
    let fixture = Fixture::new();
    let data = fixture.confidential_in_proof_owner();
    let CircuitId::AnonymousRingEddsa(2, 4, _, proof) = data.circuit() else {
        panic!("the in-proof owner proves on SPP's anonymous rail");
    };
    assert_eq!(proof.default_owner_tag, None);
    assert_eq!(proof.bsb22_commitment.commitment, fixture.bytes[20]);
    assert_eq!(
        data.transfer_circuit(1),
        Ok(RingCircuit::TransferConfidential {
            outputs: 4,
            inputs: 24,
            withdrawals: 4,
            owners: 4,
            data: false,
        })
    );
    assert_eq!(
        data.transfer_circuit(33),
        Err(CustomRingError::RingShapeUnkeyed)
    );
}

fn binding<'a>(
    fixture: &'a Fixture,
    config: &'a RingPolicy,
    roots: &'a TransferRoots,
    recipients: &'a [[u8; 32]],
    key_escrow: bool,
) -> TransferBinding<'a> {
    TransferBinding {
        ring_id: &fixture.fields[60],
        auditor_pubkey: &config.auditor_pubkey,
        key_escrow,
        sender: &fixture.fields[61],
        signers: SignerSet::default(),
        party_identities: &[[0; 32]; 3],
        recipients,
        roots,
        public_assets: &[[0; 32]; 3],
        public_amounts: &[[0; 32]; 3],
        public_gross: &[[0; 32]; 3],
        withdrawal_hash: &fixture.fields[62],
    }
}

#[test]
fn the_transfer_statement_reads_the_frame_and_names_its_family() {
    let fixture = Fixture::new();
    let config = config();
    let roots = TransferRoots::default();
    let parsed = ParsedTransact::new(fixture.anonymous()).unwrap();
    let data = parsed.data();
    let recipients = data.recipients();
    assert_eq!(recipients, vec![[0; 32]; 4]);
    let statement = parsed
        .transfer_statement(binding(&fixture, &config, &roots, &recipients, false))
        .unwrap();
    assert_eq!(statement.head.first_nullifier, &data.nullifiers[0]);
    assert_eq!(statement.head.salt, data.salt);
    assert_eq!(statement.head.layout.value(), 0);
    assert_eq!(statement.head.envelope, data.envelope);
    assert_eq!(statement.input_count, data.nullifiers.len());
    assert_eq!(statement.private_tx_hash, data.private_tx_hash);
    assert_eq!(statement.output_capacity, 4);
    assert_eq!(
        statement.family,
        TransferFamily::Anonymous {
            party_identities: &[[0; 32]; 3],
            sender: data.sender.unwrap(),
            replies: None,
        }
    );
    let delivered = ParsedTransact::new(fixture.confidential_delivered()).unwrap();
    let none = delivered.data().recipients();
    assert_eq!(none, vec![[0; 32]; 8]);
    assert_eq!(
        delivered
            .transfer_statement(binding(&fixture, &config, &roots, &none, false))
            .unwrap()
            .family,
        TransferFamily::Confidential {
            sender: ConfidentialSender::Signer,
            recipients: &none,
        }
    );
    let in_proof = ParsedTransact::new(fixture.confidential_in_proof_owner()).unwrap();
    let framed = in_proof.data().recipients();
    assert_eq!(framed, fixture.fields[50..54]);
    assert_eq!(
        in_proof.data().in_proof_sender(),
        Ok(Some(solana_owner_identity(&fixture.bytes[16]).unwrap()))
    );
    assert_eq!(
        in_proof
            .transfer_statement(binding(&fixture, &config, &roots, &framed, false))
            .unwrap()
            .family,
        TransferFamily::Confidential {
            sender: ConfidentialSender::InProof(&fixture.fields[61]),
            recipients: &framed,
        }
    );
    let delegate = ParsedTransact::new(fixture.delegate()).unwrap();
    let moved = delegate.data().recipients();
    assert_eq!(
        delegate
            .transfer_statement(binding(&fixture, &config, &roots, &moved, true))
            .unwrap()
            .family,
        TransferFamily::Confidential {
            sender: ConfidentialSender::Authority,
            recipients: &moved,
        }
    );
}

#[test]
fn a_key_escrow_flag_off_the_ring_mode_is_refused() {
    let fixture = Fixture::new();
    let config = config();
    let roots = TransferRoots::default();
    let statement = |data: &RingTransactData<'_>, key_escrow| {
        let recipients = data.recipients();
        ParsedTransact::new(data.clone())
            .unwrap()
            .transfer_statement(binding(&fixture, &config, &roots, &recipients, key_escrow))
            .map(|statement| statement.head.layout.value())
    };
    let escrowed = fixture.confidential_policy();
    assert_eq!(
        statement(&escrowed, false),
        Err(CustomRingError::FlagNotAllowed)
    );
    assert_eq!(statement(&escrowed, true), Ok(0b0010));
    assert_eq!(
        statement(&fixture.confidential_delivered(), true),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut anonymous = fixture.anonymous();
    anonymous.key_escrow = true;
    assert_eq!(
        statement(&fixture.with_audit_stream(anonymous), false),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut delegate = fixture.delegate();
    delegate.key_escrow = false;
    assert_eq!(
        statement(&fixture.with_audit_stream(delegate), true),
        Err(CustomRingError::FlagNotAllowed)
    );
}

#[test]
fn an_anonymous_ring_always_reads_its_own_records() {
    let mut anonymous = config();
    anonymous.mode = RingMode::Anonymous as u8;
    assert_eq!(RootRead::transfer(&anonymous, false), RootRead::Own);
    anonymous.policy_hash = [1; 32];
    assert_eq!(RootRead::transfer(&anonymous, false), RootRead::Policy);
    let audit_only = config();
    assert_eq!(RootRead::transfer(&audit_only, false), RootRead::None);
    assert_eq!(RootRead::transfer(&audit_only, true), RootRead::Own);
}

#[test]
fn withdrawal_owner_metadata_is_required_in_transfer_order() {
    let fixture = Fixture::new();
    let owners = [[0x61; 32], [0x62; 32]];
    let mut data = fixture.confidential_policy();
    data.interface_transfers = vec![
        InterfaceTransfer::SplWithdrawal {
            amount: 7,
            spl_interface_bump: 0,
        },
        InterfaceTransfer::SolDeposit { amount: 100 },
        InterfaceTransfer::SplWithdrawal {
            amount: 8,
            spl_interface_bump: 0,
        },
    ];
    assert!(data.encode().is_err());
    data.policy.as_mut().unwrap().spl_withdrawal_owners = &owners;
    let encoded = data.encode().unwrap();
    let parsed = RingTransactData::parse(&encoded, RingRail::Confidential).unwrap();
    assert_eq!(parsed.data().policy.unwrap().spl_withdrawal_owners, owners);
    assert_eq!(parsed.data().interface_transfers, data.interface_transfers);
    data.policy.as_mut().unwrap().spl_withdrawal_owners = &owners[..1];
    assert!(data.encode().is_err());
}
