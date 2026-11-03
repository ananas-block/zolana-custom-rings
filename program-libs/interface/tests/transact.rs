//! Pins `test-vectors/proof/ring-transact-expansion.json` for the TS SDK and the ring program tests.

mod frames;

use frames::{config, spp_b, Fixture};

use custom_ring_interface::{
    encode_anonymous_recipient_output, encode_anonymous_sender_output,
    ring_confidential_delivered_output_body, CONFIDENTIAL_DATA_FREE_BODY_LEN,
};
use custom_ring_interface::{
    input_flag,
    key_catalog::RingCircuit,
    shape_flag,
    storage::{Revision, Root, StorageRegistry},
    transact_flag, AnonymousAuditKey, AnonymousLayout, CustomRingError, DeliveredLayout,
    DisclosureLayout, InstructionTag, LiveRoots, ParsedTransact, PlainGroth16Proof, PolicyProof,
    RailSigner, RingMode, RingOutput, RingPolicy, RingRail, RingTransactData, SenderBundle,
    Settlement, SourceSlot, TransferBinding, TransferFamily, TransferRoots,
};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_event::{
    confidential_encrypted_output_body, OutputDataEncoding,
    ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG, ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG,
    CONFIDENTIAL_ENCRYPTED_SCHEME_TAG,
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
                      owner (bit 3), exempt (bit 4) and second tree flags, the one ring proof \
                      follows the header, the own registry revision under the policy or exempt \
                      flag, the curator revision under the curator flag and the recipients under \
                      the policy flag on a publishing rail. Byte 1 of the compact data indexes \
                      SPP_SUPPORTED_SHAPES below the default owner tag flag (bit 6), bit 7 refused. \
                      Byte 2 is the input count below the key escrow flag (bit 6) and the \
                      anonymous entry key flag (bit 7), the expiry is a u32, every rail \
                      publishes all n_out slots with no output count, exit payloads take 83 \
                      bytes without a u16 prefix, an anonymous slot is its hash, a 32-byte \
                      owner tag, a u16 little-endian length and the scheme 1 body, empty on \
                      a change output, the anonymous rail's scheme 2 sender bundle follows \
                      the outputs as a 32-byte tag, a nonzero u16 length and the body, and \
                      the random 16-byte salt follows the transaction viewing key. Under the \
                      in-proof owner flag (byte 0 bit 3) SPP proves the anonymous rail with no \
                      default owner tag, and the owner key, commitment and commitment pok \
                      follow private_tx_hash. Produced by \
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
                    encode_anonymous_sender_output(bundle.body).unwrap(),
                )
            })
            .collect();
        assert_eq!(sender, expected, "{}", case.name);
        for (output, slot) in spp.outputs.iter().zip(&data.outputs) {
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
                        body.map(|body| encode_anonymous_recipient_output(body).unwrap()),
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

#[test]
fn anonymous_and_exit_slots_keep_the_borsh_framing_at_exact_capacity() {
    let fixture = Fixture::new();
    let borsh_framing = |scheme: u8, payload: &[u8]| {
        borsh::to_vec(&OutputDataEncoding::Encrypted(
            [&[scheme][..], payload].concat(),
        ))
        .unwrap()
    };
    for (data, scheme, payload) in [
        (
            fixture.tagged(1).transact_output().unwrap().data.unwrap(),
            ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG,
            &fixture.recipient_body[..],
        ),
        (
            encode_anonymous_sender_output(&fixture.sender_body).unwrap(),
            ANONYMOUS_SENDER_ENCRYPTED_SCHEME_TAG,
            &fixture.sender_body[..],
        ),
        (
            fixture
                .exit(1, &fixture.payload)
                .transact_output()
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
fn a_delivered_rail_publishes_every_output_slot() {
    let fixture = Fixture::new();
    let mut data = fixture.confidential_delivered();
    data.outputs.pop();
    assert_eq!(data.encode(), Err(CustomRingError::RingTransactLength));
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
    let compact = fixture.with_disclosure(exit).encode().unwrap();
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
        (fixture.tags[0], None),
        (
            fixture.tags[1],
            framed(
                ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG,
                &fixture.recipient_body,
            ),
        ),
        (
            fixture.bytes[14],
            framed(CONFIDENTIAL_ENCRYPTED_SCHEME_TAG, &fixture.payload),
        ),
        (
            fixture.tags[3],
            framed(
                ANONYMOUS_RECIPIENT_ENCRYPTED_SCHEME_TAG,
                &fixture.recipient_body,
            ),
        ),
    ];
    for (slot, (output, (owner_tag, data))) in parsed.outputs.iter().zip(expected).enumerate() {
        let spp = output.transact_output().unwrap();
        assert_eq!(spp.utxo_hash, fixture.fields[10 + slot], "slot {slot}");
        assert_eq!(spp.owner_tag, OwnerTag::Inline(owner_tag), "slot {slot}");
        assert_eq!(spp.data, data, "slot {slot}");
    }
}

/// The offset of the anonymous slot frame that publishes `tag`, past its hash.
fn tag_offset(compact: &[u8], tag: &[u8; 32]) -> usize {
    compact
        .windows(32)
        .position(|window| window == tag)
        .expect("the frame carries the tag")
}

#[test]
fn an_anonymous_body_length_past_the_data_is_refused() {
    let fixture = Fixture::new();
    let compact = fixture.anonymous().encode().unwrap();
    let len = tag_offset(&compact, &fixture.tags[1]) + 32;
    assert_eq!(
        compact[len..len + 2],
        u16::try_from(fixture.recipient_body.len())
            .unwrap()
            .to_le_bytes()
    );
    let mut refused = compact.clone();
    refused[len..len + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(
        RingTransactData::parse(&refused, RingRail::Anonymous),
        Err(CustomRingError::RingTransactLength),
    );
}

#[test]
fn an_empty_sender_bundle_is_refused() {
    let fixture = Fixture::new();
    let compact = fixture.anonymous().encode().unwrap();
    let outputs_end =
        tag_offset(&compact, &fixture.tags[3]) + 32 + 2 + fixture.recipient_body.len();
    let len = outputs_end + 32;
    assert_eq!(compact[outputs_end..len], fixture.tags[0]);
    let mut refused = compact[..len].to_vec();
    refused.extend_from_slice(&0u16.to_le_bytes());
    refused.extend_from_slice(&compact[len + 2 + fixture.sender_body.len()..]);
    assert_eq!(
        RingTransactData::parse(&refused, RingRail::Anonymous),
        Err(CustomRingError::AnonymousBodyLength),
    );
}

#[test]
fn an_anonymous_body_the_frame_cannot_carry_is_refused_at_encoding() {
    let fixture = Fixture::new();
    let oversized = vec![0x11; usize::from(u16::MAX) + 1];
    for body in [&[][..], &oversized] {
        let mut data = fixture.anonymous();
        data.outputs[1] = RingOutput::Anonymous {
            hash: &fixture.fields[11],
            tag: &fixture.tags[1],
            body: Some(body),
        };
        assert_eq!(
            data.encode(),
            Err(CustomRingError::AnonymousBodyLength),
            "{} body bytes",
            body.len()
        );
        let mut data = fixture.anonymous();
        data.sender = Some(SenderBundle {
            tag: &fixture.tags[0],
            body,
        });
        assert_eq!(data.encode(), Err(CustomRingError::AnonymousBodyLength));
    }
}

#[test]
fn the_sender_bundle_is_present_exactly_on_the_anonymous_rail() {
    let fixture = Fixture::new();
    let mut anonymous = fixture.anonymous();
    anonymous.sender = None;
    assert_eq!(anonymous.encode(), Err(CustomRingError::RingTransactLength));
    let mut confidential = fixture.confidential_policy();
    confidential.sender = fixture.sender();
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
        let mut registry = StorageRegistry::new(Address::default(), 0);
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
fn every_rail_reads_its_disclosure_layout() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.confidential_policy().disclosure_layout(),
        Ok(DisclosureLayout::Delivered(DeliveredLayout {
            outputs: 2,
            exits: true,
            key_escrow: true,
        }))
    );
    assert_eq!(
        fixture.confidential_delivered().disclosure_layout(),
        Ok(DisclosureLayout::Delivered(DeliveredLayout {
            outputs: 8,
            exits: true,
            key_escrow: false,
        }))
    );
    assert_eq!(
        fixture.confidential_in_proof_owner().disclosure_layout(),
        Ok(DisclosureLayout::Delivered(DeliveredLayout {
            outputs: 4,
            exits: true,
            key_escrow: false,
        }))
    );
    assert_eq!(
        fixture.anonymous().disclosure_layout(),
        Ok(DisclosureLayout::Anonymous(AnonymousLayout {
            key: AnonymousAuditKey::Commitment { class: 16 },
            inputs: 3,
            outputs: 4,
            exits: true,
        }))
    );
    assert_eq!(
        fixture.anonymous_entry().disclosure_layout(),
        Ok(DisclosureLayout::Anonymous(AnonymousLayout {
            key: AnonymousAuditKey::Entry { class: 8 },
            inputs: 2,
            outputs: 2,
            exits: true,
        }))
    );
    assert_eq!(
        delegate_delivered(&fixture).disclosure_layout(),
        Err(CustomRingError::RingShapeUnkeyed)
    );
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
            withdrawals: 4
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
    assert_eq!(statement.head.layout.value(), 0b0001);
    assert_eq!(statement.disclosure, data.disclosure);
    assert_eq!(statement.private_tx_hash, data.private_tx_hash);
    assert_eq!(
        statement.family,
        TransferFamily::Anonymous {
            party_identities: &[[0; 32]; 3]
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
            in_proof: false,
            delegate: false,
            sender: &fixture.fields[61],
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
            in_proof: true,
            delegate: false,
            sender: &fixture.fields[61],
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
            in_proof: false,
            delegate: true,
            sender: &fixture.fields[61],
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
    assert_eq!(statement(&escrowed, true), Ok(0b0011));
    assert_eq!(
        statement(&fixture.confidential_delivered(), true),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut anonymous = fixture.anonymous();
    anonymous.key_escrow = true;
    assert_eq!(
        statement(&fixture.with_disclosure(anonymous), false),
        Err(CustomRingError::FlagNotAllowed)
    );
    let mut delegate = fixture.delegate();
    delegate.key_escrow = false;
    assert_eq!(
        statement(&fixture.with_disclosure(delegate), true),
        Err(CustomRingError::FlagNotAllowed)
    );
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
