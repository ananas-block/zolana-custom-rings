//! Gate items 1 to 4 as far as a failing proof reaches, no row shows a frame settling.

use custom_ring_interface::{
    frame_digest,
    key_catalog::{TransferShape, ANONYMOUS_TRANSFER_SHAPES, CONFIDENTIAL_TRANSFER_SHAPES},
    settled_frame, tag, AnonymousProofData, CoSignScope, CreateFrameBufferIxData, CustomRingError,
    FrameBuffer, FrameBufferHeader, PlainGroth16Proof, Replies, RingPolicy, RingRail,
    RingTransactData, RootRead, FRAME_BUFFER_HEADER_LEN, MAX_FRAME_LEN, MIN_REPLY_LEN,
};
use solana_address::Address;
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_message::{v1, VersionedMessage};
use solana_transaction_error::TransactionError;
use spr_interface::{
    error::ShieldedPoolError,
    instruction::{CircuitId, InputUtxo, InterfaceTransfer, TreeContext},
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    state::{
        discriminator::TREE_ACCOUNT_DISCRIMINATOR, RingConfig, NULLIFIER_PDA_SEED, STATE_HEIGHT,
    },
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use spr_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule};

use crate::{
    buffer_rules::{settle_instruction, transfer_accounts, transfer_frame, Buffer, EXPIRY},
    common::{
        deployed, on_curve_g2, policy_pda, reaches_verification, refused, ring_auth, set_co_signer,
        CoSignerSlot, Ring, SentWithMeta, Setup, PROGRAM, RECORDS, SYSTEM,
    },
    transact_rules::{spp_list, Fixture, SPP},
};

const CPI_DATA_CEILING: usize = 10 * 1024;
const TRANSACTION_ADDRESSES: usize = v1::MAX_ADDRESSES as usize;
const MAX_SIGNATURES: usize = v1::MAX_SIGNATURES as usize;
const DATA_TOO_LARGE: &str = "Invoked an instruction with data that is too large";

fn funded(ring: &mut Ring) -> Keypair {
    let wallet = Keypair::new();
    ring.svm()
        .airdrop(&wallet.pubkey(), 100_000_000_000)
        .expect("fund the wallet");
    wallet
}

/// Decompresses and fails the pairing, the pairing syscall still runs.
fn failing_spp_proof() -> PlainGroth16Proof {
    PlainGroth16Proof {
        proof_a: [0; 32],
        proof_b: alt_bn128_g2_compress_be(&on_curve_g2()).unwrap(),
        proof_c: [0; 32],
    }
}

fn logs_refuse_size(sent: &SentWithMeta) -> bool {
    sent.as_ref().err().is_some_and(|failed| {
        failed
            .meta
            .logs
            .iter()
            .any(|line| line.contains(DATA_TOO_LARGE))
    })
}

/// The ring's bump allocator peak from `just build-ring-heap-report`, `None` without that build.
fn ring_heap_peak(ring: &mut Ring, instruction: &Instruction) -> Option<u64> {
    let report = std::panic::catch_unwind(|| deployed("ring_heap_report.so")).ok()?;
    ring.svm()
        .add_program(PROGRAM, &report)
        .expect("load the heap report");
    let sent = ring.send_with_meta(instruction.clone(), &[]);
    let meta = match &sent {
        Ok(meta) => meta,
        Err(failed) => &failed.meta,
    };
    Some(u64::from_le_bytes(
        meta.return_data
            .data
            .as_slice()
            .try_into()
            .expect("the peak"),
    ))
}

/// A sealed buffer the program never wrote, for lengths its create refuses.
fn store_sealed(ring: &mut Ring, frame: &[u8], rent_payer: Address) -> Address {
    let create = CreateFrameBufferIxData {
        nonce: 0,
        digest: frame_digest(frame).unwrap(),
        length: 1,
        expiry_unix_ts: EXPIRY,
    };
    let header = FrameBufferHeader::new(&create, rent_payer, rent_payer).unwrap();
    let mut data = bytemuck::bytes_of(&header).to_vec();
    data[1] = 1;
    data[2..4].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    data.extend_from_slice(frame);
    assert!(FrameBuffer::of(&data).is_ok());
    let address = Address::new_unique();
    ring.store(address, PROGRAM, data);
    address
}

#[test]
fn gate_1_the_event_cpi_stops_at_the_runtime_ceiling() {
    for (frame_len, fits) in [
        (MAX_FRAME_LEN, true),
        (CPI_DATA_CEILING - 1, true),
        (CPI_DATA_CEILING, false),
    ] {
        let mut ring = Ring::new(Setup::Policy);
        let payer = ring.payer.pubkey();
        let mut frame = vec![0; frame_len];
        frame[0] = tag::TRANSFER;
        let buffer = store_sealed(&mut ring, &frame, payer);
        let policy: RingPolicy = ring.read(&policy_pda());
        let inner = [
            vec![AccountMeta::new_readonly(policy_pda(), false)],
            ring.registries(RootRead::transfer(&policy, false)),
            vec![AccountMeta::new(ring_auth(), false)],
        ]
        .concat();
        let settle = settle_instruction(
            buffer,
            payer,
            &frame_digest(&frame).unwrap(),
            tag::TRANSFER,
            inner,
        );
        let sent = ring.send_with_meta(settle, &[]);
        let failed = sent.as_ref().expect_err("a zero frame fails to parse");
        if fits {
            let event = &failed.meta.inner_instructions[0][0];
            assert_eq!(event.instruction.data.len(), frame_len + 1);
            assert!(!logs_refuse_size(&sent));
        } else {
            assert!(logs_refuse_size(&sent));
        }
        println!(
            "GATE1 event measured frame={frame_len} cpi_data={} fits={fits} units={}",
            frame_len + 1,
            failed.meta.compute_units_consumed,
        );
    }
}

#[test]
fn gate_1_a_cpi_create_stops_at_the_frame_buffer_ceiling() {
    for (space, fits) in [
        (MAX_FRAME_LEN + FRAME_BUFFER_HEADER_LEN, true),
        (CPI_DATA_CEILING + 1, false),
    ] {
        let mut ring = Ring::new(Setup::Policy);
        ring.svm()
            .add_program(PROGRAM, &deployed("ring_gate_probe.so"))
            .expect("load the probe");
        let target = Address::find_program_address(&[b"grow"], &PROGRAM).0;
        let grow = Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(ring.payer.pubkey(), true),
                AccountMeta::new(target, false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: [vec![1], (space as u64).to_le_bytes().to_vec()].concat(),
        };
        let sent = ring.send(grow, &[]);
        println!("GATE1 create measured space={space} fits={fits} sent={sent:?}");
        assert_eq!(sent.is_ok(), fits);
    }
}

struct SppPath {
    ring: Ring,
    tree: Address,
}

impl SppPath {
    fn new(setup: Setup) -> Self {
        let mut ring = Ring::new(setup);
        ring.svm()
            .add_program(PROGRAM, &deployed("ring_gate_probe.so"))
            .expect("load the probe");
        let mut config: RingConfig = ring.read(&ring_auth());
        config.activated = 1;
        ring.store(ring_auth(), SPP, bytemuck::bytes_of(&config).to_vec());
        let tree = Address::new_unique();
        let mut data = vec![0; TreeAccount::account_size()];
        TreeAccount::init(
            &mut data,
            TREE_ACCOUNT_DISCRIMINATOR,
            STATE_HEIGHT as u8,
            tree.to_bytes(),
            1,
            NullifierTreeInitParams::default(),
            TreeFeeSchedule {
                fee_per_nullifier: 0,
                append_reimbursement: 0,
                close_reimbursement: 0,
            },
        )
        .expect("init the tree");
        ring.store(tree, SPP, data);
        ring.svm()
            .airdrop(&tree, 100_000_000_000)
            .expect("fund the tree");
        Self { ring, tree }
    }

    fn accounts(&self, nullifiers: &[[u8; 32]]) -> Vec<AccountMeta> {
        let payer = self.ring.payer.pubkey();
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(self.tree, false),
            AccountMeta::new_readonly(SPP, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new(ring_auth(), false),
            AccountMeta::new(self.tree, false),
        ];
        accounts.extend(nullifiers.iter().map(|nullifier| {
            let pda = Address::find_program_address(
                &[NULLIFIER_PDA_SEED, self.tree.as_ref(), nullifier],
                &SPP,
            )
            .0;
            AccountMeta::new(pda, false)
        }));
        accounts
    }

    fn forward(&mut self, payload: Vec<u8>, spp: Vec<AccountMeta>) -> Instruction {
        let account = Address::new_unique();
        self.ring.store(account, Address::new_unique(), payload);
        let mut accounts = vec![AccountMeta::new_readonly(account, false)];
        accounts.extend(spp);
        Instruction {
            program_id: PROGRAM,
            accounts,
            data: [vec![0], SHIELDED_POOL_PROGRAM_ID.to_vec()].concat(),
        }
    }
}

#[test]
fn gate_1_a_full_size_cpi_enters_spp_and_a_larger_one_never_does() {
    for (len, fits) in [(CPI_DATA_CEILING, true), (CPI_DATA_CEILING + 1, false)] {
        let mut path = SppPath::new(Setup::Policy);
        let spp = path.accounts(&[]);
        let mut payload = vec![0xff; len];
        payload[0] = spr_interface::instruction::tag::RING_TRANSACT;
        let forward = path.forward(payload, spp);
        let sent = path.ring.send_with_meta(forward, &[]);
        assert_eq!(logs_refuse_size(&sent), !fits);
        let failed = sent.as_ref().expect_err("no frame parses from filler");
        println!(
            "GATE1 spp_ceiling measured data={len} entered_spp={fits} err={:?} units={}",
            failed.err, failed.meta.compute_units_consumed
        );
    }
}

/// The reply length filling the one recipient slot to `target` expanded bytes.
fn reply_len_for(fixture: &Fixture, policy: &RingPolicy, target: usize) -> usize {
    let filled = |len: usize, region: &[u8]| {
        let mut data = fixture.transfer(RingRail::Anonymous, 1, 2, false);
        data.replies = Some(Replies {
            len: len as u16,
            region,
        });
        data.spp_instruction_data(policy).unwrap().len()
    };
    let region = vec![0x11; MIN_REPLY_LEN + target];
    let base = filled(MIN_REPLY_LEN, &region[..MIN_REPLY_LEN]);
    MIN_REPLY_LEN + target - base
}

struct Row {
    name: String,
    frame: Vec<u8>,
    inner: Vec<AccountMeta>,
    spp_bytes: usize,
}

fn zero_anonymous<'a>(data: &mut RingTransactData<'a>, zero: &'a [u8; 32]) {
    if data.anonymous.is_some() {
        data.anonymous = Some(AnonymousProofData {
            commitment: zero,
            commitment_pok: zero,
            default_owner_tag: None,
        });
    }
}

fn shapes(family: &[TransferShape]) -> Vec<(u8, u8)> {
    family
        .iter()
        .flat_map(|shape| [(1, shape.outputs), (shape.inputs, shape.outputs)])
        .collect()
}

fn run_row(ring: &mut Ring, row: Row) {
    let writer = ring.payer.insecure_clone();
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &writer,
        nonce: 1,
    };
    let seal_units = buffer.seal(ring, &row.frame);
    let digest = frame_digest(&row.frame).unwrap();
    let settle = buffer.settle(&digest, tag::TRANSFER, row.inner.clone());
    let buffered = reaches_verification(ring.send(settle.clone(), &[]));
    let inline = Instruction {
        program_id: PROGRAM,
        accounts: row.inner,
        data: row.frame.clone(),
    };
    let inline_units = match ring.send(inline, &[]) {
        Err((TransactionError::InstructionError(..), units)) => Some(units),
        _ => None,
    };
    let heap = ring_heap_peak(ring, &settle);
    println!(
        "GATE1 ring_path measured {} frame={} spp_data={} seal_write_units={seal_units} buffered_units_through_pairing={buffered} inline_units_through_pairing={inline_units:?} ring_heap_bytes_through_pairing={heap:?}",
        row.name,
        row.frame.len(),
        row.spp_bytes,
    );
}

#[test]
fn gate_1_keyed_frames_reach_the_ring_pairing_from_a_buffer() {
    let proof = failing_spp_proof();
    let zero = [0; 32];
    let fixture = Fixture::new().with_identity_proof();
    let families = [
        (
            Setup::Policy,
            RingRail::Confidential,
            true,
            shapes(&CONFIDENTIAL_TRANSFER_SHAPES),
        ),
        (
            Setup::AnonymousPolicy,
            RingRail::Anonymous,
            true,
            shapes(&ANONYMOUS_TRANSFER_SHAPES),
        ),
    ];
    for (setup, rail, policy, cases) in families {
        for (inputs, outputs) in cases {
            let mut ring = Ring::new(setup);
            let mut data = fixture.transfer(rail, inputs, outputs, policy);
            data.spp_proof = &proof;
            zero_anonymous(&mut data, &zero);
            let ring_policy: RingPolicy = ring.read(&policy_pda());
            let row = Row {
                name: format!("{rail} {inputs}x{outputs} policy={policy}"),
                frame: transfer_frame(&data),
                inner: transfer_accounts(&ring, &data),
                spp_bytes: data.spp_instruction_data(&ring_policy).unwrap().len(),
            };
            run_row(&mut ring, row);
        }
    }
}

#[test]
fn gate_1_the_widest_buffer_reaches_the_ring_pairing() {
    let proof = failing_spp_proof();
    let zero = [0; 32];
    let fixture = Fixture::new().with_identity_proof();
    let mut ring = Ring::new(Setup::Anonymous);
    let policy: RingPolicy = ring.read(&policy_pda());
    let frame_len = |reply: usize, region: &[u8]| {
        let mut data = fixture.transfer(RingRail::Anonymous, 1, 2, false);
        data.replies = Some(Replies {
            len: reply as u16,
            region,
        });
        transfer_frame(&data).len()
    };
    let filler = vec![0x11; MAX_FRAME_LEN];
    let base = frame_len(MIN_REPLY_LEN, &filler[..MIN_REPLY_LEN]);
    let reply = MIN_REPLY_LEN + MAX_FRAME_LEN - base;
    let mut data = fixture.transfer(RingRail::Anonymous, 1, 2, false);
    data.replies = Some(Replies {
        len: reply as u16,
        region: &filler[..reply],
    });
    data.spp_proof = &proof;
    zero_anonymous(&mut data, &zero);
    let frame = transfer_frame(&data);
    assert_eq!(frame.len(), MAX_FRAME_LEN);
    let row = Row {
        name: "anonymous 1x2 widest buffer".into(),
        inner: transfer_accounts(&ring, &data),
        spp_bytes: data.spp_instruction_data(&policy).unwrap().len(),
        frame,
    };
    assert!(row.spp_bytes <= CPI_DATA_CEILING, "{}", row.spp_bytes);
    run_row(&mut ring, row);
}

/// The rows stop at SPP's first pairing, its transfers and event stay unrun.
#[test]
fn gate_1_spp_reaches_its_pairing_on_the_expanded_frames() {
    let proof = failing_spp_proof();
    let zero = [0; 32];
    let fixture = Fixture::new().with_identity_proof();
    let context = TreeContext {
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
    };
    let run = |name: String, payload: Vec<u8>, nullifiers: &[[u8; 32]], setup: Setup| {
        let mut path = SppPath::new(setup);
        let spp = path.accounts(nullifiers);
        let forward = path.forward(payload.clone(), spp);
        let sent = path.ring.send_with_meta(forward, &[]);
        let (err, units, trace) = match &sent {
            Ok(meta) => (None, meta.compute_units_consumed, &meta.inner_instructions),
            Err(failed) => (
                Some(failed.err.clone()),
                failed.meta.compute_units_consumed,
                &failed.meta.inner_instructions,
            ),
        };
        let trace = trace.iter().map(Vec::len).sum::<usize>();
        assert_eq!(
            err,
            Some(TransactionError::InstructionError(
                0,
                InstructionError::Custom(ShieldedPoolError::TransactProofVerificationFailed as u32),
            )),
            "{name}"
        );
        println!(
            "GATE1 spp_path measured {name} spp_data={} units_through_spp_pairing={units} default_heap inner_instructions={trace}",
            payload.len(),
        );
    };
    for (setup, rail, cases) in [
        (
            Setup::Policy,
            RingRail::Confidential,
            shapes(&CONFIDENTIAL_TRANSFER_SHAPES),
        ),
        (
            Setup::Anonymous,
            RingRail::Anonymous,
            shapes(&ANONYMOUS_TRANSFER_SHAPES),
        ),
    ] {
        for (inputs, outputs) in cases {
            let ring = Ring::new(setup);
            let policy: RingPolicy = ring.read(&policy_pda());
            let mut data = fixture.transfer(rail, inputs, outputs, false);
            data.spp_proof = &proof;
            data.input_trees = custom_ring_interface::InputTrees::One(context);
            zero_anonymous(&mut data, &zero);
            run(
                format!("{rail} {inputs}x{outputs}"),
                data.spp_instruction_data(&policy).unwrap(),
                data.nullifiers,
                setup,
            );
        }
    }
    // No ring key serves 49 inputs, the row starts at the expansion.
    let ring = Ring::new(Setup::Policy);
    let policy: RingPolicy = ring.read(&policy_pda());
    let mut data = fixture.transfer(RingRail::Confidential, 24, 2, false);
    data.spp_proof = &proof;
    data.input_trees = custom_ring_interface::InputTrees::One(context);
    let nullifiers: Vec<[u8; 32]> = (1..=49u8)
        .map(|index| {
            let mut nullifier = [index; 32];
            nullifier[0] = 0x0e;
            nullifier
        })
        .collect();
    let mut expanded = data.expand(&policy).unwrap();
    expanded.inputs = nullifiers
        .iter()
        .map(|nullifier| InputUtxo {
            nullifier_hash: *nullifier,
            tree_index: 0,
        })
        .collect();
    expanded.circuit = CircuitId::ConfidentialRingEddsa(49, 2, N_PUBLIC_SLOTS as u8);
    run(
        "confidential 49x2 past the catalog".into(),
        [
            vec![RingRail::Confidential.spp_tag()],
            expanded.serialize().unwrap(),
        ]
        .concat(),
        &nullifiers,
        Setup::Policy,
    );

    let ring = Ring::new(Setup::Anonymous);
    let policy: RingPolicy = ring.read(&policy_pda());
    let reply = reply_len_for(&fixture, &policy, CPI_DATA_CEILING);
    let region = vec![0x11; reply];
    let mut data = fixture.transfer(RingRail::Anonymous, 1, 2, false);
    data.replies = Some(Replies {
        len: reply as u16,
        region: &region,
    });
    data.spp_proof = &proof;
    data.input_trees = custom_ring_interface::InputTrees::One(context);
    zero_anonymous(&mut data, &zero);
    let payload = data.spp_instruction_data(&policy).unwrap();
    assert_eq!(payload.len(), CPI_DATA_CEILING);
    run(
        "anonymous 1x2 at the data ceiling".into(),
        payload,
        data.nullifiers,
        Setup::Anonymous,
    );
}

/// The contract's bound, modelled.
fn owner_capacity(inputs: usize, buffered: bool, co_signers: usize, leg_accounts: usize) -> i64 {
    const RING_ACCOUNTS: i64 = 6;
    let buffer = if buffered { 2 } else { 0 };
    TRANSACTION_ADDRESSES as i64
        - 4
        - inputs as i64
        - RING_ACCOUNTS
        - buffer
        - 2 * co_signers as i64
        - leg_accounts as i64
}

#[test]
fn gate_2_the_widest_message_holds_64_addresses_and_reaches_the_pairing() {
    let mut inputs: Vec<usize> = SPP_SUPPORTED_SHAPES.iter().map(Shape::n_inputs).collect();
    inputs.sort_unstable();
    inputs.dedup();
    for n_in in inputs {
        println!(
            "GATE2 modelled inputs={n_in} owners_inline={} owners_buffered={} owners_buffered_cosigner={} owners_buffered_cosigner_sol_leg={}",
            owner_capacity(n_in, false, 0, 0),
            owner_capacity(n_in, true, 0, 0),
            owner_capacity(n_in, true, 1, 0),
            owner_capacity(n_in, true, 1, 2),
        );
    }

    for (legs, owners) in [(8, 10), (9, 9), (8, 11), (9, 10)] {
        let outcome = widest_message(legs, owners);
        println!("GATE2 measured confidential 24x2 cosigner=1 buffer+rent_payer=2 sol_legs={legs} owners={owners} {outcome:?}");
        if outcome.addresses > TRANSACTION_ADDRESSES || outcome.signatures > MAX_SIGNATURES {
            assert_eq!(
                outcome.sent.map_err(|(error, _)| error),
                Err(TransactionError::SanitizeFailure)
            );
        } else {
            assert!(outcome.bytes <= v1::MAX_TRANSACTION_SIZE);
            reaches_verification(outcome.sent);
        }
    }
}

#[derive(Debug)]
struct WidestMessage {
    addresses: usize,
    signatures: usize,
    bytes: usize,
    sent: crate::common::Sent,
}

fn widest_message(legs: u64, owner_count: usize) -> WidestMessage {
    let fixture = Fixture::new().with_identity_proof();
    let proof = failing_spp_proof();
    let mut data = fixture.transfer(RingRail::Confidential, 24, 2, true);
    data.spp_proof = &proof;
    data.interface_transfers = (0..legs)
        .map(|leg| InterfaceTransfer::SolWithdrawal { amount: 1 + leg })
        .collect();
    let frame = transfer_frame(&data);
    let digest = frame_digest(&frame).unwrap();

    let mut ring = Ring::new(Setup::Policy);
    let co_signer = Keypair::new();
    set_co_signer(
        &mut ring,
        &co_signer.pubkey(),
        CoSignScope::TRANSFERS.bits(),
    );
    let writer = funded(&mut ring);
    let rent_payer = funded(&mut ring);
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &rent_payer,
        nonce: 1,
    };
    buffer.seal(&mut ring, &frame);

    let owners: Vec<Keypair> = (0..owner_count).map(|_| Keypair::new()).collect();
    let metas: Vec<AccountMeta> = owners
        .iter()
        .map(|owner| AccountMeta::new_readonly(owner.pubkey(), true))
        .collect();
    let payer = ring.payer.pubkey();
    let mut spp = spp_list(&payer, &data, &metas);
    for _ in 0..data.interface_transfers.len() {
        spp.push(AccountMeta::new(Address::new_unique(), false));
        spp.push(AccountMeta::new(Address::new_unique(), false));
    }
    let inner = [
        vec![AccountMeta::new_readonly(policy_pda(), false)],
        vec![AccountMeta::new_readonly(RECORDS, false)],
        CoSignerSlot::own(co_signer.pubkey()).signed(),
        spp,
    ]
    .concat();
    let settle = buffer.settle(&digest, tag::TRANSFER, inner);
    let message = v1::Message::try_compile_with_config(
        &payer,
        core::slice::from_ref(&settle),
        ring.svm().latest_blockhash(),
        v1::TransactionConfig::empty()
            .with_compute_unit_limit(1_400_000)
            .with_loaded_accounts_data_size_limit(64 * 1024 * 1024),
    )
    .expect("the compiler sets no address ceiling");
    let signatures = usize::from(message.header.num_required_signatures);
    let bytes = VersionedMessage::V1(message.clone()).serialize().len() + 64 * signatures;
    let mut signers: Vec<&Keypair> = owners.iter().collect();
    signers.push(&co_signer);
    let sent = ring.send(settle, &signers);
    WidestMessage {
        addresses: message.account_keys.len(),
        signatures,
        bytes,
        sent,
    }
}

#[test]
fn gate_3_the_frame_rebuilds_from_the_transaction_alone() {
    let proof = failing_spp_proof();
    let zero = [0; 32];
    let fixture = Fixture::new().with_identity_proof();
    for (setup, rail, inputs, outputs) in [
        (Setup::Policy, RingRail::Confidential, 5, 16),
        (Setup::AnonymousPolicy, RingRail::Anonymous, 5, 8),
    ] {
        let mut ring = Ring::new(setup);
        let policy: RingPolicy = ring.read(&policy_pda());
        let mut data = fixture.transfer(rail, inputs, outputs, true);
        data.spp_proof = &proof;
        zero_anonymous(&mut data, &zero);
        let frame = transfer_frame(&data);
        let inner = transfer_accounts(&ring, &data);
        let payer = ring.payer.insecure_clone();
        let buffer = Buffer {
            writer: &payer,
            rent_payer: &payer,
            nonce: 1,
        };
        buffer.seal(&mut ring, &frame);
        let digest = frame_digest(&frame).unwrap();
        let settle = buffer.settle(&digest, tag::TRANSFER, inner);
        let failed = ring
            .send_with_meta(settle.clone(), &[])
            .expect_err("the failing proof stops at the pairing");
        assert_eq!(
            failed.err,
            TransactionError::InstructionError(
                0,
                InstructionError::Custom(CustomRingError::ProofVerificationFailed as u32),
            )
        );

        ring.drain(&buffer.address());
        let event = &failed.meta.inner_instructions[0][0];
        assert_eq!(event.stack_height, 2);
        let read = settled_frame(&settle.data, &event.instruction.data).unwrap();
        assert_eq!(read, frame);
        let parsed = RingTransactData::parse(&read[1..], rail).unwrap();
        let rebuilt = parsed.data();
        assert_eq!(rebuilt.encode().unwrap(), data.encode().unwrap());
        assert_eq!(rebuilt.auditor_message(), data.auditor_message());
        assert_eq!(rebuilt.nullifiers, data.nullifiers);
        assert_eq!(
            rebuilt.spp_instruction_data(&policy).unwrap(),
            data.spp_instruction_data(&policy).unwrap()
        );
        let mut forged = settle.data.clone();
        forged[1] ^= 1;
        assert_eq!(
            settled_frame(&forged, &event.instruction.data),
            Err(CustomRingError::InvalidFrameEvent)
        );
        println!(
            "GATE3 measured {rail} {inputs}x{outputs} event_data={} rebuilt_frame_equal=true buffer_lamports={}",
            event.instruction.data.len(),
            ring.lamports(&buffer.address()),
        );
    }
}

#[test]
fn gate_4_a_buffer_changed_after_the_fetch_fails_the_signed_digest() {
    let fixture = Fixture::new().with_identity_proof();
    let proof = failing_spp_proof();
    let mut frame_a = fixture.transfer(RingRail::Confidential, 2, 2, true);
    frame_a.spp_proof = &proof;
    let mut frame_b = fixture.transfer(RingRail::Confidential, 2, 2, true);
    frame_b.spp_proof = &proof;
    frame_b.expiry_unix_ts += 1;

    let mut ring = Ring::new(Setup::Policy);
    let co_signer = Keypair::new();
    set_co_signer(
        &mut ring,
        &co_signer.pubkey(),
        CoSignScope::TRANSFERS.bits(),
    );
    let writer = funded(&mut ring);
    let rent_payer = funded(&mut ring);
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &rent_payer,
        nonce: 1,
    };
    let bytes_a = transfer_frame(&frame_a);
    let bytes_b = transfer_frame(&frame_b);
    let digest_a = frame_digest(&bytes_a).unwrap();
    let digest_b = frame_digest(&bytes_b).unwrap();
    let inner = |ring: &Ring, data: &RingTransactData<'_>| {
        let policy: RingPolicy = ring.read(&policy_pda());
        [
            vec![AccountMeta::new_readonly(policy_pda(), false)],
            ring.registries(RootRead::transfer(&policy, false)),
            CoSignerSlot::own(co_signer.pubkey()).signed(),
            spp_list(
                &ring.payer.pubkey(),
                data,
                &[AccountMeta::new_readonly(ring.payer.pubkey(), true)],
            ),
        ]
        .concat()
    };

    buffer
        .create(&mut ring, digest_a, bytes_a.len() as u16)
        .unwrap();
    let fetch = |ring: &mut Ring| {
        let account = ring.svm().get_account(&buffer.address()).unwrap();
        (account.owner, account.data)
    };
    let (owner, data) = fetch(&mut ring);
    assert_eq!(
        FrameBuffer::inspect(&owner, &PROGRAM, &data, &digest_a),
        Err(CustomRingError::FrameBufferNotSealed)
    );
    buffer.write(&mut ring, 0, true, &bytes_a).unwrap();

    let (owner, data) = fetch(&mut ring);
    let inspected = FrameBuffer::inspect(&owner, &PROGRAM, &data, &digest_a).unwrap();
    assert_eq!(
        RingTransactData::parse(&inspected[1..], RingRail::Confidential)
            .unwrap()
            .data()
            .expiry_unix_ts,
        frame_a.expiry_unix_ts
    );
    let signed_over_a = buffer.settle(&digest_a, tag::TRANSFER, inner(&ring, &frame_a));

    // Sealed bytes change only through a close and a new create at the address.
    refused(
        buffer.write(&mut ring, 0, false, &bytes_b),
        CustomRingError::FrameBufferSealed,
    );
    buffer.close(&mut ring, &writer).unwrap();
    buffer.seal(&mut ring, &bytes_b);

    refused(
        ring.send(signed_over_a, &[&co_signer]),
        CustomRingError::FrameDigestMismatch,
    );
    let (owner, data) = fetch(&mut ring);
    assert_eq!(
        FrameBuffer::inspect(&owner, &PROGRAM, &data, &digest_a),
        Err(CustomRingError::FrameDigestMismatch)
    );
    let signed_over_b = buffer.settle(&digest_b, tag::TRANSFER, inner(&ring, &frame_b));
    reaches_verification(ring.send(signed_over_b, &[&co_signer]));
    println!("GATE4 measured signature over A refused after rewrite to B, signature over B reaches the pairing");
}
