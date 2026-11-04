use std::collections::HashSet;

use custom_ring_interface::{
    frame_digest, settle_buffered_data, tag, CustomRingError, FrameBufferHeader, RecipientBody,
    RingPolicy, RingRail, RingTransactData, RootRead, SettledFrame, SlotBody, WriteFrameIxData,
    CONFIDENTIAL_DATA_FREE_BODY_LEN, DATA_TAIL_LEN, FRAME_BUFFER_PDA_SEED, MAX_FRAME_LEN,
};
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_transaction_error::TransactionError;
use spr_interface::instruction::InterfaceTransfer;

use crate::{
    common::{delegate_ring, policy_pda, refused, Ring, SentWithMeta, Setup, PROGRAM, SYSTEM},
    transact_rules::{spp_list, Fixture},
};

const CHUNK: usize = 3_000;
const NONCE: u64 = 7;
/// The widest shape the catalog keys.
const INPUTS: u8 = 5;
const OUTPUTS: u8 = 16;
const LEGS: usize = 8;

fn buffer_of(writer: &Address) -> Address {
    Address::find_program_address(
        &[FRAME_BUFFER_PDA_SEED, writer.as_ref(), &NONCE.to_le_bytes()],
        &PROGRAM,
    )
    .0
}

fn write(
    ring: &mut Ring,
    writer: &Keypair,
    frame_len: u16,
    offset: u16,
    bytes: &[u8],
) -> crate::common::Sent {
    let instruction = Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new(writer.pubkey(), true),
            AccountMeta::new(buffer_of(&writer.pubkey()), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
        data: WriteFrameIxData {
            nonce: NONCE,
            frame_len,
            offset,
            bytes,
        }
        .encode(),
    };
    ring.send(instruction, &[writer])
}

fn write_all(ring: &mut Ring, frame: &[u8]) -> u64 {
    let writer = ring.payer.insecure_clone();
    let frame_len = u16::try_from(frame.len()).unwrap();
    frame
        .chunks(CHUNK)
        .enumerate()
        .map(|(index, bytes)| {
            let offset = u16::try_from(index * CHUNK).unwrap();
            write(ring, &writer, frame_len, offset, bytes).expect("write the frame")
        })
        .sum()
}

fn settle_data(frame: &[u8]) -> Vec<u8> {
    settle_buffered_data(&frame_digest(frame).unwrap())
}

fn settle(
    ring: &mut Ring,
    data: Vec<u8>,
    inline: Vec<AccountMeta>,
    signers: &[&Keypair],
) -> SentWithMeta {
    let buffer = buffer_of(&ring.payer.pubkey());
    let mut accounts = vec![
        AccountMeta::new(buffer, false),
        AccountMeta::new_readonly(PROGRAM, false),
    ];
    accounts.extend(inline);
    ring.send_with_meta(
        Instruction {
            program_id: PROGRAM,
            accounts,
            data,
        },
        signers,
    )
}

/// The compiled count with the buffer and the invoked program.
fn unique_accounts(accounts: &[AccountMeta]) -> usize {
    accounts
        .iter()
        .map(|meta| meta.pubkey)
        .chain([PROGRAM, Address::new_from_array([0xbf; 32])])
        .collect::<HashSet<_>>()
        .len()
}

fn swap_key(accounts: &[AccountMeta], from: &Address, to: &Address) -> Vec<AccountMeta> {
    accounts
        .iter()
        .map(|meta| AccountMeta {
            pubkey: if meta.pubkey == *from {
                *to
            } else {
                meta.pubkey
            },
            ..meta.clone()
        })
        .collect()
}

fn custom_code(sent: &SentWithMeta) -> Option<u32> {
    match sent {
        Err(failed) => match failed.err {
            TransactionError::InstructionError(_, InstructionError::Custom(code)) => Some(code),
            _ => None,
        },
        Ok(_) => None,
    }
}

struct BufferedFrame {
    bytes: Vec<u8>,
    accounts: Vec<AccountMeta>,
}

fn largest_frame(ring: &mut Ring) -> BufferedFrame {
    let fixture = Fixture::new().with_identity_proof();
    let body = RecipientBody {
        ring_data_hash: Some([0x5a; 32]),
        ..RecipientBody::default()
    }
    .encode();
    let exit = [0x66; CONFIDENTIAL_DATA_FREE_BODY_LEN + 33];
    let tail = [0x7b; DATA_TAIL_LEN];
    let mut data = fixture.transfer(RingRail::Anonymous, INPUTS, OUTPUTS, true);
    data.has_data = true;
    data.interface_transfers = (0..LEGS as u64)
        .map(|leg| InterfaceTransfer::SolWithdrawal {
            amount: 1_000 + leg,
        })
        .collect();
    let last = data.outputs.len() - 1;
    for (slot, output) in data.outputs.iter_mut().enumerate() {
        output.tail = Some(&tail);
        output.body = match slot == last {
            true => SlotBody::Exit(&exit),
            false => SlotBody::Recipient(&body),
        };
    }
    fixture.fit_stream(&mut data);
    let payer = ring.payer.pubkey();
    let mut spp = spp_list(&payer, &data, &[]);
    let pool = AccountMeta::new(Address::new_unique(), false);
    let destination = AccountMeta::new(Address::new_unique(), false);
    for _ in 0..LEGS {
        spp.extend([pool.clone(), destination.clone()]);
    }
    let policy: RingPolicy = ring.read(&policy_pda());
    BufferedFrame {
        bytes: [vec![tag::TRANSFER], data.encode().unwrap()].concat(),
        accounts: [
            vec![AccountMeta::new_readonly(policy_pda(), false)],
            ring.registries(RootRead::transfer(&policy, false)),
            spp,
        ]
        .concat(),
    }
}

#[test]
fn the_largest_keyed_frame_clears_every_check_ahead_of_the_key_and_its_event_decodes() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let frame = largest_frame(&mut ring);
    let write_units = write_all(&mut ring, &frame.bytes);
    let data = settle_data(&frame.bytes);
    let failed = settle(&mut ring, data.clone(), frame.accounts.clone(), &[]).unwrap_err();
    // Without its verifying key the frame stops at the lookup.
    assert!(
        matches!(
            failed.err,
            TransactionError::InstructionError(0, InstructionError::Custom(code))
                if code == CustomRingError::UnsupportedCircuit as u32
        ),
        "{:?}",
        failed.err
    );
    let event = failed.meta.inner_instructions[0]
        .first()
        .expect("the frame event ahead of the proof");
    let settled = |succeeded| SettledFrame {
        ring_program: &PROGRAM,
        settle_program: &PROGRAM,
        event_program: &PROGRAM,
        succeeded,
        settle: &data,
        event: &event.instruction.data,
    };
    assert!(settled(false).frame().is_err());
    // Reader decoding only, the transaction failed and nothing settled.
    let rebuilt = settled(true).frame().unwrap();
    assert_eq!(rebuilt, frame.bytes);
    RingTransactData::parse(&rebuilt[1..], RingRail::Anonymous).unwrap();
    println!(
        "frame {} B, {} accounts, writes {write_units} CU, settle to the key lookup {} CU, heap report {:?}",
        frame.bytes.len(),
        unique_accounts(&frame.accounts),
        failed.meta.compute_units_consumed,
        failed.meta.return_data.data,
    );
}

#[test]
fn a_rewritten_buffer_fails_the_signed_digest() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let frame = largest_frame(&mut ring);
    write_all(&mut ring, &frame.bytes);
    let writer = ring.payer.insecure_clone();
    let frame_len = u16::try_from(frame.bytes.len()).unwrap();
    write(&mut ring, &writer, frame_len, 40, &[0xee]).unwrap();
    let sent = settle(&mut ring, settle_data(&frame.bytes), frame.accounts, &[]);
    assert_eq!(
        custom_code(&sent),
        Some(CustomRingError::FrameDigestMismatch as u32)
    );
}

#[test]
fn a_settlement_whose_payer_is_not_the_writer_is_refused() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let frame = largest_frame(&mut ring);
    write_all(&mut ring, &frame.bytes);
    let other = Keypair::new();
    let inline = swap_key(&frame.accounts, &ring.payer.pubkey(), &other.pubkey());
    let sent = settle(&mut ring, settle_data(&frame.bytes), inline, &[&other]);
    assert_eq!(
        custom_code(&sent),
        Some(CustomRingError::FramePayerNotWriter as u32)
    );
}

#[test]
fn only_the_writer_writes_and_closes_and_a_closed_buffer_does_not_settle() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let writer = ring.payer.insecure_clone();
    let buffer = buffer_of(&writer.pubkey());
    write(&mut ring, &writer, 16, 0, &[tag::TRANSFER]).unwrap();
    let other = Keypair::new();
    let foreign_write = Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new(other.pubkey(), true),
            AccountMeta::new(buffer, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
        data: WriteFrameIxData {
            nonce: NONCE,
            frame_len: 16,
            offset: 0,
            bytes: &[9],
        }
        .encode(),
    };
    refused(
        ring.send(foreign_write, &[&other]),
        CustomRingError::UnauthorizedFrameWriter,
    );
    let rent_recipient = Address::new_unique();
    let close = |closer: &Address| Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new_readonly(*closer, true),
            AccountMeta::new(buffer, false),
            AccountMeta::new(rent_recipient, false),
        ],
        data: vec![tag::CLOSE_FRAME_BUFFER],
    };
    refused(
        ring.send(close(&other.pubkey()), &[&other]),
        CustomRingError::UnauthorizedFrameWriter,
    );
    let rent = ring.lamports(&buffer);
    assert!(rent > 0);
    ring.send(close(&writer.pubkey()), &[]).unwrap();
    assert_eq!(ring.lamports(&buffer), 0);
    assert_eq!(ring.lamports(&rent_recipient), rent);
    let sent = settle(&mut ring, settle_data(&[tag::TRANSFER]), Vec::new(), &[]);
    assert_eq!(
        custom_code(&sent),
        Some(CustomRingError::InvalidFrameBuffer as u32)
    );
}

#[test]
fn an_empty_frame_and_a_write_outside_the_frame_are_refused() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let writer = ring.payer.insecure_clone();
    refused(
        write(&mut ring, &writer, 0, 0, &[]),
        CustomRingError::FrameLength,
    );
    refused(
        write(&mut ring, &writer, 4, 3, &[1, 2]),
        CustomRingError::FrameWriteOutOfRange,
    );
}

#[test]
fn a_frame_of_another_tag_does_not_settle_from_a_buffer() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let writer = ring.payer.insecure_clone();
    let frame = [tag::MERGE, 1, 2, 3];
    write(&mut ring, &writer, 4, 0, &frame).unwrap();
    let sent = settle(&mut ring, settle_data(&frame), Vec::new(), &[]);
    assert_eq!(
        custom_code(&sent),
        Some(CustomRingError::UnsupportedBufferedTag as u32)
    );
}

#[test]
fn a_synthetic_frame_of_10206_bytes_reaches_the_parser_and_one_more_byte_is_refused() {
    assert_eq!(MAX_FRAME_LEN, 10_206);
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let writer = ring.payer.insecure_clone();
    refused(
        write(&mut ring, &writer, 10_207, 0, &[]),
        CustomRingError::FrameLength,
    );
    assert_eq!(ring.lamports(&buffer_of(&writer.pubkey())), 0);
    let mut frame = vec![0u8; 10_206];
    frame[0] = tag::TRANSFER;
    write_all(&mut ring, &frame);
    let policy: RingPolicy = ring.read(&policy_pda());
    let inline = [
        vec![AccountMeta::new_readonly(policy_pda(), false)],
        ring.registries(RootRead::transfer(&policy, false)),
    ]
    .concat();
    let failed = settle(&mut ring, settle_data(&frame), inline, &[]).unwrap_err();
    assert_eq!(
        failed.meta.inner_instructions[0][0].instruction.data.len(),
        10_207
    );
    assert!(
        matches!(
            failed.err,
            TransactionError::InstructionError(0, InstructionError::Custom(code))
                if code == CustomRingError::OutputCountOutOfRange as u32
        ),
        "{:?}",
        failed.err
    );
    println!(
        "ceiling frame to the parser {} CU",
        failed.meta.compute_units_consumed
    );
}

fn delegate_frame(ring: &mut Ring, delegate: &Keypair) -> BufferedFrame {
    let fixture = Fixture::new().with_identity_proof();
    let data = fixture.transfer(RingRail::Delegate, 2, 2, false);
    let policy: RingPolicy = ring.read(&policy_pda());
    BufferedFrame {
        bytes: [vec![tag::AUTHORITY_TRANSFER], data.encode().unwrap()].concat(),
        accounts: [
            vec![AccountMeta::new_readonly(policy_pda(), false)],
            ring.registries(RootRead::transfer(&policy, true)),
            vec![AccountMeta::new_readonly(delegate.pubkey(), true)],
            spp_list(&ring.payer.pubkey(), &data, &[]),
        ]
        .concat(),
    }
}

#[test]
fn an_authority_frame_clears_every_check_ahead_of_the_key_and_its_event_decodes() {
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let frame = delegate_frame(&mut ring, &delegate);
    write_all(&mut ring, &frame.bytes);
    let data = settle_data(&frame.bytes);
    let failed = settle(&mut ring, data.clone(), frame.accounts, &[&delegate]).unwrap_err();
    assert!(
        matches!(
            failed.err,
            TransactionError::InstructionError(0, InstructionError::Custom(code))
                if code == CustomRingError::UnsupportedCircuit as u32
        ),
        "{:?}",
        failed.err
    );
    let event = &failed.meta.inner_instructions[0][0].instruction.data;
    // Reader decoding only, the transaction failed and nothing settled.
    let rebuilt = SettledFrame {
        ring_program: &PROGRAM,
        settle_program: &PROGRAM,
        event_program: &PROGRAM,
        succeeded: true,
        settle: &data,
        event,
    }
    .frame()
    .unwrap();
    assert_eq!(rebuilt, frame.bytes);
    RingTransactData::parse(&rebuilt[1..], RingRail::Delegate).unwrap();
}

#[test]
fn a_rewritten_authority_frame_fails_the_signed_digest() {
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let frame = delegate_frame(&mut ring, &delegate);
    write_all(&mut ring, &frame.bytes);
    let writer = ring.payer.insecure_clone();
    let frame_len = u16::try_from(frame.bytes.len()).unwrap();
    write(&mut ring, &writer, frame_len, 40, &[0xee]).unwrap();
    let sent = settle(
        &mut ring,
        settle_data(&frame.bytes),
        frame.accounts,
        &[&delegate],
    );
    assert_eq!(
        custom_code(&sent),
        Some(CustomRingError::FrameDigestMismatch as u32)
    );
}

#[test]
fn an_authority_settlement_whose_payer_is_not_the_writer_is_refused() {
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let frame = delegate_frame(&mut ring, &delegate);
    write_all(&mut ring, &frame.bytes);
    let other = Keypair::new();
    let inline = swap_key(&frame.accounts, &ring.payer.pubkey(), &other.pubkey());
    let sent = settle(
        &mut ring,
        settle_data(&frame.bytes),
        inline,
        &[&delegate, &other],
    );
    assert_eq!(
        custom_code(&sent),
        Some(CustomRingError::FramePayerNotWriter as u32)
    );
}

#[test]
fn an_authority_frame_the_delegate_did_not_sign_is_refused() {
    let delegate = Keypair::new();
    let mut ring = delegate_ring(&delegate);
    let frame = delegate_frame(&mut ring, &delegate);
    write_all(&mut ring, &frame.bytes);
    let other = Keypair::new();
    let inline = swap_key(&frame.accounts, &delegate.pubkey(), &other.pubkey());
    let sent = settle(&mut ring, settle_data(&frame.bytes), inline, &[&other]);
    assert_eq!(
        custom_code(&sent),
        Some(CustomRingError::UnauthorizedDelegate as u32)
    );
    let unsigned = frame
        .accounts
        .iter()
        .map(|meta| match meta.pubkey == delegate.pubkey() {
            true => AccountMeta::new_readonly(meta.pubkey, false),
            false => meta.clone(),
        })
        .collect();
    let sent = settle(&mut ring, settle_data(&frame.bytes), unsigned, &[]);
    assert_eq!(
        custom_code(&sent),
        Some(CustomRingError::UnauthorizedDelegate as u32)
    );
}

#[test]
fn a_close_without_the_writers_signature_is_refused() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let writer = Address::new_unique();
    let buffer = Address::new_unique();
    ring.store(
        buffer,
        PROGRAM,
        bytemuck::bytes_of(&FrameBufferHeader::new(writer)).to_vec(),
    );
    let unsigned = Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new_readonly(writer, false),
            AccountMeta::new(buffer, false),
            AccountMeta::new(Address::new_unique(), false),
        ],
        data: vec![tag::CLOSE_FRAME_BUFFER],
    };
    refused(
        ring.send(unsigned, &[]),
        CustomRingError::UnauthorizedFrameWriter,
    );
}

#[test]
fn a_write_away_from_the_canonical_address_or_to_another_account_is_refused() {
    let mut ring = Ring::new(Setup::AnonymousPolicy);
    let writer = ring.payer.insecure_clone();
    let write_to = |buffer| Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new(writer.pubkey(), true),
            AccountMeta::new(buffer, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
        data: WriteFrameIxData {
            nonce: NONCE,
            frame_len: 16,
            offset: 0,
            bytes: &[9],
        }
        .encode(),
    };
    for buffer in [Address::new_unique(), policy_pda()] {
        refused(
            ring.send(write_to(buffer), &[]),
            CustomRingError::InvalidFrameBuffer,
        );
    }
}
