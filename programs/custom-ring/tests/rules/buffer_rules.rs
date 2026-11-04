//! Frame buffer refusals ahead of the ring pairing.

use custom_ring_interface::{
    frame_digest, tag, CreateFrameBufferIxData, CustomRingError, RingPolicy, RingRail,
    RingTransactData, RootRead, SettleBufferedIxData, WriteFrameIxData, FRAME_BUFFER_PDA_SEED,
    MAX_FRAME_LEN,
};
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use spr_interface::instruction::instruction_data::merge_ring::MergeRingAuthority;

use crate::{
    common::{policy_pda, reaches_verification, refused, Ring, Sent, Setup, PROGRAM, SYSTEM},
    merge_rules::{merge_data, merge_instruction},
    transact_rules::{spp_list, Fixture},
};

pub const EXPIRY: u32 = 1_800_000_000;
const WRITE_CHUNK: usize = 3_000;

pub fn buffer_address(writer: &Address, nonce: u64) -> Address {
    Address::find_program_address(
        &[FRAME_BUFFER_PDA_SEED, writer.as_ref(), &nonce.to_le_bytes()],
        &PROGRAM,
    )
    .0
}

fn tagged(tag: u8, body: Vec<u8>) -> Vec<u8> {
    [vec![tag], body].concat()
}

pub struct Buffer<'a> {
    pub writer: &'a Keypair,
    pub rent_payer: &'a Keypair,
    pub nonce: u64,
}

impl Buffer<'_> {
    pub fn address(&self) -> Address {
        buffer_address(&self.writer.pubkey(), self.nonce)
    }

    pub fn create(&self, ring: &mut Ring, digest: [u8; 32], length: u16) -> Sent {
        let instruction = Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.rent_payer.pubkey(), true),
                AccountMeta::new_readonly(self.writer.pubkey(), true),
                AccountMeta::new(self.address(), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: tagged(
                tag::CREATE_FRAME_BUFFER,
                CreateFrameBufferIxData {
                    nonce: self.nonce,
                    digest,
                    length,
                    expiry_unix_ts: EXPIRY,
                }
                .encode(),
            ),
        };
        ring.send(instruction, &[self.rent_payer, self.writer])
    }

    pub fn write(&self, ring: &mut Ring, offset: u16, seal: bool, bytes: &[u8]) -> Sent {
        let instruction =
            write_instruction(&self.writer.pubkey(), self.address(), offset, seal, bytes);
        ring.send(instruction, &[self.writer])
    }

    /// Returns the sealing write's units.
    pub fn seal(&self, ring: &mut Ring, frame: &[u8]) -> u64 {
        self.create(ring, frame_digest(frame).unwrap(), frame.len() as u16)
            .expect("create the buffer");
        let chunks: Vec<&[u8]> = frame.chunks(WRITE_CHUNK).collect();
        let mut units = 0;
        for (index, chunk) in chunks.iter().enumerate() {
            units = self
                .write(
                    ring,
                    (index * WRITE_CHUNK) as u16,
                    index + 1 == chunks.len(),
                    chunk,
                )
                .expect("write the frame");
        }
        units
    }

    pub fn close(&self, ring: &mut Ring, closer: &Keypair) -> Sent {
        let instruction =
            close_instruction(&closer.pubkey(), self.address(), self.rent_payer.pubkey());
        ring.send(instruction, &[closer])
    }

    pub fn settle(&self, digest: &[u8; 32], inner_tag: u8, inner: Vec<AccountMeta>) -> Instruction {
        settle_instruction(
            self.address(),
            self.rent_payer.pubkey(),
            digest,
            inner_tag,
            inner,
        )
    }
}

fn write_instruction(
    writer: &Address,
    buffer: Address,
    offset: u16,
    seal: bool,
    bytes: &[u8],
) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new_readonly(*writer, true),
            AccountMeta::new(buffer, false),
        ],
        data: tagged(
            tag::WRITE_FRAME,
            WriteFrameIxData {
                offset,
                seal,
                bytes,
            }
            .encode(),
        ),
    }
}

fn close_instruction(closer: &Address, buffer: Address, rent_payer: Address) -> Instruction {
    Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new_readonly(*closer, true),
            AccountMeta::new(buffer, false),
            AccountMeta::new(rent_payer, false),
        ],
        data: vec![tag::CLOSE_FRAME_BUFFER],
    }
}

pub fn settle_instruction(
    buffer: Address,
    rent_payer: Address,
    digest: &[u8; 32],
    inner_tag: u8,
    inner: Vec<AccountMeta>,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(buffer, false),
        AccountMeta::new(rent_payer, false),
        AccountMeta::new_readonly(PROGRAM, false),
    ];
    accounts.extend(inner);
    Instruction {
        program_id: PROGRAM,
        accounts,
        data: tagged(
            tag::SETTLE_BUFFERED,
            SettleBufferedIxData {
                digest,
                buffer: buffer.as_array(),
                inner_tag,
            }
            .encode(),
        ),
    }
}

pub fn transfer_accounts(ring: &Ring, data: &RingTransactData<'_>) -> Vec<AccountMeta> {
    let payer = ring.payer.pubkey();
    let owners = match data.rail {
        RingRail::Anonymous => Vec::new(),
        _ => vec![AccountMeta::new_readonly(payer, true)],
    };
    let policy: RingPolicy = ring.read(&policy_pda());
    [
        vec![AccountMeta::new_readonly(policy_pda(), false)],
        ring.registries(RootRead::transfer(&policy, false)),
        spp_list(&payer, data, &owners),
    ]
    .concat()
}

pub fn transfer_frame(data: &RingTransactData<'_>) -> Vec<u8> {
    [vec![tag::TRANSFER], data.encode().unwrap()].concat()
}

fn past_expiry(ring: &mut Ring) {
    let mut clock: Clock = ring.svm().get_sysvar();
    clock.unix_timestamp = i64::from(EXPIRY);
    ring.svm().set_sysvar(&clock);
}

fn funded(ring: &mut Ring) -> Keypair {
    let wallet = Keypair::new();
    ring.svm()
        .airdrop(&wallet.pubkey(), 10_000_000_000)
        .expect("fund the wallet");
    wallet
}

struct Sealed {
    frame: Vec<u8>,
    inner: Vec<AccountMeta>,
    digest: [u8; 32],
}

fn sealed(ring: &mut Ring, buffer: &Buffer<'_>) -> Sealed {
    let fixture = Fixture::new();
    let data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    let frame = transfer_frame(&data);
    let inner = transfer_accounts(ring, &data);
    buffer.seal(ring, &frame);
    let digest = frame_digest(&frame).unwrap();
    Sealed {
        frame,
        inner,
        digest,
    }
}

#[test]
fn creation_binds_the_address_to_the_signing_writer() {
    let mut ring = Ring::new(Setup::Policy);
    let writer = funded(&mut ring);
    let rent_payer = funded(&mut ring);
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &rent_payer,
        nonce: 1,
    };
    let mut squat = Instruction {
        program_id: PROGRAM,
        accounts: vec![
            AccountMeta::new(rent_payer.pubkey(), true),
            AccountMeta::new_readonly(rent_payer.pubkey(), true),
            AccountMeta::new(buffer.address(), false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
        data: tagged(
            tag::CREATE_FRAME_BUFFER,
            CreateFrameBufferIxData {
                nonce: 1,
                digest: [1; 32],
                length: 8,
                expiry_unix_ts: EXPIRY,
            }
            .encode(),
        ),
    };
    refused(
        ring.send(squat.clone(), &[&rent_payer]),
        CustomRingError::FrameBufferAddress,
    );
    squat.accounts[1] = AccountMeta::new_readonly(writer.pubkey(), false);
    assert!(ring.send(squat, &[&rent_payer]).is_err());

    refused(
        buffer.create(&mut ring, [1; 32], 0),
        CustomRingError::FrameLength,
    );
    refused(
        buffer.create(&mut ring, [1; 32], MAX_FRAME_LEN as u16 + 1),
        CustomRingError::FrameLength,
    );
    buffer
        .create(&mut ring, [1; 32], MAX_FRAME_LEN as u16)
        .expect("the widest frame creates");
    refused(
        buffer.create(&mut ring, [2; 32], 8),
        CustomRingError::FrameBufferExists,
    );
}

#[test]
fn a_stranger_writes_nothing_and_a_sealed_frame_takes_no_write() {
    let mut ring = Ring::new(Setup::Policy);
    let writer = funded(&mut ring);
    let rent_payer = funded(&mut ring);
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &rent_payer,
        nonce: 1,
    };
    let frame = [tag::TRANSFER, 2, 3, 4];
    buffer
        .create(&mut ring, frame_digest(&frame).unwrap(), 4)
        .unwrap();
    let stranger = funded(&mut ring);
    let by_stranger = write_instruction(&stranger.pubkey(), buffer.address(), 0, false, &frame);
    refused(
        ring.send(by_stranger, &[&stranger]),
        CustomRingError::UnauthorizedFrameWriter,
    );
    refused(
        buffer.write(&mut ring, 0, true, &frame[..2]),
        CustomRingError::FrameDigestMismatch,
    );
    refused(
        buffer.write(&mut ring, 3, false, &frame[..2]),
        CustomRingError::FrameWriteOutOfRange,
    );
    buffer.write(&mut ring, 0, false, &frame[..2]).unwrap();
    buffer.write(&mut ring, 2, true, &frame[2..]).unwrap();
    refused(
        buffer.write(&mut ring, 0, false, &frame),
        CustomRingError::FrameBufferSealed,
    );
}

#[test]
fn rent_returns_to_the_payer_whoever_closes() {
    let mut ring = Ring::new(Setup::Policy);
    let writer = funded(&mut ring);
    let rent_payer = funded(&mut ring);
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &rent_payer,
        nonce: 1,
    };
    buffer.create(&mut ring, [1; 32], 64).unwrap();
    let rent = ring.lamports(&buffer.address());
    let before = ring.lamports(&rent_payer.pubkey());

    let closer = funded(&mut ring);
    refused(
        buffer.close(&mut ring, &closer),
        CustomRingError::UnauthorizedFrameCloser,
    );
    let wrong_recipient = close_instruction(&writer.pubkey(), buffer.address(), closer.pubkey());
    refused(
        ring.send(wrong_recipient, &[&writer]),
        CustomRingError::FrameRentPayer,
    );

    past_expiry(&mut ring);
    let closer_before = ring.lamports(&closer.pubkey());
    buffer.close(&mut ring, &closer).unwrap();
    assert_eq!(ring.lamports(&rent_payer.pubkey()), before + rent);
    assert_eq!(ring.lamports(&closer.pubkey()), closer_before);
    assert_eq!(ring.lamports(&buffer.address()), 0);
}

#[test]
fn the_writer_closes_before_expiry() {
    let mut ring = Ring::new(Setup::Policy);
    let writer = funded(&mut ring);
    let rent_payer = funded(&mut ring);
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &rent_payer,
        nonce: 1,
    };
    let sealed = sealed(&mut ring, &buffer);
    buffer.close(&mut ring, &writer).unwrap();
    refused(
        ring.send(
            buffer.settle(&sealed.digest, tag::TRANSFER, sealed.inner),
            &[],
        ),
        CustomRingError::InvalidFrameBuffer,
    );
}

#[test]
fn settlement_refuses_each_buffer_mismatch_ahead_of_the_proof() {
    let mut ring = Ring::new(Setup::Policy);
    let writer = funded(&mut ring);
    let rent_payer = funded(&mut ring);
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &rent_payer,
        nonce: 1,
    };
    let Sealed {
        frame,
        inner,
        digest,
    } = sealed(&mut ring, &buffer);

    refused(
        ring.send(buffer.settle(&[9; 32], tag::TRANSFER, inner.clone()), &[]),
        CustomRingError::FrameDigestMismatch,
    );
    refused(
        ring.send(buffer.settle(&digest, tag::MERGE, inner.clone()), &[]),
        CustomRingError::FrameTagMismatch,
    );
    refused(
        ring.send(
            buffer.settle(&digest, tag::UPDATE_POLICY, inner.clone()),
            &[],
        ),
        CustomRingError::UnsupportedBufferedTag,
    );
    refused(
        ring.send(
            buffer.settle(&digest, tag::SETTLE_BUFFERED, inner.clone()),
            &[],
        ),
        CustomRingError::UnsupportedBufferedTag,
    );
    let wrong_payer = settle_instruction(
        buffer.address(),
        writer.pubkey(),
        &digest,
        tag::TRANSFER,
        inner.clone(),
    );
    refused(ring.send(wrong_payer, &[]), CustomRingError::FrameRentPayer);
    let mut named_other = buffer.settle(&digest, tag::TRANSFER, inner.clone());
    named_other.data[33..65].copy_from_slice(&[7; 32]);
    refused(
        ring.send(named_other, &[]),
        CustomRingError::FrameBufferMismatch,
    );
    reaches_verification(ring.send(buffer.settle(&digest, tag::TRANSFER, inner.clone()), &[]));
    assert_eq!(frame.first(), Some(&tag::TRANSFER));

    past_expiry(&mut ring);
    refused(
        ring.send(buffer.settle(&digest, tag::TRANSFER, inner), &[]),
        CustomRingError::FrameBufferExpired,
    );
}

#[test]
fn a_partial_frame_does_not_settle() {
    let mut ring = Ring::new(Setup::Policy);
    let writer = funded(&mut ring);
    let rent_payer = funded(&mut ring);
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &rent_payer,
        nonce: 1,
    };
    let fixture = Fixture::new();
    let data = fixture.transfer(RingRail::Confidential, 2, 2, true);
    let frame = transfer_frame(&data);
    let digest = frame_digest(&frame).unwrap();
    buffer
        .create(&mut ring, digest, frame.len() as u16)
        .unwrap();
    buffer.write(&mut ring, 0, false, &frame[..100]).unwrap();
    let inner = transfer_accounts(&ring, &data);
    refused(
        ring.send(buffer.settle(&digest, tag::TRANSFER, inner), &[]),
        CustomRingError::FrameBufferNotSealed,
    );
}

#[test]
fn only_the_ring_pda_signs_a_frame_event() {
    let mut ring = Ring::new(Setup::Policy);
    let forger = funded(&mut ring);
    let event = Instruction {
        program_id: PROGRAM,
        accounts: vec![AccountMeta::new_readonly(forger.pubkey(), true)],
        data: vec![tag::FRAME_EVENT, tag::TRANSFER],
    };
    refused(
        ring.send(event, &[&forger]),
        CustomRingError::InvalidFrameEvent,
    );
    let unsigned = Instruction {
        program_id: PROGRAM,
        accounts: vec![AccountMeta::new_readonly(crate::common::ring_auth(), false)],
        data: vec![tag::FRAME_EVENT, tag::TRANSFER],
    };
    refused(ring.send(unsigned, &[]), CustomRingError::InvalidFrameEvent);
}

fn anonymous_settlement(writer: Option<&Keypair>, rent_payer: Option<&Keypair>) -> Sent {
    let mut ring = Ring::new(Setup::Anonymous);
    let payer = ring.payer.insecure_clone();
    let buffer = Buffer {
        writer: writer.unwrap_or(&payer),
        rent_payer: rent_payer.unwrap_or(&payer),
        nonce: 1,
    };
    for wallet in [writer, rent_payer].into_iter().flatten() {
        ring.svm()
            .airdrop(&wallet.pubkey(), 10_000_000_000)
            .expect("fund the wallet");
    }
    let fixture = Fixture::new();
    let data = fixture.transfer(RingRail::Anonymous, 2, 2, false);
    let frame = transfer_frame(&data);
    let inner = transfer_accounts(&ring, &data);
    buffer.seal(&mut ring, &frame);
    let digest = frame_digest(&frame).unwrap();
    ring.send(buffer.settle(&digest, tag::TRANSFER, inner), &[])
}

#[test]
fn a_hidden_sender_named_writer_or_rent_payer_fails_the_party_check() {
    let hidden_sender = Keypair::new();
    refused(
        anonymous_settlement(Some(&hidden_sender), None),
        CustomRingError::FramePartyNotPayer,
    );
    refused(
        anonymous_settlement(None, Some(&hidden_sender)),
        CustomRingError::FramePartyNotPayer,
    );
    // The statement's party slot excludes the payer from the hidden sender.
    reaches_verification(anonymous_settlement(None, None));
}

#[test]
fn an_anonymous_merge_holds_the_writer_to_the_payer() {
    let mut ring = Ring::new(Setup::Anonymous);
    let payer = ring.payer.insecure_clone();
    let hidden_sender = funded(&mut ring);
    let mut data = merge_data(MergeRingAuthority::Ring);
    data.output_ring_data_hash = [0; 32];
    let merge = merge_instruction(&ring, &data, None);
    let frame = merge.data;
    let digest = frame_digest(&frame).unwrap();

    let by_sender = Buffer {
        writer: &hidden_sender,
        rent_payer: &payer,
        nonce: 1,
    };
    by_sender.seal(&mut ring, &frame);
    refused(
        ring.send(
            by_sender.settle(&digest, tag::MERGE, merge.accounts.clone()),
            &[],
        ),
        CustomRingError::FramePartyNotPayer,
    );

    let by_payer = Buffer {
        writer: &payer,
        rent_payer: &payer,
        nonce: 2,
    };
    by_payer.seal(&mut ring, &frame);
    reaches_verification(ring.send(by_payer.settle(&digest, tag::MERGE, merge.accounts), &[]));
}

#[test]
fn a_confidential_ring_takes_any_writer() {
    let mut ring = Ring::new(Setup::Policy);
    let writer = funded(&mut ring);
    let rent_payer = funded(&mut ring);
    let buffer = Buffer {
        writer: &writer,
        rent_payer: &rent_payer,
        nonce: 1,
    };
    let sealed = sealed(&mut ring, &buffer);
    reaches_verification(ring.send(
        buffer.settle(&sealed.digest, tag::TRANSFER, sealed.inner),
        &[],
    ));
}
