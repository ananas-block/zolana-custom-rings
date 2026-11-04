//! Pins the buffered wire the SDKs build, `test-vectors/settlement/frame_buffer.json`.

use custom_ring_interface::{
    frame_digest, settle_buffered_data, tag, CustomRingError, FrameBuffer, FrameBufferHeader,
    SettledFrame, WriteFrameIxData, FRAME_BUFFER_HEADER_LEN, FRAME_BUFFER_PDA_SEED, MAX_FRAME_LEN,
};
use serde_json::{json, Value};
use solana_address::Address;

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/settlement/frame_buffer.json"
);

const FRAME: [u8; 6] = [tag::TRANSFER, 1, 2, 3, 4, 5];

fn compute_vector() -> Value {
    let digest = frame_digest(&FRAME).unwrap();
    json!({
        "description": "The buffered wire. Frame is the inline instruction data with its tag. WRITE_FRAME data is tag || u64le(nonce) || u16le(frame_len) || u16le(offset) || bytes, accounts writer (signer, writable), buffer (writable), and on the first write the system program, creating the buffer at [seed, writer, u64le(nonce)]. CLOSE_FRAME_BUFFER is the tag alone, accounts writer (signer), buffer (writable), rent recipient (writable). SETTLE_BUFFERED data is tag || sha256(frame), accounts buffer (writable), ring program, then the inline accounts of a TRANSFER or AUTHORITY_TRANSFER, the frame tags it takes, and its SPP payer is the writer. FRAME_EVENT is tag || frame, the inner instruction readers take the frame from, accepted when it is an inner instruction of a SETTLE_BUFFERED of the ring program in a successful transaction whose digest it matches. Produced by program-libs/interface/tests/frame_buffer.rs.",
        "seed": hex::encode(FRAME_BUFFER_PDA_SEED),
        "header_len": FRAME_BUFFER_HEADER_LEN,
        "max_frame_len": MAX_FRAME_LEN,
        "frame": hex::encode(FRAME),
        "write": hex::encode(WriteFrameIxData { nonce: 7, frame_len: 6, offset: 2, bytes: &FRAME[2..] }.encode()),
        "close": hex::encode([tag::CLOSE_FRAME_BUFFER]),
        "settle": hex::encode(settle_buffered_data(&digest)),
        "event": hex::encode([&[tag::FRAME_EVENT][..], &FRAME].concat()),
    })
}

#[test]
fn the_wire_is_the_shared_vector() {
    let committed: Value = serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap();
    assert_eq!(committed, compute_vector());
}

#[test]
#[ignore = "rewrites test-vectors/settlement/frame_buffer.json"]
fn write_frame_buffer_vector() {
    let json = serde_json::to_string_pretty(&compute_vector()).unwrap() + "\n";
    std::fs::write(VECTOR, json).unwrap();
}

#[test]
fn the_header_ends_on_the_event_tag_so_the_event_borrows_the_frame() {
    let writer = Address::new_from_array([3; 32]);
    let mut account = vec![0; FRAME_BUFFER_HEADER_LEN + FRAME.len()];
    account[..FRAME_BUFFER_HEADER_LEN]
        .copy_from_slice(bytemuck::bytes_of(&FrameBufferHeader::new(writer)));
    let write = |offset, bytes| WriteFrameIxData {
        nonce: 7,
        frame_len: 6,
        offset,
        bytes,
    };
    write(0, &FRAME[..]).apply(&mut account).unwrap();
    let buffer = FrameBuffer::of(&account).unwrap();
    assert_eq!(buffer.frame(), FRAME);
    assert_eq!(buffer.event_data()[0], tag::FRAME_EVENT);
    assert_eq!(&buffer.event_data()[1..], FRAME);
    buffer.check_writer(&writer).unwrap();
    assert_eq!(
        buffer.check_writer(&Address::new_from_array([4; 32])),
        Err(CustomRingError::UnauthorizedFrameWriter)
    );
    assert_eq!(
        write(1, &FRAME[..]).apply(&mut account),
        Err(CustomRingError::FrameWriteOutOfRange)
    );
}

#[test]
fn a_reader_takes_the_frame_only_from_a_successful_ring_settlement_that_signed_it() {
    let ring = Address::new_from_array([5; 32]);
    let foreign = Address::new_from_array([6; 32]);
    let settle = settle_buffered_data(&frame_digest(&FRAME).unwrap());
    let event = [&[tag::FRAME_EVENT][..], &FRAME].concat();
    let honest = || SettledFrame {
        ring_program: &ring,
        settle_program: &ring,
        event_program: &ring,
        succeeded: true,
        settle: &settle,
        event: &event,
    };
    assert_eq!(honest().frame(), Ok(&FRAME[..]));
    let mut forged = event.clone();
    forged[3] ^= 1;
    assert_eq!(
        SettledFrame {
            event: &forged,
            ..honest()
        }
        .frame(),
        Err(CustomRingError::FrameDigestMismatch)
    );
    let invalid = Err(CustomRingError::InvalidInstructionData);
    let mut other_tag = event.clone();
    other_tag[0] = tag::TRANSFER;
    let mut other_settle = settle.clone();
    other_settle[0] = tag::TRANSFER;
    for refused in [
        SettledFrame {
            event: &other_tag,
            ..honest()
        },
        SettledFrame {
            settle: &other_settle,
            ..honest()
        },
        SettledFrame {
            succeeded: false,
            ..honest()
        },
        SettledFrame {
            settle_program: &foreign,
            ..honest()
        },
        SettledFrame {
            event_program: &foreign,
            ..honest()
        },
    ] {
        assert_eq!(refused.frame(), invalid);
    }
}
