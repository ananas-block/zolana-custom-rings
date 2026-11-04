use custom_ring_interface::{tag, WriteFrameIxData, MAX_FRAME_LEN};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1;
use spr_client::transaction_size;

use super::*;

const WRITER: Address = Address::new_from_array([7; 32]);
const RING: Address = Address::new_from_array([9; 32]);

fn inline(frame_len: usize) -> Instruction {
    let mut data: Vec<u8> = (0..frame_len).map(|index| index as u8).collect();
    data[0] = tag::TRANSFER;
    Instruction {
        program_id: RING,
        accounts: vec![AccountMeta::new(WRITER, true)],
        data,
    }
}

#[test]
fn the_writes_rebuild_the_frame_and_each_fits_one_transaction() {
    let frame = inline(MAX_FRAME_LEN);
    let buffered = BufferedFrame::new(&frame, WRITER, 3).unwrap();
    let writes = buffered.writes().unwrap();
    assert!(writes.len() > 1);
    let mut rebuilt = vec![0; MAX_FRAME_LEN];
    for write in &writes {
        assert_eq!(write.data[0], tag::WRITE_FRAME);
        let size = transaction_size(&WRITER, core::slice::from_ref(write), write_budget()).unwrap();
        assert!(size.bytes <= v1::MAX_TRANSACTION_SIZE);
        let parsed = WriteFrameIxData::parse(&write.data[1..]).unwrap();
        assert_eq!(parsed.nonce, 3);
        assert_eq!(usize::from(parsed.frame_len), MAX_FRAME_LEN);
        let start = usize::from(parsed.offset);
        rebuilt[start..start + parsed.bytes.len()].copy_from_slice(parsed.bytes);
    }
    assert_eq!(rebuilt, frame.data);
}

#[test]
fn the_settlement_signs_the_frame_digest_ahead_of_the_transfer_accounts() {
    let frame = inline(5000);
    let buffered = BufferedFrame::new(&frame, WRITER, 0).unwrap();
    let settle = buffered.settle();
    assert_eq!(
        settle.data,
        settle_buffered_data(&frame_digest(&frame.data).unwrap())
    );
    assert_eq!(settle.accounts[0].pubkey, buffered.buffer());
    assert_eq!(settle.accounts[1].pubkey, RING);
    assert_eq!(settle.accounts[2..], frame.accounts);
    let close = buffered.close();
    assert_eq!(close.data, [tag::CLOSE_FRAME_BUFFER]);
    assert_eq!(close.accounts[0].pubkey, WRITER);
    assert!(close.accounts[0].is_signer);
}

#[test]
fn a_frame_past_the_cpi_limit_or_of_another_tag_has_no_buffer() {
    assert!(matches!(
        BufferedFrame::new(&inline(MAX_FRAME_LEN + 1), WRITER, 0),
        Err(AddressCeilingError::FrameTooLarge { .. })
    ));
    let mut delegate = inline(10);
    delegate.data[0] = tag::AUTHORITY_TRANSFER;
    assert!(matches!(
        BufferedFrame::new(&delegate, WRITER, 0),
        Err(AddressCeilingError::Program(
            CustomRingError::UnsupportedBufferedTag
        ))
    ));
}
