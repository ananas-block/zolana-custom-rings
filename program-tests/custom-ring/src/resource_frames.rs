use custom_ring_interface::{
    AppMessage, RingPolicy, RingTransactData, MAX_CPI_DATA_LEN, MAX_FRAME_LEN,
};
use spr_interface::instruction::TransactProof;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Payload {
    Base,
    MaximumBytes,
    MaximumMessages,
}

pub struct MaximumPayload<'a, 'data> {
    pub data: &'a mut RingTransactData<'data>,
    pub policy: &'a RingPolicy,
    pub message: &'data [u8],
    pub view_tag: &'data [u8; 32],
}

impl MaximumPayload<'_, '_> {
    pub fn fill(self, payload: Payload) {
        assert!(payload != Payload::Base);
        let Self {
            data,
            policy,
            message,
            view_tag,
        } = self;
        data.extensions.messages.push(AppMessage {
            view_tag,
            data: &[],
        });
        let mut compact = data.encode().unwrap().len() + 1;
        let mut expanded = data
            .spp_instruction_data_under(policy, TransactProof::zeroed())
            .unwrap()
            .len();
        if payload == Payload::MaximumMessages {
            let empty = data.extensions.messages[0];
            data.extensions.messages.push(empty);
            let compact_stride = data.encode().unwrap().len() + 1 - compact;
            let expanded_stride = data
                .spp_instruction_data_under(policy, TransactProof::zeroed())
                .unwrap()
                .len()
                - expanded;
            data.extensions.messages.pop();
            let extra = ((MAX_FRAME_LEN - compact) / compact_stride)
                .min((MAX_CPI_DATA_LEN - expanded) / expanded_stride)
                .min(usize::from(u8::MAX) - 2 - usize::from(data.sender.is_some()));
            data.extensions.messages.extend((0..extra).map(|_| empty));
            compact += extra * compact_stride;
            expanded += extra * expanded_stride;
        }
        let remaining = MAX_FRAME_LEN
            .checked_sub(compact)
            .unwrap()
            .min(MAX_CPI_DATA_LEN.checked_sub(expanded).unwrap());
        data.extensions.messages[0].data = &message[..remaining];
        let compact = data.encode().unwrap().len() + 1;
        let expanded = data
            .spp_instruction_data_under(policy, TransactProof::zeroed())
            .unwrap()
            .len();
        assert!(compact == MAX_FRAME_LEN || expanded == MAX_CPI_DATA_LEN);
    }
}
