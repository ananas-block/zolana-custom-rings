//! Frames of every rail, shared by the codec and the heap budget tests.

use custom_ring_interface::{
    sender_bundle_len, storage::Revision, AnonymousProofData, CustomRingProof, FramedSenderBundle,
    InProofOwner, InputTrees, PlainGroth16Proof, PolicyProof, PolicyRecipients, Replies,
    RingOutput, RingPolicy, RingRail, RingTransactData, CONFIDENTIAL_DATA_FREE_BODY_LEN,
    EXIT_RECORD_LEN, RECIPIENT_BODY_LEN, RING_POLICY,
};
use solana_bn254::compression::prelude::alt_bn128_g2_compress_be;
use spr_interface::instruction::{InterfaceTransfer, TreeContext};

#[path = "../common/mod.rs"]
mod common;

pub use common::spp_b;

pub const ZERO_TAG: [u8; 32] = [0; 32];

pub struct Fixture {
    pub proofs: [CustomRingProof; 2],
    pub spp_proof: PlainGroth16Proof,
    pub fields: Vec<[u8; 32]>,
    pub bytes: [[u8; 32]; 64],
    /// One slot's ciphertext, cut to the stream layout's length.
    pub ciphertexts: [[u8; 104]; 16],
    /// Cut to the stream layout's envelope length.
    pub envelope: Vec<u8>,
    pub tags: [[u8; 32]; 8],
    pub recipient_body: [u8; RECIPIENT_BODY_LEN],
    /// Cut to the frame's `m`.
    pub sender_body: Vec<u8>,
    /// Cut to one length per body-bearing slot.
    pub replies: Vec<u8>,
    pub payload: Vec<u8>,
    pub salt: [u8; 16],
}

impl Fixture {
    pub fn new() -> Self {
        let proof = |seed: u8| CustomRingProof {
            groth16: PlainGroth16Proof {
                proof_a: [seed; 32],
                proof_b: [seed + 1; 64],
                proof_c: [seed + 2; 32],
            },
            commitment: [seed + 3; 32],
            commitment_pok: [seed + 4; 32],
        };
        Self {
            proofs: [proof(0x10), proof(0x20)],
            spp_proof: PlainGroth16Proof {
                proof_a: [0x31; 32],
                proof_b: alt_bn128_g2_compress_be(&spp_b()).unwrap(),
                proof_c: [0x32; 32],
            },
            fields: (0..=u8::MAX).map(field).collect(),
            bytes: core::array::from_fn(|i| [0x40 + i as u8; 32]),
            ciphertexts: core::array::from_fn(|i| [0x80 + i as u8; 104]),
            envelope: (0..2048u32).map(|byte| byte as u8 ^ 0x93).collect(),
            tags: core::array::from_fn(|i| field(0xa0 + i as u8)),
            recipient_body: core::array::from_fn(|byte| byte as u8 ^ 0x5a),
            sender_body: (0..sender_bundle_len(16) as u16)
                .map(|byte| byte as u8 ^ 0x2d)
                .collect(),
            replies: (0..2048u32).map(|byte| byte as u8 ^ 0x17).collect(),
            payload: (0..CONFIDENTIAL_DATA_FREE_BODY_LEN as u8)
                .map(|byte| byte ^ 0x66)
                .collect(),
            salt: [0x5c; 16],
        }
    }

    pub fn base(&self, rail: RingRail, n_in: u8, n_out: u8) -> RingTransactData<'_> {
        RingTransactData {
            rail,
            n_in,
            n_out,
            proof: &self.proofs[0],
            own_revision: None,
            policy: None,
            exempt: false,
            approval_required: false,
            expiry_unix_ts: 1_800_000_000,
            tx_viewing_u: &self.bytes[0],
            salt: &self.salt,
            interface_transfers: Vec::new(),
            key_escrow: false,
            full_openings: false,
            outputs: Vec::new(),
            replies: None,
            sender: None,
            eph_u: &self.bytes[1],
            envelope: &[],
            private_tx_hash: &self.fields[0],
            anonymous: None,
            in_proof_owner: None,
            spp_proof: &self.spp_proof,
            nullifiers: &self.fields[1..1 + usize::from(n_in)],
            input_trees: InputTrees::One(TreeContext {
                utxo_tree_root_index: 11,
                nullifier_tree_root_index: 12,
            }),
        }
    }

    pub fn exit<'a>(&'a self, slot: usize, payload: &'a [u8]) -> RingOutput<'a> {
        RingOutput::Exit {
            hash: &self.fields[10 + slot],
            owner_tag: &self.bytes[12 + slot],
            payload,
            record: &self.ciphertexts[slot][..EXIT_RECORD_LEN],
        }
    }

    /// Cuts the envelope and every slot's ciphertext to the frame's stream layout.
    pub fn with_audit_stream<'a>(&'a self, mut data: RingTransactData<'a>) -> RingTransactData<'a> {
        let stream = data.audit_stream().unwrap();
        data.envelope = &self.envelope[..stream.envelope().len];
        for (slot, output) in data.outputs.iter_mut().enumerate() {
            let ciphertext = &self.ciphertexts[slot][..stream.ciphertext_len(slot)];
            match output {
                RingOutput::Delivered { body, .. } => *body = ciphertext,
                RingOutput::Anonymous { record, .. } | RingOutput::Exit { record, .. } => {
                    *record = ciphertext;
                }
            }
        }
        data
    }

    pub fn confidential_policy(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 2);
        data.key_escrow = true;
        data.own_revision = Some(Revision::from(7));
        data.policy = Some(PolicyProof {
            spl_withdrawal_owners: &[],
            curator_revision: Some(Revision::from(3)),
            recipients: PolicyRecipients::Framed(&self.fields[50..52]),
        });
        data.approval_required = true;
        data.interface_transfers = vec![
            InterfaceTransfer::SolWithdrawal { amount: 5_000 },
            InterfaceTransfer::SplDeposit {
                amount: 77,
                spl_interface_bump: 254,
            },
        ];
        data.outputs = vec![self.delivered(0), self.exit(1, &self.payload)];
        data.input_trees = InputTrees::Two {
            first: TreeContext {
                utxo_tree_root_index: 1,
                nullifier_tree_root_index: 2,
            },
            second: TreeContext {
                utxo_tree_root_index: 3,
                nullifier_tree_root_index: 4,
            },
            second_inputs: 0b10,
        };
        self.with_audit_stream(data)
    }

    /// No owner signs, SPP's anonymous rail hides the owner the delivered audit publishes.
    pub fn confidential_in_proof_owner(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 2, 4);
        data.own_revision = Some(Revision::from(5));
        data.policy = Some(PolicyProof {
            spl_withdrawal_owners: &[],
            curator_revision: None,
            recipients: PolicyRecipients::Framed(&self.fields[50..54]),
        });
        data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 4_000 }];
        data.outputs = (0..4)
            .map(|slot| match slot {
                1 => self.exit(slot, &self.payload),
                _ => self.delivered(slot),
            })
            .collect();
        data.in_proof_owner = Some(InProofOwner {
            owner: &self.bytes[16],
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
        });
        self.with_audit_stream(data)
    }

    pub fn confidential_delivered(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 1, 8);
        data.outputs = (0..8)
            .map(|slot| match slot {
                3 | 6 => self.exit(slot, &self.payload),
                _ => self.delivered(slot),
            })
            .collect();
        self.with_audit_stream(data)
    }

    pub fn confidential_exempt(&self) -> RingTransactData<'_> {
        let mut data = self.confidential_delivered();
        data.exempt = true;
        data.own_revision = Some(Revision::from(7));
        data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 2_500 }];
        data
    }

    pub fn anonymous(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 3, 4);
        data.own_revision = Some(Revision::from(31));
        data.policy = Some(PolicyProof {
            spl_withdrawal_owners: &[],
            curator_revision: None,
            recipients: PolicyRecipients::Hidden,
        });
        data.interface_transfers = vec![InterfaceTransfer::SolWithdrawal { amount: 9_999 }];
        data.outputs = (0..4)
            .map(|slot| match slot {
                2 => self.exit(slot, &self.payload),
                _ => self.tagged(slot),
            })
            .collect();
        data.sender = self.sender(4);
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: Some(&self.bytes[22]),
        });
        self.with_audit_stream(data)
    }

    pub fn anonymous_entry(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 2, 2);
        data.own_revision = Some(Revision::from(0));
        data.full_openings = true;
        data.outputs = vec![self.tagged(0), self.exit(1, &self.payload)];
        data.sender = self.sender(2);
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: None,
        });
        self.with_audit_stream(data)
    }

    pub fn delegate(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Delegate, 2, 2);
        data.key_escrow = true;
        data.own_revision = Some(Revision::from(0));
        data.policy = Some(self.delegate_policy(2));
        data.outputs = vec![self.delivered(0), self.delivered(1)];
        self.with_audit_stream(data)
    }

    pub fn delegate_policy(&self, outputs: usize) -> PolicyProof<'_> {
        PolicyProof {
            spl_withdrawal_owners: &[],
            curator_revision: None,
            recipients: PolicyRecipients::Framed(&self.fields[50..50 + outputs]),
        }
    }

    pub fn delivered(&self, slot: usize) -> RingOutput<'_> {
        RingOutput::Delivered {
            hash: &self.fields[10 + slot],
            u: &self.bytes[3 + slot],
            body: &self.ciphertexts[slot],
        }
    }

    /// Slot 0 a change output, any other slot a recipient body.
    pub fn tagged(&self, slot: usize) -> RingOutput<'_> {
        RingOutput::Anonymous {
            hash: &self.fields[10 + slot],
            tag: if slot == 0 {
                &ZERO_TAG
            } else {
                &self.tags[slot]
            },
            body: (slot != 0).then_some(&self.recipient_body),
            record: &self.ciphertexts[slot],
        }
    }

    /// `outputs` is the frame's `m`.
    pub fn sender(&self, outputs: usize) -> Option<FramedSenderBundle<'_>> {
        Some(FramedSenderBundle {
            tag: &self.tags[0],
            body: &self.sender_body[..sender_bundle_len(outputs)],
        })
    }

    /// The anonymous frame's replies, one of `len` bytes per body-bearing slot.
    pub fn anonymous_replies(&self, len: u16) -> RingTransactData<'_> {
        let mut data = self.anonymous();
        data.replies = Some(Replies {
            len,
            region: &self.replies[..2 * usize::from(len)],
        });
        data
    }

    pub fn anonymous_compact(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Anonymous, 3, 4);
        data.own_revision = Some(Revision::from(33));
        data.outputs = vec![self.tagged(0), self.tagged(1)];
        data.sender = self.sender(2);
        data.anonymous = Some(AnonymousProofData {
            commitment: &self.bytes[20],
            commitment_pok: &self.bytes[21],
            default_owner_tag: None,
        });
        self.with_audit_stream(data)
    }

    pub fn confidential_compact(&self) -> RingTransactData<'_> {
        let mut data = self.base(RingRail::Confidential, 1, 8);
        data.outputs = (0..5).map(|slot| self.delivered(slot)).collect();
        self.with_audit_stream(data)
    }

    pub fn cases(&self) -> [(&'static str, RingTransactData<'_>); 10] {
        [
            ("confidential_delivered_policy", self.confidential_policy()),
            (
                "confidential_in_proof_owner_policy",
                self.confidential_in_proof_owner(),
            ),
            (
                "confidential_delivered_audit_only",
                self.confidential_delivered(),
            ),
            ("confidential_exempt_audit_only", self.confidential_exempt()),
            ("anonymous_policy", self.anonymous()),
            ("anonymous_entry_audit_only", self.anonymous_entry()),
            ("delegate_move", self.delegate()),
            ("anonymous_reply_metadata", self.anonymous_replies(97)),
            ("anonymous_compact", self.anonymous_compact()),
            ("confidential_compact", self.confidential_compact()),
        ]
    }
}

pub fn field(seed: u8) -> [u8; 32] {
    let mut value = [seed; 32];
    value[0] = 0x0f;
    value
}

pub fn config() -> Box<RingPolicy> {
    let mut config: Box<RingPolicy> = bytemuck::zeroed_box();
    config.discriminator = RING_POLICY;
    config.auditor_pubkey[0] = 4;
    config.auditor_pubkey[1..].copy_from_slice(&[0xa1; 32]);
    config
}
