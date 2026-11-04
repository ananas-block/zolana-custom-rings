use std::collections::BTreeSet;

use anyhow::{Context, Result};
use custom_ring_interface::{
    cosign::{ApprovalMask, CoSignHeader, MAX_CO_SIGNERS},
    sender_bundle_len, spl_withdrawal_count,
    storage::Revision,
    tag, AnonymousProofData, AuditKey, CustomRingMergeIxData, CustomRingProof, DepositPrefix,
    FrameExtensions, FramedSenderBundle, InProofOwner, InputTrees, PlainGroth16Proof, PolicyProof,
    RecipientBody, Replies, RingDepositAuditCapsule, RingOutput, RingPolicy, RingRail,
    RingTransactData, RootRead, SealedMergeRecord, SlotBody, AUDIT_RECORD_LEN, DATA_TAIL_LEN,
    MAX_RING_DEPOSIT_AUDIT_SLOTS, MIN_REPLY_LEN, OPENING_RECORD_LEN, RECIPIENT_KEY_LEN,
    RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN, TAGGED_X25519_KEY_LEN,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1::{MAX_ADDRESSES, MAX_SIGNATURES, MAX_TRANSACTION_SIZE};
use spr_client::{transaction_size, ComputeBudgetConfig};
use spr_interface::{
    instruction::{
        instruction_data::merge_ring::MergeRingAuthority,
        instruction_data::merge_transact::{
            MergeOutputEncryption, MergeProof, MergeTransactIxData, MERGE_SUPPORTED_INPUT_COUNTS,
        },
        InterfaceTransfer, TransactProof, TreeContext,
    },
    shape::{Shape, SPP_SUPPORTED_SHAPES},
    N_PUBLIC_SLOTS,
};
use spr_keypair::ViewingKey;
use spr_program::instruction::{
    DepositAsset, DepositSplAccounts, MergeRingV2, RingAssetDeposit, RingAuthorityTransact,
    RingDeposit, RingTransact, TransactInterfaceTransferAccounts, TransactSolTransferAccounts,
    TransactSplWithdrawalAccounts,
};
use spr_transaction::{serialization::confidential::ConfidentialOutputPlaintext, Data, DataRecord};
use zolana_ring_transaction::RingDepositPlaintext;

/// The narrowest withdrawal capacity the catalog keys.
const LEGS: usize = 4;
/// `N_PUBLIC_SLOTS` distinct mints name the most SPL accounts.
const SPL_MINTS: usize = N_PUBLIC_SLOTS;

const RING_PROGRAM: Address = address(0xa0);
const TREE: Address = address(0xa1);
const SECOND_TREE: Address = address(0xa2);
const PAYER: Address = address(0xa3);
const OWN: Address = address(0xa4);
const CURATOR: Address = address(0xa5);
const PRIVATE: Address = address(0xa6);
const TRACKING: Address = address(0xa7);
const DELEGATE: Address = address(0xa8);
const TOKEN_PROGRAM: Address = address(0xab);

const fn address(seed: u8) -> Address {
    Address::new_from_array([seed; 32])
}

fn indexed(offset: u8, index: usize) -> Address {
    let mut bytes = [offset; 32];
    bytes[0] = index as u8;
    Address::new_from_array(bytes)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameRail {
    Signer,
    InProof,
    Hidden,
    PublicOwners,
    SignerEntry,
    HiddenEntry,
    Delegate,
    AnonymousDelegate,
}

impl FrameRail {
    const ALL: [Self; 8] = [
        Self::Signer,
        Self::InProof,
        Self::Hidden,
        Self::PublicOwners,
        Self::SignerEntry,
        Self::HiddenEntry,
        Self::Delegate,
        Self::AnonymousDelegate,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Signer => "confidential signer",
            Self::InProof => "confidential in-proof",
            Self::Hidden => "anonymous hidden",
            Self::PublicOwners => "anonymous public owners",
            Self::SignerEntry => "confidential entry",
            Self::HiddenEntry => "anonymous entry",
            Self::Delegate => "delegate",
            Self::AnonymousDelegate => "anonymous delegate",
        }
    }

    const fn rail(self) -> RingRail {
        match self {
            Self::Signer | Self::InProof | Self::SignerEntry => RingRail::Confidential,
            Self::Hidden | Self::PublicOwners | Self::HiddenEntry => RingRail::Anonymous,
            Self::Delegate => RingRail::Delegate,
            Self::AnonymousDelegate => RingRail::AnonymousDelegate,
        }
    }

    const fn entry(self) -> bool {
        matches!(self, Self::SignerEntry | Self::HiddenEntry)
    }

    const fn hidden_sender(self) -> bool {
        matches!(self, Self::Hidden | Self::HiddenEntry)
    }

    /// The signers SPP's owner run must hold for a spend.
    const fn required_owners(self) -> usize {
        match self {
            Self::Signer | Self::PublicOwners | Self::SignerEntry => 1,
            Self::InProof | Self::Hidden | Self::HiddenEntry => 0,
            Self::Delegate | Self::AnonymousDelegate => 0,
        }
    }

    const fn has_owner_run(self) -> bool {
        !self.rail().is_delegate()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Legs {
    None,
    Sol,
    Spl,
}

#[derive(Clone, Copy)]
struct Load {
    name: &'static str,
    outsider_payer: bool,
    /// Own, curator and private roots beside the tracking root every frame names.
    policy_roots: bool,
    co_signers: u8,
    legs: Legs,
    priority_fee: bool,
    /// Every slot carries a body and the last slot exits.
    every_body: bool,
    has_data: bool,
    replies: bool,
    second_tree: bool,
}

const MIN: Load = Load {
    name: "min",
    outsider_payer: false,
    policy_roots: false,
    co_signers: 0,
    legs: Legs::None,
    priority_fee: false,
    every_body: false,
    has_data: false,
    replies: false,
    second_tree: false,
};
const FULL: Load = Load {
    name: "full",
    outsider_payer: true,
    policy_roots: true,
    co_signers: 1,
    legs: Legs::Sol,
    priority_fee: true,
    every_body: true,
    ..MIN
};
const LOADS: [Load; 7] = [
    MIN,
    FULL,
    Load {
        name: "full+spl",
        legs: Legs::Spl,
        ..FULL
    },
    Load {
        name: "full+data",
        has_data: true,
        ..FULL
    },
    Load {
        name: "full+reply",
        replies: true,
        ..FULL
    },
    Load {
        name: "full+2tree",
        second_tree: true,
        ..FULL
    },
    Load {
        name: "full+5cosign",
        co_signers: MAX_CO_SIGNERS as u8,
        ..FULL
    },
];

#[derive(Clone, Copy)]
struct Fit {
    bytes: usize,
    addresses: usize,
    signatures: usize,
}

impl Fit {
    const fn fits(self) -> bool {
        self.bytes <= MAX_TRANSACTION_SIZE
            && self.addresses <= MAX_ADDRESSES as usize
            && self.signatures <= MAX_SIGNATURES as usize
    }

    fn over(self) -> String {
        let mut over = Vec::new();
        if self.bytes > MAX_TRANSACTION_SIZE {
            over.push(format!("{} B", self.bytes - MAX_TRANSACTION_SIZE));
        }
        if self.addresses > MAX_ADDRESSES as usize {
            over.push(format!(
                "{} accounts",
                self.addresses - MAX_ADDRESSES as usize
            ));
        }
        if self.signatures > MAX_SIGNATURES as usize {
            over.push(format!(
                "{} signatures",
                self.signatures - MAX_SIGNATURES as usize
            ));
        }
        over.join(", ")
    }

    fn of(instruction: &Instruction, payer: &Address, priority_fee: bool) -> Result<Self> {
        let budget = ComputeBudgetConfig::new(0);
        let budget = match priority_fee {
            true => budget.with_priority_fee(1),
            false => budget,
        };
        let size = transaction_size(payer, std::slice::from_ref(instruction), budget)?;
        let signers: BTreeSet<_> = instruction
            .accounts
            .iter()
            .filter(|meta| meta.is_signer)
            .map(|meta| meta.pubkey)
            .chain([*payer])
            .collect();
        Ok(Self {
            bytes: size.bytes,
            addresses: size.addresses,
            signatures: signers.len(),
        })
    }
}

/// Every input and output slot of `shape` published.
struct Transfer {
    frame: FrameRail,
    shape: Shape,
    load: Load,
    owners: usize,
}

struct Measured {
    fit: Fit,
    /// The catalog keys it and `parse` read it back.
    keyed: bool,
}

impl Transfer {
    fn measure(&self) -> Result<Measured> {
        let (frame, load) = (self.frame, self.load);
        let (inputs, outputs) = (self.shape.n_inputs(), self.shape.n_outputs());
        let rail = frame.rail();
        let delegate = rail.is_delegate();
        let policy_roots = load.policy_roots && !delegate;
        let co_signers = if delegate { 0 } else { load.co_signers };
        // The catalog keys no private rows with tails.
        let private_source = policy_roots && !load.has_data;
        let read = match policy_roots {
            true => RootRead::Policy,
            false => RootRead::None,
        };
        let config = ring_config(private_source);
        let anonymous_frame = rail.anonymous_frame();

        let proof = CustomRingProof {
            groth16: PlainGroth16Proof {
                proof_a: [1; 32],
                proof_b: [2; 64],
                proof_c: [3; 32],
            },
            commitment: [4; 32],
            commitment_pok: [5; 32],
        };
        let spp_proof = proof.groth16;
        let field = [6u8; 32];
        let record = [7u8; AUDIT_RECORD_LEN];
        let tail = [8u8; DATA_TAIL_LEN];
        let salt = [9u8; 16];
        let ring_data = load.has_data.then_some([10u8; 32]);
        let recipient_body = RecipientBody {
            ring_data_hash: ring_data,
            ..RecipientBody::default()
        }
        .encode();
        let exit_body = vec![
            11u8;
            RECIPIENT_KEY_LEN
                + ConfidentialOutputPlaintext {
                    asset_id: 1,
                    amount: 1,
                    blinding: [11; 32],
                    ring_program_id: None,
                    data: match ring_data {
                        Some(hash) => Data::new(vec![DataRecord::RingData(hash.to_vec())]),
                        None => Data::default(),
                    },
                }
                .serialize()?
                .len()
        ];
        let nullifiers: Vec<[u8; 32]> = (0..inputs)
            .map(|input| indexed(0xb0, input).to_bytes())
            .collect();
        let bundle = vec![12u8; sender_bundle_len(outputs)];
        let revision = Revision::from(1);

        let legs = self.legs(frame);
        let interface_transfers: Vec<InterfaceTransfer> =
            legs.iter().map(|(transfer, _)| *transfer).collect();
        let withdrawal_owners = match policy_roots {
            true => vec![field; spl_withdrawal_count(&interface_transfers)],
            false => Vec::new(),
        };

        let slots: Vec<RingOutput<'_>> = (0..outputs)
            .map(|slot| RingOutput {
                hash: &field,
                owner_tag: &field,
                body: match (load.every_body, anonymous_frame, slot) {
                    (true, _, slot) if slot + 1 == outputs => SlotBody::Exit(&exit_body),
                    (false, true, 0) => SlotBody::None,
                    _ => SlotBody::Recipient(&recipient_body),
                },
                record: &record,
                tail: load.has_data.then_some(&tail),
            })
            .collect();
        let reply_bodies = slots
            .iter()
            .filter(|slot| matches!(slot.body, SlotBody::Recipient(_)))
            .count();
        let reply_region = vec![13u8; MIN_REPLY_LEN * reply_bodies];

        let context = TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        };
        let mut data = RingTransactData {
            rail,
            n_in: u8::try_from(inputs)?,
            n_out: u8::try_from(outputs)?,
            proof: &proof,
            tracking_revision: revision,
            own_revision: policy_roots.then_some(revision),
            policy: policy_roots.then_some(PolicyProof {
                curator_revision: Some(revision),
            }),
            spl_withdrawal_owners: &withdrawal_owners,
            co_sign: CoSignHeader {
                approval: match co_signers {
                    0 => ApprovalMask::default(),
                    _ => ApprovalMask::OUTFLOW,
                },
                co_signers,
            },
            no_spend: false,
            public_owners: frame == FrameRail::PublicOwners,
            expiry_unix_ts: u32::MAX,
            tx_viewing_u: &field,
            salt: &salt,
            extensions: FrameExtensions {
                private_revision: private_source.then_some(revision),
                ..FrameExtensions::default()
            },
            interface_transfers,
            has_data: load.has_data,
            entry: frame.entry(),
            wide_owners: false,
            outputs: slots,
            replies: (load.replies && anonymous_frame).then_some(Replies {
                len: MIN_REPLY_LEN as u16,
                region: &reply_region,
            }),
            sender: anonymous_frame.then_some(FramedSenderBundle {
                tag: &field,
                body: &bundle,
            }),
            eph_u: &field,
            envelope: &[],
            private_tx_hash: &field,
            anonymous: frame.hidden_sender().then_some(AnonymousProofData {
                commitment: &field,
                commitment_pok: &field,
                default_owner_tag: frame.entry().then_some(&field),
            }),
            in_proof_owner: (frame == FrameRail::InProof).then_some(InProofOwner {
                owner: &field,
                commitment: &field,
                commitment_pok: &field,
            }),
            spp_proof: &spp_proof,
            nullifiers: &nullifiers,
            input_trees: match load.second_tree {
                true => InputTrees::Two {
                    first: context,
                    second: context,
                    second_inputs: 1,
                },
                false => InputTrees::One(context),
            },
        };
        let catalog = data.audit_stream().map(|stream| stream.key);
        let circuit_legs = if delegate {
            0
        } else {
            data.interface_transfers.len()
        };
        let keyed = catalog.is_ok() && data.transfer_circuit(circuit_legs).is_ok();
        let key = catalog.unwrap_or(AuditKey {
            class: inputs,
            entry: frame.entry(),
        });
        let envelope = vec![14u8; data.stream_under(key).envelope().len];
        data.envelope = &envelope;
        let encoded = data
            .encode_under(key)
            .with_context(|| format!("{} {:?}", frame.name(), self.shape))?;
        if keyed {
            let parsed = RingTransactData::parse(&encoded, rail)?;
            anyhow::ensure!(parsed.data() == &data, "parse reads another frame");
        }

        let payer = match (load.outsider_payer, frame) {
            (false, FrameRail::Signer | FrameRail::SignerEntry | FrameRail::PublicOwners) => {
                indexed(0xc0, 0)
            }
            (false, FrameRail::Delegate | FrameRail::AnonymousDelegate) => DELEGATE,
            _ => PAYER,
        };
        let owner_signers: Vec<Address> =
            (0..self.owners).map(|owner| indexed(0xc0, owner)).collect();
        let input_trees = match load.second_tree {
            true => vec![TREE, SECOND_TREE],
            false => vec![TREE],
        };
        let accounts: Vec<TransactInterfaceTransferAccounts> =
            legs.iter().map(|(_, accounts)| *accounts).collect();
        let expanded = data.transact_ix_data(&config, TransactProof::zeroed())?;
        let spp = match delegate {
            true => {
                RingAuthorityTransact {
                    payer,
                    input_trees,
                    output_tree: TREE,
                    ring_program_id: RING_PROGRAM,
                    interface_transfer_accounts: accounts,
                    data: expanded,
                }
                .instruction()
                .accounts
            }
            false => {
                RingTransact {
                    payer,
                    input_trees,
                    output_tree: TREE,
                    ring_program_id: RING_PROGRAM,
                    owner_signers,
                    interface_transfer_accounts: accounts,
                    data: expanded,
                }
                .instruction()
                .accounts
            }
        };
        if !delegate {
            let settlements = data
                .interface_transfers
                .iter()
                .map(|transfer| transfer.settlement_account_count())
                .sum();
            let read = data
                .owner_signers(&spp, settlements)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            anyhow::ensure!(
                read.len() == self.owners,
                "the program reads another owner run"
            );
        }

        let mut metas = ring_prefix(&config, read, co_signers);
        if delegate {
            metas.push(AccountMeta::new_readonly(DELEGATE, true));
        }
        metas.extend(spp);
        let ring_tag = match delegate {
            true => tag::AUTHORITY_TRANSFER,
            false => tag::TRANSFER,
        };
        let instruction = Instruction {
            program_id: RING_PROGRAM,
            accounts: metas,
            data: [&[ring_tag][..], &encoded].concat(),
        };
        Ok(Measured {
            fit: Fit::of(&instruction, &payer, load.priority_fee)?,
            keyed,
        })
    }

    /// A hidden sender's exit names one destination.
    fn legs(
        &self,
        frame: FrameRail,
    ) -> Vec<(InterfaceTransfer, TransactInterfaceTransferAccounts)> {
        let destination = |leg: usize| match frame.hidden_sender() {
            true => indexed(0xd0, 0),
            false => indexed(0xd0, leg),
        };
        (0..LEGS)
            .filter_map(|leg| match self.load.legs {
                Legs::None => None,
                Legs::Sol => Some((
                    InterfaceTransfer::SolWithdrawal { amount: 1 },
                    TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                        recipient: destination(leg),
                    }),
                )),
                Legs::Spl => Some((
                    InterfaceTransfer::SplWithdrawal {
                        amount: 1,
                        spl_interface_bump: 255,
                    },
                    TransactInterfaceTransferAccounts::SplWithdrawal(
                        TransactSplWithdrawalAccounts {
                            mint: indexed(0xa9, leg % SPL_MINTS),
                            spl_interface: indexed(0xaa, leg % SPL_MINTS),
                            user_token_account: destination(leg),
                            token_program: TOKEN_PROGRAM,
                        },
                    ),
                )),
            })
            .collect()
    }

    /// The most owner signers the ceilings admit, the catalog's rows bound a key apart.
    fn widest_owner_run(&self) -> Result<Option<usize>> {
        let mut widest = None;
        for owners in self.frame.required_owners()..=self.shape.n_inputs() {
            let attempt = Self {
                frame: self.frame,
                shape: self.shape,
                load: self.load,
                owners,
            };
            if !attempt.measure()?.fit.fits() {
                break;
            }
            widest = Some(owners);
        }
        Ok(widest)
    }
}

fn ring_config(private_source: bool) -> Box<RingPolicy> {
    let mut config: Box<RingPolicy> = bytemuck::zeroed_box();
    config.auditor_pubkey[0] = 4;
    config.records = OWN;
    config.tracking = TRACKING;
    config.sources[0].registry = CURATOR;
    if private_source {
        config.private_source = PRIVATE;
    }
    config
}

fn ring_prefix(config: &RingPolicy, read: RootRead, co_signers: u8) -> Vec<AccountMeta> {
    let (policy, _) = Address::find_program_address(&[RingPolicy::SEED], &RING_PROGRAM);
    let mut metas = vec![AccountMeta::new_readonly(policy, false)];
    metas.extend(
        config
            .root_registries(read)
            .map(|registry| AccountMeta::new_readonly(registry, false)),
    );
    for index in 0..usize::from(co_signers) {
        metas.push(AccountMeta::new_readonly(indexed(0xe0, index), false));
        metas.push(AccountMeta::new_readonly(indexed(0xe8, index), true));
    }
    metas
}

fn merge_fit(width: usize, authority: MergeRingAuthority) -> Result<Fit> {
    let merge = MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [4; 32],
        output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
            salt: [5; 16],
            ciphertext: [[6; 32]; 3],
        },
        private_tx_hash: [7; 32],
        nullifiers: (0..width)
            .map(|input| indexed(0xb0, input).to_bytes())
            .collect(),
        utxo_tree_root_index: 0,
        nullifier_tree_root_index: 0,
        cache_slot: None,
    };
    let encoded = CustomRingMergeIxData {
        tracking_revision: Revision::from(1),
        output_ring_data_hash: [8; 32],
        authority,
        sealed: SealedMergeRecord {
            proof: bytemuck::Zeroable::zeroed(),
            eph_pk: [9; TAGGED_X25519_KEY_LEN],
            ciphertext: [10; OPENING_RECORD_LEN],
        },
        merge: merge.clone(),
    }
    .serialize()?;
    let spp = MergeRingV2 {
        input_tree: TREE,
        output_tree: TREE,
        ring_program_id: RING_PROGRAM,
        payer: PAYER,
        owner: matches!(authority, MergeRingAuthority::OwnerSigned).then_some(indexed(0xc0, 0)),
        data: merge,
        output_ring_data_hash: [8; 32],
        cache: None,
    }
    .instruction()
    .accounts;
    let mut metas = ring_prefix(&ring_config(false), RootRead::merge(), 0);
    metas.extend(spp);
    let instruction = Instruction {
        program_id: RING_PROGRAM,
        accounts: metas,
        data: [&[tag::MERGE][..], &encoded].concat(),
    };
    Fit::of(&instruction, &PAYER, true)
}

fn deposit_fit(width: usize, full: bool) -> Result<Fit> {
    let recipient = ViewingKey::new().pubkey();
    let capsule_ciphertext = [11u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN];
    let eph_pk = [12u8; TAGGED_X25519_KEY_LEN];
    let deposits = (0..width)
        .map(|slot| {
            let mut encrypted = RingDepositPlaintext {
                blinding: [13; 32],
                utxo_data: None,
                memo: None,
                ring_data: Vec::new(),
            }
            .encrypt(&recipient)?;
            encrypted.ciphertext = RingDepositAuditCapsule {
                slot_index: slot as u8,
                eph_pk: &eph_pk,
                ciphertext: &capsule_ciphertext,
                recipient_ciphertext: &encrypted.ciphertext,
            }
            .encode();
            Ok(RingAssetDeposit {
                asset: match full {
                    true => DepositAsset::Spl(DepositSplAccounts {
                        mint: indexed(0xa9, 0),
                        user_token: indexed(0xd0, 0),
                        token_program: TOKEN_PROGRAM,
                    }),
                    false => DepositAsset::Sol,
                },
                view_tag: [14; 32],
                owner_utxo_hash: [15; 32],
                amount: 1,
                ring_data_hash: [16; 32],
                encrypted,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let spp = RingDeposit {
        tree: TREE,
        depositor: PAYER,
        ring_program_id: RING_PROGRAM,
        deposits,
    }
    .instruction()?;
    let prefix = DepositPrefix {
        tag: tag::DEPOSIT,
        proof: bytemuck::Zeroable::zeroed(),
        tracking_revision: Revision::from(1),
        own_revision: Revision::from(1),
        curator_revision: Revision::from(1),
    };
    let read = match full {
        true => RootRead::Policy,
        false => RootRead::None,
    };
    let mut metas = ring_prefix(&ring_config(full), read, u8::from(full));
    metas.extend(spp.accounts);
    let instruction = Instruction {
        program_id: RING_PROGRAM,
        accounts: metas,
        data: [bytemuck::bytes_of(&prefix), &spp.data].concat(),
    };
    Fit::of(&instruction, &PAYER, full)
}

fn verdict(fit: Fit) -> &'static str {
    match fit.fits() {
        true => "fits",
        false => "no",
    }
}

pub fn run() -> Result<()> {
    println!(
        "Measured with the frame encoders, SPP's account builders and the v1 compiler. Ceilings {MAX_TRANSACTION_SIZE} B, {MAX_ADDRESSES} accounts, {MAX_SIGNATURES} signatures."
    );
    println!("| shape | rail | load | key | bytes | accounts | signatures | widest owner run | fits | over |");
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for shape in SPP_SUPPORTED_SHAPES {
        for frame in FrameRail::ALL {
            if !frame.rail().supports(shape) {
                continue;
            }
            for load in LOADS {
                let transfer = Transfer {
                    frame,
                    shape,
                    load,
                    owners: frame.required_owners(),
                };
                let measured = transfer.measure()?;
                let widest = match frame.has_owner_run() && load.name == FULL.name {
                    true => transfer
                        .widest_owner_run()?
                        .map_or("none".to_owned(), |owners| owners.to_string()),
                    false => "-".to_owned(),
                };
                let fit = measured.fit;
                println!(
                    "| {}x{} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                    shape.n_inputs(),
                    shape.n_outputs(),
                    frame.name(),
                    load.name,
                    if measured.keyed { "yes" } else { "none" },
                    fit.bytes,
                    fit.addresses,
                    fit.signatures,
                    widest,
                    verdict(fit),
                    fit.over(),
                );
            }
        }
    }
    for width in MERGE_SUPPORTED_INPUT_COUNTS {
        for (name, authority) in [
            ("ring", MergeRingAuthority::Ring),
            ("owner signed", MergeRingAuthority::OwnerSigned),
        ] {
            let fit = merge_fit(width, authority)?;
            println!(
                "| {width}x1 | merge | {name} | yes | {} | {} | {} | - | {} | {} |",
                fit.bytes,
                fit.addresses,
                fit.signatures,
                verdict(fit),
                fit.over(),
            );
        }
    }
    for width in (1..=MAX_RING_DEPOSIT_AUDIT_SLOTS).filter(|width| width.is_power_of_two()) {
        for (name, full) in [("min", false), ("full", true)] {
            let fit = deposit_fit(width, full)?;
            println!(
                "| 0x{width} | deposit | {name} | yes | {} | {} | {} | - | {} | {} |",
                fit.bytes,
                fit.addresses,
                fit.signatures,
                verdict(fit),
                fit.over(),
            );
        }
    }
    Ok(())
}
