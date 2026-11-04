//! The widest frames of every transfer key reach the pairing within Pinocchio's heap, the validator sweep settles each key's widest policy legs.

use custom_ring_interface::{
    key_catalog::{
        TransferShape, ANONYMOUS_TRANSFER_SHAPES, CONFIDENTIAL_TRANSFER_SHAPES,
        ENTRY_TRANSFER_SHAPES,
    },
    storage::Revision,
    tag, CustomRingError, RingPolicy, RingRail, RingTransactData, RootRead,
};
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta};
use solana_keypair::Signer;
use solana_transaction_error::TransactionError;
use spl_token_2022_interface::pod::PodAccount;
use spr_interface::{
    instruction::InterfaceTransfer, MAX_INTERFACE_TRANSFERS, SPL_TOKEN_ACCOUNT_INITIALIZED,
    SPL_TOKEN_PROGRAM_ID,
};

use crate::{
    common::{policy_pda, transact, Ring, Sent, Setup, RECORDS},
    transact_rules::{spp_list, Fixture},
};

const IN_PROOF_OWNER: [u8; 32] = [0x6e; 32];

#[derive(Clone, Copy)]
enum Legs {
    Sol(usize),
    Spl(usize),
}

impl Legs {
    fn count(self) -> usize {
        match self {
            Self::Sol(count) | Self::Spl(count) => count,
        }
    }

    fn with(self, count: usize) -> Self {
        match self {
            Self::Sol(_) => Self::Sol(count),
            Self::Spl(_) => Self::Spl(count),
        }
    }
}

#[derive(Clone, Copy)]
struct Wide {
    setup: Setup,
    rail: RingRail,
    inputs: u8,
    outputs: u8,
    legs: Legs,
    policy: bool,
    exempt: bool,
    entry: bool,
    in_proof: bool,
}

impl Wide {
    fn name(&self) -> String {
        let (legs, kind) = match self.legs {
            Legs::Sol(count) => (count, "sol"),
            Legs::Spl(count) => (count, "spl"),
        };
        format!(
            "{} {}x{} {legs} {kind}{}{}{}{}",
            self.rail,
            self.inputs,
            self.outputs,
            if self.policy { " policy" } else { "" },
            if self.exempt { " exempt" } else { "" },
            if self.entry { " entry" } else { "" },
            if self.in_proof { " in-proof" } else { "" },
        )
    }
}

fn widest(shape: &TransferShape) -> usize {
    shape
        .withdrawals
        .iter()
        .copied()
        .max()
        .map_or(0, usize::from)
}

/// Per key, one input with the widest legs, the input class with them, and the class alone.
fn cases() -> Vec<Wide> {
    let mut cases = Vec::new();
    let mut push = |base: Wide, shape: &TransferShape| {
        let legs = widest(shape);
        let fewest = usize::from(base.exempt);
        for (inputs, count) in [(1, legs), (shape.inputs, legs), (shape.inputs, fewest)] {
            cases.push(Wide {
                inputs,
                legs: base.legs.with(count),
                ..base
            });
        }
    };
    for shape in &CONFIDENTIAL_TRANSFER_SHAPES {
        let policy = Wide {
            setup: Setup::Policy,
            rail: RingRail::Confidential,
            inputs: 1,
            outputs: shape.outputs,
            legs: Legs::Sol(0),
            policy: true,
            exempt: false,
            entry: false,
            in_proof: false,
        };
        push(policy, shape);
        push(
            Wide {
                in_proof: true,
                ..policy
            },
            shape,
        );
        push(
            Wide {
                legs: Legs::Spl(0),
                ..policy
            },
            shape,
        );
        push(
            Wide {
                setup: Setup::AuditOnly,
                policy: false,
                exempt: true,
                ..policy
            },
            shape,
        );
    }
    for (family, entry) in [
        (&ANONYMOUS_TRANSFER_SHAPES[..], false),
        (&ENTRY_TRANSFER_SHAPES[..], true),
    ] {
        for shape in family {
            push(
                Wide {
                    setup: Setup::AnonymousPolicy,
                    rail: RingRail::Anonymous,
                    inputs: 1,
                    outputs: shape.outputs,
                    legs: Legs::Sol(0),
                    policy: true,
                    exempt: false,
                    entry,
                    in_proof: false,
                },
                shape,
            );
        }
    }
    cases
}

fn frame<'a>(fixture: &'a Fixture, owners: &'a [[u8; 32]], case: Wide) -> RingTransactData<'a> {
    let mut data = match case.in_proof {
        true => fixture.in_proof_owner(&IN_PROOF_OWNER, case.inputs, case.outputs, case.policy),
        false => fixture.transfer(case.rail, case.inputs, case.outputs, case.policy),
    };
    data.entry = case.entry;
    let count = case.legs.count();
    let amount = |leg: usize| 1_000 + leg as u64;
    data.interface_transfers = match case.legs {
        Legs::Sol(_) => (0..count)
            .map(|leg| InterfaceTransfer::SolWithdrawal {
                amount: amount(leg),
            })
            .collect(),
        Legs::Spl(_) => (0..count)
            .map(|leg| InterfaceTransfer::SplWithdrawal {
                amount: amount(leg),
                spl_interface_bump: 254,
            })
            .collect(),
    };
    if let Legs::Spl(_) = case.legs {
        data.spl_withdrawal_owners = &owners[..count];
    }
    fixture.fit_stream(&mut data);
    data
}

fn token_account(mint: Address, owner: [u8; 32]) -> Vec<u8> {
    bytemuck::bytes_of(&PodAccount {
        mint: mint.to_bytes().into(),
        owner: owner.into(),
        state: SPL_TOKEN_ACCOUNT_INITIALIZED,
        ..PodAccount::default()
    })
    .to_vec()
}

/// The settlement groups after the SPP list, one destination and one mint for every leg.
fn settlements(
    ring: &mut Ring,
    data: &RingTransactData<'_>,
    owners: &[[u8; 32]],
) -> Vec<AccountMeta> {
    let destination = Address::new_unique();
    let mint = Address::new_unique();
    let token_program = Address::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let mut accounts = Vec::new();
    for (leg, transfer) in data.interface_transfers.iter().enumerate() {
        match transfer {
            InterfaceTransfer::SolWithdrawal { .. } => accounts.extend([
                AccountMeta::new(Address::new_unique(), false),
                AccountMeta::new(destination, false),
            ]),
            InterfaceTransfer::SplWithdrawal { .. } => {
                let token = Address::new_unique();
                ring.store(token, token_program, token_account(mint, owners[leg]));
                accounts.extend([
                    AccountMeta::new_readonly(Address::new_unique(), false),
                    AccountMeta::new_readonly(mint, false),
                    AccountMeta::new(Address::new_unique(), false),
                    AccountMeta::new(token, false),
                    AccountMeta::new_readonly(token_program, false),
                ]);
            }
            InterfaceTransfer::SolDeposit { .. } | InterfaceTransfer::SplDeposit { .. } => {
                unreachable!("a wide frame withdraws")
            }
        }
    }
    accounts
}

struct Sending {
    case: Wide,
    accounts: Vec<AccountMeta>,
    bytes: Vec<u8>,
}

fn prepare(ring: &mut Ring, case: Wide) -> Sending {
    let fixture = Fixture::new().with_identity_proof();
    let owners: Vec<[u8; 32]> = (0..MAX_INTERFACE_TRANSFERS)
        .map(|leg| [0x70 + leg as u8; 32])
        .collect();
    let data = frame(&fixture, &owners, case);
    let payer = ring.payer.pubkey();
    let owner_run = match (case.rail, case.in_proof) {
        (RingRail::Confidential, false) => vec![AccountMeta::new_readonly(payer, true)],
        _ => Vec::new(),
    };
    let mut spp = spp_list(&payer, &data, &owner_run);
    spp.extend(settlements(ring, &data, &owners));
    let policy: RingPolicy = ring.read(&policy_pda());
    let accounts = [
        vec![AccountMeta::new_readonly(policy_pda(), false)],
        ring.registries(RootRead::transfer(&policy, false)),
        spp,
    ]
    .concat();
    Sending {
        case,
        accounts,
        bytes: data.encode().unwrap(),
    }
}

/// The runtime refuses a transaction past its ceilings before any instruction runs.
fn fits(sent: &Sent) -> bool {
    !matches!(sent, Err((error, _)) if !matches!(error, TransactionError::InstructionError(..)))
}

/// Sends `case` with the most legs one transaction carries.
fn send_widest(case: Wide) -> (Wide, Sent) {
    let mut legs = case.legs.count();
    loop {
        let case = Wide {
            legs: case.legs.with(legs),
            ..case
        };
        let mut ring = Ring::new(case.setup);
        let sending = prepare(&mut ring, case);
        let sent = ring.send(
            transact(tag::TRANSFER, sending.accounts, sending.bytes),
            &[],
        );
        if fits(&sent) || legs == 0 {
            return (sending.case, sent);
        }
        legs -= 1;
    }
}

/// Settlement allocates CPI account metadata past the pairing.
#[test]
fn the_widest_frames_of_every_key_reach_the_pairing() {
    let pairing = InstructionError::Custom(CustomRingError::ProofVerificationFailed as u32);
    let missed: Vec<String> = cases()
        .into_iter()
        .map(send_widest)
        .filter(|(_, sent)| {
            !matches!(sent, Err((TransactionError::InstructionError(0, error), _)) if *error == pairing)
        })
        .map(|(case, sent)| format!("{}, got {sent:?}", case.name()))
        .collect();
    assert!(missed.is_empty(), "{missed:#?}");
}
