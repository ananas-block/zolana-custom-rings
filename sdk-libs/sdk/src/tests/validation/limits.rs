use solana_address::Address;
use spr_interface::N_PUBLIC_SLOTS;
use spr_transaction::{instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo, Mint};
use zolana_ring_policy::{Member, OutflowLimit};

use super::support::{keypair, program, ring_utxo};
use crate::{limits::Outflows, RingError};

fn sol_outflows(net: i128, limit: OutflowLimit) -> Result<bool, RingError> {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let other = keypair(2).shielded_address().unwrap();
    let sol = Member::asset(&Mint::SOL.asset).unwrap();
    let output = |owner, amount, ring: Option<Address>| {
        let output = SppProofOutputUtxo::new(Mint::SOL, amount, owner).unwrap();
        match ring {
            Some(ring) => output.with_ring_program_id(ring),
            None => output,
        }
    };
    let outputs = [
        output(other, 3, Some(program())),
        output(sender, 7, Some(program())),
        output(sender, 2, None),
    ];
    let inputs: Vec<SppProofInputUtxo> = vec![ring_utxo(&owner, Mint::SOL, 12, 0).into()];
    let mut public_assets = [[0; 32]; N_PUBLIC_SLOTS];
    public_assets[0] = *sol.as_bytes();
    let mut public_amounts = [0; N_PUBLIC_SLOTS];
    public_amounts[0] = net;
    Outflows {
        senders: &[sender.signing_pubkey.owner_proof_input_hash().unwrap()],
        inputs: &inputs,
        outputs: &outputs,
        public_assets: &public_assets,
        public_amounts: &public_amounts,
    }
    .approval_required(&[limit])
}

/// An exit to the sender leaves the ring, ring change stays its own.
#[test]
fn the_debit_counts_what_leaves_the_sender_and_clamps_at_zero() {
    let sol = Member::asset(&Mint::SOL.asset).unwrap();
    let limit = |cap, cosign| {
        OutflowLimit::of(&sol)
            .with_cap(cap)
            .with_cosign_above(cosign)
    };
    assert!(!sol_outflows(0, limit(5, 5)).unwrap());
    assert!(sol_outflows(0, limit(5, 4)).unwrap());
    assert!(matches!(
        sol_outflows(0, limit(4, 0)),
        Err(RingError::OutflowCapExceeded {
            outflow: 5,
            cap: 4,
            ..
        })
    ));
}

/// A deposit funding outputs lowers one owner's net.
#[test]
fn a_single_owner_deposit_offset_stays_below_its_cap() {
    let owner = keypair(1);
    let sender = owner.shielded_address().unwrap();
    let other = keypair(2).shielded_address().unwrap();
    let sol = Member::asset(&Mint::SOL.asset).unwrap();
    let outputs = [
        SppProofOutputUtxo::new(Mint::SOL, 3, other)
            .unwrap()
            .with_ring_program_id(program()),
        SppProofOutputUtxo::new(Mint::SOL, 9, sender)
            .unwrap()
            .with_ring_program_id(program()),
    ];
    let inputs: Vec<SppProofInputUtxo> = vec![ring_utxo(&owner, Mint::SOL, 7, 0).into()];
    let mut public_assets = [[0; 32]; N_PUBLIC_SLOTS];
    public_assets[0] = *sol.as_bytes();
    let mut public_amounts = [0; N_PUBLIC_SLOTS];
    public_amounts[0] = 5;
    let flows = Outflows {
        senders: &[sender.signing_pubkey.owner_proof_input_hash().unwrap()],
        inputs: &inputs,
        outputs: &outputs,
        public_assets: &public_assets,
        public_amounts: &public_amounts,
    };
    flows.check_deposits().unwrap();
    assert!(!flows
        .approval_required(&[OutflowLimit::of(&sol).with_cap(1).with_cosign_above(1)])
        .unwrap());
}

#[test]
fn a_mixed_owner_deposit_of_a_spent_asset_is_refused() {
    let first = keypair(1);
    let second = keypair(2);
    let other = keypair(3).shielded_address().unwrap();
    let sol = Member::asset(&Mint::SOL.asset).unwrap();
    let inputs: Vec<SppProofInputUtxo> = vec![
        ring_utxo(&first, Mint::SOL, 7, 0).into(),
        ring_utxo(&second, Mint::SOL, 7, 1).into(),
    ];
    let outputs = [SppProofOutputUtxo::new(Mint::SOL, 3, other)
        .unwrap()
        .with_ring_program_id(program())];
    let mut public_assets = [[0; 32]; N_PUBLIC_SLOTS];
    public_assets[0] = *sol.as_bytes();
    let mut public_amounts = [0; N_PUBLIC_SLOTS];
    public_amounts[0] = 5;
    let flows = Outflows {
        senders: &[],
        inputs: &inputs,
        outputs: &outputs,
        public_assets: &public_assets,
        public_amounts: &public_amounts,
    };
    assert!(matches!(
        flows.check_deposits(),
        Err(RingError::MixedOwnerDeposit)
    ));
    let unrelated = [[9; 32], [0; 32], [0; 32]];
    Outflows {
        public_assets: &unrelated,
        ..flows
    }
    .check_deposits()
    .unwrap();
}
