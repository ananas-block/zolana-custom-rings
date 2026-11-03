//! Each sender's debit per limit row, a shared vector pins `owner_debits` to the circuit.

use spr_interface::N_PUBLIC_SLOTS;
use spr_transaction::{instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo};
use zolana_ring_policy::{
    owner_debits, DebitInput, DebitOutput, DebitTransfer, Member, OutflowLimit,
};

use crate::RingError;

pub(crate) struct Outflows<'a> {
    /// The transfer's screened owners, one identity per sender subject.
    pub senders: &'a [[u8; 32]],
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// Signed nets, a withdrawal negative.
    pub public_amounts: &'a [i128; N_PUBLIC_SLOTS],
}

impl Outflows<'_> {
    fn debit_inputs(&self) -> Result<Vec<DebitInput>, RingError> {
        self.inputs
            .iter()
            .filter(|input| !input.is_dummy())
            .map(|input| {
                Ok(DebitInput {
                    owner: input.utxo.owner.owner_proof_input_hash()?,
                    asset: *Member::asset(&input.utxo.asset.asset)?.as_bytes(),
                    amount: input.utxo.amount,
                })
            })
            .collect()
    }

    /// An exit reads no ring output, so it counts as leaving.
    fn debit_outputs(&self) -> Result<Vec<DebitOutput>, RingError> {
        self.outputs
            .iter()
            .filter_map(|output| output.owner_address.map(|owner| (output, owner)))
            .map(|(output, owner)| {
                Ok(DebitOutput {
                    ring: output.ring_program_id.is_some(),
                    owner: owner.signing_pubkey.owner_proof_input_hash()?,
                    asset: *Member::asset(&output.asset.asset)?.as_bytes(),
                    amount: output.amount,
                })
            })
            .collect()
    }

    /// A deposit offsets one owner's net, a mixed spend of its asset cannot split the credit.
    pub fn check_deposits(&self) -> Result<(), RingError> {
        let inputs = self.debit_inputs()?;
        let mixed = inputs
            .first()
            .is_some_and(|first| inputs.iter().any(|input| input.owner != first.owner));
        let deposits_spent = self
            .public_assets
            .iter()
            .zip(self.public_amounts)
            .filter(|(asset, net)| **net > 0 && **asset != [0; 32])
            .any(|(asset, _)| inputs.iter().any(|input| input.asset == *asset));
        match mixed && deposits_spent {
            true => Err(RingError::MixedOwnerDeposit),
            false => Ok(()),
        }
    }

    /// Refuses a debit above a nonzero cap, `true` past a nonzero co-sign bound.
    pub fn approval_required(&self, limits: &[OutflowLimit]) -> Result<bool, RingError> {
        let inputs = self.debit_inputs()?;
        let outputs = self.debit_outputs()?;
        let assets: Vec<[u8; 32]> = limits.iter().map(|limit| *limit.asset()).collect();
        let debits = owner_debits(&DebitTransfer {
            senders: self.senders,
            assets: &assets,
            inputs: &inputs,
            outputs: &outputs,
        });
        let mut approval = false;
        for debit in debits {
            let Some(limit) = limits.iter().find(|limit| *limit.asset() == debit.asset) else {
                continue;
            };
            let over = |bound: u64| bound != 0 && debit.debit > u128::from(bound);
            if over(limit.cap) {
                return Err(RingError::OutflowCapExceeded {
                    asset: debit.asset,
                    cap: limit.cap,
                    outflow: u64::try_from(debit.debit).map_err(|_| RingError::OutflowOverflow)?,
                });
            }
            approval |= over(limit.cosign_above);
        }
        Ok(approval)
    }
}
