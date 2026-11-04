//! A shared vector pins `owner_debits` to the circuit.

use spr_interface::N_PUBLIC_SLOTS;
use spr_transaction::{instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo};
use zolana_ring_policy::{
    owner_debits, DebitInput, DebitOutput, DebitTransfer, Member, MintPolicy, OwnerDebit,
    PublicGross,
};

use crate::RingError;

pub(crate) struct Outflows<'a> {
    /// The transfer's owner rows, zero rows pad.
    pub senders: &'a [[u8; 32]],
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
    pub public_assets: &'a [[u8; 32]; N_PUBLIC_SLOTS],
    /// No deposit subtracted, a net of the legs undercounts `leaving`.
    pub public_gross: &'a [u128; N_PUBLIC_SLOTS],
}

impl Outflows<'_> {
    fn debit_inputs(&self) -> Result<Vec<DebitInput>, RingError> {
        self.inputs
            .iter()
            .filter(|input| !input.is_dummy() && !input.is_address())
            .map(|input| {
                Ok(DebitInput {
                    owner: input.utxo.owner.owner_proof_input_hash()?,
                    asset: *Member::asset(&input.utxo.asset.asset)?.as_bytes(),
                    amount: input.utxo.amount,
                })
            })
            .collect()
    }

    /// Default-ring notes stay out, entry funding is a receipt.
    pub fn ring_inputs(&self) -> Result<Vec<DebitInput>, RingError> {
        self.inputs
            .iter()
            .filter(|input| {
                !input.is_dummy() && !input.is_address() && input.utxo.ring_program_id.is_some()
            })
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
            .filter(|output| !output.is_dummy())
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

    /// `outflow` per row and asset.
    pub fn flows(&self) -> Result<Vec<OwnerDebit>, RingError> {
        let inputs = self.debit_inputs()?;
        let outputs = self.debit_outputs()?;
        let public_gross: Vec<PublicGross> = self
            .public_assets
            .iter()
            .zip(self.public_gross)
            .filter(|(asset, _)| **asset != [0; 32])
            .map(|(asset, gross)| PublicGross {
                asset: *asset,
                gross: *gross,
            })
            .collect();
        let assets: Vec<[u8; 32]> = outputs
            .iter()
            .map(|output| output.asset)
            .chain(inputs.iter().map(|input| input.asset))
            .chain(public_gross.iter().map(|public| public.asset))
            .collect();
        Ok(owner_debits(&DebitTransfer {
            senders: self.senders,
            assets: &assets,
            inputs: &inputs,
            outputs: &outputs,
            public_gross: &public_gross,
        }))
    }

    /// Refuses before proving what the circuit fails to solve.
    pub fn check_caps(
        flows: &[OwnerDebit],
        policy_of: impl Fn(&[u8; 32]) -> MintPolicy,
    ) -> Result<(), RingError> {
        for flow in flows {
            let cap = policy_of(&flow.asset).cap;
            if cap != 0 && flow.outflow > u128::from(cap) {
                return Err(RingError::OutflowCapExceeded {
                    asset: flow.asset,
                    cap,
                    outflow: u64::try_from(flow.outflow).map_err(|_| RingError::OutflowOverflow)?,
                });
            }
        }
        Ok(())
    }
}
