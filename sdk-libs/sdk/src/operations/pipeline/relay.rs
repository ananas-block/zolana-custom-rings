//! The wallet half of a relayed transfer, Ring RPC reads the Merkle paths and records and proves.

use solana_address::Address;
use solana_signature::Signature;
use spr_client::AsyncRpc;
use spr_indexer_api::{Hash, SerializablePubkey, SerializableSignature};
use spr_keypair::{NullifierKey, PublicKey, SigningKey};
use spr_program::instruction::CreateAssociatedTokenAccount;
use zolana_ring_client::rpc::{
    PrepareRelayRequest, ProofInputBytes, RelayCoOwner, RelayIntent, RelayProofInputs, RelayQuote,
    RelayRail,
};
use zolana_ring_transaction::{published_outputs, RingDelivery};

use super::{approval_totals_of, Anonymous, Delegated, Owner, Rail, RingTransfer, Sealed};
use crate::{
    relay_message::{
        ApprovalOpening, ExpectedMessage, RelayTransferTerms, SealedTerms, SlotOpening,
        TokenAccountCreate,
    },
    PreparedRelay, RingError,
};

impl RingTransfer<Anonymous<'_>> {
    /// The hidden owner signs the message hash, the wallet reads no Merkle path and no record.
    pub async fn prepare_relay<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        WalletRelay {
            transfer: self,
            owner: &self.rail.owner,
            signer: self.rail.signer,
            exit_token_owner: self.rail.exit_token_owner,
        }
        .prepare(client, quote)
        .await
    }
}

impl RingTransfer<Owner<'_>> {
    /// The in-proof owner signs the message hash, the wallet reads no Merkle path and no record.
    pub async fn prepare_relay<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        WalletRelay {
            transfer: self,
            owner: &self.rail,
            signer: self
                .rail
                .in_proof_owner
                .ok_or(RingError::MissingInProofOwnerSignature)?,
            exit_token_owner: None,
        }
        .prepare(client, quote)
        .await
    }
}

struct WalletRelay<'t, R: Rail> {
    transfer: &'t RingTransfer<R>,
    owner: &'t Owner<'t>,
    signer: &'t SigningKey,
    exit_token_owner: Option<Address>,
}

impl<R: Rail> WalletRelay<'_, R> {
    async fn prepare<C: AsyncRpc + ?Sized>(
        self,
        client: &C,
        quote: RelayQuote,
    ) -> Result<PreparedRelay, RingError> {
        let payer = self.owner.transaction.payer();
        if payer != quote.fee_payer.0 {
            return Err(RingError::RelayPayerMismatch {
                payer,
                fee_payer: quote.fee_payer.0,
            });
        }
        let sealed = self.transfer.seal_unread(client).await?;
        let staged = &sealed.pipeline.staged;
        let inputs = &staged.proof_inputs;
        let nullifier_key = staged
            .authority
            .owner
            .clone()
            .ok_or(RingError::MissingAnonymousSigner)?;
        let owner_signature = SerializableSignature(Signature::from(
            self.signer.sign_message(&inputs.message_hash()?)?,
        ));
        let token_account_setup = self.owner.token_account_setup.clone();
        // The relay refuses a setup naming no withdrawal, only an owner's terms read it here.
        let setup = match staged.owner_signers.is_empty() {
            true => Vec::new(),
            false => sealed
                .relay_proof_inputs(RelayRail::Confidential, nullifier_key.clone())
                .token_account_setup(payer, &token_account_setup)?,
        };
        let terms = sealed.transfer_terms(payer, &setup)?;
        let approval = sealed
            .pipeline
            .approval_blinder
            .map(|blinder| {
                let totals = approval_totals_of(inputs, sealed.preview.n_out)?;
                Ok::<_, RingError>(ApprovalOpening::of(&totals, &blinder))
            })
            .transpose()?;
        let encode = |rail| {
            sealed
                .relay_proof_inputs(rail, nullifier_key)
                .encode()
                .map(ProofInputBytes::new)
                .map_err(RingError::from)
        };
        let intent = match staged.rail.delivery() {
            RingDelivery::Anonymous(plan) => RelayIntent::Anonymous {
                proof_inputs: encode(RelayRail::Anonymous {
                    plan: plan.clone(),
                    exit_token_owner: self.exit_token_owner,
                })?,
                owner_signature,
                token_account_setup,
            },
            RingDelivery::Delivered => RelayIntent::Confidential {
                proof_inputs: encode(RelayRail::Confidential)?,
                owner_signature,
                token_account_setup,
            },
        };
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: SerializablePubkey(self.transfer.ring.program_id()),
            quote,
            intent,
            co_signers: self
                .transfer
                .co_signers
                .iter()
                .copied()
                .map(SerializablePubkey)
                .collect(),
        })
        .expecting(ExpectedMessage::Sealed(SealedTerms {
            owners: terms,
            approval,
        })))
    }
}

impl RingTransfer<Delegated<'_>> {
    /// Reads accounts only, the relayed delegate rail proves the result.
    pub async fn relay_proof_inputs<C: AsyncRpc + ?Sized>(
        &self,
        client: &C,
    ) -> Result<RelayProofInputs, RingError> {
        let sealed = self.seal_unread(client).await?;
        let plan = match sealed.pipeline.staged.rail.delivery() {
            RingDelivery::Anonymous(plan) => Some(plan.clone()),
            RingDelivery::Delivered => None,
        };
        Ok(sealed.relay_proof_inputs(
            RelayRail::Delegate {
                delegate: self.rail.delegate,
                plan,
            },
            self.rail.source_key.clone(),
        ))
    }
}

impl<P> Sealed<'_, P> {
    /// One per public owner, its own slots and notes alone.
    fn transfer_terms(
        &self,
        fee_payer: Address,
        setup: &[CreateAssociatedTokenAccount],
    ) -> Result<Vec<RelayTransferTerms>, RingError> {
        let staged = &self.pipeline.staged;
        let inputs = &staged.proof_inputs;
        let ring = self.pipeline.ring.program_id();
        let setup: Vec<TokenAccountCreate> = setup
            .iter()
            .map(|create| TokenAccountCreate {
                owner: SerializablePubkey(create.owner),
                mint: SerializablePubkey(create.mint),
                token_program: SerializablePubkey(create.token_program),
            })
            .collect();
        Ok(staged
            .owner_signers
            .iter()
            .map(|signer| {
                let key = PublicKey::from_ed25519(signer.as_array());
                let slots = published_outputs(&inputs.output_utxos)
                    .iter()
                    .zip(0u32..)
                    .filter_map(|(output, slot)| {
                        let owner = output
                            .owner_address
                            .filter(|owner| !output.is_dummy() && owner.signing_pubkey == key)?;
                        Some(SlotOpening {
                            slot,
                            owner: SerializablePubkey(*signer),
                            nullifier_pk: Hash(owner.nullifier_pubkey),
                            mint: SerializablePubkey(output.asset.asset),
                            amount: output.amount,
                            blinding: Hash(output.blinding),
                            tree_id: inputs.output_tree_id,
                            data_hash: Hash(output.data_hash.unwrap_or_default()),
                            ring_data_hash: Hash(output.ring_data_hash.unwrap_or_default()),
                        })
                    })
                    .collect();
                RelayTransferTerms {
                    ring: SerializablePubkey(ring),
                    fee_payer: SerializablePubkey(fee_payer),
                    signer: SerializablePubkey(*signer),
                    slots,
                    nullifiers: inputs
                        .input_utxos
                        .iter()
                        .filter(|input| !input.is_dummy() && input.utxo.owner == key)
                        .map(|input| Hash(input.nullifier()))
                        .collect(),
                    setup: setup.clone(),
                }
            })
            .collect())
    }

    fn relay_proof_inputs(&self, rail: RelayRail, nullifier_key: NullifierKey) -> RelayProofInputs {
        let staged = &self.pipeline.staged;
        let inputs = &staged.proof_inputs;
        RelayProofInputs {
            rail,
            ring_program_id: self.pipeline.ring.program_id(),
            sender: staged.sender,
            nullifier_key,
            co_owners: staged
                .authority
                .co_owners
                .iter()
                .map(|held| RelayCoOwner {
                    owner: held.owner,
                    nullifier_key: held.key.clone(),
                })
                .collect(),
            tx_viewing_key: staged.rail.tx_viewing_key().clone(),
            inputs: inputs.input_utxos.clone(),
            outputs: inputs.output_utxos.clone(),
            external_data: inputs.external_data.clone(),
            interface_transfer_accounts: staged.interface_transfer_accounts.clone(),
            blinding_seed: inputs.blinding_seed,
            output_tree_id: inputs.output_tree_id,
            list_salts: staged.list_salts.clone(),
            wide_owners: self.preview.wide_owners,
            approval_blinder: self.pipeline.approval_blinder,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/operations/relay.rs"]
mod tests;
