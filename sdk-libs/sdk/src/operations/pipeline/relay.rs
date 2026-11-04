//! The wallet half of a relayed transfer, Ring RPC reads the Merkle paths and records and proves.

use solana_address::Address;
use solana_signature::Signature;
use spr_client::AsyncRpc;
use spr_indexer_api::{Base64String, SerializablePubkey, SerializableSignature};
use spr_keypair::{NullifierKey, SigningKey};
use spr_program::instruction::CreateAssociatedTokenAccount;
use zolana_ring_client::rpc::{
    PrepareRelayRequest, ProofInputBytes, RelayCoOwner, RelayIntent, RelayProofInputs, RelayQuote,
    RelayRail, TxViewingSecret,
};
use zolana_ring_transaction::{published_outputs, RingDelivery};

use super::{
    audit::{audit_record, data_tail},
    carries_data, Anonymous, Delegated, Owner, Rail, RingTransfer, Sealed,
};
use crate::{
    relay_message::{ExpectedMessage, ExpectedTransfer, RelayTransferTerms, TokenAccountCreate},
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
        let setup = sealed
            .relay_proof_inputs(RelayRail::Confidential, nullifier_key.clone())
            .token_account_setup(payer, &token_account_setup)
            .map_err(|_| RingError::RelayAuditorMessage)?;
        let terms = sealed.transfer_terms(payer, &self.transfer.co_signers, &setup)?;
        let config = self.transfer.ring.require_config(client).await?;
        let expected = ExpectedTransfer::new(terms, &config)?;
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
        .expecting(ExpectedMessage::Transfer(expected)))
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
    fn transfer_terms(
        &self,
        fee_payer: Address,
        co_signers: &[Address],
        setup: &[CreateAssociatedTokenAccount],
    ) -> Result<RelayTransferTerms, RingError> {
        let staged = &self.pipeline.staged;
        let inputs = &staged.proof_inputs;
        let slots = published_outputs(&inputs.output_utxos);
        let bytes = |encoded: &[u8]| Base64String(encoded.to_vec());
        Ok(RelayTransferTerms {
            ring: SerializablePubkey(self.pipeline.ring.program_id()),
            fee_payer: SerializablePubkey(fee_payer),
            tx_viewing_key: TxViewingSecret::from(staged.rail.tx_viewing_key()),
            signers: staged
                .owner_signers
                .iter()
                .chain(co_signers)
                .copied()
                .map(SerializablePubkey)
                .collect(),
            records: slots
                .iter()
                .map(|slot| Ok(bytes(&audit_record(slot)?.encode())))
                .collect::<Result<_, RingError>>()?,
            tails: match inputs.output_utxos.iter().any(carries_data) {
                true => slots
                    .iter()
                    .map(|slot| bytes(&data_tail(slot).encode()))
                    .collect(),
                false => Vec::new(),
            },
            nullifiers: inputs
                .input_utxos
                .iter()
                .filter(|input| !input.is_compact())
                .map(|input| bytes(&input.nullifier()))
                .collect(),
            legs: inputs
                .external_data
                .interface_transfers
                .iter()
                .map(|leg| wincode::serialize(&leg.interface_transfer()).map(Base64String))
                .collect::<Result<_, _>>()
                .map_err(|_| RingError::RelayAuditorMessage)?,
            setup: setup
                .iter()
                .map(|create| TokenAccountCreate {
                    owner: SerializablePubkey(create.owner),
                    mint: SerializablePubkey(create.mint),
                    token_program: SerializablePubkey(create.token_program),
                })
                .collect(),
        })
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
        }
    }
}

#[cfg(test)]
#[path = "../../tests/operations/relay.rs"]
mod tests;
