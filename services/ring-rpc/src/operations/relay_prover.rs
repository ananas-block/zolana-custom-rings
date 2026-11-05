use async_trait::async_trait;
use custom_ring_interface::{
    compute_unit_limit,
    storage_instruction::EnrollRequest,
    tracking::{TrackingAuthorization, TrackingRegistry},
    InstructionTag, RegisterKeyCheck,
};
use custom_ring_sdk::{
    AllowedNullifiers, CustomRing, DelegateMove, DelegatePayment, DelegateSource, RelayedDeposit,
    RelayedTransferInput, RingClient, RingIndexerBackend, RingTransfer, WideFrames,
};
use solana_address::Address;
use solana_instruction::Instruction;
use spr_client::{AsyncRpc, ComputeBudgetConfig};
use spr_keypair::{NullifierKey, ShieldedAddress, ViewingKey};
use spr_transaction::{AssetRegistry, WalletUtxo};
use zolana_ring_client::rpc::{
    RelayDepositInputs, RelayEnrollInputs, RelayMergeInputs, RelayProofInputs, RelayRail,
};

use crate::{
    error::RingRpcError,
    escrow_merge::OwnerMergeProof,
    managed_merge::OwnerMerge,
    relay::{RelayError, RelayPayload},
};

pub struct RelayProofRequest<'a> {
    pub ring: Address,
    pub parties: RelayParties,
    pub payload: &'a RelayPayload,
    /// Verified over `SppProofInputs::message_hash`, the anonymous and confidential proofs take it.
    pub owner_signature: Option<[u8; 64]>,
}

/// The source's notes open under the escrowed key, the source signs nothing.
#[must_use]
pub struct DelegateSeal<'a> {
    pub ring: Address,
    pub delegate: Address,
    pub sources: &'a [SealedSource],
    /// Admitted from `sources`, the relay holds the sealed inputs to it before proving.
    pub allowed: &'a AllowedNullifiers,
    pub tx_viewing_key: ViewingKey,
    pub payments: Vec<DelegatePayment>,
    pub assets: &'a AssetRegistry,
}

/// One member the service holds the key and opened notes of.
pub struct SealedSource {
    pub address: ShieldedAddress,
    pub nullifier_key: NullifierKey,
    pub notes: Vec<WalletUtxo>,
}

/// Read from the relay, never from the request.
#[derive(Clone)]
pub struct RelayParties {
    pub fee_payer: Address,
    /// In run order, read while a demanded class stays uncovered.
    pub co_signers: Vec<Address>,
}

pub struct ProvenRelay {
    pub instruction: Instruction,
    pub budget: ComputeBudgetConfig,
    pub co_signers: Vec<Address>,
    /// The owners, the delegate or the depositor, each signs the returned message.
    pub signers: Vec<Address>,
}

#[async_trait]
pub trait RelayProver: Send + Sync {
    async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError>;

    /// Selects the notes and seals the delegate's move, `prove` proves it.
    async fn seal_delegate(
        &self,
        seal: DelegateSeal<'_>,
        parties: RelayParties,
    ) -> Result<RelayProofInputs, RingRpcError>;

    /// Refuses a proof the program would refuse, ahead of any charge, the relay pays the account's rent.
    async fn check_enrollment(&self, enrollment: &RelayEnrollInputs) -> Result<(), RingRpcError>;
}

/// What the storage program reads of a relayed enrollment ahead of creating its account.
#[must_use]
struct EnrollmentProof<'a> {
    enrollment: &'a RelayEnrollInputs,
    registry: &'a TrackingRegistry,
    /// The owner's authorization account holds data, a rotation proves nothing.
    enrolled: bool,
}

impl EnrollmentProof<'_> {
    fn check(self) -> Result<(), RelayError> {
        let data = self
            .enrollment
            .instruction_data
            .get(1..)
            .ok_or(RelayError::InvalidEnrollment)?;
        let EnrollRequest { ix, proof } =
            EnrollRequest::parse(data).map_err(|_| RelayError::InvalidEnrollment)?;
        ix.check().map_err(|_| RelayError::InvalidEnrollment)?;
        match (self.enrolled, proof) {
            (true, None) => Ok(()),
            (false, Some(proof)) => RegisterKeyCheck {
                ring_id: &self.registry.ring_id,
                auditor_pubkey: &self.registry.auditor_pubkey,
                owner: &self.enrollment.owner,
                ix,
                proof,
            }
            .verify()
            .map_err(|_| RelayError::InvalidEnrollment),
            (true, Some(_)) | (false, None) => Err(RelayError::InvalidEnrollment),
        }
    }
}

pub struct SdkRelayProver<R, I> {
    client: RingClient<R, I>,
}

impl<R, I> SdkRelayProver<R, I> {
    pub fn new(client: RingClient<R, I>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<R: AsyncRpc + 'static, I: RingIndexerBackend + 'static> RelayProver for SdkRelayProver<R, I> {
    async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
        match request.payload {
            RelayPayload::Transfer(proof_inputs) => self.transfer(&request, proof_inputs).await,
            RelayPayload::Deposit(deposit) => self.deposit(&request, deposit).await,
            RelayPayload::Merge(merge) => self.merge(&request, merge).await,
            // `Relay::prepare` builds it, it holds nothing to prove here.
            RelayPayload::Enroll(_) => Err(RelayError::InvalidEnrollment.into()),
        }
    }

    async fn seal_delegate(
        &self,
        seal: DelegateSeal<'_>,
        parties: RelayParties,
    ) -> Result<RelayProofInputs, RingRpcError> {
        let transfer = DelegateMove {
            ring: CustomRing::new(seal.ring),
            delegate: seal.delegate,
            payer: parties.fee_payer,
            sources: seal
                .sources
                .iter()
                .map(|source| DelegateSource {
                    address: source.address,
                    nullifier_key: &source.nullifier_key,
                    utxos: &source.notes,
                })
                .collect(),
            payments: seal.payments,
            assets: seal.assets,
            wide_frames: WideFrames::Buffer,
            tx_viewing_key: seal.tx_viewing_key,
        }
        .select(&self.client)
        .await
        .map_err(RelayError::proof)?;
        transfer
            .relay_proof_inputs(self.client.zolana())
            .await
            .map_err(RelayError::proof)
    }

    async fn check_enrollment(&self, enrollment: &RelayEnrollInputs) -> Result<(), RingRpcError> {
        let rpc = self.client.zolana();
        let registry = rpc
            .get_account(enrollment.tracking_registry)
            .await?
            .and_then(|account| TrackingRegistry::decode(&account.owner, &account.data))
            .ok_or(RelayError::InvalidEnrollment)?;
        let (authorization, _) =
            TrackingAuthorization::find_address(&enrollment.tracking_registry, &enrollment.owner);
        let enrolled = rpc
            .get_account(authorization)
            .await?
            .is_some_and(|account| !account.data.is_empty());
        Ok(EnrollmentProof {
            enrollment,
            registry: &registry,
            enrolled,
        }
        .check()?)
    }
}

impl<R: AsyncRpc + 'static, I: RingIndexerBackend + 'static> SdkRelayProver<R, I> {
    async fn transfer(
        &self,
        request: &RelayProofRequest<'_>,
        proof_inputs: &RelayProofInputs,
    ) -> Result<ProvenRelay, RingRpcError> {
        let mut transfer = RingTransfer::relayed(RelayedTransferInput {
            ring: CustomRing::new(request.ring),
            proof_inputs,
            fee_payer: request.parties.fee_payer,
        });
        // The relay writes the buffer of a frame past one transaction.
        transfer = transfer.with_buffered_settlement();
        if let Some(signature) = request.owner_signature {
            transfer = transfer.with_owner_signature(signature);
        }
        for co_signer in &request.parties.co_signers {
            transfer = transfer.with_co_signer(*co_signer);
        }
        let proven = transfer
            .prove(&self.client)
            .await
            .map_err(RelayError::proof)?;
        let (tag, delegate) = match proof_inputs.rail {
            RelayRail::Delegate { delegate, .. } => {
                (InstructionTag::AuthorityTransfer, Some(delegate))
            }
            _ => (InstructionTag::Transfer, None),
        };
        Ok(ProvenRelay {
            instruction: proven.instruction().map_err(RelayError::proof)?,
            budget: ComputeBudgetConfig::new(compute_unit_limit(tag)),
            co_signers: proven.co_signers.clone(),
            signers: proven
                .owner_signers()
                .iter()
                .copied()
                .chain(delegate)
                .chain(
                    proven
                        .deposit_funders()
                        .into_iter()
                        .filter(|funder| *funder != request.parties.fee_payer),
                )
                .collect(),
        })
    }

    async fn deposit(
        &self,
        request: &RelayProofRequest<'_>,
        deposit: &RelayDepositInputs,
    ) -> Result<ProvenRelay, RingRpcError> {
        let prepared = RelayedDeposit {
            ring: CustomRing::new(request.ring),
            inputs: deposit,
            fee_payer: request.parties.fee_payer,
            // A deposit demands one class, one record covers it.
            co_signer: request.parties.co_signers.first().copied(),
        }
        .prepare(self.client.zolana())
        .await
        .map_err(RelayError::proof)?;
        Ok(ProvenRelay {
            instruction: prepared
                .prove(&self.client)
                .await
                .map_err(RelayError::proof)?,
            budget: ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Deposit)),
            co_signers: prepared.co_signer().into_iter().collect(),
            signers: vec![prepared.depositor()],
        })
    }

    async fn merge(
        &self,
        request: &RelayProofRequest<'_>,
        merge: &RelayMergeInputs,
    ) -> Result<ProvenRelay, RingRpcError> {
        let owner = merge
            .sender
            .signing_pubkey
            .as_ed25519()
            .map_err(|error| RelayError::proof(error.into()))?;
        let proven = OwnerMergeProof {
            client: &self.client,
            payer: request.parties.fee_payer,
        }
        .prove(OwnerMerge {
            ring: merge.ring_program_id,
            owner: Address::new_from_array(owner),
            nullifier_key: &merge.nullifier_key,
            inputs: merge.inputs.clone(),
        })
        .await
        .map_err(RelayError::proof)?;
        Ok(ProvenRelay {
            instruction: proven
                .instruction(request.parties.fee_payer)
                .map_err(RelayError::proof)?,
            budget: ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Merge)),
            co_signers: Vec::new(),
            signers: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use bytemuck::Zeroable;
    use custom_ring_interface::{storage_instruction::EnrollIxData, CustomRingProof};
    use solana_address::Address;

    use super::*;

    /// Passes the program's field checks, a canonical key and nonzero scalars.
    fn fields() -> EnrollIxData {
        let mut ix = EnrollIxData::zeroed();
        ix.viewing_u[31] = 9;
        ix.nullifier_pk[31] = 1;
        ix
    }

    fn checked(data: Vec<u8>, enrolled: bool) -> Result<(), RelayError> {
        EnrollmentProof {
            enrollment: &RelayEnrollInputs {
                ring_program_id: Address::new_from_array([1; 32]),
                owner: Address::new_from_array([2; 32]),
                tracking_registry: Address::new_from_array([3; 32]),
                instruction_data: data,
            },
            registry: &TrackingRegistry::zeroed(),
            enrolled,
        }
        .check()
    }

    fn data(ix: &EnrollIxData, proof: Option<&CustomRingProof>) -> Vec<u8> {
        let mut data = vec![6];
        data.extend_from_slice(bytemuck::bytes_of(ix));
        if let Some(proof) = proof {
            data.extend_from_slice(bytemuck::bytes_of(proof));
        }
        data
    }

    #[test]
    fn only_a_rotation_goes_without_a_proof_and_garbage_refuses() {
        let (ix, zero_proof) = (fields(), CustomRingProof::zeroed());
        assert!(checked(data(&ix, None), true).is_ok());
        for (bytes, enrolled) in [
            (data(&ix, None), false),
            (data(&ix, Some(&zero_proof)), false),
            (data(&ix, Some(&zero_proof)), true),
            (data(&EnrollIxData::zeroed(), None), true),
            (vec![6, 1, 2, 3], true),
            (Vec::new(), true),
        ] {
            assert!(matches!(
                checked(bytes, enrolled),
                Err(RelayError::InvalidEnrollment)
            ));
        }
    }
}
