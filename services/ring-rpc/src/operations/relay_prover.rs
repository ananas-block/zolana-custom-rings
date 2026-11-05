use async_trait::async_trait;
use custom_ring_interface::{
    compute_unit_limit, tag, EnrollRequest, Enrollment, InstructionTag, RegisterKeyCheck,
    TAGGED_X25519_KEY_LEN,
};
use custom_ring_sdk::{
    AllowedNullifiers, CustomRing, DelegateMove, DelegatePayment, DelegateSource, RelayedDeposit,
    RelayedTransferInput, RingClient, RingIndexerBackend, RingTransfer,
};
use solana_address::Address;
use solana_instruction::Instruction;
use spr_client::{AsyncRpc, ComputeBudgetConfig};
use spr_keypair::{NullifierKey, ShieldedAddress, ViewingKey};
use spr_transaction::{AssetRegistry, WalletUtxo};
use zolana_ring_client::rpc::{
    CredentialAccounts, RelayDepositInputs, RelayEnrollInputs, RelayMergeInputs, RelayProofInputs,
    RelayRail,
};
use zolana_ring_policy::ring_id_field;

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

    /// Refuses a RegisterKey proof the program would refuse and a reserved address, ahead of any charge.
    async fn check_enrollment(&self, enrollment: &RelayEnrollInputs) -> Result<(), RingRpcError>;
}

/// The RegisterKey check the ring program runs, over the credential it rebuilds.
#[must_use]
struct EnrollmentProof<'a> {
    enrollment: &'a RelayEnrollInputs,
    /// Read from the ring account, never from the request.
    auditor_pubkey: &'a [u8; TAGGED_X25519_KEY_LEN],
}

impl EnrollmentProof<'_> {
    fn check(self) -> Result<(), RelayError> {
        let Some((&tag::ENROLL, data)) = self.enrollment.instruction_data.split_first() else {
            return Err(RelayError::InvalidEnrollment);
        };
        let request = EnrollRequest::parse(data).map_err(refused)?;
        // The program's constructor binds the ring, the signing owner and the ring's auditor key.
        let credential = Enrollment {
            ring_id: &ring_id_field(self.enrollment.ring_program_id.as_array()).map_err(refused)?,
            auditor_pubkey: self.auditor_pubkey,
            owner: &self.enrollment.owner,
            ix: request.ix,
        }
        .credential()
        .map_err(refused)?;
        RegisterKeyCheck {
            credential: &credential,
            proof: request.register_key,
        }
        .verify()
        .map_err(|_| RelayError::RegisterKeyProof)
    }
}

fn refused<E>(_: E) -> RelayError {
    RelayError::InvalidEnrollment
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
        let credential = CredentialAccounts::derive(&enrollment.ring_program_id, &enrollment.owner)
            .map_err(RelayError::from)?;
        if rpc.get_account(credential.nullifier_pda).await?.is_some() {
            return Err(RelayError::AlreadyEnrolled.into());
        }
        let config = CustomRing::new(enrollment.ring_program_id)
            .require_config(rpc)
            .await
            .map_err(RelayError::proof)?;
        Ok(EnrollmentProof {
            enrollment,
            auditor_pubkey: config.auditor_pubkey.as_bytes(),
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
        .map_err(|error| RelayError::proof(*error))?;
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
    use custom_ring_interface::{CustomRingProof, EnrollIxData};
    use solana_address::Address;
    use spr_interface::instruction::TransactProof;

    use super::*;

    /// Passes the program's field checks, a nonzero canonical key.
    fn fields() -> EnrollIxData {
        let mut ix = EnrollIxData::zeroed();
        ix.nullifier_pk[31] = 1;
        ix
    }

    fn data(ix: &EnrollIxData) -> Vec<u8> {
        let request = EnrollRequest {
            ix,
            register_key: &CustomRingProof::zeroed(),
            transact: TransactProof::zeroed(),
            address_root_index: 0,
        };
        [&[tag::ENROLL][..], &request.encode().unwrap()].concat()
    }

    fn checked(instruction_data: Vec<u8>) -> Result<(), RelayError> {
        EnrollmentProof {
            enrollment: &RelayEnrollInputs {
                ring_program_id: Address::new_from_array([1; 32]),
                owner: Address::new_from_array([2; 32]),
                output_tree: Address::new_from_array([3; 32]),
                instruction_data,
            },
            auditor_pubkey: &[4; TAGGED_X25519_KEY_LEN],
        }
        .check()
    }

    #[test]
    fn an_unproven_or_malformed_enrollment_refuses() {
        assert!(matches!(
            checked(data(&fields())),
            Err(RelayError::RegisterKeyProof)
        ));
        let mut storage_tag = data(&fields());
        storage_tag[0] = 6;
        let mut trailing = data(&fields());
        trailing.push(0);
        let zero_key = EnrollIxData {
            nullifier_pk: spr_interface::ZERO_NULLIFIER_PUBKEY,
            ..fields()
        };
        for bytes in [
            data(&zero_key),
            storage_tag,
            trailing,
            vec![tag::ENROLL, 1, 2, 3],
            Vec::new(),
        ] {
            assert!(matches!(checked(bytes), Err(RelayError::InvalidEnrollment)));
        }
    }
}
