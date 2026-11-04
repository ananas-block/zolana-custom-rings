//! The first enrollment proves the sealed key.

use custom_ring_interface::{
    domain,
    key_catalog::RingCircuit,
    storage_instruction::{tag, EnrollIxData, OwnerGrantIxData},
    tracking::TrackingAuthorization,
    CustomRingProof, ReaderKeyBytes, RegisterKeyStatement, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signer::Signer;
use spr_client::AsyncRpc;
use spr_hasher::primitives::{right_align, solana_owner_identity};
use spr_keypair::{NullifierKey, ViewingKey};
use zeroize::Zeroizing;
use zolana_ring_client::{
    rpc::{PrepareRelayRequest, ProofInputBytes, RelayEnrollInputs, RelayIntent, RelayQuote},
    NullifierKeyEnvelope,
};

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    prover::{to_instruction_proof, RingRequest},
    relay_message::{ExpectedEnroll, ExpectedMessage},
    request::KeyRegister,
    storage::storage_ix,
    CustomRing, MessageMismatch, PreparedRelay, RingError,
};

/// The owner signs, a wallet with its key and a PDA through its program's `invoke_signed`.
#[must_use]
pub struct Enroll<'a> {
    pub ring: CustomRing,
    pub payer: Address,
    pub owner: Address,
    pub nullifier_key: &'a NullifierKey,
    pub viewing_key: &'a ViewingKey,
    /// `ListSaltHolder::list_salt` of the ring.
    pub list_salt: [u8; 32],
}

/// The program signs through CPI for a PDA.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteOwnerGrant {
    pub payer: Address,
    pub owner: Address,
    pub tracking_registry: Address,
    pub grant: Address,
    pub reader: ReaderKeyBytes,
    pub active: bool,
}

impl Enroll<'_> {
    /// `payer` is the quoted fee payer.
    pub async fn prepare_relay<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        quote: RelayQuote,
        owner: &dyn Signer,
    ) -> Result<PreparedRelay, RingError> {
        if self.payer != quote.fee_payer.0 {
            return Err(RingError::RelayPayerMismatch {
                payer: self.payer,
                fee_payer: quote.fee_payer.0,
            });
        }
        let instruction = self.prove(client).await?;
        let config = self.ring.require_config(client.zolana()).await?;
        EnrollRelay {
            inputs: RelayEnrollInputs {
                ring_program_id: self.ring.program_id(),
                owner: self.owner,
                tracking_registry: config.account().tracking,
                instruction_data: instruction.data,
            },
            owner,
        }
        .prepare(quote)
    }

    /// The program refuses a second key for one owner.
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<Instruction, RingError> {
        let config = self.ring.require_config(client.zolana()).await?;
        let policy = config.account();
        let ring_id = self.ring.ring_id()?;
        let auditor_pk = config.auditor_pubkey;
        let key = self.nullifier_key;
        let envelope = NullifierKeyEnvelope::new(key, &self.list_salt, &auditor_pk)?;
        let nullifier_pk = key.pubkey()?;
        let secret = Zeroizing::new(right_align(&key.secret()));
        let list_tag = domain::list_tag(&self.list_salt)?;
        let member = solana_owner_identity(self.owner.as_array())?;
        let eph_u = envelope.sealed.eph_pk.u();
        let public_input_hash = RegisterKeyStatement {
            ring_id: &ring_id,
            member: &member,
            nullifier_pk: &nullifier_pk,
            list_tag: &list_tag,
            auditor_pubkey: auditor_pk.as_bytes(),
            eph_u: &eph_u,
            ciphertext: &envelope.sealed.ciphertext,
        }
        .hash()?;
        let body = KeyRegister {
            public_input_hash,
            ring_id,
            member,
            nullifier_secret: secret,
            list_salt: self.list_salt,
            eph_sk: envelope.ephemeral_sk.clone(),
            auditor_pk,
        };
        let proof = RingRequest::new(RingCircuit::RegisterKey, &body)?
            .prove(client, public_input_hash)
            .await?;
        Ok(EnrollInstruction {
            payer: self.payer,
            owner: self.owner,
            tracking_registry: policy.tracking,
            data: EnrollIxData {
                nullifier_pk,
                list_tag,
                viewing_u: self.viewing_key.pubkey().u(),
                eph_u,
                ciphertext: envelope.sealed.ciphertext,
            },
            proof: Some(to_instruction_proof(proof)?),
        }
        .instruction())
    }
}

/// An owner with no SOL, the relay pays and the owner signs the digest here and the message after.
#[must_use]
pub struct EnrollRelay<'a> {
    pub inputs: RelayEnrollInputs,
    pub owner: &'a dyn Signer,
}

impl EnrollRelay<'_> {
    /// A PDA holds no key to sign here, its program enrolls through CPI.
    pub fn prepare(self, quote: RelayQuote) -> Result<PreparedRelay, RingError> {
        if self.owner.try_pubkey()? != self.inputs.owner {
            return Err(MessageMismatch::Signer.into());
        }
        let owner_signature = self
            .owner
            .try_sign_message(&self.inputs.request_digest())?
            .into();
        let expected = ExpectedEnroll {
            fee_payer: quote.fee_payer.0,
            inputs: self.inputs.clone(),
        };
        Ok(PreparedRelay::new(PrepareRelayRequest {
            ring: self.inputs.ring_program_id.into(),
            quote,
            intent: RelayIntent::Enroll {
                proof_inputs: ProofInputBytes::new(Zeroizing::new(self.inputs.encode()?)),
                owner_signature,
            },
            co_signers: Vec::new(),
        })
        .expecting(ExpectedMessage::Enroll(expected)))
    }
}

/// A first enrollment holds the proof, a rotation none.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollInstruction {
    pub payer: Address,
    pub owner: Address,
    pub tracking_registry: Address,
    pub data: EnrollIxData,
    pub proof: Option<CustomRingProof>,
}

impl EnrollInstruction {
    pub fn instruction(self) -> Instruction {
        let (authorization, _) =
            TrackingAuthorization::find_address(&self.tracking_registry, &self.owner);
        let mut data = vec![tag::ENROLL];
        data.extend_from_slice(bytemuck::bytes_of(&self.data));
        if let Some(proof) = &self.proof {
            data.extend_from_slice(bytemuck::bytes_of(proof));
        }
        storage_ix(
            vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.owner, true),
                AccountMeta::new(self.tracking_registry, false),
                AccountMeta::new(authorization, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data,
        )
    }
}

impl WriteOwnerGrant {
    pub fn instruction(self) -> Instruction {
        let data = OwnerGrantIxData {
            reader: self.reader,
            active: u8::from(self.active),
        };
        storage_ix(
            vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.owner, true),
                AccountMeta::new_readonly(self.tracking_registry, false),
                AccountMeta::new(self.grant, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            [&[tag::OWNER_GRANT][..], bytemuck::bytes_of(&data)].concat(),
        )
    }
}
