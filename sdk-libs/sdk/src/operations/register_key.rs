//! The first enrollment proves the sealed key.

use custom_ring_interface::{
    key_catalog::RingCircuit,
    storage_instruction::{tag, EnrollIxData, OwnerGrantIxData},
    tracking::TrackingAuthorization,
    CustomRingProof, ReaderKeyBytes, RegisterKeyStatement, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_client::AsyncRpc;
use spr_hasher::primitives::{right_align, solana_owner_identity};
use spr_keypair::{NullifierKey, ViewingKey};
use zeroize::Zeroizing;
use zolana_ring_client::NullifierKeyEnvelope;
use zolana_ring_keys::list_tag;

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    prover::{to_instruction_proof, RingRequest},
    request::KeyRegister,
    storage::storage_ix,
    CustomRing, RingError,
};

/// The owner signs, a wallet with its key and a PDA through its program's `invoke_signed`.
#[must_use]
pub struct Enroll<'a> {
    pub ring: CustomRing,
    pub payer: Address,
    pub owner: Address,
    pub nullifier_key: &'a NullifierKey,
    pub viewing_key: &'a ViewingKey,
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
        let envelope = NullifierKeyEnvelope::new(key, &auditor_pk)?;
        let nullifier_pk = key.pubkey()?;
        let secret = Zeroizing::new(right_align(&key.secret()));
        let list_tag = list_tag(key, &ring_id)?;
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
