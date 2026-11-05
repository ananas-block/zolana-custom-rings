//! Ring `Enroll` accounts and the relayed request an owner with no SOL signs.
//!
//! The credential PDA, its address and the address nullifier PDA derive from the ring program and the
//! owner alone. No caller names them, so a wallet, the relay and the program agree on one identity.
//!
//! Read after `program-libs/interface/src/accounts/credential.rs`.
//! Read before `sdk-libs/sdk/src/operations/enrollment.rs` and `services/ring-rpc/src/operations/relay.rs`.

use custom_ring_interface::{
    credential::owner_member, AuditCredential, CREDENTIAL_PDA_SEED, SYSTEM_PROGRAM_ID,
};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use spr_interface::{pda, SHIELDED_POOL_PROGRAM_ID};
use spr_program::{
    program::{NewAddress, PdaOwner},
    ADDRESS_TREE_ID,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_ring_policy::ring_id_field;

use super::RelayProofInputsError;

/// The one credential identity of an owner in a ring.
#[derive(Clone, Copy)]
pub struct CredentialAccounts {
    pub pda: Address,
    pub owner: PdaOwner,
    /// The address slot nullifier, the key of the credential.
    pub address: [u8; 32],
    /// SPP creates it with the reservation and closes it after the address tree batch applies.
    pub nullifier_pda: Address,
}

impl CredentialAccounts {
    pub fn derive(
        ring_program_id: &Address,
        owner: &Address,
    ) -> Result<Self, RelayProofInputsError> {
        // 1. The program signs only for its canonical credential PDA, never the ring settlement PDA.
        let (pda, _) = Address::find_program_address(&[CREDENTIAL_PDA_SEED], ring_program_id);
        let owner_pda = PdaOwner::new(&pda)?;
        // 2. CRCA reads ring and member alone, the other credential fields cannot move the address.
        let seed = AuditCredential {
            ring_id: ring_id_field(ring_program_id.as_array())?,
            member: owner_member(owner)?,
            ..AuditCredential::default()
        }
        .seed()?;
        let address = *NewAddress::derive(&owner_pda, seed)?.address();
        // 3. Tree 0 holds every credential address, its nullifier PDA refuses a second reservation.
        let (nullifier_pda, _) = pda::nullifier_pda(&address_tree(), &address);
        Ok(Self {
            pda,
            owner: owner_pda,
            address,
            nullifier_pda,
        })
    }
}

/// The tree 0 account every credential address enters.
pub fn address_tree() -> Address {
    pda::tree(ADDRESS_TREE_ID)
}

/// `owner, ring, payer, output_tree, spp_program, system_program, address_tree, nullifier_pda,
/// credential_pda`, the program hands SPP every account from `payer` on.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct EnrollAccounts {
    pub ring_program_id: Address,
    pub owner: Address,
    pub payer: Address,
    pub output_tree: Address,
}

impl EnrollAccounts {
    /// `data` starts with the ring `Enroll` tag. A PDA owner signs its meta through its program's CPI.
    pub fn instruction(self, data: Vec<u8>) -> Result<Instruction, RelayProofInputsError> {
        let credential = CredentialAccounts::derive(&self.ring_program_id, &self.owner)?;
        let ring = Address::find_program_address(
            &[custom_ring_interface::RingPolicy::SEED],
            &self.ring_program_id,
        )
        .0;
        Ok(Instruction {
            program_id: self.ring_program_id,
            accounts: vec![
                AccountMeta::new_readonly(self.owner, true),
                AccountMeta::new_readonly(ring, false),
                AccountMeta::new(self.payer, true),
                AccountMeta::new(self.output_tree, false),
                AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new(address_tree(), false),
                AccountMeta::new(credential.nullifier_pda, false),
                AccountMeta::new_readonly(credential.pda, false),
            ],
            data,
        })
    }
}

/// `Enroll` data as the wallet built it, both proofs proven and its owner's signature still due.
#[derive(Clone, Debug, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct RelayEnrollInputs {
    pub ring_program_id: Address,
    pub owner: Address,
    /// The SPP proof binds its id into the credential UTXO hash.
    pub output_tree: Address,
    /// The ring `Enroll` tag first, the program holds every field to both proofs.
    pub instruction_data: Vec<u8>,
}

const ENROLL_REQUEST_DOMAIN: &[u8] = b"zolana/ring-rpc-relay-enroll";

impl RelayEnrollInputs {
    /// The owner's signature over it spends the relay's budget, it names no quote so a retry keeps it.
    pub fn request_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(ENROLL_REQUEST_DOMAIN)
            .chain_update(self.ring_program_id.as_ref())
            .chain_update(self.owner.as_ref())
            .chain_update(self.output_tree.as_ref())
            .chain_update(&self.instruction_data)
            .finalize()
            .into()
    }

    pub fn instruction(&self, fee_payer: Address) -> Result<Instruction, RelayProofInputsError> {
        EnrollAccounts {
            ring_program_id: self.ring_program_id,
            owner: self.owner,
            payer: fee_payer,
            output_tree: self.output_tree,
        }
        .instruction(self.instruction_data.clone())
    }

    pub fn encode(&self) -> Result<Vec<u8>, RelayProofInputsError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RelayProofInputsError> {
        Ok(wincode::deserialize_exact(bytes)?)
    }
}
