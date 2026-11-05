//! Ring `Enroll` turns the owner's sealed nullifier key into one immutable credential.
//!
//! The wallet proves two statements over one `AuditCredential` value. RegisterKey binds ring, member,
//! nullifier key, list tag, auditor key and ciphertext. The SPP proof reserves the credential address
//! in tree 0 and creates the credential UTXO under the ring's credential PDA. The program rebuilds the
//! credential from the ring account and the signing owner, so a proof for any other value fails.
//!
//! A signed attempt is recorded before its broadcast and reconciled by signature and by the address
//! nullifier PDA. The fixed address makes a second landing impossible, a resubmission waits for expiry.
//!
//! Read after `sdk-libs/client/src/rpc/relay_enroll.rs` and
//! `programs/custom-ring/src/instructions/enrollment/enroll.rs`.
//! Read before `services/ring-rpc/src/operations/relay.rs`.

use std::error::Error as StdError;

use async_trait::async_trait;
use borsh::BorshDeserialize;
use custom_ring_interface::{
    domain,
    key_catalog::RingCircuit,
    storage_instruction::{tag as storage_tag, OwnerGrantIxData},
    tag, AuditCredential, EnrollIxData, EnrollRequest, Enrollment, InstructionTag, OwnerGrant,
    ReaderKeyBytes, SYSTEM_PROGRAM_ID,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction_error::TransactionError;
use spr_client::{
    compile_message, sign_transaction, transaction_size, AsyncRpc, RpcSendTransactionConfig,
};
use spr_hasher::primitives::right_align;
use spr_interface::{
    event::OutputDataEncoding,
    instruction::instruction_data::transact::{
        TransactIxData, TransactProof, TreeContext, NO_UTXO_ROOT,
    },
    ZERO_NULLIFIER_PUBKEY,
};
use spr_keypair::{
    constants::BLINDING_LEN, NullifierKey, PublicKey, ShieldedAddress, X25519Pubkey,
};
use spr_program::{
    derive_output_blinding_seed, derive_transact_output_blinding,
    program::{SppTransactCpi, UniqueDataUtxo, ACCOUNT_BLINDING_SEED},
    ADDRESS_TREE_ID,
};
use spr_transaction::{
    instructions::transact::SppProofInputs, utxo::SppProofInputUtxo, ExternalData, Mint,
    SppProofOutputUtxo,
};
use spr_user_registry_interface::{
    instruction::{register, RegisterData},
    user_record_pda,
};
use wincode::{SchemaRead, SchemaWrite};
use zeroize::Zeroizing;
use zolana_ring_client::{
    rpc::{
        CredentialAccounts, EnrollAccounts, PrepareRelayRequest, ProofInputBytes,
        RelayEnrollInputs, RelayIntent, RelayQuote,
    },
    NullifierKeyEnvelope, ViewingKeyError, ViewingKeyResolver,
};

use crate::client::{RingClient, RingIndexerBackend};
use crate::{
    prover::{to_instruction_proof, RingRequest},
    relay_message::{ExpectedEnroll, ExpectedMessage},
    request::KeyRegister,
    storage::storage_ix,
    submission::{check_transaction_size, outcome, send_budget, transaction_error, Outcome},
    trees::tree_id,
    CustomRing, CustomRingConfig, MessageMismatch, PreparedRelay, RingError,
};

#[cfg(test)]
#[path = "../tests/operations/enrollment.rs"]
mod tests;

/// `payer` funds the fees and authorizes nothing.
#[must_use]
pub struct Enroll<'a> {
    pub ring: CustomRing,
    pub owner: Address,
    pub payer: Address,
    pub output_tree: Address,
    pub nullifier_key: &'a NullifierKey,
    /// `ListSaltHolder::list_salt` of the ring.
    pub list_salt: [u8; 32],
    /// Registered with the nullifier key when the owner holds no `UserRecord`.
    pub viewing_pubkey: X25519Pubkey,
}

#[must_use]
#[derive(Clone, Debug)]
pub struct ProvenEnrollment {
    pub instruction: EnrollInstruction,
    pub credential: AuditCredential,
    pub address: [u8; 32],
}

/// For a PDA owner its program passes `instruction()` to `invoke_signed`.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct EnrollInstruction {
    pub accounts: EnrollAccounts,
    /// The ring `Enroll` tag, then `EnrollRequest::encode`.
    pub data: Vec<u8>,
    /// `REGISTER` runs ahead of `Enroll` in the same transaction, `None` for a registered owner.
    pub registration: Option<UserRegistration>,
}

/// The keys zolana `REGISTER` stores, the nullifier key equal to the credential's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaWrite, SchemaRead)]
pub struct UserRegistration {
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: [u8; 33],
}

/// The owner signs the request digest here and the relayed message after.
#[must_use]
pub struct EnrollRelay<'a> {
    pub inputs: RelayEnrollInputs,
    pub owner: &'a dyn Signer,
}

#[async_trait]
pub trait EnrollmentJournal: Send + Sync {
    /// Returns once `attempt` survives a restart, the broadcast follows only `Ok`.
    async fn record(
        &self,
        attempt: &EnrollmentAttempt,
    ) -> Result<(), Box<dyn StdError + Send + Sync>>;
}

#[must_use]
#[derive(Clone, Debug, PartialEq, SchemaWrite, SchemaRead)]
pub struct EnrollmentAttempt {
    pub instruction: EnrollInstruction,
    pub transaction: VersionedTransaction,
    pub last_valid_block_height: u64,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollmentOutcome {
    Landed {
        slot: u64,
    },
    Failed(TransactionError),
    /// The attempt shows no landing and an `Enroll` holds the owner's address, ours or another.
    Reserved,
    /// The attempt can still land.
    Pending,
    /// No landing and no reservation past the blockhash, the same request may go again.
    Expired,
}

struct CredentialCreation<'a> {
    credential: &'a AuditCredential,
    accounts: &'a CredentialAccounts,
    output_tree_id: u16,
}

struct ProvenCreation {
    transact: TransactProof,
    address_root_index: u16,
}

/// X25519 base point, the SPP owner hash takes no viewing key.
const UNSEALED_VIEWER_U: [u8; 32] = {
    let mut u = [0u8; 32];
    u[0] = 9;
    u
};

impl Enroll<'_> {
    /// The program refuses a second credential for one owner, the SDK refuses before proving.
    pub async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<ProvenEnrollment, RingError> {
        let ring_program_id = self.ring.program_id();
        // 1. A reserved address refuses here. A credential never changes, a retry reuses the attempt.
        let accounts = CredentialAccounts::derive(&ring_program_id, &self.owner)?;
        if client.get_account(accounts.nullifier_pda).await?.is_some() {
            return Err(RingError::AlreadyEnrolled { owner: self.owner });
        }
        let registration = self.registration(client).await?;
        // 2. The program's constructor builds the credential from the ring account and the owner, so
        // the proofs below commit to the value the program rebuilds.
        let config = self.ring.require_config(client.zolana()).await?;
        let envelope =
            NullifierKeyEnvelope::new(self.nullifier_key, &self.list_salt, &config.auditor_pubkey)?;
        let ix = EnrollIxData {
            nullifier_pk: self.nullifier_key.pubkey()?,
            list_tag: domain::list_tag(&self.list_salt)?,
            eph_u: envelope.sealed.eph_pk.u(),
            ciphertext: envelope.sealed.ciphertext,
        };
        let credential = self.credential(&config, &ix)?;
        // 3. RegisterKey proves the ciphertext opens to the nullifier secret and list salt.
        let public_input_hash = credential.register_key_hash()?;
        let body = KeyRegister {
            public_input_hash,
            ring_id: credential.ring_id,
            member: credential.member,
            nullifier_secret: Zeroizing::new(right_align(&self.nullifier_key.secret())),
            list_salt: self.list_salt,
            eph_sk: envelope.ephemeral_sk.clone(),
            auditor_pk: config.auditor_pubkey,
        };
        let register_key = RingRequest::new(RingCircuit::RegisterKey, &body)?
            .prove(client, public_input_hash)
            .await?;
        // 4. The SPP proof reserves the address and creates the exact output the program builds.
        let creation = CredentialCreation {
            credential: &credential,
            accounts: &accounts,
            output_tree_id: tree_id(client.zolana(), self.output_tree).await?,
        };
        let ProvenCreation {
            transact,
            address_root_index,
        } = creation.prove(client, self.payer).await?;
        let request = EnrollRequest {
            ix: &ix,
            register_key: &to_instruction_proof(register_key)?,
            transact,
            address_root_index,
        };
        Ok(ProvenEnrollment {
            instruction: EnrollInstruction {
                accounts: self.accounts(),
                data: [&[tag::ENROLL][..], &request.encode()?].concat(),
                registration,
            },
            credential,
            address: accounts.address,
        })
    }

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
        // The relay carries `Enroll` alone and funds no record rent.
        if self.registration(client).await?.is_some() {
            return Err(RingError::RelayNeedsUserRecord { owner: self.owner });
        }
        let proven = self.prove(client).await?;
        EnrollRelay {
            inputs: RelayEnrollInputs {
                ring_program_id: self.ring.program_id(),
                owner: self.owner,
                output_tree: self.output_tree,
                instruction_data: proven.instruction.data,
            },
            owner,
        }
        .prepare(quote)
    }

    pub fn credential(
        &self,
        config: &CustomRingConfig,
        ix: &EnrollIxData,
    ) -> Result<AuditCredential, RingError> {
        Ok(Enrollment {
            ring_id: &self.ring.ring_id()?,
            auditor_pubkey: config.auditor_pubkey.as_bytes(),
            owner: &self.owner,
            ix,
        }
        .credential()?)
    }

    /// An RPC failure or a malformed record is an error, never a missing record.
    async fn registration<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<Option<UserRegistration>, RingError> {
        // `UPDATE_KEYS` never changes a nullifier key, a record under another key refuses for good.
        let nullifier_pubkey = self.nullifier_key.pubkey()?;
        let record = ViewingKeyResolver::new(self.owner)
            .with_credential(nullifier_pubkey)
            .resolve(client.zolana())
            .await;
        match record {
            Ok(Some(_)) => Ok(None),
            Ok(None) => Ok(Some(UserRegistration {
                nullifier_pubkey,
                viewing_pubkey: *self.viewing_pubkey.as_bytes(),
            })),
            Err(ViewingKeyError::NullifierKeyMismatch) => {
                Err(RingError::UserRecordKeyMismatch { owner: self.owner })
            }
            Err(error) => Err(RingError::UserRecord(error)),
        }
    }

    fn accounts(&self) -> EnrollAccounts {
        EnrollAccounts {
            ring_program_id: self.ring.program_id(),
            owner: self.owner,
            payer: self.payer,
            output_tree: self.output_tree,
        }
    }
}

impl CredentialCreation<'_> {
    /// A proven transaction other than the one the program builds fails here, not on chain.
    async fn prove<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        payer: Address,
    ) -> Result<ProvenCreation, RingError> {
        // The PDA owner's nullifier secret is zero, the address slot carries it already.
        let pda_key = NullifierKey::from_secret([0; BLINDING_LEN]);
        let proven = client
            .zolana()
            .prove_transact(self.proof_inputs(payer)?, None, &pda_key)
            .await?;
        // The program passes NO_UTXO_ROOT, the address slot reads only a tree 0 nullifier root.
        let [TreeContext {
            utxo_tree_root_index: NO_UTXO_ROOT,
            nullifier_tree_root_index: address_root_index,
        }] = proven.tree_contexts[..]
        else {
            return Err(RingError::EnrollmentMismatch);
        };
        let unproven = TransactIxData {
            proof: TransactProof::zeroed(),
            ..proven.clone()
        };
        if unproven != self.program_data(address_root_index)? {
            return Err(RingError::EnrollmentMismatch);
        }
        Ok(ProvenCreation {
            transact: proven.proof,
            address_root_index,
        })
    }

    /// `UniqueDataUtxo::new_init` and `SppTransactCpi` exactly as `Enroll` calls them.
    fn program_data(&self, address_root_index: u16) -> Result<TransactIxData, RingError> {
        let mut output = UniqueDataUtxo::new_init(
            &self.accounts.owner,
            self.credential.seed()?,
            TreeContext {
                utxo_tree_root_index: NO_UTXO_ROOT,
                nullifier_tree_root_index: address_root_index,
            },
        )?;
        *output = *self.credential;
        Ok(SppTransactCpi::new(TransactProof::zeroed())
            .with_unique_data_utxo(output)?
            .into_ix_data(self.output_tree_id)?)
    }

    /// One address slot and one credential output, compact padding fills the 2x2 shape.
    fn proof_inputs(&self, payer: Address) -> Result<SppProofInputs, RingError> {
        let address = &self.accounts.address;
        let pda = self.accounts.owner.pda();
        // 1. The published output and its payload come from the program's builder, never a copy.
        let program = self.program_data(0)?;
        let [published] = program.outputs.as_slice() else {
            return Err(RingError::EnrollmentMismatch);
        };
        let Some(OutputDataEncoding::Plaintext(payload)) = published
            .data
            .as_deref()
            .and_then(|data| OutputDataEncoding::try_from_slice(data).ok())
        else {
            return Err(RingError::EnrollmentMismatch);
        };
        // 2. The address is the only and first nullifier, so it seeds every output blinding.
        let seed = derive_output_blinding_seed(address, &ACCOUNT_BLINDING_SEED)?;
        let credential = SppProofOutputUtxo {
            asset: Mint::SOL,
            amount: 0,
            blinding: derive_transact_output_blinding(address, &seed, 0)?,
            owner_address: Some(ShieldedAddress::for_pda(
                pda,
                ZERO_NULLIFIER_PUBKEY,
                X25519Pubkey::from_u(UNSEALED_VIEWER_U)?,
            )),
            owner_tag: Some(pda.to_bytes()),
            ..SppProofOutputUtxo::default()
        }
        .with_utxo_data(payload, self.credential.data_hash(address)?);
        let padding = SppProofOutputUtxo {
            blinding: derive_transact_output_blinding(address, &seed, 1)?,
            compact: true,
            ..SppProofOutputUtxo::default()
        };
        // 3. The reservation slot derives the same address `NewAddress::derive` gives the program.
        let reservation = SppProofInputUtxo::new_address(
            PublicKey::from_pda(pda),
            *self.credential.seed()?.as_bytes(),
            ADDRESS_TREE_ID,
        )?;
        if reservation.nullifier != *address {
            return Err(RingError::EnrollmentMismatch);
        }
        Ok(SppProofInputs {
            input_utxos: vec![reservation, SppProofInputUtxo::compact(ADDRESS_TREE_ID)?],
            output_utxos: vec![credential, padding],
            blinding_seed: ACCOUNT_BLINDING_SEED,
            output_tree_id: self.output_tree_id,
            external_data: ExternalData::new(
                [0; 33],
                [0; 16],
                program.outputs,
                vec![pda.to_bytes()],
                Vec::new(),
            ),
            payer,
            cache_accounts: Default::default(),
        })
    }
}

impl EnrollInstruction {
    /// A PDA owner's program issues each one through CPI, in order.
    pub fn instructions(&self) -> Result<Vec<Instruction>, RingError> {
        let EnrollAccounts { owner, payer, .. } = self.accounts;
        let register = self.registration.map(|keys| {
            register(
                user_record_pda(&owner).0,
                owner,
                payer,
                RegisterData {
                    nullifier_pubkey: keys.nullifier_pubkey,
                    viewing_pubkey: keys.viewing_pubkey,
                },
            )
        });
        let enroll = self.accounts.instruction(self.data.clone())?;
        Ok(register.into_iter().chain([enroll]).collect())
    }

    /// `Ok` means recorded and broadcast or in doubt, a preflight refusal returns its error.
    pub async fn submit<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
        signers: &[&(dyn Signer + Sync)],
        journal: &dyn EnrollmentJournal,
    ) -> Result<EnrollmentAttempt, RingError> {
        // 1. The payer heads the message, the owner signs beside it unless it is the payer. The
        // enrollment fit covers its SPP call, the message size covers a prepended `REGISTER` too.
        let instructions = self.instructions()?;
        let budget = send_budget(InstructionTag::Enroll, None);
        let payer = &self.accounts.payer;
        if let Some(enroll) = instructions.last() {
            check_transaction_size(payer, enroll, budget)?;
        }
        let size = transaction_size(payer, &instructions, budget)?;
        if !size.fits() {
            return Err(RingError::TransactionTooLarge {
                bytes: size.bytes,
                limit: solana_message::v1::MAX_TRANSACTION_SIZE,
            });
        }
        let (blockhash, last_valid_block_height) = client.get_latest_blockhash().await?;
        let message = compile_message(payer, &instructions, blockhash, budget)?;
        let transaction = {
            let all: Vec<&dyn Signer> = signers
                .iter()
                .map(|signer| *signer as &dyn Signer)
                .collect();
            sign_transaction(message, &all)?
        };
        let attempt = EnrollmentAttempt {
            instruction: self.clone(),
            transaction,
            last_valid_block_height,
        };
        // 2. The attempt is durable before any byte leaves, a crash after the send still reconciles.
        journal
            .record(&attempt)
            .await
            .map_err(RingError::AttemptNotRecorded)?;
        // 3. Only a preflight refusal proves the bytes did not land, any other error stays in doubt.
        let config = RpcSendTransactionConfig {
            preflight_commitment: Some(solana_commitment_config::CommitmentLevel::Confirmed),
            ..RpcSendTransactionConfig::default()
        };
        match client
            .send_transaction_with_config(&attempt.transaction, config)
            .await
            .err()
            .and_then(transaction_error)
        {
            Some(refused) => Err(RingError::EnrollmentRefused(refused)),
            None => Ok(attempt),
        }
    }
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

impl EnrollmentAttempt {
    pub fn signature(&self) -> Signature {
        self.transaction.signatures[0]
    }

    pub fn encode(&self) -> Result<Vec<u8>, RingError> {
        Ok(wincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RingError> {
        wincode::deserialize_exact(bytes).map_err(|_| RingError::AttemptUnreadable)
    }

    /// An RPC failure is an error, never an expiry.
    pub async fn reconcile<R: AsyncRpc, I: RingIndexerBackend>(
        &self,
        client: &RingClient<R, I>,
    ) -> Result<EnrollmentOutcome, RingError> {
        // 1. The attempt's own status decides first, a landed attempt is the credential.
        let observed = outcome(
            client.zolana(),
            self.signature(),
            self.last_valid_block_height,
        )
        .await?;
        if let Outcome::Confirmed { slot } = observed {
            return Ok(EnrollmentOutcome::Landed { slot });
        }
        // 2. A live nullifier PDA means some `Enroll` reserved the address. Its batch apply closes the
        // PDA later, a resubmission then fails in SPP on the address and spends only its fee.
        let credential = CredentialAccounts::derive(
            &self.instruction.accounts.ring_program_id,
            &self.instruction.accounts.owner,
        )?;
        if client
            .get_account(credential.nullifier_pda)
            .await?
            .is_some()
        {
            return Ok(EnrollmentOutcome::Reserved);
        }
        Ok(match observed {
            Outcome::Unknown => EnrollmentOutcome::Pending,
            Outcome::Failed(TransactionError::BlockhashNotFound) => EnrollmentOutcome::Expired,
            Outcome::Failed(error) | Outcome::Stale(error) => EnrollmentOutcome::Failed(error),
            Outcome::Confirmed { slot } => EnrollmentOutcome::Landed { slot },
        })
    }

    pub async fn resubmit<R: AsyncRpc, I: RingIndexerBackend>(
        self,
        client: &RingClient<R, I>,
        signers: &[&(dyn Signer + Sync)],
        journal: &dyn EnrollmentJournal,
    ) -> Result<EnrollmentAttempt, RingError> {
        match self.reconcile(client).await? {
            EnrollmentOutcome::Expired => self.instruction.submit(client, signers, journal).await,
            settled => Err(RingError::AttemptNotExpired(settled)),
        }
    }
}

/// A PDA owner's on-chain reader grant, its program signs through CPI. The grant address binds the
/// ring program, the owner and the reader, so the builder derives it and takes no address.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteOwnerGrant {
    pub payer: Address,
    pub owner: Address,
    pub ring: CustomRing,
    pub reader: ReaderKeyBytes,
    pub active: bool,
}

impl WriteOwnerGrant {
    pub fn grant(&self) -> Address {
        OwnerGrant::find_address(&self.ring.program_id(), &self.owner, &self.reader).0
    }

    pub fn instruction(self) -> Instruction {
        let data = OwnerGrantIxData {
            ring_program: self.ring.program_id(),
            reader: self.reader,
            active: u8::from(self.active),
        };
        storage_ix(
            vec![
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(self.owner, true),
                AccountMeta::new(self.grant(), false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            [&[storage_tag::OWNER_GRANT][..], bytemuck::bytes_of(&data)].concat(),
        )
    }
}
