//! Audit credentials of one ring, read from its finalized enrollments and opened with the auditor key.
//!
//! Enroll writes one immutable `AuditCredential` per owner as an SPP data UTXO under the ring's
//! credential PDA, and the PDA bytes are the output's view tag. The finalized history binds every row
//! to its confirmed SPP event. SPP admits an output under the credential owner hash only when the PDA
//! signs, and only Enroll signs for it. An output whose hash and payload rebuild from the decoded
//! credential is therefore a verified enrollment without a state proof.
//!
//! A scan moves its position only past a page whose every credential verified, resolved its owner and
//! opened. On the lease holder the page commits with that position before the move. A held
//! credential is never replaced, and a page naming a held member with other contents refuses whole.
//! A missing credential reads as unknown until a scan ends on a terminal page.
//!
//! Read after `rpc/finalized_history.rs` and `program-libs/interface/src/accounts/credential.rs`.
//! Read before `operations/audit.rs`, the caller holding the backfill lock.

use std::{collections::HashMap, future::Future, num::NonZeroU32};

use borsh::BorshDeserialize;
use custom_ring_interface::{domain, AuditCredential, CREDENTIAL_PDA_SEED};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{ClientError, GetShieldedTransactionsByTagsResponse};
use spr_event::OutputDataEncoding;
use spr_interface::instruction::{TransactOutput, TransactProof, TreeContext};
use spr_keypair::{hash::owner_hash, NullifierKey, PublicKey, X25519Keypair, X25519Pubkey};
use spr_program::program::{PdaOwner, SppTransactCpi, UniqueDataUtxo};
use spr_transaction::{OutputSlot, ShieldedTransaction};
use thiserror::Error;
use zolana_ring_client::{
    history::{HistoryPosition, PageEnd},
    open_credential,
    rpc::WalletEnrollment,
    CredentialSecrets, UnknownCredential,
};
use zolana_ring_policy::{ring_id_field, Member, MemberError};

use crate::{
    error::RingRpcError,
    spent_index::ProjectionWriter,
    upstream::{TransactionPage, TransactionSource},
    utxos::AuditStore,
};

const CREDENTIAL_PAGE_ROWS: NonZeroU32 = NonZeroU32::MIN.saturating_add(99);
/// The next refresh resumes from the position the cap leaves.
pub(crate) const MAX_CREDENTIAL_PAGES: usize = 64;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CredentialRefusal {
    #[error("a credential page is truncated, misordered or names an event outside its row")]
    PageShape,
    #[error("a credential output does not rebuild to its confirmed hash and payload")]
    OutputMismatch,
    #[error("a credential names another ring")]
    ForeignRing,
    #[error("a credential is sealed to another auditor key")]
    ForeignAuditor,
    #[error("a credential does not open to its nullifier key and list tag")]
    Sealed,
    #[error("no account of the enrollment hashes to the credential member")]
    OwnerUnresolved,
    #[error("a held credential member names other contents")]
    Conflict,
    #[error("credential discovery has not reached its terminal page")]
    Incomplete,
    #[error("the credential PDA or ring identity does not hash")]
    PdaIdentity,
}

pub(crate) struct CredentialPda {
    ring: Address,
    pda: Address,
    owner: PdaOwner,
    ring_id: [u8; 32],
}

/// Verified against its confirmed output, the auditor opened it once at admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldCredential {
    pub(crate) owner_key: [u8; 32],
    pub(crate) owner_hash: [u8; 32],
    pub(crate) address: [u8; 32],
    pub(crate) credential: AuditCredential,
    pub(crate) leaf: CredentialLeaf,
    /// `Member::salted(member, list_salt)`, the key a salted list writes for the owner.
    pub(crate) list_key: [u8; 32],
}

/// `utxo_hash` binds `tree_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialLeaf {
    pub utxo_hash: [u8; 32],
    pub tree_id: u16,
    pub leaf_index: u64,
}

/// `Unknown` only while the scan has not reached its terminal page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OwnerCredential {
    Held(Box<HeldCredential>),
    Absent,
    Unknown,
}

/// Mutated only by a scan, the scan runs under the backfill lock.
#[derive(Default)]
pub(crate) struct HeldCredentials {
    by_member: HashMap<[u8; 32], HeldCredential>,
    /// Owner hash to member, the deposit capsule names the owner by its hash.
    members: HashMap<[u8; 32], [u8; 32]>,
    /// List key to member, a salted write names the owner by its list key.
    list_keys: HashMap<[u8; 32], [u8; 32]>,
}

/// Rebuilt from its confirmed output, owner and opening still unchecked.
struct FoundCredential {
    address: [u8; 32],
    credential: AuditCredential,
    leaf: CredentialLeaf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScanEnd {
    /// The terminal page answered, every finalized enrollment through its slot is held.
    Complete,
    /// The page cap stopped the scan, an owner not held reads as unknown.
    Partial,
}

/// Unverified pages and transaction accounts, `CredentialScan` checks both.
pub(crate) trait CredentialSource: Sync {
    fn credential_page(
        &self,
        request: TransactionPage,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send;

    fn transaction_accounts(
        &self,
        signature: Signature,
    ) -> impl Future<Output = Result<Vec<Address>, ClientError>> + Send;
}

#[must_use]
pub(crate) struct CredentialScan<'a, C> {
    pub ring: Address,
    pub auditor: &'a X25519Keypair,
    pub source: &'a C,
    pub store: &'a AuditStore,
    /// The lease holder persists each page, another replica scans into memory only.
    pub durable: Option<&'a ProjectionWriter<'a>>,
}

impl<S: TransactionSource> CredentialSource for S {
    fn credential_page(
        &self,
        request: TransactionPage,
    ) -> impl Future<Output = Result<GetShieldedTransactionsByTagsResponse, ClientError>> + Send
    {
        self.transactions_by_tag(request)
    }

    fn transaction_accounts(
        &self,
        signature: Signature,
    ) -> impl Future<Output = Result<Vec<Address>, ClientError>> + Send {
        TransactionSource::transaction_accounts(self, signature)
    }
}

impl CredentialPda {
    pub fn of(ring: &Address) -> Result<Self, RingRpcError> {
        let (pda, _) = Address::find_program_address(&[CREDENTIAL_PDA_SEED], ring);
        Ok(Self {
            ring: *ring,
            pda,
            owner: PdaOwner::new(&pda).map_err(|_| CredentialRefusal::PdaIdentity)?,
            ring_id: ring_id_field(ring.as_array()).map_err(|_| CredentialRefusal::PdaIdentity)?,
        })
    }

    pub fn view_tag(&self) -> [u8; 32] {
        self.pda.to_bytes()
    }

    pub fn ring_id(&self) -> [u8; 32] {
        self.ring_id
    }

    /// `None` for an output under another view tag, a credential output must rebuild exactly.
    fn credential(
        &self,
        transaction: &ShieldedTransaction,
        slot: &OutputSlot,
    ) -> Result<Option<FoundCredential>, CredentialRefusal> {
        if slot.view_tag != self.view_tag() {
            return Ok(None);
        }
        // 1. The plaintext is `address || Borsh(credential)`, a trailing byte fails the decode.
        let Some(OutputDataEncoding::Plaintext(blob)) = slot.output_data() else {
            return Err(CredentialRefusal::OutputMismatch);
        };
        let (address, state) = blob
            .split_first_chunk::<32>()
            .ok_or(CredentialRefusal::OutputMismatch)?;
        let credential = AuditCredential::try_from_slice(state)
            .map_err(|_| CredentialRefusal::OutputMismatch)?;
        if transaction.ring_program_id != Some(self.ring) || credential.ring_id != self.ring_id {
            return Err(CredentialRefusal::ForeignRing);
        }
        // 2. Enroll's SPP builder rebuilds hash and payload, a forged address or field fails the match.
        let rebuilt = self.output(&credential, slot.output_context.tree_id)?;
        if rebuilt.utxo_hash != slot.output_context.hash
            || rebuilt.data.as_deref() != Some(slot.payload.as_slice())
        {
            return Err(CredentialRefusal::OutputMismatch);
        }
        Ok(Some(FoundCredential {
            address: *address,
            credential,
            leaf: CredentialLeaf {
                utxo_hash: slot.output_context.hash,
                tree_id: slot.output_context.tree_id,
                leaf_index: slot.output_context.leaf_index,
            },
        }))
    }

    /// The output Enroll's CPI writes for `credential` into the tree `tree_id`.
    pub fn output(
        &self,
        credential: &AuditCredential,
        tree_id: u16,
    ) -> Result<TransactOutput, CredentialRefusal> {
        let mismatch = |_| CredentialRefusal::OutputMismatch;
        let mut account = UniqueDataUtxo::<AuditCredential>::new_init(
            &self.owner,
            credential.seed().map_err(mismatch)?,
            TreeContext {
                utxo_tree_root_index: 0,
                nullifier_tree_root_index: 0,
            },
        )
        .map_err(mismatch)?;
        *account = *credential;
        SppTransactCpi::new(TransactProof::zeroed())
            .with_unique_data_utxo(account)
            .and_then(|cpi| cpi.into_ix_data(tree_id))
            .map_err(mismatch)?
            .outputs
            .into_iter()
            .next()
            .ok_or(CredentialRefusal::OutputMismatch)
    }
}

impl HeldCredential {
    pub fn member(&self) -> [u8; 32] {
        self.credential.member
    }

    /// Opened per use, the secrets never stay in the store.
    pub fn secrets(&self, auditor: &X25519Keypair) -> Result<CredentialSecrets, CredentialRefusal> {
        open_credential(&self.credential, auditor).map_err(|_| CredentialRefusal::Sealed)
    }
}

impl OwnerCredential {
    /// Refuses an unknown owner, an unscanned credential never reads as absent.
    pub fn known(self) -> Result<Option<HeldCredential>, CredentialRefusal> {
        match self {
            Self::Held(held) => Ok(Some(*held)),
            Self::Absent => Ok(None),
            Self::Unknown => Err(CredentialRefusal::Incomplete),
        }
    }

    pub fn held(&self) -> Option<&HeldCredential> {
        match self {
            Self::Held(held) => Some(held),
            Self::Absent | Self::Unknown => None,
        }
    }

    pub fn enrollment(&self) -> WalletEnrollment {
        match self {
            Self::Held(_) => WalletEnrollment::Enrolled,
            Self::Absent => WalletEnrollment::NotEnrolled,
            Self::Unknown => WalletEnrollment::Unknown(UnknownCredential::PartialPage),
        }
    }
}

impl HeldCredentials {
    pub fn by_member(&self, member: &[u8; 32]) -> Option<&HeldCredential> {
        self.by_member.get(member)
    }

    pub fn by_owner_hash(&self, owner_hash: &[u8; 32]) -> Option<&HeldCredential> {
        self.by_member.get(self.members.get(owner_hash)?)
    }

    pub fn by_list_key(&self, list_key: &[u8; 32]) -> Option<&HeldCredential> {
        self.by_member.get(self.list_keys.get(list_key)?)
    }

    /// All or nothing, returns the owner keys held for the first time.
    pub fn admit(
        &mut self,
        found: Vec<HeldCredential>,
    ) -> Result<Vec<[u8; 32]>, CredentialRefusal> {
        // 1. A second credential for one member is impossible on chain, a differing one refuses the page.
        let mut fresh: HashMap<[u8; 32], HeldCredential> = HashMap::new();
        for held in found {
            let known = self
                .by_member
                .get(&held.member())
                .or_else(|| fresh.get(&held.member()));
            match known {
                Some(known) if *known != held => return Err(CredentialRefusal::Conflict),
                Some(_) => {}
                None => {
                    fresh.insert(held.member(), held);
                }
            }
        }
        // 2. Nothing is written before every credential of the page passed step 1.
        let mut owners = Vec::with_capacity(fresh.len());
        for (member, held) in fresh {
            self.members.insert(held.owner_hash, member);
            self.list_keys.insert(held.list_key, member);
            self.by_member.insert(member, held);
            owners.push(held.owner_key);
        }
        Ok(owners)
    }
}

impl<C: CredentialSource> CredentialScan<'_, C> {
    /// Reads from `position` until the terminal page or the page cap.
    pub async fn run(self, position: &mut HistoryPosition) -> Result<ScanEnd, RingRpcError> {
        let pda = CredentialPda::of(&self.ring)?;
        let limit = CREDENTIAL_PAGE_ROWS;
        for _ in 0..MAX_CREDENTIAL_PAGES {
            // 1. One page after the position, checked on a copy until the page applies.
            let response = self
                .source
                .credential_page(TransactionPage {
                    ring: self.ring,
                    tag: pda.view_tag(),
                    position: *position,
                    limit,
                })
                .await?;
            let mut next = *position;
            let end = checked_page(&response, &mut next, limit)?;
            // 2. Every credential of the page verifies, resolves its owner and opens before any is held.
            let mut found = Vec::new();
            for row in &response.data {
                for transaction in &row.events {
                    for slot in &transaction.output_slots {
                        if let Some(credential) = pda.credential(transaction, slot)? {
                            found.push(self.held(row.signature, credential).await?);
                        }
                    }
                }
            }
            // 3. The page applies whole and commits with the position past it, a restart resumes there.
            let admitted = found.clone();
            self.store.admit_credentials(found)?;
            if let Some(writer) = self.durable {
                writer.commit_credentials(&admitted, &next).await?;
            }
            *position = next;
            if matches!(end, PageEnd::Terminal(_)) {
                return Ok(ScanEnd::Complete);
            }
        }
        Ok(ScanEnd::Partial)
    }

    async fn held(
        &self,
        signature: Signature,
        found: FoundCredential,
    ) -> Result<HeldCredential, RingRpcError> {
        let FoundCredential {
            address,
            credential,
            leaf,
        } = found;
        if credential.auditor_pubkey != *self.auditor.pubkey().as_bytes() {
            return Err(CredentialRefusal::ForeignAuditor.into());
        }
        // The member is a hash of the owner, any account hashing to it is the owner whatever its role.
        let owner = self
            .source
            .transaction_accounts(signature)
            .await?
            .into_iter()
            .find(|account| {
                Member::owner_tag(account.as_array())
                    .is_ok_and(|member| *member.as_bytes() == credential.member)
            })
            .ok_or(CredentialRefusal::OwnerUnresolved)?;
        // The credential opens once here, its list key derives from the opened salt.
        let secrets =
            open_credential(&credential, self.auditor).map_err(|_| CredentialRefusal::Sealed)?;
        Ok(HeldCredential {
            owner_key: owner.to_bytes(),
            owner_hash: owner_hash(
                &PublicKey::from_ed25519(owner.as_array()),
                &credential.nullifier_pk,
            )?,
            address,
            list_key: list_key(&credential, &secrets.list_salt)?,
            credential,
            leaf,
        })
    }
}

fn list_key(credential: &AuditCredential, list_salt: &[u8; 32]) -> Result<[u8; 32], MemberError> {
    let key = Member::salted(&Member::from_bytes(credential.member)?, list_salt)?;
    Ok(*key.as_bytes())
}

/// A short continued page is refused, the finalized history fills every page but the last.
fn checked_page(
    response: &GetShieldedTransactionsByTagsResponse,
    position: &mut HistoryPosition,
    limit: NonZeroU32,
) -> Result<PageEnd, CredentialRefusal> {
    let end = position
        .advance(response, limit.get())
        .map_err(|_| CredentialRefusal::PageShape)?;
    let truncated = matches!(end, PageEnd::More)
        && u32::try_from(response.data.len()).ok() != Some(limit.get());
    let unbound = response.data.iter().any(|row| {
        let mut previous = None;
        row.events.iter().any(|transaction| {
            let misordered =
                transaction.event_index.is_none() || transaction.event_index <= previous;
            previous = transaction.event_index;
            misordered || transaction.tx_signature != row.signature || transaction.slot != row.slot
        })
    });
    if truncated || unbound {
        return Err(CredentialRefusal::PageShape);
    }
    Ok(end)
}

/// Finalized Enroll events for tests outside the crate.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixture {
    use spr_transaction::OutputContext;
    use zolana_ring_client::NullifierKeyEnvelope;

    use super::*;

    pub const TREE_ID: u16 = 1;

    #[must_use]
    pub struct Enrollment<'a> {
        pub ring: Address,
        pub owner: Address,
        pub key: &'a NullifierKey,
        pub list_salt: [u8; 32],
        pub auditor: &'a X25519Pubkey,
        pub signature: Signature,
        pub slot: u64,
    }

    impl Enrollment<'_> {
        /// The credential Enroll builds, sealed to `auditor`.
        pub fn credential(&self) -> AuditCredential {
            let sealed = NullifierKeyEnvelope::new(self.key, &self.list_salt, self.auditor)
                .expect("envelope")
                .sealed;
            AuditCredential {
                ring_id: CredentialPda::of(&self.ring).expect("pda").ring_id(),
                member: *Member::owner_tag(self.owner.as_array())
                    .expect("member")
                    .as_bytes(),
                nullifier_pk: self.key.pubkey().expect("nullifier pk"),
                list_tag: domain::list_tag(&self.list_salt).expect("list tag"),
                auditor_pubkey: *self.auditor.as_bytes(),
                eph_u: sealed.eph_pk.u(),
                ciphertext: sealed.ciphertext,
            }
        }

        /// The confirmed event of the Enroll writing `credential`.
        pub fn event_of(&self, credential: &AuditCredential) -> ShieldedTransaction {
            let pda = CredentialPda::of(&self.ring).expect("credential pda");
            let output = pda.output(credential, TREE_ID).expect("output");
            ShieldedTransaction {
                slot: self.slot,
                tx_signature: self.signature,
                event_index: Some(0),
                tx_viewing_pk: None,
                salt: None,
                output_slots: vec![OutputSlot {
                    view_tag: pda.view_tag(),
                    output_context: OutputContext {
                        hash: output.utxo_hash,
                        tree_id: TREE_ID,
                        leaf_index: self.slot,
                    },
                    payload: output.data.expect("plaintext"),
                }],
                messages: Vec::new(),
                nullifiers: Vec::new(),
                proofless: false,
                ring_config: None,
                ring_program_id: Some(self.ring),
            }
        }

        /// What a scan of `event_of(credential)` holds.
        pub fn held(&self, credential: AuditCredential) -> HeldCredential {
            let event = self.event_of(&credential);
            let slot = &event.output_slots[0];
            let nullifier_pk = credential.nullifier_pk;
            HeldCredential {
                owner_key: self.owner.to_bytes(),
                owner_hash: owner_hash(
                    &PublicKey::from_ed25519(self.owner.as_array()),
                    &nullifier_pk,
                )
                .expect("owner hash"),
                address: payload_address(slot),
                list_key: list_key(&credential, &self.list_salt).expect("list key"),
                credential,
                leaf: CredentialLeaf {
                    utxo_hash: slot.output_context.hash,
                    tree_id: slot.output_context.tree_id,
                    leaf_index: slot.output_context.leaf_index,
                },
            }
        }
    }

    fn payload_address(slot: &OutputSlot) -> [u8; 32] {
        let Some(OutputDataEncoding::Plaintext(blob)) = slot.output_data() else {
            panic!("a plaintext credential output");
        };
        let (address, _) = blob.split_first_chunk::<32>().expect("address");
        *address
    }
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod credentials_tests;
