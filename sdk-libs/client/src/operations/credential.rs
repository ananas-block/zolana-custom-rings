//! A ring member's audit credential, found through Photon and authenticated against SPP tree accounts.
//!
//! Read after `custom_ring_interface::credential`, where the credential, its address seed and its
//! state hash live, and after `viewing_key.rs`.
//!
//! Photon only names candidates. A credential is present once the UTXO hash rebuilt from the plaintext
//! `Enroll` output folds to a state root its tree account holds. Only `Enroll` signs for the credential
//! PDA, hence inclusion proves the enrollment. A credential is absent once the address gap folds to
//! an address root of tree 0 and the address has no queue PDA, both read in one account snapshot.
//! Every other answer is unknown. Unknown never selects the zero key.

use custom_ring_interface::{
    credential::owner_member, domain, storage::StorageError, AuditCredential, CREDENTIAL_PDA_SEED,
};
use solana_account::Account;
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    rpc::{
        IndexerRpcConfig, MerkleProof, NonInclusionProof, ShieldedTransaction,
        NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT,
    },
    AsyncRpc, ClientError, HistoryFilters,
};
use spr_event::OutputDataEncoding;
use spr_hasher::{Hasher, HasherError, Poseidon};
use spr_interface::{
    pda, state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, SHIELDED_POOL_PROGRAM_ID,
    ZERO_NULLIFIER_PUBKEY,
};
use spr_keypair::{KeypairError, X25519Pubkey};
use spr_program::{
    program::{CompressedAccountError, NewAddress, PdaOwner, ACCOUNT_BLINDING_SEED},
    ADDRESS_TREE_ID,
};
use spr_transaction::{
    utxo::{derive_output_blinding_seed, derive_transact_output_blinding, ProofInputUtxo},
    TransactionError, SOL_MINT,
};
use spr_tree::{nullifier_tree::layout::NullifierTreeLayout, TreeAccount, TreeError};
use thiserror::Error;
use zolana_ring_keys::{RingAddress, RingKeyError};
use zolana_ring_policy::ring_id_field;

use crate::viewing_key::{ViewingKeyError, ViewingKeyResolver};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialLookup {
    Present(Box<PresentCredential>),
    Absent(Box<AbsentCredential>),
    Unknown(UnknownCredential),
}

/// A state inclusion proof under a root the tree account held when read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentCredential {
    pub credential: AuditCredential,
    pub address: [u8; 32],
    pub blinding: [u8; 32],
    pub tree_id: u16,
    pub leaf_index: u64,
    pub path: [[u8; 32]; STATE_TREE_HEIGHT],
    pub root: StateRoot,
    pub enrollment: Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateRoot {
    pub root_index: u16,
    pub root: [u8; 32],
}

/// The address gap in tree 0 under a root the snapshot held while the address had no queue PDA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbsentCredential {
    pub address: [u8; 32],
    pub low: [u8; 32],
    pub next: [u8; 32],
    pub low_index: u64,
    pub path: [[u8; 32]; NULLIFIER_TREE_HEIGHT],
    pub root: AddressRoot,
}

/// `sequence` is the tree 0 append count at `root`, read from the same snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRoot {
    pub root_index: u16,
    pub root: [u8; 32],
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownCredential {
    /// The address holds a queue PDA and the indexer serves no enrollment for it.
    Queued,
    /// The indexer serves the enrollment without a state proof of its leaf.
    StateProofMissing,
    /// The indexer serves neither an enrollment nor an address gap.
    AbsenceProofMissing,
    /// The indexer ended an empty answer with a continuation.
    PartialPage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecipientKeys {
    /// The request names the key the credential holds.
    Registered {
        viewing_pubkey: X25519Pubkey,
        credential: Box<PresentCredential>,
    },
    /// The request names the zero key and the owner holds no credential.
    ZeroKey {
        viewing_pubkey: X25519Pubkey,
        absence: Box<AbsentCredential>,
    },
    /// The caller accepted a zero key note the enrolled owner cannot spend privately.
    ZeroKeyToEnrolled {
        viewing_pubkey: X25519Pubkey,
        credential: Box<PresentCredential>,
    },
}

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error(transparent)]
    Rpc(#[from] ClientError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
    #[error(transparent)]
    Address(#[from] CompressedAccountError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Tree(#[from] TreeError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    RingKey(#[from] RingKeyError),
    #[error(transparent)]
    ViewingKey(#[from] ViewingKeyError),
    #[error("the indexer answered {0} enrollments for one credential address")]
    EnrollmentCount(usize),
    #[error("the enrollment output does not rebuild the credential leaf")]
    MalformedEnrollment,
    #[error("the enrolled credential binds another ring or owner")]
    CredentialMismatch,
    #[error("the credential holds another nullifier key")]
    NullifierKeyMismatch,
    #[error("the credential holds another list tag")]
    ListTagMismatch,
    #[error("the indexer proof names another leaf, tree or path length")]
    MalformedProof,
    #[error("the state path does not fold to its root")]
    InvalidStateProof,
    #[error("the address gap does not bracket the address or fold to its root")]
    InvalidAbsenceProof,
    #[error("the tree account at {address} is missing or not an SPP tree")]
    InvalidTree { address: Address },
    #[error("the state root is not in the root history of its tree")]
    StateRootNotAccepted,
    #[error("the address root is not in the root history of tree 0")]
    AddressRootNotAccepted,
    #[error("the address root at sequence {sequence} is below the floor {floor}")]
    AbsenceRootBelowFloor { sequence: u64, floor: u64 },
    #[error("the credential lookup is unknown, {0:?}")]
    Unknown(UnknownCredential),
    #[error("the request names a key, the owner holds no credential")]
    NotEnrolled,
    #[error("the owner holds a credential, the request names the zero key")]
    EnrolledOwnerAtZeroKey,
    #[error("the enrolled owner holds no user record to seal a zero key note to")]
    UnverifiedViewingKey,
}

#[must_use]
pub struct CredentialResolver {
    ring: Address,
    owner: Address,
    nullifier_pk: Option<[u8; 32]>,
    list_tag: Option<[u8; 32]>,
}

#[must_use]
pub struct RecipientKeyResolver<'a> {
    address: &'a RingAddress,
    zero_key_to_enrolled: bool,
}

struct CredentialIdentity {
    ring_id: [u8; 32],
    member: [u8; 32],
    owner: PdaOwner,
    address: [u8; 32],
}

impl CredentialResolver {
    pub fn new(ring: Address, owner: Address) -> Self {
        Self {
            ring,
            owner,
            nullifier_pk: None,
            list_tag: None,
        }
    }

    /// A credential holding another key is refused.
    pub fn with_nullifier_key(self, nullifier_pk: [u8; 32]) -> Self {
        Self {
            nullifier_pk: Some(nullifier_pk),
            ..self
        }
    }

    /// A credential holding another tag is refused.
    pub fn with_list_tag(self, list_tag: [u8; 32]) -> Self {
        Self {
            list_tag: Some(list_tag),
            ..self
        }
    }

    pub async fn resolve<P, R>(
        self,
        photon: &P,
        rpc: &R,
    ) -> Result<CredentialLookup, CredentialError>
    where
        P: AsyncRpc,
        R: AsyncRpc,
    {
        let identity = CredentialIdentity::derive(&self.ring, &self.owner)?;
        // The address is the nullifier of the enrollment's address slot, so the one transaction
        // publishing it as a nullifier is the enrollment. An empty answer proves nothing yet.
        let page = photon
            .get_shielded_transactions_by_nullifiers(
                vec![identity.address],
                None,
                None,
                HistoryFilters::default(),
                None,
            )
            .await?;
        let mut enrollments = page
            .data
            .into_iter()
            .flat_map(|group| group.events)
            .filter(|transaction| transaction.nullifiers.contains(&identity.address));
        match (enrollments.next(), enrollments.count()) {
            (Some(enrollment), 0) => self.present(&identity, enrollment, photon, rpc).await,
            (Some(_), more) => Err(CredentialError::EnrollmentCount(more + 1)),
            (None, _) if page.pagination_token.is_some() => {
                Ok(CredentialLookup::Unknown(UnknownCredential::PartialPage))
            }
            (None, _) => absent(&identity, photon, rpc).await,
        }
    }

    async fn present<P, R>(
        &self,
        identity: &CredentialIdentity,
        enrollment: ShieldedTransaction,
        photon: &P,
        rpc: &R,
    ) -> Result<CredentialLookup, CredentialError>
    where
        P: AsyncRpc,
        R: AsyncRpc,
    {
        // 1. The plaintext is untrusted until its rebuilt leaf folds to an on chain root, but a
        //    credential naming another ring, owner, key or tag is refused before any proof read.
        let (credential, output) = enrolled_credential(identity, &enrollment)?;
        if credential.ring_id != identity.ring_id || credential.member != identity.member {
            return Err(CredentialError::CredentialMismatch);
        }
        if self
            .nullifier_pk
            .is_some_and(|nullifier_pk| nullifier_pk != credential.nullifier_pk)
        {
            return Err(CredentialError::NullifierKeyMismatch);
        }
        if self
            .list_tag
            .is_some_and(|list_tag| list_tag != credential.list_tag)
        {
            return Err(CredentialError::ListTagMismatch);
        }
        // 2. `Enroll` writes the credential as its only output, so the blinding derives from the
        //    address alone, and the leaf commits to the credential PDA and the tree it landed in.
        let blinding = credential_blinding(&identity.address)?;
        let leaf = ProofInputUtxo::new(
            *identity.owner.owner_hash(),
            &SOL_MINT,
            0,
            &blinding,
            output.tree_id,
        )?
        .with_data_hash(credential.data_hash(&identity.address)?)
        .hash()?;
        if leaf != output.hash {
            return Err(CredentialError::MalformedEnrollment);
        }
        // 3. Requiring the enrollment slot keeps a lagging indexer from answering without the leaf.
        let tree = pda::tree(output.tree_id);
        let proofs = photon
            .get_merkle_proofs(
                tree,
                vec![leaf],
                Some(IndexerRpcConfig::at_slot(enrollment.slot)),
            )
            .await?
            .proofs;
        let proof = match <[MerkleProof; 1]>::try_from(proofs) {
            Ok([proof]) => proof,
            Err(proofs) if proofs.is_empty() => {
                return Ok(CredentialLookup::Unknown(
                    UnknownCredential::StateProofMissing,
                ));
            }
            Err(_) => return Err(CredentialError::MalformedProof),
        };
        if proof.leaf != leaf
            || proof.merkle_context.tree != tree
            || proof.leaf_index != output.leaf_index
        {
            return Err(CredentialError::MalformedProof);
        }
        let path = fixed_path::<STATE_TREE_HEIGHT>(&proof.path, proof.leaf_index)?;
        if fold_path(leaf, proof.leaf_index, &path)? != proof.root {
            return Err(CredentialError::InvalidStateProof);
        }
        // 4. The root must be in the history SPP accepts roots from. A paused or full tree keeps
        //    its history, so its credentials stay readable.
        let mut data = spp_tree(tree, rpc.get_account(tree).await?)?;
        let account = TreeAccount::from_bytes(&mut data, tree.to_bytes())?;
        if account.tree_id() != output.tree_id {
            return Err(CredentialError::InvalidTree { address: tree });
        }
        if account.get_utxo_tree_root(proof.root_index).ok() != Some(proof.root) {
            return Err(CredentialError::StateRootNotAccepted);
        }
        Ok(CredentialLookup::Present(Box::new(PresentCredential {
            credential,
            address: identity.address,
            blinding,
            tree_id: output.tree_id,
            leaf_index: proof.leaf_index,
            path,
            root: StateRoot {
                root_index: proof.root_index,
                root: proof.root,
            },
            enrollment: enrollment.tx_signature,
        })))
    }
}

impl AbsentCredential {
    /// A salted read accepts only an address root at or above every source floor it reads through.
    pub fn check_floor(&self, floor: u64) -> Result<(), CredentialError> {
        match self.root.sequence >= floor {
            true => Ok(()),
            false => Err(CredentialError::AbsenceRootBelowFloor {
                sequence: self.root.sequence,
                floor,
            }),
        }
    }
}

impl RecipientKeys {
    pub fn nullifier_pk(&self) -> [u8; 32] {
        match self {
            Self::Registered { credential, .. } => credential.credential.nullifier_pk,
            Self::ZeroKey { .. } | Self::ZeroKeyToEnrolled { .. } => ZERO_NULLIFIER_PUBKEY,
        }
    }

    pub fn viewing_pubkey(&self) -> X25519Pubkey {
        match self {
            Self::Registered { viewing_pubkey, .. }
            | Self::ZeroKey { viewing_pubkey, .. }
            | Self::ZeroKeyToEnrolled { viewing_pubkey, .. } => *viewing_pubkey,
        }
    }
}

impl<'a> RecipientKeyResolver<'a> {
    pub fn new(address: &'a RingAddress) -> Self {
        Self {
            address,
            zero_key_to_enrolled: false,
        }
    }

    /// The zero key request of an enrolled owner settles a note only a public spend opens.
    pub fn with_zero_key_to_enrolled(self) -> Self {
        Self {
            zero_key_to_enrolled: true,
            ..self
        }
    }

    pub async fn resolve<P, R>(self, photon: &P, rpc: &R) -> Result<RecipientKeys, CredentialError>
    where
        P: AsyncRpc,
        R: AsyncRpc,
    {
        let RingAddress {
            recipient,
            ring_program_id,
            list_salt,
        } = self.address;
        RingAddress::check_list_salt(recipient, list_salt)?;
        let owner = recipient.solana_address()?;
        let resolver = CredentialResolver::new(*ring_program_id, owner);
        // 1. A request naming a key binds the lookup to that key and its list tag. The zero key
        //    request binds nothing, the lookup only decides whether the owner holds a credential.
        if recipient.nullifier_pubkey != ZERO_NULLIFIER_PUBKEY {
            let lookup = resolver
                .with_nullifier_key(recipient.nullifier_pubkey)
                .with_list_tag(domain::list_tag(list_salt)?)
                .resolve(photon, rpc)
                .await?;
            let credential = match lookup {
                CredentialLookup::Present(credential) => credential,
                CredentialLookup::Absent(_) => return Err(CredentialError::NotEnrolled),
                CredentialLookup::Unknown(unknown) => {
                    return Err(CredentialError::Unknown(unknown))
                }
            };
            // 2. The record key must belong to the credential key. Without a record the request
            //    key serves, since step 1 matched the request key to the credential.
            let viewing_pubkey = ViewingKeyResolver::new(owner)
                .with_credential(credential.credential.nullifier_pk)
                .resolve(rpc)
                .await?
                .map_or(recipient.viewing_pubkey, |record| record.viewing_pubkey);
            return Ok(RecipientKeys::Registered {
                viewing_pubkey,
                credential,
            });
        }
        // 3. A zero key note to an enrolled owner leaves the owner's private spend path, so it
        //    needs the caller's opt in and a record bound to the credential key.
        match resolver.resolve(photon, rpc).await? {
            CredentialLookup::Present(credential) if self.zero_key_to_enrolled => {
                let viewing_pubkey = ViewingKeyResolver::new(owner)
                    .with_credential(credential.credential.nullifier_pk)
                    .resolve(rpc)
                    .await?
                    .ok_or(CredentialError::UnverifiedViewingKey)?
                    .viewing_pubkey;
                Ok(RecipientKeys::ZeroKeyToEnrolled {
                    viewing_pubkey,
                    credential,
                })
            }
            CredentialLookup::Present(_) => Err(CredentialError::EnrolledOwnerAtZeroKey),
            CredentialLookup::Absent(absence) => {
                let viewing_pubkey = ViewingKeyResolver::new(owner)
                    .resolve(rpc)
                    .await?
                    .map_or(recipient.viewing_pubkey, |record| record.viewing_pubkey);
                Ok(RecipientKeys::ZeroKey {
                    viewing_pubkey,
                    absence,
                })
            }
            CredentialLookup::Unknown(unknown) => Err(CredentialError::Unknown(unknown)),
        }
    }
}

impl CredentialIdentity {
    fn derive(ring: &Address, owner: &Address) -> Result<Self, CredentialError> {
        let ring_id = ring_id_field(ring.as_array())?;
        let member = owner_member(owner)?;
        let (credential_pda, _) = Address::find_program_address(&[CREDENTIAL_PDA_SEED], ring);
        let pda_owner = PdaOwner::new(&credential_pda)?;
        // The seed reads only the ring and member of a credential.
        let seed = AuditCredential {
            ring_id,
            member,
            ..AuditCredential::default()
        }
        .seed()?;
        let address = *NewAddress::derive(&pda_owner, seed)?.address();
        Ok(Self {
            ring_id,
            member,
            owner: pda_owner,
            address,
        })
    }
}

async fn absent<P, R>(
    identity: &CredentialIdentity,
    photon: &P,
    rpc: &R,
) -> Result<CredentialLookup, CredentialError>
where
    P: AsyncRpc,
    R: AsyncRpc,
{
    let tree = pda::tree(ADDRESS_TREE_ID);
    let (queue, _) = pda::nullifier_pda(&tree, &identity.address);
    // 1. The gap is checked before the snapshot, the snapshot then decides the roots it may use.
    let proofs = photon
        .get_non_inclusion_proofs(tree, vec![identity.address], None)
        .await?
        .proofs;
    let gap = match <[NonInclusionProof; 1]>::try_from(proofs) {
        Ok([gap]) => gap,
        Err(proofs) if proofs.is_empty() => {
            return Ok(CredentialLookup::Unknown(
                UnknownCredential::AbsenceProofMissing,
            ));
        }
        Err(_) => return Err(CredentialError::MalformedProof),
    };
    if gap.leaf != identity.address || gap.merkle_context.tree != tree {
        return Err(CredentialError::MalformedProof);
    }
    let path = fixed_path::<NULLIFIER_TREE_HEIGHT>(&gap.path, gap.low_element_index)?;
    let brackets = gap.low_element < identity.address && identity.address < gap.high_element;
    let low_leaf = Poseidon::hashv(&[&gap.low_element, &gap.high_element])?;
    if !brackets || fold_path(low_leaf, gap.low_element_index, &path)? != gap.root {
        return Err(CredentialError::InvalidAbsenceProof);
    }
    // 2. An address enters the queue before any root holds it. Its queue PDA closes only after
    //    every root in the history holds the address, so an empty PDA and a gap under a root of
    //    the same snapshot cover both the queue and the tree.
    let [tree_account, queue_account] =
        <[Option<Account>; 2]>::try_from(rpc.get_multiple_accounts(vec![tree, queue]).await?)
            .map_err(|answers| {
                ClientError::Rpc(format!("expected 2 accounts, got {}", answers.len()))
            })?;
    if queue_account
        .is_some_and(|account| account.owner != Address::default() || !account.data.is_empty())
    {
        return Ok(CredentialLookup::Unknown(UnknownCredential::Queued));
    }
    let mut data = spp_tree(tree, tree_account)?;
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes())?;
    if account.tree_id() != ADDRESS_TREE_ID {
        return Err(CredentialError::InvalidTree { address: tree });
    }
    let sequence = match root_sequence(account.nullifier_tree(), gap.root_index) {
        Some((root, sequence)) if root == gap.root => sequence,
        _ => return Err(CredentialError::AddressRootNotAccepted),
    };
    Ok(CredentialLookup::Absent(Box::new(AbsentCredential {
        address: identity.address,
        low: gap.low_element,
        next: gap.high_element,
        low_index: gap.low_element_index,
        path,
        root: AddressRoot {
            root_index: gap.root_index,
            root: gap.root,
            sequence,
        },
    })))
}

/// The one plaintext output carrying `address || Borsh(credential)` and the context it landed in.
fn enrolled_credential(
    identity: &CredentialIdentity,
    enrollment: &ShieldedTransaction,
) -> Result<(AuditCredential, spr_client::rpc::OutputContext), CredentialError> {
    if enrollment.nullifiers.first() != Some(&identity.address) {
        return Err(CredentialError::MalformedEnrollment);
    }
    let mut credentials = enrollment.output_slots.iter().filter_map(|slot| {
        let OutputDataEncoding::Plaintext(data) = slot.output_data()? else {
            return None;
        };
        let state = data.strip_prefix(identity.address.as_slice())?;
        let credential = borsh::from_slice::<AuditCredential>(state).ok()?;
        Some((credential, slot.output_context.clone()))
    });
    match (credentials.next(), credentials.next()) {
        (Some(credential), None) => Ok(credential),
        _ => Err(CredentialError::MalformedEnrollment),
    }
}

fn credential_blinding(address: &[u8; 32]) -> Result<[u8; 32], TransactionError> {
    let seed = derive_output_blinding_seed(address, &ACCOUNT_BLINDING_SEED)?;
    derive_transact_output_blinding(address, &seed, 0)
}

fn spp_tree(address: Address, account: Option<Account>) -> Result<Vec<u8>, CredentialError> {
    match account {
        Some(account)
            if account.owner.to_bytes() == SHIELDED_POOL_PROGRAM_ID
                && account.data.first() == Some(&TREE_ACCOUNT_DISCRIMINATOR) =>
        {
            Ok(account.data)
        }
        _ => Err(CredentialError::InvalidTree { address }),
    }
}

/// A leaf index past the tree width has no path, its high bits would be ignored by the fold.
fn fixed_path<const HEIGHT: usize>(
    path: &[[u8; 32]],
    leaf_index: u64,
) -> Result<[[u8; 32]; HEIGHT], CredentialError> {
    match leaf_index >> HEIGHT {
        0 => <[[u8; 32]; HEIGHT]>::try_from(path).map_err(|_| CredentialError::MalformedProof),
        _ => Err(CredentialError::MalformedProof),
    }
}

/// Bit `level` of the index places the node left on zero, as the circuit's Merkle gadget does.
fn fold_path(leaf: [u8; 32], leaf_index: u64, path: &[[u8; 32]]) -> Result<[u8; 32], HasherError> {
    path.iter()
        .enumerate()
        .try_fold(leaf, |node, (level, sibling)| {
            match (leaf_index >> level) & 1 {
                0 => Poseidon::hashv(&[&node, sibling]),
                _ => Poseidon::hashv(&[sibling, &node]),
            }
        })
}

/// Each apply adds one to `sequence_number` and writes one root at the history cursor, so a slot's
/// distance behind the latest root is its distance behind the latest sequence.
fn root_sequence<const ZKP_BATCHES: usize>(
    tree: &NullifierTreeLayout<ZKP_BATCHES>,
    root_index: u16,
) -> Option<([u8; 32], u64)> {
    let root = tree.root_by_index(root_index)?;
    let capacity = u64::try_from(ZKP_BATCHES).ok()?;
    let latest = u64::from(tree.get_root_index());
    let distance = (latest + capacity - u64::from(root_index)) % capacity;
    Some((root, tree.sequence_number.checked_sub(distance)?))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use borsh::BorshSerialize;
    use spr_client::rpc::{
        Context, GetMerkleProofsResponse, GetNonInclusionProofsResponse,
        GetShieldedTransactionsByNullifiersResponse, MerkleContext, OutputContext, OutputSlot,
        PaginationToken, TransactionEvents,
    };
    use spr_hasher::primitives::BN254_SCALAR_MODULUS_BE;
    use spr_keypair::{
        shielded::{ShieldedAddress, ShieldedKeypair},
        SigningKey, ViewingKey,
    };
    use spr_tree::{
        nullifier_tree::constants::NULLIFIER_TREE_INIT_ROOT_40, NullifierTreeInitParams,
        TreeFeeSchedule,
    };
    use spr_user_registry_interface::{user_record_pda, MergeEncryptionScheme, UserRecord};
    use zolana_ring_keys::ListSaltHolder;

    use super::*;

    const RING: Address = Address::new_from_array([4; 32]);
    const TREE_ID: u16 = 3;
    const ENROLLMENT_SLOT: u64 = 9;
    const ADDRESS_ROOT_SEQUENCE: u64 = 6;

    /// One account store and one indexer, a test passes it as Photon and as RPC.
    #[derive(Default)]
    struct Ledger {
        accounts: HashMap<Address, Account>,
        enrollments: Vec<ShieldedTransaction>,
        continuation: Option<PaginationToken>,
        state_proofs: Vec<MerkleProof>,
        gaps: Vec<NonInclusionProof>,
    }

    #[async_trait]
    impl AsyncRpc for Ledger {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok(self.accounts.get(&address).cloned())
        }

        async fn get_multiple_accounts(
            &self,
            addresses: Vec<Address>,
        ) -> Result<Vec<Option<Account>>, ClientError> {
            Ok(addresses
                .iter()
                .map(|address| self.accounts.get(address).cloned())
                .collect())
        }

        async fn get_shielded_transactions_by_nullifiers(
            &self,
            _nullifiers: Vec<[u8; 32]>,
            _pagination_token: Option<PaginationToken>,
            _limit: Option<u32>,
            _filters: HistoryFilters,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Ok(GetShieldedTransactionsByNullifiersResponse {
                context: context(),
                output_tree_id: None,
                data: self
                    .enrollments
                    .iter()
                    .map(|enrollment| TransactionEvents {
                        slot: enrollment.slot,
                        signature: enrollment.tx_signature,
                        events: vec![enrollment.clone()],
                    })
                    .collect(),
                pagination_token: self.continuation,
            })
        }

        async fn get_merkle_proofs(
            &self,
            _tree_account: Address,
            _leaves: Vec<[u8; 32]>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetMerkleProofsResponse, ClientError> {
            Ok(GetMerkleProofsResponse {
                context: context(),
                proofs: self.state_proofs.clone(),
            })
        }

        async fn get_non_inclusion_proofs(
            &self,
            _tree_account: Address,
            _leaves: Vec<[u8; 32]>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetNonInclusionProofsResponse, ClientError> {
            Ok(GetNonInclusionProofsResponse {
                context: context(),
                proofs: self.gaps.clone(),
            })
        }
    }

    impl Ledger {
        /// Tree 0 holds only its init leaf, its init root sits one apply behind the latest.
        fn absent() -> Self {
            let tree = pda::tree(ADDRESS_TREE_ID);
            let mut data = tree_bytes(ADDRESS_TREE_ID);
            {
                let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).unwrap();
                let layout = account.nullifier_tree();
                layout.root_history.roots[1] = [9; 32];
                layout.root_history.current_index = 2;
                layout.sequence_number = ADDRESS_ROOT_SEQUENCE + 1;
            }
            let mut high_element = BN254_SCALAR_MODULUS_BE;
            high_element[31] -= 1;
            Self {
                accounts: HashMap::from([(tree, spp_account(data))]),
                gaps: vec![NonInclusionProof {
                    leaf: identity().address,
                    merkle_context: MerkleContext { tree_type: 0, tree },
                    path: Poseidon::zero_bytes()[..NULLIFIER_TREE_HEIGHT].to_vec(),
                    low_element: [0; 32],
                    low_element_index: 0,
                    high_element,
                    high_element_index: 0,
                    root: NULLIFIER_TREE_INIT_ROOT_40,
                    root_seq: ADDRESS_ROOT_SEQUENCE,
                    root_index: 0,
                }],
                ..Self::default()
            }
        }

        /// The credential leaf sits at index 0 of a real state tree, its path is the zero subtrees.
        fn enrolled(credential: &AuditCredential) -> Self {
            let identity = identity();
            let blinding = credential_blinding(&identity.address).unwrap();
            let leaf = ProofInputUtxo::new(
                *identity.owner.owner_hash(),
                &SOL_MINT,
                0,
                &blinding,
                TREE_ID,
            )
            .unwrap()
            .with_data_hash(credential.data_hash(&identity.address).unwrap())
            .hash()
            .unwrap();
            let tree = pda::tree(TREE_ID);
            let mut data = tree_bytes(TREE_ID);
            let (root, root_index) = {
                let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).unwrap();
                account.utxo_tree().append(leaf, ENROLLMENT_SLOT).unwrap();
                let root_index = account.utxo_tree().current_root_index();
                (account.get_utxo_tree_root(root_index).unwrap(), root_index)
            };
            let mut state = identity.address.to_vec();
            credential.serialize(&mut state).unwrap();
            let enrollment = ShieldedTransaction {
                slot: ENROLLMENT_SLOT,
                tx_signature: Signature::from([1; 64]),
                event_index: Some(0),
                tx_viewing_pk: None,
                salt: None,
                output_slots: vec![OutputSlot {
                    view_tag: [0; 32],
                    output_context: OutputContext {
                        hash: leaf,
                        tree_id: TREE_ID,
                        leaf_index: 0,
                    },
                    payload: borsh::to_vec(&OutputDataEncoding::Plaintext(state)).unwrap(),
                }],
                messages: Vec::new(),
                nullifiers: vec![identity.address, [2; 32]],
                proofless: false,
                ring_config: None,
                ring_program_id: None,
            };
            let mut ledger = Self::absent();
            ledger.accounts.insert(tree, spp_account(data));
            ledger.enrollments = vec![enrollment];
            ledger.state_proofs = vec![MerkleProof {
                leaf,
                merkle_context: MerkleContext { tree_type: 0, tree },
                path: Poseidon::zero_bytes()[..STATE_TREE_HEIGHT].to_vec(),
                leaf_index: 0,
                root,
                root_seq: ENROLLMENT_SLOT,
                root_index,
            }];
            ledger
        }

        fn queue(&mut self) {
            let tree = pda::tree(ADDRESS_TREE_ID);
            let (queue, _) = pda::nullifier_pda(&tree, &identity().address);
            self.accounts.insert(queue, spp_account(vec![1]));
        }

        fn register(&mut self, nullifier_pubkey: [u8; 32], viewing_pubkey: X25519Pubkey) {
            let (address, bump) = user_record_pda(&owner());
            let record = UserRecord {
                owner: owner(),
                bump,
                nullifier_pubkey,
                viewing_pubkey: *viewing_pubkey.as_bytes(),
                merge_encryption: MergeEncryptionScheme::Disabled,
            };
            let mut data = vec![UserRecord::DISCRIMINATOR];
            record.serialize(&mut data).unwrap();
            let account = Account {
                data,
                owner: spr_user_registry_interface::user_registry_program_id(),
                ..Account::default()
            };
            self.accounts.insert(address, account);
        }

        async fn resolve(
            &self,
            resolver: CredentialResolver,
        ) -> Result<CredentialLookup, CredentialError> {
            resolver.resolve(self, self).await
        }
    }

    fn context() -> Context {
        Context {
            block_time: 0,
            slot: ENROLLMENT_SLOT,
        }
    }

    fn tree_bytes(tree_id: u16) -> Vec<u8> {
        let mut data = vec![0; TreeAccount::account_size()];
        TreeAccount::init(
            &mut data,
            TREE_ACCOUNT_DISCRIMINATOR,
            STATE_TREE_HEIGHT as u8,
            pda::tree(tree_id).to_bytes(),
            tree_id,
            NullifierTreeInitParams::default(),
            TreeFeeSchedule::at_cost(250, 5_000, 46).unwrap(),
        )
        .unwrap();
        data
    }

    fn spp_account(data: Vec<u8>) -> Account {
        Account {
            lamports: 1,
            data,
            owner: Address::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            ..Account::default()
        }
    }

    fn holder() -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[6; 32])).unwrap()
    }

    fn owner() -> Address {
        holder()
            .shielded_address()
            .unwrap()
            .solana_address()
            .unwrap()
    }

    fn identity() -> CredentialIdentity {
        CredentialIdentity::derive(&RING, &owner()).unwrap()
    }

    fn credential() -> AuditCredential {
        let holder = holder();
        let mut auditor_pubkey = [3; 33];
        auditor_pubkey[0] = spr_keypair::x25519::X25519_KEY_TAG;
        AuditCredential {
            ring_id: ring_id_field(RING.as_array()).unwrap(),
            member: owner_member(&owner()).unwrap(),
            nullifier_pk: holder.nullifier_key.pubkey().unwrap(),
            list_tag: domain::list_tag(&holder.list_salt(&RING).unwrap()).unwrap(),
            auditor_pubkey,
            eph_u: [5; 32],
            ciphertext: [7; 64],
        }
    }

    fn resolver() -> CredentialResolver {
        CredentialResolver::new(RING, owner())
    }

    fn registered_address() -> RingAddress {
        RingAddress::enrolled(&holder(), RING).unwrap()
    }

    fn zero_key_address() -> RingAddress {
        RingAddress {
            recipient: ShieldedAddress {
                nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
                ..holder().shielded_address().unwrap()
            },
            ring_program_id: RING,
            list_salt: [0; 32],
        }
    }

    fn present(lookup: CredentialLookup) -> PresentCredential {
        match lookup {
            CredentialLookup::Present(present) => *present,
            other => panic!("expected a present credential, got {other:?}"),
        }
    }

    fn absent(lookup: CredentialLookup) -> AbsentCredential {
        match lookup {
            CredentialLookup::Absent(absent) => *absent,
            other => panic!("expected an absent credential, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_present_credential_opens_under_its_tree_root_even_when_paused() {
        let credential = credential();
        let mut ledger = Ledger::enrolled(&credential);
        let expected = ledger.state_proofs[0].clone();
        let opened = present(
            ledger
                .resolve(
                    resolver()
                        .with_nullifier_key(credential.nullifier_pk)
                        .with_list_tag(credential.list_tag),
                )
                .await
                .unwrap(),
        );
        assert_eq!(opened.credential, credential);
        assert_eq!(opened.address, identity().address);
        assert_eq!((opened.tree_id, opened.leaf_index), (TREE_ID, 0));
        assert_eq!(
            opened.root,
            StateRoot {
                root_index: expected.root_index,
                root: expected.root,
            }
        );
        let tree = ledger.accounts.get_mut(&pda::tree(TREE_ID)).unwrap();
        TreeAccount::from_bytes(&mut tree.data, pda::tree(TREE_ID).to_bytes())
            .unwrap()
            .set_paused(true);
        assert_eq!(present(ledger.resolve(resolver()).await.unwrap()), opened);
    }

    #[tokio::test]
    async fn an_owner_without_enrollment_is_absent_at_its_root_sequence() {
        let opened = absent(Ledger::absent().resolve(resolver()).await.unwrap());
        assert_eq!(opened.address, identity().address);
        assert_eq!(
            opened.root,
            AddressRoot {
                root_index: 0,
                root: NULLIFIER_TREE_INIT_ROOT_40,
                sequence: ADDRESS_ROOT_SEQUENCE,
            }
        );
        opened.check_floor(ADDRESS_ROOT_SEQUENCE).unwrap();
        assert!(matches!(
            opened.check_floor(ADDRESS_ROOT_SEQUENCE + 1),
            Err(CredentialError::AbsenceRootBelowFloor { sequence: ADDRESS_ROOT_SEQUENCE, floor })
                if floor == ADDRESS_ROOT_SEQUENCE + 1
        ));
    }

    #[tokio::test]
    async fn a_queued_address_the_indexer_has_not_served_is_unknown() {
        let mut ledger = Ledger::absent();
        ledger.queue();
        assert_eq!(
            ledger.resolve(resolver()).await.unwrap(),
            CredentialLookup::Unknown(UnknownCredential::Queued)
        );
    }

    #[tokio::test]
    async fn a_root_outside_the_history_or_a_path_off_the_root_is_refused() {
        let mut stale_state = Ledger::enrolled(&credential());
        stale_state.state_proofs[0].root_index = 0;
        let result = stale_state.resolve(resolver()).await;
        assert!(
            matches!(result, Err(CredentialError::StateRootNotAccepted)),
            "{result:?}"
        );

        let mut forged_path = Ledger::enrolled(&credential());
        forged_path.state_proofs[0].path[4] = [1; 32];
        let result = forged_path.resolve(resolver()).await;
        assert!(
            matches!(result, Err(CredentialError::InvalidStateProof)),
            "{result:?}"
        );

        let mut stale_address = Ledger::absent();
        stale_address.gaps[0].root_index = 1;
        let result = stale_address.resolve(resolver()).await;
        assert!(
            matches!(result, Err(CredentialError::AddressRootNotAccepted)),
            "{result:?}"
        );

        let mut covering_gap = Ledger::absent();
        covering_gap.gaps[0].low_element = identity().address;
        let result = covering_gap.resolve(resolver()).await;
        assert!(
            matches!(result, Err(CredentialError::InvalidAbsenceProof)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_credential_of_another_ring_owner_key_or_tag_is_refused() {
        let ledger = Ledger::enrolled(&credential());
        let result = ledger.resolve(resolver().with_nullifier_key([1; 32])).await;
        assert!(
            matches!(result, Err(CredentialError::NullifierKeyMismatch)),
            "{result:?}"
        );
        let result = ledger.resolve(resolver().with_list_tag([1; 32])).await;
        assert!(
            matches!(result, Err(CredentialError::ListTagMismatch)),
            "{result:?}"
        );

        let other_ring = AuditCredential {
            ring_id: [1; 32],
            ..credential()
        };
        let other_owner = AuditCredential {
            member: [1; 32],
            ..credential()
        };
        for served in [other_ring, other_owner] {
            let result = Ledger::enrolled(&served).resolve(resolver()).await;
            assert!(
                matches!(result, Err(CredentialError::CredentialMismatch)),
                "{result:?}"
            );
        }
    }

    #[tokio::test]
    async fn partial_indexer_answers_stay_unknown_or_refused() {
        let mut without_proof = Ledger::enrolled(&credential());
        without_proof.state_proofs.clear();
        assert_eq!(
            without_proof.resolve(resolver()).await.unwrap(),
            CredentialLookup::Unknown(UnknownCredential::StateProofMissing)
        );

        let mut without_gap = Ledger::absent();
        without_gap.gaps.clear();
        assert_eq!(
            without_gap.resolve(resolver()).await.unwrap(),
            CredentialLookup::Unknown(UnknownCredential::AbsenceProofMissing)
        );

        let mut continued = Ledger::absent();
        continued.continuation = Some(PaginationToken::new(1, Signature::from([3; 64])));
        assert_eq!(
            continued.resolve(resolver()).await.unwrap(),
            CredentialLookup::Unknown(UnknownCredential::PartialPage)
        );

        let mut twice = Ledger::enrolled(&credential());
        twice.enrollments.push(twice.enrollments[0].clone());
        let result = twice.resolve(resolver()).await;
        assert!(
            matches!(result, Err(CredentialError::EnrollmentCount(2))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_payment_takes_the_registered_key_and_the_record_bound_to_it() {
        let credential = credential();
        let address = registered_address();
        let mut ledger = Ledger::enrolled(&credential);
        let keys = RecipientKeyResolver::new(&address)
            .resolve(&ledger, &ledger)
            .await
            .unwrap();
        assert_eq!(keys.nullifier_pk(), credential.nullifier_pk);
        assert_eq!(keys.viewing_pubkey(), address.recipient.viewing_pubkey);

        let rotated = ViewingKey::new().pubkey();
        ledger.register(credential.nullifier_pk, rotated);
        let keys = RecipientKeyResolver::new(&address)
            .resolve(&ledger, &ledger)
            .await
            .unwrap();
        assert!(
            matches!(keys, RecipientKeys::Registered { viewing_pubkey, .. } if viewing_pubkey == rotated)
        );

        ledger.register([1; 32], rotated);
        let result = RecipientKeyResolver::new(&address)
            .resolve(&ledger, &ledger)
            .await;
        assert!(
            matches!(
                result,
                Err(CredentialError::ViewingKey(
                    ViewingKeyError::NullifierKeyMismatch
                ))
            ),
            "{result:?}"
        );

        let result = RecipientKeyResolver::new(&address)
            .resolve(&Ledger::absent(), &Ledger::absent())
            .await;
        assert!(
            matches!(result, Err(CredentialError::NotEnrolled)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn the_zero_key_needs_an_absent_owner_or_an_opt_in() {
        let address = zero_key_address();
        let ledger = Ledger::absent();
        let keys = RecipientKeyResolver::new(&address)
            .resolve(&ledger, &ledger)
            .await
            .unwrap();
        assert!(matches!(keys, RecipientKeys::ZeroKey { .. }), "{keys:?}");
        assert_eq!(keys.nullifier_pk(), ZERO_NULLIFIER_PUBKEY);

        let mut queued = Ledger::absent();
        queued.queue();
        let result = RecipientKeyResolver::new(&address)
            .resolve(&queued, &queued)
            .await;
        assert!(
            matches!(
                result,
                Err(CredentialError::Unknown(UnknownCredential::Queued))
            ),
            "{result:?}"
        );

        let credential = credential();
        let mut enrolled = Ledger::enrolled(&credential);
        let result = RecipientKeyResolver::new(&address)
            .resolve(&enrolled, &enrolled)
            .await;
        assert!(
            matches!(result, Err(CredentialError::EnrolledOwnerAtZeroKey)),
            "{result:?}"
        );
        let opted_in = RecipientKeyResolver::new(&address).with_zero_key_to_enrolled();
        let result = opted_in.resolve(&enrolled, &enrolled).await;
        assert!(
            matches!(result, Err(CredentialError::UnverifiedViewingKey)),
            "{result:?}"
        );

        let viewing_pubkey = ViewingKey::new().pubkey();
        enrolled.register(credential.nullifier_pk, viewing_pubkey);
        let keys = RecipientKeyResolver::new(&address)
            .with_zero_key_to_enrolled()
            .resolve(&enrolled, &enrolled)
            .await
            .unwrap();
        assert!(
            matches!(keys, RecipientKeys::ZeroKeyToEnrolled { .. }),
            "{keys:?}"
        );
        assert_eq!(keys.viewing_pubkey(), viewing_pubkey);
    }
}
