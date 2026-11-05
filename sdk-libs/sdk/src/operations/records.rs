//! Registry records, read under a root or signed as record updates.

use async_trait::async_trait;
use custom_ring_interface::{domain, AuditCredential};
use solana_address::Address;
use solana_signer::Signer;
use spr_api::ZolanaApi;
use spr_client::{AsyncRpc, ClientError};
use spr_indexer_api::Hash;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::ShieldedAddress;
use zolana_ring_client::{
    records::{MemberOpeningRead, RecordPoolCheck, RecordPoolRead},
    rpc::{
        method::{GetRecordUpdateStatus, SubmitRecordUpdate},
        GetRecordUpdateStatusRequest, ReaderAccess, RecordUpdate, RecordUpdateEntry,
        RecordUpdateId, RecordUpdateStatus, SubmitRecordUpdateRequest, WalletGrant,
        AWAITABLE_LISTS,
    },
    AsyncRingIndexer, CredentialError, CredentialLookup, CredentialResolver, ReaderKey,
    RecipientKeyResolver, RecipientKeys, ViewingKeyResolver,
};
use zolana_ring_indexer::rpc::{
    GetStorageMemberOpeningsRequest, GetStorageRecordPoolRequest, RingListWriteView,
    MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_ring_keys::RingAddress;
use zolana_ring_policy::{ListSet, ListWrite, Member, MintPolicy, Writer};

use crate::{submission::BoundRoot, CustomRing, RingError};

/// Members' records under the newest root of the ring's records registry.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberRecords<'a> {
    pub ring: CustomRing,
    pub members: &'a [Member],
}

impl MemberRecords<'_> {
    /// One opening per member in member order, each verified against the root.
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<Vec<MemberOpeningRead>, RingError> {
        let members: Vec<[u8; 32]> = self
            .members
            .iter()
            .map(|member| *member.as_bytes())
            .collect();
        RecordReads {
            root: BoundRoot::newest(self.ring, rpc).await?,
            members: &members,
        }
        .read(rpc)
        .await
    }
}

pub(crate) struct RecordReads<'a> {
    pub root: BoundRoot,
    pub members: &'a [[u8; 32]],
}

impl RecordReads<'_> {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<Vec<MemberOpeningRead>, RingError> {
        let BoundRoot { registry, root, .. } = self.root;
        let mut reads = Vec::with_capacity(self.members.len());
        for chunk in self.members.chunks(MAX_RING_MEMBER_PAGE_LIMIT as usize) {
            let response = rpc
                .get_storage_member_openings(GetStorageMemberOpeningsRequest {
                    registry: registry.into(),
                    members: chunk.iter().copied().map(Hash).collect(),
                    expected_root: Hash(root),
                })
                .await?;
            if response.openings.len() != chunk.len() {
                return Err(RingError::InvalidRecordOpening);
            }
            for (member, view) in chunk.iter().zip(&response.openings) {
                reads.push(MemberOpeningRead::verify(view, &root, member)?);
            }
        }
        Ok(reads)
    }
}

/// Distinct members' records under a bound root, the canopy sized for `openings` paths.
pub(crate) struct PoolRead<'a> {
    pub root: BoundRoot,
    pub members: &'a [[u8; 32]],
    pub openings: usize,
}

impl PoolRead<'_> {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + AsyncRingIndexer + ?Sized),
    ) -> Result<RecordPoolRead, RingError> {
        let BoundRoot { registry, root, .. } = self.root;
        let response = rpc
            .get_storage_record_pool(GetStorageRecordPoolRequest {
                registry: registry.into(),
                members: self.members.iter().copied().map(Hash).collect(),
                expected_root: Hash(root),
                openings: self.openings as u64,
            })
            .await?;
        Ok(RecordPoolCheck {
            response: &response,
            root: &root,
            members: self.members,
            openings: self.openings,
        }
        .verify()?)
    }
}

/// A salted entry reads only under the salt the owner's credential commits, any other disarms it silently.
#[must_use]
pub struct SaltedOwnerCheck<'a> {
    pub address: &'a RingAddress,
}

impl SaltedOwnerCheck<'_> {
    /// The address's keys, bound to the owner's credential or to its authenticated absence.
    pub async fn run<R: AsyncRpc>(self, rpc: &R) -> Result<RecipientKeys, RingError> {
        Ok(RecipientKeyResolver::new(self.address)
            .resolve(rpc, rpc)
            .await?)
    }
}

/// An entry under a salt the owner's tag does not open is one no proof reads.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct OwnerSaltCheck<'a> {
    pub ring: CustomRing,
    pub owner: &'a Address,
    pub list_salt: &'a [u8; 32],
}

impl OwnerSaltCheck<'_> {
    pub async fn run<R: AsyncRpc>(self, rpc: &R) -> Result<(), RingError> {
        let member = *Member::owner_tag(self.owner.as_array())?.as_bytes();
        match CredentialResolver::new(self.ring.program_id(), *self.owner)
            .resolve(rpc, rpc)
            .await?
        {
            CredentialLookup::Present(present)
                if domain::list_tag(self.list_salt)? == present.credential.list_tag =>
            {
                Ok(())
            }
            CredentialLookup::Present(_) => Err(RingError::ListSaltMismatch { member }),
            CredentialLookup::Absent(_) => Err(RingError::ListSaltUnknown { member }),
            CredentialLookup::Unknown(unknown) => Err(CredentialError::Unknown(unknown).into()),
        }
    }
}

/// A nonzero key pays only the owner whose credential holds it. The zero key needs no credential,
/// the sender's key resolution decides whether an enrolled owner may take it.
pub(crate) fn check_output_key(
    credential: Option<&AuditCredential>,
    nullifier_pk: &[u8; 32],
    slot_index: usize,
) -> Result<(), RingError> {
    if *nullifier_pk == ZERO_NULLIFIER_PUBKEY {
        return Ok(());
    }
    match credential {
        None => Err(RingError::RecipientNotEnrolled { slot_index }),
        Some(credential) if credential.nullifier_pk != *nullifier_pk => {
            Err(RingError::RecipientKeyMismatch { slot_index })
        }
        Some(_) => Ok(()),
    }
}

/// The user record names the current viewing key, a body sealed to any other stays unread. An
/// owner with no record keeps the key its address names.
pub(crate) async fn check_recipient_viewing_key<R: AsyncRpc>(
    rpc: &R,
    recipient: &ShieldedAddress,
    slot_index: usize,
) -> Result<(), RingError> {
    let record = ViewingKeyResolver::new(recipient.solana_address()?)
        .with_credential(recipient.nullifier_pubkey)
        .resolve(rpc)
        .await?;
    match record {
        Some(record) if record.viewing_pubkey != recipient.viewing_pubkey => {
            Err(RingError::RecipientViewingKeyStale { slot_index })
        }
        Some(_) | None => Ok(()),
    }
}

/// The writer refuses the update after `valid_until_slot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordUpdateTarget {
    /// The cluster the writer serves.
    pub genesis_hash: [u8; 32],
    pub ring: CustomRing,
    /// The ring's own `StorageRegistry`.
    pub registry: Address,
    pub valid_until_slot: u64,
}

/// Signed by the wallet, every entry names the wallet.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletRecordUpdate {
    draft: UpdateDraft,
    member: Member,
}

/// Signed by the policy authority, a write may name any record.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityRecordUpdate {
    draft: UpdateDraft,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UpdateDraft {
    target: RecordUpdateTarget,
    signer: Address,
    entries: Vec<RecordUpdateEntry>,
    awaited_lists: ListSet,
}

#[async_trait]
pub trait RecordUpdateService: Send + Sync {
    /// Refuses before sending a request whose signature does not verify.
    async fn submit_record_update(
        &self,
        request: SubmitRecordUpdateRequest,
    ) -> Result<RecordUpdateId, RingError>;

    async fn get_record_update_status(
        &self,
        update_id: RecordUpdateId,
    ) -> Result<RecordUpdateStatus, RingError>;
}

impl WalletRecordUpdate {
    pub fn new(target: RecordUpdateTarget, wallet: Address) -> Result<Self, RingError> {
        Ok(Self {
            draft: UpdateDraft::new(target, wallet),
            member: Member::owner_tag(wallet.as_array())?,
        })
    }

    pub fn with_lists(mut self, lists: ListWrite) -> Result<Self, RingError> {
        check_writer(lists, Writer::Member)?;
        self.draft
            .entries
            .push(RecordUpdateEntry::Write(list_write(self.member, lists)));
        Ok(self)
    }

    /// Sets or clears the `Reader` list of the record [`Member::wallet_grant`] keys.
    pub fn with_wallet_grant(
        mut self,
        reader: ReaderKey,
        access: ReaderAccess,
    ) -> Result<Self, RingError> {
        let reader = reader.member()?;
        Member::wallet_grant(&self.member, &reader)?;
        self.draft
            .entries
            .push(RecordUpdateEntry::WalletGrant(WalletGrant {
                wallet: Hash(*self.member.as_bytes()),
                reader: Hash(*reader.as_bytes()),
                access,
            }));
        Ok(self)
    }

    /// Puts the update pending list approval, the writer sends none of its writes until a policy authority update sets every list of `lists` on the member.
    pub fn awaiting_list_approval(mut self, lists: ListSet) -> Result<Self, RingError> {
        if lists.is_empty() || !lists.is_subset(AWAITABLE_LISTS) {
            return Err(RingError::InvalidAwaitedLists);
        }
        self.draft.awaited_lists = lists;
        Ok(self)
    }

    pub fn sign<S: Signer + ?Sized>(
        self,
        wallet: &S,
    ) -> Result<SubmitRecordUpdateRequest, RingError> {
        self.draft.sign(wallet)
    }
}

impl AuthorityRecordUpdate {
    pub const fn new(target: RecordUpdateTarget, authority: Address) -> Self {
        Self {
            draft: UpdateDraft::new(target, authority),
        }
    }

    /// `member` is any record key, an owner identity or an asset.
    pub fn with_write(mut self, member: Member, write: ListWrite) -> Result<Self, RingError> {
        check_writer(write, Writer::Authority)?;
        self.draft
            .entries
            .push(RecordUpdateEntry::Write(list_write(member, write)));
        Ok(self)
    }

    /// Replaces all mint settings, zero values clear them.
    pub fn with_mint_policy(mut self, member: Member, policy: MintPolicy) -> Self {
        self.draft
            .entries
            .push(RecordUpdateEntry::Write(RingListWriteView {
                mint_policy: Some(policy),
                member: Hash(*member.as_bytes()),
                mask: 0,
                value: 0,
            }));
        self
    }

    /// The writer refuses a signer other than the policy authority.
    pub fn sign<S: Signer + ?Sized>(
        self,
        authority: &S,
    ) -> Result<SubmitRecordUpdateRequest, RingError> {
        self.draft.sign(authority)
    }
}

impl UpdateDraft {
    const fn new(target: RecordUpdateTarget, signer: Address) -> Self {
        Self {
            target,
            signer,
            entries: Vec::new(),
            awaited_lists: ListSet::EMPTY,
        }
    }

    fn sign<S: Signer + ?Sized>(self, signer: &S) -> Result<SubmitRecordUpdateRequest, RingError> {
        if self.entries.is_empty() {
            return Err(RingError::EmptyListWrite);
        }
        if signer.pubkey() != self.signer {
            return Err(RingError::RecordUpdateSigner {
                expected: self.signer,
            });
        }
        Ok(RecordUpdate {
            genesis_hash: Hash(self.target.genesis_hash),
            ring: self.target.ring.program_id().into(),
            entries: self.entries,
            valid_until_slot: self.target.valid_until_slot,
            awaited_lists: self.awaited_lists.record_bits(),
        }
        .sign(self.target.registry, signer)?)
    }
}

#[async_trait]
impl RecordUpdateService for ZolanaApi {
    async fn submit_record_update(
        &self,
        request: SubmitRecordUpdateRequest,
    ) -> Result<RecordUpdateId, RingError> {
        let id = request.verify()?;
        let response = self
            .call::<SubmitRecordUpdate>(request)
            .await
            .map_err(|error| ClientError::Rpc(error.to_string()))?;
        if response.update_id != id {
            return Err(RingError::RecordUpdateIdMismatch);
        }
        Ok(id)
    }

    async fn get_record_update_status(
        &self,
        update_id: RecordUpdateId,
    ) -> Result<RecordUpdateStatus, RingError> {
        Ok(self
            .call::<GetRecordUpdateStatus>(GetRecordUpdateStatusRequest { update_id })
            .await
            .map_err(|error| ClientError::Rpc(error.to_string()))?)
    }
}

fn list_write(member: Member, write: ListWrite) -> RingListWriteView {
    RingListWriteView {
        mint_policy: None,
        member: Hash(*member.as_bytes()),
        mask: write.mask(),
        value: write.value(),
    }
}

fn check_writer(write: ListWrite, writer: Writer) -> Result<(), RingError> {
    let lists = write.set().union(write.clear());
    match lists.difference(writer.writable()).iter().next() {
        Some(list) => Err(RingError::ListNotWritable { list, writer }),
        None => Ok(()),
    }
}
