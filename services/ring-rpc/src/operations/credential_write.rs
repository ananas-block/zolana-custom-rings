//! The writer's proven salted owner write, planned before its apply proof.
//!
//! A private list entry for an owner without a public asset entry proves three things in the apply
//! proof. The written key is `ListKey(member, salt)` under the salt the owner's credential commits to,
//! the credential UTXO sits in a state tree, and the credential address sits in tree 0 under one
//! address checkpoint. The same update raises the source's absence floor to the checkpoint sequence,
//! so every later salted read of the source proves under a root that holds the address and must open
//! the credential instead of proving absence.
//!
//! A settled credential whose address is still queued has no inclusion. Its write waits for the
//! forester batch and is refused if the wait ends first, it never proves under an older root.
//!
//! Read after `operations/credentials.rs`.

use std::{collections::BTreeMap, num::NonZeroU32, time::Duration};

use async_trait::async_trait;
use custom_ring_interface::{domain, AuditCredential};
use solana_address::Address;
use spr_instruction::{derive_output_blinding_seed, derive_transact_output_blinding};
use spr_program::program::ACCOUNT_BLINDING_SEED;
use spr_tree::{nullifier_tree::constants::DEFAULT_NULLIFIER_TREE_HEIGHT, UTXO_TREE_HEIGHT};
use thiserror::Error;
use zolana_ring_policy::Member;

use crate::{
    credentials::{CredentialPda, HeldCredential},
    error::RingRpcError,
};

pub const ADDRESS_TREE_HEIGHT: usize = DEFAULT_NULLIFIER_TREE_HEIGHT as usize;
/// `credential_writes` is a u16 bitmask over write indexes.
pub const MAX_CREDENTIAL_WRITES: usize = u16::BITS as usize;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CredentialWriteRefusal {
    #[error("a credential write batch names no write or more than its key width")]
    Width,
    #[error("write index {0} repeats or exceeds the credential write mask")]
    WriteIndex(u8),
    #[error("write {0} is not the list key of its owner under the credential salt")]
    UnboundListKey(u8),
    #[error("write {0} uses a salt the owner's credential does not commit to")]
    ListTag(u8),
    #[error("the address of write {0} is not yet in tree 0")]
    NotActive(u8),
    #[error("the address snapshot does not answer every requested address")]
    SnapshotShape,
    #[error("a state opening names another leaf or a second root of one tree")]
    StateOpening,
    #[error("the credential blinding does not derive from its address")]
    Blinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressLeaf {
    pub next: [u8; 32],
    pub index: u64,
    pub path: [[u8; 32]; ADDRESS_TREE_HEIGHT],
}

/// A leaf is `None` for an address still queued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressSnapshot {
    pub root: [u8; 32],
    pub sequence: u64,
    pub leaves: Vec<Option<AddressLeaf>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateOpening {
    pub tree_id: u16,
    pub root: [u8; 32],
    pub leaf_index: u64,
    pub path: [[u8; 32]; UTXO_TREE_HEIGHT],
}

#[async_trait]
pub trait CredentialEvidence: Sync {
    /// Every address under one root of one coherent read, in request order.
    async fn address_snapshot(
        &self,
        addresses: &[[u8; 32]],
    ) -> Result<AddressSnapshot, RingRpcError>;

    async fn state_opening(&self, leaf: &HeldCredential) -> Result<StateOpening, RingRpcError>;
}

/// `written_key` is the member field of `writes[write_index]` the update publishes.
#[derive(Clone, Copy, Debug)]
pub struct SaltedOwnerWrite {
    pub write_index: u8,
    pub written_key: [u8; 32],
    pub owner: HeldCredential,
    pub list_salt: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct ActivationWait {
    pub attempts: NonZeroU32,
    pub interval: Duration,
}

#[must_use]
pub struct CredentialWriteBatch {
    pub ring: Address,
    pub writes: Vec<SaltedOwnerWrite>,
    /// The apply key's credential write width, the state root table pads to it.
    pub width: usize,
    /// The source registry's current `absence_floor`.
    pub absence_floor: u64,
    pub wait: ActivationWait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialStateRoot {
    pub tree_id: u16,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialWriteInput {
    pub write_index: u8,
    pub list_salt: [u8; 32],
    pub credential: AuditCredential,
    pub blinding: [u8; 32],
    pub tree_slot: u8,
    pub state_index: u64,
    pub state_path: [[u8; 32]; UTXO_TREE_HEIGHT],
    pub address: AddressLeaf,
}

/// The apply statement credential run and the inputs its proof opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialWritePlan {
    pub credential_writes: u16,
    pub private_ring_id: [u8; 32],
    pub credential_owner: [u8; 32],
    pub address_root: [u8; 32],
    pub state_roots: Vec<CredentialStateRoot>,
    pub credentials: Vec<CredentialWriteInput>,
    /// `max(absence_floor, checkpoint sequence)`, written by the same update.
    pub absence_floor: u64,
}

impl CredentialWriteBatch {
    pub async fn plan(
        self,
        evidence: &impl CredentialEvidence,
    ) -> Result<CredentialWritePlan, RingRpcError> {
        // 1. The mask and the bindings need no chain read, a wrong salt fails before any wait.
        let credential_writes = self.mask()?;
        for write in &self.writes {
            write.bind()?;
        }
        // 2. Every address under one checkpoint, a queued one waits for the forester batch.
        let addresses: Vec<[u8; 32]> = self
            .writes
            .iter()
            .map(|write| write.owner.address)
            .collect();
        let (snapshot, leaves) = self.active(evidence, &addresses).await?;
        // 3. Distinct state trees in ascending id, one root each, padded with entry 0 to the width.
        let mut openings = Vec::with_capacity(self.writes.len());
        let mut roots: BTreeMap<u16, [u8; 32]> = BTreeMap::new();
        for write in &self.writes {
            let opening = evidence.state_opening(&write.owner).await?;
            let leaf = write.owner.leaf;
            let other_root = roots
                .insert(opening.tree_id, opening.root)
                .is_some_and(|root| root != opening.root);
            if opening.tree_id != leaf.tree_id
                || opening.leaf_index != leaf.leaf_index
                || other_root
            {
                return Err(CredentialWriteRefusal::StateOpening.into());
            }
            openings.push(opening);
        }
        let mut state_roots: Vec<CredentialStateRoot> = roots
            .into_iter()
            .map(|(tree_id, root)| CredentialStateRoot { tree_id, root })
            .collect();
        if state_roots.len() > self.width {
            return Err(CredentialWriteRefusal::Width.into());
        }
        if let Some(&first) = state_roots.first() {
            state_roots.resize(self.width, first);
        }
        // 4. Each credential selects its tree's slot privately, the blinding follows from its address.
        let credentials = self
            .writes
            .iter()
            .zip(openings)
            .zip(leaves)
            .map(|((write, opening), address)| {
                let tree_slot = state_roots
                    .iter()
                    .position(|entry| entry.tree_id == opening.tree_id)
                    .and_then(|slot| u8::try_from(slot).ok())
                    .ok_or(CredentialWriteRefusal::Width)?;
                Ok(CredentialWriteInput {
                    write_index: write.write_index,
                    list_salt: write.list_salt,
                    credential: write.owner.credential,
                    blinding: credential_blinding(&write.owner.address)?,
                    tree_slot,
                    state_index: opening.leaf_index,
                    state_path: opening.path,
                    address,
                })
            })
            .collect::<Result<Vec<_>, RingRpcError>>()?;
        let pda = CredentialPda::of(&self.ring)?;
        Ok(CredentialWritePlan {
            credential_writes,
            private_ring_id: pda.ring_id(),
            credential_owner: pda.owner_hash(),
            address_root: snapshot.root,
            state_roots,
            credentials,
            absence_floor: self.absence_floor.max(snapshot.sequence),
        })
    }

    fn mask(&self) -> Result<u16, CredentialWriteRefusal> {
        if self.writes.is_empty()
            || self.writes.len() > self.width
            || self.width > MAX_CREDENTIAL_WRITES
        {
            return Err(CredentialWriteRefusal::Width);
        }
        self.writes.iter().try_fold(0u16, |mask, write| {
            let bit = 1u16
                .checked_shl(u32::from(write.write_index))
                .filter(|bit| mask & bit == 0)
                .ok_or(CredentialWriteRefusal::WriteIndex(write.write_index))?;
            Ok(mask | bit)
        })
    }

    /// Reads until every address is applied or the wait ends, a timeout never reads as active.
    async fn active(
        &self,
        evidence: &impl CredentialEvidence,
        addresses: &[[u8; 32]],
    ) -> Result<(AddressSnapshot, Vec<AddressLeaf>), RingRpcError> {
        let mut attempt = 1;
        loop {
            let snapshot = evidence.address_snapshot(addresses).await?;
            if snapshot.leaves.len() != addresses.len() {
                return Err(CredentialWriteRefusal::SnapshotShape.into());
            }
            let queued = self
                .writes
                .iter()
                .zip(&snapshot.leaves)
                .find_map(|(write, leaf)| leaf.is_none().then_some(write.write_index));
            match queued {
                None => {
                    let leaves = snapshot.leaves.iter().copied().flatten().collect();
                    return Ok((snapshot, leaves));
                }
                Some(write_index) if attempt >= self.wait.attempts.get() => {
                    return Err(CredentialWriteRefusal::NotActive(write_index).into());
                }
                Some(_) => {
                    attempt += 1;
                    tokio::time::sleep(self.wait.interval).await;
                }
            }
        }
    }
}

impl SaltedOwnerWrite {
    /// The circuit rebuilds both checks, a refusal here saves a proof that cannot verify.
    fn bind(&self) -> Result<(), RingRpcError> {
        let credential = &self.owner.credential;
        let key = Member::salted(&Member::from_bytes(credential.member)?, &self.list_salt)?;
        if *key.as_bytes() != self.written_key {
            return Err(CredentialWriteRefusal::UnboundListKey(self.write_index).into());
        }
        if domain::list_tag(&self.list_salt).ok() != Some(credential.list_tag) {
            return Err(CredentialWriteRefusal::ListTag(self.write_index).into());
        }
        Ok(())
    }
}

/// Enroll's only write takes output slot 0 and its first nullifier is the credential address.
fn credential_blinding(address: &[u8; 32]) -> Result<[u8; 32], RingRpcError> {
    let derived = derive_output_blinding_seed(address, &ACCOUNT_BLINDING_SEED)
        .and_then(|seed| derive_transact_output_blinding(address, &seed, 0));
    derived.map_err(|_| CredentialWriteRefusal::Blinding.into())
}

#[cfg(test)]
#[path = "credential_write_tests.rs"]
mod credential_write_tests;
