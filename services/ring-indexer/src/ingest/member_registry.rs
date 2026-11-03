use std::collections::{BTreeMap, BTreeSet};

use custom_ring_interface::{
    member_registry::AuthorizedAddress, QueueEntry, MEMBER_REGISTRY_CAPACITY,
};
use sea_orm::ConnectionTrait;
use zolana_ring_indexer::{
    records::{QueuedWrite, SealedKey},
    tree::{
        node_keys, Canopy, IndexedRecord, LoadedTree, MemberRead, MemberRecord, ReadRows,
        WrittenRows,
    },
};

use crate::{
    indexer::{fault, ApplyError},
    storage::{RegistryStore, StoredRecord, TreeVersion},
};

/// `stored` keeps the sealed keys and addresses the tree does not hold.
pub(crate) struct LoadedRegistry {
    pub tree: LoadedTree,
    pub stored: BTreeMap<[u8; 32], StoredRecord>,
}

pub(crate) struct TreeRead {
    pub at: TreeVersion,
    pub records: RecordRead,
    /// Empty leaves past `next_index` the read loads for new records.
    pub inserts: u64,
    pub canopy: Option<Canopy>,
}

pub(crate) enum RecordRead {
    /// Each member's record, the low record of an absent member.
    Members(BTreeSet<[u8; 32]>),
    Leaves(Vec<StoredRecord>),
}

impl TreeRead {
    /// Reads for applying `entries`, each entry may insert a record.
    pub fn batch(at: TreeVersion, entries: &[QueueEntry]) -> Self {
        Self {
            at,
            records: RecordRead::Members(entries.iter().map(|entry| entry.member).collect()),
            inserts: entries.len() as u64,
            canopy: None,
        }
    }

    pub async fn load<C: ConnectionTrait>(
        self,
        store: &RegistryStore<'_, C>,
    ) -> anyhow::Result<LoadedRegistry> {
        let applied = self.at.version;
        let mut reads = Vec::new();
        let mut stored = BTreeMap::new();
        match self.records {
            RecordRead::Members(members) => {
                for member in members {
                    let read = match store.record(&member, applied).await? {
                        Some(record) => {
                            stored.insert(member, record);
                            MemberRead::Present(record.record)
                        }
                        None => {
                            let low = store.low_record(&member, applied).await?;
                            stored.insert(low.record.record.member, low);
                            MemberRead::Absent {
                                member,
                                low: low.record,
                            }
                        }
                    };
                    reads.push(read);
                }
            }
            RecordRead::Leaves(rows) => {
                for row in rows {
                    reads.push(MemberRead::Present(row.record));
                    stored.insert(row.record.record.member, row);
                }
            }
        }
        let next_index = self.at.next_index;
        let appended = next_index..(next_index + self.inserts).min(MEMBER_REGISTRY_CAPACITY);
        let leaves = stored.values().map(|record| record.record.index);
        let mut keys = node_keys(leaves.chain(appended))?;
        keys.extend(self.canopy.into_iter().flat_map(Canopy::positions));
        let nodes = store.nodes(&keys, applied).await?;
        let rows = ReadRows {
            next_index,
            reads,
            nodes,
        };
        Ok(LoadedRegistry {
            tree: rows.into_tree(),
            stored,
        })
    }
}

pub(crate) async fn plant_tree<C: ConnectionTrait>(
    store: &RegistryStore<'_, C>,
) -> anyhow::Result<()> {
    let rows = WrittenRows::fresh()?;
    let records = rows
        .records
        .values()
        .map(|record| StoredRecord {
            record: *record,
            seal: None,
            address: None,
        })
        .collect::<Vec<_>>();
    store.save_records(&records, 0).await?;
    store.save_nodes(&rows.nodes, 0).await
}

/// `address` is the enrolled preimage of an address write's hash.
pub(crate) struct ProjectedWrite {
    pub queued: QueuedWrite,
    pub address: Option<AuthorizedAddress>,
}

/// The fields a leaf hides, carried across relinks and unrelated writes.
pub(crate) struct HiddenFields<'a> {
    pub base: &'a BTreeMap<[u8; 32], StoredRecord>,
    pub pending: &'a [ProjectedWrite],
}

impl HiddenFields<'_> {
    pub fn stored(&self, record: IndexedRecord) -> Result<StoredRecord, ApplyError> {
        Ok(StoredRecord {
            record,
            seal: self.seal(&record.record)?,
            address: self.address(&record.record)?,
        })
    }

    /// A record keeps its sealed key, an escrow key the batch filled takes the seal of its entry.
    fn seal(&self, record: &MemberRecord) -> Result<Option<SealedKey>, ApplyError> {
        if record.escrow_key == [0; 32] {
            return Ok(None);
        }
        if let Some(kept) = self
            .base
            .get(&record.member)
            .filter(|stored| stored.record.record.escrow_key == record.escrow_key)
        {
            return Ok(kept.seal);
        }
        self.pending
            .iter()
            .map(|write| &write.queued)
            .find(|write| {
                write.entry.member == record.member && write.entry.escrow_key == record.escrow_key
            })
            .and_then(|write| write.seal)
            .map(Some)
            .ok_or_else(|| fault("an escrow key has no registration in its batch"))
    }

    /// A record keeps its address, an address hash the batch wrote takes the entry's enrollment.
    fn address(&self, record: &MemberRecord) -> Result<Option<AuthorizedAddress>, ApplyError> {
        if record.address_hash == [0; 32] {
            return Ok(None);
        }
        if let Some(kept) = self
            .base
            .get(&record.member)
            .filter(|stored| stored.record.record.address_hash == record.address_hash)
        {
            return Ok(kept.address);
        }
        self.pending
            .iter()
            .find(|write| {
                write.queued.entry.member == record.member
                    && write.queued.entry.address_hash == record.address_hash
            })
            .and_then(|write| write.address)
            .map(Some)
            .ok_or_else(|| fault("an address hash has no enrollment in its batch"))
    }
}
