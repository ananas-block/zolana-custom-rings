use std::collections::BTreeSet;

use custom_ring_interface::QUAD_HEIGHT;
use sea_orm::ConnectionTrait;
use zolana_ring_indexer::tree::{
    node_keys, Canopy, IndexedRecord, LoadedTree, MemberRead, MemberRecord, ReadRows, WritableLeaf,
    WrittenRows,
};

use crate::storage::{RegistryStore, StoredLeaf, TreeVersion};

pub(crate) struct LoadedRegistry<L = MemberRecord, const H: usize = QUAD_HEIGHT> {
    pub tree: LoadedTree<L, H>,
}

pub(crate) struct TreeRead<L = MemberRecord> {
    pub at: TreeVersion,
    pub records: RecordRead<L>,
    /// Empty leaves past `next_index` the read loads for new records.
    pub inserts: u64,
    pub canopy: Option<Canopy>,
}

pub(crate) enum RecordRead<L = MemberRecord> {
    /// Each member's record, the low record of an absent member.
    Members(BTreeSet<[u8; 32]>),
    Leaves(Vec<IndexedRecord<L>>),
}

impl<L: StoredLeaf> TreeRead<L> {
    /// Reads for applying `entries`, each entry may insert a record.
    pub fn batch<const H: usize>(at: TreeVersion, entries: &[L::Entry]) -> Self
    where
        L: WritableLeaf<H>,
    {
        Self {
            at,
            records: RecordRead::Members(
                entries
                    .iter()
                    .map(|entry| *<L as WritableLeaf<H>>::entry_member(entry))
                    .collect(),
            ),
            inserts: entries.len() as u64,
            canopy: None,
        }
    }

    pub async fn load<C: ConnectionTrait, const H: usize>(
        self,
        store: &RegistryStore<'_, C, L>,
    ) -> anyhow::Result<LoadedRegistry<L, H>> {
        let applied = self.at.version;
        let mut reads = Vec::new();
        let mut leaves = BTreeSet::new();
        match self.records {
            RecordRead::Members(members) => {
                for member in members {
                    let read = match store.record(&member, applied).await? {
                        Some(record) => {
                            leaves.insert(record.index);
                            MemberRead::Present(record)
                        }
                        None => {
                            let low = store.low_record(&member, applied).await?;
                            leaves.insert(low.index);
                            MemberRead::Absent { member, low }
                        }
                    };
                    reads.push(read);
                }
            }
            RecordRead::Leaves(rows) => {
                for row in rows {
                    reads.push(MemberRead::Present(row));
                    leaves.insert(row.index);
                }
            }
        }
        let next_index = self.at.next_index;
        let appended = next_index..(next_index + self.inserts).min(1 << (2 * H));
        let mut keys = node_keys::<H>(leaves.into_iter().chain(appended))?;
        keys.extend(self.canopy.into_iter().flat_map(Canopy::positions));
        let nodes = store.nodes(&keys, applied).await?;
        let rows = ReadRows {
            next_index,
            reads,
            nodes,
        };
        Ok(LoadedRegistry {
            tree: rows.into_tree(),
        })
    }
}

pub(crate) async fn plant_tree<C: ConnectionTrait, L: StoredLeaf, const H: usize>(
    store: &RegistryStore<'_, C, L>,
) -> anyhow::Result<()> {
    let rows = WrittenRows::<L>::fresh::<H>()?;
    let records = rows.records.values().copied().collect::<Vec<_>>();
    store.save_records(&records, 0).await?;
    store.save_nodes(&rows.nodes, 0).await
}
