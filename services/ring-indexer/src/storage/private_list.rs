use anyhow::Result;
use custom_ring_interface::{
    storage_instruction::PrivateListWriteData, tracking::TrackingRegistry,
};
use sea_orm::{ConnectionTrait, QueryResult};

use super::{bytes, field, int, uint, ProjectedStore, StorageStore};

/// The only part of a private source the index holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredListWrite {
    pub position: [u8; 32],
    pub leaf: [u8; 32],
    pub write_counter: u64,
}

/// From `start`, written at or below `revision`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ListWritePage {
    pub start: u64,
    pub limit: u64,
    pub revision: u64,
}

impl<C: ConnectionTrait> StorageStore<'_, C> {
    pub async fn tracking_state(&self, registry: [u8; 32]) -> Result<Option<super::TrackingState>> {
        ProjectedStore::<C, TrackingRegistry>::new(self.tree.conn, registry)
            .state()
            .await
    }

    /// Ordinals continue over the source.
    pub async fn save_list_writes(
        &self,
        writes: &[PrivateListWriteData],
        revision: u64,
    ) -> Result<()> {
        let sql = "SELECT COUNT(*) AS writes FROM private_list_writes WHERE registry=$1";
        let row = self.tree.query_one(sql, vec![]).await?;
        let first = row.as_ref().map(|row| uint(row, "writes")).transpose()?;
        for (ordinal, write) in (first.unwrap_or_default()..).zip(writes) {
            let published = write.published();
            let sql = "INSERT INTO private_list_writes(registry,ordinal,revision,position,leaf,\
                       write_counter) VALUES($1,$2,$3,$4,$5,$6)";
            let values = vec![
                int(ordinal)?,
                int(revision)?,
                bytes(&published.position.0),
                bytes(&published.leaf),
                int(published.write_counter)?,
            ];
            self.tree.exec(sql, values).await?;
        }
        Ok(())
    }

    pub async fn list_writes(&self, page: ListWritePage) -> Result<Vec<StoredListWrite>> {
        let sql = "SELECT position, leaf, write_counter FROM private_list_writes \
                   WHERE registry=$1 AND ordinal>=$2 AND revision<=$3 ORDER BY ordinal LIMIT $4";
        let values = vec![int(page.start)?, int(page.revision)?, int(page.limit)?];
        let rows = self.tree.query_all(sql, values).await?;
        rows.iter().map(list_write).collect()
    }
}

fn list_write(row: &QueryResult) -> Result<StoredListWrite> {
    Ok(StoredListWrite {
        position: field(row, "position")?,
        leaf: field(row, "leaf")?,
        write_counter: uint(row, "write_counter")?,
    })
}
