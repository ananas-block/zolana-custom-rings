use anyhow::Result;
use custom_ring_interface::tracking::TrackingAuthorization;
use sea_orm::{ConnectionTrait, QueryResult};
use solana_address::Address;

use super::{bytes, field, int, uint, TrackingStore};

/// The owner's authorization as the chain holds it after its newest `Enroll`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Enrollment {
    pub owner: [u8; 32],
    pub authorization: [u8; 32],
    pub member: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub ct_hash: [u8; 32],
    pub list_tag: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; 32],
    pub viewing_u: [u8; 32],
    pub revision: u64,
    pub applied_revision: u64,
    pub last_enroll_slot: u64,
}

impl Enrollment {
    /// The account the program holds, its canonical checks run on this image.
    pub fn account(&self, registry: [u8; 32]) -> TrackingAuthorization {
        TrackingAuthorization {
            discriminator: TrackingAuthorization::DISCRIMINATOR,
            bump: 0,
            registry: Address::new_from_array(registry),
            owner: Address::new_from_array(self.owner),
            nullifier_pk: self.nullifier_pk,
            list_tag: self.list_tag,
            viewing_u: self.viewing_u,
            eph_u: self.eph_u,
            ciphertext: self.ciphertext,
            revision: self.revision.to_le_bytes(),
            applied_revision: self.applied_revision.to_le_bytes(),
            last_enroll_slot: self.last_enroll_slot.to_le_bytes(),
        }
    }
}

const ENROLLMENT_READ: &str = "SELECT a.owner, a.authorization, a.member, a.nullifier_pk, \
     a.ct_hash, a.list_tag, a.eph_u, a.ciphertext, e.viewing_u, e.revision, \
     e.slot AS last_enroll_slot, \
     (SELECT COALESCE(MAX(d.revision),0) FROM tracking_enrollments AS d \
      WHERE d.registry=a.registry AND d.owner=a.owner AND d.applied_slot IS NOT NULL) \
     AS applied_revision \
     FROM tracking_authorizations AS a JOIN tracking_enrollments AS e \
     ON e.registry=a.registry AND e.owner=a.owner \
     AND e.revision=(SELECT MAX(m.revision) FROM tracking_enrollments AS m \
     WHERE m.registry=a.registry AND m.owner=a.owner)";

impl<C: ConnectionTrait> TrackingStore<'_, C> {
    pub async fn enrollment(&self, owner: &[u8; 32]) -> Result<Option<Enrollment>> {
        self.enrollment_where("a.owner", owner).await
    }

    /// The account an apply names.
    pub async fn enrollment_at(&self, authorization: &[u8; 32]) -> Result<Option<Enrollment>> {
        self.enrollment_where("a.authorization", authorization)
            .await
    }

    /// The final fields of a member's authorization, the source of a leaf's seal.
    pub async fn enrollment_of(&self, member: &[u8; 32]) -> Result<Option<Enrollment>> {
        self.enrollment_where("a.member", member).await
    }

    async fn enrollment_where(&self, column: &str, key: &[u8; 32]) -> Result<Option<Enrollment>> {
        let sql = format!("{ENROLLMENT_READ} WHERE a.registry=$1 AND {column}=$2");
        let row = self.tree.query_one(&sql, vec![bytes(key)]).await?;
        row.as_ref().map(enrollment).transpose()
    }

    /// Ascending by owner, a rotation pending behind an applied revision included.
    pub async fn pending(&self, after: Option<&[u8; 32]>, limit: u64) -> Result<Vec<Enrollment>> {
        let sql = format!(
            "{ENROLLMENT_READ} WHERE a.registry=$1 AND a.owner>$2 AND e.applied_slot IS NULL \
             ORDER BY a.owner LIMIT $3"
        );
        let after = bytes(after.unwrap_or(&[0; 32]));
        let rows = self.tree.query_all(&sql, vec![after, int(limit)?]).await?;
        rows.iter().map(enrollment).collect()
    }

    pub async fn save_first(&self, first: &Enrollment, slot: u64) -> Result<()> {
        let sql = "INSERT INTO tracking_authorizations(registry,owner,authorization,member,\
                   nullifier_pk,ct_hash,list_tag,eph_u,ciphertext,slot) \
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)";
        let values = vec![
            bytes(&first.owner),
            bytes(&first.authorization),
            bytes(&first.member),
            bytes(&first.nullifier_pk),
            bytes(&first.ct_hash),
            bytes(&first.list_tag),
            bytes(&first.eph_u),
            bytes(&first.ciphertext),
            int(slot)?,
        ];
        self.tree.exec(sql, values).await?;
        self.save_revision(&first.owner, &first.viewing_u, first.revision, slot)
            .await
    }

    pub async fn save_revision(
        &self,
        owner: &[u8; 32],
        viewing_u: &[u8; 32],
        revision: u64,
        slot: u64,
    ) -> Result<()> {
        let sql = "INSERT INTO tracking_enrollments(registry,owner,revision,viewing_u,slot) \
                   VALUES($1,$2,$3,$4,$5)";
        let values = vec![bytes(owner), int(revision)?, bytes(viewing_u), int(slot)?];
        self.tree.exec(sql, values).await
    }

    pub async fn mark_applied(&self, owner: &[u8; 32], revision: u64, slot: u64) -> Result<()> {
        let sql = "UPDATE tracking_enrollments SET applied_slot=$4 \
                   WHERE registry=$1 AND owner=$2 AND revision=$3";
        let values = vec![bytes(owner), int(revision)?, int(slot)?];
        self.tree.exec(sql, values).await
    }
}

/// Undoes what the block at `slot` wrote, enrollments carry no revision a registry undo can read.
pub(super) async fn rollback_slot<C: ConnectionTrait>(conn: &C, slot: u64) -> Result<()> {
    for sql in [
        "DELETE FROM tracking_authorizations WHERE slot=$1",
        "DELETE FROM tracking_enrollments WHERE slot=$1",
        "UPDATE tracking_enrollments SET applied_slot=NULL WHERE applied_slot=$1",
    ] {
        super::exec(conn, sql, vec![int(slot)?]).await?;
    }
    Ok(())
}

fn enrollment(row: &QueryResult) -> Result<Enrollment> {
    Ok(Enrollment {
        owner: field(row, "owner")?,
        authorization: field(row, "authorization")?,
        member: field(row, "member")?,
        nullifier_pk: field(row, "nullifier_pk")?,
        ct_hash: field(row, "ct_hash")?,
        list_tag: field(row, "list_tag")?,
        eph_u: field(row, "eph_u")?,
        ciphertext: field(row, "ciphertext")?,
        viewing_u: field(row, "viewing_u")?,
        revision: uint(row, "revision")?,
        applied_revision: uint(row, "applied_revision")?,
        last_enroll_slot: uint(row, "last_enroll_slot")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::database;

    const REGISTRY: [u8; 32] = [7; 32];

    fn first(owner: u8) -> Enrollment {
        Enrollment {
            owner: [owner; 32],
            authorization: [owner + 50; 32],
            member: [owner + 100; 32],
            nullifier_pk: [1; 32],
            ct_hash: [2; 32],
            list_tag: [3; 32],
            eph_u: [4; 32],
            ciphertext: [5; 32],
            viewing_u: [6; 32],
            revision: 1,
            applied_revision: 0,
            last_enroll_slot: 10,
        }
    }

    #[tokio::test]
    async fn an_applied_enrollment_leaves_pending_and_a_rotation_returns_it() {
        let db = database().await;
        let store = TrackingStore::new(&db, REGISTRY);
        let owner = first(9);
        store.save_first(&owner, 10).await.unwrap();
        assert_eq!(store.pending(None, 8).await.unwrap(), [owner]);
        store.mark_applied(&owner.owner, 1, 11).await.unwrap();
        assert!(store.pending(None, 8).await.unwrap().is_empty());
        store
            .save_revision(&owner.owner, &[8; 32], 2, 12)
            .await
            .unwrap();
        let rotated = Enrollment {
            viewing_u: [8; 32],
            revision: 2,
            applied_revision: 1,
            last_enroll_slot: 12,
            ..owner
        };
        assert_eq!(store.pending(None, 8).await.unwrap(), [rotated]);
        assert_eq!(
            store.enrollment_of(&owner.member).await.unwrap(),
            Some(rotated)
        );
    }

    #[tokio::test]
    async fn pending_pages_ascend_by_owner_within_one_registry() {
        let db = database().await;
        let store = TrackingStore::new(&db, REGISTRY);
        for owner in [3, 1, 2] {
            store.save_first(&first(owner), 10).await.unwrap();
        }
        TrackingStore::new(&db, [8; 32])
            .save_first(&first(4), 10)
            .await
            .unwrap();
        let owners =
            |page: Vec<Enrollment>| page.iter().map(|row| row.owner[0]).collect::<Vec<_>>();
        assert_eq!(owners(store.pending(None, 2).await.unwrap()), [1, 2]);
        let after = [2; 32];
        assert_eq!(owners(store.pending(Some(&after), 2).await.unwrap()), [3]);
    }

    #[tokio::test]
    async fn a_rolled_back_block_restores_the_enrollment_it_moved() {
        let db = database().await;
        let store = TrackingStore::new(&db, REGISTRY);
        let owner = first(9);
        store.save_first(&owner, 10).await.unwrap();
        store.mark_applied(&owner.owner, 1, 11).await.unwrap();
        store
            .save_revision(&owner.owner, &[8; 32], 2, 12)
            .await
            .unwrap();
        rollback_slot(&db, 12).await.unwrap();
        let applied = Enrollment {
            applied_revision: 1,
            ..owner
        };
        assert_eq!(store.enrollment(&owner.owner).await.unwrap(), Some(applied));
        rollback_slot(&db, 11).await.unwrap();
        assert_eq!(store.enrollment(&owner.owner).await.unwrap(), Some(owner));
        rollback_slot(&db, 10).await.unwrap();
        assert_eq!(store.enrollment(&owner.owner).await.unwrap(), None);
    }
}
