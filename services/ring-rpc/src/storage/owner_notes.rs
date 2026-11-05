//! Each owner's active notes, sealed and keyed, a stolen database groups no note under an owner.
//!
//! A row enters with the commit that opens its note. The commit that spends the note writes the
//! spend slot on the row, and a later commit whose prior history slot covers that spend deletes it.
//! A read therefore touches the owner's live notes and the spends of at most one commit beyond the
//! history slot, and never a settled spend.
//!
//! Read after `storage/spent_index.rs`, its page commit runs these writes in its transaction.
//! Read before `operations/utxos.rs`, the wallet reads page over these rows.

use hkdf::Hkdf;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, Statement, Value};
use sha2::Sha256;
use solana_address::Address;
use spr_keypair::X25519Keypair;
use zolana_ring_policy::Member;

use crate::{
    spent_index::{note_body, note_from_body, slot_value, NoteSeal},
    utxos::{IndexedNote, PageDelta},
};

const INDEX_TAG_INFO: &[u8] = b"zolana/ring-rpc-owner-index";

/// One domain per tagged value, a tag of one kind never equals a tag of another of the same bytes.
#[derive(Clone, Copy)]
#[repr(u8)]
enum TagDomain {
    Owner = 0,
    Note = 1,
    Nullifier = 2,
}

/// HKDF expand under the ring salt is the PRF, the tags of another ring or auditor never match.
pub(crate) struct IndexTags(Hkdf<Sha256>);

impl IndexTags {
    pub(crate) fn derive(auditor: &X25519Keypair, ring: Address) -> Self {
        Self(Hkdf::new(
            Some(ring.as_ref()),
            auditor.secret_bytes().as_slice(),
        ))
    }

    /// Finds a note row by its nullifier, the row names neither the nullifier nor its spend.
    pub(crate) fn nullifier_tag(&self, nullifier: &[u8; 32]) -> Result<[u8; 32], DbErr> {
        self.tag(TagDomain::Nullifier, nullifier)
    }

    fn tag(&self, domain: TagDomain, value: &[u8; 32]) -> Result<[u8; 32], DbErr> {
        let mut tag = [0; 32];
        self.0
            .expand_multi_info(&[INDEX_TAG_INFO, &[domain as u8], value], &mut tag)
            .map_err(|_| DbErr::Custom("owner index tag is unusable".into()))?;
        Ok(tag)
    }
}

/// The note tag keys the seal, a row moved to another note tag fails to open.
fn sealed_row(
    seal: &NoteSeal,
    note_tag: &[u8; 32],
    indexed: &IndexedNote,
) -> Result<Vec<u8>, DbErr> {
    seal.seal(
        note_tag,
        &[indexed.commitment.as_slice(), &note_body(&indexed.note)].concat(),
    )
}

/// Every change of one page, inside the caller's transaction.
#[must_use]
pub(crate) struct OwnerNoteWrites<'a> {
    pub ring: Address,
    pub seal: &'a NoteSeal,
    pub delta: &'a PageDelta,
}

impl OwnerNoteWrites<'_> {
    pub(crate) async fn write(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        let Self { ring, seal, delta } = self;
        let backend = db.get_database_backend();
        let ring_value = || Value::from(ring.as_ref().to_vec());
        // 1. Each changed note takes its whole row, its spend slot set once a published row names it.
        for change in delta.owner_changes() {
            let note_tag = seal.tags.tag(TagDomain::Note, &change.note.commitment)?;
            let owner_tag = seal.tags.tag(TagDomain::Owner, &change.member)?;
            let spent_slot = match change.note.spent_at {
                Some(slot) => slot_value(slot)?,
                None => Value::BigInt(None),
            };
            db.execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO owner_notes(ring,owner_tag,note_tag,sealed,spent_slot) \
                 VALUES($1,$2,$3,$4,$5) ON CONFLICT(ring,owner_tag,note_tag) DO UPDATE SET \
                 sealed=excluded.sealed,spent_slot=excluded.spent_slot",
                vec![
                    ring_value(),
                    owner_tag.to_vec().into(),
                    note_tag.to_vec().into(),
                    sealed_row(seal, &note_tag, &change.note)?.into(),
                    spent_slot,
                ],
            ))
            .await?;
        }
        // 2. The history slot before the page bounds the deletion, a read holding that slot or a
        //    later one never counts the change of a note it no longer finds.
        db.execute(Statement::from_sql_and_values(
            backend,
            "DELETE FROM owner_notes WHERE ring=$1 AND spent_slot<=$2",
            vec![ring_value(), slot_value(delta.prune_through())?],
        ))
        .await?;
        Ok(())
    }
}

/// One owner's rows in note tag order, the cursor of a wallet page.
#[must_use]
pub(crate) struct OwnerNotesRead<'a> {
    pub db: &'a DatabaseConnection,
    pub ring: Address,
    pub seal: &'a NoteSeal,
    pub member: [u8; 32],
}

impl OwnerNotesRead<'_> {
    pub(crate) async fn read(self) -> Result<Vec<IndexedNote>, DbErr> {
        let Self {
            db,
            ring,
            seal,
            member,
        } = self;
        let owner_tag = seal.tags.tag(TagDomain::Owner, &member)?;
        let rows = db
            .query_all(Statement::from_sql_and_values(
                db.get_database_backend(),
                "SELECT note_tag,sealed,spent_slot FROM owner_notes WHERE ring=$1 AND owner_tag=$2 \
                 ORDER BY note_tag",
                vec![ring.as_ref().to_vec().into(), owner_tag.to_vec().into()],
            ))
            .await?;
        let moved = || DbErr::Custom("owner note row names another note or owner".into());
        rows.iter()
            .map(|row| {
                let note_tag = <[u8; 32]>::try_from(row.try_get::<Vec<u8>>("", "note_tag")?)
                    .map_err(|_| moved())?;
                let body = seal.open(&note_tag, &row.try_get::<Vec<u8>>("", "sealed")?)?;
                let (commitment, note) = body.split_at_checked(32).ok_or_else(moved)?;
                let commitment = <[u8; 32]>::try_from(commitment).map_err(|_| moved())?;
                let note = note_from_body(note)?;
                // A row copied under another owner tag opens, its body still names the first owner.
                let owner = Member::owner_tag(&note.utxo.owner_key).map_err(|_| moved())?;
                if seal.tags.tag(TagDomain::Note, &commitment)? != note_tag
                    || *owner.as_bytes() != member
                {
                    return Err(moved());
                }
                let spent_at = row
                    .try_get::<Option<i64>>("", "spent_slot")?
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| DbErr::Custom("negative spend slot".into()))?;
                Ok(IndexedNote {
                    key: note_tag,
                    commitment,
                    note,
                    spent_at,
                })
            })
            .collect()
    }
}
