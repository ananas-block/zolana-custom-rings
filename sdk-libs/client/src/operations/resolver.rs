use custom_ring_interface::domain;
use solana_address::Address;
use spr_hasher::HasherError;
use spr_indexer_api::Hash;
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{KeypairError, X25519Pubkey};
use thiserror::Error;
use zolana_ring_indexer::tracking::{
    GetTrackingOpeningsRequest, RingTrackingOpening, RingTrackingRecordView,
};
use zolana_ring_keys::{RingAddress, RingKeyError};
use zolana_ring_member_registry::{OpeningCheck, RecordTreeError, TrackingOpening, TrackingRecord};

use crate::{
    indexer::{AsyncRingIndexer, RingIndexerError},
    records::path_of,
};

/// The salt stays with the address it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedRecipient {
    pub nullifier_pk: [u8; 32],
    /// The leaf's, a rotation moves it past the address.
    pub viewing_pubkey: X25519Pubkey,
    pub revision: u64,
    /// Zero under the zero key.
    pub list_tag: [u8; 32],
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error(transparent)]
    Address(#[from] RingKeyError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
    #[error(transparent)]
    Indexer(#[from] RingIndexerError),
    #[error("the tracking opening fails against the root")]
    Opening(#[source] RecordTreeError),
    #[error("the tracking opening is malformed")]
    MalformedOpening,
    #[error("the indexer answered {0} openings for one owner")]
    OpeningCount(usize),
    #[error("the address list salt hashes to another list tag than the tracking leaf")]
    ListTagMismatch,
    #[error("the tracking leaf holds another nullifier key than the address")]
    NullifierKeyMismatch,
    #[error("the owner holds no tracking row under the root, a pending enrollment grants nothing")]
    NotEnrolled,
    #[error("the owner holds a tracking row, the address names the zero key")]
    EnrolledOwnerAtZeroKey,
}

/// `registry` is the one the ring's policy names.
#[must_use]
pub struct RecipientResolver<'a> {
    pub address: &'a RingAddress,
    pub registry: Address,
    pub root: [u8; 32],
}

impl RecipientResolver<'_> {
    pub async fn resolve<I: AsyncRingIndexer + ?Sized>(
        self,
        indexer: &I,
    ) -> Result<ResolvedRecipient, ResolveError> {
        let member = self
            .address
            .recipient
            .signing_pubkey
            .owner_proof_input_hash()?;
        let response = indexer
            .get_tracking_openings(GetTrackingOpeningsRequest {
                registry: self.registry.into(),
                members: vec![Hash(member)],
                expected_root: Hash(self.root),
            })
            .await?;
        let [opening] = response.openings.as_slice() else {
            return Err(ResolveError::OpeningCount(response.openings.len()));
        };
        self.verify(&member, opening)
    }

    pub fn verify(
        &self,
        member: &[u8; 32],
        view: &RingTrackingOpening,
    ) -> Result<ResolvedRecipient, ResolveError> {
        let address = self.address;
        RingAddress::check_list_salt(&address.recipient, &address.list_salt)?;
        let path = path_of(&view.path).map_err(|_| ResolveError::MalformedOpening)?;
        let record = tracking_record(&view.record);
        let opening = match view.present {
            true => TrackingOpening::Present { record, path },
            false => TrackingOpening::Absent { low: record, path },
        };
        let row = OpeningCheck {
            opening: &opening,
            root: &self.root,
            member,
        }
        .verify()
        .map_err(ResolveError::Opening)?;
        let nullifier_pk = address.recipient.nullifier_pubkey;
        let zero_key = nullifier_pk == ZERO_NULLIFIER_PUBKEY;
        match (row, zero_key) {
            (None, true) => Ok(ResolvedRecipient {
                nullifier_pk,
                viewing_pubkey: address.recipient.viewing_pubkey,
                revision: 0,
                list_tag: [0; 32],
            }),
            (None, false) => Err(ResolveError::NotEnrolled),
            (Some(_), true) => Err(ResolveError::EnrolledOwnerAtZeroKey),
            (Some(row), false) => {
                if row.nullifier_pk != nullifier_pk {
                    return Err(ResolveError::NullifierKeyMismatch);
                }
                if domain::list_tag(&address.list_salt)? != row.list_tag {
                    return Err(ResolveError::ListTagMismatch);
                }
                Ok(ResolvedRecipient {
                    nullifier_pk: row.nullifier_pk,
                    viewing_pubkey: X25519Pubkey::from_u(row.viewing_u)?,
                    revision: row.revision,
                    list_tag: row.list_tag,
                })
            }
        }
    }
}

/// The leaf hashes only `ct_hash`.
pub fn tracking_record(view: &RingTrackingRecordView) -> TrackingRecord {
    TrackingRecord {
        member: view.member.0,
        next: view.next.0,
        nullifier_pk: view.nullifier_pk.0,
        ct_hash: view.ct_hash.0,
        viewing_u: view.viewing_u.0,
        revision: view.revision,
        list_tag: view.list_tag.0,
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use custom_ring_interface::tracking::TrackingEntry;
    use spr_indexer_api::Context;
    use spr_keypair::{
        shielded::{ShieldedAddress, ShieldedKeypair},
        SigningKey, ViewingKey,
    };
    use zolana_ring_indexer::{
        rpc::{RingRecordPathView, StorageRootView},
        tracking::{GetTrackingOpeningsResponse, RingTrackingOpening},
    };
    use zolana_ring_keys::list_tag;
    use zolana_ring_member_registry::{RecordOpening, RecordTree, TrackingPath, TrackingTree};

    use super::*;

    const RING: Address = Address::new_from_array([4; 32]);
    const REGISTRY: Address = Address::new_from_array([5; 32]);

    fn wallet(byte: u8) -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[byte; 32])).unwrap()
    }

    fn enrolled(owner: &ShieldedKeypair) -> RingAddress {
        RingAddress::enrolled(owner, RING).unwrap()
    }

    fn zero_key(owner: &ShieldedKeypair) -> RingAddress {
        RingAddress {
            recipient: ShieldedAddress {
                nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
                ..owner.shielded_address().unwrap()
            },
            ring_program_id: RING,
            list_salt: [0; 32],
        }
    }

    fn member(owner: &ShieldedKeypair) -> [u8; 32] {
        owner.signing_pubkey().owner_proof_input_hash().unwrap()
    }

    fn entry(owner: &ShieldedKeypair, viewing: X25519Pubkey) -> TrackingEntry {
        TrackingEntry {
            member: member(owner),
            nullifier_pk: owner.nullifier_key.pubkey().unwrap(),
            ct_hash: [7; 32],
            viewing_u: viewing.u(),
            revision: 3,
            list_tag: list_tag(
                &owner.nullifier_key,
                &zolana_ring_policy::ring_id_field(RING.as_array()).unwrap(),
            )
            .unwrap(),
        }
    }

    fn view_path(path: &TrackingPath) -> RingRecordPathView {
        RingRecordPathView {
            index: path.index,
            siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
        }
    }

    fn view_record(record: &TrackingRecord) -> RingTrackingRecordView {
        RingTrackingRecordView {
            member: Hash(record.member),
            next: Hash(record.next),
            nullifier_pk: Hash(record.nullifier_pk),
            ct_hash: Hash(record.ct_hash),
            viewing_u: Hash(record.viewing_u),
            revision: record.revision,
            list_tag: Hash(record.list_tag),
            seal: None,
        }
    }

    fn view(tree: &TrackingTree, member: &[u8; 32]) -> RingTrackingOpening {
        match tree.opening(member).unwrap() {
            RecordOpening::Present { record, path } => RingTrackingOpening {
                present: true,
                record: view_record(&record),
                path: view_path(&path),
            },
            RecordOpening::Absent { low, path } => RingTrackingOpening {
                present: false,
                record: view_record(&low),
                path: view_path(&path),
            },
        }
    }

    struct Fixture {
        tree: TrackingTree,
    }

    impl Fixture {
        fn with(entries: &[TrackingEntry]) -> Self {
            let mut tree = TrackingTree::new().unwrap();
            tree.apply([0; 32], entries).unwrap();
            Self { tree }
        }

        fn resolve(
            &self,
            address: &RingAddress,
            owner: &ShieldedKeypair,
        ) -> Result<ResolvedRecipient, ResolveError> {
            let member = member(owner);
            RecipientResolver {
                address,
                registry: REGISTRY,
                root: self.tree.root().unwrap(),
            }
            .verify(&member, &view(&self.tree, &member))
        }
    }

    #[test]
    fn an_applied_enrollment_resolves_to_its_leaf_and_the_leaf_viewing_key() {
        let owner = wallet(3);
        let rotated = ViewingKey::new().pubkey();
        let leaf = entry(&owner, rotated);
        let resolved = Fixture::with(&[leaf])
            .resolve(&enrolled(&owner), &owner)
            .unwrap();
        assert_eq!(
            resolved,
            ResolvedRecipient {
                nullifier_pk: leaf.nullifier_pk,
                viewing_pubkey: rotated,
                revision: 3,
                list_tag: leaf.list_tag,
            }
        );
    }

    #[test]
    fn a_salt_of_another_list_tag_is_refused() {
        let owner = wallet(3);
        let mut address = enrolled(&owner);
        address.list_salt = [9; 32];
        let leaf = entry(&owner, ViewingKey::new().pubkey());
        assert!(matches!(
            Fixture::with(&[leaf]).resolve(&address, &owner),
            Err(ResolveError::ListTagMismatch)
        ));
    }

    #[test]
    fn a_leaf_key_off_the_address_key_is_refused() {
        let owner = wallet(3);
        let mut leaf = entry(&owner, ViewingKey::new().pubkey());
        leaf.nullifier_pk = [8; 32];
        assert!(matches!(
            Fixture::with(&[leaf]).resolve(&enrolled(&owner), &owner),
            Err(ResolveError::NullifierKeyMismatch)
        ));
    }

    #[test]
    fn a_keyed_address_with_no_row_is_refused_as_pending_grants_nothing() {
        let owner = wallet(3);
        let other = wallet(4);
        let leaf = entry(&other, ViewingKey::new().pubkey());
        assert!(matches!(
            Fixture::with(&[leaf]).resolve(&enrolled(&owner), &owner),
            Err(ResolveError::NotEnrolled)
        ));
    }

    #[test]
    fn a_row_under_a_zero_key_address_is_refused() {
        let owner = wallet(3);
        let leaf = entry(&owner, ViewingKey::new().pubkey());
        assert!(matches!(
            Fixture::with(&[leaf]).resolve(&zero_key(&owner), &owner),
            Err(ResolveError::EnrolledOwnerAtZeroKey)
        ));
    }

    #[test]
    fn a_zero_key_address_with_no_row_resolves_to_the_zero_key() {
        let owner = wallet(3);
        let address = zero_key(&owner);
        let resolved = Fixture::with(&[]).resolve(&address, &owner).unwrap();
        assert_eq!(resolved.nullifier_pk, ZERO_NULLIFIER_PUBKEY);
        assert_eq!(resolved.viewing_pubkey, address.recipient.viewing_pubkey);
        assert_eq!(resolved.list_tag, [0; 32]);
    }

    #[test]
    fn an_opening_under_another_root_and_a_forged_absence_are_refused() {
        let owner = wallet(3);
        let member = member(&owner);
        let fixture = Fixture::with(&[entry(&owner, ViewingKey::new().pubkey())]);
        let address = enrolled(&owner);
        let check = |root, opening: &RingTrackingOpening| {
            RecipientResolver {
                address: &address,
                registry: REGISTRY,
                root,
            }
            .verify(&member, opening)
        };
        let honest = view(&fixture.tree, &member);
        assert!(matches!(
            check([1; 32], &honest),
            Err(ResolveError::Opening(RecordTreeError::RootMismatch))
        ));
        let empty = TrackingTree::new().unwrap();
        let forged = view(&empty, &member);
        assert!(matches!(
            check(fixture.tree.root().unwrap(), &forged),
            Err(ResolveError::Opening(RecordTreeError::RootMismatch))
        ));
    }

    struct Served {
        openings: Vec<RingTrackingOpening>,
        root: [u8; 32],
    }

    #[async_trait]
    impl AsyncRingIndexer for Served {
        async fn get_tracking_openings(
            &self,
            request: GetTrackingOpeningsRequest,
        ) -> Result<GetTrackingOpeningsResponse, RingIndexerError> {
            assert_eq!(request.registry, REGISTRY.into());
            assert_eq!(request.expected_root, Hash(self.root));
            Ok(GetTrackingOpeningsResponse {
                context: Context {
                    slot: 1,
                    block_time: 0,
                },
                root: StorageRootView {
                    root: Hash(self.root),
                    revision: 1,
                    next_index: 2,
                },
                openings: self.openings.clone(),
            })
        }
    }

    #[tokio::test]
    async fn the_read_names_the_owner_identity_and_refuses_an_extra_opening() {
        let owner = wallet(3);
        let member = member(&owner);
        let fixture = Fixture::with(&[entry(&owner, ViewingKey::new().pubkey())]);
        let root = fixture.tree.root().unwrap();
        let address = enrolled(&owner);
        let resolver = || RecipientResolver {
            address: &address,
            registry: REGISTRY,
            root,
        };
        let one = view(&fixture.tree, &member);
        let served = Served {
            openings: vec![one.clone()],
            root,
        };
        assert!(resolver().resolve(&served).await.is_ok());
        let served = Served {
            openings: vec![one.clone(), one],
            root,
        };
        assert!(matches!(
            resolver().resolve(&served).await,
            Err(ResolveError::OpeningCount(2))
        ));
    }
}
