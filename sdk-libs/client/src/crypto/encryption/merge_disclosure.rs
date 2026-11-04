//! Tag 47 commitment lists, read and never written.

use custom_ring_interface::{
    merge_disclosure_field_count, merge_disclosure_len, unpack_disclosure, MERGE_DISCLOSURE_INFO,
    MERGE_KEY_CIPHERTEXT_LEN,
};
use spr_hasher::primitives::{right_align, PACK_BE_CHUNK_BYTES};
use spr_keypair::{X25519Keypair, X25519Pubkey};
use zeroize::Zeroizing;

use super::{open_stream, Result, StreamSchedule};
use crate::{AuditError, DisclosurePad};

/// Frozen with the tag 47 frame.
const HISTORICAL_MERGE_WIDTHS: [usize; 2] = [8, 24];

/// ASCII "CR_MD", the Go `MergeDisclosureDomain`, a merge pad never repeats an output pad.
const MERGE_DISCLOSURE_DOMAIN: u64 = 0x4352_5f4d44;
const MERGE_SCHEDULE: StreamSchedule = StreamSchedule::Labelled(MERGE_DISCLOSURE_INFO);

/// The spent commitments of one merge in circuit slot order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeOpening {
    /// One per circuit slot, zero at a dummy, published or not.
    pub input_commitments: Vec<[u8; 32]>,
}

impl MergeOpening {
    fn decode(plaintext: &[u8], width: usize) -> Result<Self> {
        let (opening, padding) = plaintext
            .split_at_checked(merge_disclosure_len(width))
            .ok_or(AuditError::DisclosureLayout)?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(AuditError::DisclosurePadding);
        }
        Ok(Self {
            input_commitments: opening.as_chunks::<32>().0.to_vec(),
        })
    }
}

/// Opens a disclosure the ring program verified, its proof binds the list to the merge's commitments.
pub fn open_merge_disclosure(
    auditor: &X25519Keypair,
    eph_pk: &X25519Pubkey,
    ciphertext: &[u8; MERGE_KEY_CIPHERTEXT_LEN],
    salt: [u8; 16],
    fields: &[[u8; 32]],
) -> Result<MergeOpening> {
    let width = HISTORICAL_MERGE_WIDTHS
        .into_iter()
        .find(|width| merge_disclosure_field_count(*width) == fields.len())
        .ok_or(AuditError::DisclosureLayout)?;
    let mut key = Zeroizing::new(*ciphertext);
    open_stream(auditor, eph_pk, MERGE_SCHEDULE, &mut *key)?;
    let chunks = Zeroizing::new(merge_pad(&key, &salt)?.decrypt(fields)?);
    let plaintext = Zeroizing::new(
        unpack_disclosure(&chunks, chunks.len() * PACK_BE_CHUNK_BYTES)
            .ok_or(AuditError::DisclosureField)?,
    );
    MergeOpening::decode(&plaintext, width)
}

fn merge_pad(disclosure_key: &[u8; 32], salt: &[u8; 16]) -> Result<DisclosurePad> {
    DisclosurePad::keyed(
        &right_align(&MERGE_DISCLOSURE_DOMAIN.to_be_bytes()),
        disclosure_key,
        salt,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use custom_ring_interface::pack_disclosure;
    use spr_keypair::random_salt;

    use super::*;
    use crate::encryption::seal_stream;

    pub(crate) struct MergeDisclosureEncryption {
        pub(crate) eph_pk: X25519Pubkey,
        pub(crate) ciphertext: [u8; MERGE_KEY_CIPHERTEXT_LEN],
        pub(crate) fields: Vec<[u8; 32]>,
    }

    impl MergeDisclosureEncryption {
        pub(crate) fn new(
            opening: &MergeOpening,
            salt: [u8; 16],
            auditor_pk: &X25519Pubkey,
        ) -> Result<Self> {
            let width = opening.input_commitments.len();
            if !HISTORICAL_MERGE_WIDTHS.contains(&width) {
                return Err(AuditError::DisclosureLayout);
            }
            let ephemeral = X25519Keypair::new();
            let mut key = Zeroizing::new([0u8; 32]);
            key[..16].copy_from_slice(&random_salt());
            key[16..].copy_from_slice(&random_salt());
            let mut ciphertext = *key;
            seal_stream(&ephemeral, auditor_pk, MERGE_SCHEDULE, &mut ciphertext)?;
            let mut plaintext = opening.input_commitments.concat();
            plaintext.resize(merge_disclosure_field_count(width) * PACK_BE_CHUNK_BYTES, 0);
            Ok(Self {
                eph_pk: ephemeral.pubkey(),
                ciphertext,
                fields: merge_pad(&key, &salt)?.encrypt(&pack_disclosure(&plaintext))?,
            })
        }
    }

    fn opening() -> MergeOpening {
        let mut input_commitments = vec![[0; 32]; 8];
        input_commitments[0] = [1; 32];
        input_commitments[1] = [2; 32];
        MergeOpening { input_commitments }
    }

    #[test]
    fn a_base_commit_disclosure_opens() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../test-vectors/historical/merge_sealed.json"
        ))
        .unwrap();
        let bytes = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
        let fields = |value: &serde_json::Value| -> Vec<[u8; 32]> {
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|field| bytes(field).try_into().unwrap())
                .collect()
        };
        let opened = open_merge_disclosure(
            &X25519Keypair::from_bytes(&Zeroizing::new([0x51; 32])),
            &X25519Pubkey::from_bytes(bytes(&vector["eph_pk"]).try_into().unwrap()).unwrap(),
            &bytes(&vector["ciphertext"]).try_into().unwrap(),
            [0x21; 16],
            &fields(&vector["fields"]),
        )
        .unwrap();
        assert_eq!(opened.input_commitments, fields(&vector["list"]));
    }

    #[test]
    fn a_list_seals_to_its_field_count_and_opens_in_slot_order() {
        let auditor = X25519Keypair::new();
        let salt = [5; 16];
        let sealed = MergeDisclosureEncryption::new(&opening(), salt, &auditor.pubkey()).unwrap();
        assert_eq!(sealed.fields.len(), 9);
        let opened = open_merge_disclosure(
            &auditor,
            &sealed.eph_pk,
            &sealed.ciphertext,
            salt,
            &sealed.fields,
        )
        .unwrap();
        assert_eq!(opened, opening());
        let mut other_salt = salt;
        other_salt[0] ^= 1;
        assert!(!matches!(
            open_merge_disclosure(&auditor, &sealed.eph_pk, &sealed.ciphertext, other_salt, &sealed.fields),
            Ok(wrong) if wrong == opening()
        ));
    }

    #[test]
    fn a_list_off_every_merge_width_is_refused() {
        let auditor = X25519Keypair::new();
        let short = MergeOpening {
            input_commitments: vec![[1; 32]; 7],
        };
        assert!(matches!(
            MergeDisclosureEncryption::new(&short, [5; 16], &auditor.pubkey()),
            Err(AuditError::DisclosureLayout)
        ));
    }
}
