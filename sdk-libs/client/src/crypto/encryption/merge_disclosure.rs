//! Host mirror of the anonymous merge disclosure (`prover/server/custom_rings/circuits/merge`).

use custom_ring_interface::{
    merge_disclosure_field_count, merge_disclosure_len, pack_disclosure, unpack_disclosure,
    MERGE_DISCLOSURE_INFO, MERGE_KEY_CIPHERTEXT_LEN, MERGE_WIDTHS,
};
use spr_hasher::primitives::{right_align, PACK_BE_CHUNK_BYTES};
use spr_keypair::{random_salt, X25519Keypair, X25519Pubkey};
use zeroize::Zeroizing;

use super::{open_stream, seal_stream, Result, StreamSchedule};
use crate::{AuditError, DisclosurePad};

/// ASCII "CR_MD", the Go `MergeDisclosureDomain`, a merge pad never repeats an output pad.
const MERGE_DISCLOSURE_DOMAIN: u64 = 0x4352_5f4d44;
const MERGE_SCHEDULE: StreamSchedule = StreamSchedule::Labelled(MERGE_DISCLOSURE_INFO);

/// The spent commitments of one merge in circuit slot order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeOpening {
    /// One per circuit slot, zero at a dummy, published or not.
    pub input_commitments: Vec<[u8; 32]>,
}

/// The sealed disclosure key and masked fields of one merge, with the secrets its proof witnesses.
pub struct MergeDisclosureEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub disclosure_key: Zeroizing<[u8; 32]>,
    pub eph_pk: X25519Pubkey,
    pub ciphertext: [u8; MERGE_KEY_CIPHERTEXT_LEN],
    pub fields: Vec<[u8; 32]>,
}

impl MergeOpening {
    /// The circuit packs whole 31-byte chunks, so the plaintext is zero padded to a chunk boundary.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let width = self.input_commitments.len();
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            merge_disclosure_field_count(width) * PACK_BE_CHUNK_BYTES,
        ));
        for commitment in &self.input_commitments {
            plaintext.extend_from_slice(commitment);
        }
        plaintext.resize(merge_disclosure_field_count(width) * PACK_BE_CHUNK_BYTES, 0);
        plaintext
    }

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

impl MergeDisclosureEncryption {
    /// `salt` is the SPP merge output salt, the statement binds the pad to it.
    pub fn new(opening: &MergeOpening, salt: [u8; 16], auditor_pk: &X25519Pubkey) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        key[..16].copy_from_slice(&random_salt());
        key[16..].copy_from_slice(&random_salt());
        Self::seal(opening, salt, auditor_pk, X25519Keypair::new(), key)
    }

    fn seal(
        opening: &MergeOpening,
        salt: [u8; 16],
        auditor_pk: &X25519Pubkey,
        ephemeral: X25519Keypair,
        disclosure_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        if !MERGE_WIDTHS.contains(&opening.input_commitments.len()) {
            return Err(AuditError::DisclosureLayout);
        }
        let mut ciphertext = *disclosure_key;
        seal_stream(&ephemeral, auditor_pk, MERGE_SCHEDULE, &mut ciphertext)?;
        let fields =
            merge_pad(&disclosure_key, &salt)?.encrypt(&pack_disclosure(&opening.encode()))?;
        Ok(Self {
            ephemeral_sk: ephemeral.secret_bytes(),
            disclosure_key,
            eph_pk: ephemeral.pubkey(),
            ciphertext,
            fields,
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
    let width = MERGE_WIDTHS
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
    use super::*;

    fn opening() -> MergeOpening {
        let mut input_commitments = vec![[0; 32]; 8];
        input_commitments[0] = [1; 32];
        input_commitments[1] = [2; 32];
        MergeOpening { input_commitments }
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
