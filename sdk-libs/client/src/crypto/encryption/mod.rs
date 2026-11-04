//! Mirrors `custom_rings/circuits/base`, streams keyed by `Poseidon(CR_S, dh, eph_pk, auditor_pk)`.

use custom_ring_interface::{
    domain::{self, DEPOSIT_AUDIT_LABEL, REGISTER_KEY_LABEL},
    OpeningRecord, RecordKind, RingDepositAuditCapsule, MAX_RING_DEPOSIT_AUDIT_SLOTS,
    OPENING_RECORD_LEN, REGISTER_KEY_CIPHERTEXT_LEN, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN,
    STREAM_BLOCK_LEN, STREAM_FIRST_COUNTER,
};
use spr_hasher::{
    primitives::{is_canonical_bn254_scalar_be, pack_be, right_align, solana_owner_identity},
    Hasher, Poseidon,
};
use spr_keypair::{symmetric_apply, NullifierKey, X25519Keypair, X25519Pubkey};
use zeroize::Zeroizing;
use zolana_ring_keys::{symmetric_apply_audit, RingStream};

use crate::AuditError;

type Result<T> = core::result::Result<T, AuditError>;

mod deposit_capsule;
mod merge_disclosure;
mod merge_record;
pub use deposit_capsule::{DepositCapsule, HistoricalDepositCapsule};
#[cfg(test)]
pub(crate) use merge_disclosure::tests::MergeDisclosureEncryption;
pub use merge_disclosure::{open_merge_disclosure, MergeOpening};
pub use merge_record::{open_merge_record, MergeRecordSeal, SealedMergeOpening};

/// The auditor key's u-coordinate, the tag the auditor scans for.
pub fn auditor_view_tag(pk: &X25519Pubkey) -> [u8; 32] {
    pk.u()
}

/// The key schedule of a sealed stream, `Labelled` is zolana's `TMS*` and serves merge alone.
#[derive(Clone, Copy)]
pub(crate) enum StreamSchedule {
    Ring(&'static [u8; 10]),
    Labelled(&'static [u8; 10]),
}

/// Binds the X25519 output to both keys that produced it, in the order `seal.go` hashes.
pub(crate) fn shared_secret(
    dh: &[u8; 32],
    ephemeral: &X25519Pubkey,
    auditor: &X25519Pubkey,
) -> Result<Zeroizing<[u8; 32]>> {
    let [dh0, dh1] = pack_be(dh);
    let [eph0, eph1] = pack_be(ephemeral.as_bytes());
    let [aud0, aud1] = pack_be(auditor.as_bytes());
    Ok(Zeroizing::new(Poseidon::hashv(&[
        &domain::field(domain::AUDIT_SHARED_SECRET),
        &dh0,
        &dh1,
        &eph0,
        &eph1,
        &aud0,
        &aud1,
    ])?))
}

/// Seals `data` from an ephemeral key to the auditor.
pub(crate) fn seal_stream(
    ephemeral: &X25519Keypair,
    auditor: &X25519Pubkey,
    schedule: StreamSchedule,
    data: &mut [u8],
) -> Result<()> {
    apply_stream(&*sealing_secret(ephemeral, auditor)?, schedule, data)
}

pub(crate) fn open_stream(
    auditor: &X25519Keypair,
    ephemeral: &X25519Pubkey,
    schedule: StreamSchedule,
    data: &mut [u8],
) -> Result<()> {
    apply_stream(&*opening_secret(auditor, ephemeral)?, schedule, data)
}

pub(crate) fn sealing_ring_stream(
    ephemeral: &X25519Keypair,
    auditor: &X25519Pubkey,
    label: &[u8; 10],
) -> Result<RingStream> {
    Ok(RingStream::new(
        &*sealing_secret(ephemeral, auditor)?,
        label,
    )?)
}

/// Reads each region of a sealed stream at its own counter.
pub(crate) fn opening_ring_stream(
    auditor: &X25519Keypair,
    ephemeral: &X25519Pubkey,
    label: &[u8; 10],
) -> Result<RingStream> {
    Ok(RingStream::new(
        &*opening_secret(auditor, ephemeral)?,
        label,
    )?)
}

fn sealing_secret(
    ephemeral: &X25519Keypair,
    auditor: &X25519Pubkey,
) -> Result<Zeroizing<[u8; 32]>> {
    shared_secret(&*ephemeral.ecdh(auditor)?, &ephemeral.pubkey(), auditor)
}

fn opening_secret(
    auditor: &X25519Keypair,
    ephemeral: &X25519Pubkey,
) -> Result<Zeroizing<[u8; 32]>> {
    shared_secret(&*auditor.ecdh(ephemeral)?, ephemeral, &auditor.pubkey())
}

fn apply_stream(secret: &[u8; 32], schedule: StreamSchedule, data: &mut [u8]) -> Result<()> {
    match schedule {
        StreamSchedule::Ring(label) => symmetric_apply_audit(secret, label, data)?,
        StreamSchedule::Labelled(label) => symmetric_apply(secret, label, data)?,
    }
    Ok(())
}

/// A nullifier key sealed to the ring auditor, plaintext byte zero is the pad the circuit pins.
pub struct NullifierKeyEnvelope {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub sealed: SealedNullifierKey,
    pub nullifier_pk: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedNullifierKey {
    pub eph_pk: X25519Pubkey,
    pub ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
}

impl NullifierKeyEnvelope {
    pub fn new(nullifier_key: &NullifierKey, auditor_pk: &X25519Pubkey) -> Result<Self> {
        Self::seal(nullifier_key, auditor_pk, X25519Keypair::new())
    }

    fn seal(
        nullifier_key: &NullifierKey,
        auditor_pk: &X25519Pubkey,
        ephemeral: X25519Keypair,
    ) -> Result<Self> {
        let mut ciphertext = Zeroizing::new(right_align(&nullifier_key.secret()));
        seal_stream(
            &ephemeral,
            auditor_pk,
            StreamSchedule::Ring(REGISTER_KEY_LABEL),
            &mut *ciphertext,
        )?;
        Ok(Self {
            ephemeral_sk: ephemeral.secret_bytes(),
            sealed: SealedNullifierKey {
                eph_pk: ephemeral.pubkey(),
                ciphertext: *ciphertext,
            },
            nullifier_pk: nullifier_key.pubkey()?,
        })
    }
}

impl SealedNullifierKey {
    /// The pad alone does not authenticate the key against its registry record.
    pub fn open(&self, auditor: &X25519Keypair) -> Result<NullifierKey> {
        let mut plaintext = Zeroizing::new(self.ciphertext);
        open_stream(
            auditor,
            &self.eph_pk,
            StreamSchedule::Ring(REGISTER_KEY_LABEL),
            &mut *plaintext,
        )?;
        let [pad, secret @ ..] = &*plaintext;
        if *pad != 0 {
            return Err(AuditError::NullifierPad);
        }
        Ok(NullifierKey::from_secret(*secret))
    }
}

/// The owner commitment preimage a deposit discloses to the auditor.
pub struct DepositOpening {
    pub owner_hash: [u8; 32],
    pub blinding: Zeroizing<[u8; 32]>,
    /// The proof binds its Solana owner identity into `owner_hash`.
    pub owner_key: [u8; 32],
    /// `None` under `CRDEP001`, which named only the commitment preimage.
    pub note: Option<DepositedNote>,
}

/// What a `CRDEP002` record names of its note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositedNote {
    pub nullifier_pk: [u8; 32],
    pub mint: [u8; 32],
    pub amount: u64,
}

impl DepositOpening {
    /// False when a record names another mint or amount than the confirmed output.
    pub(crate) fn agrees_with(&self, mint: &[u8; 32], amount: u64) -> bool {
        self.note
            .is_none_or(|note| note.mint == *mint && note.amount == amount)
    }
}

/// Batch ciphertexts and the ephemeral secret the disclosure proof witnesses.
pub struct DepositEncryption {
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
    pub ephemeral_pk: X25519Pubkey,
    pub ciphertexts: Vec<[u8; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN]>,
}

const DEPOSIT_STREAM_LEN: usize = RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN * MAX_RING_DEPOSIT_AUDIT_SLOTS;
const DEPOSIT_SCHEDULE: StreamSchedule = StreamSchedule::Ring(DEPOSIT_AUDIT_LABEL);
/// AES blocks per slot, slot i starts at `2 + 9i`.
const DEPOSIT_SLOT_BLOCKS: u32 = (RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN / STREAM_BLOCK_LEN) as u32;
const _: () = assert!(RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN.is_multiple_of(STREAM_BLOCK_LEN));

/// Seals one record per deposit to the ring's pinned auditor key, each record's secret its blinding.
pub fn seal_deposits(
    records: &[OpeningRecord],
    auditor_pk: &X25519Pubkey,
) -> Result<DepositEncryption> {
    seal_deposits_with(records, auditor_pk, X25519Keypair::new())
}

fn seal_deposits_with(
    records: &[OpeningRecord],
    auditor_pk: &X25519Pubkey,
    ephemeral: X25519Keypair,
) -> Result<DepositEncryption> {
    if records.is_empty() || records.len() > MAX_RING_DEPOSIT_AUDIT_SLOTS {
        return Err(AuditError::DepositCount(records.len()));
    }
    let mut plaintext = Zeroizing::new([0u8; DEPOSIT_STREAM_LEN]);
    let (slots, _) = plaintext.as_chunks_mut::<RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN>();
    for (slot, record) in slots.iter_mut().zip(records) {
        *slot = record.encode();
    }
    seal_stream(&ephemeral, auditor_pk, DEPOSIT_SCHEDULE, &mut *plaintext)?;
    Ok(DepositEncryption {
        ephemeral_sk: ephemeral.secret_bytes(),
        ephemeral_pk: ephemeral.pubkey(),
        ciphertexts: plaintext.as_chunks().0[..records.len()].to_vec(),
    })
}

/// Opens a capsule only after binding every ciphertext byte to its confirmed deposit proof.
pub fn open_deposit(
    capsule: &DepositCapsule<'_>,
    auditor: &X25519Keypair,
    owner_utxo_hash: &[u8; 32],
    confirmed: &crate::ConfirmedDeposit,
) -> Result<DepositOpening> {
    if !confirmed.matches(*capsule, owner_utxo_hash) {
        return Err(AuditError::DepositOpeningMismatch);
    }
    let opening = match capsule {
        DepositCapsule::Record(capsule) => open_record(capsule, auditor)?,
        DepositCapsule::Historical(capsule) => capsule.open(auditor)?,
    };
    if Poseidon::hashv(&[&opening.owner_hash, opening.blinding.as_slice()])? != *owner_utxo_hash {
        return Err(AuditError::DepositOpeningMismatch);
    }
    Ok(opening)
}

/// Slot `i` at counter `2 + 9i`, the owner hash rebuilt from the record's key and owner.
fn open_record(
    capsule: &RingDepositAuditCapsule<'_>,
    auditor: &X25519Keypair,
) -> Result<DepositOpening> {
    let mut plaintext = Zeroizing::new([0u8; OPENING_RECORD_LEN]);
    plaintext.copy_from_slice(capsule.ciphertext);
    opening_ring_stream(
        auditor,
        &X25519Pubkey::from_bytes(*capsule.eph_pk)?,
        DEPOSIT_AUDIT_LABEL,
    )?
    .apply_at(
        STREAM_FIRST_COUNTER + u32::from(capsule.slot_index) * DEPOSIT_SLOT_BLOCKS,
        &mut *plaintext,
    );
    let mismatch = |_| AuditError::DepositOpeningMismatch;
    let OpeningRecord { record, secret } =
        OpeningRecord::decode(&*plaintext).map_err(mismatch)?;
    if record.kind != RecordKind::Ring
        || !is_canonical_bn254_scalar_be(&record.nullifier_pk)
        || !is_canonical_bn254_scalar_be(&secret)
    {
        return Err(AuditError::DepositOpeningMismatch);
    }
    let owner_hash = Poseidon::hashv(&[
        &solana_owner_identity(&record.owner_key)?,
        &record.nullifier_pk,
    ])?;
    Ok(DepositOpening {
        owner_hash,
        blinding: Zeroizing::new(secret),
        owner_key: record.owner_key,
        note: Some(DepositedNote {
            nullifier_pk: record.nullifier_pk,
            mint: record.mint,
            amount: record.amount,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    mod deposit_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/common/deposit.rs"
        ));
    }

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        let decoded = hex::decode(value).expect("hex");
        decoded.try_into().expect("byte length")
    }

    #[test]
    fn shared_secret_matches_the_circuit_vector() {
        let diffie_hellman_x =
            bytes("464b33b122dc1346a6012199742d7e14b2ee6436589c454a579fdda24feec92c");
        let ephemeral_key = X25519Pubkey::from_bytes(bytes(
            "048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966",
        ))
        .expect("ephemeral key");
        let auditor_key = X25519Pubkey::from_bytes(bytes(
            "04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a",
        ))
        .expect("auditor key");
        let secret =
            shared_secret(&diffie_hellman_x, &ephemeral_key, &auditor_key).expect("shared secret");
        assert_eq!(
            *secret,
            bytes("2590b2b949a2f87b9201e4d065167ea9282c4bd06a32e888e24e33c5bddae54f")
        );
    }

    #[test]
    fn shared_secret_binds_both_keys_and_the_ecdh_value() {
        let auditor_key = X25519Keypair::new().pubkey();
        let other_auditor_key = X25519Keypair::new().pubkey();
        let ephemeral_key = X25519Keypair::new().pubkey();
        let other_ephemeral_key = X25519Keypair::new().pubkey();
        let derive = |dh, eph, auditor| shared_secret(dh, eph, auditor).expect("shared secret");
        let secret = derive(&[7u8; 32], &ephemeral_key, &auditor_key);
        assert_ne!(secret, derive(&[8u8; 32], &ephemeral_key, &auditor_key));
        assert_ne!(
            secret,
            derive(&[7u8; 32], &other_ephemeral_key, &auditor_key)
        );
        assert_ne!(
            secret,
            derive(&[7u8; 32], &ephemeral_key, &other_auditor_key)
        );
    }

    #[test]
    fn nullifier_key_envelope_round_trips_through_the_auditor() {
        let auditor = X25519Keypair::new();
        let nullifier_key = NullifierKey::from_secret([7u8; 31]);
        let envelope =
            NullifierKeyEnvelope::new(&nullifier_key, &auditor.pubkey()).expect("encrypt");
        let recovered = envelope.sealed.open(&auditor).expect("decrypt");
        assert_eq!(
            recovered.secret().as_slice(),
            nullifier_key.secret().as_slice()
        );
        assert_eq!(
            envelope.nullifier_pk,
            nullifier_key.pubkey().expect("pubkey")
        );
    }

    #[test]
    fn a_stranger_auditor_cannot_recover_the_nullifier_key() {
        let auditor = X25519Keypair::new();
        let stranger = X25519Keypair::new();
        let nullifier_key = NullifierKey::from_secret([9u8; 31]);
        let envelope =
            NullifierKeyEnvelope::new(&nullifier_key, &auditor.pubkey()).expect("encrypt");
        match envelope.sealed.open(&stranger) {
            Err(AuditError::NullifierPad) => {}
            Ok(recovered) => {
                assert_ne!(
                    recovered.secret().as_slice(),
                    nullifier_key.secret().as_slice()
                )
            }
            Err(other) => panic!("unexpected error {other}"),
        }
    }

    /// The `go_vectors.rs` auditor scalar, the TypeScript mirror pins the same values.
    const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";
    const EPHEMERAL_SK: &str = "011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e";
    const NULLIFIER_SECRET: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const NULLIFIER_PK: &str = "2d1faf6cf358763421511eb637adf7b6609443d38edc4ed2b042dfbf834b03f5";
    const EPH_PK: &str = "043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63";
    const CIPHERTEXT: &str = "44409b9e390ec45df98e391d4a86c1e57b52cbd8d60eb9f7426442ed822616ba";

    #[test]
    fn the_sealed_key_matches_the_pinned_vector() {
        let auditor = X25519Keypair::from_bytes(&bytes(AUDITOR_SK));
        let nullifier_key = NullifierKey::from_secret(bytes(NULLIFIER_SECRET));
        let ephemeral = X25519Keypair::from_bytes(&bytes(EPHEMERAL_SK));
        let envelope =
            NullifierKeyEnvelope::seal(&nullifier_key, &auditor.pubkey(), ephemeral).expect("seal");
        assert_eq!(envelope.nullifier_pk, bytes(NULLIFIER_PK));
        assert_eq!(envelope.sealed.eph_pk.as_bytes(), &bytes::<33>(EPH_PK));
        assert_eq!(envelope.sealed.ciphertext, bytes(CIPHERTEXT));
        assert_eq!(
            envelope
                .sealed
                .open(&auditor)
                .expect("open")
                .secret()
                .as_slice(),
            &bytes::<31>(NULLIFIER_SECRET)
        );
    }

    fn hex_field(value: &serde_json::Value) -> [u8; 32] {
        let digits = value.as_str().unwrap().trim_start_matches("0x");
        bytes(&format!("{digits:0>64}"))
    }

    /// The prover's own request, its statement names every sealed byte through `hash_bytes`.
    #[test]
    fn the_seal_reaches_the_public_hash_of_the_go_request() {
        let request: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../prover/ring/testdata/deposit/custom-ring-deposit-2.json"
        ))
        .unwrap();
        let count = request["count"].as_u64().unwrap() as usize;
        let list = |name: &str| -> Vec<[u8; 32]> {
            request[name]
                .as_array()
                .unwrap()
                .iter()
                .map(hex_field)
                .collect()
        };
        let amounts = list("amounts");
        let amount = |slot: usize| {
            let (_, low) = amounts[slot].split_last_chunk::<8>().unwrap();
            u64::from_be_bytes(*low)
        };
        let secrets = list("blindingSecrets");
        let blindings: Vec<_> = secrets[..count]
            .iter()
            .map(|secret| domain::deposit_blinding(secret).unwrap())
            .collect();
        let mints: Vec<[u8; 32]> = request["mintChunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|chunks| {
                let (head, tail) = (hex_field(&chunks[0]), hex_field(&chunks[1]));
                let mut mint = [0; 32];
                mint[..31].copy_from_slice(&head[1..]);
                mint[31] = tail[31];
                mint
            })
            .collect();
        let (owner_keys, nullifier_pks) = (list("ownerKeys"), list("nullifierPks"));
        let records: Vec<_> = (0..count)
            .map(|slot| OpeningRecord {
                record: custom_ring_interface::AuditRecord {
                    kind: RecordKind::Ring,
                    amount: amount(slot),
                    owner_key: owner_keys[slot],
                    mint: mints[slot],
                    nullifier_pk: nullifier_pks[slot],
                },
                secret: blindings[slot],
            })
            .collect();
        let auditor_pk =
            X25519Pubkey::from_bytes(custom_ring_interface::tagged_x25519(&hex_field(
                &request["auditorPk"],
            )))
            .unwrap();
        let ephemeral = X25519Keypair::from_bytes(&hex_field(&request["ephSk"]));
        let sealed = seal_deposits_with(&records, &auditor_pk, ephemeral).unwrap();
        let owner_hashes = list("ownerPkHashes");
        let owners: Vec<_> = (0..count)
            .map(|slot| {
                let owner = Poseidon::hashv(&[&owner_hashes[slot], &nullifier_pks[slot]]).unwrap();
                Poseidon::hashv(&[&owner, &blindings[slot]]).unwrap()
            })
            .collect();
        let assets: Vec<_> = (0..count)
            .map(|slot| custom_ring_interface::DepositedAsset {
                asset: list("assets")[slot],
                amount: amount(slot),
            })
            .collect();
        let hash = custom_ring_interface::DepositPublicInput {
            context_hash: &hex_field(&request["contextHash"]),
            anonymous: request["anonymous"].as_u64().unwrap_or(0) != 0,
            owner_utxo_hashes: &owners,
            ciphertexts: &sealed.ciphertexts,
            assets: &assets,
            auditor_pk: auditor_pk.as_bytes(),
            eph_pk: sealed.ephemeral_pk.as_bytes(),
            tracking_root: &hex_field(&request["trackingRoot"]),
            registry: Some(custom_ring_interface::DepositRegistry {
                own_root: &hex_field(&request["ownRoot"]),
                curator_root: Some(&hex_field(&request["curatorRoot"])),
                policy_hash: Some(&hex_field(&request["policyHash"])),
            }),
        }
        .hash()
        .unwrap();
        assert_eq!(hash, hex_field(&request["publicInputHash"]));
    }

    /// One real wallet identity per slot, the hash the proof holds the record to.
    fn deposit_record(index: u8) -> OpeningRecord {
        let mut nullifier_pk = [index + 3; 32];
        nullifier_pk[0] = 0;
        let mut blinding = [index + 1; 32];
        blinding[0] = 0;
        OpeningRecord {
            record: custom_ring_interface::AuditRecord {
                kind: RecordKind::Ring,
                amount: u64::from(index) + 7,
                owner_key: [index + 2; 32],
                mint: [index + 4; 32],
                nullifier_pk,
            },
            secret: blinding,
        }
    }

    fn record_commitment(record: &OpeningRecord) -> [u8; 32] {
        let owner = Poseidon::hashv(&[
            &solana_owner_identity(&record.record.owner_key).unwrap(),
            &record.record.nullifier_pk,
        ])
        .unwrap();
        spr_transaction::owner_utxo_hash(&owner, &record.secret).unwrap()
    }

    #[test]
    fn every_slot_uses_its_batch_stream_offset() {
        let auditor = X25519Keypair::new();
        let records: Vec<_> = (0..MAX_RING_DEPOSIT_AUDIT_SLOTS)
            .map(|index| deposit_record(index as u8))
            .collect();
        let sealed = seal_deposits(&records, &auditor.pubkey()).unwrap();
        for (index, ciphertext) in sealed.ciphertexts.iter().enumerate() {
            let capsule = RingDepositAuditCapsule {
                slot_index: index as u8,
                eph_pk: sealed.ephemeral_pk.as_bytes(),
                ciphertext,
                recipient_ciphertext: &[],
            };
            let owner = record_commitment(&records[index]);
            let ring = solana_address::Address::new_from_array([9; 32]);
            let deposits = (0..=index)
                .map(|slot| {
                    let capsule = RingDepositAuditCapsule {
                        slot_index: slot as u8,
                        ..capsule
                    };
                    (owner, capsule.encode())
                })
                .collect();
            let group = deposit_fixture::group(ring, true, deposits);
            let origin = crate::ring_event_origin_in(&[group], 0, ring).unwrap();
            let binding = &origin.deposits[index];
            let wrapped = DepositCapsule::Record(capsule);
            let opened = open_deposit(&wrapped, &auditor, &owner, binding).unwrap();
            let mut corrupted = *capsule.ciphertext;
            corrupted[16] ^= 1;
            let altered = DepositCapsule::Record(RingDepositAuditCapsule {
                ciphertext: &corrupted,
                ..capsule
            });
            assert!(matches!(
                open_deposit(&altered, &auditor, &owner, binding),
                Err(AuditError::DepositOpeningMismatch)
            ));
            assert_eq!(opened.owner_key, records[index].record.owner_key);
            assert_eq!(*opened.blinding, records[index].secret);
            let note = opened.note.unwrap();
            assert_eq!(note.mint, records[index].record.mint);
            assert_eq!(note.amount, records[index].record.amount);
            assert_eq!(note.nullifier_pk, records[index].record.nullifier_pk);
        }
    }

    /// Seals a `CRDEP001` slot as its circuit did, one stream with slot `i` at counter `2 + 6i`.
    fn historical_capsule_bytes(
        auditor: &X25519Pubkey,
        slot_index: u8,
        opening: &[u8; 96],
    ) -> Vec<u8> {
        let ephemeral = X25519Keypair::new();
        let mut ciphertext = *opening;
        sealing_ring_stream(&ephemeral, auditor, DEPOSIT_AUDIT_LABEL)
            .unwrap()
            .apply_at(STREAM_FIRST_COUNTER + u32::from(slot_index) * 6, &mut ciphertext);
        HistoricalDepositCapsule {
            slot_index,
            eph_pk: ephemeral.pubkey().as_bytes(),
            ciphertext: &ciphertext,
            recipient_ciphertext: &[7, 8],
        }
        .encode()
    }

    fn historical_opening(owner_key: [u8; 32]) -> ([u8; 96], [u8; 32], [u8; 32]) {
        let owner_hash = [0x11; 32].map(|byte: u8| byte & 0x0f);
        let blinding = [0x22; 32].map(|byte: u8| byte & 0x0f);
        let mut opening = [0u8; 96];
        opening[..32].copy_from_slice(&owner_hash);
        opening[32..64].copy_from_slice(&blinding);
        opening[64..].copy_from_slice(&owner_key);
        let commitment = spr_transaction::owner_utxo_hash(&owner_hash, &blinding).unwrap();
        (opening, owner_hash, commitment)
    }

    fn historical_group(
        ring: solana_address::Address,
        deposits: Vec<([u8; 32], Vec<u8>)>,
    ) -> spr_event_parser::InstructionGroup {
        let mut group = deposit_fixture::group(ring, true, deposits);
        let revision = core::mem::size_of::<custom_ring_interface::storage::Revision>();
        group.outer.data.drain(..revision);
        group.outer.data[0] = custom_ring_interface::tag::HISTORICAL_DEPOSIT;
        group
    }

    #[test]
    fn a_crdep001_capsule_opens_under_its_own_slot_counter() {
        let auditor = X25519Keypair::new();
        let (opening, owner_hash, commitment) = historical_opening([0x33; 32]);
        let ring = solana_address::Address::new_from_array([9; 32]);
        let first = historical_capsule_bytes(&auditor.pubkey(), 0, &[0; 96]);
        let bytes = historical_capsule_bytes(&auditor.pubkey(), 1, &opening);
        let group = historical_group(ring, vec![([1; 32], first), (commitment, bytes.clone())]);
        let origin = crate::ring_event_origin_in(&[group], 0, ring).unwrap();
        let capsule = DepositCapsule::parse(&bytes).unwrap().unwrap();
        assert!(capsule.is_historical());
        assert_eq!(capsule.recipient_ciphertext(), [7, 8]);
        let opened = open_deposit(&capsule, &auditor, &commitment, &origin.deposits[1]).unwrap();
        assert_eq!(opened.owner_hash, owner_hash);
        assert_eq!(opened.owner_key, [0x33; 32]);
        assert_eq!(opened.note, None);
    }

    #[test]
    fn a_crdep001_capsule_with_a_changed_byte_or_out_of_range_slot_is_refused() {
        let auditor = X25519Keypair::new();
        let (opening, _, commitment) = historical_opening([0x33; 32]);
        let ring = solana_address::Address::new_from_array([9; 32]);
        let bytes = historical_capsule_bytes(&auditor.pubkey(), 0, &opening);
        let mut corrupted = bytes.clone();
        corrupted[8 + 1 + 33] ^= 1;
        let group = historical_group(ring, vec![(commitment, corrupted.clone())]);
        let origin = crate::ring_event_origin_in(&[group], 0, ring).unwrap();
        let capsule = DepositCapsule::parse(&corrupted).unwrap().unwrap();
        assert!(matches!(
            open_deposit(&capsule, &auditor, &commitment, &origin.deposits[0]),
            Err(AuditError::DepositOpeningMismatch)
        ));
        let mut far = bytes;
        far[8] = MAX_RING_DEPOSIT_AUDIT_SLOTS as u8;
        assert_eq!(
            DepositCapsule::parse(&far),
            Err(custom_ring_interface::RingDepositAuditError::InvalidSlot)
        );
    }

    #[test]
    fn a_capsule_under_the_other_tag_binds_nothing() {
        let auditor = X25519Keypair::new();
        let (opening, _, commitment) = historical_opening([0x33; 32]);
        let ring = solana_address::Address::new_from_array([9; 32]);
        let old = historical_capsule_bytes(&auditor.pubkey(), 0, &opening);
        let group = deposit_fixture::group(ring, true, vec![(commitment, old)]);
        assert!(crate::ring_event_origin_in(&[group], 0, ring).is_err());
        let sealed = seal_deposits(&[deposit_record(0)], &auditor.pubkey()).unwrap();
        let new = RingDepositAuditCapsule {
            slot_index: 0,
            eph_pk: sealed.ephemeral_pk.as_bytes(),
            ciphertext: &sealed.ciphertexts[0],
            recipient_ciphertext: &[],
        }
        .encode();
        let group = historical_group(ring, vec![(commitment, new)]);
        assert!(crate::ring_event_origin_in(&[group], 0, ring).is_err());
    }

    #[test]
    fn empty_and_oversized_batches_are_rejected() {
        let auditor = X25519Keypair::new().pubkey();
        assert!(matches!(
            seal_deposits(&[], &auditor),
            Err(AuditError::DepositCount(0))
        ));
        let records = [OpeningRecord::default(); MAX_RING_DEPOSIT_AUDIT_SLOTS + 1];
        assert!(matches!(
            seal_deposits(&records, &auditor),
            Err(AuditError::DepositCount(9))
        ));
    }
}
