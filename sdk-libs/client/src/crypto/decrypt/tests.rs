use zolana_ring_transaction::RingAssets;

use super::*;
use crate::types::UtxoOwner;

fn note(byte: u8) -> KnownUtxo {
    KnownUtxo {
        owner_key: [0xa1; 32],
        owner: UtxoOwner::Keyed {
            nullifier_pk: [byte; 32],
        },
        asset: [byte; 32],
        mint: None,
        amount: u64::from(byte),
        blinding: [byte; 32],
        data_hash: [0; 32],
        ring_data_hash: [0; 32],
        tree_id: 1,
    }
}

fn opening_of(evidence: &AuditEvidence, known: &dyn KnownUtxos, nullifiers: &[[u8; 32]]) -> Spent {
    let tx_key = ViewingKey::new();
    let assets = RingAssets::new([]).unwrap();
    Transfer {
        ring: Address::new_from_array([1; 32]),
        tx_viewing_pk: tx_key.pubkey(),
        tx_key: &tx_key,
        salt: [2; 16],
        first_nullifier: nullifiers[0],
        seed_out: [3; 32],
        body_len: 0,
        assets: &assets,
    }
    .inputs(SpentInputs {
        key: AuditKey::Confidential { class: 4 },
        evidence,
        nullifiers,
        trees: None,
        known: Some(known),
    })
    .unwrap()
}

/// Two notes share one 16 byte prefix, a full hash names one.
#[test]
fn a_named_hash_opens_exactly_its_note_and_absence_reads_unseen() {
    let named = [0x2a; 32];
    let mut sibling = named;
    sibling[31] ^= 1;
    let missing = [0x2b; 32];
    let known = KnownUtxoIndex::from_iter([(named, note(7)), (sibling, note(8))]);
    let evidence = AuditEvidence::InputHashes(vec![named, missing, [0; 32]]);
    let spent = opening_of(&evidence, &known, &[[11; 32], [12; 32], [13; 32]]);
    let openings: Vec<_> = spent.inputs.iter().map(|input| &input.opening).collect();
    assert_eq!(
        openings,
        [
            &InputOpening::Opened(ring_input(named, note(7))),
            &InputOpening::UnseenHash { hash: missing },
            &InputOpening::Dummy,
        ]
    );
    let hashes: Vec<_> = spent.inputs.iter().map(|input| input.hash).collect();
    assert_eq!(hashes, [named, missing, [0; 32]]);
}
