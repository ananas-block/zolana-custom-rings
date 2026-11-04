use custom_ring_interface::RingMode;
use solana_signer::Signer;
use spr_interface::pda;
use spr_keypair::ShieldedKeypair;
use spr_transaction::Mint;

use super::support::{keypair, ring, ring_utxo, zero_key, Chain, RingSettings, TREE_ID};
use crate::{
    CustomRingMerge, FittedMerge, MergeProofInput, PreparedCustomRingMerge, RingError,
    RingMergeOperation, RingSubmission,
};

struct Merge<'a> {
    owner: &'a ShieldedKeypair,
    settings: RingSettings,
    payer: &'a ShieldedKeypair,
    signers: &'a [&'a (dyn Signer + Sync)],
}

fn prepared(owner: &ShieldedKeypair) -> PreparedCustomRingMerge {
    let utxos = (0..2)
        .map(|leaf| ring_utxo(owner, Mint::SOL, 5, leaf))
        .collect();
    CustomRingMerge::new(ring(), utxos, None)
        .unwrap()
        .encrypt(owner)
        .unwrap()
}

impl Merge<'_> {
    async fn refusal(self) -> RingError {
        let merge = RingMergeOperation::new(
            prepared(self.owner),
            MergeProofInput {
                nullifier_key: self.owner.nullifier_key.clone(),
                input_tree: pda::tree(TREE_ID),
                output_tree: pda::tree(TREE_ID),
            },
        );
        RingSubmission::new(merge)
            .send(
                &Chain::ring(self.settings).client(),
                self.payer,
                self.signers,
            )
            .await
            .unwrap_err()
    }
}

/// The hidden owner never pays, signs or co-signs its anonymous merge.
#[tokio::test]
async fn an_anonymous_merge_its_owner_would_sign_in_public_is_refused_before_proving() {
    let owner = keypair(1);
    let unsigned: &[&(dyn Signer + Sync)] = &[];
    let anonymous = RingSettings::new(RingMode::Anonymous);
    let refusal = |settings, payer, signers| {
        Merge {
            owner: &owner,
            settings,
            payer,
            signers,
        }
        .refusal()
    };
    assert!(matches!(
        refusal(anonymous, &owner, unsigned).await,
        RingError::AnonymousPublicSignerLinksOwner
    ));
    let payer = keypair(9);
    assert!(matches!(
        refusal(anonymous, &payer, &[&owner]).await,
        RingError::AnonymousPublicSignerLinksOwner
    ));
    let confidential = ring()
        .require_config(&Chain::ring(RingSettings::new(RingMode::Confidential)))
        .await
        .unwrap();
    assert!(prepared(&owner)
        .check_public_signers([owner.pubkey()], &confidential)
        .is_ok());
}

/// The merge circuit keeps the owner off the payer and co-signer on every ring.
#[tokio::test]
async fn a_confidential_merge_its_owner_pays_is_refused_before_proving() {
    let owner = keypair(1);
    let merge = Merge {
        owner: &owner,
        settings: RingSettings::new(RingMode::Confidential),
        payer: &owner,
        signers: &[],
    };
    let refusal = merge.refusal().await;
    assert!(
        matches!(refusal, RingError::AnonymousPublicSignerLinksOwner),
        "{refusal}"
    );
}

/// Compact padding publishes nothing, the widest circuit carries what the bytes and accounts allow.
#[tokio::test]
async fn a_merge_takes_every_input_one_transaction_carries() {
    use solana_address::Address;
    let owner = keypair(1);
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
    let input = MergeProofInput {
        nullifier_key: owner.nullifier_key.clone(),
        input_tree: pda::tree(TREE_ID),
        output_tree: pda::tree(TREE_ID),
    };
    let payer = Address::new_from_array([7; 32]);
    let notes = |count: u64| -> Vec<_> {
        (0..count)
            .map(|leaf| ring_utxo(&owner, Mint::SOL, 5, leaf))
            .collect()
    };
    let fitted = |inputs| FittedMerge {
        ring: ring(),
        inputs,
        output_tree_id: TREE_ID,
        keys: &owner,
        proof_input: &input,
        payer,
    };
    let carried = fitted(notes(crate::MAX_RING_MERGE_INPUTS as u64))
        .prepare(&chain)
        .await
        .unwrap();
    let published = carried.published_inputs();
    assert_eq!(published, WIDEST_MERGE);

    let config = ring().require_config(&chain).await.unwrap();
    let one_more = CustomRingMerge::new(ring(), notes(published as u64 + 1), None)
        .unwrap()
        .with_output_tree_id(TREE_ID)
        .encrypt(&owner)
        .unwrap();
    assert!(matches!(
        crate::submission::check_transaction_size(
            &payer,
            &one_more
                .preview_instruction(&input, payer, &config)
                .unwrap(),
            crate::submission::send_budget(custom_ring_interface::InstructionTag::Merge, None),
        ),
        Err(RingError::TransactionTooLarge { .. })
    ));
}

/// Inputs a keyed merge carries in one v1 transaction, measured here.
const WIDEST_MERGE: usize = 45;

/// What `OwnerMergeProof` builds from the relay's wire, it holds no merge seed.
#[test]
fn the_relays_keyed_build_names_no_signer_on_a_zero_key_merge() {
    use spr_interface::ZERO_NULLIFIER_PUBKEY;
    let owner = keypair(1);
    let utxos: Vec<_> = (0..2)
        .map(|leaf| zero_key(ring_utxo(&owner, Mint::SOL, 5, leaf)))
        .collect();
    let viewing = spr_keypair::ViewingKey::new();
    let keys = spr_transaction::LocalShieldedKeys::new(
        spr_keypair::ShieldedAddress {
            signing_pubkey: owner.signing_pubkey(),
            nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
            viewing_pubkey: viewing.pubkey(),
        },
        vec![viewing],
        spr_keypair::NullifierKey::from_secret([0; 31]),
    )
    .unwrap();
    let built = CustomRingMerge::new(ring(), utxos, None)
        .unwrap()
        .encrypt(&keys);
    match built {
        Ok(prepared) => assert_eq!(prepared.signing_owner().unwrap(), None),
        Err(refusal) => panic!("REFUSED {refusal:?}"),
    }
}

#[test]
fn a_zero_key_merge_names_a_zero_key_owner() {
    use spr_interface::ZERO_NULLIFIER_PUBKEY;
    let owner = keypair(1);
    let utxos: Vec<_> = (0..2)
        .map(|leaf| zero_key(ring_utxo(&owner, Mint::SOL, 5, leaf)))
        .collect();
    let merge = || CustomRingMerge::new(ring(), utxos.clone(), None).unwrap();
    let keyed = owner.shielded_address().unwrap();
    assert!(matches!(
        merge().encrypt_zero_key(&owner, &keyed),
        Err(RingError::MergeOwnerKey)
    ));
    let zero = spr_keypair::ShieldedAddress {
        nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
        ..keyed
    };
    let prepared = merge().encrypt_zero_key(&owner, &zero).unwrap();
    assert_eq!(prepared.signing_owner().unwrap(), Some(owner.pubkey()));
}
