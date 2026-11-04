use custom_ring_interface::RingMode;
use solana_signer::Signer;
use spr_interface::pda;
use spr_keypair::ShieldedKeypair;
use spr_transaction::Mint;

use super::support::{keypair, ring, ring_utxo, zero_key, Chain, RingSettings, TREE_ID};
use crate::{
    CustomRingMerge, MergeProofInput, PreparedCustomRingMerge, RingError, RingMergeOperation,
    RingSubmission,
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

#[tokio::test]
async fn the_widest_merge_fits_a_transaction() {
    use custom_ring_interface::{compute_unit_limit, InstructionTag};
    use solana_address::Address;
    use spr_client::ComputeBudgetConfig;
    let owner = keypair(1);
    let utxos = (0..crate::MAX_RING_MERGE_INPUTS as u64)
        .map(|leaf| ring_utxo(&owner, Mint::SOL, 5, leaf))
        .collect();
    let merge = RingMergeOperation::new(
        CustomRingMerge::new(ring(), utxos, None)
            .unwrap()
            .encrypt(&owner)
            .unwrap(),
        MergeProofInput {
            nullifier_key: owner.nullifier_key.clone(),
            input_tree: pda::tree(TREE_ID),
            output_tree: pda::tree(TREE_ID),
        },
    );
    let config = ring()
        .require_config(&Chain::ring(RingSettings::new(RingMode::Confidential)))
        .await
        .unwrap();
    let payer = Address::new_from_array([7; 32]);
    crate::submission::check_transaction_size(
        &payer,
        &merge
            .prepared
            .preview_instruction(&merge.input, payer, &config)
            .unwrap(),
        ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Merge)),
    )
    .unwrap();
}

/// SPP keys a wider merge, its record and the ring's accounts leave it past the ceiling.
#[tokio::test]
async fn the_next_merge_width_past_the_ring_widest_does_not_fit() {
    use custom_ring_interface::{compute_unit_limit, InstructionTag};
    use spr_client::ComputeBudgetConfig;
    use spr_interface::instruction::instruction_data::merge_transact::MERGE_SUPPORTED_INPUT_COUNTS;
    use spr_transaction::instructions::merge::MergeTransaction;
    let owner = keypair(1);
    let width = MERGE_SUPPORTED_INPUT_COUNTS[2];
    let utxos = (0..width as u64)
        .map(|leaf| ring_utxo(&owner, Mint::SOL, 5, leaf))
        .collect();
    let prepared = PreparedCustomRingMerge {
        ring: ring(),
        inner: MergeTransaction::new_ring_v2(utxos, ring().program_id(), None)
            .unwrap()
            .encrypt(&owner)
            .unwrap(),
        priority_fee: None,
    };
    let config = ring()
        .require_config(&Chain::ring(RingSettings::new(RingMode::Confidential)))
        .await
        .unwrap();
    let payer = solana_address::Address::new_from_array([7; 32]);
    let input = MergeProofInput {
        nullifier_key: owner.nullifier_key.clone(),
        input_tree: pda::tree(TREE_ID),
        output_tree: pda::tree(TREE_ID),
    };
    assert!(matches!(
        crate::submission::check_transaction_size(
            &payer,
            &prepared
                .preview_instruction(&input, payer, &config)
                .unwrap(),
            ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Merge)),
        ),
        Err(RingError::TransactionTooLarge { .. })
    ));
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
