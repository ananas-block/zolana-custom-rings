use custom_ring_interface::{CoSignScope, RingMode};
use solana_signer::Signer;
use spr_interface::pda;
use spr_keypair::ShieldedKeypair;
use spr_transaction::Mint;

use super::support::{
    keypair, owner_identity, ring, ring_utxo, Chain, Registry, RingSettings, TREE_ID,
};
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
                co_signer: self.settings.co_signer.map(|(signer, _)| signer),
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

/// A key escrow merge opens the owner's escrow record before any proof.
#[tokio::test]
async fn a_key_escrow_merge_of_an_unregistered_owner_is_refused() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(
        Registry::new(&[(&registered, 1)]),
        &crate::tests::pipeline_rules(),
    );
    let client = chain.client();
    let merge = RingMergeOperation::new(
        prepared(&stranger),
        MergeProofInput {
            nullifier_key: stranger.nullifier_key.clone(),
            input_tree: pda::tree(TREE_ID),
            output_tree: pda::tree(TREE_ID),
            co_signer: None,
        },
    );
    let owner = owner_identity(&stranger);
    assert!(matches!(
        RingSubmission::new(merge).send(&client, &payer, &[]).await,
        Err(RingError::UnregisteredOutputKey { owner: refused }) if refused == owner
    ));
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
    let co_signed = RingSettings {
        co_signer: Some((owner.pubkey(), CoSignScope::TRANSFERS)),
        ..anonymous
    };
    let payer = keypair(9);
    assert!(matches!(
        refusal(co_signed, &payer, unsigned).await,
        RingError::AnonymousPublicSignerLinksOwner
    ));
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
async fn the_widest_merge_fits_a_transaction_beside_its_co_signer() {
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
            co_signer: Some(Address::new_from_array([0x46; 32])),
        },
    );
    let config = ring()
        .require_config(
            &Chain::ring(RingSettings {
                co_signer: Some((Address::new_from_array([0x46; 32]), CoSignScope::TRANSFERS)),
                ..RingSettings::new(RingMode::ConfidentialEscrow)
            })
            .with_records(crate::tests::support::Registry::new(&[(&owner, 0)])),
        )
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

struct MergeFrame {
    mode: RingMode,
    width: u64,
    co_signed: bool,
    second_tree: bool,
    bytes: usize,
}

/// One registry read only under key escrow, a registry address never the system program's.
#[tokio::test]
async fn every_merge_width_takes_the_modelled_frame_on_each_ring_mode() {
    use custom_ring_interface::{compute_unit_limit, InstructionTag};
    use solana_address::Address;
    use spr_client::ComputeBudgetConfig;
    let owner = keypair(1);
    let co_signer = Address::new_from_array([0x46; 32]);
    let frame = |mode, width, co_signed, second_tree, bytes| MergeFrame {
        mode,
        width,
        co_signed,
        second_tree,
        bytes,
    };
    for MergeFrame {
        mode,
        width,
        co_signed,
        second_tree,
        bytes,
    } in [
        frame(RingMode::Confidential, 8, false, false, 1775),
        frame(RingMode::Confidential, 8, true, false, 1905),
        frame(RingMode::Confidential, 24, false, false, 3327),
        frame(RingMode::Confidential, 24, true, false, 3457),
        frame(RingMode::Anonymous, 8, false, false, 1775),
        frame(RingMode::Anonymous, 24, true, true, 3489),
        frame(RingMode::ConfidentialEscrow, 8, false, false, 1808),
        frame(RingMode::ConfidentialEscrow, 8, true, false, 1938),
        frame(RingMode::ConfidentialEscrow, 8, true, true, 1970),
        frame(RingMode::ConfidentialEscrow, 24, false, false, 3360),
        frame(RingMode::ConfidentialEscrow, 24, true, false, 3490),
        frame(RingMode::ConfidentialEscrow, 24, true, true, 3522),
    ] {
        let utxos = (0..width)
            .map(|leaf| ring_utxo(&owner, Mint::SOL, 5, leaf))
            .collect();
        let merge = CustomRingMerge::new(ring(), utxos, None)
            .unwrap()
            .encrypt(&owner)
            .unwrap();
        let input = MergeProofInput {
            nullifier_key: owner.nullifier_key.clone(),
            input_tree: pda::tree(TREE_ID),
            output_tree: pda::tree(TREE_ID + u16::from(second_tree)),
            co_signer: co_signed.then_some(co_signer),
        };
        let settings = RingSettings {
            co_signer: co_signed.then_some((co_signer, CoSignScope::TRANSFERS)),
            ..RingSettings::new(mode)
        };
        let chain = Chain::ring(settings)
            .with_records(crate::tests::support::Registry::new(&[(&owner, 0)]));
        let config = ring().require_config(&chain).await.unwrap();
        let payer = Address::new_from_array([7; 32]);
        let size = spr_client::transaction_size(
            &payer,
            &[merge.preview_instruction(&input, payer, &config).unwrap()],
            ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Merge)),
        )
        .unwrap();
        assert_eq!(
            size.bytes, bytes,
            "{mode:?} width {width}, co-signer {co_signed}, second tree {second_tree}"
        );
    }
}
