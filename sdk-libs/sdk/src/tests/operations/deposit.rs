use custom_ring_interface::{CoSignScope, CustomRingError, RingMode};
use solana_address::Address;
use solana_signature::Signature;
use zolana_client::{OutputContext, OutputSlot, ShieldedTransaction};
use zolana_interface::pda;
use zolana_ring_client::AnonymousRingState;
use zolana_ring_keys::RingKeys;

use crate::{
    tests::support::{keypair, owner_identity, ring, Chain, Registry, RingSettings, TREE_ID},
    DepositAsset, DepositRecipient, RingDeposit, RingError,
};

fn deposit<'a>(
    payer: &'a (dyn solana_signer::Signer + Sync),
    recipient: DepositRecipient<'a>,
) -> RingDeposit<'a> {
    RingDeposit {
        ring: ring(),
        payer,
        recipient,
        tree: pda::tree(TREE_ID),
        asset: DepositAsset::Sol,
        amount: 5,
        cosigner: None,
    }
}

#[tokio::test]
async fn an_anonymous_ring_takes_deposits_only_for_the_depositors_hidden_owner() {
    let member = keypair(1);
    let payer = keypair(9);
    let anonymous = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let confidential = Chain::ring(RingSettings::new(RingMode::Off));
    let address = member.shielded_address().unwrap();
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let hidden = DepositRecipient::Anonymous {
        keys: &member,
        state: &state,
    };
    assert!(matches!(
        deposit(&payer, DepositRecipient::Confidential(address))
            .prepare(&anonymous)
            .await,
        Err(RingError::Program(CustomRingError::AnonymousRingRefused))
    ));
    assert!(matches!(
        deposit(&payer, hidden).prepare(&confidential).await,
        Err(RingError::NotAnonymousRing)
    ));
    assert!(matches!(
        deposit(&member, hidden).prepare(&anonymous).await,
        Err(RingError::AnonymousPublicSignerLinksOwner)
    ));
    let prepared = deposit(&payer, hidden).prepare(&anonymous).await.unwrap();
    assert_eq!(
        (prepared.utxo().owner, prepared.utxo().amount),
        (member.signing_pubkey(), 5)
    );
}

#[tokio::test]
async fn an_escrowed_ring_refuses_a_deposit_to_a_member_without_an_escrowed_key() {
    let registered = keypair(1);
    let stranger = keypair(2);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Registry)
    })
    .with_registry(
        Registry::new(&[(&registered, 1)]),
        &crate::tests::pipeline_rules(),
    );
    let client = chain.client();
    let prepared = deposit(
        &payer,
        DepositRecipient::Confidential(stranger.shielded_address().unwrap()),
    )
    .prepare(client.zolana())
    .await
    .unwrap();
    let owner = owner_identity(&stranger);
    assert!(matches!(
        prepared.prove(&client).await,
        Err(RingError::UnregisteredOutputKey { owner: refused }) if refused == owner
    ));
}

#[tokio::test]
async fn a_deposit_names_the_co_signer_a_deposit_scope_demands() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let chain = Chain::ring(RingSettings {
        co_signer: Some((
            solana_signer::Signer::pubkey(&co_signer),
            CoSignScope::DEPOSITS,
        )),
        ..RingSettings::new(RingMode::Off)
    });
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    assert!(matches!(
        deposit(&payer, recipient).prepare(&chain).await,
        Err(RingError::Program(CustomRingError::MissingCoSigner))
    ));
    let named = RingDeposit {
        cosigner: Some(&co_signer),
        ..deposit(&payer, recipient)
    };
    assert!(named.prepare(&chain).await.is_ok());
    let stranger = keypair(7);
    let wrong = RingDeposit {
        cosigner: Some(&stranger),
        ..deposit(&payer, recipient)
    };
    assert!(matches!(
        wrong.prepare(&chain).await,
        Err(RingError::Program(CustomRingError::MissingCoSigner))
    ));
}

#[tokio::test]
async fn a_co_signer_outside_the_deposit_scope_does_not_sign() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    for (scope, signs) in [
        (CoSignScope::WITHDRAWALS, false),
        (CoSignScope::DEPOSITS, true),
    ] {
        let chain = Chain::ring(RingSettings {
            co_signer: Some((solana_signer::Signer::pubkey(&co_signer), scope)),
            ..RingSettings::new(RingMode::Off)
        });
        let named = RingDeposit {
            cosigner: Some(&co_signer),
            ..deposit(&payer, recipient)
        };
        let prepared = named.prepare(&chain).await.unwrap();
        assert_eq!(named.signers(&prepared).len(), 1 + usize::from(signs));
    }
}

/// An indexer that shows every counter of the first window taken moves no deposit tag.
#[tokio::test]
async fn a_deposit_takes_the_stored_counter_whatever_the_indexer_shows() {
    let member = keypair(1);
    let payer = keypair(9);
    let first_window: Vec<u64> = (0..64).collect();
    let chain = member
        .sender_view_tags(&first_window)
        .unwrap()
        .into_iter()
        .zip(0u8..)
        .fold(
            Chain::ring(RingSettings::new(RingMode::Anonymous)),
            |chain, (view_tag, seed)| {
                chain.with_transaction(ShieldedTransaction {
                    slot: 1,
                    tx_signature: Signature::from([seed; 64]),
                    event_index: Some(0),
                    tx_viewing_pk: None,
                    salt: None,
                    output_slots: vec![OutputSlot {
                        view_tag,
                        output_context: OutputContext {
                            hash: [seed; 32],
                            tree_id: TREE_ID,
                            leaf_index: u64::from(seed),
                        },
                        payload: Vec::new(),
                    }],
                    messages: Vec::new(),
                    nullifiers: Vec::new(),
                    proofless: true,
                    ring_config: None,
                    ring_program_id: None,
                })
            },
        );
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let hidden = DepositRecipient::Anonymous {
        keys: &member,
        state: &state,
    };
    let prepared = deposit(&payer, hidden).prepare(&chain).await.unwrap();
    let tag = member.sender_view_tags(&[state.deposit_next()]).unwrap()[0];
    assert!(prepared
        .spp
        .data
        .windows(tag.len())
        .any(|bytes| bytes == tag));
}

#[tokio::test]
async fn a_deposit_refuses_the_state_of_another_ring() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let other = Address::new_from_array([0x47; 32]);
    let state = AnonymousRingState::new(other, 0);
    let hidden = DepositRecipient::Anonymous {
        keys: &member,
        state: &state,
    };
    assert!(matches!(
        deposit(&payer, hidden).prepare(&chain).await,
        Err(RingError::ForeignRingState { state, ring: paid })
            if state == other && paid == ring().program_id()
    ));
}
