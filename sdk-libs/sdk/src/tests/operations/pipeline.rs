//! A child of `pipeline`, every rail stages and assembles through its private items.

use custom_ring_interface::{
    anonymous_recipient_output_body, anonymous_sender_output_body, CustomRingError, RingMode,
    RingRail, RingTransactData,
};
use solana_address::Address;
use spl_token_2022_interface::pod::{PodAccount, PodCOption};
use spr_client::ClientError;
use spr_interface::{
    instruction::instruction_data::transact::OwnerTag, pda, SPL_TOKEN_ACCOUNT_INITIALIZED,
    SPL_TOKEN_PROGRAM_ID,
};
use spr_keypair::ShieldedKeypair;
use spr_program::instruction::{TransactSolTransferAccounts, TransactSplWithdrawalAccounts};
use spr_transaction::{
    instructions::transact::ConfidentialTransaction, AssetRegistry, Mint, WalletUtxo,
};
use zolana_ring_client::{FirstContact, StreamCounter, ViewingHistory};
use zolana_ring_keys::RingAddress;
use zolana_ring_transaction::{
    listed_recipients, AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext,
    RingDelivery,
};

use super::*;
use crate::client::RingClient;
use crate::tests::support::{
    account, empty, history, ring, ring_utxo, Chain, RingSettings, TREE_ID,
};

fn anonymous() -> RingSettings {
    RingSettings::new(RingMode::Anonymous)
}

fn ring_transaction(utxos: Vec<WalletUtxo>) -> ConfidentialTransaction {
    paid_ring_transaction(utxos, crate::tests::support::payer())
}

fn paid_ring_transaction(utxos: Vec<WalletUtxo>, payer: Address) -> ConfidentialTransaction {
    ConfidentialTransaction::new_with_ring(utxos, payer, ring().program_id()).unwrap()
}

fn owner_transfer(
    sender: &ShieldedKeypair,
    transaction: ConfidentialTransaction,
) -> CustomRingTransfer<'_> {
    CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
}

fn ring_address(owner: &ShieldedKeypair) -> RingAddress {
    RingAddress {
        recipient: owner.shielded_address().unwrap(),
        ring_program_id: ring().program_id(),
    }
}

fn payment(to: &RingAddress, amount: u64) -> AnonymousPayment {
    AnonymousPayment {
        to: to.clone(),
        first_contact: FirstContact::Bootstrap,
        asset: Mint::SOL,
        amount,
    }
}

async fn stage_anonymous<'a>(
    transfer: &'a AnonymousTransfer<'a>,
    chain: &Chain,
) -> Result<Staged<'a>, RingError> {
    let config = ring().require_config(chain).await?;
    transfer.rail.stage(ring(), chain, &config).await
}

async fn exit_owner(
    transfer: AnonymousTransfer<'_>,
    named: Option<Address>,
    chain: Chain,
) -> Result<(), RingError> {
    let transfer = match named {
        Some(owner) => transfer.with_exit_token_owner(owner),
        None => transfer,
    };
    match stage_anonymous(&transfer, &chain).await?.spend {
        Spend::Anonymous(_) => Ok(()),
        Spend::Owner | Spend::InProofOwner(_) | Spend::Delegate { .. } => {
            unreachable!("an anonymous ring stages its rail")
        }
    }
}

fn token_state(mint: Address, owner: Address) -> PodAccount {
    PodAccount {
        mint: mint.to_bytes().into(),
        owner: owner.to_bytes().into(),
        state: SPL_TOKEN_ACCOUNT_INITIALIZED,
        ..PodAccount::default()
    }
}

fn token_account(state: PodAccount) -> solana_account::Account {
    account(Address::new_from_array(SPL_TOKEN_PROGRAM_ID), &state)
}

#[tokio::test]
async fn an_anonymous_spl_exit_names_neither_the_hidden_owner_nor_a_second_key() {
    let sender = &crate::tests::support::keypair(1);
    let state = &history(sender);
    let hidden = Address::new_from_array(sender.signing_pubkey().as_ed25519().unwrap());
    let mint = Address::new_from_array([0x31; 32]);
    let stranger = Address::new_from_array([0x32; 32]);
    let other = Address::new_from_array([0x35; 32]);
    let token_program = Address::new_from_array(SPL_TOKEN_PROGRAM_ID);
    let destination = pda::associated_token_address_with_program(&stranger, &mint, &token_program);
    let associated = pda::associated_token_address_with_program(&hidden, &mint, &token_program);
    let chain = || Chain::ring(anonymous());
    let stage = |to: Address, named: Option<Address>, chain: Chain| {
        let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::new(mint, 2), 10, 0)]);
        transaction.withdraw(mint, 4, to).unwrap();
        let transfer = owner_transfer(sender, transaction)
            .with_interface_transfer_accounts(vec![
                TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
                    mint,
                    spl_interface: pda::spl_interface(&mint),
                    user_token_account: to,
                    token_program,
                }),
            ])
            .with_anonymous_signer(&sender.signing_key, state);
        exit_owner(transfer, named, chain)
    };
    for (to, owner) in [
        (destination, hidden),
        (hidden, stranger),
        (associated, stranger),
    ] {
        let refused = stage(
            to,
            None,
            chain().with(to, token_account(token_state(mint, owner))),
        )
        .await;
        assert!(
            matches!(refused, Err(RingError::AnonymousExitLinksOwner(exit)) if exit == to),
            "{to} owned by {owner}"
        );
    }
    let key = PodCOption::some(stranger.to_bytes().into());
    for state in [
        PodAccount {
            delegate: key,
            ..token_state(mint, stranger)
        },
        PodAccount {
            close_authority: key,
            ..token_state(mint, stranger)
        },
    ] {
        assert!(matches!(
            stage(destination, None, chain().with(destination, token_account(state))).await,
            Err(RingError::AnonymousExitTokenAccountShared(exit)) if exit == destination
        ));
    }
    let foreign_mint = chain().with(destination, token_account(token_state(stranger, stranger)));
    assert!(matches!(
        stage(destination, None, foreign_mint).await,
        Err(RingError::AnonymousExitTokenAccountInvalid(exit)) if exit == destination
    ));
    let keypair_address = Address::new_from_array([0x33; 32]);
    assert!(keypair_address.is_on_curve());
    let on_curve = chain().with(keypair_address, token_account(token_state(mint, stranger)));
    assert!(matches!(
        stage(keypair_address, None, on_curve).await,
        Err(RingError::AnonymousExitTokenAccountOnCurve(exit)) if exit == keypair_address
    ));
    let existing = || chain().with(destination, token_account(token_state(mint, stranger)));
    for named in [None, Some(stranger)] {
        stage(destination, named, existing()).await.unwrap();
    }
    assert!(matches!(
        stage(destination, Some(other), existing()).await,
        Err(RingError::AnonymousExitNamedOwnerMismatch { token_account, named, owner })
            if token_account == destination && named == other && owner == stranger
    ));
    // The transaction creates the associated token account before SPP reads it.
    let minted = || chain().with(mint, empty(token_program));
    stage(destination, Some(stranger), minted()).await.unwrap();
    for (named, chain) in [
        (None, minted()),
        (Some(other), minted()),
        (Some(stranger), chain()),
    ] {
        assert!(matches!(
            stage(destination, named, chain).await,
            Err(RingError::AnonymousExitTokenAccountInvalid(exit)) if exit == destination
        ));
    }
    assert!(matches!(
        stage(associated, Some(hidden), minted()).await,
        Err(RingError::AnonymousExitLinksOwner(exit)) if exit == associated
    ));
}

/// SPP binds a SOL exit's recipient alone, a program owner, data or the hidden owner there is
/// refused before proving.
#[tokio::test]
async fn an_anonymous_sol_exit_leaves_to_a_wallet_other_than_the_hidden_owner() {
    let sender = &crate::tests::support::keypair(1);
    let state = &history(sender);
    let hidden = Address::new_from_array(sender.signing_pubkey().as_ed25519().unwrap());
    let stage = |to: Address, named: Option<Address>, chain: Chain| {
        let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
        transaction.withdraw_sol(4, to).unwrap();
        let transfer = owner_transfer(sender, transaction)
            .with_interface_transfer_accounts(vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient: to },
            )])
            .with_anonymous_signer(&sender.signing_key, state);
        exit_owner(transfer, named, chain)
    };
    assert!(matches!(
        stage(hidden, None, Chain::ring(anonymous())).await,
        Err(RingError::AnonymousExitLinksOwner(exit)) if exit == hidden
    ));
    let wallet = Address::new_from_array([0x34; 32]);
    let mut nonce = empty(Address::default());
    nonce.data = vec![0; 80];
    for held in [empty(Address::new_from_array(SPL_TOKEN_PROGRAM_ID)), nonce] {
        assert!(matches!(
            stage(wallet, None, Chain::ring(anonymous()).with(wallet, held)).await,
            Err(RingError::AnonymousExitAccountHasData(exit)) if exit == wallet
        ));
    }
    for chain in [
        Chain::ring(anonymous()),
        Chain::ring(anonymous()).with(wallet, empty(Address::default())),
    ] {
        stage(wallet, None, chain).await.unwrap();
    }
    assert!(matches!(
        stage(wallet, Some(wallet), Chain::ring(anonymous())).await,
        Err(RingError::AnonymousExitTokenOwnerWithoutSplExit)
    ));
}

#[test]
fn a_payment_to_another_rings_address_is_refused() {
    let sender = &crate::tests::support::keypair(1);
    let state = history(sender);
    let foreign = RingAddress {
        ring_program_id: Address::new_from_array([43; 32]),
        ..ring_address(&crate::tests::support::keypair(2))
    };
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    assert!(matches!(
        owner_transfer(sender, transaction)
            .with_anonymous_signer(&sender.signing_key, &state)
            .with_payment(payment(&foreign, 3)),
        Err(RingError::ForeignRingAddress { address, ring: paid })
            if address == foreign.ring_program_id && paid == ring().program_id()
    ));
}

/// The published owner tag and recipient body of every slot, `None` on a change output.
fn published<'s>(staged: &'s Staged<'_>) -> Vec<([u8; 32], Option<&'s [u8]>)> {
    staged
        .proof_inputs
        .external_data
        .outputs
        .iter()
        .map(|output| {
            let OwnerTag::Inline(tag) = output.owner_tag else {
                panic!("an anonymous slot is tagged inline, {:?}", output.owner_tag);
            };
            let body = output.data.as_deref().map(|data| {
                anonymous_recipient_output_body(data).expect("a scheme 1 recipient body")
            });
            (tag, body)
        })
        .collect()
}

fn opened(
    staged: &Staged<'_>,
    reader: &ShieldedKeypair,
    ciphertext: &[u8],
    slot: usize,
) -> Vec<u8> {
    let external = &staged.proof_inputs.external_data;
    reader
        .viewing_key
        .decrypt_utxo(
            ciphertext,
            &spr_keypair::X25519Pubkey::from_bytes(external.tx_viewing_pk).unwrap(),
            external.salt,
            slot as u32,
        )
        .unwrap()
}

fn payment_at(
    staged: &Staged<'_>,
    reader: &ShieldedKeypair,
    position: usize,
) -> AnonymousTransferRecipientPlaintext {
    let body = published(staged)[position].1.expect("a recipient body");
    AnonymousTransferRecipientPlaintext::deserialize(&opened(staged, reader, body, position))
        .unwrap()
}

/// The sender bundle, the first message, opened under the sender's own viewing key.
fn bundle(staged: &Staged<'_>, sender: &ShieldedKeypair) -> AnonymousTransferSenderPlaintext {
    let external = &staged.proof_inputs.external_data;
    let message = &external.messages[0];
    assert_eq!(message.view_tag, published(staged)[0].0);
    let body = anonymous_sender_output_body(&message.data).expect("a scheme 2 sender bundle");
    let plaintext = opened(staged, sender, body, external.outputs.len());
    AnonymousTransferSenderPlaintext::deserialize(&plaintext).unwrap()
}

/// Change leads with no body, SPL before SOL.
#[tokio::test]
async fn an_anonymous_transfer_publishes_each_payment_and_the_sender_bundle() {
    use crate::tests::support::keypair;
    let sender = &keypair(1);
    let bootstrap = keypair(2);
    let requester = keypair(3);
    let usdc = Mint::new(Address::new_from_array([0x31; 32]), 2);
    let request = requester.get_recipient_request_view_tag(0).unwrap();
    let state = history(sender);
    let transaction = ring_transaction(vec![
        ring_utxo(sender, usdc, 10, 0),
        ring_utxo(sender, Mint::SOL, 10, 1),
    ]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(AnonymousPayment {
            asset: usdc,
            ..payment(&ring_address(&bootstrap), 3)
        })
        .unwrap()
        .with_payment(AnonymousPayment {
            first_contact: FirstContact::Request(request),
            ..payment(&ring_address(&requester), 2)
        })
        .unwrap()
        .with_shape(spr_client::Shape::IN2_OUT8)
        .unwrap();
    let staged = stage_anonymous(&transfer, &Chain::ring(anonymous()))
        .await
        .unwrap();
    let outputs = &staged.proof_inputs.output_utxos;
    let sender_address = sender.shielded_address().unwrap();
    assert_eq!(
        outputs[..2]
            .iter()
            .map(|output| (output.owner_address, output.asset, output.amount))
            .collect::<Vec<_>>(),
        [
            (Some(sender_address), usdc, 7),
            (Some(sender_address), Mint::SOL, 8)
        ]
    );
    let slots = published(&staged);
    let sender_tag = sender.get_sender_view_tag(0).unwrap();
    assert_eq!(slots[0].0, sender_tag);
    assert_ne!(slots[1].0, sender_tag);
    assert_eq!(slots[2].0, bootstrap.viewing_pubkey().u());
    assert_eq!(slots[3].0, request);
    assert!(slots[..2].iter().all(|(_, body)| body.is_none()));
    assert!(slots[2..].iter().all(|(_, body)| body.is_some()));
    for (tag, _) in &slots[3..] {
        assert_eq!(tag[0], 0, "a request or dummy tag is zero-led");
    }
    let sent = bundle(&staged, sender);
    assert_eq!(
        (
            sent.verified.spl_mint,
            sent.verified.spl_amount,
            sent.verified.sol_amount
        ),
        (usdc.asset, 7, 8)
    );
    assert_eq!(
        sent.verified.recipient_viewing_pks.len(),
        outputs.len() - 2,
        "one entry per non-change output"
    );
    assert_eq!(
        listed_recipients(&sent).copied().collect::<Vec<_>>(),
        [bootstrap.viewing_pubkey(), requester.viewing_pubkey()]
    );
    let paid = payment_at(&staged, &bootstrap, 2);
    assert_eq!(
        (
            paid.verified.owner_pubkey,
            paid.verified.mint,
            paid.verified.amount,
            paid.unverified.sender_pubkey
        ),
        (
            bootstrap.signing_pubkey(),
            usdc.asset,
            3,
            sender.viewing_pubkey()
        )
    );
}

#[tokio::test]
async fn a_transfer_returning_nothing_leads_with_a_zero_sol_change() {
    use crate::tests::support::keypair;
    let sender = &keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(sender);
    let transfer = owner_transfer(
        sender,
        ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
    )
    .with_anonymous_signer(&sender.signing_key, &state)
    .with_payment(payment(&paid, 10))
    .unwrap();
    let staged = stage_anonymous(&transfer, &Chain::ring(anonymous()))
        .await
        .unwrap();
    let leading = &staged.proof_inputs.output_utxos[0];
    assert_eq!(
        (leading.owner_address, leading.asset, leading.amount),
        (Some(sender.shielded_address().unwrap()), Mint::SOL, 0)
    );
    let sent = bundle(&staged, sender);
    assert_eq!(
        (sent.verified.sol_amount, listed_recipients(&sent).count()),
        (0, 1)
    );
}

/// A first payment pairs the recipient, the next one takes the shared tag at index 0.
#[tokio::test]
async fn a_known_recipient_takes_the_shared_tag_and_the_history_advances() {
    use crate::tests::support::keypair;
    let sender = &keypair(1);
    let recipient = keypair(2);
    let paid = ring_address(&recipient);
    let pay = |state: &ViewingHistory| {
        owner_transfer(
            sender,
            ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
        )
        .with_anonymous_signer(&sender.signing_key, state)
        .with_payment(payment(&paid, 4))
        .unwrap()
        .viewing_history()
        .unwrap()
    };
    let first = pay(&history(sender));
    assert_eq!(first.current().tx_count(), 1);
    assert_eq!(
        first
            .current()
            .known_recipients()
            .get(&recipient.viewing_pubkey())
            .map(StreamCounter::next),
        Some(0)
    );
    let transfer = owner_transfer(
        sender,
        ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
    )
    .with_anonymous_signer(&sender.signing_key, &first)
    .with_payment(payment(&paid, 4))
    .unwrap();
    let staged = stage_anonymous(&transfer, &Chain::ring(anonymous()))
        .await
        .unwrap();
    let slots = published(&staged);
    assert_eq!(slots[0].0, sender.get_sender_view_tag(1).unwrap());
    assert_eq!(
        slots[1].0,
        sender
            .get_send_shared_view_tag(&recipient.viewing_pubkey(), 0)
            .unwrap()
    );
    let Spend::Anonymous(spend) = staged.spend else {
        panic!("an anonymous ring stages its rail");
    };
    let second = spend
        .history
        .as_ref()
        .expect("the wallet rail keeps its history");
    assert_eq!(second, &pay(&first));
    assert_eq!(second.current().tx_count(), 2);
    assert_eq!(
        second
            .current()
            .known_recipients()
            .get(&recipient.viewing_pubkey())
            .map(StreamCounter::next),
        Some(1)
    );
}

/// SPP publishes the hidden owner's key beside a default-ring spend, the preview sizes it.
#[tokio::test]
async fn a_default_ring_spend_previews_the_hidden_owners_published_key() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    let entry = crate::tests::support::wallet(
        spr_transaction::Utxo {
            owner: sender.signing_pubkey(),
            asset: Mint::SOL,
            amount: 10,
            blinding: spr_keypair::random_blinding(),
            ring_program_id: None,
            data: spr_transaction::Data::default(),
        },
        &sender.nullifier_key,
        TREE_ID,
        0,
    );
    let transfer = owner_transfer(sender, ring_transaction(vec![entry]))
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let unwitnessed = transfer
        .frame(&Chain::ring(anonymous()).client())
        .await
        .unwrap();
    let instruction = unwitnessed.instruction().unwrap();
    let parsed = RingTransactData::parse(&instruction.data[1..], RingRail::Anonymous).unwrap();
    assert_eq!(
        parsed.data().anonymous.unwrap().default_owner_tag,
        Some(&sender.signing_pubkey().as_ed25519().unwrap())
    );
}

struct MoveSender<'a> {
    sender: &'a ShieldedKeypair,
    state: &'a ViewingHistory,
    payer: Address,
}

impl<'a> MoveSender<'a> {
    fn anonymous_move(
        &self,
        utxos: &'a [WalletUtxo],
        payments: Vec<RingPayment>,
    ) -> AnonymousMove<'a> {
        AnonymousMove {
            ring: ring(),
            sender: self.sender,
            nullifier_key: &self.sender.nullifier_key,
            signer: &self.sender.signing_key,
            history: self.state,
            payer: self.payer,
            utxos,
            asset: Mint::SOL,
            payments,
            entry: EntrySpend::Allow,
            co_signer: None,
        }
    }
}

fn default_ring_utxo(owner: &ShieldedKeypair, amount: u64, leaf: u64) -> WalletUtxo {
    crate::tests::support::wallet(
        spr_transaction::Utxo {
            owner: owner.signing_pubkey(),
            asset: Mint::SOL,
            amount,
            blinding: spr_keypair::random_blinding(),
            ring_program_id: None,
            data: spr_transaction::Data::default(),
        },
        &owner.nullifier_key,
        TREE_ID,
        leaf,
    )
}

/// Ordinary padding publishes the shape's inputs, 24 at 2 outputs is the widest keyed spend.
#[tokio::test]
async fn an_anonymous_move_takes_the_widest_keyed_spend_and_refuses_past_it() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let client = Chain::ring(anonymous()).client();
    let utxos: Vec<WalletUtxo> = (0..36)
        .map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf))
        .collect();
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let pay =
        |amount| owner.anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), amount)]);
    let widest = pay(24).select(&client).await.unwrap();
    let assembled = widest.assemble(&client).await.unwrap();
    assert_eq!(
        assembled.frame.proof_inputs.check_shape().unwrap(),
        spr_client::Shape::IN24_OUT2
    );
    assert!(matches!(
        pay(25).select(&client).await,
        Err(RingError::Unfunded {
            amount: 25,
            max_inputs: 24,
            ..
        })
    ));
}

/// Five payments and the change pad to 8 outputs, the anonymous key there holds 5 inputs and not 6.
#[tokio::test]
async fn an_anonymous_move_past_the_eight_output_key_is_refused_before_proving() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let recipients: Vec<ShieldedKeypair> = (10..15).map(keypair).collect();
    let client = Chain::ring(anonymous()).client();
    let state = history(&sender);
    let utxos: Vec<WalletUtxo> = (0..8)
        .map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf))
        .collect();
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let pay = |first: u64| {
        owner.anonymous_move(
            &utxos,
            recipients
                .iter()
                .zip(core::iter::once(first).chain(core::iter::repeat(1)))
                .map(|(recipient, amount)| RingPayment::bootstrap(ring_address(recipient), amount))
                .collect(),
        )
    };
    let fits = pay(1).select(&client).await.unwrap();
    assert_eq!(
        fits.assemble(&client)
            .await
            .unwrap()
            .frame
            .proof_inputs
            .check_shape()
            .unwrap(),
        spr_client::Shape::IN5_OUT8
    );
    assert!(matches!(
        pay(2).select(&client).await,
        Err(RingError::Unfunded {
            amount: 6,
            max_inputs: 5,
            ..
        })
    ));
}

/// An entry spend publishes the hidden owner's key, ring UTXOs fund the move first.
#[tokio::test]
async fn an_anonymous_move_spends_ring_utxos_before_an_entry() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let chain = Chain::ring(anonymous()).client();
    let client = &chain;
    let mut utxos = vec![default_ring_utxo(&sender, 50, 10)];
    utxos.extend((0..4).map(|leaf| ring_utxo(&sender, Mint::SOL, 5, leaf)));
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let spend = |amount| {
        let anonymous_move =
            owner.anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), amount)]);
        async move {
            let transfer = anonymous_move.select(client).await.unwrap();
            transfer.assemble(client).await.unwrap()
        }
    };
    let ring_only = spend(20).await;
    assert!(!ring_only.frame.parts.full_openings);
    assert_eq!(
        ring_only
            .frame
            .proof_inputs
            .input_utxos
            .iter()
            .filter(|input| !input.is_dummy())
            .count(),
        4
    );
    assert!(spend(30).await.frame.parts.full_openings);
    let refused = AnonymousMove {
        entry: EntrySpend::Refuse,
        ..owner.anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), 30)])
    };
    assert!(matches!(
        refused.select(client).await,
        Err(RingError::Unfunded { amount: 30, .. })
    ));
}

/// Only a mix of ring and default-ring UTXOs funds the move, the prover refuses one.
#[tokio::test]
async fn an_anonymous_move_never_mixes_ring_and_default_ring_utxos() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let mut utxos = vec![default_ring_utxo(&sender, 25, 10)];
    utxos.extend((0..4).map(|leaf| ring_utxo(&sender, Mint::SOL, 5, leaf)));
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let selection = owner
        .anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), 30)])
        .select(&Chain::ring(anonymous()).client())
        .await;
    assert!(matches!(
        selection,
        Err(RingError::Unfunded { amount: 30, .. })
    ));
}

/// Nine inputs exceed the entry class, the mix is refused before the width.
#[tokio::test]
async fn an_anonymous_spend_of_ring_and_default_ring_utxos_is_refused_before_proving() {
    let sender = crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(&sender);
    let mut utxos = vec![default_ring_utxo(&sender, 5, 10)];
    utxos.extend((0..8).map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf)));
    let transaction = ring_transaction(utxos);
    let transfer = owner_transfer(&sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    assert!(matches!(
        stage_anonymous(&transfer, &Chain::ring(anonymous())).await,
        Err(RingError::EntryRingInput { index: 1 })
    ));
}

#[tokio::test]
async fn an_anonymous_transfer_reserving_an_address_is_refused_before_signing() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    for note in [
        ring_utxo(sender, Mint::SOL, 10, 0),
        default_ring_utxo(sender, 10, 0),
    ] {
        let address =
            SppProofInputUtxo::new_address(sender.signing_pubkey(), [7; 32], TREE_ID).unwrap();
        let transaction = ConfidentialTransaction::new_with_addresses(
            vec![note],
            vec![address],
            crate::tests::support::payer(),
        )
        .unwrap();
        // A ring-less change would exit to the sender and fail first.
        let transfer = owner_transfer(sender, transaction)
            .with_anonymous_signer(&sender.signing_key, &state)
            .with_payment(payment(&paid, 10))
            .unwrap();
        assert!(matches!(
            stage_anonymous(&transfer, &Chain::ring(anonymous())).await,
            Err(RingError::InvalidAnonymousSlot)
        ));
    }
}

/// The entry key rebuilds every spent UTXO from its opening, a data hash breaks the audit proof.
#[tokio::test]
async fn an_entry_spend_of_a_utxo_carrying_data_is_refused_before_proving() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let chain = Chain::ring(anonymous());
    let mut entry = default_ring_utxo(&sender, 50, 10);
    entry.data_hash = Some([7; 32]);
    entry.utxo_hash = entry
        .utxo
        .hash(&entry.nullifier_pubkey, &[7; 32], &[0; 32], TREE_ID)
        .unwrap();
    entry.nullifier = sender
        .nullifier_key
        .nullifier(&entry.utxo_hash, &entry.utxo.blinding)
        .unwrap();
    let transfer = owner_transfer(&sender, ring_transaction(vec![entry.clone()]))
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    assert!(matches!(
        stage_anonymous(&transfer, &chain).await,
        Err(RingError::EntryInputData { index: 0 })
    ));
    let utxos = [entry];
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let selection = owner
        .anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), 4)])
        .select(&chain.client())
        .await;
    assert!(matches!(
        selection,
        Err(RingError::Unfunded { amount: 4, .. })
    ));
}

/// The fee payer is a public signer, the hidden owner may not pay its move.
#[tokio::test]
async fn an_anonymous_move_its_owner_would_pay_is_refused_before_proving() {
    use crate::tests::support::keypair;
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = history(&sender);
    let utxos = [ring_utxo(&sender, Mint::SOL, 5, 0)];
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: HiddenOwner::of(&sender.signing_pubkey()).unwrap().0,
    };
    let selection = owner
        .anonymous_move(&utxos, vec![RingPayment::bootstrap(paid.clone(), 5)])
        .select(&Chain::ring(anonymous()).client())
        .await;
    assert!(matches!(
        selection,
        Err(RingError::AnonymousPublicSignerLinksOwner)
    ));
}

/// The transaction payer differs from the hidden owner, the submission's signers do not.
#[tokio::test]
async fn an_anonymous_transfer_its_owner_would_sign_in_public_is_refused_before_proving() {
    use solana_signer::Signer;
    let sender = &crate::tests::support::keypair(1);
    let payer = crate::tests::support::keypair(9);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    let client = Chain::ring(anonymous()).client();
    let unsigned: &[&(dyn Signer + Sync)] = &[];
    for (fee_payer, signers) in [
        (sender, unsigned),
        (&payer, &[sender as &(dyn Signer + Sync)]),
    ] {
        let transfer = owner_transfer(
            sender,
            ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
        )
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
        let refused = crate::RingSubmission::new(transfer)
            .send(&client, fee_payer, signers)
            .await;
        assert!(matches!(
            refused,
            Err(RingError::AnonymousPublicSignerLinksOwner)
        ));
    }
}

#[tokio::test]
async fn only_the_configured_delegate_moves_utxos_on_an_escrowed_policy_ring() {
    let member = &crate::tests::support::keypair(1);
    let stranger = &crate::tests::support::keypair(3);
    let delegate = Address::new_from_array([0x44; 32]);
    let escrowed = RingSettings {
        has_policy: true,
        delegate: Some(delegate),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    };
    let stage = |settings: RingSettings, signer: Address, key: &ShieldedKeypair, inputs| {
        stage_delegate(DelegateCase {
            settings,
            delegate: signer,
            member,
            key: key.nullifier_key.clone(),
            inputs,
        })
    };
    let utxos = |count: u64| -> Vec<WalletUtxo> {
        (0..count)
            .map(|leaf| ring_utxo(member, Mint::SOL, 1, leaf))
            .collect()
    };
    assert!(stage(escrowed, delegate, member, utxos(2)).await.is_ok());
    assert!(matches!(
        stage(
            RingSettings {
                delegate: None,
                ..escrowed
            },
            delegate,
            member,
            utxos(2)
        )
        .await,
        Err(RingError::MissingDelegate)
    ));
    assert!(matches!(
        stage(
            escrowed,
            Address::new_from_array([0x45; 32]),
            member,
            utxos(2)
        )
        .await,
        Err(RingError::Program(CustomRingError::UnauthorizedDelegate))
    ));
    for settings in [
        RingSettings {
            has_policy: false,
            ..escrowed
        },
        RingSettings {
            mode: RingMode::Confidential,
            ..escrowed
        },
    ] {
        assert!(matches!(
            stage(settings, delegate, member, utxos(2)).await,
            Err(RingError::DelegateRequiresEscrow)
        ));
    }
    assert!(matches!(
        stage(escrowed, delegate, stranger, utxos(2)).await,
        Err(RingError::NullifierKeyMismatch)
    ));
    let mut mixed = utxos(1);
    mixed.push(ring_utxo(stranger, Mint::SOL, 1, 1));
    assert!(matches!(
        stage(escrowed, delegate, member, mixed).await,
        Err(RingError::MixedOwners { index: 1 })
    ));
    assert!(matches!(
        stage(escrowed, delegate, member, utxos(41)).await,
        Err(RingError::ShapeUnkeyed {
            rail: RingRail::Delegate
        })
    ));
}

#[test]
fn an_unkeyed_shape_names_its_rail_in_words() {
    assert_eq!(
        RingError::ShapeUnkeyed {
            rail: RingRail::Delegate
        }
        .to_string(),
        "the transfer needs a shape no delegate key serves"
    );
}

#[tokio::test]
async fn a_delegate_move_pads_to_any_ring_authority_shape_it_is_given() {
    use spr_client::Shape;
    let member = &crate::tests::support::keypair(1);
    let delegate = Address::new_from_array([0x44; 32]);
    let source = member.shielded_address().unwrap();
    let assets = AssetRegistry::default();
    let transfer = || {
        DelegateTransfer::new(DelegateTransferInput {
            ring: ring(),
            delegate,
            payer: crate::tests::support::payer(),
            source,
            source_nullifier_key: &member.nullifier_key,
            inputs: vec![ring_utxo(member, Mint::SOL, 3, 0)],
            outputs: vec![DelegateOutput {
                recipient: source,
                asset: Mint::SOL.asset,
                amount: 2,
            }],
        })
        .with_assets(&assets)
    };
    assert!(matches!(
        transfer().with_shape(Shape::IN48_OUT2),
        Err(RingError::ShapeUnkeyed {
            rail: RingRail::Delegate
        })
    ));
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        delegate: Some(delegate),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    });
    let config = ring().require_config(&chain).await.unwrap();
    let automatic = transfer();
    let staged = automatic.rail.stage(ring(), &chain, &config).await.unwrap();
    assert_eq!(staged.proof_inputs.check_shape().unwrap(), Shape::IN2_OUT2);
    assert!(matches!(
        staged.rail.delivery(),
        RingDelivery::Delivered { .. }
    ));
    let shaped = transfer().with_shape(Shape::IN4_OUT4).unwrap();
    let staged = shaped.rail.stage(ring(), &chain, &config).await.unwrap();
    assert_eq!(staged.proof_inputs.check_shape().unwrap(), Shape::IN4_OUT4);
    assert!(matches!(
        staged.rail.delivery(),
        RingDelivery::Delivered { .. }
    ));
}

struct MoveFixture<'a> {
    member: &'a ShieldedKeypair,
    recipient: spr_keypair::ShieldedAddress,
    delegate: Address,
    assets: &'a AssetRegistry,
}

struct MoveCase<'a> {
    utxos: &'a [WalletUtxo],
    payer: Address,
    amounts: &'a [u64],
}

impl<'a> MoveFixture<'a> {
    fn delegate_move(&self, case: MoveCase<'a>) -> DelegateMove<'a> {
        DelegateMove {
            ring: ring(),
            delegate: self.delegate,
            payer: case.payer,
            source: self.member.shielded_address().unwrap(),
            source_nullifier_key: &self.member.nullifier_key,
            utxos: case.utxos,
            mint: Mint::SOL.asset,
            payments: case
                .amounts
                .iter()
                .map(|amount| DelegatePayment {
                    recipient: self.recipient,
                    amount: *amount,
                })
                .collect(),
            assets: self.assets,
            co_signer: None,
        }
    }
}

/// The selected move's shape and the tree its inputs sit on.
async fn selected(
    transfer: DelegateTransfer<'_>,
    client: &RingClient<Chain, Chain>,
) -> (spr_client::Shape, u16) {
    let assembled = transfer.assemble(client).await.unwrap();
    (
        assembled.frame.proof_inputs.check_shape().unwrap(),
        assembled.frame.proof_inputs.input_utxos[0].tree_id,
    )
}

/// A delegate move on a policy ring with one member paying another.
fn move_chain(members: [&ShieldedKeypair; 2], delegate: Address) -> Chain {
    use crate::tests::support::Registry;
    Chain::ring(RingSettings {
        has_policy: true,
        delegate: Some(delegate),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_tree(1)
    .with_registry(
        Registry::new(&members.map(|member| (member, 1))),
        &crate::tests::pipeline_rules(),
    )
}

/// Four UTXOs fill the widest delegate shape, one large UTXO takes the narrowest whoever pays.
#[tokio::test]
async fn a_delegate_move_takes_the_fewest_utxos() {
    use crate::tests::support::{keypair, payer, wallet};
    let member = keypair(1);
    let recipient = keypair(2);
    let delegate = Address::new_from_array([0x44; 32]);
    let client = move_chain([&member, &recipient], delegate).client();
    let assets = AssetRegistry::default();
    let fixture = MoveFixture {
        member: &member,
        recipient: recipient.shielded_address().unwrap(),
        delegate,
        assets: &assets,
    };
    let mut utxos: Vec<WalletUtxo> = (0..8)
        .map(|leaf| ring_utxo(&member, Mint::SOL, 1, leaf))
        .collect();
    let lean = fixture.delegate_move(MoveCase {
        utxos: &utxos,
        payer: delegate,
        amounts: &[4],
    });
    assert_eq!(
        selected(lean.select(&client).await.unwrap(), &client).await,
        (spr_client::Shape::IN4_OUT4, TREE_ID)
    );
    let short = fixture.delegate_move(MoveCase {
        utxos: &utxos,
        payer: delegate,
        amounts: &[5],
    });
    assert!(matches!(
        short.select(&client).await,
        Err(RingError::Unfunded {
            amount: 5,
            max_inputs: 4,
            ..
        })
    ));
    let large = ring_utxo(&member, Mint::SOL, 50, 8);
    utxos.push(wallet(large.utxo, &member.nullifier_key, 1, 8));
    for payer in [delegate, payer()] {
        let wide = fixture.delegate_move(MoveCase {
            utxos: &utxos,
            payer,
            amounts: &[4],
        });
        assert_eq!(
            selected(wide.select(&client).await.unwrap(), &client).await,
            (spr_client::Shape::IN2_OUT2, 1)
        );
    }
}

/// Every tree funds the move, the assembly reads the first tree's inputs alone.
#[tokio::test]
async fn a_selection_over_three_candidates_reads_only_the_chosen_inputs() {
    use crate::tests::support::{keypair, wallet};
    let member = keypair(1);
    let recipient = keypair(2);
    let delegate = Address::new_from_array([0x44; 32]);
    let chain = move_chain([&member, &recipient], delegate)
        .with_tree(2)
        .with_tree(3);
    let client = chain.clone().witness_client();
    let assets = AssetRegistry::default();
    let fixture = MoveFixture {
        member: &member,
        recipient: recipient.shielded_address().unwrap(),
        delegate,
        assets: &assets,
    };
    let utxos: Vec<WalletUtxo> = [1u16, 2, 3]
        .into_iter()
        .flat_map(|tree| (0..4).map(move |leaf| (tree, leaf)))
        .map(|(tree, leaf)| WalletUtxo {
            latest_tree_id: Some(3),
            ..wallet(
                ring_utxo(&member, Mint::SOL, 1, leaf).utxo,
                &member.nullifier_key,
                tree,
                leaf,
            )
        })
        .collect();
    let chosen = fixture
        .delegate_move(MoveCase {
            utxos: &utxos,
            payer: delegate,
            amounts: &[4],
        })
        .select(&client)
        .await
        .unwrap();
    assert!(chain.witness_requests.lock().unwrap().is_empty());
    assert!(matches!(
        chosen.assemble(&client).await,
        Err(RingError::Client(ClientError::NoInputs))
    ));
    let mut chosen_inputs: Vec<[u8; 32]> = utxos
        .iter()
        .filter(|utxo| utxo.tree_id == 1)
        .map(|utxo| utxo.utxo_hash)
        .collect();
    chosen_inputs.sort_unstable();
    let requests = chain.witness_requests.lock().unwrap().clone();
    let [requested] = requests.as_slice() else {
        panic!("one witness read, {requests:?}");
    };
    let mut requested = requested.clone();
    requested.sort_unstable();
    assert_eq!(requested, chosen_inputs);
}

/// Four payments fill the widest delegate output count, an exact funding needs no change slot.
#[tokio::test]
async fn a_delegate_move_takes_a_change_slot_only_for_change() {
    use crate::tests::support::keypair;
    let member = keypair(1);
    let recipient = keypair(2);
    let delegate = Address::new_from_array([0x44; 32]);
    let client = move_chain([&member, &recipient], delegate).client();
    let assets = AssetRegistry::default();
    let exact = [ring_utxo(&member, Mint::SOL, 4, 0)];
    let over = [ring_utxo(&member, Mint::SOL, 5, 0)];
    let fixture = MoveFixture {
        member: &member,
        recipient: recipient.shielded_address().unwrap(),
        delegate,
        assets: &assets,
    };
    let four = |utxos| {
        fixture.delegate_move(MoveCase {
            utxos,
            payer: delegate,
            amounts: &[1; 4],
        })
    };
    assert_eq!(
        selected(four(&exact).select(&client).await.unwrap(), &client).await,
        (spr_client::Shape::IN4_OUT4, TREE_ID)
    );
    assert!(matches!(
        four(&over).select(&client).await,
        Err(RingError::ShapeUnkeyed {
            rail: RingRail::Delegate
        })
    ));
}

struct DelegateCase<'a> {
    settings: RingSettings,
    delegate: Address,
    member: &'a ShieldedKeypair,
    key: spr_keypair::NullifierKey,
    inputs: Vec<WalletUtxo>,
}

async fn stage_delegate(case: DelegateCase<'_>) -> Result<(), RingError> {
    let assets = AssetRegistry::default();
    let source = case.member.shielded_address()?;
    let transfer = DelegateTransfer::new(DelegateTransferInput {
        ring: ring(),
        delegate: case.delegate,
        payer: crate::tests::support::payer(),
        source,
        source_nullifier_key: &case.key,
        inputs: case.inputs,
        outputs: vec![DelegateOutput {
            recipient: source,
            asset: Mint::SOL.asset,
            amount: 2,
        }],
    })
    .with_assets(&assets);
    let chain = Chain::ring(case.settings);
    let config = ring().require_config(&chain).await?;
    transfer
        .rail
        .stage(ring(), &chain, &config)
        .await
        .map(|_| ())
}

/// Every string a request draws, hashes or derives keeps only its length.
fn request_layout(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => serde_json::Value::String(format!("str{}", text.len())),
        serde_json::Value::Array(items) => items.iter().map(request_layout).collect(),
        serde_json::Value::Object(fields) => fields
            .iter()
            .map(|(key, field)| (key.clone(), request_layout(field)))
            .collect(),
        other => other.clone(),
    }
}

fn nonzero(value: &serde_json::Value) -> bool {
    value
        .as_str()
        .unwrap()
        .trim_start_matches("0x")
        .bytes()
        .any(|digit| digit != b'0')
}

/// Each output slot as the anonymous audit circuit reads it, change the slots `sender_key` owns.
fn slot_kinds(request: &serde_json::Value, sender_key: &[u8; 32]) -> Vec<&'static str> {
    let sender_key = format!("0x{}", hex::encode(sender_key));
    request["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|slot| {
            let opening = &slot["output"];
            match (
                nonzero(&opening["ownerPkHash"]),
                nonzero(&opening["ringProgramId"]),
            ) {
                (false, _) => "padding",
                (true, false) => "exit",
                (true, true) if slot["ownerKey"] == sender_key.as_str() => "change",
                (true, true) => "payment",
            }
        })
        .collect()
}

/// A rebuilt transfer never reuses a key and nonce with another plaintext.
#[tokio::test]
async fn two_builds_of_one_transfer_draw_a_fresh_salt_and_a_fresh_ephemeral_key() {
    let sender = &crate::tests::support::keypair(1);
    let state = history(sender);
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let build = || async {
        owner_transfer(sender, transaction.clone())
            .with_anonymous_signer(&sender.signing_key, &state)
            .with_shape(spr_client::Shape::IN1_OUT4)
            .unwrap()
            .assemble(&Chain::ring(anonymous()).client())
            .await
            .unwrap()
    };
    let (first, second) = (build().await, build().await);
    assert_ne!(first.frame.parts.salt, second.frame.parts.salt);
    assert_ne!(first.frame.parts.eph_u, second.frame.parts.eph_u);
    assert_ne!(
        **first.frame.sealed.ephemeral_secret(),
        **second.frame.sealed.ephemeral_secret()
    );
    assert_ne!(first.frame.parts.envelope, second.frame.parts.envelope);
}

/// `UPDATE_PROVER_JSON=1` rewrites the pinned request.
#[tokio::test]
async fn the_anonymous_audit_request_of_an_exit_a_payment_and_change_keeps_its_pinned_layout() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let exit = crate::tests::support::keypair(3)
        .shielded_address()
        .unwrap();
    let state = history(sender);
    let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(&exit, Mint::SOL, 3, None)
        .unwrap();
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap()
        .with_shape(spr_client::Shape::IN1_OUT4)
        .unwrap();
    let assembled = transfer
        .assemble(&Chain::ring(anonymous()).client())
        .await
        .unwrap();
    let request = assembled.request().unwrap();
    assert_eq!(
        request.circuit,
        custom_ring_interface::key_catalog::RingCircuit::TransferAnonymous {
            outputs: 4,
            class: 16,
            withdrawals: 4
        }
    );
    let built = serde_json::to_value(
        crate::prover::RequestBody::new(request.circuit, &request.body).unwrap(),
    )
    .unwrap();
    let sender_key = sender.signing_pubkey().as_ed25519().unwrap();
    assert_eq!(
        slot_kinds(&built, &sender_key),
        ["change", "exit", "payment", "padding"]
    );
    assert_eq!(built["inputCount"], 1);
    assert_eq!(built["inputs"].as_array().unwrap().len(), 16);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/custom-ring-transfer-anonymous-exit.json");
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(request_layout(&built), request_layout(&pinned));
    assert_eq!(
        slot_kinds(&pinned, &sender_key),
        slot_kinds(&built, &sender_key)
    );
}

/// SPP hides the in-proof owner, the ring proof holds both spent notes to the sender it publishes.
#[tokio::test]
async fn the_in_proof_owner_request_publishes_the_sender_of_every_spent_note() {
    let sender = &crate::tests::support::keypair(1);
    let recipient = crate::tests::support::keypair(2)
        .shielded_address()
        .unwrap();
    let mut transaction = ring_transaction(vec![
        ring_utxo(sender, Mint::SOL, 10, 0),
        ring_utxo(sender, Mint::SOL, 5, 1),
    ]);
    transaction
        .transfer_with_ring(&recipient, Mint::SOL, 4, Some(ring().program_id()))
        .unwrap();
    let assembled = owner_transfer(sender, transaction)
        .with_in_proof_owner(&sender.signing_key)
        .assemble(&Chain::ring(RingSettings::new(RingMode::Confidential)).client())
        .await
        .unwrap();
    let request = assembled.request().unwrap();
    assert_eq!(
        request.circuit,
        custom_ring_interface::key_catalog::RingCircuit::TransferConfidential {
            outputs: 2,
            inputs: 32,
            withdrawals: 4
        }
    );
    let built = serde_json::to_value(
        crate::prover::RequestBody::new(request.circuit, &request.body).unwrap(),
    )
    .unwrap();
    let sender_pk_hash = sender.signing_pubkey().owner_proof_input_hash().unwrap();
    // The audit-only ring screens nothing, the in-proof owner still names the sender.
    assert_eq!(
        built["sender"],
        format!("0x{}", hex::encode(sender_pk_hash))
    );
    assert_eq!(built["inProof"], true);
    assert_eq!(built["policyHash"], format!("0x{}", "00".repeat(32)));
    let inputs = built["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 32);
    assert_eq!(
        inputs
            .iter()
            .filter(|input| nonzero(&input["ownerPkHash"]))
            .count(),
        2
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/custom-ring-transfer-confidential-in-proof.json");
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(request_layout(&built), request_layout(&pinned));
}

/// The program refuses dual control the owner would satisfy itself.
#[tokio::test]
async fn an_approval_its_owner_would_co_sign_is_refused_before_proving() {
    use crate::tests::support::{keypair, Registry};
    use zolana_ring_policy::{ListId, Member, OutflowLimit, Rule, RuleTable, Subject};
    let sender = keypair(1);
    let recipient = keypair(2);
    let owner = Address::new_from_array(sender.signing_pubkey().confidential_view_tag().unwrap());
    let limit = OutflowLimit::of(&Member::asset(&Mint::SOL.asset).unwrap()).with_cosign_above(1);
    let rules = RuleTable::builder()
        .rule(Rule::require(Subject::Sender, ListId::Allow))
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .build();
    // The deposit scope leaves the approval as the transfer's only demand.
    let settings = RingSettings {
        has_policy: true,
        co_signer: Some((owner, custom_ring_interface::CoSignScope::DEPOSITS)),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    };
    let client = Chain::ring(settings)
        .with_registry(
            Registry::new(&[(&sender, 1), (&recipient, 1)]).with_mint(
                Mint::SOL.asset,
                zolana_ring_policy::MintPolicy {
                    cosign_above: limit.cosign_above,
                    ..Default::default()
                },
            ),
            &rules,
        )
        .client();
    let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(
            &recipient.shielded_address().unwrap(),
            Mint::SOL,
            3,
            Some(ring().program_id()),
        )
        .unwrap();
    assert!(matches!(
        owner_transfer(&sender, transaction)
            .with_co_signer(owner)
            .assemble(&client)
            .await,
        Err(RingError::Program(CustomRingError::CoSignerIsOwner))
    ));
}

/// The transfer scope demands the co-signer on every transfer, an owner signer cannot be it.
#[tokio::test]
async fn a_scope_co_signer_among_the_owner_signers_is_refused_before_proving() {
    use crate::tests::support::keypair;
    let sender = keypair(1);
    let recipient = keypair(2);
    let owner = Address::new_from_array(sender.signing_pubkey().confidential_view_tag().unwrap());
    let client = Chain::ring(RingSettings {
        co_signer: Some((owner, custom_ring_interface::CoSignScope::TRANSFERS)),
        ..RingSettings::new(RingMode::Confidential)
    })
    .client();
    let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(
            &recipient.shielded_address().unwrap(),
            Mint::SOL,
            3,
            Some(ring().program_id()),
        )
        .unwrap();
    assert!(matches!(
        owner_transfer(&sender, transaction)
            .with_co_signer(owner)
            .assemble(&client)
            .await,
        Err(RingError::Program(CustomRingError::CoSignerIsOwner))
    ));
}

/// The hidden owner signs for every spent note, a note of another owner fails both proofs.
#[tokio::test]
async fn an_anonymous_transfer_of_another_owners_utxo_is_refused_before_proving() {
    let sender = &crate::tests::support::keypair(1);
    let other = &crate::tests::support::keypair(3);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    let transaction = ring_transaction(vec![
        ring_utxo(sender, Mint::SOL, 10, 0),
        ring_utxo(other, Mint::SOL, 10, 1),
    ]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    assert!(matches!(
        stage_anonymous(&transfer, &Chain::ring(anonymous())).await,
        Err(RingError::MixedOwners { index: 1 })
    ));
}

/// A policy transfer spends one owner's notes, the program takes exactly one owner signer.
#[tokio::test]
async fn a_policy_transfer_of_two_owners_utxos_is_refused_before_proving() {
    use crate::tests::support::{keypair, Registry};
    let sender = keypair(1);
    let other = keypair(2);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(
        Registry::new(&[(&sender, 1), (&other, 1)]),
        &crate::tests::pipeline_rules(),
    )
    .client();
    let transaction = ring_transaction(vec![
        ring_utxo(&sender, Mint::SOL, 10, 0),
        ring_utxo(&other, Mint::SOL, 10, 1),
    ]);
    assert!(matches!(
        owner_transfer(&sender, transaction).assemble(&client).await,
        Err(RingError::Program(CustomRingError::OwnerSignerCount))
    ));
}

/// The refusal of a recipient off the allow list names its rule and output.
#[tokio::test]
async fn a_recipient_the_rules_refuse_fails_before_proving() {
    use crate::tests::support::{keypair, Registry};
    use zolana_ring_policy::{RuleRefusal, TransferSubject};
    let sender = keypair(1);
    let recipient = keypair(2);
    let settings = RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    };
    let client = Chain::ring(settings)
        .with_registry(
            Registry::new(&[(&sender, 1), (&recipient, 0)]),
            &crate::tests::pipeline_rules(),
        )
        .client();
    let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(
            &recipient.shielded_address().unwrap(),
            Mint::SOL,
            3,
            Some(ring().program_id()),
        )
        .unwrap();
    assert!(matches!(
        owner_transfer(&sender, transaction).assemble(&client).await,
        Err(RingError::PolicyRuleUnsatisfied(RuleRefusal::Lists {
            rule: 1,
            subject: TransferSubject::Owner(0),
        }))
    ));
}

/// The records follow the ring account, a curator registry only where a source names one.
#[tokio::test]
async fn a_policy_transfer_names_a_curator_registry_only_under_a_curator_source() {
    use crate::tests::support::{keypair, Registry, RECORDS};
    use custom_ring_interface::SourceSlot;
    use solana_instruction::AccountMeta;
    use zolana_ring_policy::ListId;
    let sender = keypair(1);
    let recipient = keypair(2);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Confidential)
    })
    .with_registry(
        Registry::new(&[(&sender, 1), (&recipient, 1)]),
        &crate::tests::pipeline_rules(),
    )
    .client();
    let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(
            &recipient.shielded_address().unwrap(),
            Mint::SOL,
            3,
            Some(ring().program_id()),
        )
        .unwrap();
    let transfer = owner_transfer(&sender, transaction);
    let unwitnessed = transfer.frame(&client).await.unwrap();
    let registry = |address| AccountMeta::new_readonly(address, false);
    let accounts = unwitnessed.instruction().unwrap().accounts;
    assert_eq!(accounts[1], registry(RECORDS));
    assert_ne!(accounts[2].pubkey, RECORDS);
    let curator = Address::new_from_array([0x5c; 32]);
    let mut curated = *unwitnessed.config.account();
    curated.sources[ListId::Allow.slot()] = SourceSlot {
        list_id: ListId::Allow as u8,
        registry: curator,
    };
    let frame = &unwitnessed.frame;
    let accounts = frame
        .accounts
        .instruction(frame.ring, &curated, &frame.parts)
        .unwrap()
        .accounts;
    assert_eq!(accounts[1..3], [registry(RECORDS), registry(curator)]);
    assert_eq!(
        accounts[3..],
        unwitnessed.instruction().unwrap().accounts[2..]
    );
}

/// `UPDATE_PROVER_JSON=1` rewrites the shared pooled request Go solves and TS rebuilds.
#[tokio::test]
async fn the_member_policy_request_opens_each_subject_once_in_padded_pools() {
    use crate::tests::support::{keypair, Registry};
    let sender = keypair(1);
    let recipient = keypair(2);
    let settings = RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    };
    let client = Chain::ring(settings)
        .with_registry(
            Registry::new(&[(&sender, 1), (&recipient, 1)]),
            &crate::tests::pipeline_rules(),
        )
        .client();
    let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(
            &recipient.shielded_address().unwrap(),
            Mint::SOL,
            3,
            Some(ring().program_id()),
        )
        .unwrap();
    let assembled = owner_transfer(&sender, transaction)
        .assemble(&client)
        .await
        .unwrap();
    let request = assembled.request().unwrap();
    let built = serde_json::to_value(
        crate::prover::RequestBody::new(request.circuit, &request.body).unwrap(),
    )
    .unwrap();
    let subjects = |pool: &str| -> Vec<String> {
        built[pool]
            .as_array()
            .unwrap()
            .iter()
            .map(|subject| subject["member"].as_str().unwrap().to_owned())
            .collect()
    };
    let own = subjects("ownSubjects");
    // The sender, the recipient and the asset, cycled to the pool width.
    assert_eq!(
        own[..3]
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    assert!(own
        .iter()
        .enumerate()
        .all(|(index, member)| *member == own[index % 3]));
    assert_eq!(built["ownRecords"].as_array().unwrap().len(), own.len());
    let name = built["circuitType"].as_str().unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/fixtures/{name}.json"));
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(request_layout(&built), request_layout(&pinned));
}

include!("size_pins.rs");

impl Measured {
    /// A delegate moves only on a policy ring.
    fn policy(self) -> bool {
        !matches!(
            self,
            Self::Confidential | Self::InProofOwner | Self::Anonymous | Self::AnonymousEntry
        )
    }

    fn anonymous(self) -> bool {
        matches!(
            self,
            Self::Anonymous
                | Self::AnonymousPolicy
                | Self::AnonymousEntry
                | Self::AnonymousEntryPolicy
        )
    }

    fn entry(self) -> bool {
        matches!(self, Self::AnonymousEntry | Self::AnonymousEntryPolicy)
    }

    fn ring_rail(self) -> RingRail {
        match self {
            Self::Confidential
            | Self::ConfidentialPolicy
            | Self::ConfidentialEscrow
            | Self::InProofOwner
            | Self::InProofOwnerPolicy
            | Self::InProofOwnerEscrow => RingRail::Confidential,
            Self::Anonymous
            | Self::AnonymousPolicy
            | Self::AnonymousEntry
            | Self::AnonymousEntryPolicy => RingRail::Anonymous,
            Self::Delegate => RingRail::Delegate,
        }
    }

    fn keyed(self, shape: spr_client::Shape) -> bool {
        match self.entry() {
            true => super::anonymous::AnonymousKey::Entry.serves(shape),
            false => shape_keyed(self.ring_rail(), shape),
        }
    }

    fn sweep_payer(self) -> Payer {
        match self {
            Self::Confidential | Self::ConfidentialPolicy | Self::ConfidentialEscrow => {
                Payer::Owner
            }
            Self::Delegate => Payer::Delegate,
            Self::InProofOwner
            | Self::InProofOwnerPolicy
            | Self::InProofOwnerEscrow
            | Self::Anonymous
            | Self::AnonymousPolicy
            | Self::AnonymousEntry
            | Self::AnonymousEntryPolicy => Payer::Outsider,
        }
    }

    fn mode(self) -> RingMode {
        match self {
            Self::Anonymous
            | Self::AnonymousPolicy
            | Self::AnonymousEntry
            | Self::AnonymousEntryPolicy => RingMode::Anonymous,
            Self::ConfidentialEscrow | Self::InProofOwnerEscrow | Self::Delegate => {
                RingMode::ConfidentialEscrow
            }
            Self::Confidential
            | Self::ConfidentialPolicy
            | Self::InProofOwner
            | Self::InProofOwnerPolicy => RingMode::Confidential,
        }
    }
}

const MEASURED_DELEGATE: Address = Address::new_from_array([0x44; 32]);

#[derive(Clone, Copy, Debug)]
enum Payer {
    Outsider,
    Owner,
    Delegate,
}

impl Payer {
    fn address(self, owner: &ShieldedKeypair) -> Address {
        match self {
            Self::Outsider => crate::tests::support::payer(),
            Self::Owner => owner.shielded_address().unwrap().solana_address().unwrap(),
            Self::Delegate => MEASURED_DELEGATE,
        }
    }
}

const MEASURED_CO_SIGNER: (Address, custom_ring_interface::CoSignScope) = (
    Address::new_from_array([0x46; 32]),
    custom_ring_interface::CoSignScope::TRANSFERS,
);

/// The transfer filling `shape`, every output but the change paying another member.
#[derive(Clone, Copy)]
struct Measure {
    rail: Measured,
    shape: spr_client::Shape,
    payer: Payer,
    co_signer: Option<(Address, custom_ring_interface::CoSignScope)>,
    /// SOL withdrawal legs.
    legs: usize,
}

/// `addresses` stays `None` past the byte ceiling.
#[derive(Clone, Copy, Debug)]
struct Fit {
    bytes: usize,
    addresses: Option<usize>,
}

impl Measure {
    /// The frame the validator sweep compares against `SIZE_PINS`.
    fn pinned(rail: Measured, shape: spr_client::Shape) -> Self {
        Self {
            rail,
            shape,
            payer: rail.sweep_payer(),
            co_signer: None,
            legs: 0,
        }
    }

    fn relayed(rail: Measured, shape: spr_client::Shape) -> Self {
        Self {
            payer: Payer::Outsider,
            ..Self::pinned(rail, shape)
        }
    }

    async fn bytes(self) -> usize {
        self.fit().await.bytes
    }

    async fn fit(self) -> Fit {
        use crate::tests::support::{keypair, Registry};
        let Self {
            rail,
            shape,
            payer,
            co_signer,
            legs,
        } = self;
        let policy = rail.policy();
        let sender = keypair(1);
        let payer = payer.address(&sender);
        let recipients: Vec<ShieldedKeypair> = (0..shape.n_outputs() - 1)
            .map(|index| keypair(10 + index as u8))
            .collect();
        let utxos: Vec<WalletUtxo> = (0..shape.n_inputs() as u64)
            .map(|leaf| match rail.entry() {
                true => crate::tests::support::wallet(
                    spr_transaction::Utxo {
                        owner: sender.signing_pubkey(),
                        asset: Mint::SOL,
                        amount: 100,
                        blinding: spr_keypair::random_blinding(),
                        ring_program_id: None,
                        data: spr_transaction::Data::default(),
                    },
                    &sender.nullifier_key,
                    TREE_ID,
                    leaf,
                ),
                false => ring_utxo(&sender, Mint::SOL, 100, leaf),
            })
            .collect();
        // An anonymous exit pays one destination.
        let leg_owners: Vec<ShieldedKeypair> = match rail.anonymous() {
            true => (0..legs.min(1)).map(|_| keypair(40)).collect(),
            false => (0..legs).map(|index| keypair(40 + index as u8)).collect(),
        };
        let destinations: Vec<Address> = (0..legs)
            .map(|index| {
                let owner = &leg_owners[index.min(leg_owners.len() - 1)];
                owner.shielded_address().unwrap().solana_address().unwrap()
            })
            .collect();
        let with_legs = |transaction: &mut ConfidentialTransaction| {
            destinations
                .iter()
                .map(|recipient| {
                    transaction.withdraw_sol(1, *recipient).unwrap();
                    TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                        recipient: *recipient,
                    })
                })
                .collect::<Vec<_>>()
        };
        let settings = RingSettings {
            has_policy: policy,
            co_signer,
            delegate: (rail == Measured::Delegate).then_some(MEASURED_DELEGATE),
            ..RingSettings::new(rail.mode())
        };
        let owners: Vec<(&ShieldedKeypair, u64)> = core::iter::once(&sender)
            .chain(&recipients)
            // The allow rule needs each destination enrolled.
            .chain(&leg_owners)
            .map(|owner| (owner, 1))
            .collect();
        let chain = match policy {
            true => Chain::ring(settings)
                .with_registry(Registry::new(&owners), &crate::tests::pipeline_rules()),
            false => Chain::ring(settings),
        };
        let client = chain.client();
        let state = history(&sender);
        let assets = AssetRegistry::default();
        let size = FrameSize {
            client: &client,
            rail,
            shape,
            payer,
            co_signer: co_signer.map(|(signer, _)| signer),
        };
        let confidential = |utxos: Vec<WalletUtxo>| {
            let mut transaction = paid_ring_transaction(utxos, payer);
            for recipient in &recipients {
                transaction
                    .transfer_with_ring(
                        &recipient.shielded_address().unwrap(),
                        Mint::SOL,
                        1,
                        Some(ring().program_id()),
                    )
                    .unwrap();
            }
            let accounts = with_legs(&mut transaction);
            owner_transfer(&sender, transaction).with_interface_transfer_accounts(accounts)
        };
        match rail {
            Measured::Confidential
            | Measured::ConfidentialPolicy
            | Measured::ConfidentialEscrow => size.of(confidential(utxos)).await,
            Measured::InProofOwner
            | Measured::InProofOwnerPolicy
            | Measured::InProofOwnerEscrow => {
                size.of(confidential(utxos).with_in_proof_owner(&sender.signing_key))
                    .await
            }
            Measured::Anonymous
            | Measured::AnonymousPolicy
            | Measured::AnonymousEntry
            | Measured::AnonymousEntryPolicy => {
                let mut transaction = paid_ring_transaction(utxos, payer);
                let accounts = with_legs(&mut transaction);
                let mut transfer = owner_transfer(&sender, transaction)
                    .with_interface_transfer_accounts(accounts)
                    .with_anonymous_signer(&sender.signing_key, &state);
                for recipient in &recipients {
                    transfer = transfer
                        .with_payment(payment(&ring_address(recipient), 1))
                        .unwrap();
                }
                size.of(transfer).await
            }
            Measured::Delegate => {
                assert_eq!(legs, 0, "the authority rail carries no public leg");
                let transfer = DelegateTransfer::new(DelegateTransferInput {
                    ring: ring(),
                    delegate: MEASURED_DELEGATE,
                    payer,
                    source: sender.shielded_address().unwrap(),
                    source_nullifier_key: &sender.nullifier_key,
                    inputs: utxos,
                    outputs: recipients
                        .iter()
                        .map(|recipient| DelegateOutput {
                            recipient: recipient.shielded_address().unwrap(),
                            asset: Mint::SOL.asset,
                            amount: 1,
                        })
                        .collect(),
                })
                .with_assets(&assets);
                size.of(transfer).await
            }
        }
    }
}

#[derive(Clone, Copy)]
struct FrameSize<'c> {
    client: &'c RingClient<Chain, Chain>,
    rail: Measured,
    shape: spr_client::Shape,
    payer: Address,
    co_signer: Option<Address>,
}

impl FrameSize<'_> {
    /// A refusal past the v1 ceiling carries the bytes of the framed transfer.
    async fn of<R: Rail>(self, transfer: RingTransfer<R>) -> Fit {
        let transfer = match self.co_signer {
            Some(signer) => transfer.with_co_signer(signer),
            None => transfer,
        };
        match transfer.frame(self.client).await {
            Ok(unwitnessed) => {
                assert_eq!(
                    unwitnessed.frame.proof_inputs.check_shape().unwrap(),
                    self.shape
                );
                let size = spr_client::transaction_size(
                    &self.payer,
                    &[unwitnessed.instruction().unwrap()],
                    ComputeBudgetConfig::new(0),
                )
                .unwrap();
                Fit {
                    bytes: size.bytes,
                    addresses: Some(size.addresses),
                }
            }
            Err(RingError::TransferTooWide { bytes, .. }) => Fit {
                bytes,
                addresses: None,
            },
            Err(error) => panic!("{:?} {:?}: {error}", self.rail, self.shape),
        }
    }
}

/// One JSON line per keyed measurement when `RING_FIT_REPORT` names the file.
#[tokio::test]
async fn ring_fit_report_measures_every_keyed_shape_with_withdrawal_legs() {
    let Ok(path) = std::env::var("RING_FIT_REPORT") else {
        return;
    };
    let mut lines = Vec::new();
    for shape in spr_client::SPP_SUPPORTED_SHAPES {
        for rail in Measured::COLUMNS
            .into_iter()
            .filter(|rail| rail.keyed(shape))
        {
            for payer in [rail.sweep_payer(), Payer::Outsider] {
                for co_signer in [None, Some(MEASURED_CO_SIGNER)] {
                    for legs in [0usize, 1, 2, 3, 4, 6, 8, 12, 16, 20, 24, 28, 32] {
                        if legs > 0 && rail == Measured::Delegate {
                            break;
                        }
                        let served = custom_ring_interface::key_catalog::RingCircuit::transfer(
                            custom_ring_interface::key_catalog::TransferSpend {
                                rail: rail.ring_rail(),
                                inputs: shape.n_inputs(),
                                outputs: shape.n_outputs(),
                                spends_default_ring: rail.entry(),
                                legs,
                            },
                        );
                        if served.is_none() {
                            break;
                        }
                        let fit = Measure {
                            payer,
                            co_signer,
                            legs,
                            ..Measure::pinned(rail, shape)
                        }
                        .fit()
                        .await;
                        let addresses = fit
                            .addresses
                            .map_or_else(|| "null".to_owned(), |addresses| addresses.to_string());
                        lines.push(format!(
                            r#"{{"rail":"{rail:?}","payer":"{payer:?}","co_signer":{},"n_in":{},"n_out":{},"legs":{legs},"bytes":{},"addresses":{addresses}}}"#,
                            co_signer.is_some(),
                            shape.n_inputs(),
                            shape.n_outputs(),
                            fit.bytes
                        ));
                        if fit.bytes > solana_message::v1::MAX_TRANSACTION_SIZE {
                            break;
                        }
                    }
                }
            }
        }
    }
    std::fs::write(path, lines.join("\n") + "\n").unwrap();
}

/// The program cannot depend on the SDK's ciphertexts, the SDK pins the sizes.
#[tokio::test]
async fn every_transfer_shape_takes_its_pinned_transaction_size() {
    let mut measured = Vec::new();
    for shape in spr_client::SPP_SUPPORTED_SHAPES {
        let mut bytes = [None; Measured::COLUMNS.len()];
        for (rail, slot) in Measured::COLUMNS.into_iter().zip(&mut bytes) {
            if rail.keyed(shape) {
                *slot = Some(Measure::pinned(rail, shape).bytes().await);
            }
        }
        measured.push(SizePin {
            n_in: shape.n_inputs(),
            n_out: shape.n_outputs(),
            bytes,
        });
    }
    let table: String = measured
        .iter()
        .map(|SizePin { n_in, n_out, bytes }| {
            format!("    SizePin {{ n_in: {n_in}, n_out: {n_out}, bytes: {bytes:?} }},\n")
        })
        .collect();
    assert_eq!(measured, SIZE_PINS, "measured:\n{table}");
}

/// Each confidential input class is the widest shape both rails fit without a policy, relayed.
#[tokio::test]
async fn every_confidential_class_fits_the_signer_and_in_proof_rails_relayed() {
    for family in custom_ring_interface::key_catalog::CONFIDENTIAL_TRANSFER_SHAPES {
        let shape = spr_client::Shape::new(usize::from(family.inputs), usize::from(family.outputs));
        for rail in [Measured::Confidential, Measured::InProofOwner] {
            let bytes = Measure::relayed(rail, shape).bytes().await;
            assert!(
                bytes <= solana_message::v1::MAX_TRANSACTION_SIZE,
                "{rail:?} {shape:?} takes {bytes}"
            );
        }
    }
}

/// The class stops at 5 inputs and 32 inputs, a wider spend merges first.
#[test]
fn a_shape_past_a_confidential_class_is_unkeyed() {
    use crate::shape_keyed;
    use spr_client::Shape;
    for (widest, unkeyed) in [
        (Shape::IN32_OUT2, Shape::new(40, 2)),
        (Shape::IN5_OUT16, Shape::IN8_OUT16),
    ] {
        assert!(shape_keyed(RingRail::Confidential, widest));
        assert!(!shape_keyed(RingRail::Confidential, unkeyed));
    }
}

/// A framed recipient replaces the nullifier key's bytes only in an escrowed output.
#[tokio::test]
async fn sixteen_policy_outputs_fit_only_under_key_escrow() {
    for family in spr_client::SPP_SUPPORTED_SHAPES
        .into_iter()
        .filter(|shape| shape.n_outputs() == 16 && Measured::ConfidentialPolicy.keyed(*shape))
    {
        let plain = Measure::pinned(Measured::ConfidentialPolicy, family);
        let escrowed = Measure::pinned(Measured::ConfidentialEscrow, family);
        assert!(plain.bytes().await > solana_message::v1::MAX_TRANSACTION_SIZE);
        assert!(escrowed.bytes().await <= solana_message::v1::MAX_TRANSACTION_SIZE);
    }
}

#[tokio::test]
async fn the_widest_escrowed_sixteen_output_shape_with_a_co_signer_fits_only_when_the_owner_pays() {
    let fits = |measure: Measure| async move {
        measure.bytes().await <= solana_message::v1::MAX_TRANSACTION_SIZE
    };
    let policy = Measure {
        co_signer: Some(MEASURED_CO_SIGNER),
        ..Measure::pinned(Measured::ConfidentialEscrow, spr_client::Shape::IN5_OUT16)
    };
    assert!(fits(policy).await);
    assert!(
        !fits(Measure {
            payer: Payer::Outsider,
            ..policy
        })
        .await
    );
}

#[tokio::test]
async fn a_confidential_policy_shape_past_one_transaction_is_refused_before_proving() {
    use crate::tests::support::{keypair, payer, Registry};
    let sender = keypair(1);
    let shape = spr_client::Shape::IN5_OUT16;
    let recipients: Vec<ShieldedKeypair> = (0..shape.n_outputs() - 1)
        .map(|index| keypair(10 + index as u8))
        .collect();
    let owners: Vec<(&ShieldedKeypair, u64)> = core::iter::once(&sender)
        .chain(&recipients)
        .map(|owner| (owner, 1))
        .collect();
    let client = Chain::ring(RingSettings {
        has_policy: true,
        co_signer: Some(MEASURED_CO_SIGNER),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(Registry::new(&owners), &crate::tests::pipeline_rules())
    .client();
    let utxos = (0..shape.n_inputs() as u64)
        .map(|leaf| ring_utxo(&sender, Mint::SOL, 100, leaf))
        .collect();
    let mut transaction = paid_ring_transaction(utxos, payer());
    for recipient in &recipients {
        transaction
            .transfer_with_ring(
                &recipient.shielded_address().unwrap(),
                Mint::SOL,
                1,
                Some(ring().program_id()),
            )
            .unwrap();
    }
    let transfer = owner_transfer(&sender, transaction)
        .with_in_proof_owner(&sender.signing_key)
        .with_co_signer(MEASURED_CO_SIGNER.0);
    let refused = transfer.measure(&client).await;
    assert!(
        matches!(
            refused,
            Err(RingError::TransferTooWide { inputs, outputs, bytes, limit })
                if (inputs, outputs) == (shape.n_inputs(), shape.n_outputs()) && bytes > limit
        ),
        "{refused:?}"
    );
}

/// The transfers scope demands the co-signer on every move.
#[tokio::test]
async fn a_delegate_its_own_co_signer_is_refused_before_proving() {
    use crate::tests::support::{keypair, Registry};
    let member = keypair(1);
    let recipient = keypair(2);
    let delegate = Address::new_from_array([0x44; 32]);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        delegate: Some(delegate),
        co_signer: Some((delegate, custom_ring_interface::CoSignScope::TRANSFERS)),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    })
    .with_registry(
        Registry::new(&[(&member, 1), (&recipient, 1)]),
        &crate::tests::pipeline_rules(),
    )
    .client();
    let assets = AssetRegistry::default();
    let transfer = DelegateTransfer::new(DelegateTransferInput {
        ring: ring(),
        delegate,
        payer: delegate,
        source: member.shielded_address().unwrap(),
        source_nullifier_key: &member.nullifier_key,
        inputs: vec![ring_utxo(&member, Mint::SOL, 10, 0)],
        outputs: vec![DelegateOutput {
            recipient: recipient.shielded_address().unwrap(),
            asset: Mint::SOL.asset,
            amount: 3,
        }],
    })
    .with_assets(&assets)
    .with_shape(spr_client::Shape::IN2_OUT2)
    .unwrap();
    assert!(matches!(
        transfer.with_co_signer(delegate).assemble(&client).await,
        Err(RingError::Program(CustomRingError::CoSignerIsDelegate))
    ));
}

#[tokio::test]
async fn an_anonymous_deposit_leg_another_key_funds_is_refused_before_proving() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = history(sender);
    let stage = |funder: Address| {
        let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
        transaction.deposit_sol(5, funder).unwrap();
        owner_transfer(sender, transaction)
            .with_interface_transfer_accounts(vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient: funder },
            )])
            .with_anonymous_signer(&sender.signing_key, &state)
            .with_payment(payment(&paid, 4))
            .unwrap()
    };
    let chain = Chain::ring(anonymous());
    assert!(
        stage_anonymous(&stage(crate::tests::support::payer()), &chain)
            .await
            .is_ok()
    );
    assert!(matches!(
        stage_anonymous(&stage(Address::new_from_array([0x66; 32])), &chain).await,
        Err(RingError::Program(CustomRingError::InvalidAnonymousSigner))
    ));
}

#[test]
fn a_payment_total_past_a_u64_is_refused() {
    assert!(matches!(
        super::selection::payment_total([u64::MAX, 1]),
        Err(RingError::PaymentOverflow)
    ));
}

#[tokio::test]
async fn an_audit_only_withdrawal_is_exempt_within_its_threshold_and_co_signed_past_it() {
    use crate::tests::support::{keypair, Registry};
    use custom_ring_interface::CoSignScope;
    use spr_program::instruction::TransactSolTransferAccounts;
    use zolana_ring_policy::MintPolicy;
    let sender = keypair(1);
    let co_signer = Address::new_from_array([77; 32]);
    let settings = RingSettings {
        co_signer: Some((co_signer, CoSignScope::WITHDRAWALS)),
        ..RingSettings::new(RingMode::Confidential)
    };
    let recorded = Chain::ring(settings)
        .with_records(Registry::new(&[]).with_mint(
            Mint::SOL.asset,
            MintPolicy {
                withdrawal_threshold: 100,
                ..MintPolicy::EMPTY
            },
        ))
        .client();
    let withdrawing = |legs: &[u64], deposit: Option<u64>| {
        let mut transaction = ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 200, 0)]);
        let mut accounts: Vec<_> = legs
            .iter()
            .enumerate()
            .map(|(index, amount)| {
                let recipient = keypair(40 + index as u8)
                    .shielded_address()
                    .unwrap()
                    .solana_address()
                    .unwrap();
                transaction.withdraw_sol(*amount, recipient).unwrap();
                TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient })
            })
            .collect();
        if let Some(amount) = deposit {
            let funder = crate::tests::support::payer();
            transaction.deposit_sol(amount, funder).unwrap();
            accounts.push(TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient: funder },
            ));
        }
        owner_transfer(&sender, transaction).with_interface_transfer_accounts(accounts)
    };
    let exempt = withdrawing(&[40, 60], None)
        .frame(&recorded)
        .await
        .unwrap()
        .frame;
    assert!(exempt.parts.exempt);
    assert!(exempt.parts.own_revision.is_some());
    assert_eq!(exempt.accounts.co_signer, None);
    // The gross is the withdrawal total, a deposit of the same mint offsets nothing.
    let offset = withdrawing(&[60, 60], Some(100))
        .with_co_signer(co_signer)
        .frame(&recorded)
        .await
        .unwrap()
        .frame;
    assert!(!offset.parts.exempt);
    assert_eq!(offset.parts.own_revision, None);
    assert_eq!(offset.accounts.co_signer, Some(co_signer));
    let unrecorded = Chain::ring(settings)
        .with_records(Registry::new(&[]))
        .client();
    let missing = withdrawing(&[40], None)
        .with_co_signer(co_signer)
        .frame(&unrecorded)
        .await
        .unwrap()
        .frame;
    assert!(
        !missing.parts.exempt,
        "a mint without a record keeps the co-signer"
    );
}
