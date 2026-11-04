//! A child of `pipeline`, every rail stages and assembles through its private items.

use custom_ring_interface::{
    ring_recipient_output_body, ring_sender_bundle_output_body, CustomRingError, RecipientBody,
    RingMode, RingRail, RingTransactData, SenderBundle, RECIPIENT_BODY_LEN,
};
use solana_address::Address;
use spl_token_2022_interface::pod::{PodAccount, PodCOption};
use spr_client::ClientError;
use spr_hasher::primitives::is_canonical_bn254_scalar_be;
use spr_interface::{
    instruction::instruction_data::transact::OwnerTag, pda, SPL_TOKEN_ACCOUNT_INITIALIZED,
    SPL_TOKEN_PROGRAM_ID, ZERO_NULLIFIER_PUBKEY,
};
use spr_keypair::ShieldedKeypair;
use spr_program::instruction::{TransactSolTransferAccounts, TransactSplWithdrawalAccounts};
use spr_transaction::{
    instructions::transact::ConfidentialTransaction, AssetRegistry, Mint, WalletUtxo,
};
use zolana_ring_keys::RingAddress;
use zolana_ring_transaction::{open_recipient_body, open_sender_bundle, RingDelivery};

use super::*;
use crate::client::RingClient;
use crate::tests::support::{account, empty, ring, ring_utxo, Chain, RingSettings, TREE_ID};

fn anonymous() -> RingSettings {
    RingSettings::new(RingMode::Anonymous)
}

/// An audit-only anonymous ring whose records enroll every owner, delivery reads them on every rail.
fn enrolled(owners: &[&ShieldedKeypair]) -> Chain {
    let owners: Vec<(&ShieldedKeypair, u64)> = owners.iter().map(|owner| (*owner, 0)).collect();
    Chain::ring(anonymous()).with_records(crate::tests::support::Registry::new(&owners))
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
        list_salt: [7; 32],
    }
}

fn own_reply(sender: &ShieldedKeypair) -> zolana_ring_transaction::ReplyMetadata {
    let address = sender.shielded_address().unwrap();
    zolana_ring_transaction::ReplyMetadata {
        viewing_key: address.viewing_pubkey,
        owner_key: address.signing_pubkey.as_ed25519().unwrap(),
        nullifier_pk: address.nullifier_pubkey,
        data: spr_transaction::Data::default(),
    }
}

fn payment(to: &RingAddress, amount: u64) -> AnonymousPayment {
    AnonymousPayment {
        to: to.clone(),
        asset: Mint::SOL,
        amount,
        reply: None,
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
        Spend::Owner | Spend::InProofOwner(_) | Spend::PublicOwners | Spend::Delegate { .. } => {
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
            .with_anonymous_signer(&sender.signing_key);
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
    let hidden = Address::new_from_array(sender.signing_pubkey().as_ed25519().unwrap());
    let stage = |to: Address, named: Option<Address>, chain: Chain| {
        let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
        transaction.withdraw_sol(4, to).unwrap();
        let transfer = owner_transfer(sender, transaction)
            .with_interface_transfer_accounts(vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient: to },
            )])
            .with_anonymous_signer(&sender.signing_key);
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
    let foreign = RingAddress {
        ring_program_id: Address::new_from_array([43; 32]),
        ..ring_address(&crate::tests::support::keypair(2))
    };
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    assert!(matches!(
        owner_transfer(sender, transaction)
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(payment(&foreign, 3)),
        Err(RingError::ForeignRingAddress { address, ring: paid })
            if address == foreign.ring_program_id && paid == ring().program_id()
    ));
}

/// The published owner tag and recipient body of every slot, `None` on a change output.
fn published<'s>(staged: &'s Staged<'_>) -> Vec<([u8; 32], Option<&'s [u8; RECIPIENT_BODY_LEN]>)> {
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
                ring_recipient_output_body(data)
                    .expect("a scheme 11 recipient body")
                    .0
            });
            (tag, body)
        })
        .collect()
}

fn slot_secret(
    staged: &Staged<'_>,
    reader: &ShieldedKeypair,
    slot: usize,
) -> custom_ring_interface::stream::SlotSecret {
    let external = &staged.proof_inputs.external_data;
    let tx_viewing_pk = spr_keypair::X25519Pubkey::from_bytes(external.tx_viewing_pk).unwrap();
    custom_ring_interface::stream::DeliveredSlot {
        agreement: &reader.viewing_key.ecdh(&tx_viewing_pk).unwrap(),
        tx_viewing_pk: tx_viewing_pk.as_bytes(),
        recipient_viewing_pk: reader.viewing_pubkey().as_bytes(),
        salt: &external.salt,
        output_index: slot as u32,
        first_nullifier: &staged.proof_inputs.input_utxos[0].nullifier(),
    }
    .secret()
    .unwrap()
}

fn payment_at(staged: &Staged<'_>, reader: &ShieldedKeypair, position: usize) -> RecipientBody {
    let body = published(staged)[position].1.expect("a recipient body");
    open_recipient_body(body, &slot_secret(staged, reader, position)).unwrap()
}

/// The sender bundle, the first message, opened under the sender's own viewing key.
fn bundle(staged: &Staged<'_>, sender: &ShieldedKeypair) -> SenderBundle {
    let external = &staged.proof_inputs.external_data;
    let message = &external.messages[0];
    let body = ring_sender_bundle_output_body(&message.data).expect("a scheme 12 sender bundle");
    let published = external.outputs.len();
    open_sender_bundle(body, &slot_secret(staged, sender, published), published).unwrap()
}

/// Change leads with no body, SPL before SOL.
#[tokio::test]
async fn an_anonymous_transfer_publishes_each_payment_and_the_sender_bundle() {
    use crate::tests::support::keypair;
    let sender = &keypair(1);
    let bootstrap = keypair(2);
    let requester = keypair(3);
    let usdc = Mint::new(Address::new_from_array([0x31; 32]), 2);
    let transaction = ring_transaction(vec![
        ring_utxo(sender, usdc, 10, 0),
        ring_utxo(sender, Mint::SOL, 10, 1),
    ]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(AnonymousPayment {
            asset: usdc,
            ..payment(&ring_address(&bootstrap), 3)
        })
        .unwrap()
        .with_payment(AnonymousPayment {
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
    assert_eq!(slots[0].0, [0; 32], "change publishes zero");
    assert_eq!(slots[1].0, [0; 32], "change publishes zero");
    assert_ne!(slots[2].0, bootstrap.viewing_pubkey().u());
    assert_ne!(slots[3].0, requester.viewing_pubkey().u());
    assert_ne!(slots[2].0, slots[3].0);
    assert!(slots[..2].iter().all(|(_, body)| body.is_none()));
    assert!(slots[2..].iter().all(|(_, body)| body.is_some()));
    for (tag, _) in &slots[2..] {
        assert!(is_canonical_bn254_scalar_be(tag), "a tag is a field value");
    }
    let sent = bundle(&staged, sender);
    assert_eq!(
        (sent.mint, sent.amount, sent.sol_amount),
        (usdc.asset.to_bytes(), 7, 8)
    );
    assert_eq!(sent.recipient_keys.len(), outputs.len());
    assert_eq!(sent.recipient_keys[0], [0; 32], "a change cell reads zero");
    assert_eq!(sent.recipient_keys[2], bootstrap.viewing_pubkey().u());
    assert_eq!(sent.recipient_keys[3], requester.viewing_pubkey().u());
    let paid = payment_at(&staged, &bootstrap, 2);
    assert_eq!((paid.mint, paid.amount), (usdc.asset.to_bytes(), 3));
}

#[tokio::test]
async fn a_transfer_returning_nothing_leads_with_a_zero_sol_change() {
    use crate::tests::support::keypair;
    let sender = &keypair(1);
    let paid = ring_address(&keypair(2));
    let transfer = owner_transfer(
        sender,
        ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
    )
    .with_anonymous_signer(&sender.signing_key)
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
    assert_eq!(sent.amount, 0);
    assert_eq!(
        sent.recipient_keys
            .iter()
            .filter(|key| **key != [0; 32])
            .count(),
        1
    );
}

/// Two payments to one recipient share no tag, the slot secret binds each frame.
#[tokio::test]
async fn a_repeat_payment_to_one_recipient_publishes_a_fresh_tag() {
    use crate::tests::support::keypair;
    let sender = &keypair(1);
    let paid = ring_address(&keypair(2));
    let pay = || {
        owner_transfer(
            sender,
            ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
        )
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(payment(&paid, 4).with_reply(own_reply(sender)))
        .unwrap()
    };
    let (first, second) = (pay(), pay());
    let chain = Chain::ring(anonymous());
    let first = stage_anonymous(&first, &chain).await.unwrap();
    let second = stage_anonymous(&second, &chain).await.unwrap();
    assert_ne!(published(&first)[1].0, published(&second)[1].0);
}

/// SPP publishes the hidden owner's key beside a default-ring spend, the preview sizes it.
#[tokio::test]
async fn a_default_ring_spend_previews_the_hidden_owners_published_key() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
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
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let unwitnessed = transfer
        .frame(&enrolled(&[sender, &crate::tests::support::keypair(2)]).client())
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
    let client = enrolled(&[&sender, &keypair(2)]).client();
    let utxos: Vec<WalletUtxo> = (0..36)
        .map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf))
        .collect();
    let owner = MoveSender {
        sender: &sender,
        payer: payer(),
    };
    let pay = |amount| owner.anonymous_move(&utxos, vec![RingPayment::new(paid.clone(), amount)]);
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
    let enrolled_owners: Vec<&ShieldedKeypair> =
        core::iter::once(&sender).chain(&recipients).collect();
    let client = enrolled(&enrolled_owners).client();
    let utxos: Vec<WalletUtxo> = (0..8)
        .map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf))
        .collect();
    let owner = MoveSender {
        sender: &sender,
        payer: payer(),
    };
    let pay = |first: u64| {
        owner.anonymous_move(
            &utxos,
            recipients
                .iter()
                .zip(core::iter::once(first).chain(core::iter::repeat(1)))
                .map(|(recipient, amount)| RingPayment::new(ring_address(recipient), amount))
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
    let chain = enrolled(&[&sender, &keypair(2)]).client();
    let client = &chain;
    let mut utxos = vec![default_ring_utxo(&sender, 50, 10)];
    utxos.extend((0..4).map(|leaf| ring_utxo(&sender, Mint::SOL, 5, leaf)));
    let owner = MoveSender {
        sender: &sender,
        payer: payer(),
    };
    let spend = |amount| {
        let anonymous_move =
            owner.anonymous_move(&utxos, vec![RingPayment::new(paid.clone(), amount)]);
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
        ..owner.anonymous_move(&utxos, vec![RingPayment::new(paid.clone(), 30)])
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
    let mut utxos = vec![default_ring_utxo(&sender, 25, 10)];
    utxos.extend((0..4).map(|leaf| ring_utxo(&sender, Mint::SOL, 5, leaf)));
    let owner = MoveSender {
        sender: &sender,
        payer: payer(),
    };
    let selection = owner
        .anonymous_move(&utxos, vec![RingPayment::new(paid.clone(), 30)])
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
    let mut utxos = vec![default_ring_utxo(&sender, 5, 10)];
    utxos.extend((0..8).map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf)));
    let transaction = ring_transaction(utxos);
    let transfer = owner_transfer(&sender, transaction)
        .with_anonymous_signer(&sender.signing_key)
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
            .with_anonymous_signer(&sender.signing_key)
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
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(payment(&paid, 4))
        .unwrap();
    assert!(matches!(
        stage_anonymous(&transfer, &chain).await,
        Err(RingError::EntryInputData { index: 0 })
    ));
    let utxos = [entry];
    let owner = MoveSender {
        sender: &sender,
        payer: payer(),
    };
    let selection = owner
        .anonymous_move(&utxos, vec![RingPayment::new(paid.clone(), 4)])
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
    let utxos = [ring_utxo(&sender, Mint::SOL, 5, 0)];
    let owner = MoveSender {
        sender: &sender,
        payer: HiddenOwner::of(&sender.signing_pubkey()).unwrap().0,
    };
    let selection = owner
        .anonymous_move(&utxos, vec![RingPayment::new(paid.clone(), 5)])
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
        .with_anonymous_signer(&sender.signing_key)
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
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let build = || async {
        owner_transfer(sender, transaction.clone())
            .with_anonymous_signer(&sender.signing_key)
            .with_shape(spr_client::Shape::IN1_OUT4)
            .unwrap()
            .assemble(&enrolled(&[sender]).client())
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
    let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(&exit, Mint::SOL, 3, None)
        .unwrap();
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(payment(&paid, 4))
        .unwrap()
        .with_shape(spr_client::Shape::IN1_OUT4)
        .unwrap();
    let assembled = transfer
        .assemble(&enrolled(&[sender, &crate::tests::support::keypair(2)]).client())
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
            inputs: 24,
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
    assert_eq!(inputs.len(), 24);
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
    let transaction = ring_transaction(vec![
        ring_utxo(sender, Mint::SOL, 10, 0),
        ring_utxo(other, Mint::SOL, 10, 1),
    ]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let other_owner = other.shielded_address().unwrap().solana_address().unwrap();
    assert!(matches!(
        stage_anonymous(&transfer, &Chain::ring(anonymous())).await,
        Err(RingError::MissingCoOwnerKey { owner }) if owner == other_owner
    ));
    let co_owned = owner_transfer(
        sender,
        ring_transaction(vec![
            ring_utxo(sender, Mint::SOL, 10, 0),
            ring_utxo(other, Mint::SOL, 10, 1),
        ]),
    )
    .with_anonymous_signer(&sender.signing_key)
    .with_co_owner(CoOwner {
        owner: other_owner,
        nullifier_key: &other.nullifier_key,
    })
    .with_payment(payment(&paid, 4))
    .unwrap();
    let staged = stage_anonymous(&co_owned, &Chain::ring(anonymous()))
        .await
        .unwrap();
    assert_eq!(staged.owner_signers, [other_owner]);
}

/// A frame of only public owners belongs to the confidential family.
#[tokio::test]
async fn an_anonymous_frame_of_only_public_owners_is_refused() {
    use crate::tests::support::keypair;
    let (sender, other) = (keypair(1), keypair(2));
    let paid = ring_address(&keypair(3));
    let transaction = ring_transaction(vec![ring_utxo(&other, Mint::SOL, 10, 0)]);
    let transfer = owner_transfer(&sender, transaction)
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(payment(&paid, 4))
        .unwrap();
    assert!(matches!(
        stage_anonymous(&transfer, &Chain::ring(anonymous())).await,
        Err(RingError::HiddenOwnerMissing)
    ));
}

/// A sender with no enrolled address is refused before any proof.
#[tokio::test]
async fn an_unenrolled_anonymous_sender_or_recipient_is_refused() {
    use crate::tests::support::keypair;
    let (sender, recipient) = (keypair(1), keypair(2));
    let paid = ring_address(&recipient);
    let transfer = owner_transfer(
        &sender,
        ring_transaction(vec![ring_utxo(&sender, Mint::SOL, 10, 0)]),
    )
    .with_anonymous_signer(&sender.signing_key)
    .with_payment(payment(&paid, 4))
    .unwrap();
    assert!(matches!(
        transfer
            .frame(&enrolled(&[&recipient]).client())
            .await
            .err(),
        Some(RingError::SenderNotEnrolled)
    ));
    assert!(matches!(
        transfer.frame(&enrolled(&[&sender]).client()).await.err(),
        Some(RingError::RecipientNotEnrolled { slot_index: _ })
    ));
    assert!(transfer
        .frame(&enrolled(&[&sender, &recipient]).client())
        .await
        .is_ok());
}

/// The frame carries `m` and leaves each omitted slot off the wire.
#[tokio::test]
async fn compact_padding_publishes_the_prefix_under_the_keys_capacity() {
    use crate::tests::support::keypair;
    let (sender, recipient) = (keypair(1), keypair(2));
    let transaction = ConfidentialTransaction::new_compact_with_ring(
        vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
        crate::tests::support::payer(),
        ring().program_id(),
    )
    .unwrap();
    let transfer = owner_transfer(&sender, transaction)
        .with_anonymous_signer(&sender.signing_key)
        .with_payment(payment(&ring_address(&recipient), 4))
        .unwrap()
        .with_shape(spr_client::Shape::IN1_OUT4)
        .unwrap();
    let unwitnessed = transfer
        .frame(&enrolled(&[&sender, &recipient]).client())
        .await
        .unwrap();
    let instruction = unwitnessed.instruction().unwrap();
    let parsed = RingTransactData::parse(&instruction.data[1..], RingRail::Anonymous).unwrap();
    assert_eq!(parsed.data().outputs.len(), 2);
    assert_eq!(parsed.data().n_out, 4);
}

/// Every reply of a frame sits in the bound region, the default path attaches none.
#[tokio::test]
async fn a_reply_joins_the_frame_only_through_with_reply() {
    use crate::tests::support::keypair;
    let (sender, recipient) = (keypair(1), keypair(2));
    let frame_of = |reply: Option<zolana_ring_transaction::ReplyMetadata>| {
        let paid = ring_address(&recipient);
        let sender = &sender;
        let recipient = &recipient;
        async move {
            let paying = payment(&paid, 4);
            let transfer = owner_transfer(
                sender,
                ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
            )
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(match reply {
                Some(reply) => paying.with_reply(reply),
                None => paying,
            })
            .unwrap();
            let unwitnessed = transfer
                .frame(&enrolled(&[sender, recipient]).client())
                .await
                .unwrap();
            unwitnessed.instruction().unwrap().data
        }
    };
    let parse = |data: &[u8]| {
        RingTransactData::parse(&data[1..], RingRail::Anonymous)
            .unwrap()
            .data()
            .replies
            .map(|replies| replies.len)
    };
    assert_eq!(parse(&frame_of(None).await), None);
    let replied = frame_of(Some(own_reply(&sender))).await;
    assert_eq!(
        parse(&replied),
        Some(custom_ring_interface::MIN_REPLY_LEN as u16)
    );
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
    let two_owners = owner_transfer(&sender, transaction);
    let Ok(framed) = two_owners.frame(&client).await else {
        panic!("two owners stay within the screened owners");
    };
    assert_eq!(framed.frame.accounts.owner_signers.len(), 2);
    let many: Vec<ShieldedKeypair> = (0..5).map(|seed| keypair(20 + seed)).collect();
    let utxos = many
        .iter()
        .enumerate()
        .map(|(leaf, owner)| ring_utxo(owner, Mint::SOL, 1, leaf as u64))
        .collect();
    let too_many = owner_transfer(&many[0], ring_transaction(utxos));
    assert!(matches!(
        too_many.frame(&client).await.err(),
        Some(RingError::Program(CustomRingError::OwnerSignerCount))
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

/// `frame` runs before any witness read or prover call, the ceiling keeps no margin.
#[tokio::test]
async fn the_ceiling_frame_passes_and_a_longer_reply_is_refused_before_proving() {
    let entry = |reply_len| Measure {
        reply_len: Some(reply_len),
        ..Measure::pinned(Measured::AnonymousEntry, spr_client::Shape::new(1, 8))
    };
    let at_ceiling = entry(custom_ring_interface::MIN_REPLY_LEN).fit().await;
    assert_eq!(at_ceiling.bytes, solana_message::v1::MAX_TRANSACTION_SIZE);
    assert!(at_ceiling.addresses.is_some());
    let past = entry(custom_ring_interface::MIN_REPLY_LEN + 4).fit().await;
    assert!(past.bytes > solana_message::v1::MAX_TRANSACTION_SIZE);
    assert!(past.addresses.is_none(), "TransferTooWide");
    let paid = Measure {
        priority_fee: true,
        ..entry(custom_ring_interface::MIN_REPLY_LEN)
    }
    .fit()
    .await;
    assert_eq!(paid.bytes, solana_message::v1::MAX_TRANSACTION_SIZE + 8);
    assert!(
        paid.addresses.is_none(),
        "the fee moves the frame past the ceiling"
    );
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

const MEASURED_SPL: Mint = Mint {
    asset: Address::new_from_array([0x47; 32]),
    asset_id: 7,
};

const MEASURED_CURATOR: Address = Address::new_from_array([0x5c; 32]);

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
    /// Published slots below the shape's `N`, the rest compact padding.
    published: Option<usize>,
    /// Leading change outputs, zero to two.
    change_slots: usize,
    reply_len: Option<usize>,
    /// Public owners of the last inputs.
    co_owners: usize,
    /// A curator source beside the ring's own records.
    curator: bool,
    /// The legs settle in SPL under one mint.
    spl_legs: bool,
    priority_fee: bool,
    /// Notes below the shape's `n_in`, the rest compact padding.
    spent_inputs: Option<usize>,
    /// The last note spends from another input tree.
    second_tree: bool,
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
            published: None,
            change_slots: 1,
            reply_len: None,
            co_owners: 0,
            curator: false,
            spl_legs: false,
            priority_fee: false,
            spent_inputs: None,
            second_tree: false,
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
            published,
            change_slots,
            reply_len,
            co_owners,
            curator,
            spl_legs,
            priority_fee,
            spent_inputs,
            second_tree,
        } = self;
        let spent_notes = spent_inputs.unwrap_or(shape.n_inputs()) as u64;
        let policy = rail.policy();
        let sender = keypair(1);
        let payer = payer.address(&sender);
        let m = published.unwrap_or(shape.n_outputs());
        let recipients: Vec<ShieldedKeypair> = (0..m - change_slots)
            .map(|index| keypair(10 + index as u8))
            .collect();
        let co_owner_keys: Vec<ShieldedKeypair> = (0..co_owners)
            .map(|index| keypair(60 + index as u8))
            .collect();
        let mut utxos: Vec<WalletUtxo> = (0..spent_notes)
            .map(|leaf| {
                let from_end = spent_notes - leaf;
                if rail.entry() || from_end > co_owners as u64 {
                    return None;
                }
                Some(ring_utxo(
                    &co_owner_keys[(from_end - 1) as usize],
                    Mint::SOL,
                    100,
                    leaf,
                ))
            })
            .zip(0..spent_notes)
            .map(|(co_owned, leaf)| match co_owned {
                Some(utxo) => utxo,
                None if (change_slots == 2 || spl_legs) && leaf == 0 => {
                    ring_utxo(&sender, MEASURED_SPL, 100, leaf)
                }
                None if rail.entry() => crate::tests::support::wallet(
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
                None => ring_utxo(&sender, Mint::SOL, 100, leaf),
            })
            .collect();
        if second_tree {
            let last = utxos.last_mut().unwrap();
            *last = crate::tests::support::wallet(
                last.utxo.clone(),
                &sender.nullifier_key,
                TREE_ID + 1,
                last.leaf_index,
            );
        }
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
                    if spl_legs {
                        return measured_spl_leg(transaction, *recipient);
                    }
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
            .chain(&co_owner_keys)
            // The allow rule needs each destination enrolled.
            .chain(&leg_owners)
            .map(|owner| (owner, 1))
            .collect();
        let mut registry = Registry::new(&owners);
        if spl_legs {
            registry = registry.with_mint(MEASURED_SPL.asset, Default::default());
        }
        // Escrow and delivery name a registry the size of any other, never the system program's key.
        let chain = match policy {
            true => Chain::ring(settings).with_registry(registry, &crate::tests::pipeline_rules()),
            false => Chain::ring(settings).with_records(registry),
        };
        let chain = match curator {
            true => chain.with_curator(
                MEASURED_CURATOR,
                &zolana_ring_policy::RuleTable::builder()
                    .rule(zolana_ring_policy::Rule::require(
                        zolana_ring_policy::Subject::Sender,
                        zolana_ring_policy::ListId::Allow,
                    ))
                    .rule(zolana_ring_policy::Rule::require(
                        zolana_ring_policy::Subject::OutputOwner,
                        zolana_ring_policy::ListId::Allow,
                    ))
                    .rule(zolana_ring_policy::Rule::forbid(
                        zolana_ring_policy::Subject::OutputOwner,
                        zolana_ring_policy::ListId::Block,
                    ))
                    .build(),
            ),
            false => chain,
        };
        let chain = match second_tree {
            true => chain.with_tree(TREE_ID + 1),
            false => chain,
        };
        let chain = match spl_legs {
            true => destinations.iter().fold(chain, |chain, recipient| {
                chain.with(
                    pda::associated_token_address_with_program(
                        recipient,
                        &MEASURED_SPL.asset,
                        &Address::new_from_array(SPL_TOKEN_PROGRAM_ID),
                    ),
                    token_account(token_state(MEASURED_SPL.asset, *recipient)),
                )
            }),
            false => chain,
        };
        let client = chain.client();
        let assets = AssetRegistry::default();
        let size = FrameSize {
            client: &client,
            rail,
            shape,
            payer,
            co_signer: co_signer.map(|(signer, _)| signer),
            priority_fee,
        };
        let compact = published.is_some() || spent_inputs.is_some();
        let spent = |utxos: Vec<WalletUtxo>| match compact {
            true => {
                ConfidentialTransaction::new_compact_with_ring(utxos, payer, ring().program_id())
                    .unwrap()
            }
            false => paid_ring_transaction(utxos, payer),
        };
        // Nothing returns to the sender on a frame of no change slot.
        let paid_amount = |index: usize| match (change_slots, index) {
            (0, 0) => {
                let spent = spent_notes * 100;
                spent - (recipients.len() as u64 - 1) - legs as u64
            }
            _ => 1,
        };
        let confidential = |utxos: Vec<WalletUtxo>| {
            let mut transaction = spent(utxos);
            for (index, recipient) in recipients.iter().enumerate() {
                transaction
                    .transfer_with_ring(
                        &recipient.shielded_address().unwrap(),
                        Mint::SOL,
                        paid_amount(index),
                        Some(ring().program_id()),
                    )
                    .unwrap();
            }
            let accounts = with_legs(&mut transaction);
            let mut transfer =
                owner_transfer(&sender, transaction).with_interface_transfer_accounts(accounts);
            if compact {
                transfer = transfer.with_shape(shape).unwrap();
            }
            for owner in &co_owner_keys {
                transfer = transfer.with_co_owner(CoOwner {
                    owner: owner.shielded_address().unwrap().solana_address().unwrap(),
                    nullifier_key: &owner.nullifier_key,
                });
            }
            transfer
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
                let mut transaction = spent(utxos);
                let accounts = with_legs(&mut transaction);
                let mut transfer = owner_transfer(&sender, transaction)
                    .with_interface_transfer_accounts(accounts)
                    .with_anonymous_signer(&sender.signing_key);
                for owner in &co_owner_keys {
                    transfer = transfer.with_co_owner(CoOwner {
                        owner: owner.shielded_address().unwrap().solana_address().unwrap(),
                        nullifier_key: &owner.nullifier_key,
                    });
                }
                for (index, recipient) in recipients.iter().enumerate() {
                    let paying = payment(&ring_address(recipient), paid_amount(index));
                    transfer = transfer
                        .with_payment(match (index, reply_len) {
                            (0, Some(reply_len)) => {
                                paying.with_reply(measured_reply(&sender, reply_len))
                            }
                            _ => paying,
                        })
                        .unwrap();
                }
                size.of(transfer.with_shape(shape).unwrap()).await
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
    priority_fee: bool,
}

impl FrameSize<'_> {
    /// A refusal past the v1 ceiling carries the bytes of the framed transfer.
    async fn of<R: Rail>(self, transfer: RingTransfer<R>) -> Fit {
        let transfer = match self.co_signer {
            Some(signer) => transfer.with_co_signer(signer),
            None => transfer,
        };
        let transfer = match self.priority_fee {
            true => transfer.with_priority_fee(1),
            false => transfer,
        };
        match transfer.frame(self.client).await {
            Ok(unwitnessed) => {
                assert_eq!(
                    unwitnessed.frame.proof_inputs.check_shape().unwrap(),
                    self.shape
                );
                let budget = match self.priority_fee {
                    true => spr_client::ComputeBudgetConfig::new(0).with_priority_fee(1),
                    false => spr_client::ComputeBudgetConfig::new(0),
                };
                let size = spr_client::transaction_size(
                    &self.payer,
                    &[unwitnessed.instruction().unwrap()],
                    budget,
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

/// A memo pads the reply to `reply_len`, the head, the wincode and the record frame count.
fn measured_reply(
    sender: &ShieldedKeypair,
    reply_len: usize,
) -> zolana_ring_transaction::ReplyMetadata {
    let memo = reply_len.saturating_sub(custom_ring_interface::MIN_REPLY_LEN + 3);
    zolana_ring_transaction::ReplyMetadata {
        data: match memo {
            0 => spr_transaction::Data::default(),
            memo => {
                spr_transaction::Data::new(vec![spr_transaction::DataRecord::Memo(vec![0; memo])])
            }
        },
        ..own_reply(sender)
    }
}

/// An associated token account the policy read finds owned by `recipient`.
fn measured_spl_leg(
    transaction: &mut ConfidentialTransaction,
    recipient: Address,
) -> TransactInterfaceTransferAccounts {
    transaction
        .withdraw_to(
            MEASURED_SPL.asset,
            1,
            recipient,
            Some(Address::new_from_array(SPL_TOKEN_PROGRAM_ID)),
        )
        .unwrap()
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
                                owners: 0,
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
async fn every_confidential_class_fits_the_signer_and_in_proof_rails_owner_paid_or_relayed() {
    for family in custom_ring_interface::key_catalog::CONFIDENTIAL_TRANSFER_SHAPES {
        let shape = spr_client::Shape::new(usize::from(family.inputs), usize::from(family.outputs));
        for rail in [Measured::Confidential, Measured::InProofOwner] {
            // The in-proof rail stops one input short of the signer rail at 16 outputs.
            let shape = match (rail, shape.n_outputs()) {
                (Measured::InProofOwner, 16) => spr_client::Shape::new(4, 16),
                _ => shape,
            };
            let payer = match (rail, shape.n_outputs()) {
                (Measured::Confidential, 16) => Payer::Owner,
                _ => Payer::Outsider,
            };
            let bytes = Measure {
                payer,
                ..Measure::relayed(rail, shape)
            }
            .bytes()
            .await;
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
        (Shape::new(24, 2), Shape::IN32_OUT2),
        (Shape::IN5_OUT16, Shape::IN8_OUT16),
    ] {
        assert!(shape_keyed(RingRail::Confidential, widest));
        assert!(!shape_keyed(RingRail::Confidential, unkeyed));
    }
}

/// The limits the byte model names, each frame measured below and at its ceiling.
#[tokio::test]
async fn every_frame_limit_of_the_byte_model_holds() {
    use spr_client::Shape;
    let ceiling = solana_message::v1::MAX_TRANSACTION_SIZE;
    let pin = |measure: Measure| async move { measure.bytes().await };

    // Entry with a 97 byte reply at one input, the anonymous ceiling.
    let entry = Measure {
        reply_len: Some(custom_ring_interface::MIN_REPLY_LEN),
        ..Measure::pinned(Measured::AnonymousEntry, Shape::new(1, 8))
    };
    assert_eq!(pin(entry).await, 4096);

    // Plain policy at 24x4 with an outsider payer.
    let signer_policy = Measure {
        payer: Payer::Outsider,
        ..Measure::pinned(Measured::ConfidentialPolicy, Shape::new(24, 4))
    };
    let in_proof_policy = Measure {
        payer: Payer::Outsider,
        ..Measure::pinned(Measured::InProofOwnerPolicy, Shape::new(24, 4))
    };
    assert_eq!(pin(signer_policy).await, 4094);
    assert_eq!(pin(in_proof_policy).await, 4093);

    // 5x16 fits an owner payer and not an outsider.
    let owner_paid = Measure::pinned(Measured::Confidential, Shape::IN5_OUT16);
    assert_eq!(pin(owner_paid).await, 4003);
    assert_eq!(
        pin(Measure {
            payer: Payer::Outsider,
            ..owner_paid
        })
        .await,
        4099
    );

    // Plain policy past 8 outputs fits only through compact padding.
    let plain = |inputs, published| Measure {
        published: Some(published),
        ..Measure::pinned(Measured::ConfidentialPolicy, Shape::new(inputs, 16))
    };
    assert!(pin(plain(1, 15)).await <= ceiling);
    assert!(pin(plain(1, 16)).await > ceiling);
    let outsider = |inputs, published| Measure {
        payer: Payer::Outsider,
        ..plain(inputs, published)
    };
    assert!(pin(outsider(4, 13)).await <= ceiling);
    assert!(pin(outsider(4, 14)).await > ceiling);

    // The extras keep their slopes.
    let base = Measure::pinned(Measured::ConfidentialPolicy, Shape::new(2, 2));
    let base_bytes = pin(base).await;
    assert_eq!(
        pin(Measure {
            curator: true,
            ..base
        })
        .await,
        base_bytes + 41,
        "a curator registry"
    );
    assert_eq!(
        pin(Measure {
            priority_fee: true,
            ..base
        })
        .await,
        base_bytes + 8,
        "a priority fee"
    );
    let wider = Measure::pinned(Measured::ConfidentialPolicy, Shape::new(2, 8));
    let spl = pin(Measure {
        legs: 1,
        spl_legs: true,
        ..wider
    })
    .await;
    assert!(spl > pin(wider).await, "an SPL leg under a policy");
}

/// Each boundary the model prices, on the side a frame fits and the side it is refused.
#[tokio::test]
async fn every_frame_boundary_takes_its_modelled_bytes() {
    use spr_client::Shape;
    let relayed = Measure::relayed;
    let key_escrow_co_signed = Measure {
        co_signer: Some(MEASURED_CO_SIGNER),
        ..relayed(Measured::ConfidentialEscrow, Shape::new(24, 4))
    };
    let loaded_commitment = Measure {
        co_signer: Some(MEASURED_CO_SIGNER),
        legs: 4,
        ..relayed(Measured::Anonymous, Shape::new(24, 2))
    };
    let with_reply = |rail, inputs| Measure {
        reply_len: Some(custom_ring_interface::MIN_REPLY_LEN),
        ..relayed(rail, Shape::new(inputs, 8))
    };
    let compact_fifteen = Measure {
        spent_inputs: Some(15),
        ..relayed(Measured::ConfidentialPolicy, Shape::new(16, 8))
    };
    for (measure, bytes) in [
        (with_reply(Measured::AnonymousEntry, 2), 4265),
        (with_reply(Measured::Anonymous, 5), 4316),
        (
            relayed(Measured::ConfidentialPolicy, Shape::new(16, 8)),
            4118,
        ),
        (
            relayed(Measured::InProofOwnerPolicy, Shape::new(16, 8)),
            4117,
        ),
        (compact_fifteen, 4021),
        (relayed(Measured::InProofOwner, Shape::IN5_OUT16), 4098),
        (
            relayed(Measured::InProofOwnerEscrow, Shape::IN5_OUT16),
            4139,
        ),
        (
            Measure::pinned(Measured::ConfidentialEscrow, Shape::IN5_OUT16),
            4044,
        ),
        (
            relayed(Measured::ConfidentialEscrow, Shape::IN5_OUT16),
            4140,
        ),
        (relayed(Measured::InProofOwner, Shape::new(4, 16)), 4001),
        (key_escrow_co_signed, 4096),
        (loaded_commitment, 4084),
    ] {
        assert_eq!(
            measure.bytes().await,
            bytes,
            "{:?} {:?}",
            measure.rail,
            measure.shape
        );
    }
}

/// A co-signer and each SOL leg add the same bytes at any width.
#[tokio::test]
async fn co_signers_and_sol_legs_keep_their_slopes() {
    use spr_client::Shape;
    for rail in [
        Measured::Confidential,
        Measured::InProofOwnerPolicy,
        Measured::Anonymous,
        Measured::AnonymousEntry,
    ] {
        let base = Measure::pinned(rail, Shape::new(2, 2));
        let with_legs = |legs| Measure { legs, ..base };
        let later_leg = if rail.anonymous() { 11 } else { 43 };
        let plain = base.bytes().await;
        assert_eq!(
            Measure {
                co_signer: Some(MEASURED_CO_SIGNER),
                ..base
            }
            .bytes()
            .await,
            plain + 130,
            "{rail:?}"
        );
        assert_eq!(with_legs(1).bytes().await, plain + 75, "{rail:?}");
        assert_eq!(
            with_legs(4).bytes().await,
            plain + 75 + 3 * later_leg,
            "{rail:?}"
        );
    }
}

/// An SPL leg names more accounts than a SOL leg, and a policy adds its token owner.
#[tokio::test]
async fn spl_legs_take_their_accounts_and_the_policy_owner_field() {
    use spr_client::Shape;
    for (rail, first, later) in [
        (Measured::Confidential, 175, 47),
        (Measured::ConfidentialPolicy, 207, 79),
        (Measured::ConfidentialEscrow, 207, 79),
        (Measured::Anonymous, 175, 15),
        (Measured::AnonymousPolicy, 207, 47),
    ] {
        let at = |legs| Measure {
            legs,
            spl_legs: legs > 0,
            change_slots: 2,
            ..Measure::pinned(rail, Shape::new(2, 4))
        };
        let plain = at(0).bytes().await;
        assert_eq!(at(1).bytes().await, plain + first, "{rail:?}");
        assert_eq!(at(2).bytes().await, plain + first + later, "{rail:?}");
    }
}

/// A second input tree adds its account, its root indices and one bitmap bit per input.
#[tokio::test]
async fn a_second_input_tree_takes_its_account_context_and_bitmap() {
    use spr_client::Shape;
    for (measure, bytes) in [
        (
            Measure::pinned(Measured::Confidential, Shape::new(2, 2)),
            1359 + 38,
        ),
        (
            Measure::pinned(Measured::Anonymous, Shape::new(2, 2)),
            1712 + 38,
        ),
        (
            Measure::pinned(Measured::ConfidentialPolicy, Shape::new(16, 8)),
            4022 + 39,
        ),
        (
            Measure::relayed(Measured::ConfidentialPolicy, Shape::new(24, 4)),
            4094 + 40,
        ),
        (
            Measure::relayed(Measured::InProofOwnerPolicy, Shape::new(24, 4)),
            4093 + 40,
        ),
    ] {
        let second_tree = Measure {
            second_tree: true,
            ..measure
        };
        assert_eq!(
            second_tree.bytes().await,
            bytes,
            "{:?} {:?}",
            measure.rail,
            measure.shape
        );
    }
}

/// Compact padding removes a body and a slot per omitted output.
#[tokio::test]
async fn omitted_slots_save_their_bytes_on_each_family() {
    use spr_client::Shape;
    for (rail, saved) in [
        (Measured::Confidential, 168),
        (Measured::ConfidentialPolicy, 200),
        (Measured::Anonymous, 272),
    ] {
        let at = |published| Measure {
            published: Some(published),
            ..Measure::pinned(rail, Shape::IN1_OUT4)
        };
        assert_eq!(at(3).bytes().await - at(2).bytes().await, saved, "{rail:?}");
    }
}

/// A slot without a body costs its body and a change cell, a reply its length per body.
#[tokio::test]
async fn change_slots_and_replies_move_the_anonymous_frame_by_their_bytes() {
    use spr_client::Shape;
    let base = Measure::pinned(Measured::Anonymous, Shape::new(2, 4));
    let at = |change_slots| Measure {
        change_slots,
        ..base
    };
    assert_eq!(at(0).bytes().await - at(1).bytes().await, 72);
    assert_eq!(at(1).bytes().await - at(2).bytes().await, 72);
    let replied = Measure {
        reply_len: Some(custom_ring_interface::MIN_REPLY_LEN),
        ..base
    };
    assert_eq!(
        replied.bytes().await - base.bytes().await,
        2 + 3 * custom_ring_interface::MIN_REPLY_LEN,
        "the length and one reply per body"
    );
    let co_owned = Measure {
        co_owners: 1,
        ..base
    };
    assert_eq!(co_owned.bytes().await - base.bytes().await, 32 + 65);
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
        ..Measure::pinned(Measured::ConfidentialEscrow, spr_client::Shape::new(4, 16))
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
    let stage = |funder: Address| {
        let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
        transaction.deposit_sol(5, funder).unwrap();
        owner_transfer(sender, transaction)
            .with_interface_transfer_accounts(vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient: funder },
            )])
            .with_anonymous_signer(&sender.signing_key)
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

#[tokio::test]
async fn an_audit_only_deposit_refuses_only_mixed_owners_of_its_spent_asset() {
    use crate::tests::support::{keypair, payer};

    let sender = keypair(1);
    let other = keypair(2);
    let unrelated = Mint::new(Address::new_from_array([0x31; 32]), 2);
    let client = Chain::ring(RingSettings::new(RingMode::Confidential)).client();
    for (asset, second_owner, refused) in [
        (Mint::SOL, &other, true),
        (Mint::SOL, &sender, false),
        (unrelated, &other, false),
    ] {
        let mut transaction = ring_transaction(vec![
            ring_utxo(&sender, asset, 10, 0),
            ring_utxo(second_owner, asset, 10, 1),
        ]);
        transaction.deposit_sol(5, payer()).unwrap();
        let transfer = owner_transfer(&sender, transaction).with_interface_transfer_accounts(vec![
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                recipient: payer(),
            }),
        ]);
        let result = transfer.frame(&client).await;
        if refused {
            assert!(matches!(result, Err(RingError::MixedOwnerDeposit)));
        } else {
            result.unwrap();
        }
    }
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

fn zero_key(mut note: WalletUtxo) -> WalletUtxo {
    let key = NullifierKey::from_secret([0; 31]);
    note.nullifier_pubkey = ZERO_NULLIFIER_PUBKEY;
    note.utxo_hash = note
        .utxo
        .hash(&ZERO_NULLIFIER_PUBKEY, &[0; 32], &[0; 32], note.tree_id)
        .unwrap();
    note.nullifier = key.nullifier(&note.utxo_hash, &note.utxo.blinding).unwrap();
    note
}

#[tokio::test]
async fn automatic_selection_skips_a_zero_key_note_and_names_the_exposure() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let client = enrolled(&[&sender, &keypair(2)]).client();
    let utxos = vec![
        ring_utxo(&sender, Mint::SOL, 10, 0),
        zero_key(ring_utxo(&sender, Mint::SOL, 90, 1)),
    ];
    let owner = MoveSender {
        sender: &sender,
        payer: payer(),
    };
    let pay = |amount| owner.anonymous_move(&utxos, vec![RingPayment::new(paid.clone(), amount)]);
    let selected = pay(10).select(&client).await.unwrap();
    assert!(selected
        .rail
        .owner
        .transaction
        .inputs()
        .iter()
        .all(|input| input.nullifier_pubkey != ZERO_NULLIFIER_PUBKEY));
    assert!(matches!(
        pay(50).select(&client).await,
        Err(RingError::UnfundedPastExposure {
            amount: 50,
            exposed_if_spent: 90,
            ..
        })
    ));
    let merged =
        crate::select_merge_where(&utxos, Mint::SOL.asset, 8, &Default::default(), |_| true);
    assert!(matches!(
        merged,
        Err(spr_transaction::TransactionError::NothingToMerge { .. })
    ));
}

/// The hidden rail and the signer rail refuse the wallet's zero-key note unless it was named.
#[tokio::test]
async fn only_a_named_public_spend_takes_the_wallets_zero_key_note() {
    use crate::tests::support::keypair;
    let sender = keypair(1);
    let note = zero_key(ring_utxo(&sender, Mint::SOL, 10, 0));
    let chain = enrolled(&[&sender]);
    let hidden = owner_transfer(&sender, ring_transaction(vec![note.clone()]))
        .with_anonymous_signer(&sender.signing_key);
    assert!(matches!(
        stage_anonymous(&hidden, &chain).await,
        Err(RingError::ZeroKeyInputUnnamed { index: 0 })
    ));

    let config = ring().require_config(&chain).await.unwrap();
    let wallet = sender.shielded_address().unwrap().solana_address().unwrap();
    let public = owner_transfer(&sender, ring_transaction(vec![note.clone()])).spend_public(wallet);
    let staged = public.rail.stage(ring(), &config).await.unwrap();
    assert!(matches!(staged.spend, Spend::PublicOwners));
    assert_eq!(staged.owner_signers, [wallet]);

    let other = Address::new_from_array([9; 32]);
    let misnamed =
        owner_transfer(&sender, ring_transaction(vec![note.clone()])).spend_public(other);
    assert!(matches!(
        misnamed.rail.stage(ring(), &config).await,
        Err(RingError::PublicSpendWalletMismatch { named, .. }) if named == other
    ));

    let confidential = Chain::ring(RingSettings::new(RingMode::Confidential));
    let config = ring().require_config(&confidential).await.unwrap();
    let signer = owner_transfer(&sender, ring_transaction(vec![note.clone()]));
    assert!(matches!(
        signer.rail.stage(ring(), &confidential, &config).await,
        Err(RingError::ZeroKeyInputUnnamed { index: 0 })
    ));
    let named = owner_transfer(&sender, ring_transaction(vec![note])).spend_public(wallet);
    assert!(matches!(
        named.rail.stage(ring(), &config).await.unwrap().spend,
        Spend::Owner
    ));
}

/// A public co-owner may bring a zero-key note beside the hidden sender's own keyed note.
#[tokio::test]
async fn a_public_co_owners_zero_key_note_stands_beside_a_hidden_sender() {
    use crate::tests::support::keypair;
    let sender = keypair(1);
    let co_owner = keypair(3);
    let chain = enrolled(&[&sender, &co_owner]);
    let notes = vec![
        ring_utxo(&sender, Mint::SOL, 10, 0),
        zero_key(ring_utxo(&co_owner, Mint::SOL, 10, 1)),
    ];
    let owner = co_owner
        .shielded_address()
        .unwrap()
        .solana_address()
        .unwrap();
    let transfer = owner_transfer(&sender, ring_transaction(notes))
        .with_anonymous_signer(&sender.signing_key)
        .with_co_owner(CoOwner {
            owner,
            nullifier_key: &co_owner.nullifier_key,
        });
    let staged = stage_anonymous(&transfer, &chain).await.unwrap();
    assert_eq!(staged.owner_signers, [owner]);
}

/// The hidden owner's secret must not complete a zero-key input, its nullifier would mismatch.
#[test]
fn each_input_takes_the_secret_its_own_nullifier_names() {
    use crate::tests::support::keypair;
    use num_bigint::BigUint;
    let owner = keypair(1);
    let keyed = ring_utxo(&owner, Mint::SOL, 10, 0);
    let zero = zero_key(ring_utxo(&owner, Mint::SOL, 10, 1));
    let input_of = |note: &WalletUtxo| TransferInput {
        utxo: spr_transaction::utxo::ProofInputUtxo::try_from(
            &spr_transaction::utxo::SppProofInputUtxo::try_from(note.clone()).unwrap(),
        )
        .unwrap(),
        is_dummy: BigUint::default(),
        state_path_elements: Vec::new(),
        state_path_index: BigUint::default(),
        nullifier_low_value: BigUint::default(),
        nullifier_next_value: BigUint::default(),
        nullifier_low_path_elements: Vec::new(),
        nullifier_low_path_index: BigUint::default(),
        tree_slot: BigUint::default(),
        nullifier: BigUint::from_bytes_be(&note.nullifier),
        owner_pk_hash: BigUint::from_bytes_be(
            &owner.signing_pubkey().owner_proof_input_hash().unwrap(),
        ),
        nullifier_secret: None,
    };
    let mut inputs = [input_of(&keyed), input_of(&zero)];
    TransferAuthority {
        owner: Some(owner.nullifier_key.clone()),
        co_owners: Vec::new(),
    }
    .complete_inputs(&mut inputs)
    .unwrap();
    assert_eq!(
        inputs[0].nullifier_secret,
        Some(BigUint::from_bytes_be(&*owner.nullifier_key.secret()))
    );
    assert_eq!(inputs[1].nullifier_secret, Some(BigUint::default()));
}
