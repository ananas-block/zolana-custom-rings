//! A child of `pipeline`, every rail stages and assembles through its private items.

use std::collections::BTreeSet;

use custom_ring_interface::{
    stream::{tag_epoch, TagIndex, EPOCH_SLOTS},
    CustomRingError, RingMode, RingRail, RingTransactData, SOL_ASSET_ADDRESS,
};
use solana_address::Address;
use spl_token_2022_interface::pod::{PodAccount, PodCOption};
use zolana_client::ClientError;
use zolana_interface::{pda, SPL_TOKEN_ACCOUNT_INITIALIZED, SPL_TOKEN_PROGRAM_ID};
use zolana_keypair::ShieldedKeypair;
use zolana_program::instruction::{TransactSolTransferAccounts, TransactSplWithdrawalAccounts};
use zolana_ring_client::{AnonymousRingState, DecoyLeaf, SentFirstContact};
use zolana_ring_keys::{Pairing, RingAddress};
use zolana_ring_transaction::{RingDelivery, RingRailError, StreamPosition};
use zolana_transaction::{
    instructions::transact::ConfidentialTransaction, AssetRegistry, Mint, WalletUtxo,
};

use super::*;
use crate::client::RingClient;
use crate::tests::support::{account, empty, ring, ring_utxo, Chain, RingSettings, SLOT, TREE_ID};

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
    let mut state = AnonymousRingState::new(ring().program_id(), 0);
    state.issue(0, Pairing::default()).unwrap();
    state.address(owner, 0).unwrap().unwrap()
}

fn payment(to: &RingAddress, amount: u64) -> AnonymousPayment {
    AnonymousPayment {
        to: to.clone(),
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
        Spend::Owner | Spend::Delegate { .. } => unreachable!("an anonymous ring stages its rail"),
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
    let state = &AnonymousRingState::new(ring().program_id(), 0);
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
    let state = &AnonymousRingState::new(ring().program_id(), 0);
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

/// A default-ring note under a ring address key would tie the address to the exit.
#[tokio::test]
async fn an_exit_to_a_ring_address_key_is_refused() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let mut state = AnonymousRingState::new(ring().program_id(), 0);
    state.issue(0, Pairing::default()).unwrap();
    let own = state.address(sender, 0).unwrap().unwrap();
    for exit in [paid.recipient, own.recipient] {
        let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
        transaction
            .transfer_with_ring(&exit, Mint::SOL, 2, None)
            .unwrap();
        let transfer = owner_transfer(sender, transaction)
            .with_anonymous_signer(&sender.signing_key, &state)
            .with_payment(payment(&paid, 3))
            .unwrap();
        assert!(matches!(
            stage_anonymous(&transfer, &Chain::ring(anonymous())).await,
            Err(RingError::Rail(RingRailError::RingAddressExit {
                slot_index: 0
            }))
        ));
    }
}

#[test]
fn a_payment_to_another_rings_address_is_refused() {
    let sender = &crate::tests::support::keypair(1);
    let state = AnonymousRingState::new(ring().program_id(), 0);
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

#[tokio::test]
async fn an_inbox_payment_becomes_the_senders_first_contact_once_it_lands() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_tag_rng(zero_tag_rng)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let assembled = transfer
        .assemble(&Chain::ring(anonymous()).client())
        .await
        .unwrap();
    let [contact] = assembled.first_contacts.as_slice() else {
        panic!("one inbox payment, {:?}", assembled.first_contacts);
    };
    let outputs = &assembled.frame.proof_inputs.output_utxos;
    let slot_index = outputs
        .iter()
        .position(|output| output.hash(TREE_ID).unwrap() == contact.utxo_hash)
        .unwrap();
    let output = &outputs[slot_index];
    let first_nullifier = assembled.frame.proof_inputs.input_utxos[0].nullifier();
    assert_eq!(
        (contact.recipient, contact.index, contact.epoch),
        (
            paid.recipient.viewing_pubkey,
            TagIndex::new(0).unwrap(),
            tag_epoch(SLOT)
        )
    );
    assert_eq!(contact.blinding, output.blinding);
    assert_eq!(
        contact.slot_secret,
        *assembled
            .frame
            .rail
            .slot_secret(
                &paid.recipient.viewing_pubkey,
                &first_nullifier,
                u32::try_from(slot_index).unwrap(),
            )
            .unwrap()
            .as_bytes()
    );
    let sent = contact.confirm(11);
    assert_eq!((sent.leaf_index, sent.amount), (11, 4));
    assert!(sent.is_live(contact.epoch));
}

#[test]
fn a_pending_first_contact_prints_neither_its_slot_secret_nor_its_leaf() {
    let contact = PendingFirstContact {
        recipient: crate::tests::support::auditor().pubkey(),
        tree_id: TREE_ID,
        utxo_hash: [0xab; 32],
        slot_secret: [0xab; 32],
        blinding: [0xab; 32],
        epoch: 3,
        index: TagIndex::new(4).unwrap(),
        asset: Address::new_from_array(SOL_ASSET_ADDRESS),
        amount: 5,
    };
    let printed = format!("{contact:?}");
    assert!(crate::tests::support::redacts(
        &printed,
        &["recipient", "utxo_hash", "slot_secret", "blinding"]
    ));
    assert!(!printed.contains("171, 171"));
}

/// `state` keeping `leaves` of tree 0 as decoys, the shape a scan leaves behind.
fn with_decoys(state: &AnonymousRingState, leaves: &[DecoyLeaf]) -> AnonymousRingState {
    let mut json: serde_json::Value = serde_json::from_str(&state.to_json()).unwrap();
    json["decoys"] = serde_json::json!([{
        "treeId": TREE_ID,
        "leaves": leaves
            .iter()
            .map(|leaf| serde_json::json!({
                "leafIndex": leaf.leaf_index,
                "hash": hex::encode(leaf.hash),
            }))
            .collect::<Vec<_>>(),
    }]);
    AnonymousRingState::from_json(&json.to_string()).unwrap()
}

/// A sender's live first contact to `paid` beside more decoys than one anchor fetch takes.
struct Paired {
    contact: SentFirstContact,
    decoys: Vec<DecoyLeaf>,
    state: AnonymousRingState,
}

impl Paired {
    fn new(paid: &RingAddress) -> Self {
        let contact = SentFirstContact {
            recipient: paid.recipient.viewing_pubkey,
            tree_id: TREE_ID,
            leaf_index: 11,
            utxo_hash: [0x21; 32],
            slot_secret: [0x22; 32],
            blinding: [0x23; 32],
            epoch: tag_epoch(SLOT) - 1,
            index: TagIndex::new(3).unwrap(),
            asset: Address::new_from_array(SOL_ASSET_ADDRESS),
            amount: 4,
        };
        let mut state = AnonymousRingState::new(ring().program_id(), 0);
        state.record_first_contact(contact);
        let decoys: Vec<DecoyLeaf> = (1..=12u8)
            .map(|seed| DecoyLeaf {
                leaf_index: 20 + u64::from(seed),
                hash: [seed; 32],
            })
            .collect();
        let mut json: serde_json::Value =
            serde_json::from_str(&with_decoys(&state, &decoys).to_json()).unwrap();
        json["sent"][0]["decoys"] = decoys[..ANCHOR_DECOYS]
            .iter()
            .map(|leaf| hex::encode(leaf.hash))
            .collect();
        Self {
            state: AnonymousRingState::from_json(&json.to_string()).unwrap(),
            contact,
            decoys,
        }
    }

    /// The pinned decoys and the anchor.
    fn pinned(&self) -> BTreeSet<[u8; 32]> {
        self.decoys[..ANCHOR_DECOYS]
            .iter()
            .map(|leaf| leaf.hash)
            .chain([self.contact.utxo_hash])
            .collect()
    }

    fn chain(&self) -> Chain {
        self.decoys.iter().fold(
            Chain::ring(anonymous()).with_leaf(self.contact.utxo_hash, self.contact.leaf_index),
            |chain, decoy| chain.with_leaf(decoy.hash, decoy.leaf_index),
        )
    }
}

#[tokio::test]
async fn a_pair_payment_anchors_its_first_contact_among_seven_decoys() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let paired = Paired::new(&paid);
    let (contact, chain) = (paired.contact, paired.chain());
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &paired.state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let staged = stage_anonymous(&transfer, &chain).await.unwrap();
    let Spend::Anonymous(spend) = &staged.spend else {
        unreachable!("an anonymous ring stages its rail");
    };
    assert!(chain.proof_requests.lock().unwrap().is_empty());
    let anchor = spend.anchor(&chain).await.unwrap().unwrap();
    let requests = chain.proof_requests.lock().unwrap().clone();
    let [leaves] = requests.as_slice() else {
        panic!("one anchor fetch, {requests:?}");
    };
    let distinct: BTreeSet<_> = leaves.iter().collect();
    assert_eq!(
        (leaves.len(), distinct.len()),
        (ANCHOR_DECOYS + 1, ANCHOR_DECOYS + 1)
    );
    assert_eq!(
        distinct.into_iter().copied().collect::<BTreeSet<_>>(),
        paired.pinned()
    );
    assert_eq!(anchor.bound.tree, pda::tree(TREE_ID));
    assert!(anchor.bound.holds(&chain).await.unwrap());
    assert_eq!(
        (
            anchor.request.path_index,
            anchor.request.slot_secret,
            anchor.request.epoch
        ),
        (contact.leaf_index, contact.slot_secret, contact.epoch)
    );
    let RingDelivery::Anonymous(slots) = staged.rail.delivery() else {
        unreachable!("an anonymous ring delivers to streams");
    };
    assert!(matches!(
        slots.payment(0).map(|payment| payment.position),
        Some(StreamPosition::Pair(_))
    ));
    assert!(spend.first_contacts.is_empty());
}

#[tokio::test]
async fn an_anonymous_selection_reads_no_anchor_path() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let paired = Paired::new(&paid);
    let chain = paired.chain();
    let client = chain.clone().client();
    let utxos = [ring_utxo(&sender, Mint::SOL, 10, 0)];
    let owner = MoveSender {
        sender: &sender,
        state: &paired.state,
        payer: payer(),
    };
    let transfer = AnonymousMove {
        signer: &sender.signing_key,
        ..owner.anonymous_move(
            &utxos,
            vec![RingPayment {
                to: paid.clone(),
                amount: 4,
            }],
        )
    }
    .select(&client)
    .await
    .unwrap();
    assert!(chain.proof_requests.lock().unwrap().is_empty());
    transfer.assemble(&client).await.unwrap();
    assert_eq!(chain.proof_requests.lock().unwrap().len(), 1);
}

/// A grown pool keeps the pin, the next read names the same leaves.
#[tokio::test]
async fn every_anchor_read_of_a_contact_names_the_same_leaves() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let paired = Paired::new(&paid);
    let chain = paired.chain();
    let grown: Vec<DecoyLeaf> = (0x40..0x60u8)
        .map(|seed| DecoyLeaf {
            leaf_index: u64::from(seed),
            hash: [seed; 32],
        })
        .chain(paired.decoys.iter().copied())
        .collect();
    let later = with_decoys(&paired.state, &grown);
    for state in [&paired.state, &later] {
        let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
        owner_transfer(sender, transaction)
            .with_anonymous_signer(&sender.signing_key, state)
            .with_payment(payment(&paid, 4))
            .unwrap()
            .assemble(&chain.clone().client())
            .await
            .unwrap();
    }
    let requests = chain.proof_requests.lock().unwrap().clone();
    let [first, second] = requests.as_slice() else {
        panic!("two anchor fetches, {requests:?}");
    };
    assert_eq!(first, second);
    assert_eq!(
        first.iter().copied().collect::<BTreeSet<_>>(),
        paired.pinned()
    );
}

/// Answers every proof request with the error its function makes.
struct FailingIndexer(fn() -> ClientError);

#[async_trait::async_trait]
impl zolana_client::AsyncRpc for FailingIndexer {
    async fn get_merkle_proofs(
        &self,
        _tree_account: Address,
        _leaves: Vec<[u8; 32]>,
        _config: Option<zolana_client::IndexerRpcConfig>,
    ) -> Result<zolana_client::GetMerkleProofsResponse, ClientError> {
        Err((self.0)())
    }

    async fn get_shielded_transactions_by_ring(
        &self,
        _options: zolana_client::RingHistoryOptions,
        _config: Option<zolana_client::IndexerRpcConfig>,
    ) -> Result<zolana_client::GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(zolana_client::GetShieldedTransactionsByTagsResponse {
            context: zolana_client::Context {
                block_time: 0,
                slot: SLOT,
            },
            output_tree_id: None,
            transactions: Vec::new(),
            next_cursor: None,
            scanned_through: None,
        })
    }
}

#[tokio::test]
async fn a_refused_pinned_leaf_names_the_first_contact_to_retire() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let paired = Paired::new(&paid);
    let chain = paired.chain();
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &paired.state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let staged = stage_anonymous(&transfer, &chain).await.unwrap();
    let Spend::Anonymous(spend) = &staged.spend else {
        unreachable!("an anonymous ring stages its rail");
    };
    let refused = FailingIndexer(|| ClientError::Indexer("leaf not found".to_owned()));
    assert!(matches!(
        spend.anchor(&refused).await,
        Err(RingError::FirstContactLeavesRefused { tree, recipient })
            if tree == pda::tree(TREE_ID) && recipient == paired.contact.recipient
    ));
    let unavailable = FailingIndexer(|| ClientError::IndexerUnavailable("timeout".to_owned()));
    assert!(matches!(
        spend.anchor(&unavailable).await,
        Err(RingError::Client(ClientError::IndexerUnavailable(_)))
    ));
}

/// Answers proof reads with `proofs`, every other read with an empty page at `slot`.
#[derive(Debug)]
struct AnsweringIndexer {
    proofs: serde_json::Value,
    slot: u64,
}

impl zolana_api::HttpClient for AnsweringIndexer {
    fn send<'a>(&'a self, request: zolana_api::HttpRequest) -> zolana_api::HttpFuture<'a> {
        let answer = match request.url.ends_with("getMerkleProofs") {
            true => self.proofs.clone(),
            false => serde_json::json!({
                "result": {
                    "context": { "blockTime": 0, "slot": self.slot },
                    "transactions": [],
                    "nextCursor": null,
                },
            }),
        };
        let body = serde_json::to_vec(&answer).unwrap();
        Box::pin(async move {
            Ok(zolana_api::HttpResponse {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body,
            })
        })
    }
}

async fn anchor_read(proofs: serde_json::Value, slot: u64) -> Result<(), RingError> {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let paired = Paired::new(&paid);
    let chain = paired.chain();
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &paired.state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let staged = stage_anonymous(&transfer, &chain).await.unwrap();
    let Spend::Anonymous(spend) = &staged.spend else {
        unreachable!("an anonymous ring stages its rail");
    };
    let indexer = zolana_client::AsyncZolanaIndexer::with_api(zolana_api::ZolanaApi::with_client(
        "http://indexer.invalid",
        AnsweringIndexer { proofs, slot },
    ));
    let answer = spend.anchor(&indexer).await.map(drop);
    if let Err(RingError::FirstContactLeavesRefused { tree, recipient }) = &answer {
        assert_eq!(
            (*tree, *recipient),
            (pda::tree(TREE_ID), paired.contact.recipient)
        );
    }
    answer
}

#[tokio::test]
async fn an_indexer_at_the_staging_slot_without_every_pinned_proof_retires_the_contact() {
    let context = serde_json::json!({ "blockTime": 0, "slot": SLOT });
    for proofs in [
        serde_json::json!({ "result": { "context": context, "proofs": [] } }),
        serde_json::json!({ "result": { "context": context, "proofs": [{ "leaf": 7 }] } }),
        serde_json::json!({ "error": { "code": -32600, "message": "Record Not Found" } }),
    ] {
        assert!(matches!(
            anchor_read(proofs, SLOT).await,
            Err(RingError::FirstContactLeavesRefused { .. })
        ));
    }
    let internal = serde_json::json!({ "error": { "code": -32603, "message": "Internal error" } });
    assert!(matches!(
        anchor_read(internal, SLOT).await,
        Err(RingError::Client(ClientError::IndexerUnavailable(_)))
    ));
}

#[tokio::test(start_paused = true)]
async fn an_indexer_behind_the_staging_slot_keeps_the_first_contact() {
    let missing = serde_json::json!({ "error": { "code": -32600, "message": "Record Not Found" } });
    assert!(matches!(
        anchor_read(missing, SLOT - 1).await,
        Err(RingError::Client(ClientError::IndexerNotCaughtUp { .. }))
    ));
}

#[derive(Clone, Copy, Debug)]
enum ProofFault {
    Withheld,
    Path,
    Root,
    RootIndex,
    LeafIndex,
}

struct FaultyProofs {
    chain: Chain,
    leaf: [u8; 32],
    fault: ProofFault,
}

#[async_trait::async_trait]
impl zolana_client::AsyncRpc for FaultyProofs {
    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<zolana_client::IndexerRpcConfig>,
    ) -> Result<zolana_client::GetMerkleProofsResponse, ClientError> {
        let mut response =
            zolana_client::AsyncRpc::get_merkle_proofs(&self.chain, tree_account, leaves, config)
                .await?;
        let at = response
            .proofs
            .iter()
            .position(|proof| proof.leaf == self.leaf)
            .unwrap();
        match self.fault {
            ProofFault::Withheld => drop(response.proofs.remove(at)),
            ProofFault::Path => response.proofs[at].path[3][31] ^= 1,
            ProofFault::Root => {
                let proof = &mut response.proofs[at];
                proof.path[3][31] ^= 1;
                proof.root = anonymous::path_root(proof)?;
            }
            ProofFault::RootIndex => response.proofs[at].root_index ^= 1,
            ProofFault::LeafIndex => response.proofs[at].leaf_index ^= 1,
        }
        Ok(response)
    }
}

const PROOF_FAULTS: [ProofFault; 5] = [
    ProofFault::Withheld,
    ProofFault::Path,
    ProofFault::Root,
    ProofFault::RootIndex,
    ProofFault::LeafIndex,
];

#[tokio::test]
async fn a_fault_on_any_pinned_proof_refuses_the_read_as_one_on_the_anchor() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let paired = Paired::new(&paid);
    let chain = paired.chain();
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &paired.state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let staged = stage_anonymous(&transfer, &chain).await.unwrap();
    let Spend::Anonymous(spend) = &staged.spend else {
        unreachable!("an anonymous ring stages its rail");
    };
    let pair = paired
        .state
        .pair_anchor(&paired.contact.recipient, paired.contact.epoch)
        .unwrap();
    for leaf in pair.leaves {
        for fault in PROOF_FAULTS {
            let faulty = FaultyProofs {
                chain: paired.chain(),
                leaf,
                fault,
            };
            assert!(
                matches!(
                    spend.anchor(&faulty).await,
                    Err(RingError::FirstContactLeavesRefused { tree, recipient })
                        if tree == pda::tree(TREE_ID) && recipient == paired.contact.recipient
                ),
                "{fault:?} on {}",
                hex::encode(leaf)
            );
        }
    }
}

struct CatchingUpProofs {
    chain: Chain,
    refused: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl zolana_client::AsyncRpc for CatchingUpProofs {
    async fn get_account(
        &self,
        address: Address,
    ) -> Result<Option<solana_account::Account>, ClientError> {
        zolana_client::AsyncRpc::get_account(&self.chain, address).await
    }

    async fn get_merkle_proofs(
        &self,
        tree_account: Address,
        leaves: Vec<[u8; 32]>,
        config: Option<zolana_client::IndexerRpcConfig>,
    ) -> Result<zolana_client::GetMerkleProofsResponse, ClientError> {
        if !self
            .refused
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            return Err(ClientError::Indexer("Record Not Found".to_owned()));
        }
        zolana_client::AsyncRpc::get_merkle_proofs(&self.chain, tree_account, leaves, config).await
    }

    async fn get_shielded_transactions_by_ring(
        &self,
        _options: zolana_client::RingHistoryOptions,
        _config: Option<zolana_client::IndexerRpcConfig>,
    ) -> Result<zolana_client::GetShieldedTransactionsByTagsResponse, ClientError> {
        Ok(zolana_client::GetShieldedTransactionsByTagsResponse {
            context: zolana_client::Context {
                block_time: 0,
                slot: SLOT,
            },
            output_tree_id: None,
            transactions: Vec::new(),
            next_cursor: None,
            scanned_through: None,
        })
    }
}

#[tokio::test]
async fn an_indexer_that_catches_up_during_the_slot_check_keeps_the_first_contact() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let paired = Paired::new(&paid);
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &paired.state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let staged = stage_anonymous(&transfer, &paired.chain()).await.unwrap();
    let Spend::Anonymous(spend) = &staged.spend else {
        unreachable!("an anonymous ring stages its rail");
    };
    let late = CatchingUpProofs {
        chain: paired.chain(),
        refused: std::sync::atomic::AtomicBool::new(false),
    };
    assert!(spend.anchor(&late).await.unwrap().is_some());
}

/// The program reads the first-contact root from an unpaused tree, any other root fails the transfer.
#[tokio::test]
async fn a_first_contact_root_the_program_would_not_read_is_refused_before_proving() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let paired = Paired::new(&paid);
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &paired.state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let tree = pda::tree(TREE_ID);
    let unsettled = paired.chain().with_unsettled_leaf([9; 32], 3);
    assert!(matches!(
        transfer.assemble(&unsettled.client()).await,
        Err(RingError::FirstContactRootStale { tree: stale, root_index: 1 }) if stale == tree
    ));
    assert!(matches!(
        transfer
            .assemble(&paired.chain().with_paused_tree().client())
            .await,
        Err(RingError::Program(CustomRingError::FirstContactTreePaused))
    ));
}

#[tokio::test]
async fn a_leaf_keeps_an_earlier_pause_of_its_tree() {
    let tree = pda::tree(TREE_ID);
    let mut account = Chain::ring(anonymous())
        .with_paused_tree()
        .with_leaf([9; 32], 0)
        .get_account(tree)
        .await
        .unwrap()
        .unwrap();
    let mut view =
        zolana_tree::TreeAccount::from_bytes(&mut account.data, tree.to_bytes()).unwrap();
    assert!(view.is_paused());
    assert_eq!(view.utxo_tree().next_index(), 1);
}

/// SPP publishes the hidden owner's key beside a default-ring spend, the preview sizes it.
#[tokio::test]
async fn a_default_ring_spend_previews_the_hidden_owners_published_key() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let entry = crate::tests::support::wallet(
        zolana_transaction::Utxo {
            owner: sender.signing_pubkey(),
            asset: Mint::SOL,
            amount: 10,
            blinding: zolana_keypair::random_blinding(),
            ring_program_id: None,
            data: zolana_transaction::Data::default(),
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
    state: &'a AnonymousRingState,
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
            state: self.state,
            payer: self.payer,
            utxos,
            asset: Mint::SOL,
            payments,
            entry: EntrySpend::Allow,
        }
    }
}

fn default_ring_utxo(owner: &ShieldedKeypair, amount: u64, leaf: u64) -> WalletUtxo {
    crate::tests::support::wallet(
        zolana_transaction::Utxo {
            owner: owner.signing_pubkey(),
            asset: Mint::SOL,
            amount,
            blinding: zolana_keypair::random_blinding(),
            ring_program_id: None,
            data: zolana_transaction::Data::default(),
        },
        &owner.nullifier_key,
        TREE_ID,
        leaf,
    )
}

/// Ordinary padding publishes the shape's inputs, 32 at 2 outputs is the widest keyed spend.
#[tokio::test]
async fn an_anonymous_move_takes_the_widest_keyed_spend_and_refuses_past_it() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let client = Chain::ring(anonymous()).client();
    let utxos: Vec<WalletUtxo> = (0..36)
        .map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf))
        .collect();
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let pay = |amount| {
        owner.anonymous_move(
            &utxos,
            vec![RingPayment {
                to: paid.clone(),
                amount,
            }],
        )
    };
    let widest = pay(32).select(&client).await.unwrap();
    let assembled = widest.assemble(&client).await.unwrap();
    assert_eq!(
        assembled.frame.proof_inputs.check_shape().unwrap(),
        zolana_client::Shape::IN32_OUT2
    );
    assert!(matches!(
        pay(33).select(&client).await,
        Err(RingError::Unfunded {
            amount: 33,
            max_inputs: 32,
            ..
        })
    ));
}

/// One payment without change pads to 2 outputs, a policy ring fits 24 inputs there and not 32.
#[tokio::test]
async fn an_anonymous_move_past_the_transaction_size_is_refused_before_proving() {
    use crate::tests::support::{keypair, payer, Registry};
    let sender = keypair(1);
    let recipients = [keypair(10)];
    let owners: Vec<(&ShieldedKeypair, u64)> = core::iter::once(&sender)
        .chain(&recipients)
        .map(|owner| (owner, 1))
        .collect();
    let client = Chain::ring(RingSettings {
        has_policy: true,
        ..anonymous()
    })
    .with_registry(Registry::new(&owners), &crate::tests::pipeline_rules())
    .client();
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let utxos: Vec<WalletUtxo> = (0..32)
        .map(|leaf| ring_utxo(&sender, Mint::SOL, 1, leaf))
        .collect();
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let pay = |amount| {
        owner.anonymous_move(
            &utxos,
            recipients
                .iter()
                .map(|recipient| RingPayment {
                    to: ring_address(recipient),
                    amount,
                })
                .collect(),
        )
    };
    let fits = pay(24).select(&client).await.unwrap();
    assert_eq!(
        fits.assemble(&client)
            .await
            .unwrap()
            .frame
            .proof_inputs
            .check_shape()
            .unwrap(),
        zolana_client::Shape::IN24_OUT2
    );
    assert!(matches!(
        pay(25).select(&client).await,
        Err(RingError::TransactionTooLarge { bytes, limit }) if bytes > limit
    ));
}

/// An entry spend publishes the hidden owner's key, ring UTXOs fund the move first.
#[tokio::test]
async fn an_anonymous_move_spends_ring_utxos_before_an_entry() {
    use crate::tests::support::{keypair, payer};
    let sender = keypair(1);
    let paid = ring_address(&keypair(2));
    let state = AnonymousRingState::new(ring().program_id(), 0);
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
        let anonymous_move = owner.anonymous_move(
            &utxos,
            vec![RingPayment {
                to: paid.clone(),
                amount,
            }],
        );
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
        ..owner.anonymous_move(
            &utxos,
            vec![RingPayment {
                to: paid.clone(),
                amount: 30,
            }],
        )
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
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let mut utxos = vec![default_ring_utxo(&sender, 25, 10)];
    utxos.extend((0..4).map(|leaf| ring_utxo(&sender, Mint::SOL, 5, leaf)));
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: payer(),
    };
    let selection = owner
        .anonymous_move(
            &utxos,
            vec![RingPayment {
                to: paid.clone(),
                amount: 30,
            }],
        )
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
    let state = AnonymousRingState::new(ring().program_id(), 0);
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
    let state = AnonymousRingState::new(ring().program_id(), 0);
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
    let state = AnonymousRingState::new(ring().program_id(), 0);
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
        .anonymous_move(
            &utxos,
            vec![RingPayment {
                to: paid.clone(),
                amount: 4,
            }],
        )
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
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let utxos = [ring_utxo(&sender, Mint::SOL, 5, 0)];
    let owner = MoveSender {
        sender: &sender,
        state: &state,
        payer: HiddenOwner::of(&sender.signing_pubkey()).unwrap().0,
    };
    let selection = owner
        .anonymous_move(
            &utxos,
            vec![RingPayment {
                to: paid.clone(),
                amount: 5,
            }],
        )
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
    let state = AnonymousRingState::new(ring().program_id(), 0);
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
async fn an_anonymous_transfer_lands_in_its_epoch_or_the_next_one() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_payment(payment(&paid, 4))
        .unwrap();
    let assembled = transfer
        .assemble(&Chain::ring(anonymous()).client())
        .await
        .unwrap();
    let epoch = assembled.epoch.unwrap();
    let proven = ProvenRingTransfer {
        ring: assembled.frame.ring,
        config: assembled.config,
        bound: assembled.bound,
        tx_viewing_key: assembled.frame.rail.tx_viewing_key().clone(),
        parts: assembled.frame.parts,
        accounts: assembled.frame.accounts,
        outputs: Vec::new(),
        co_signer: None,
        epoch: assembled.epoch,
        first_contacts: Vec::new(),
    };
    let previous = |slot: u64| {
        let instruction = proven.instruction_at(slot).unwrap();
        RingTransactData::parse(&instruction.data[1..], RingRail::Anonymous)
            .unwrap()
            .data()
            .previous_epoch
    };
    assert!(!previous((epoch - 1) * EPOCH_SLOTS));
    assert!(!previous(epoch * EPOCH_SLOTS));
    assert!(previous((epoch + 1) * EPOCH_SLOTS));
    assert!(matches!(
        proven.instruction_at((epoch + 2) * EPOCH_SLOTS),
        Err(RingError::EpochPassed { proof_epoch, current_epoch })
            if proof_epoch == epoch && current_epoch == epoch + 2
    ));
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
    use zolana_client::Shape;
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
    let shaped = transfer().with_shape(Shape::IN4_OUT4).unwrap();
    let staged = shaped.rail.stage(ring(), &chain, &config).await.unwrap();
    assert_eq!(staged.proof_inputs.check_shape().unwrap(), Shape::IN4_OUT4);
}

struct MoveFixture<'a> {
    member: &'a ShieldedKeypair,
    recipient: zolana_keypair::ShieldedAddress,
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
        }
    }
}

/// The selected move's shape and the tree its inputs sit on.
async fn selected(
    transfer: DelegateTransfer<'_>,
    client: &RingClient<Chain, Chain>,
) -> (zolana_client::Shape, u16) {
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
        (zolana_client::Shape::IN4_OUT4, TREE_ID)
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
            (zolana_client::Shape::IN2_OUT2, 1)
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
        (zolana_client::Shape::IN4_OUT4, TREE_ID)
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
    key: zolana_keypair::NullifierKey,
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

/// Each output slot as the anonymous audit circuit reads it.
fn slot_kinds(request: &serde_json::Value) -> Vec<&'static str> {
    request["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|slot| {
            let opening = &slot["output"];
            let stream = &slot["stream"];
            match (
                nonzero(&opening["ownerPkHash"]),
                nonzero(&opening["ringProgramId"]),
            ) {
                (false, _) => "padding",
                (true, false) => "exit",
                (true, true) if stream["inbox"] == true => "inbox",
                (true, true) if stream["pair"] == true => "pair",
                (true, true) if stream["self"] == true => "change",
                (true, true) => "ring",
            }
        })
        .collect()
}

/// `UPDATE_PROVER_JSON=1` rewrites the pinned request.
#[tokio::test]
async fn the_anonymous_audit_request_of_an_exit_a_payment_and_change_keeps_its_pinned_layout() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let exit = crate::tests::support::keypair(3)
        .shielded_address()
        .unwrap();
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let mut transaction = ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]);
    transaction
        .transfer_with_ring(&exit, Mint::SOL, 3, None)
        .unwrap();
    let transfer = owner_transfer(sender, transaction)
        .with_anonymous_signer(&sender.signing_key, &state)
        .with_tag_rng(zero_tag_rng)
        .with_payment(payment(&paid, 4))
        .unwrap()
        .with_shape(zolana_client::Shape::IN1_OUT4)
        .unwrap();
    let assembled = transfer
        .assemble(&Chain::ring(anonymous()).client())
        .await
        .unwrap();
    let request = assembled.audit().unwrap().request().unwrap();
    let built = serde_json::to_value(
        crate::prover::RequestBody::new(request.circuit, &request.body).unwrap(),
    )
    .unwrap();
    assert_eq!(slot_kinds(&built), ["exit", "inbox", "change", "padding"]);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/custom-ring-audit-anonymous-exit.json");
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(request_layout(&built), request_layout(&pinned));
    assert_eq!(slot_kinds(&pinned), slot_kinds(&built));
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
        .limits(&[limit])
        .build();
    // The deposit scope leaves the approval as the transfer's only demand.
    let settings = RingSettings {
        has_policy: true,
        co_signer: Some((owner, custom_ring_interface::CoSignScope::DEPOSITS)),
        ..RingSettings::new(RingMode::ConfidentialEscrow)
    };
    let client = Chain::ring(settings)
        .with_registry(Registry::new(&[(&sender, 1), (&recipient, 1)]), &rules)
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
        owner_transfer(&sender, transaction).assemble(&client).await,
        Err(RingError::Program(CustomRingError::CoSignerIsOwner))
    ));
}

/// The hidden owner signs for every spent note, a note of another owner fails both proofs.
#[tokio::test]
async fn an_anonymous_transfer_of_another_owners_utxo_is_refused_before_proving() {
    let sender = &crate::tests::support::keypair(1);
    let other = &crate::tests::support::keypair(3);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = AnonymousRingState::new(ring().program_id(), 0);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Measured {
    Confidential,
    ConfidentialPolicy,
    Anonymous,
    AnonymousPolicy,
    Delegate,
}

impl Measured {
    const COLUMNS: [Self; 5] = [
        Self::Confidential,
        Self::ConfidentialPolicy,
        Self::Anonymous,
        Self::AnonymousPolicy,
        Self::Delegate,
    ];

    /// A delegate moves only on a policy ring.
    fn policy(self) -> bool {
        !matches!(self, Self::Confidential | Self::Anonymous)
    }

    fn keyed(self, shape: zolana_client::Shape) -> bool {
        let rail = match self {
            Self::Confidential | Self::ConfidentialPolicy => RingRail::Confidential,
            Self::Anonymous | Self::AnonymousPolicy => RingRail::Anonymous,
            Self::Delegate => RingRail::Delegate,
        };
        shape_keyed(rail, shape)
    }
}

#[derive(Clone, Copy)]
enum Payer {
    Outsider,
    Owner,
}

impl Payer {
    fn address(self, owner: &ShieldedKeypair) -> Address {
        match self {
            Self::Outsider => crate::tests::support::payer(),
            Self::Owner => owner.shielded_address().unwrap().solana_address().unwrap(),
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
    shape: zolana_client::Shape,
    payer: Payer,
    co_signer: Option<(Address, custom_ring_interface::CoSignScope)>,
}

impl Measure {
    fn pinned(rail: Measured, shape: zolana_client::Shape) -> Self {
        Self {
            rail,
            shape,
            payer: Payer::Outsider,
            co_signer: rail.policy().then_some(MEASURED_CO_SIGNER),
        }
    }

    async fn bytes(self) -> usize {
        use crate::tests::support::{keypair, Registry};
        let Self {
            rail,
            shape,
            payer,
            co_signer,
        } = self;
        let policy = rail.policy();
        let sender = keypair(1);
        let payer = payer.address(&sender);
        let recipients: Vec<ShieldedKeypair> = (0..shape.n_outputs() - 1)
            .map(|index| keypair(10 + index as u8))
            .collect();
        let utxos: Vec<WalletUtxo> = (0..shape.n_inputs() as u64)
            .map(|leaf| ring_utxo(&sender, Mint::SOL, 100, leaf))
            .collect();
        let delegate = Address::new_from_array([0x44; 32]);
        let mode = match rail {
            Measured::Anonymous | Measured::AnonymousPolicy => RingMode::Anonymous,
            Measured::ConfidentialPolicy | Measured::Delegate => RingMode::ConfidentialEscrow,
            Measured::Confidential => RingMode::Confidential,
        };
        let settings = RingSettings {
            has_policy: policy,
            co_signer,
            delegate: (rail == Measured::Delegate).then_some(delegate),
            ..RingSettings::new(mode)
        };
        let owners: Vec<(&ShieldedKeypair, u64)> = core::iter::once(&sender)
            .chain(&recipients)
            .map(|owner| (owner, 1))
            .collect();
        let chain = match policy {
            true => Chain::ring(settings)
                .with_registry(Registry::new(&owners), &crate::tests::pipeline_rules()),
            false => Chain::ring(settings),
        };
        let client = chain.client();
        let state = AnonymousRingState::new(ring().program_id(), 0);
        let assets = AssetRegistry::default();
        let size = FrameSize {
            client: &client,
            rail,
            shape,
            payer,
        };
        match rail {
            Measured::Confidential | Measured::ConfidentialPolicy => {
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
                size.of(&owner_transfer(&sender, transaction)).await
            }
            Measured::Anonymous | Measured::AnonymousPolicy => {
                let mut transfer = owner_transfer(&sender, paid_ring_transaction(utxos, payer))
                    .with_anonymous_signer(&sender.signing_key, &state);
                for recipient in &recipients {
                    transfer = transfer
                        .with_payment(payment(&ring_address(recipient), 1))
                        .unwrap();
                }
                size.of(&transfer).await
            }
            Measured::Delegate => {
                let transfer = DelegateTransfer::new(DelegateTransferInput {
                    ring: ring(),
                    delegate,
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
                size.of(&transfer).await
            }
        }
    }
}

#[derive(Clone, Copy)]
struct FrameSize<'c> {
    client: &'c RingClient<Chain, Chain>,
    rail: Measured,
    shape: zolana_client::Shape,
    payer: Address,
}

impl FrameSize<'_> {
    /// A refusal past the v1 ceiling carries the bytes of the framed transfer.
    async fn of<R: Rail>(self, transfer: &RingTransfer<R>) -> usize {
        match transfer.frame(self.client).await {
            Ok(unwitnessed) => {
                assert_eq!(
                    unwitnessed.frame.proof_inputs.check_shape().unwrap(),
                    self.shape
                );
                zolana_client::transaction_size(
                    &self.payer,
                    &[unwitnessed.instruction().unwrap()],
                    ComputeBudgetConfig::new(0),
                )
                .unwrap()
                .bytes
            }
            Err(RingError::TransactionTooLarge { bytes, .. }) => bytes,
            Err(error) => panic!("{:?} {:?}: {error}", self.rail, self.shape),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SizePin {
    n_in: usize,
    n_out: usize,
    /// One per [`Measured::COLUMNS`] entry, `None` for a shape the rail has no key for.
    bytes: [Option<usize>; Measured::COLUMNS.len()],
}

/// A policy ring demands its co-signer, a value past `MAX_TRANSACTION_SIZE` fails assembly.
const SIZE_PINS: [SizePin; 38] = [
    SizePin {
        n_in: 1,
        n_out: 2,
        bytes: [Some(1472), Some(1731), Some(1388), Some(1743), None],
    },
    SizePin {
        n_in: 1,
        n_out: 4,
        bytes: [Some(1954), Some(2149), Some(1756), Some(2111), None],
    },
    SizePin {
        n_in: 1,
        n_out: 8,
        bytes: [Some(2365), Some(2432), Some(2492), Some(2847), None],
    },
    SizePin {
        n_in: 2,
        n_out: 2,
        bytes: [Some(1537), Some(1796), Some(1485), Some(1840), Some(1796)],
    },
    SizePin {
        n_in: 2,
        n_out: 4,
        bytes: [Some(2019), Some(2214), Some(1853), Some(2208), None],
    },
    SizePin {
        n_in: 1,
        n_out: 16,
        bytes: [Some(3710), Some(3521), Some(3997), Some(4352), None],
    },
    SizePin {
        n_in: 2,
        n_out: 8,
        bytes: [Some(2430), Some(2497), Some(2589), Some(2944), None],
    },
    SizePin {
        n_in: 3,
        n_out: 2,
        bytes: [Some(1602), Some(1861), Some(1550), Some(1905), None],
    },
    SizePin {
        n_in: 3,
        n_out: 4,
        bytes: [Some(2084), Some(2279), Some(1918), Some(2273), None],
    },
    SizePin {
        n_in: 2,
        n_out: 16,
        bytes: [Some(3775), Some(3586), None, None, None],
    },
    SizePin {
        n_in: 3,
        n_out: 8,
        bytes: [Some(2495), Some(2562), Some(2654), Some(3009), None],
    },
    SizePin {
        n_in: 4,
        n_out: 2,
        bytes: [Some(1667), Some(1926), Some(1647), Some(2002), None],
    },
    SizePin {
        n_in: 4,
        n_out: 4,
        bytes: [Some(2149), Some(2344), Some(2015), Some(2370), Some(2344)],
    },
    SizePin {
        n_in: 4,
        n_out: 8,
        bytes: [Some(2560), Some(2627), Some(2751), Some(3106), None],
    },
    SizePin {
        n_in: 5,
        n_out: 2,
        bytes: [Some(1732), Some(1991), Some(1712), Some(2067), None],
    },
    SizePin {
        n_in: 5,
        n_out: 4,
        bytes: [Some(2214), Some(2409), Some(2080), Some(2435), None],
    },
    SizePin {
        n_in: 4,
        n_out: 16,
        bytes: [Some(3905), Some(3716), None, None, None],
    },
    SizePin {
        n_in: 5,
        n_out: 8,
        bytes: [Some(2625), Some(2692), Some(2816), Some(3171), None],
    },
    SizePin {
        n_in: 6,
        n_out: 2,
        bytes: [Some(1797), Some(2056), Some(1809), Some(2164), None],
    },
    SizePin {
        n_in: 6,
        n_out: 4,
        bytes: [Some(2279), Some(2474), Some(2177), Some(2532), None],
    },
    SizePin {
        n_in: 5,
        n_out: 16,
        bytes: [Some(3970), Some(3781), None, None, None],
    },
    SizePin {
        n_in: 6,
        n_out: 8,
        bytes: [Some(2690), Some(2757), Some(2913), Some(3268), None],
    },
    SizePin {
        n_in: 8,
        n_out: 2,
        bytes: [Some(1927), Some(2186), Some(1971), Some(2326), None],
    },
    SizePin {
        n_in: 8,
        n_out: 4,
        bytes: [Some(2409), Some(2604), Some(2339), Some(2694), None],
    },
    SizePin {
        n_in: 8,
        n_out: 8,
        bytes: [Some(2820), Some(2887), Some(3075), Some(3430), None],
    },
    SizePin {
        n_in: 8,
        n_out: 16,
        bytes: [Some(4165), Some(3976), None, None, None],
    },
    SizePin {
        n_in: 12,
        n_out: 2,
        bytes: [Some(2187), Some(2446), Some(2295), Some(2650), None],
    },
    SizePin {
        n_in: 12,
        n_out: 4,
        bytes: [Some(2669), Some(2864), Some(2663), Some(3018), None],
    },
    SizePin {
        n_in: 12,
        n_out: 8,
        bytes: [Some(3080), Some(3147), Some(3399), Some(3754), None],
    },
    SizePin {
        n_in: 16,
        n_out: 2,
        bytes: [Some(2447), Some(2706), Some(2619), Some(2974), None],
    },
    SizePin {
        n_in: 16,
        n_out: 4,
        bytes: [Some(2929), Some(3124), Some(2987), Some(3342), None],
    },
    SizePin {
        n_in: 16,
        n_out: 8,
        bytes: [Some(3340), Some(3407), Some(3723), Some(4078), None],
    },
    SizePin {
        n_in: 24,
        n_out: 2,
        bytes: [Some(2967), Some(3226), Some(3267), Some(3622), None],
    },
    SizePin {
        n_in: 24,
        n_out: 4,
        bytes: [Some(3449), Some(3644), Some(3635), Some(3990), None],
    },
    SizePin {
        n_in: 32,
        n_out: 2,
        bytes: [Some(3487), Some(3746), Some(3915), Some(4270), None],
    },
    SizePin {
        n_in: 40,
        n_out: 2,
        bytes: [Some(4007), Some(4266), None, None, None],
    },
    SizePin {
        n_in: 48,
        n_out: 2,
        bytes: [Some(4527), Some(4786), None, None, None],
    },
    SizePin {
        n_in: 49,
        n_out: 2,
        bytes: [None, None, None, None, None],
    },
];

/// The program cannot depend on the SDK's ciphertexts, the SDK pins the sizes.
#[tokio::test]
async fn every_transfer_shape_takes_its_pinned_transaction_size() {
    let mut measured = Vec::new();
    for shape in zolana_client::SPP_SUPPORTED_SHAPES {
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

#[tokio::test]
async fn a_confidential_ring_fits_its_widest_shapes_only_when_the_owner_pays() {
    let fits = |measure: Measure| async move {
        measure.bytes().await <= solana_message::v1::MAX_TRANSACTION_SIZE
    };
    let audit_only = Measure {
        rail: Measured::Confidential,
        shape: zolana_client::Shape::IN8_OUT16,
        payer: Payer::Owner,
        co_signer: None,
    };
    assert!(fits(audit_only).await);
    assert!(
        !fits(Measure {
            payer: Payer::Outsider,
            ..audit_only
        })
        .await
    );
    let policy = Measure {
        rail: Measured::ConfidentialPolicy,
        shape: zolana_client::Shape::IN40_OUT2,
        ..audit_only
    };
    assert!(fits(policy).await);
    assert!(
        !fits(Measure {
            payer: Payer::Outsider,
            ..policy
        })
        .await
    );
    assert!(
        !fits(Measure {
            co_signer: Some(MEASURED_CO_SIGNER),
            ..policy
        })
        .await
    );
}

/// Outsider rows on every inbox tag of the epoch hold no payment back, no allocation reads them.
#[tokio::test]
async fn a_payment_stages_when_outsider_rows_fill_the_inbox_tags() {
    use custom_ring_interface::stream::{InboxKey, J_INBOX};
    use zolana_transaction::instructions::transact::{
        OutputContext, OutputSlot, ShieldedTransaction,
    };
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let epoch = tag_epoch(SLOT);
    let inbox = InboxKey::derive(
        &ring().ring_id().unwrap(),
        paid.recipient.viewing_pubkey.as_bytes(),
    )
    .unwrap();
    let full = ShieldedTransaction {
        slot: SLOT,
        tx_signature: Default::default(),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: (0..J_INBOX)
            .map(|index| OutputSlot {
                view_tag: inbox
                    .tag(epoch, TagIndex::new(index).unwrap())
                    .unwrap()
                    .field(),
                output_context: OutputContext {
                    hash: [index + 1; 32],
                    tree_id: TREE_ID,
                    leaf_index: u64::from(index),
                },
                payload: Vec::new(),
            })
            .collect(),
        messages: Vec::new(),
        nullifiers: Vec::new(),
        proofless: false,
        ring_config: None,
        ring_program_id: Some(ring().program_id()),
    };
    let state = AnonymousRingState::new(ring().program_id(), 0);
    let transfer = owner_transfer(
        sender,
        ring_transaction(vec![ring_utxo(sender, Mint::SOL, 10, 0)]),
    )
    .with_anonymous_signer(&sender.signing_key, &state)
    .with_payment(payment(&paid, 4))
    .unwrap();
    let chain = Chain::ring(anonymous()).with_transaction(full);
    let Spend::Anonymous(spend) = stage_anonymous(&transfer, &chain).await.unwrap().spend else {
        panic!("an anonymous ring stages its rail");
    };
    let [contact] = spend.first_contacts.as_slice() else {
        panic!("one inbox payment, {:?}", spend.first_contacts);
    };
    assert_eq!(
        (contact.recipient, contact.epoch),
        (paid.recipient.viewing_pubkey, epoch)
    );
}

/// Draws zeros, each stream index is the lowest one the transaction left free.
struct ZeroRng;

impl rand_core::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
}

impl rand_core::CryptoRng for ZeroRng {}

fn zero_tag_rng() -> Box<dyn rand_core::CryptoRng + Send> {
    Box::new(ZeroRng)
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
    .with_shape(zolana_client::Shape::IN2_OUT2)
    .unwrap();
    assert!(matches!(
        transfer.assemble(&client).await,
        Err(RingError::Program(CustomRingError::CoSignerIsDelegate))
    ));
}

#[tokio::test]
async fn an_anonymous_deposit_leg_another_key_funds_is_refused_before_proving() {
    let sender = &crate::tests::support::keypair(1);
    let paid = ring_address(&crate::tests::support::keypair(2));
    let state = AnonymousRingState::new(ring().program_id(), 0);
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
