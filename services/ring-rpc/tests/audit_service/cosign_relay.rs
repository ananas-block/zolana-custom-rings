//! The relay co-signs within its asset's window caps and refuses an outflow beyond them, a proof naming another co-signer, or a ring whose auditor key it does not hold, and keeps a reservation while a stored relay holds it.

use jsonrpsee::RpcModule;
use sea_orm::{ConnectionTrait, Statement};
use solana_instruction::AccountMeta;
use spr_keypair::{ShieldedKeypair, SigningKey};
use zolana_ring_client::input_hash_evidence;
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, RelayId, RelayProofInputs,
    RelayQuote, RelayRail, RelayStatus, RelayStep, SubmitRelayRequest, GET_RELAY_QUOTE,
    GET_RELAY_STATUS, PREPARE_RELAY, SUBMIT_RELAY,
};
use zolana_ring_policy::{AssetLimits, MintPolicy};
use zolana_ring_rpc::{
    ChainOutcome, DelegateSeal, ProvenRelay, RelayError, RelayParties, RelayParts, RelayPayload,
    RelayProofRequest, RelayProver,
};

use super::transfer::{Frame as TransferFrame, Publish, Rail};

use super::relay_fixture::{
    anonymous_rail, deposit_request, owner, proof_inputs, signed_request, signers_verify,
    RecordingChain, RecordingProver, LAST_VALID_BLOCK_HEIGHT, SLOT,
};
use super::*;

const SENDER_CAP: u64 = 1_000;
const DEPOSIT_CAP: u64 = 1_000;

/// The frame a limited co-signer opens, one published note spent into the transfer's first output.
struct FramedProver {
    inner: RecordingProver,
    auditor: X25519Pubkey,
    note: [u8; 32],
}

/// The sender's note the ring opened, a limit reads it through the auditor store.
fn sender_fields(amount: u64) -> UtxoFields {
    let sender = owner().shielded_address().expect("sender");
    UtxoFields {
        owner_key: sender.signing_pubkey.as_ed25519().expect("ed25519"),
        nullifier_pk: sender.nullifier_pubkey,
        asset_address: SOL_MINT,
        amount,
        ..UtxoFields::default()
    }
}

impl FramedProver {
    /// `[co-signer run, SPP's transact list]`, `spp[1]` the output tree and the ring auth at 4.
    fn accounts(ring: Address, fee_payer: Address, named: &[Address]) -> Vec<AccountMeta> {
        named
            .iter()
            .map(|signer| AccountMeta::new_readonly(*signer, true))
            .chain([
                AccountMeta::new(fee_payer, true),
                AccountMeta::new(spr_interface::pda::tree(TREE_ID), false),
                AccountMeta::new_readonly(spr_interface::PROGRAM_ID_PUBKEY, false),
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new_readonly(spr_interface::pda::ring_auth(&ring).0, false),
                AccountMeta::new(spr_interface::pda::tree(TREE_ID), false),
                AccountMeta::new(Address::new_from_array([0x61; 32]), false),
            ])
            .collect()
    }

    /// The first output's owner and amount, the rest of the note returns to the sender.
    fn frame(&self, inputs: &RelayProofInputs) -> Vec<u8> {
        let paid_out = &inputs.outputs[0];
        let fields = UtxoFields {
            owner_key: paid_out
                .owner_address
                .expect("output owner")
                .signing_pubkey
                .as_ed25519()
                .expect("ed25519"),
            nullifier_pk: paid_out
                .owner_address
                .expect("output owner")
                .nullifier_pubkey,
            asset_address: SOL_MINT,
            amount: paid_out.amount,
            ..UtxoFields::default()
        };
        let payment = match paid_out.ring_program_id {
            Some(_) => paid(fields, x25519_u(0x50)),
            None => Output::Exit(fields),
        };
        let change = match SENDER_CAP.saturating_sub(paid_out.amount) {
            0 => Output::Dummy,
            amount => paid(sender_fields(amount), x25519_u(0x52)),
        };
        let outputs = [payment, change];
        let transfer = ring_transfer(inputs.blinding_seed[0]);
        let disclosure = transfer.signer_disclosure(
            &outputs,
            input_hash_evidence(&[Some(self.note)]).expect("evidence"),
        );
        let tx = transfer.publish(Publish {
            slots: transfer
                .slots(Rail::Delivered, &outputs)
                .into_iter()
                .map(|slot| slot.output)
                .collect(),
            disclosure: &disclosure,
            auditor: &self.auditor,
        });
        transfer.frame(TransferFrame {
            tx: &tx,
            disclosure: &disclosure,
        })
    }
}

#[async_trait::async_trait]
impl RelayProver for FramedProver {
    async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
        let (ring, fee_payer) = (request.ring, request.parties.fee_payer);
        let framed = match &request.payload {
            RelayPayload::Transfer(inputs) => Some(self.frame(inputs)),
            RelayPayload::Deposit(_) | RelayPayload::Merge(_) => None,
        };
        let mut proven = self.inner.prove(request).await?;
        if let Some(data) = framed {
            let named: Vec<Address> = proven.co_signer.into_iter().collect();
            proven.instruction.data = data;
            proven.instruction.accounts = Self::accounts(ring, fee_payer, &named);
        }
        Ok(proven)
    }

    async fn seal_delegate(
        &self,
        seal: DelegateSeal<'_>,
        parties: RelayParties,
    ) -> Result<RelayProofInputs, RingRpcError> {
        self.inner.seal_delegate(seal, parties).await
    }
}

struct CappedRelay {
    hub: Arc<Hub<StaticSource>>,
    module: RpcModule<Arc<Hub<StaticSource>>>,
    store: Store,
    chain: Arc<RecordingChain>,
    co_signer: Address,
    quote: RelayQuote,
    rail: fn() -> RelayRail,
}

impl CappedRelay {
    async fn new(rail: fn() -> RelayRail) -> Self {
        Self::naming(rail, None, sender_capped()).await
    }

    /// `named` replaces the hub's co-signer in the proof.
    async fn naming(rail: fn() -> RelayRail, named: Option<Address>, limits: AssetLimits) -> Self {
        let fixture = Fixture::new();
        // The note a capped transfer spends, the co-signer reads its owner from the store.
        let note_row = Indexed {
            transfer: &ring_transfer(0x40),
            outputs: &[paid(sender_fields(SENDER_CAP), x25519_u(0x54))],
            auditor: &fixture.auditor.pubkey(),
            signature: 0x40,
            frames: &fixture.frames,
        }
        .delivered();
        let note = note_row.output_slots[0].output_context.hash;
        let mut source = fixture.source().with_transactions(vec![note_row]);
        // The history ends at the note, the default cursor names its own page.
        source.next_cursor = None;
        source.records.write_mint_policy(
            Member::asset(&SOL_MINT).expect("asset member"),
            MintPolicy {
                limits,
                ..MintPolicy::EMPTY
            },
        );
        let co_signer = co_signer_key().pubkey();
        let chain = Arc::new(RecordingChain::default());
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let hub = Hub::builder(source, identity(GENESIS))
            .with_origins(origins())
            .with_store(store.clone())
            .with_co_signer(co_signer_key())
            .with_relay(RelayParts {
                store: store.clone(),
                prover: Arc::new(FramedProver {
                    inner: RecordingProver {
                        co_signer: Some(named.unwrap_or(co_signer)),
                        ..RecordingProver::default()
                    },
                    auditor: fixture.auditor.pubkey(),
                    note,
                }),
                fee_payer: Keypair::new_from_array([31; 32]),
                chain: chain.clone(),
            })
            .local(RING, fixture.auditor.clone())
            .expect("hub");
        hub.service(None)
            .expect("service")
            .backfill_utxos()
            .await
            .expect("the note opens");
        let hub = Arc::new(hub);
        let module = rpc_module(hub.clone()).expect("module");
        let quote = module
            .call(
                GET_RELAY_QUOTE,
                as_object(GetRelayQuoteRequest {
                    ring: RING.into(),
                    operation: rail().operation(),
                }),
            )
            .await
            .expect("quote");
        Self {
            hub,
            module,
            store,
            chain,
            co_signer,
            quote,
            rail,
        }
    }

    async fn fault(&self, fault: StoreFault) {
        self.store
            .connection()
            .execute_unprepared(&fault.trigger())
            .await
            .expect("store fault");
    }

    async fn heal(&self) {
        self.store
            .connection()
            .execute_unprepared(&format!("DROP TRIGGER {FAULT_TRIGGER}"))
            .await
            .expect("store healed");
    }

    /// The transfer of `seed` spends the whole SENDER_CAP.
    fn spending_cap(&self, seed: u8) -> PrepareRelayRequest {
        let mut inputs = proof_inputs(RING, (self.rail)());
        inputs.outputs[0].ring_program_id = None;
        inputs.outputs[0].amount = SENDER_CAP;
        inputs.blinding_seed = [seed; 32];
        signed_request(self.quote.clone(), &inputs)
    }

    /// `outflow` fits SENDER_CAP once and passes it twice.
    async fn assert_second_refused(&self, outflow: impl Fn(&mut RelayProofInputs)) {
        let prepare = |seed| {
            let mut inputs = proof_inputs(RING, (self.rail)());
            outflow(&mut inputs);
            inputs.blinding_seed = [seed; 32];
            self.module.call::<_, RelayStep>(
                PREPARE_RELAY,
                as_object(signed_request(self.quote.clone(), &inputs)),
            )
        };

        let within = prepare(1).await.expect("within the cap");
        let beyond = prepare(2).await;

        assert!(matches!(within, RelayStep::Submitted { .. }));
        let [sent] = self.chain.sent().try_into().expect("one sent transaction");
        assert_eq!(sent.message.static_account_keys()[1], self.co_signer);
        assert!(signers_verify(&sent));
        assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
    }

    async fn status(&self, relay_id: RelayId) -> RelayStatus {
        self.module
            .call(
                GET_RELAY_STATUS,
                as_object(GetRelayStatusRequest { relay_id }),
            )
            .await
            .expect("status")
    }

    /// A full cap fits only while no reservation holds the window.
    async fn second_cap_fits(&self) {
        let step = self
            .module
            .call::<_, RelayStep>(PREPARE_RELAY, as_object(self.spending_cap(2)))
            .await
            .expect("the freed window holds a full cap");
        assert!(matches!(step, RelayStep::Submitted { .. }), "{step:?}");
    }

    /// Prepares and signs, the caller submits.
    async fn deposit(&self, depositor: &Keypair, amount: u64) -> SubmitRelayRequest {
        let step: RelayStep = self
            .module
            .call(
                PREPARE_RELAY,
                as_object(deposit_request(
                    self.quote.clone(),
                    RING,
                    depositor.pubkey(),
                    amount,
                )),
            )
            .await
            .expect("prepared deposit");
        let RelayStep::SignMessage { relay_id, message } = step else {
            panic!("the depositor signs its funding, got {step:?}");
        };
        SubmitRelayRequest {
            relay_id,
            signer: depositor.pubkey().into(),
            signature: depositor.sign_message(&message.0).into(),
        }
    }
}

const FAULT_TRIGGER: &str = "relay_store_fault";

enum StoreFault {
    /// A NOT NULL refusal proves the update never committed.
    UpdateRefused,
    /// `RAISE(FAIL)` keeps the inserted row and still returns an error.
    InsertReplyLost,
    ReservationReleaseRefused,
}

impl StoreFault {
    fn trigger(self) -> String {
        let (event, raise) = match self {
            Self::UpdateRefused => (
                "BEFORE UPDATE ON relay_relays",
                "INSERT INTO relay_relays(status) VALUES(NULL)",
            ),
            Self::InsertReplyLost => (
                "AFTER INSERT ON relay_relays",
                "SELECT RAISE(FAIL, 'the insert reply was lost')",
            ),
            Self::ReservationReleaseRefused => (
                "BEFORE DELETE ON cosign_usage",
                "SELECT RAISE(ABORT, 'reservation release refused')",
            ),
        };
        format!("CREATE TRIGGER {FAULT_TRIGGER} {event} BEGIN {raise}; END")
    }
}

fn sender_capped() -> AssetLimits {
    AssetLimits {
        sender_cap: SENDER_CAP,
        sender_window_slots: 100,
        ..AssetLimits::EMPTY
    }
}

fn deposit_capped() -> AssetLimits {
    AssetLimits {
        deposit_cap: DEPOSIT_CAP,
        deposit_window_slots: 100,
        ..AssetLimits::EMPTY
    }
}

#[tokio::test]
async fn a_relayed_transfer_over_the_sender_window_cap_is_refused() {
    let recipient = ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[47; 32]))
        .expect("recipient")
        .shielded_address()
        .expect("recipient address");
    assert_ne!(recipient, owner().shielded_address().expect("sender"));
    CappedRelay::new(anonymous_rail)
        .await
        .assert_second_refused(|inputs| inputs.outputs[0].owner_address = Some(recipient))
        .await;
}

#[tokio::test]
async fn a_relayed_exit_to_the_sender_over_the_sender_window_cap_is_refused() {
    CappedRelay::new(|| RelayRail::Confidential)
        .await
        // An exit leaves the ring even to the sender, the sender cap counts it.
        .assert_second_refused(|inputs| inputs.outputs[0].ring_program_id = None)
        .await;
}

#[tokio::test]
async fn a_proof_naming_another_co_signer_is_refused_unsent() {
    let relay = CappedRelay::naming(
        anonymous_rail,
        Some(Address::new_from_array([0x99; 32])),
        sender_capped(),
    )
    .await;

    let refused = relay
        .module
        .call::<_, RelayStep>(
            PREPARE_RELAY,
            as_object(signed_request(
                relay.quote.clone(),
                &proof_inputs(RING, anonymous_rail()),
            )),
        )
        .await;

    assert_eq!(refusal(refused), RelayError::CoSignRefused.code());
    assert!(relay.chain.sent().is_empty());
}

#[tokio::test]
async fn a_transfer_that_landed_before_a_lost_send_reply_keeps_its_reservation() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    let landed = relay.spending_cap(1);
    let relay_id = landed.relay_id().expect("relay id");
    relay.chain.reply_lost.store(true, Ordering::Relaxed);
    let interrupted = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&landed))
        .await;
    assert!(interrupted.is_err());

    relay
        .chain
        .height
        .store(LAST_VALID_BLOCK_HEIGHT + 1, Ordering::Relaxed);
    let status: RelayStatus = relay
        .module
        .call(
            GET_RELAY_STATUS,
            as_object(GetRelayStatusRequest { relay_id }),
        )
        .await
        .expect("status");

    let [sent] = relay.chain.sent().try_into().expect("one sent transaction");
    assert_eq!(
        status,
        RelayStatus::Confirmed {
            signature: sent.signatures[0].into(),
            slot: SLOT + 1,
        }
    );
    // A freed reservation would let a second full cap through.
    let beyond = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(relay.spending_cap(2)))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
}

#[tokio::test]
async fn a_stored_relay_whose_insert_reply_was_lost_keeps_its_reservation() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    let landed = relay.spending_cap(1);
    let relay_id = landed.relay_id().expect("relay id");
    relay.fault(StoreFault::InsertReplyLost).await;
    let interrupted = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&landed))
        .await;
    assert!(interrupted.is_err());
    relay.heal().await;

    let tracker = tokio::spawn(
        relay
            .hub
            .relay()
            .expect("relay")
            .clone()
            .run(Duration::from_millis(1)),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while relay.chain.sent().is_empty() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the tracker resends the stored relay");
    tracker.abort();

    let status: RelayStatus = relay
        .module
        .call(
            GET_RELAY_STATUS,
            as_object(GetRelayStatusRequest { relay_id }),
        )
        .await
        .expect("status");
    assert!(
        matches!(status, RelayStatus::Confirmed { .. }),
        "{status:?}"
    );
    // A freed reservation would let a second full cap through.
    let beyond = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(relay.spending_cap(2)))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
}

#[tokio::test]
async fn a_refused_send_whose_final_write_failed_keeps_its_reservation_through_a_resend() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    let refused = relay.spending_cap(1);
    let relay_id = refused.relay_id().expect("relay id");
    relay.chain.refuse_next.store(true, Ordering::Relaxed);
    relay.fault(StoreFault::UpdateRefused).await;
    let interrupted = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&refused))
        .await;
    assert!(interrupted.is_err());
    relay.heal().await;

    // The record still reads `Sent`, the tracker resends it and the resend lands.
    let tracker = tokio::spawn(
        relay
            .hub
            .relay()
            .expect("relay")
            .clone()
            .run(Duration::from_millis(1)),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while relay.chain.sent().is_empty() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the tracker resends the stored relay");
    tracker.abort();
    let status: RelayStatus = relay
        .module
        .call(
            GET_RELAY_STATUS,
            as_object(GetRelayStatusRequest { relay_id }),
        )
        .await
        .expect("status");
    assert!(
        matches!(status, RelayStatus::Confirmed { .. }),
        "{status:?}"
    );
    // The landed debit still counts, a freed reservation would let a second full cap through.
    let beyond = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(relay.spending_cap(2)))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
}

#[tokio::test]
async fn a_refused_send_stores_failed_and_frees_its_reservation() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    relay.chain.refuse_next.store(true, Ordering::Relaxed);
    let refused = relay.spending_cap(1);
    let relay_id = refused.relay_id().expect("relay id");
    relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&refused))
        .await
        .expect("the relay records the refusal");
    let status = relay.status(relay_id).await;
    assert!(matches!(status, RelayStatus::Failed { .. }), "{status:?}");
    relay.second_cap_fits().await;
}

#[tokio::test]
async fn a_failed_reservation_release_is_retried_by_status() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    relay.chain.refuse_next.store(true, Ordering::Relaxed);
    let refused = relay.spending_cap(1);
    let relay_id = refused.relay_id().expect("relay id");
    relay.fault(StoreFault::ReservationReleaseRefused).await;
    let interrupted = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&refused))
        .await;
    assert!(interrupted.is_err());

    let connection = relay.store.connection();
    let stored = connection
        .query_one(Statement::from_string(
            connection.get_database_backend(),
            "SELECT status FROM relay_relays",
        ))
        .await
        .expect("relay query")
        .expect("stored relay");
    assert_eq!(
        stored.try_get::<String>("", "status").expect("status"),
        "failed"
    );
    assert!(relay.chain.sent().is_empty());
    let beyond = relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(relay.spending_cap(2)))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());

    relay.heal().await;
    let status = relay.status(relay_id.clone()).await;
    assert!(matches!(status, RelayStatus::Failed { .. }), "{status:?}");
    assert_eq!(relay.status(relay_id).await, status);
    relay.second_cap_fits().await;
}

#[tokio::test]
async fn an_on_chain_failure_reads_failed_and_frees_its_reservation() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    *relay.chain.outcome.lock().expect("outcome") = Some(Some(ChainOutcome::Failed {
        reason: "custom program error".to_owned(),
    }));
    let failed = relay.spending_cap(1);
    let relay_id = failed.relay_id().expect("relay id");
    relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&failed))
        .await
        .expect("sent");
    let status = relay.status(relay_id).await;
    assert_eq!(
        status,
        RelayStatus::Failed {
            reason: "custom program error".to_owned(),
        }
    );
    *relay.chain.outcome.lock().expect("outcome") = None;
    relay.second_cap_fits().await;
}

#[tokio::test]
async fn blockhash_expiry_reads_failed_and_frees_its_reservation() {
    let relay = CappedRelay::new(|| RelayRail::Confidential).await;
    *relay.chain.outcome.lock().expect("outcome") = Some(None);
    let unlanded = relay.spending_cap(1);
    let relay_id = unlanded.relay_id().expect("relay id");
    relay
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, as_object(&unlanded))
        .await
        .expect("sent");
    // A pending transaction under a live blockhash keeps its reservation.
    let pending = relay.status(relay_id.clone()).await;
    assert!(matches!(pending, RelayStatus::Sent { .. }), "{pending:?}");
    relay
        .chain
        .height
        .store(LAST_VALID_BLOCK_HEIGHT + 1, Ordering::Relaxed);
    let expired = relay.status(relay_id).await;
    assert!(matches!(expired, RelayStatus::Failed { .. }), "{expired:?}");

    relay.chain.height.store(400, Ordering::Relaxed);
    *relay.chain.outcome.lock().expect("outcome") = None;
    relay.second_cap_fits().await;
}

#[tokio::test]
async fn a_submit_whose_store_update_failed_frees_its_reservation() {
    let relay = CappedRelay::naming(anonymous_rail, None, deposit_capped()).await;
    let (first, second) = (
        Keypair::new_from_array([51; 32]),
        Keypair::new_from_array([52; 32]),
    );
    let first_signed = relay.deposit(&first, 700).await;
    let second_signed = relay.deposit(&second, 700).await;
    relay.fault(StoreFault::UpdateRefused).await;
    let refused = relay
        .module
        .call::<_, RelayStatus>(SUBMIT_RELAY, as_object(first_signed))
        .await;
    assert!(refused.is_err());
    relay.heal().await;

    let landed: RelayStatus = relay
        .module
        .call(SUBMIT_RELAY, as_object(second_signed))
        .await
        .expect("the unstored relay holds no allowance");

    assert!(
        matches!(landed, RelayStatus::Confirmed { .. }),
        "{landed:?}"
    );
}

#[tokio::test]
async fn an_unsigned_relay_holds_no_allowance_and_the_signed_one_past_the_cap_is_refused() {
    let relay = CappedRelay::naming(anonymous_rail, None, deposit_capped()).await;
    let (first, second) = (
        Keypair::new_from_array([51; 32]),
        Keypair::new_from_array([52; 32]),
    );

    let first_signed = relay.deposit(&first, 700).await;
    let second_signed = relay.deposit(&second, 700).await;

    assert!(relay.chain.sent().is_empty());
    let landed: RelayStatus = relay
        .module
        .call(SUBMIT_RELAY, as_object(first_signed))
        .await
        .expect("the first signed deposit fits the cap");
    assert!(
        matches!(landed, RelayStatus::Confirmed { .. }),
        "{landed:?}"
    );
    let beyond = relay
        .module
        .call::<_, RelayStatus>(SUBMIT_RELAY, as_object(second_signed))
        .await;
    assert_eq!(refusal(beyond), RelayError::CoSignRefused.code());
    let [sent] = relay.chain.sent().try_into().expect("one sent transaction");
    assert_eq!(sent.message.static_account_keys()[1], first.pubkey());
    assert!(signers_verify(&sent));
}

#[tokio::test]
async fn a_derived_relay_refuses_a_ring_whose_auditor_key_it_does_not_hold() {
    let fixture = Fixture::new();
    let prover = Arc::new(RecordingProver::default());
    let chain = Arc::new(RecordingChain::default());
    let store = Store::open("sqlite::memory:", 1).await.expect("store");
    let hub = Hub::builder(fixture.source(), identity(GENESIS))
        .with_origins(origins())
        .with_store(store.clone())
        .with_relay(RelayParts {
            store,
            prover: prover.clone(),
            fee_payer: Keypair::new_from_array([31; 32]),
            chain: chain.clone(),
        })
        .derived(RootSecret::from_bytes([7; 32]).expect("root"))
        .expect("hub");
    let module = rpc_module(Arc::new(hub)).expect("module");
    let quote_request = as_object(GetRelayQuoteRequest {
        ring: RING.into(),
        operation: anonymous_rail().operation(),
    });
    let quote = RelayQuote {
        fee_payer: Keypair::new_from_array([31; 32]).pubkey().into(),
        valid_until_slot: super::relay_fixture::SLOT,
    };

    let quoted = module
        .call::<_, RelayQuote>(GET_RELAY_QUOTE, quote_request)
        .await;
    let prepared = module
        .call::<_, RelayStep>(
            PREPARE_RELAY,
            as_object(signed_request(quote, &proof_inputs(RING, anonymous_rail()))),
        )
        .await;

    assert_eq!(refusal(quoted), RelayError::RingNotServed.code());
    assert_eq!(refusal(prepared), RelayError::RingNotServed.code());
    assert!(prover.requests.lock().expect("requests").is_empty());
    assert!(chain.sent().is_empty());
}
