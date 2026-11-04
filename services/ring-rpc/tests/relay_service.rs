//! A wallet relays a sealed transfer, deposit or merge, Ring RPC proves, pays and sends it.

#[path = "common/relay.rs"]
mod relay_fixture;

use std::sync::Arc;

use async_trait::async_trait;
use jsonrpsee::RpcModule;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use spr_keypair::NullifierKey;
use spr_transaction::{utxo::SppProofInputUtxo, WalletUtxo};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareRelayRequest, ProofInputBytes,
    RelayEnrollInputs, RelayIntent, RelayMergeInputs, RelayOperation, RelayQuote, RelayRail,
    RelayStatus, RelayStep, SubmitRelayRequest, GET_RELAY_QUOTE, GET_RELAY_STATUS, PREPARE_RELAY,
    SUBMIT_RELAY,
};
use zolana_ring_rpc::{
    relay_module, Relay, RelayError, RelayParts, RingRpcError, ServedRings, Store,
};

use relay_fixture::{
    anonymous_rail, deposit_request, proof_inputs, signed_request, signers_verify, RecordingChain,
    RecordingProver, SLOT,
};

const RING: Address = Address::new_from_array([6; 32]);

struct OneRing(Address);

#[async_trait]
impl ServedRings for OneRing {
    async fn check(&self, ring: Address) -> Result<(), RingRpcError> {
        match ring == self.0 {
            true => Ok(()),
            false => Err(RelayError::RingNotServed.into()),
        }
    }

    async fn tracking_registry(&self, _ring: Address) -> Result<Address, RingRpcError> {
        Ok(TRACKING_REGISTRY)
    }
}

struct Fixture {
    module: RpcModule<Arc<Relay>>,
    prover: Arc<RecordingProver>,
    chain: Arc<RecordingChain>,
    fee_payer: Address,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_budget(0).await
    }

    async fn with_budget(budget: u64) -> Self {
        let prover = Arc::new(RecordingProver::default());
        let chain = Arc::new(RecordingChain::default());
        let fee_payer = Keypair::new_from_array([31; 32]);
        let fee_payer_address = fee_payer.pubkey();
        let relay = Relay::new(RelayParts {
            store: Store::open("sqlite::memory:", 1).await.expect("store"),
            prover: prover.clone(),
            fee_payer,
            chain: chain.clone(),
        })
        .with_rings(Arc::new(OneRing(RING)))
        .with_enrollment_budget(budget);
        Self {
            module: relay_module(Arc::new(relay)).expect("module"),
            prover,
            chain,
            fee_payer: fee_payer_address,
        }
    }

    async fn call<T: serde::de::DeserializeOwned + Clone>(
        &self,
        method: &str,
        request: impl serde::Serialize,
    ) -> T {
        let serde_json::Value::Object(params) = serde_json::to_value(request).expect("json") else {
            panic!("request is no object");
        };
        self.module.call(method, params).await.expect(method)
    }

    async fn quote(&self, operation: RelayOperation) -> RelayQuote {
        self.call(
            GET_RELAY_QUOTE,
            GetRelayQuoteRequest {
                ring: RING.into(),
                operation,
            },
        )
        .await
    }

    fn sent(&self) -> Vec<VersionedTransaction> {
        self.chain.sent()
    }
}

#[tokio::test]
async fn an_anonymous_transfer_relays_with_one_wallet_call() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let proof_inputs = proof_inputs(RING, anonymous_rail());
    let request = signed_request(quote, &proof_inputs);
    let RelayIntent::Anonymous {
        owner_signature, ..
    } = &request.intent
    else {
        unreachable!("anonymous intent");
    };
    let owner_signature = <[u8; 64]>::from(owner_signature.0);

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::Submitted { relay_id } = step else {
        panic!("an anonymous relay asks the wallet for nothing more, got {step:?}");
    };
    assert_eq!(
        *fixture.prover.requests.lock().expect("requests"),
        [(fixture.fee_payer, Some(owner_signature))]
    );
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(sent.message.static_account_keys()[0], fixture.fee_payer);
    assert_eq!(sent.signatures.len(), 1);
    assert!(signers_verify(&sent));
    let status: RelayStatus = fixture
        .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
        .await;
    assert_eq!(
        status,
        RelayStatus::Confirmed {
            signature: sent.signatures[0].into(),
            slot: SLOT + 1,
        }
    );
}

#[tokio::test]
async fn a_confidential_transfer_relays_with_one_wallet_call() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Confidential).await;
    let request = signed_request(quote, &proof_inputs(RING, RelayRail::Confidential));
    let RelayIntent::Confidential {
        owner_signature, ..
    } = &request.intent
    else {
        unreachable!("confidential intent");
    };
    let owner_signature = <[u8; 64]>::from(owner_signature.0);

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::Submitted { relay_id } = step else {
        panic!("the owner signs inside the proof, got {step:?}");
    };
    assert_eq!(
        *fixture.prover.requests.lock().expect("requests"),
        [(fixture.fee_payer, Some(owner_signature))]
    );
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(sent.signatures.len(), 1);
    assert_eq!(sent.message.static_account_keys()[0], fixture.fee_payer);
    assert!(signers_verify(&sent));
    let status: RelayStatus = fixture
        .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
        .await;
    assert_eq!(
        status,
        RelayStatus::Confirmed {
            signature: sent.signatures[0].into(),
            slot: SLOT + 1,
        }
    );
}

#[tokio::test]
async fn a_deposit_relays_through_the_depositors_signature() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Deposit).await;
    let depositor = Keypair::new_from_array([41; 32]);
    let request = deposit_request(quote, RING, depositor.pubkey(), 700);

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the depositor signs its funding, got {step:?}");
    };
    assert!(fixture.sent().is_empty());
    let _: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id: relay_id.clone(),
                signer: depositor.pubkey().into(),
                signature: depositor.sign_message(&message.0).into(),
            },
        )
        .await;
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(
        sent.message.static_account_keys()[..2],
        [fixture.fee_payer, depositor.pubkey()]
    );
    assert!(signers_verify(&sent));
    let status: RelayStatus = fixture
        .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
        .await;
    assert_eq!(
        status,
        RelayStatus::Confirmed {
            signature: sent.signatures[0].into(),
            slot: SLOT + 1,
        }
    );
}

const TRACKING_REGISTRY: Address = Address::new_from_array([0x71; 32]);

fn enrollment(owner: Address, data: Vec<u8>, quote: RelayQuote) -> PrepareRelayRequest {
    enrollment_under(TRACKING_REGISTRY, owner, data, quote)
}

fn enrollment_under(
    registry: Address,
    owner: Address,
    data: Vec<u8>,
    quote: RelayQuote,
) -> PrepareRelayRequest {
    let inputs = RelayEnrollInputs {
        ring_program_id: RING,
        owner,
        tracking_registry: registry,
        instruction_data: data,
    };
    PrepareRelayRequest {
        ring: RING.into(),
        quote,
        intent: RelayIntent::Enroll {
            proof_inputs: ProofInputBytes::new(zeroize::Zeroizing::new(
                inputs.encode().expect("encode"),
            )),
        },
        co_signers: Vec::new(),
    }
}

/// A wallet with no SOL enrolls, the relay pays and the owner's signature authorizes.
#[tokio::test]
async fn an_enrollment_relays_through_the_owners_signature() {
    let fixture = Fixture::with_budget(8).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let request = enrollment(owner.pubkey(), vec![6, 1, 2, 3], quote);

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs its enrollment, got {step:?}");
    };
    assert!(fixture.sent().is_empty());
    let _: RelayStatus = fixture
        .call(
            SUBMIT_RELAY,
            SubmitRelayRequest {
                relay_id: relay_id.clone(),
                signer: owner.pubkey().into(),
                signature: owner.sign_message(&message.0).into(),
            },
        )
        .await;
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(
        sent.message.static_account_keys()[..2],
        [fixture.fee_payer, owner.pubkey()]
    );
    assert!(signers_verify(&sent));
    let keys = sent.message.static_account_keys();
    let instruction = sent
        .message
        .instructions()
        .iter()
        .find(|instruction| {
            keys[usize::from(instruction.program_id_index)]
                == custom_ring_interface::STORAGE_PROGRAM_ID
        })
        .expect("the enrollment");
    assert_eq!(instruction.data, [6, 1, 2, 3]);
}

/// The operator's budget counts every funded enrollment, zero funds none.
#[tokio::test]
async fn enrollment_stays_off_until_the_operator_budgets_it_and_stops_at_the_budget() {
    let owner = Keypair::new_from_array([42; 32]).pubkey();
    let prepare = |fixture: Fixture, data: Vec<u8>| async move {
        let quote = fixture.quote(RelayOperation::Enroll).await;
        let serde_json::Value::Object(params) =
            serde_json::to_value(enrollment(owner, data, quote)).expect("json")
        else {
            panic!("request is no object");
        };
        let refused = fixture
            .module
            .call::<_, RelayStep>(PREPARE_RELAY, params)
            .await;
        (fixture, refused)
    };
    let budget_refusal = |refused: &Result<RelayStep, jsonrpsee::MethodsError>| {
        matches!(
            refused,
            Err(jsonrpsee::MethodsError::JsonRpc(error))
                if error.code() == RelayError::EnrollmentBudget.code()
        )
    };
    let (_, off) = prepare(Fixture::new().await, vec![6, 1]).await;
    assert!(budget_refusal(&off), "{off:?}");
    let (fixture, first) = prepare(Fixture::with_budget(1).await, vec![6, 1]).await;
    assert!(first.is_ok(), "{first:?}");
    let (_, second) = prepare(fixture, vec![6, 2]).await;
    assert!(budget_refusal(&second), "{second:?}");
}

#[tokio::test]
async fn the_relay_forwards_no_other_storage_instruction_and_never_enrolls_itself() {
    let fixture = Fixture::with_budget(8).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    for request in [
        enrollment(owner.pubkey(), vec![7, 1, 2, 3], quote.clone()),
        enrollment(owner.pubkey(), Vec::new(), quote.clone()),
        enrollment_under(
            Address::new_from_array([0x72; 32]),
            owner.pubkey(),
            vec![6, 1, 2, 3],
            quote.clone(),
        ),
        enrollment(fixture.fee_payer, vec![6, 1, 2, 3], quote),
    ] {
        let serde_json::Value::Object(params) = serde_json::to_value(&request).expect("json")
        else {
            panic!("request is no object");
        };
        let refused = fixture
            .module
            .call::<_, RelayStep>(PREPARE_RELAY, params)
            .await;
        assert!(
            matches!(
                &refused,
                Err(jsonrpsee::MethodsError::JsonRpc(error))
                    if error.code() == RelayError::InvalidEnrollment.code()
            ),
            "{refused:?}"
        );
    }
    assert!(fixture.sent().is_empty());
}

#[tokio::test]
async fn a_merge_relays_with_one_wallet_call() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Merge).await;
    let spends = proof_inputs(RING, RelayRail::Confidential);
    let note = |spend: &SppProofInputUtxo| WalletUtxo {
        utxo: spend.utxo.clone(),
        nullifier_pubkey: spend.nullifier_pubkey,
        utxo_hash: spend.utxo_hash,
        nullifier: spend.nullifier,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id: spend.tree_id,
        leaf_index: spend.leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    };
    let merge = RelayMergeInputs {
        ring_program_id: RING,
        sender: spends.sender,
        nullifier_key: NullifierKey::from_secret(*spends.nullifier_key.secret()),
        inputs: spends.inputs.iter().map(note).collect(),
    };
    let request = PrepareRelayRequest {
        ring: RING.into(),
        quote,
        intent: RelayIntent::Merge {
            proof_inputs: ProofInputBytes::new(merge.encode().expect("encode")),
        },
        co_signers: Vec::new(),
    };

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    let RelayStep::Submitted { relay_id } = step else {
        panic!("a merge needs no wallet signature, got {step:?}");
    };
    let [sent] = fixture.sent().try_into().expect("one sent transaction");
    assert_eq!(sent.signatures.len(), 1);
    assert!(signers_verify(&sent));
    let status: RelayStatus = fixture
        .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
        .await;
    assert_eq!(
        status,
        RelayStatus::Confirmed {
            signature: sent.signatures[0].into(),
            slot: SLOT + 1,
        }
    );
}

/// The relay writes and pays, the one message a co-signer signs carries the digest alone.
#[tokio::test]
async fn a_frame_past_one_transaction_relays_through_a_buffer_the_relay_writes() {
    use custom_ring_interface::{
        frame_digest, settle_buffered_data, tag as ring_tag, WriteFrameIxData,
    };
    let fixture = Fixture::new().await;
    let mut frame = vec![9; 6000];
    frame[0] = ring_tag::TRANSFER;
    *fixture.prover.frame.lock().expect("frame") = Some(frame.clone());
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = signed_request(quote, &proof_inputs(RING, anonymous_rail()));

    let step: RelayStep = fixture.call(PREPARE_RELAY, &request).await;

    assert!(matches!(step, RelayStep::Submitted { .. }), "{step:?}");
    let sent = fixture.sent();
    let (settle, writes) = sent.split_last().expect("a settlement");
    assert!(writes.len() >= 2);
    let mut rebuilt = vec![0; frame.len()];
    for write in writes {
        assert_eq!(write.message.static_account_keys()[0], fixture.fee_payer);
        assert!(
            write.message.instructions()[0].data.len() < solana_message::v1::MAX_TRANSACTION_SIZE
        );
        let data = &write.message.instructions()[0].data;
        assert_eq!(data[0], ring_tag::WRITE_FRAME);
        let parsed = WriteFrameIxData::parse(&data[1..]).unwrap();
        let start = usize::from(parsed.offset);
        rebuilt[start..start + parsed.bytes.len()].copy_from_slice(parsed.bytes);
    }
    assert_eq!(rebuilt, frame);
    assert_eq!(settle.message.static_account_keys()[0], fixture.fee_payer);
    assert_eq!(
        settle.message.instructions()[0].data,
        settle_buffered_data(&frame_digest(&frame).unwrap())
    );
}

/// Past the CPI limit no buffer can settle it, nothing is written and nothing is paid.
#[tokio::test]
async fn a_frame_past_the_cpi_limit_is_refused_before_any_write() {
    use custom_ring_interface::{tag as ring_tag, MAX_FRAME_LEN};
    let fixture = Fixture::new().await;
    let mut frame = vec![9; MAX_FRAME_LEN + 1];
    frame[0] = ring_tag::TRANSFER;
    *fixture.prover.frame.lock().expect("frame") = Some(frame);
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = signed_request(quote, &proof_inputs(RING, anonymous_rail()));
    let serde_json::Value::Object(params) = serde_json::to_value(request).expect("json") else {
        panic!("request is no object");
    };
    let refused = fixture
        .module
        .call::<_, RelayStep>(PREPARE_RELAY, params)
        .await;
    assert!(
        matches!(&refused, Err(jsonrpsee::MethodsError::JsonRpc(_))),
        "{refused:?}"
    );
    assert!(fixture.sent().is_empty());
}
