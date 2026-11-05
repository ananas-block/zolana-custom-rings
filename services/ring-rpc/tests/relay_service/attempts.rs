//! One signed request, one row, every message of it charged until settlement or proven expiry.

use custom_ring_interface::tag::{CLOSE_FRAME_BUFFER, TRANSFER};
use jsonrpsee::types::ErrorCode;
use zolana_ring_rpc::ChainOutcome;

use super::*;

fn fresh(quote: &RelayQuote) -> RelayQuote {
    RelayQuote {
        valid_until_slot: quote.valid_until_slot - 1,
        ..quote.clone()
    }
}

fn paid_failure() -> Option<Option<ChainOutcome>> {
    Some(Some(ChainOutcome::Failed {
        reason: "the write failed".to_owned(),
    }))
}

fn past_window(fixture: &Fixture) {
    fixture
        .chain
        .slot
        .fetch_add(ABANDONED_AFTER_SLOTS + 1, Ordering::Relaxed);
}

fn past_blockhash(fixture: &Fixture) {
    fixture
        .chain
        .height
        .store(LAST_VALID_BLOCK_HEIGHT + 1, Ordering::Relaxed);
}

fn wide_request(fixture: &Fixture, quote: RelayQuote) -> PrepareRelayRequest {
    *fixture.prover.frame.lock().expect("frame") = Some(wide_frame(TRANSFER));
    signed_request(quote, &proof_inputs(RING, anonymous_rail()))
}

fn pending_answer(fixture: &Fixture, answer: Option<Option<ChainOutcome>>) {
    *fixture.chain.outcome.lock().expect("outcome") = answer;
}

/// Sends the first write, then loses its reply, the row reads a send that may be on the wire.
async fn crash_after_first_send(fixture: &Fixture, request: &PrepareRelayRequest) {
    fixture.chain.reply_lost.store(true, Ordering::Relaxed);
    pending_answer(fixture, Some(None));
    assert!(fixture.prepare(request).await.is_err());
    assert_eq!(fixture.sent().len(), 1);
}

#[tokio::test]
async fn a_fresh_quote_while_the_old_message_can_land_refuses_and_the_old_stays_charged() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let step = fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote.clone()))
        .await
        .expect("the first relay");
    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs its enrollment, got {step:?}");
    };

    let retried = fixture
        .prepare(&enrollment(&owner, vec![6, 1], fresh(&quote)))
        .await;

    assert!(
        refused_with(&retried, RelayError::LiveAttempt),
        "{retried:?}"
    );
    assert_eq!(fixture.outstanding().await, ENROLLMENT_LAMPORTS as i64);

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
    let status: RelayStatus = fixture
        .call(GET_RELAY_STATUS, GetRelayStatusRequest { relay_id })
        .await;
    assert!(
        matches!(status, RelayStatus::Confirmed { .. }),
        "{status:?}"
    );

    // The landed rent and fees stay in the total, no second message exists to expire and refund them.
    past_blockhash(&fixture);
    past_window(&fixture);
    fixture.relay.sweep_abandoned().await.expect("sweep");
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(fixture.committed().await, ENROLLMENT_LAMPORTS as i64);
}

#[tokio::test]
async fn a_fresh_quote_while_a_sent_message_can_land_refuses_and_sends_nothing() {
    let fixture = Fixture::new().await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let inputs = proof_inputs(RING, anonymous_rail());
    pending_answer(&fixture, Some(None));
    let step = fixture
        .prepare(&signed_request(quote.clone(), &inputs))
        .await
        .expect("the first relay");
    assert!(matches!(step, RelayStep::Submitted { .. }), "{step:?}");

    let retried = fixture
        .prepare(&signed_request(fresh(&quote), &inputs))
        .await;

    assert!(
        refused_with(&retried, RelayError::LiveAttempt),
        "{retried:?}"
    );
    assert_eq!(fixture.sent().len(), 1);
    assert_eq!(fixture.prover.requests.lock().expect("requests").len(), 1);
}

#[tokio::test]
async fn a_fresh_quote_past_proven_expiry_replaces_the_attempt_and_charges_once() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let first = fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote.clone()))
        .await
        .expect("the first relay");
    past_blockhash(&fixture);

    let second = fixture
        .prepare(&enrollment(&owner, vec![6, 1], fresh(&quote)))
        .await
        .expect("the old message can no longer land");

    let (
        RelayStep::SignMessage { relay_id: old, .. },
        RelayStep::SignMessage { relay_id: new, .. },
    ) = (first, second)
    else {
        panic!("the owner signs each message");
    };
    assert_ne!(old, new);
    assert_eq!(fixture.outstanding().await, ENROLLMENT_LAMPORTS as i64);
    assert_eq!(fixture.committed().await, ENROLLMENT_LAMPORTS as i64);
}

#[tokio::test]
async fn a_fresh_quote_resumes_an_upload_with_no_message_and_proves_nothing_again() {
    let fixture = Fixture::with_budget(FRAME_BUDGET).await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = wide_request(&fixture, quote.clone());
    fixture.chain.refuse_at.store(1, Ordering::Relaxed);
    assert!(fixture.prepare(&request).await.is_err());
    let charged = fixture.outstanding().await;

    let retried = signed_request(fresh(&quote), &proof_inputs(RING, anonymous_rail()));
    let step = fixture.prepare(&retried).await.expect("the resume");

    assert!(matches!(step, RelayStep::Submitted { .. }), "{step:?}");
    assert_eq!(fixture.prover.requests.lock().expect("requests").len(), 1);
    assert_eq!(fixture.outstanding().await, charged);
}

#[tokio::test]
async fn concurrent_duplicates_prove_once_and_send_no_write_twice() {
    let fixture = Fixture::with_budget(FRAME_BUDGET).await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = wide_request(&fixture, quote);

    let (first, second) = tokio::join!(fixture.prepare(&request), fixture.prepare(&request));

    assert!(first.is_ok() || second.is_ok(), "{first:?} {second:?}");
    assert_eq!(fixture.prover.requests.lock().expect("requests").len(), 1);
    let sent = fixture.sent();
    let unique: std::collections::BTreeSet<_> = sent
        .iter()
        .map(|transaction| transaction.message.instructions()[0].data.clone())
        .collect();
    assert_eq!(unique.len(), sent.len());
}

#[tokio::test]
async fn a_live_attempt_past_its_allowance_refuses_before_sending() {
    let fixture = Fixture::with_budget(FRAME_BUDGET).await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = wide_request(&fixture, quote);
    pending_answer(&fixture, paid_failure());

    let mut refusal = fixture.prepare(&request).await;
    let mut rounds = 0;
    while !refused_with(&refusal, RelayError::Allowance) {
        assert!(refusal.is_err(), "a failing write ends the call");
        rounds += 1;
        assert!(rounds < 64, "the allowance bounds the retries");
        refusal = fixture.prepare(&request).await;
    }

    let sent = fixture.sent().len();
    assert_eq!(sent, rounds);
    let again = fixture.prepare(&request).await;
    assert!(refused_with(&again, RelayError::Allowance), "{again:?}");
    assert_eq!(fixture.sent().len(), sent, "the refusal sends nothing");

    // The way out survives every failed write.
    pending_answer(&fixture, None);
    let keys = fixture.sent()[0].message.static_account_keys().to_vec();
    fixture
        .chain
        .accounts
        .lock()
        .expect("accounts")
        .extend(keys);
    past_window(&fixture);
    fixture.relay.sweep_abandoned().await.expect("sweep");
    assert_eq!(fixture.outstanding().await, 0);
    let close = fixture.sent().pop().expect("the close");
    assert_eq!(close.message.instructions()[0].data, [CLOSE_FRAME_BUFFER]);
    assert_eq!(fixture.committed().await, (sent as i64 + 1) * 5_000);
}

#[tokio::test]
async fn a_crash_with_a_pending_write_blocks_cleanup_and_the_retry_until_the_chain_answers() {
    let fixture = Fixture::with_budget(FRAME_BUDGET).await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = wide_request(&fixture, quote);
    crash_after_first_send(&fixture, &request).await;
    let charged = fixture.outstanding().await;

    let retried = fixture.prepare(&request).await;
    assert!(
        matches!(
            &retried,
            Err(jsonrpsee::MethodsError::JsonRpc(object))
                if object.code() == ErrorCode::ServerIsBusy.code()
        ),
        "the write can still land, got {retried:?}"
    );
    assert_eq!(fixture.sent().len(), 1);

    past_window(&fixture);
    fixture.relay.sweep_abandoned().await.expect("sweep");
    assert_eq!(
        fixture.outstanding().await,
        charged,
        "slot age proves nothing"
    );
    assert_eq!(fixture.sent().len(), 1);

    // The chain now proves the write never lands, the fee returns with the charge.
    past_blockhash(&fixture);
    past_window(&fixture);
    fixture.relay.sweep_abandoned().await.expect("sweep");
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(fixture.committed().await, 0);
}

#[tokio::test]
async fn a_pending_write_that_landed_advances_the_cursor_and_goes_out_once() {
    let fixture = Fixture::with_budget(FRAME_BUDGET).await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = wide_request(&fixture, quote);
    crash_after_first_send(&fixture, &request).await;
    pending_answer(&fixture, None);

    let step = fixture.prepare(&request).await.expect("the resume");

    assert!(matches!(step, RelayStep::Submitted { .. }), "{step:?}");
    assert_eq!(fixture.prover.requests.lock().expect("requests").len(), 1);
    let sent = fixture.sent();
    let unique: std::collections::BTreeSet<_> = sent
        .iter()
        .map(|transaction| transaction.message.instructions()[0].data.clone())
        .collect();
    assert_eq!(unique.len(), sent.len());
}

#[tokio::test]
async fn a_late_landing_write_is_closed_for_and_its_fee_stays() {
    let fixture = Fixture::with_budget(FRAME_BUDGET).await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = wide_request(&fixture, quote);
    crash_after_first_send(&fixture, &request).await;
    pending_answer(&fixture, None);
    let keys = fixture.sent()[0].message.static_account_keys().to_vec();
    fixture
        .chain
        .accounts
        .lock()
        .expect("accounts")
        .extend(keys);

    past_window(&fixture);
    fixture.relay.sweep_abandoned().await.expect("sweep");

    assert_eq!(fixture.outstanding().await, 0);
    let close = fixture.sent().pop().expect("the close");
    assert_eq!(close.message.instructions()[0].data, [CLOSE_FRAME_BUFFER]);
    assert_eq!(fixture.committed().await, 2 * 5_000);
}

#[tokio::test]
async fn a_failed_close_stays_held_and_a_later_sweep_retries_it() {
    let fixture = Fixture::with_budget(FRAME_BUDGET).await;
    let quote = fixture.quote(RelayOperation::Anonymous).await;
    let request = wide_request(&fixture, quote);
    fixture.chain.refuse_at.store(1, Ordering::Relaxed);
    assert!(fixture.prepare(&request).await.is_err());
    let keys = fixture.sent()[0].message.static_account_keys().to_vec();
    fixture
        .chain
        .accounts
        .lock()
        .expect("accounts")
        .extend(keys);
    let charged = fixture.outstanding().await;

    past_window(&fixture);
    pending_answer(&fixture, paid_failure());
    fixture.relay.sweep_abandoned().await.expect("sweep");
    assert_eq!(fixture.outstanding().await, charged);

    pending_answer(&fixture, None);
    past_window(&fixture);
    fixture.relay.sweep_abandoned().await.expect("sweep");
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(fixture.committed().await, 3 * 5_000);
}

/// The failure and its fee commit once, a repeated status read charges nothing more.
#[tokio::test]
async fn a_failed_settlement_charges_its_fee_once_and_frees_the_key() {
    let fixture = Fixture::with_budget(ENROLLMENT_LAMPORTS).await;
    let owner = Keypair::new_from_array([42; 32]);
    let quote = fixture.quote(RelayOperation::Enroll).await;
    let step = fixture
        .prepare(&enrollment(&owner, vec![6, 1], quote))
        .await
        .expect("the relay");
    let RelayStep::SignMessage { relay_id, message } = step else {
        panic!("the owner signs its enrollment, got {step:?}");
    };
    pending_answer(&fixture, paid_failure());
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
    for _ in 0..2 {
        let status: RelayStatus = fixture
            .call(
                GET_RELAY_STATUS,
                GetRelayStatusRequest {
                    relay_id: relay_id.clone(),
                },
            )
            .await;
        assert!(matches!(status, RelayStatus::Failed { .. }), "{status:?}");
    }
    assert_eq!(fixture.outstanding().await, 0);
    assert_eq!(fixture.committed().await, 2 * 5_000);
}
