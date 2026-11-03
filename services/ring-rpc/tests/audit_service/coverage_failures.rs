use super::*;
use zolana_ring_client::rpc::{GetUnspentUtxosResponse, UnresolvedReason, GET_UNSPENT_UTXOS};

async fn unspent(hub: &Arc<Hub<StaticSource>>, owner: [u8; 32]) -> GetUnspentUtxosResponse {
    let member = *Member::owner_tag(&owner).expect("member").as_bytes();
    let request = UnspentUtxosRequest::new(target(RING), member)
        .sign(&delegate())
        .expect("signed read");
    rpc_module(hub.clone())
        .expect("module")
        .call(GET_UNSPENT_UTXOS, as_object(request))
        .await
        .expect("unspent read")
}

#[tokio::test]
async fn a_failed_config_read_clears_complete_until_the_next_terminal_pass() {
    let fixture = Fixture::new();
    let mut source = fixture.source().with_transactions(Vec::new());
    source.next_cursor = None;
    let config_down = source.config_down.clone();
    let hub = Arc::new(fixture.hub(source));
    let service = hub.service(None).expect("service");
    service.backfill_utxos().await.expect("first pass");
    let first = unspent(&hub, [0xb0; 32]).await;
    assert!(first.coverage.complete);

    config_down.store(true, Ordering::Relaxed);
    assert!(service.backfill_utxos().await.is_err());
    config_down.store(false, Ordering::Relaxed);
    let failed = unspent(&hub, [0xb0; 32]).await;
    assert!(!failed.coverage.complete);
    assert_eq!(failed.coverage.through_slot, first.coverage.through_slot);
    assert_eq!(failed.coverage.from_slot, first.coverage.from_slot);

    service.backfill_utxos().await.expect("retry");
    assert!(unspent(&hub, [0xb0; 32]).await.coverage.complete);
}

#[tokio::test]
async fn a_merge_event_mismatch_keeps_the_unspent_coverage_incomplete() {
    let fixture = Fixture::new();
    let known_hash = fixture.audited.output_slots[0].output_context.hash;
    let mut merge = fixture.audited.clone();
    merge.tx_signature = Signature::from([0x77; 64]);
    merge.tx_viewing_pk = None;
    merge.salt = None;
    merge.messages.clear();
    merge.output_slots.truncate(1);
    merge.output_slots[0].output_context.hash = field(0x77);
    merge.output_slots[0].payload.clear();
    merge.nullifiers = vec![field(0x78)];
    let confirmed = origin_fixture::event(&merge);
    merge.nullifiers[0] = field(0x79);
    let merge_signature = merge.tx_signature;
    let mut source = fixture
        .source()
        .with_transactions(vec![fixture.audited.clone(), merge]);
    source.next_cursor = None;
    source
        .confirmed_events
        .insert((merge_signature, 0), confirmed);
    let hub = Arc::new(fixture.hub(source));
    hub.service(None)
        .expect("service")
        .backfill_utxos()
        .await
        .expect("terminal pass");

    let response = unspent(&hub, [0xb0; 32]).await;
    assert!(response
        .utxos
        .iter()
        .any(|note| note.utxo_hash.0 == known_hash));
    assert!(!response.coverage.complete);
    assert_eq!(response.coverage.through_slot, 99);
    let [unresolved] = response.unresolved.as_slice() else {
        panic!("unreadable merge must hold coverage");
    };
    assert_eq!(unresolved.tx_signature.0, merge_signature);
    assert_eq!(unresolved.reason, UnresolvedReason::UnreadableRow);
    assert!(unresolved.inputs.is_empty());
}
